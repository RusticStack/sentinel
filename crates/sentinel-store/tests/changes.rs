//! O05 store additions: the commit notifier that long polls park on, the
//! keyset run pagination behind `run list --all`, the allocation-free run
//! version, and the bounded literal log search.

use std::{
    collections::HashSet,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use sentinel_core::{AttemptId, JobId, RepoId, RunId, TenantId, UnixMillis};
use sentinel_protocol::logs::{Frame, Stream};
use sentinel_store::{
    Durability, Store, jobs,
    logs::{LogStore, SearchQuery},
    status,
};

fn store() -> (tempfile::TempDir, Arc<Store>) {
    let dir = tempfile::tempdir().unwrap();
    let store =
        Arc::new(Store::open(dir.path().join("metadata.sqlite"), Durability::Normal).unwrap());
    (dir, store)
}

fn repo(store: &Store) -> (TenantId, RepoId) {
    let (tenant, repo) = (TenantId::new(), RepoId::new());
    store
        .writer()
        .write(move |tx| {
            jobs::insert_tenant(tx, tenant, "acme", UnixMillis(1))?;
            jobs::insert_repo(tx, tenant, repo, "app", UnixMillis(1))
        })
        .unwrap();
    (tenant, repo)
}

#[test]
fn a_parked_waiter_wakes_on_the_next_commit() {
    let (_dir, store) = store();
    let (tenant, _) = repo(&store);
    let seen = store.changes().generation();
    let writer = {
        let store = Arc::clone(&store);
        thread::spawn(move || {
            thread::sleep(Duration::from_millis(150));
            store
                .writer()
                .write(move |tx| jobs::insert_tenant(tx, TenantId::new(), "other", UnixMillis(2)))
                .unwrap();
        })
    };
    let started = Instant::now();
    let next = store
        .changes()
        .wait_past(seen, Instant::now() + Duration::from_secs(10));
    writer.join().unwrap();
    assert_eq!(next, seen + 1);
    assert!(started.elapsed() >= Duration::from_millis(100));
    assert!(started.elapsed() < Duration::from_secs(5));
    // A write that fails bumps nothing: its transaction rolled back.
    let before = store.changes().generation();
    assert!(
        store
            .writer()
            .write(move |tx| jobs::insert_tenant(tx, tenant, "acme", UnixMillis(3)))
            .is_err()
    );
    assert_eq!(store.changes().generation(), before);
    // Already past: no parking at all.
    let started = Instant::now();
    assert_eq!(
        store
            .changes()
            .wait_past(before - 1, Instant::now() + Duration::from_secs(10)),
        before
    );
    assert!(started.elapsed() < Duration::from_millis(100));
}

#[test]
fn a_waiter_times_out_at_its_deadline() {
    let (_dir, store) = store();
    let seen = store.changes().generation();
    let started = Instant::now();
    assert_eq!(
        store
            .changes()
            .wait_past(seen, Instant::now() + Duration::from_millis(200)),
        seen
    );
    let waited = started.elapsed();
    assert!(waited >= Duration::from_millis(200), "{waited:?}");
    assert!(waited < Duration::from_secs(3), "{waited:?}");
}

/// A thousand commit/wait handshakes: each waiter reads the generation, the
/// writer commits once it knows the waiter is about to park, and the waiter
/// must see that commit with no deadline to rescue it. A lost wakeup shows
/// up as a waiter stuck until its (far) deadline.
#[test]
fn no_wakeup_is_lost_across_a_thousand_commit_wait_cycles() {
    let (_dir, store) = store();
    const CYCLES: usize = 1_000;
    let armed = Arc::new(std::sync::Barrier::new(2));
    let done = Arc::new(AtomicBool::new(false));
    let writer = {
        let (store, armed, done) = (Arc::clone(&store), Arc::clone(&armed), Arc::clone(&done));
        thread::spawn(move || {
            for i in 0..CYCLES {
                armed.wait();
                store
                    .writer()
                    .write(move |tx| {
                        tx.execute(
                            "INSERT INTO tenants(id, slug, created_ms) VALUES (?1, ?2, 1)",
                            (TenantId::new().as_bytes(), format!("t{i}")),
                        )?;
                        Ok(())
                    })
                    .unwrap();
            }
            done.store(true, Ordering::Release);
        })
    };
    let started = Instant::now();
    for _ in 0..CYCLES {
        let seen = store.changes().generation();
        armed.wait();
        // The commit races this park: before it, during it, or after it.
        let next = store
            .changes()
            .wait_past(seen, Instant::now() + Duration::from_secs(30));
        assert!(next > seen, "a commit was missed");
    }
    writer.join().unwrap();
    assert!(done.load(Ordering::Acquire));
    // Every cycle ended on a wakeup, not on the 30 s deadline.
    assert!(started.elapsed() < Duration::from_secs(60));
    // Concurrent waiters all wake on one commit.
    let seen = store.changes().generation();
    let waiters: Vec<_> = (0..8)
        .map(|_| {
            let store = Arc::clone(&store);
            thread::spawn(move || {
                store
                    .changes()
                    .wait_past(seen, Instant::now() + Duration::from_secs(30))
            })
        })
        .collect();
    thread::sleep(Duration::from_millis(100));
    store
        .writer()
        .write(move |tx| jobs::insert_tenant(tx, TenantId::new(), "last", UnixMillis(4)))
        .unwrap();
    for waiter in waiters {
        assert!(waiter.join().unwrap() > seen);
    }
}

#[test]
fn run_pages_are_stable_across_equal_timestamps_and_new_runs() {
    let (_dir, store) = store();
    let (tenant, repo) = repo(&store);
    // 25 runs, many sharing one millisecond.
    let runs: Vec<RunId> = (0..25).map(|_| RunId::new()).collect();
    let seeded = runs.clone();
    store
        .writer()
        .write(move |tx| {
            for (i, run) in seeded.iter().enumerate() {
                jobs::insert_run(
                    tx,
                    tenant,
                    repo,
                    *run,
                    "sha",
                    UnixMillis(100 + i as i64 / 10),
                )?;
            }
            Ok(())
        })
        .unwrap();
    let mut listed = Vec::new();
    let mut before = None;
    let mut pages = 0;
    loop {
        let page = store
            .read(|c| status::runs_page(c, tenant, repo, before, 7))
            .unwrap();
        pages += 1;
        if pages == 2 {
            // A run arriving mid-listing is newer than the cursor: it
            // never shifts a later page.
            store
                .writer()
                .write(move |tx| {
                    jobs::insert_run(tx, tenant, repo, RunId::new(), "sha", UnixMillis(500))
                })
                .unwrap();
        }
        assert!(page.runs.len() <= 7);
        listed.extend(page.runs.iter().map(|r| (r.created.0, *r.id.as_bytes())));
        match page.next {
            Some(next) => {
                assert_eq!(Some(next), page.runs.last().map(|r| r.id));
                before = Some(next);
            }
            None => break,
        }
    }
    // 25 runs in pages of 7: four pages, the last one short and final.
    assert_eq!(pages, 4);
    assert_eq!(listed.len(), 25);
    let unique: HashSet<_> = listed.iter().collect();
    assert_eq!(unique.len(), 25, "no run listed twice");
    let mut sorted = listed.clone();
    sorted.sort_by(|a, b| b.cmp(a));
    assert_eq!(listed, sorted, "newest first by (created_ms, id)");
    let expected: HashSet<[u8; 16]> = runs.iter().map(|r| *r.as_bytes()).collect();
    assert_eq!(
        listed.iter().map(|(_, id)| *id).collect::<HashSet<_>>(),
        expected
    );
    // An exact final page says so without an empty follow-up.
    let page = store
        .read(|c| status::runs_page(c, tenant, repo, None, 26))
        .unwrap();
    assert_eq!((page.runs.len(), page.next), (26, None));
    // A cursor from another repository is not a cursor here.
    let (other_tenant, other_repo) = (TenantId::new(), RepoId::new());
    let foreign = RunId::new();
    store
        .writer()
        .write(move |tx| {
            jobs::insert_tenant(tx, other_tenant, "other", UnixMillis(1))?;
            jobs::insert_repo(tx, other_tenant, other_repo, "app", UnixMillis(1))?;
            jobs::insert_run(tx, other_tenant, other_repo, foreign, "sha", UnixMillis(1))
        })
        .unwrap();
    assert!(matches!(
        store.read(|c| status::runs_page(c, tenant, repo, Some(foreign), 5)),
        Err(sentinel_store::Error::NotFound)
    ));
}

#[test]
fn run_pages_are_index_ranges() {
    let (_dir, store) = store();
    store
        .read(|conn| {
            for sql in [status::PAGE_SQL, status::PAGE_JOBS_SQL] {
                let mut stmt = conn.prepare(&format!("EXPLAIN QUERY PLAN {sql}"))?;
                let plan: Vec<String> = stmt
                    .query_map(
                        (
                            [0u8; 16].as_slice(),
                            [0u8; 16].as_slice(),
                            1i64,
                            [0u8; 16].as_slice(),
                            10i64,
                        ),
                        |r| r.get(3),
                    )?
                    .collect::<Result<_, _>>()?;
                let plan = plan.join(" | ");
                assert!(
                    plan.contains("runs_by_repo") && plan.contains("(created_ms,id)<(?,?)"),
                    "the page must be a keyset range on runs_by_repo: {plan}"
                );
                assert!(!plan.contains("SCAN runs"), "{plan}");
                assert!(!plan.contains("TEMP B-TREE"), "no sort: {plan}");
                assert!(!plan.contains("SCAN jobs"), "{plan}");
            }
            Ok(())
        })
        .unwrap();
}

#[test]
fn the_run_version_moves_with_every_visible_change() {
    let (_dir, store) = store();
    let (tenant, repo) = repo(&store);
    let (run, job) = (RunId::new(), JobId::new());
    store
        .writer()
        .write(move |tx| {
            jobs::insert_run(tx, tenant, repo, run, "sha", UnixMillis(5))?;
            jobs::insert_job(tx, tenant, run, job, "build", 0, 1)
        })
        .unwrap();
    let version = || store.read(|c| status::run_version(c, tenant, run)).unwrap();
    let first = version();
    assert!(!first.finished);
    assert_eq!(version(), first, "deterministic");
    store
        .writer()
        .write(move |tx| jobs::request_cancel(tx, tenant, job).map(|_| ()))
        .unwrap();
    let cancelled = version();
    assert_ne!(cancelled.version, first.version);
    store
        .writer()
        .write(move |tx| {
            sentinel_store::dispatch::cancel(tx, tenant, job, UnixMillis(6)).map(|_| ())
        })
        .unwrap();
    let ended = version();
    assert_ne!(ended.version, cancelled.version);
    assert!(ended.finished);
    assert!(matches!(
        store.read(|c| status::run_version(c, TenantId::new(), run)),
        Err(sentinel_store::Error::NotFound)
    ));
}

#[test]
fn log_search_finds_literals_across_segments_within_its_byte_bound() {
    let dir = tempfile::tempdir().unwrap();
    let logs = LogStore::open(dir.path().join("logs")).unwrap();
    let (run, job, attempt) = (RunId::new(), JobId::new(), AttemptId::new());
    // ~10 MiB in 32 KiB frames: three 4 MiB segments. Every 32nd frame
    // carries the needle on a line of its own.
    let filler = "x".repeat(1023) + "\n";
    let mut seq = 0u64;
    for i in 0..320u32 {
        seq += 1;
        let mut text = filler.repeat(31);
        if i % 32 == 0 {
            text.push_str(&format!("error: needle {i}\r\n"));
        } else {
            text.push_str(&filler);
        }
        logs.append(
            run,
            job,
            attempt,
            &Frame {
                seq,
                step: i / 160,
                stream: if i % 64 == 0 {
                    Stream::Stderr
                } else {
                    Stream::Stdout
                },
                bytes: text.into_bytes(),
            },
        )
        .unwrap();
    }
    let query = |after, limit, budget| SearchQuery {
        needle: b"needle",
        after,
        limit,
        budget,
    };
    // One request under a 1 MiB budget stops early and says where to resume.
    let first = logs
        .search(run, job, attempt, query(0, 100, 1 << 20))
        .unwrap();
    assert!(!first.complete);
    let resume = first.next_after.expect("stopped at the byte bound");
    assert!(
        resume <= 34,
        "a 1 MiB budget covers about 32 frames: {resume}"
    );
    assert!((1..=2).contains(&first.matches.len()));
    assert_eq!(first.matches[0].seq, 1);
    assert_eq!(first.matches[0].text, b"error: needle 0");
    assert_eq!(first.matches[0].stream, Stream::Stderr);
    // Resuming walks every segment and finds every match exactly once.
    let mut found = first.matches;
    let mut after = resume;
    let mut requests = 1;
    loop {
        let page = logs
            .search(run, job, attempt, query(after, 100, 1 << 20))
            .unwrap();
        requests += 1;
        found.extend(page.matches);
        match page.next_after {
            Some(next) => {
                assert!(next > after, "every request makes progress");
                after = next;
            }
            None => {
                // Not finished yet: nothing more can be promised.
                assert!(!page.complete);
                break;
            }
        }
    }
    assert!(requests >= 10, "10 MiB at 1 MiB per request: {requests}");
    let seqs: Vec<u64> = found.iter().map(|m| m.seq).collect();
    assert_eq!(seqs, (0..10).map(|k| 1 + 32 * k).collect::<Vec<_>>());
    assert_eq!(found[9].text, b"error: needle 288");
    assert_eq!(found[9].step, 1);
    // The match limit also stops a request, between frames.
    let limited = logs
        .search(run, job, attempt, query(0, 2, u64::MAX))
        .unwrap();
    assert_eq!(limited.matches.len(), 2);
    assert_eq!(limited.next_after, Some(33));
    // Once finished, a scan to the end is complete.
    logs.finish(run, job, attempt, seq, &[]).unwrap();
    let whole = logs
        .search(run, job, attempt, query(280, 100, u64::MAX))
        .unwrap();
    assert_eq!(
        (whole.matches.len(), whole.next_after, whole.complete),
        (1, None, true)
    );
    let none = logs
        .search(
            run,
            job,
            attempt,
            SearchQuery {
                needle: b"absent",
                after: 0,
                limit: 10,
                budget: u64::MAX,
            },
        )
        .unwrap();
    assert!(none.matches.is_empty() && none.complete);
    assert!(matches!(
        logs.search(run, job, AttemptId::new(), query(0, 1, 1)),
        Err(sentinel_store::Error::NotFound)
    ));
}
