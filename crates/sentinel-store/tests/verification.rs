//! C08 verification: duplicate requests, transaction rollback, conflicting
//! updates from concurrent callers, and a real process crash between
//! acknowledged commits and reopen.
use std::{
    process::Command,
    sync::{Arc, Barrier},
    thread,
};

use sentinel_core::{Actor, Event, JobId, JobState, RepoId, RunId, TenantId, UnixMillis, WorkerId};
use sentinel_pipeline::{PinnedSource, RunSpec, compile_str};
use sentinel_protocol::idempotency::{Fingerprint, IDEMPOTENCY_TTL_MS, IdempotencyKey};
use sentinel_store::{
    Durability, Error, Store,
    idempotency::{self, Begin, Scope},
    jobs, runs,
};

const SHA: &str = "0c87e0181c794fe2bbfeb15dc34e7b6aae375d8b";

const DIGEST: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn spec() -> RunSpec {
    let text = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/pipelines/valid/minimal.yml"
    ))
    .unwrap();
    RunSpec::new(
        PinnedSource::new("r", SHA, None).unwrap(),
        compile_str(&text).unwrap(),
    )
    .unwrap()
}

fn open(dir: &std::path::Path, durability: Durability) -> (Store, TenantId, RepoId) {
    let store = Store::open(dir.join("m.sqlite"), durability).unwrap();
    let (tenant, repo) = (TenantId::new(), RepoId::new());
    store
        .writer()
        .write(move |tx| {
            jobs::insert_tenant(tx, tenant, "acme", UnixMillis(1))?;
            jobs::insert_repo(tx, tenant, repo, "app", UnixMillis(1))
        })
        .unwrap();
    (store, tenant, repo)
}

/// Dispatch with an idempotency key: begin, create, complete in one transaction.
fn dispatch(
    store: &Store,
    tenant: TenantId,
    repo: RepoId,
    key: &str,
    body: &[u8],
    now: i64,
) -> Result<(RunId, bool), Error> {
    let key = IdempotencyKey::parse(key).unwrap();
    let fp = Fingerprint::of(body);
    let s = spec();
    store.writer().write(move |tx| {
        let scope = Scope {
            tenant,
            principal: "user-1",
            route: "POST /runs",
        };
        match idempotency::begin(tx, scope, key, fp, UnixMillis(now))? {
            Begin::Replay(run) => Ok((run, true)),
            Begin::Mismatch => Err(Error::Conflict),
            Begin::InFlight => Err(Error::WriterUnavailable),
            Begin::Execute => {
                let run = RunId::new();
                runs::create_run(tx, tenant, repo, run, &s, UnixMillis(now))?;
                idempotency::complete(tx, scope, key, run)?;
                Ok((run, false))
            }
        }
    })
}

#[test]
fn duplicate_requests_execute_once_and_replay_the_same_run() {
    let dir = tempfile::tempdir().unwrap();
    let (store, tenant, repo) = open(dir.path(), Durability::Normal);
    let (first, replayed) =
        dispatch(&store, tenant, repo, "dispatch-1", b"{\"sha\":\"a\"}", 1000).unwrap();
    assert!(!replayed);
    let (second, replayed) =
        dispatch(&store, tenant, repo, "dispatch-1", b"{\"sha\":\"a\"}", 1001).unwrap();
    assert!(replayed);
    assert_eq!(
        first, second,
        "same key and body: same run, no second execution"
    );
    let count: i64 = store
        .read(|c| Ok(c.query_row("SELECT COUNT(*) FROM runs", [], |r| r.get(0))?))
        .unwrap();
    assert_eq!(count, 1);
    // Same key, different body: rejected, nothing created.
    assert!(matches!(
        dispatch(&store, tenant, repo, "dispatch-1", b"{\"sha\":\"b\"}", 1002),
        Err(Error::Conflict)
    ));
    let count: i64 = store
        .read(|c| Ok(c.query_row("SELECT COUNT(*) FROM runs", [], |r| r.get(0))?))
        .unwrap();
    assert_eq!(count, 1);
    // Another tenant with the same key is an unrelated scope.
    let (store2, tenant2, repo2) = (store, TenantId::new(), RepoId::new());
    store2
        .writer()
        .write(move |tx| {
            jobs::insert_tenant(tx, tenant2, "other", UnixMillis(1))?;
            jobs::insert_repo(tx, tenant2, repo2, "app", UnixMillis(1))
        })
        .unwrap();
    let (third, replayed) = dispatch(
        &store2,
        tenant2,
        repo2,
        "dispatch-1",
        b"{\"sha\":\"a\"}",
        1003,
    )
    .unwrap();
    assert!(!replayed);
    assert_ne!(third, first);
    // After the TTL the key is fresh again.
    let (fourth, replayed) = dispatch(
        &store2,
        tenant,
        repo,
        "dispatch-1",
        b"{\"sha\":\"b\"}",
        1000 + IDEMPOTENCY_TTL_MS + 1,
    )
    .unwrap();
    assert!(!replayed);
    assert_ne!(fourth, first);
}

#[test]
fn failed_transaction_leaves_no_partial_rows() {
    let dir = tempfile::tempdir().unwrap();
    let (store, tenant, _repo) = open(dir.path(), Durability::Normal);
    let foreign_repo = RepoId::new();
    let run = RunId::new();
    let s = spec();
    let key = IdempotencyKey::parse("k").unwrap();
    // The idempotency record is written first; the run then fails because the
    // repo is not the tenant's. Both must roll back together.
    let result = store.writer().write(move |tx| {
        let scope = Scope {
            tenant,
            principal: "p",
            route: "r",
        };
        assert_eq!(
            idempotency::begin(tx, scope, key, Fingerprint::of(b"x"), UnixMillis(5))?,
            Begin::Execute
        );
        runs::create_run(tx, tenant, foreign_repo, run, &s, UnixMillis(5))
    });
    assert!(matches!(result, Err(Error::NotFound)));
    store
        .read(|c| {
            let keys: i64 =
                c.query_row("SELECT COUNT(*) FROM idempotency_keys", [], |r| r.get(0))?;
            let runs: i64 = c.query_row("SELECT COUNT(*) FROM runs", [], |r| r.get(0))?;
            let specs: i64 = c.query_row("SELECT COUNT(*) FROM run_specs", [], |r| r.get(0))?;
            assert_eq!((keys, runs, specs), (0, 0, 0));
            Ok(())
        })
        .unwrap();
}

#[test]
fn concurrent_leases_of_one_job_succeed_exactly_once() {
    let dir = tempfile::tempdir().unwrap();
    let (store, tenant, repo) = open(dir.path(), Durability::Normal);
    let s = spec();
    let run = RunId::new();
    let ids = store
        .writer()
        .write(move |tx| runs::create_run(tx, tenant, repo, run, &s, UnixMillis(1)))
        .unwrap();
    let job = ids[0];
    store
        .writer()
        .write(move |tx| runs::resolve_image(tx, tenant, job, DIGEST, "linux/amd64"))
        .unwrap();
    let store = Arc::new(store);
    let barrier = Arc::new(Barrier::new(8));
    let handles: Vec<_> = (0..8)
        .map(|_| {
            let store = Arc::clone(&store);
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                store.writer().write(move |tx| {
                    jobs::lease(
                        tx,
                        tenant,
                        job,
                        WorkerId::new(),
                        UnixMillis(99),
                        UnixMillis(2),
                    )
                })
            })
        })
        .collect();
    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    let won = results.iter().filter(|r| r.is_ok()).count();
    assert_eq!(won, 1, "exactly one lease: {results:?}");
    assert!(results.iter().all(|r| match r {
        Ok(_) => true,
        Err(Error::Transition(_)) => true,
        other => panic!("unexpected {other:?}"),
    }));
    let row = store.read(|c| jobs::get_job(c, tenant, job)).unwrap();
    assert_eq!(row.state, JobState::Leased);
    assert_eq!(row.fence.0, 1);
    let attempts: i64 = store
        .read(|c| Ok(c.query_row("SELECT COUNT(*) FROM attempts", [], |r| r.get(0))?))
        .unwrap();
    assert_eq!(attempts, 1);
}

/// Child mode: perform N acknowledged transitions with FULL durability, then
/// abort without any cleanup. The parent then reopens and counts.
#[test]
fn crash_child() {
    let Ok(path) = std::env::var("SENTINEL_CRASH_DB") else {
        return; // Only runs when spawned by `crash_between_commits_loses_nothing_acknowledged`.
    };
    let store = Store::open(&path, Durability::Full).unwrap();
    let (tenant, repo) = (TenantId::new(), RepoId::new());
    store
        .writer()
        .write(move |tx| {
            jobs::insert_tenant(tx, tenant, "acme", UnixMillis(1))?;
            jobs::insert_repo(tx, tenant, repo, "app", UnixMillis(1))
        })
        .unwrap();
    for i in 0..25u32 {
        let run = RunId::new();
        let s = spec();
        let ids = store
            .writer()
            .write(move |tx| runs::create_run(tx, tenant, repo, run, &s, UnixMillis(i as i64)))
            .unwrap();
        let job: JobId = ids[0];
        store
            .writer()
            .write(move |tx| {
                jobs::transition(
                    tx,
                    tenant,
                    job,
                    Actor::Controller,
                    Event::Skip,
                    UnixMillis(10),
                )
            })
            .unwrap();
        // Report progress so the parent knows what was acknowledged.
        println!("ACKED {}", i + 1);
    }
    std::process::abort();
}

#[test]
fn crash_between_commits_loses_nothing_acknowledged() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("crash.sqlite");
    let out = Command::new(std::env::current_exe().unwrap())
        .args(["crash_child", "--exact", "--nocapture"])
        .env("SENTINEL_CRASH_DB", &path)
        .output()
        .unwrap();
    assert!(!out.status.success(), "child must abort");
    let acked = String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| l.strip_prefix("ACKED "))
        .filter_map(|n| n.parse::<i64>().ok())
        .max()
        .expect("child acknowledged at least one round");
    assert_eq!(acked, 25);
    // WAL and possibly a hot journal are left behind; reopen must recover.
    let store = Store::open(&path, Durability::Full).unwrap();
    store
        .read(|c| {
            let integrity: String = c.query_row("PRAGMA integrity_check", [], |r| r.get(0))?;
            assert_eq!(integrity, "ok");
            let runs: i64 = c.query_row("SELECT COUNT(*) FROM runs", [], |r| r.get(0))?;
            let skipped: i64 =
                c.query_row("SELECT COUNT(*) FROM jobs WHERE state_code = 17", [], |r| {
                    r.get(0)
                })?;
            assert_eq!(runs, acked, "every acknowledged run survived");
            assert_eq!(skipped, acked, "every acknowledged transition survived");
            Ok(())
        })
        .unwrap();
    store.checkpoint().unwrap();
}
