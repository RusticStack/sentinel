//! R07: a controller killed at any instant of storage work (reclaim, unlink, eviction, log expiry) must leave only what the
//! sweeps collect, and the counters must still equal the rows.

use std::{
    fs,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime},
};

use sentinel_auth::secret::Secret;
use sentinel_core::{
    AttemptId, JobId, PoolId, RepoId, RunId, TenantId, UnixMillis, UserId, WorkerId,
    auth::{Namespace, Permissions as P, Principal},
};
use sentinel_pipeline::{PinnedSource, RunSpec, compile_str};
use sentinel_protocol::negotiate::{Arch, Capabilities, Negotiated, ProtocolVersion};
use sentinel_store::{
    Durability, Store,
    auth::{self, Authority, NamespaceKind, provisioning},
    dispatch::{self, Capacity},
    jobs,
    logs::LogStore,
    objects::{self, Entry, Expect, Kind, Objects},
    offload::{self, ObjectRef},
    retention, runs,
    tenancy::{self, PoolKind},
    workers::{self, Presentation},
};

const CHILD: &str = "SENTINEL_R07_GC_CHILD";
const NOW: UnixMillis = UnixMillis(1_000_000_000);
const SHA: &str = "0123456789abcdef0123456789abcdef01234567";
const DIGEST: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
/// Unreferenced objects the reclaim stage collects.
const RECLAIMABLE: usize = 1_200;
/// Referenced, replicated objects the eviction stage drops from local disk.
const EVICTABLE: usize = 400;
/// Finished attempts whose logs are due.
const LOGS: usize = 200;

/// One round of every storage stage over a small batch, as the controller's pass does it: the database commit first, the files
/// after. Returns whether any stage found work.
fn storage_round(store: &Store, objects: &Arc<Objects>, logs: &LogStore, batch: u32) -> bool {
    let mut worked = false;
    let far = UnixMillis(UnixMillis::now().0 + objects::UNREFERENCED_GRACE_MS + 1);

    let reclaiming = Arc::clone(objects);
    let doomed = store
        .writer()
        .write(move |tx| Ok(reclaiming.reclaim(tx, far, i64::from(batch))?.doomed))
        .unwrap();
    if !doomed.is_empty() {
        worked = true;
        let unlinking = Arc::clone(objects);
        store
            .writer()
            .write(move |tx| unlinking.unlink(tx, &doomed))
            .unwrap();
    }

    let candidates = store.read(|c| offload::evictable(c, batch)).unwrap();
    if !candidates.is_empty() {
        worked = true;
        let keys: Vec<_> = candidates.iter().map(|c| (c.tenant, c.digest)).collect();
        let marked = keys.clone();
        store
            .writer()
            .write(move |tx| offload::evicted(tx, &marked, UnixMillis::now()))
            .unwrap();
        objects.evict_files(&keys);
    }

    let now = UnixMillis::now();
    let due = store.read(|c| retention::expiring(c, now, batch)).unwrap();
    if !due.is_empty() {
        worked = true;
        let expired = store
            .writer()
            .write(move |tx| retention::expire(tx, &due, now))
            .unwrap();
        for log in expired {
            logs.remove(log.run, log.job, log.attempt).unwrap();
        }
    }
    worked
}

fn open(data: &Path) -> (Store, Arc<Objects>, LogStore) {
    (
        Store::open(data.join("metadata.sqlite"), Durability::Normal).unwrap(),
        Arc::new(Objects::open(data).unwrap()),
        LogStore::open(data.join("logs")).unwrap(),
    )
}

fn files(root: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(read) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in read.flatten() {
            let path = entry.path();
            if entry.file_type().is_ok_and(|t| t.is_dir()) {
                stack.push(path);
            } else {
                found.push(path);
            }
        }
    }
    found
}

struct Seeded {
    tenant: TenantId,
    attempts: Vec<(RunId, JobId, AttemptId)>,
}

/// A tenant with one real finished attempt, `LOGS` copies of it with logs on disk and already due, `RECLAIMABLE` unreferenced
/// objects and `EVICTABLE` referenced ones that are already copied elsewhere.
fn seed(data: &Path) -> Seeded {
    let (store, objects, logs) = open(data);
    let (root, tenant, repo, pool) = (UserId::new(), TenantId::new(), RepoId::new(), PoolId::new());
    store
        .writer()
        .write(move |tx| {
            provisioning::insert_human(tx, root, "Root", true, NOW)?;
            auth::create_namespace(
                tx,
                Principal::new(root, P::ALL, None, None),
                tenant,
                Namespace::parse("acme").unwrap(),
                NamespaceKind::Organization,
                NOW,
            )?;
            jobs::insert_repo(tx, tenant, repo, "app", NOW)?;
            tenancy::create_pool(
                tx,
                Authority::HostLocal,
                pool,
                "builders",
                PoolKind::Dedicated(tenant),
                NOW,
            )
        })
        .unwrap();

    let (run, worker) = (RunId::new(), WorkerId::new());
    let spec = RunSpec::new(
        PinnedSource::new("https://github.com/o/r.git", SHA, Some("main")).unwrap(),
        compile_str(
            "schema: 1\non: [push]\njobs:\n  build:\n    image: alpine:3\n    steps: [{ id: s, run: 'true' }]\n",
        )
        .unwrap(),
    )
    .unwrap();
    let (job, original) = store
        .writer()
        .write(move |tx| {
            let ids = runs::create_run(tx, tenant, repo, run, &spec, NOW)?;
            runs::resolve_image(tx, tenant, ids[0], DIGEST, "linux/amd64")?;
            let issued = workers::issue_enrollment(tx, Authority::HostLocal, pool, 60_000, NOW)?;
            let mut text = String::new();
            issued.secret.expose(&mut text);
            workers::enroll(
                tx,
                &Secret::parse(&text).unwrap(),
                Presentation {
                    worker,
                    fingerprint: Secret::generate().digest(),
                    name: "w",
                    negotiated: Negotiated {
                        protocol: ProtocolVersion(4),
                        capabilities: Capabilities::REQUIRED,
                        arch: Arch::X86_64,
                    },
                },
                NOW,
            )?;
            dispatch::report_capacity(
                tx,
                worker,
                Capacity {
                    cpu_millis: 4_000,
                    memory_bytes: 8 << 30,
                    disk_bytes: 0,
                },
            )?;
            let offer = dispatch::place(tx, worker, pool, dispatch::DEFAULT_LEASE_MS, NOW)?
                .expect("a queued job was placed");
            tx.execute(
                "UPDATE attempts SET released_ms = ?2 WHERE id = ?1",
                rusqlite::params![offer.attempt.as_bytes().as_slice(), NOW.0],
            )?;
            Ok((ids[0], offer.attempt))
        })
        .unwrap();

    // Copies of the released attempt, each with a log on disk and a deadline long past.
    let copies: Vec<AttemptId> = (0..LOGS).map(|_| AttemptId::new()).collect();
    let rows = copies.clone();
    store
        .writer()
        .write(move |tx| {
            for (i, id) in rows.iter().enumerate() {
                tx.execute(
                    "INSERT INTO attempts(id, tenant_id, job_id, fence, worker_id, lease_until_ms, released_ms, log_expires_ms)
                     SELECT ?2, tenant_id, job_id, ?3, worker_id, lease_until_ms, released_ms, 1
                     FROM attempts WHERE id = ?1",
                    rusqlite::params![
                        original.as_bytes().as_slice(),
                        id.as_bytes().as_slice(),
                        1_000 + i as i64
                    ],
                )?;
            }
            Ok(())
        })
        .unwrap();
    let frame = sentinel_protocol::logs::Frame {
        seq: 1,
        step: 0,
        stream: sentinel_protocol::logs::Stream::Stdout,
        bytes: b"a line\n".to_vec(),
    };
    let mut attempts = Vec::new();
    for id in std::iter::once(original).chain(copies) {
        logs.append(run, job, id, &frame).unwrap();
        logs.finish(run, job, id, 1, &[]).unwrap();
        attempts.push((run, job, id));
    }

    for i in 0..RECLAIMABLE {
        let body = format!("an unreferenced object, number {i}");
        let staged = objects
            .stage(tenant, body.as_bytes(), u64::MAX, Expect::default())
            .unwrap();
        let objects = Arc::clone(&objects);
        store
            .writer()
            .write(move |tx| objects.commit(tx, &staged))
            .unwrap();
    }
    let mut entries = Vec::new();
    for i in 0..EVICTABLE {
        let body = format!("a kept object, number {i}");
        let staged = objects
            .stage(tenant, body.as_bytes(), u64::MAX, Expect::default())
            .unwrap();
        let (digest, len) = (staged.digest(), body.len() as u64);
        let committing = Arc::clone(&objects);
        store
            .writer()
            .write(move |tx| {
                committing.commit(tx, &staged)?;
                offload::replicated(
                    tx,
                    &ObjectRef {
                        tenant,
                        digest,
                        len,
                    },
                    NOW,
                )
            })
            .unwrap();
        entries.push(Entry {
            path: format!("file-{i}"),
            digest,
            len,
            mode: 0o644,
        });
    }
    let manifest = Arc::clone(&objects);
    store
        .writer()
        .write(move |tx| manifest.commit_manifest(tx, tenant, Kind::Artifact, "job/out", &entries))
        .unwrap();
    Seeded { tenant, attempts }
}

fn expired(store: &Store, attempt: AttemptId) -> bool {
    store
        .read(|c| {
            Ok(c.query_row(
                "SELECT log_expired_ms IS NOT NULL FROM attempts WHERE id = ?1",
                [attempt.as_bytes().as_slice()],
                |r| r.get::<_, bool>(0),
            )?)
        })
        .unwrap()
}

#[test]
fn storage_work_killed_at_staggered_points_leaves_only_what_the_sweeps_collect() {
    if let Some(data) = std::env::var_os(CHILD) {
        let (store, objects, logs) = open(Path::new(&data));
        while storage_round(&store, &objects, &logs, 2) {}
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    fs::create_dir_all(&data).unwrap();
    let seeded = seed(&data);

    // Kills that found the child still working. A host fast enough to finish all the work before the first kill would
    // otherwise pass this drill without a process ever being cut off.
    let mut interrupted = 0u32;
    for delay_ms in [150, 300, 500, 800, 1_200] {
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "storage_work_killed_at_staggered_points_leaves_only_what_the_sweeps_collect",
                "--nocapture",
            ])
            .env(CHILD, &data)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        std::thread::sleep(Duration::from_millis(delay_ms));
        if child.try_wait().unwrap().is_none() {
            interrupted += 1;
            child.kill().unwrap();
        }
        child.wait().unwrap();

        // Whatever instant the kill landed on, the database opens and no committed, local object is missing.
        let (store, objects, _) = open(&data);
        let recovery = store.read(|c| objects.recover(c)).unwrap();
        assert!(
            recovery.missing.is_empty() && recovery.corrupt.is_empty(),
            "after a kill at {delay_ms} ms: {recovery:?}"
        );
    }

    eprintln!("{interrupted} of 5 kills landed on a child still at work");
    assert!(interrupted > 0, "no kill landed inside storage work");

    // What is left finishes under the same stages, then the sweeps collect the rest.
    let (store, objects, logs) = open(&data);
    while storage_round(&store, &objects, &logs, 256) {}

    // Files a killed reclaim left behind have no row and are old enough only once their grace has passed.
    let long_ago =
        SystemTime::now() - Duration::from_millis(objects::FILE_ORPHAN_GRACE_MS as u64 * 2);
    for path in files(&data.join("objects")) {
        fs::File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_modified(long_ago)
            .unwrap();
    }
    let mut quiet = 0;
    for _ in 0..200 {
        let sweeping = Arc::clone(&objects);
        let (doomed, done) = store
            .read(move |c| sweeping.orphans(c, 256, 4_096))
            .unwrap();
        if doomed.is_empty() {
            quiet += 1;
            if done && quiet >= 2 {
                break;
            }
            continue;
        }
        quiet = 0;
        let unlinking = Arc::clone(&objects);
        store
            .writer()
            .write(move |tx| unlinking.unlink(tx, &doomed))
            .unwrap();
    }
    for _ in 0..50 {
        let gone = |attempt| expired(&store, attempt);
        if logs.sweep_dirs(256, gone).unwrap() == 0 {
            break;
        }
    }

    let recovery = store.read(|c| objects.recover(c)).unwrap();
    assert!(
        recovery.missing.is_empty() && recovery.corrupt.is_empty() && recovery.orphans.is_empty(),
        "{recovery:?}"
    );

    // Every unreferenced object is gone with its file; the kept ones are all evicted. A kill between an eviction's commit and
    // its unlink can leave that file behind: it belongs to an evicted row, so it is counted here and not asserted away.
    let (rows, evicted_rows): (i64, i64) = store
        .read(|c| {
            Ok(
                c.query_row("SELECT COUNT(*), COUNT(evicted_ms) FROM objects", [], |r| {
                    Ok((r.get(0)?, r.get(1)?))
                })?,
            )
        })
        .unwrap();
    assert_eq!(
        (rows as usize, evicted_rows as usize),
        (EVICTABLE, EVICTABLE)
    );
    let left = files(&data.join("objects")).len();
    assert!(left <= EVICTABLE, "{left} files for {EVICTABLE} rows");
    eprintln!("{left} files of evicted objects were left on disk by the kills");

    // The counters equal the rows.
    let (local, held): (u64, i64) = store
        .read(|c| {
            Ok((
                offload::totals(c)?.local_bytes,
                c.query_row(
                    "SELECT COALESCE(SUM(len), 0) FROM objects WHERE evicted_ms IS NULL",
                    [],
                    |r| r.get(0),
                )?,
            ))
        })
        .unwrap();
    assert_eq!(local, held as u64, "local bytes");
    let (usage, all, logged): (retention::Usage, i64, i64) =
        store
            .read(|c| {
                Ok((
                retention::tenant_usage(c, seeded.tenant)?,
                c.query_row("SELECT COALESCE(SUM(len), 0) FROM objects", [], |r| r.get(0))?,
                c.query_row(
                    "SELECT COALESCE(SUM(log_bytes), 0) FROM attempts WHERE log_expired_ms IS NULL",
                    [],
                    |r| r.get(0),
                )?,
            ))
            })
            .unwrap();
    assert_eq!(usage.object_bytes, all as u64, "tenant object bytes");
    assert_eq!(usage.log_bytes, logged as u64, "tenant log bytes");

    // The due logs are expired and their files are gone; the one attempt that was never due keeps its log.
    let (original, copies) = seeded.attempts.split_first().unwrap();
    assert!(!expired(&store, original.2));
    assert!(
        logs.attempt_dir(original.0, original.1, original.2)
            .exists()
    );
    for (run, job, attempt) in copies {
        assert!(expired(&store, *attempt));
        assert!(
            !logs.attempt_dir(*run, *job, *attempt).exists(),
            "the log of an expired attempt is gone"
        );
    }
}
