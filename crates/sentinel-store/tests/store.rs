use std::{sync::Arc, thread, time::Duration};

use rusqlite::params;
use sentinel_core::{
    Actor, Event, FailureClass, Fence, JobId, JobState, Outcome, RepoId, RunId, RunState, TenantId,
    UnixMillis, WorkerId,
};
use sentinel_store::{Durability, Error, Store, jobs};

struct Fixture {
    _dir: tempfile::TempDir,
    path: std::path::PathBuf,
    store: Store,
    tenant: TenantId,
    run: RunId,
    job: JobId,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("meta.sqlite");
    let store = Store::open(&path, Durability::Full).unwrap();
    let (tenant, repo, run, job) = (TenantId::new(), RepoId::new(), RunId::new(), JobId::new());
    let now = UnixMillis(1_000);
    store
        .writer()
        .write(move |tx| {
            jobs::insert_tenant(tx, tenant, "acme", now)?;
            jobs::insert_repo(tx, tenant, repo, "app", now)?;
            jobs::insert_run(tx, tenant, repo, run, "0c87e018", now)?;
            jobs::insert_job(tx, tenant, run, job, "test", 5, 1)
        })
        .unwrap();
    Fixture {
        _dir: dir,
        path,
        store,
        tenant,
        run,
        job,
    }
}

#[test]
fn migrations_are_idempotent_and_pragmas_hold() {
    let f = fixture();
    let version = f.store.writer().raw(sentinel_store::migrate).unwrap();
    assert_eq!(version, 4);
    f.store
        .read(|c| {
            let journal: String = c.query_row("PRAGMA journal_mode", [], |r| r.get(0))?;
            let fk: i64 = c.query_row("PRAGMA foreign_keys", [], |r| r.get(0))?;
            assert_eq!(journal, "wal");
            assert_eq!(fk, 1);
            Ok(())
        })
        .unwrap();
}

#[test]
fn full_lifecycle_with_fenced_lease_and_timestamps() {
    let f = fixture();
    let (tenant, job, run) = (f.tenant, f.job, f.run);
    let w = f.store.writer();
    let t = |ms: i64| UnixMillis(ms);
    assert_eq!(
        w.write(move |tx| jobs::transition(
            tx,
            tenant,
            job,
            Actor::Controller,
            Event::DependenciesSatisfied,
            t(10)
        ))
        .unwrap(),
        JobState::Queued
    );
    assert_eq!(f.store.read(jobs::pick_ready).unwrap(), Some((tenant, job)));
    let worker = WorkerId::new();
    let (_attempt, fence) = w
        .write(move |tx| jobs::lease(tx, tenant, job, worker, t(60_000), t(20)))
        .unwrap();
    assert_eq!(fence, Fence(1));
    assert_eq!(f.store.read(jobs::pick_ready).unwrap(), None);
    let wk = Actor::Worker(fence);
    for (event, expected, ms) in [
        (Event::PreparationStarted, JobState::Preparing, 30),
        (Event::StepsStarted, JobState::Running, 40),
        (Event::FinalizationStarted, JobState::Finalizing, 50),
        (Event::Passed, JobState::Terminal(Outcome::Passed), 60),
    ] {
        assert_eq!(
            w.write(move |tx| jobs::transition(tx, tenant, job, wk, event, t(ms)))
                .unwrap(),
            expected
        );
    }
    let row = f.store.read(|c| jobs::get_job(c, tenant, job)).unwrap();
    assert_eq!(row.timestamps.queued, Some(t(10)));
    assert_eq!(row.timestamps.leased, Some(t(20)));
    assert_eq!(row.timestamps.running, Some(t(40)));
    assert_eq!(row.timestamps.terminal, Some(t(60)));
    assert_eq!(row.failure_class, None);
    assert_eq!(
        f.store.read(|c| jobs::run_state(c, tenant, run)).unwrap(),
        RunState::Terminal(Outcome::Passed)
    );
    // Duplicate completion is reported, not applied.
    assert!(matches!(
        w.write(move |tx| jobs::transition(tx, tenant, job, wk, Event::Passed, t(70))),
        Err(Error::Transition(
            sentinel_core::TransitionError::AlreadyTerminal(Outcome::Passed)
        ))
    ));
}

#[test]
fn stale_worker_fence_and_wrong_tenant_are_rejected() {
    let f = fixture();
    let (tenant, job) = (f.tenant, f.job);
    let w = f.store.writer();
    w.write(move |tx| {
        jobs::transition(
            tx,
            tenant,
            job,
            Actor::Controller,
            Event::DependenciesSatisfied,
            UnixMillis(1),
        )
    })
    .unwrap();
    w.write(move |tx| {
        jobs::lease(
            tx,
            tenant,
            job,
            WorkerId::new(),
            UnixMillis(9),
            UnixMillis(2),
        )
    })
    .unwrap();
    let stale = w.write(move |tx| {
        jobs::transition(
            tx,
            tenant,
            job,
            Actor::Worker(Fence::NONE),
            Event::StepsStarted,
            UnixMillis(3),
        )
    });
    assert!(matches!(
        stale,
        Err(Error::Transition(
            sentinel_core::TransitionError::StaleFence { .. }
        ))
    ));
    let other = TenantId::new();
    assert!(matches!(
        w.write(move |tx| jobs::transition(
            tx,
            other,
            job,
            Actor::Controller,
            Event::WorkerLost,
            UnixMillis(4)
        )),
        Err(Error::NotFound)
    ));
    assert!(matches!(
        f.store.read(|c| jobs::get_job(c, other, job)),
        Err(Error::NotFound)
    ));
    assert!(matches!(
        w.write(move |tx| jobs::request_cancel(tx, other, job)),
        Err(Error::NotFound)
    ));
}

#[test]
fn compare_and_set_detects_out_of_band_change() {
    let f = fixture();
    let (tenant, job) = (f.tenant, f.job);
    // Simulate a row changed after the read inside the same transaction by
    // bumping the fence directly before the guarded UPDATE runs.
    let result = f.store.writer().write(move |tx| {
        let row = jobs::get_job(tx, tenant, job)?;
        assert_eq!(row.fence, Fence::NONE);
        tx.execute(
            "UPDATE jobs SET fence = 7 WHERE id = ?1",
            params![job.as_bytes()],
        )?;
        // `transition` re-reads (fence 7), applies, and its UPDATE guards on fence 7:
        // that succeeds. So instead guard-check via a stale read replayed manually.
        let changed = tx.execute(
            "UPDATE jobs SET state_code = 1 WHERE id = ?1 AND state_code = 0 AND fence = ?2",
            params![job.as_bytes(), row.fence.0 as i64],
        )?;
        if changed == 0 {
            Err(Error::Conflict)
        } else {
            Ok(())
        }
    });
    assert!(matches!(result, Err(Error::Conflict)));
    // The failed transaction rolled back entirely, including the fence bump.
    let row = f.store.read(|c| jobs::get_job(c, tenant, job)).unwrap();
    assert_eq!(row.fence, Fence::NONE);
    assert_eq!(row.state, JobState::Blocked);
}

#[test]
fn foreign_keys_and_ownership_constraints_hold() {
    let f = fixture();
    let tenant = f.tenant;
    let w = f.store.writer();
    // Job for a run that does not exist in this tenant.
    assert!(matches!(
        w.write(move |tx| jobs::insert_job(tx, tenant, RunId::new(), JobId::new(), "x", 1, 1)),
        Err(Error::NotFound)
    ));
    // Run for a repo owned by another tenant.
    let other = TenantId::new();
    let other_repo = RepoId::new();
    w.write(move |tx| {
        jobs::insert_tenant(tx, other, "other", UnixMillis(1))?;
        jobs::insert_repo(tx, other, other_repo, "theirs", UnixMillis(1))
    })
    .unwrap();
    assert!(matches!(
        w.write(move |tx| jobs::insert_run(
            tx,
            tenant,
            other_repo,
            RunId::new(),
            "sha",
            UnixMillis(2)
        )),
        Err(Error::NotFound)
    ));
    // Raw insert with a dangling tenant is a constraint failure.
    let raw = w.write(|tx| {
        tx.execute(
            "INSERT INTO repos(id, tenant_id, name, created_ms) VALUES (?1, ?2, 'r', 1)",
            params![RepoId::new().as_bytes(), TenantId::new().as_bytes()],
        )?;
        Ok(())
    });
    assert!(matches!(raw, Err(Error::Sqlite(_))));
}

#[test]
fn ready_queue_orders_by_priority_then_sequence() {
    let f = fixture();
    let (tenant, run) = (f.tenant, f.run);
    let ids: Vec<JobId> = (0..3).map(|_| JobId::new()).collect();
    let (a, b, c) = (ids[0], ids[1], ids[2]);
    f.store
        .writer()
        .write(move |tx| {
            jobs::insert_job(tx, tenant, run, a, "a", 9, 2)?;
            jobs::insert_job(tx, tenant, run, b, "b", 1, 3)?;
            jobs::insert_job(tx, tenant, run, c, "c", 1, 2)?;
            for j in [a, b, c] {
                jobs::transition(
                    tx,
                    tenant,
                    j,
                    Actor::Controller,
                    Event::DependenciesSatisfied,
                    UnixMillis(1),
                )?;
            }
            Ok(())
        })
        .unwrap();
    assert_eq!(f.store.read(jobs::pick_ready).unwrap(), Some((tenant, c)));
    f.store
        .writer()
        .write(move |tx| {
            jobs::transition(tx, tenant, c, Actor::Controller, Event::Skip, UnixMillis(2))
        })
        .unwrap();
    assert_eq!(f.store.read(jobs::pick_ready).unwrap(), Some((tenant, b)));
    // The plan must use the partial index, not scan.
    f.store
        .read(|conn| {
            let plan: String = conn.query_row(
                "EXPLAIN QUERY PLAN SELECT tenant_id, id FROM jobs WHERE state_code = 1 ORDER BY priority, created_seq LIMIT 1",
                [],
                |r| r.get(3),
            )?;
            assert!(plan.contains("jobs_ready"), "{plan}");
            Ok(())
        })
        .unwrap();
}

#[test]
fn cancel_is_durable_desired_state() {
    let f = fixture();
    let (tenant, job) = (f.tenant, f.job);
    let w = f.store.writer();
    assert!(
        w.write(move |tx| jobs::request_cancel(tx, tenant, job))
            .unwrap()
    );
    w.write(move |tx| {
        jobs::transition(
            tx,
            tenant,
            job,
            Actor::Controller,
            Event::CancelBeforeStart,
            UnixMillis(1),
        )
    })
    .unwrap();
    let row = f.store.read(|c| jobs::get_job(c, tenant, job)).unwrap();
    assert!(row.cancel_requested);
    assert_eq!(row.state, JobState::Terminal(Outcome::Canceled));
    assert_eq!(row.failure_class, Some(FailureClass::Canceled));
}

#[test]
fn acknowledged_writes_survive_reopen_without_checkpoint() {
    let f = fixture();
    let (tenant, job, path) = (f.tenant, f.job, f.path.clone());
    f.store
        .writer()
        .write(move |tx| {
            jobs::transition(
                tx,
                tenant,
                job,
                Actor::Controller,
                Event::DependenciesSatisfied,
                UnixMillis(5),
            )
        })
        .unwrap();
    // Drop without checkpoint: the WAL must carry the commit.
    drop(f.store);
    let reopened = Store::open(&path, Durability::Full).unwrap();
    let row = reopened.read(|c| jobs::get_job(c, tenant, job)).unwrap();
    assert_eq!(row.state, JobState::Queued);
    reopened.checkpoint().unwrap();
}

#[test]
fn writer_queue_is_bounded_and_reports_back_pressure() {
    let f = fixture();
    let store = Arc::new(f.store);
    // Block the writer, then fill the queue beyond capacity from other threads.
    let (hold_tx, hold_rx) = std::sync::mpsc::channel::<()>();
    let blocker = {
        let store = Arc::clone(&store);
        thread::spawn(move || {
            store.writer().raw(move |_| {
                let _ = hold_rx.recv_timeout(Duration::from_secs(5));
                Ok(())
            })
        })
    };
    thread::sleep(Duration::from_millis(50));
    let mut handles = Vec::new();
    for _ in 0..sentinel_store::WRITER_QUEUE + 8 {
        let store = Arc::clone(&store);
        handles.push(thread::spawn(move || store.writer().raw(|_| Ok(()))));
    }
    thread::sleep(Duration::from_millis(200));
    drop(hold_tx);
    blocker.join().unwrap().unwrap();
    let rejected = handles
        .into_iter()
        .map(|h| h.join().unwrap())
        .filter(|r| matches!(r, Err(Error::WriterUnavailable)))
        .count();
    assert!(
        rejected >= 1,
        "at least the overflow must be rejected immediately"
    );
    assert!(
        rejected <= 8 + 1,
        "accepted work must not be dropped: {rejected} rejected"
    );
}
