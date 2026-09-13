use sentinel_core::{
    Actor, Event, FailureClass, Fence, JobState, Outcome, RepoId, RunId, TenantId, UnixMillis,
    WorkerId,
};
use sentinel_pipeline::{PinnedSource, RunSpec, compile_str};
use sentinel_store::{Durability, Error, Store, jobs, runs};

const SHA: &str = "0c87e0181c794fe2bbfeb15dc34e7b6aae375d8b";

fn spec() -> RunSpec {
    let text = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/pipelines/valid/full.yml"
    ))
    .unwrap();
    RunSpec::new(
        PinnedSource::new("https://github.com/o/r.git", SHA, Some("main")).unwrap(),
        compile_str(&text).unwrap(),
    )
    .unwrap()
}

struct Fx {
    _dir: tempfile::TempDir,
    store: Store,
    tenant: TenantId,
    repo: RepoId,
}

fn fx() -> Fx {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path().join("m.sqlite"), Durability::Normal).unwrap();
    let (tenant, repo) = (TenantId::new(), RepoId::new());
    store
        .writer()
        .write(move |tx| {
            jobs::insert_tenant(tx, tenant, "acme", UnixMillis(1))?;
            jobs::insert_repo(tx, tenant, repo, "app", UnixMillis(1))
        })
        .unwrap();
    Fx {
        _dir: dir,
        store,
        tenant,
        repo,
    }
}

#[test]
fn create_run_persists_spec_and_seeds_job_states() {
    let f = fx();
    let (tenant, repo, run) = (f.tenant, f.repo, RunId::new());
    let s = spec();
    let s2 = s.clone();
    let ids = f
        .store
        .writer()
        .write(move |tx| runs::create_run(tx, tenant, repo, run, &s2, UnixMillis(10)))
        .unwrap();
    assert_eq!(ids.len(), 2);
    let stored = f
        .store
        .read(|c| runs::get_run_spec(c, tenant, run))
        .unwrap();
    assert_eq!(stored, s);
    let states = f.store.read(|c| runs::run_jobs(c, tenant, run)).unwrap();
    assert_eq!(
        states[0],
        (ids[0], JobState::Queued),
        "no dependencies: queued"
    );
    assert_eq!(
        states[1],
        (ids[1], JobState::Blocked),
        "needs test: blocked"
    );
    assert_eq!(
        f.store.read(jobs::pick_ready).unwrap(),
        Some((tenant, ids[0]))
    );
    // Other tenants see nothing.
    let other = TenantId::new();
    assert!(matches!(
        f.store.read(|c| runs::get_run_spec(c, other, run)),
        Err(Error::NotFound)
    ));
}

#[test]
fn spec_is_written_once_per_run() {
    let f = fx();
    let (tenant, repo, run) = (f.tenant, f.repo, RunId::new());
    let s = spec();
    let s2 = s.clone();
    f.store
        .writer()
        .write(move |tx| runs::create_run(tx, tenant, repo, run, &s2, UnixMillis(10)))
        .unwrap();
    let again = f
        .store
        .writer()
        .write(move |tx| runs::create_run(tx, tenant, repo, run, &s, UnixMillis(11)));
    assert!(
        matches!(again, Err(Error::Sqlite(_))),
        "same run id cannot be re-created"
    );
    // The failed transaction left the original spec and jobs intact.
    assert_eq!(
        f.store
            .read(|c| runs::run_jobs(c, tenant, run))
            .unwrap()
            .len(),
        2
    );
}

#[test]
fn rerun_is_a_new_attempt_of_the_same_spec() {
    let f = fx();
    let (tenant, repo, run) = (f.tenant, f.repo, RunId::new());
    let s = spec();
    let ids = f
        .store
        .writer()
        .write(move |tx| runs::create_run(tx, tenant, repo, run, &s, UnixMillis(10)))
        .unwrap();
    let job = ids[0];
    let w = f.store.writer();
    // Attempt 1 fails.
    let (_, fence) = w
        .write(move |tx| {
            jobs::lease(
                tx,
                tenant,
                job,
                WorkerId::new(),
                UnixMillis(99),
                UnixMillis(20),
            )
        })
        .unwrap();
    assert_eq!(fence, Fence(1));
    w.write(move |tx| {
        jobs::transition(
            tx,
            tenant,
            job,
            Actor::Worker(fence),
            Event::StepsStarted,
            UnixMillis(30),
        )?;
        jobs::transition(
            tx,
            tenant,
            job,
            Actor::Worker(fence),
            Event::Failed(FailureClass::CommandFailed),
            UnixMillis(40),
        )
    })
    .unwrap();
    // Rerun: queued again, history cleared, fence kept.
    assert_eq!(
        w.write(move |tx| runs::rerun_job(tx, tenant, job, UnixMillis(50)))
            .unwrap(),
        JobState::Queued
    );
    let row = f.store.read(|c| jobs::get_job(c, tenant, job)).unwrap();
    assert_eq!(row.fence, Fence(1));
    assert_eq!(row.failure_class, None);
    assert_eq!(row.timestamps.queued, Some(UnixMillis(50)));
    assert_eq!(row.timestamps.running, None);
    assert_eq!(row.timestamps.terminal, None);
    // Attempt 2 gets fence 2; the old worker's fence is now stale.
    let (_, fence2) = w
        .write(move |tx| {
            jobs::lease(
                tx,
                tenant,
                job,
                WorkerId::new(),
                UnixMillis(99),
                UnixMillis(60),
            )
        })
        .unwrap();
    assert_eq!(fence2, Fence(2));
    assert!(matches!(
        w.write(move |tx| jobs::transition(
            tx,
            tenant,
            job,
            Actor::Worker(fence),
            Event::Passed,
            UnixMillis(70)
        )),
        Err(Error::Transition(
            sentinel_core::TransitionError::StaleFence { .. }
        ))
    ));
    // The spec never changed.
    assert_eq!(
        f.store
            .read(|c| runs::get_run_spec(c, tenant, run))
            .unwrap(),
        spec()
    );
}

#[test]
fn rerun_refuses_running_and_cancelled_jobs() {
    let f = fx();
    let (tenant, repo, run) = (f.tenant, f.repo, RunId::new());
    let s = spec();
    let ids = f
        .store
        .writer()
        .write(move |tx| runs::create_run(tx, tenant, repo, run, &s, UnixMillis(10)))
        .unwrap();
    let (queued, blocked) = (ids[0], ids[1]);
    let w = f.store.writer();
    assert!(matches!(
        w.write(move |tx| runs::rerun_job(tx, tenant, queued, UnixMillis(20))),
        Err(Error::Transition(
            sentinel_core::TransitionError::Forbidden { .. }
        ))
    ));
    w.write(move |tx| {
        jobs::request_cancel(tx, tenant, blocked)?;
        jobs::transition(
            tx,
            tenant,
            blocked,
            Actor::Controller,
            Event::CancelBeforeStart,
            UnixMillis(21),
        )
    })
    .unwrap();
    assert!(matches!(
        w.write(move |tx| runs::rerun_job(tx, tenant, blocked, UnixMillis(22))),
        Err(Error::Transition(
            sentinel_core::TransitionError::Invalid { .. }
        ))
    ));
    let row = f.store.read(|c| jobs::get_job(c, tenant, blocked)).unwrap();
    assert_eq!(row.state, JobState::Terminal(Outcome::Canceled));
}
