use sentinel_core::{
    Actor, Event, FailureClass, Fence, JobState, Outcome, RepoId, RunId, TenantId, UnixMillis,
    UserId, WorkerId,
};
use sentinel_pipeline::{PinnedSource, RunSpec, compile_str};
use sentinel_store::{
    Durability, Error, Store,
    auth::provisioning,
    jobs,
    provenance::{self, Provenance, RunActor},
    runs, status,
};

const DIGEST: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
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
    let (_, fence) = w
        .write(move |tx| {
            runs::resolve_image(tx, tenant, job, DIGEST, "linux/amd64")?;
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

#[test]
fn a_stored_run_spec_cannot_be_rewritten_even_by_raw_sql() {
    // Every attempt and rerun executes this blob; it is written once.
    let f = fx();
    let (tenant, repo, run) = (f.tenant, f.repo, RunId::new());
    let s = spec();
    let expected = s.clone();
    f.store
        .writer()
        .write(move |tx| runs::create_run(tx, tenant, repo, run, &s, UnixMillis(10)))
        .unwrap();
    for sql in [
        "UPDATE run_specs SET spec = x'04' WHERE run_id = ?1",
        "UPDATE run_specs SET digest = zeroblob(16) WHERE run_id = ?1",
        "UPDATE run_specs SET format = 3 WHERE run_id = ?1",
        "UPDATE run_specs SET spec = spec WHERE run_id = ?1",
    ] {
        let raw = f.store.writer().write(move |tx| {
            tx.execute(sql, [run.as_bytes().as_slice()])?;
            Ok(())
        });
        assert!(matches!(raw, Err(Error::Sqlite(_))), "{sql}: {raw:?}");
    }
    let stored = f
        .store
        .read(|c| runs::get_run_spec(c, tenant, run))
        .unwrap();
    assert_eq!(stored, expected);
}

fn provenance_of(f: &Fx, trigger: &str) -> Provenance {
    Provenance {
        tenant: f.tenant,
        repo: f.repo,
        trigger: trigger.into(),
        delivery: None,
        provider: None,
        ref_name: None,
        old_sha: None,
        new_sha: None,
        head_sha: None,
        base_sha: None,
        merge_sha: None,
        pipeline_sha: SHA.into(),
        pipeline_path: None,
        pipeline_digest: [3; 16],
        pr_number: None,
        group_ref: None,
    }
}

#[test]
fn a_manual_runs_actor_round_trips_and_a_webhook_runs_is_none() {
    let f = fx();
    let (tenant, alice, former) = (f.tenant, UserId::new(), UserId::new());
    f.store
        .writer()
        .write(move |tx| {
            provisioning::insert_human(tx, alice, "Alice Example", false, UnixMillis(1))?;
            provisioning::insert_human(tx, former, "Former Member", false, UnixMillis(1))?;
            tx.execute(
                "INSERT INTO memberships(tenant_id, user_id, role) VALUES (?1, ?2, 2)",
                rusqlite::params![tenant.as_bytes(), alice.as_bytes()],
            )?;
            Ok(())
        })
        .unwrap();
    let [manual, former_run, webhook] = [RunId::new(), RunId::new(), RunId::new()];
    let (repo, s) = (f.repo, spec());
    for (run, trigger, actor) in [
        (manual, "manual", Some(alice)),
        (former_run, "manual", Some(former)),
        (webhook, "push", None),
    ] {
        let (s, p) = (s.clone(), provenance_of(&f, trigger));
        f.store
            .writer()
            .write(move |tx| {
                runs::create_run(tx, tenant, repo, run, &s, UnixMillis(10))?;
                provenance::insert_with_actor(tx, &p, run, UnixMillis(10), actor)
            })
            .unwrap();
    }
    let view = |run| f.store.read(|c| status::run(c, tenant, run)).unwrap();
    assert_eq!(
        view(manual).actor,
        Some(RunActor {
            user: alice,
            display_name: Some("Alice Example".into())
        })
    );
    assert_eq!(view(manual).trigger.as_deref(), Some("manual"));
    assert_eq!(
        view(former_run).actor,
        Some(RunActor {
            user: former,
            display_name: None
        }),
        "an account that left the tenant keeps its id but not its name"
    );
    assert_eq!(view(webhook).actor, None);
    assert_eq!(view(webhook).trigger.as_deref(), Some("push"));
}

#[test]
fn another_tenant_reads_no_provenance_of_a_run() {
    let f = fx();
    let (tenant, repo, run, alice) = (f.tenant, f.repo, RunId::new(), UserId::new());
    let (s, p) = (spec(), provenance_of(&f, "manual"));
    f.store
        .writer()
        .write(move |tx| {
            runs::create_run(tx, tenant, repo, run, &s, UnixMillis(10))?;
            provenance::insert_with_actor(tx, &p, run, UnixMillis(10), Some(alice))
        })
        .unwrap();
    let other = TenantId::new();
    assert_eq!(
        f.store.read(|c| provenance::origin(c, other, run)).unwrap(),
        None
    );
    assert!(
        f.store
            .read(|c| provenance::origin(c, tenant, run))
            .unwrap()
            .is_some_and(|o| o.actor.is_some_and(|a| a.user == alice))
    );
}
