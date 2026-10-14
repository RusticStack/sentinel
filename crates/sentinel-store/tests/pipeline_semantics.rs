//! Job conditions, failure propagation and rerun semantics of the schedule
//! phase: what the controller decides for a blocked job once its dependencies
//! have finished (docs/pipeline-schema.md, "Job conditions").
use sentinel_core::{
    Actor, Event, FailureClass, JobId, JobState, Outcome, RepoId, RunId, RunState, TenantId,
    UnixMillis, aggregate,
};
use sentinel_pipeline::{Expr, PinnedSource, RunSpec, compile_str};
use sentinel_store::{
    Durability, Store, dispatch, jobs,
    provenance::{self, Provenance},
    runs, status,
};

const SHA: &str = "0c87e0181c794fe2bbfeb15dc34e7b6aae375d8b";

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

fn spec_of(jobs_yaml: &str) -> RunSpec {
    let text = format!("schema: 1\non: [push]\njobs:\n{jobs_yaml}");
    RunSpec::new(
        PinnedSource::new("https://github.com/o/r.git", SHA, Some("main")).unwrap(),
        compile_str(&text).unwrap(),
    )
    .unwrap()
}

const STEPS: &str = "image: busybox, steps: [{id: s, run: x}]";

/// A run as an event-driven dispatch creates it: the run, the event it
/// carries, then the release of whatever is decidable.
fn start(f: &Fx, spec: &RunSpec, ref_name: Option<&str>) -> (RunId, Vec<JobId>) {
    let (tenant, repo, run) = (f.tenant, f.repo, RunId::new());
    let spec = spec.clone();
    let ref_name = ref_name.map(str::to_owned);
    let ids = f
        .store
        .writer()
        .write(move |tx| {
            let ids = runs::create_run(tx, tenant, repo, run, &spec, UnixMillis(10))?;
            if let Some(ref_name) = ref_name {
                provenance::insert(
                    tx,
                    &Provenance {
                        tenant,
                        repo,
                        trigger: "push".into(),
                        delivery: None,
                        provider: None,
                        ref_name: Some(ref_name),
                        old_sha: None,
                        new_sha: Some(SHA.into()),
                        head_sha: None,
                        base_sha: None,
                        merge_sha: None,
                        pipeline_sha: SHA.into(),
                        pipeline_path: None,
                        pipeline_digest: [0; 16],
                        pr_number: None,
                    },
                    run,
                    UnixMillis(10),
                )?;
            }
            dispatch::release_dependents(tx, tenant, run, UnixMillis(11))?;
            Ok(ids)
        })
        .unwrap();
    (run, ids)
}

fn id_of(spec: &RunSpec, ids: &[JobId], name: &str) -> JobId {
    let index = spec
        .pipeline
        .jobs
        .iter()
        .position(|j| j.name == name)
        .unwrap();
    ids[index]
}

fn state(f: &Fx, job: JobId) -> JobState {
    let tenant = f.tenant;
    f.store
        .read(move |c| jobs::get_job(c, tenant, job))
        .unwrap()
        .state
}

/// Run a queued job to its end the way a worker would, then decide its
/// dependents, as the controller does when an attempt finishes.
fn finish(f: &Fx, run: RunId, job: JobId, passed: bool, at: i64) {
    let tenant = f.tenant;
    f.store
        .writer()
        .write(move |tx| {
            let fence = jobs::get_job(tx, tenant, job)?.fence.next();
            let now = UnixMillis(at);
            jobs::transition(
                tx,
                tenant,
                job,
                Actor::Controller,
                Event::Leased(fence),
                now,
            )?;
            let worker = Actor::Worker(fence);
            jobs::transition(tx, tenant, job, worker, Event::StepsStarted, now)?;
            if passed {
                jobs::transition(tx, tenant, job, worker, Event::FinalizationStarted, now)?;
                jobs::transition(tx, tenant, job, worker, Event::Passed, now)?;
            } else {
                let failed = Event::Failed(FailureClass::CommandFailed);
                jobs::transition(tx, tenant, job, worker, failed, now)?;
            }
            dispatch::release_dependents(tx, tenant, run, now)?;
            Ok(())
        })
        .unwrap();
}

fn skipped() -> JobState {
    JobState::Terminal(Outcome::Skipped)
}

#[test]
fn a_job_with_an_if_never_starts_queued_before_its_event_is_known() {
    let f = fx();
    let spec = spec_of(&format!(
        "  deploy: {{{STEPS}, if: \"event.ref == 'refs/heads/main'\"}}\n  build: {{{STEPS}}}\n"
    ));
    let (tenant, repo, run) = (f.tenant, f.repo, RunId::new());
    let s = spec.clone();
    let ids = f
        .store
        .writer()
        .write(move |tx| runs::create_run(tx, tenant, repo, run, &s, UnixMillis(10)))
        .unwrap();
    assert_eq!(state(&f, id_of(&spec, &ids, "build")), JobState::Queued);
    assert_eq!(
        state(&f, id_of(&spec, &ids, "deploy")),
        JobState::Blocked,
        "its condition reads the event, which is recorded after the run row"
    );
}

#[test]
fn a_job_if_is_decided_against_the_runs_event() {
    let f = fx();
    let spec = spec_of(&format!(
        "  deploy: {{{STEPS}, if: \"event.ref == 'refs/heads/main'\"}}\n  build: {{{STEPS}}}\n"
    ));
    let (_, on_branch) = start(&f, &spec, Some("refs/heads/feature"));
    assert_eq!(state(&f, id_of(&spec, &on_branch, "deploy")), skipped());
    assert_eq!(
        state(&f, id_of(&spec, &on_branch, "build")),
        JobState::Queued
    );
    let (_, on_main) = start(&f, &spec, Some("refs/heads/main"));
    assert_eq!(
        state(&f, id_of(&spec, &on_main, "deploy")),
        JobState::Queued
    );
}

#[test]
fn always_runs_after_a_failure_and_a_plain_if_does_not() {
    let f = fx();
    let spec = spec_of(&format!(
        "  test: {{{STEPS}}}\n  cleanup: {{{STEPS}, needs: [test], if: \"always()\"}}\n  \
         deploy: {{{STEPS}, needs: [test], if: \"event.ref == 'refs/heads/main'\"}}\n  \
         notify: {{{STEPS}, needs: [test], if: \"failure()\"}}\n  \
         plain: {{{STEPS}, needs: [test]}}\n"
    ));
    let (run, ids) = start(&f, &spec, Some("refs/heads/main"));
    let test = id_of(&spec, &ids, "test");
    assert_eq!(state(&f, id_of(&spec, &ids, "cleanup")), JobState::Blocked);
    finish(&f, run, test, false, 20);
    assert_eq!(state(&f, id_of(&spec, &ids, "cleanup")), JobState::Queued);
    assert_eq!(state(&f, id_of(&spec, &ids, "notify")), JobState::Queued);
    // The event matches, but without a status function the dependency must
    // also have succeeded; so for a job with no `if` at all.
    assert_eq!(state(&f, id_of(&spec, &ids, "deploy")), skipped());
    assert_eq!(state(&f, id_of(&spec, &ids, "plain")), skipped());
}

#[test]
fn a_passing_dependency_runs_the_plain_if_and_skips_failure() {
    let f = fx();
    let spec = spec_of(&format!(
        "  test: {{{STEPS}}}\n  deploy: {{{STEPS}, needs: [test], if: \"event.ref == 'refs/heads/main'\"}}\n  \
         notify: {{{STEPS}, needs: [test], if: \"failure()\"}}\n"
    ));
    let (run, ids) = start(&f, &spec, Some("refs/heads/main"));
    finish(&f, run, id_of(&spec, &ids, "test"), true, 20);
    assert_eq!(state(&f, id_of(&spec, &ids, "deploy")), JobState::Queued);
    assert_eq!(state(&f, id_of(&spec, &ids, "notify")), skipped());
}

#[test]
fn a_conditional_job_waits_for_every_dependency_before_deciding() {
    let f = fx();
    let spec = spec_of(&format!(
        "  a: {{{STEPS}}}\n  b: {{{STEPS}}}\n  cleanup: {{{STEPS}, needs: [a, b], if: \"always()\"}}\n"
    ));
    let (run, ids) = start(&f, &spec, Some("refs/heads/main"));
    finish(&f, run, id_of(&spec, &ids, "a"), false, 20);
    assert_eq!(
        state(&f, id_of(&spec, &ids, "cleanup")),
        JobState::Blocked,
        "b is still queued: always() needs the whole picture"
    );
    finish(&f, run, id_of(&spec, &ids, "b"), true, 30);
    assert_eq!(state(&f, id_of(&spec, &ids, "cleanup")), JobState::Queued);
}

#[test]
fn a_dependency_result_can_be_named_in_the_condition() {
    let f = fx();
    let spec = spec_of(&format!(
        "  test: {{{STEPS}}}\n  report: {{{STEPS}, needs: [test], if: \"always() && needs.test.result == 'failed'\"}}\n"
    ));
    let (run, ids) = start(&f, &spec, Some("refs/heads/main"));
    finish(&f, run, id_of(&spec, &ids, "test"), false, 20);
    assert_eq!(state(&f, id_of(&spec, &ids, "report")), JobState::Queued);
}

#[test]
fn a_skip_caused_by_a_failure_does_not_release_the_chain_behind_it() {
    let f = fx();
    let spec = spec_of(&format!(
        "  test: {{{STEPS}}}\n  build: {{{STEPS}, needs: [test]}}\n  deploy: {{{STEPS}, needs: [build]}}\n"
    ));
    let (run, ids) = start(&f, &spec, Some("refs/heads/main"));
    finish(&f, run, id_of(&spec, &ids, "test"), false, 20);
    assert_eq!(state(&f, id_of(&spec, &ids, "build")), skipped());
    assert_eq!(
        state(&f, id_of(&spec, &ids, "deploy")),
        skipped(),
        "deploy must not run because build was skipped for a failed test"
    );
}

#[test]
fn a_skip_by_the_jobs_own_condition_still_releases_what_follows() {
    let f = fx();
    let spec = spec_of(&format!(
        "  optional: {{{STEPS}, if: \"event.ref == 'refs/heads/main'\"}}\n  after: {{{STEPS}, needs: [optional]}}\n"
    ));
    let (_, ids) = start(&f, &spec, Some("refs/heads/feature"));
    assert_eq!(state(&f, id_of(&spec, &ids, "optional")), skipped());
    assert_eq!(
        state(&f, id_of(&spec, &ids, "after")),
        JobState::Queued,
        "an optional branch that was not taken does not drag the DAG"
    );
}

#[test]
fn a_condition_that_cannot_be_evaluated_fails_the_job_instead_of_guessing() {
    let f = fx();
    let text = format!("schema: 1\non: [push]\njobs:\n  gated: {{{STEPS}}}\n");
    let mut pipeline = compile_str(&text).unwrap();
    // The compiler types every condition; a spec stored before it did can
    // still carry one that fails at evaluation.
    pipeline.jobs[0].spec.condition = Some(Expr::parse("event.ref == 7").unwrap());
    let spec = RunSpec::new(
        PinnedSource::new("https://github.com/o/r.git", SHA, Some("main")).unwrap(),
        pipeline,
    )
    .unwrap();
    let (_, ids) = start(&f, &spec, Some("refs/heads/main"));
    let tenant = f.tenant;
    let job = ids[0];
    let row = f
        .store
        .read(move |c| jobs::get_job(c, tenant, job))
        .unwrap();
    assert_eq!(row.state, JobState::Terminal(Outcome::InfraFailed));
    assert_eq!(row.failure_class, Some(FailureClass::Preparation));
}

#[test]
fn a_cancelled_run_records_it_and_a_rerun_resumes_it() {
    let f = fx();
    let spec = spec_of(&format!(
        "  test: {{{STEPS}}}\n  cleanup: {{{STEPS}, needs: [test], if: \"always()\"}}\n"
    ));
    let (run, ids) = start(&f, &spec, Some("refs/heads/main"));
    let (tenant, test) = (f.tenant, id_of(&spec, &ids, "test"));
    finish(&f, run, test, false, 20);
    let cleanup = id_of(&spec, &ids, "cleanup");
    finish(&f, run, cleanup, true, 30);
    let flag = |f: &Fx| {
        let tenant = f.tenant;
        f.store
            .read(move |c| status::run(c, tenant, run))
            .unwrap()
            .cancel_requested
    };
    assert!(!flag(&f));
    f.store
        .writer()
        .write(move |tx| dispatch::cancel_run(tx, tenant, run, UnixMillis(40)))
        .unwrap();
    assert!(flag(&f), "cancelling the run is durable desired state");
    f.store
        .writer()
        .write(move |tx| runs::rerun_job(tx, tenant, test, UnixMillis(50)))
        .unwrap();
    assert!(!flag(&f), "a rerun resumes the run");
}

#[test]
fn a_rerun_revives_the_dependents_skipped_for_the_failure_it_replaces() {
    let f = fx();
    let spec = spec_of(&format!(
        "  test: {{{STEPS}}}\n  build: {{{STEPS}, needs: [test]}}\n  deploy: {{{STEPS}, needs: [build]}}\n  \
         cleanup: {{{STEPS}, needs: [test], if: \"always()\"}}\n"
    ));
    let (run, ids) = start(&f, &spec, Some("refs/heads/main"));
    let [test, build, deploy, cleanup] =
        ["test", "build", "deploy", "cleanup"].map(|n| id_of(&spec, &ids, n));
    finish(&f, run, test, false, 20);
    finish(&f, run, cleanup, true, 30);
    assert_eq!(
        (state(&f, build), state(&f, deploy)),
        (skipped(), skipped())
    );
    let tenant = f.tenant;
    let outcome = |f: &Fx| {
        let states = f
            .store
            .read(move |c| runs::run_jobs(c, tenant, run))
            .unwrap();
        aggregate(states.into_iter().map(|(_, s)| s))
    };
    assert_eq!(outcome(&f), RunState::Terminal(Outcome::Failed));

    f.store
        .writer()
        .write(move |tx| runs::rerun_job(tx, tenant, test, UnixMillis(40)))
        .unwrap();
    assert_eq!(state(&f, test), JobState::Queued);
    assert_eq!(
        state(&f, build),
        JobState::Blocked,
        "decided again, not stuck"
    );
    assert_eq!(
        state(&f, deploy),
        JobState::Blocked,
        "the whole skipped chain"
    );
    assert_eq!(
        state(&f, cleanup),
        JobState::Terminal(Outcome::Passed),
        "a dependent that ran keeps its result"
    );
    assert_eq!(
        outcome(&f),
        RunState::Active,
        "the run is not passed while a required job has not run"
    );

    finish(&f, run, test, true, 50);
    assert_eq!(state(&f, build), JobState::Queued);
    assert_eq!(
        state(&f, deploy),
        JobState::Blocked,
        "deploy still waits for build"
    );
    finish(&f, run, build, true, 60);
    finish(&f, run, deploy, true, 70);
    assert_eq!(outcome(&f), RunState::Terminal(Outcome::Passed));
}

#[test]
fn a_rerun_that_fails_again_skips_the_revived_dependents_again() {
    let f = fx();
    let spec = spec_of(&format!(
        "  test: {{{STEPS}}}\n  deploy: {{{STEPS}, needs: [test]}}\n"
    ));
    let (run, ids) = start(&f, &spec, Some("refs/heads/main"));
    let (test, deploy) = (id_of(&spec, &ids, "test"), id_of(&spec, &ids, "deploy"));
    finish(&f, run, test, false, 20);
    let tenant = f.tenant;
    f.store
        .writer()
        .write(move |tx| runs::rerun_job(tx, tenant, test, UnixMillis(30)))
        .unwrap();
    assert_eq!(state(&f, deploy), JobState::Blocked);
    finish(&f, run, test, false, 40);
    assert_eq!(state(&f, deploy), skipped());
}
