//! Checks outbox store behavior: it coalesces one row per (run, scope),
//! the stable aggregate follows the run, a settled event still owes a
//! completed check, and publications are retried and guarded against stale
//! writes.
use rusqlite::Connection;
use sentinel_auth::sealed::Key;
use sentinel_core::{
    DeliveryId, Fence, JobId, RepoId, RunId, TenantId, UnixMillis, UserId,
    auth::{Namespace, Permissions, Principal},
    state::{Actor, Event, FailureClass, JobState},
};
use sentinel_pipeline::{PinnedSource, RunSpec, compile_str};
use sentinel_protocol::source::{Binding, Credential};
use sentinel_store::{
    Error,
    auth::{self, NamespaceKind, provisioning},
    checks::{self, Conclusion, Status},
    intake::{self, NewDelivery, PrTerms},
    provenance::{self, Provenance},
    registration::{self, Authority},
    runs, sources,
    sources_forge::{self, Snapshot},
};

const NOW: UnixMillis = UnixMillis(1_000);
const REF: &str = "refs/heads/main";
const SHA_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const SHA_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const GITHUB_REPO_ID: u64 = 91;
const IMAGE: &str = "docker.io/library/busybox@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662";

struct Fixture {
    conn: Connection,
    _key: Key,
    _dir: tempfile::TempDir,
    alice: Principal,
    tenant: TenantId,
    repo: RepoId,
    generic: RepoId,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("key");
    Key::create(&path).unwrap();
    let key = Key::load(&path).unwrap();
    let mut conn = Connection::open_in_memory().unwrap();
    conn.execute_batch("PRAGMA foreign_keys=ON").unwrap();
    sentinel_store::migrate(&mut conn).unwrap();
    let alice = Principal::new(UserId::new(), Permissions::ALL, None, None);
    let (tenant, repo, generic) = (TenantId::new(), RepoId::new(), RepoId::new());
    let tx = conn.transaction().unwrap();
    provisioning::insert_human(&tx, alice.user, "alice", true, NOW).unwrap();
    auth::create_namespace(
        &tx,
        alice,
        tenant,
        Namespace::parse("acme").unwrap(),
        NamespaceKind::Personal(alice.user),
        NOW,
    )
    .unwrap();
    auth::create_repo(&tx, alice, tenant, repo, "app", NOW).unwrap();
    auth::create_repo(&tx, alice, tenant, generic, "generic", NOW).unwrap();
    let installation = sources_forge::refresh(
        &tx,
        Snapshot {
            external_id: 42,
            account_id: 73,
            login: "account",
            personal: false,
            suspended: false,
            permissions_valid: true,
            expected: 0,
        },
        NOW,
    )
    .unwrap();
    registration::bind_installation_trusted(&tx, installation, tenant, NOW).unwrap();
    let mut binding = Binding {
        remote: "https://git.example:8443/team/repo.git".into(),
        allowed_refs: vec![REF.into(), "refs/tags/v1".into()],
        pipeline_path: ".sentinel.yml".into(),
        trust: String::new(),
    };
    sources::bind(
        &tx,
        Authority::HostLocal,
        Some(alice.user),
        sources::Update {
            repo: generic,
            expected: 0,
            binding: &binding,
            credential: &Credential::Https {
                username: "deploy".into(),
                secret: "deploy-token".into(),
            },
            forge: None,
        },
        &["https://git.example:8443".into()],
        &key,
        NOW,
    )
    .unwrap();
    binding.remote = "https://github.com/account/app.git".into();
    sources::bind(
        &tx,
        Authority::HostLocal,
        Some(alice.user),
        sources::Update {
            repo,
            expected: 0,
            binding: &binding,
            credential: &Credential::Public,
            forge: Some((installation, GITHUB_REPO_ID)),
        },
        &["https://github.com".into()],
        &key,
        NOW,
    )
    .unwrap();
    tx.commit().unwrap();
    Fixture {
        conn,
        _key: key,
        _dir: dir,
        alice,
        tenant,
        repo,
        generic,
    }
}

fn spec(remote: &str) -> RunSpec {
    let yaml = format!(
        "schema: 1\non: [push]\njobs:\n  build:\n    image: {IMAGE}\n    steps: [{{ id: s, run: 'true' }}]\n  test:\n    image: {IMAGE}\n    needs: [build]\n    steps: [{{ id: s, run: 'true' }}]\n"
    );
    RunSpec::new(
        PinnedSource::new(remote, SHA_B, Some(REF)).unwrap(),
        compile_str(&yaml).unwrap(),
    )
    .unwrap()
}

/// Create a run with manual provenance (which publishes nothing) or event
/// provenance (which publishes the aggregate and a check per job).
fn create_run(f: &mut Fixture, repo: RepoId, event: bool) -> (RunId, Vec<JobId>) {
    let run = RunId::new();
    let remote = sources::metadata_trusted(&f.conn, repo)
        .unwrap()
        .binding
        .remote;
    let spec = spec(&remote);
    let tx = f.conn.transaction().unwrap();
    let jobs = runs::create_run(&tx, f.tenant, repo, run, &spec, NOW).unwrap();
    if event {
        provenance::insert(
            &tx,
            &Provenance {
                tenant: f.tenant,
                repo,
                trigger: "push".into(),
                delivery: None,
                provider: None,
                ref_name: Some(REF.into()),
                old_sha: Some(SHA_A.into()),
                new_sha: Some(SHA_B.into()),
                head_sha: None,
                base_sha: None,
                merge_sha: None,
                pipeline_sha: SHA_B.into(),
                pipeline_path: Some(".sentinel.yml".into()),
                pipeline_digest: spec.pipeline.digest.to_le_bytes(),
                pr_number: None,
            },
            run,
            NOW,
        )
        .unwrap();
    }
    // As `intake::dispatch` and the API route do: rows appear once provenance
    // says whether this is an event-driven run.
    checks::record_run(&tx, f.tenant, run, NOW).unwrap();
    tx.commit().unwrap();
    (run, jobs)
}

fn step(f: &mut Fixture, job: JobId, event: Event, at: i64) -> JobState {
    step_as(f, job, Actor::Controller, event, at)
}

fn step_as(f: &mut Fixture, job: JobId, actor: Actor, event: Event, at: i64) -> JobState {
    let tx = f.conn.transaction().unwrap();
    let state =
        sentinel_store::jobs::transition(&tx, f.tenant, job, actor, event, UnixMillis(at)).unwrap();
    tx.commit().unwrap();
    state
}

fn publication(f: &Fixture, run: RunId, scope: &str) -> checks::Publication {
    checks::of_run(&f.conn, f.tenant, run)
        .unwrap()
        .into_iter()
        .find(|p| p.scope == scope)
        .unwrap_or_else(|| panic!("no publication for {scope}"))
}

fn accept(f: &mut Fixture, repo: RepoId, id: &str, ref_name: &str) -> DeliveryId {
    let tx = f.conn.transaction().unwrap();
    let accepted = intake::accept(
        &tx,
        repo,
        &NewDelivery {
            provider: "generic",
            external_id: id,
            event: "ref_update",
            ref_name,
            old_sha: SHA_A,
            new_sha: SHA_B,
        },
        None,
        NOW,
    )
    .unwrap()
    .id();
    tx.commit().unwrap();
    accepted
}

fn settle(f: &mut Fixture, delivery: DeliveryId, resolution: intake::Resolution) {
    let tx = f.conn.transaction().unwrap();
    intake::settle(&tx, delivery, resolution, NOW).unwrap();
    tx.commit().unwrap();
}

#[test]
fn a_run_gets_a_stable_aggregate_and_one_check_per_job() {
    let mut f = fixture();
    let (run, jobs) = {
        let repo = f.repo;
        create_run(&mut f, repo, true)
    };
    let rows = checks::of_run(&f.conn, f.tenant, run).unwrap();
    assert_eq!(rows.len(), 3, "two jobs and the aggregate");
    let aggregate = publication(&f, run, checks::AGGREGATE_SCOPE);
    assert_eq!(aggregate.name, checks::AGGREGATE_NAME);
    assert_eq!(aggregate.status, Status::Queued);
    assert!(aggregate.conclusion.is_none());
    assert_eq!(aggregate.head_sha, SHA_B);
    assert_eq!(aggregate.external_id, format!("sentinel:{run}:aggregate"));
    for (name, job) in [("build", jobs[0]), ("test", jobs[1])] {
        let row = publication(&f, run, &job.to_string());
        assert_eq!(row.name, format!("sentinel / {name}"));
        assert_eq!(row.status, Status::Queued);
        assert_eq!(row.external_id, format!("sentinel:{run}:{job}"));
    }
    // A generic repository gets no rows at all.
    let (plain, _) = {
        let generic = f.generic;
        create_run(&mut f, generic, true)
    };
    assert!(
        checks::of_run(&f.conn, f.tenant, plain).unwrap().is_empty(),
        "a generic run publishes nothing"
    );
}

#[test]
fn job_transitions_move_their_check_and_the_aggregate() {
    let mut f = fixture();
    let (run, jobs) = {
        let repo = f.repo;
        create_run(&mut f, repo, true)
    };
    let (build, test) = (jobs[0], jobs[1]);

    assert_eq!(
        step(&mut f, build, Event::Leased(Fence(1)), NOW.0 + 1),
        JobState::Leased
    );
    // A leased job is already being handed to a worker, which is what the
    // run-level aggregate says too.
    assert_eq!(
        publication(&f, run, &build.to_string()).status,
        Status::InProgress
    );
    step_as(
        &mut f,
        build,
        Actor::Worker(Fence(1)),
        Event::PreparationStarted,
        NOW.0 + 2,
    );
    assert_eq!(
        publication(&f, run, &build.to_string()).status,
        Status::InProgress
    );
    assert_eq!(
        publication(&f, run, checks::AGGREGATE_SCOPE).status,
        Status::InProgress
    );
    step_as(
        &mut f,
        build,
        Actor::Worker(Fence(1)),
        Event::StepsStarted,
        NOW.0 + 3,
    );
    step_as(
        &mut f,
        build,
        Actor::Worker(Fence(1)),
        Event::FinalizationStarted,
        NOW.0 + 4,
    );
    step_as(
        &mut f,
        build,
        Actor::Worker(Fence(1)),
        Event::Passed,
        NOW.0 + 5,
    );
    let done = publication(&f, run, &build.to_string());
    assert_eq!(done.status, Status::Completed);
    assert_eq!(done.conclusion, Some(Conclusion::Success));
    assert_eq!(done.title, "Passed");
    // The aggregate is still running while `test` is unfinished.
    assert_eq!(
        publication(&f, run, checks::AGGREGATE_SCOPE).status,
        Status::InProgress
    );
    // The dependency released `test` (as `release_dependents` does on
    // completion); it then fails for its own reason.
    step(&mut f, test, Event::DependenciesSatisfied, NOW.0 + 5);
    assert_eq!(
        publication(&f, run, &test.to_string()).status,
        Status::Queued
    );
    step(&mut f, test, Event::Leased(Fence(1)), NOW.0 + 6);
    step_as(
        &mut f,
        test,
        Actor::Worker(Fence(1)),
        Event::PreparationStarted,
        NOW.0 + 7,
    );
    step_as(
        &mut f,
        test,
        Actor::Worker(Fence(1)),
        Event::StepsStarted,
        NOW.0 + 8,
    );
    step_as(
        &mut f,
        test,
        Actor::Worker(Fence(1)),
        Event::Failed(FailureClass::CommandFailed),
        NOW.0 + 9,
    );
    let failed = publication(&f, run, &test.to_string());
    assert_eq!(failed.conclusion, Some(Conclusion::Failure));
    assert_eq!(failed.title, "Failed");
    assert!(
        failed.summary.contains("a command exited non-zero"),
        "{}",
        failed.summary
    );
    let aggregate = publication(&f, run, checks::AGGREGATE_SCOPE);
    assert_eq!(aggregate.status, Status::Completed);
    assert_eq!(aggregate.conclusion, Some(Conclusion::Failure));
    assert_eq!(aggregate.title, "Failed");
    assert!(
        aggregate.summary.contains("1/2 jobs passed"),
        "{}",
        aggregate.summary
    );
    assert!(
        aggregate.seq >= 3,
        "every change of content is a generation"
    );
    assert_eq!(aggregate.published_seq, 0);

    // A timeout is its own conclusion; cancellation another.
    let (other, other_jobs) = {
        let repo = f.repo;
        create_run(&mut f, repo, true)
    };
    let job = other_jobs[0];
    step(&mut f, job, Event::Leased(Fence(1)), NOW.0 + 10);
    step_as(
        &mut f,
        job,
        Actor::Worker(Fence(1)),
        Event::PreparationStarted,
        NOW.0 + 11,
    );
    step_as(
        &mut f,
        job,
        Actor::Worker(Fence(1)),
        Event::Failed(FailureClass::ExecutionTimeout),
        NOW.0 + 12,
    );
    assert_eq!(
        publication(&f, other, &job.to_string()).conclusion,
        Some(Conclusion::TimedOut)
    );
    let (third, third_jobs) = {
        let repo = f.repo;
        create_run(&mut f, repo, true)
    };
    step(&mut f, third_jobs[0], Event::CancelBeforeStart, NOW.0 + 13);
    let cancelled = publication(&f, third, &third_jobs[0].to_string());
    assert_eq!(cancelled.conclusion, Some(Conclusion::Cancelled));
    // A skipped job is skipped, and the aggregate with every job skipped is
    // skipped rather than pending.
    let (fourth, fourth_jobs) = {
        let repo = f.repo;
        create_run(&mut f, repo, true)
    };
    step(&mut f, fourth_jobs[0], Event::Skip, NOW.0 + 14);
    step(&mut f, fourth_jobs[1], Event::Skip, NOW.0 + 15);
    assert_eq!(
        publication(&f, fourth, &fourth_jobs[0].to_string()).conclusion,
        Some(Conclusion::Skipped)
    );
    assert_eq!(
        publication(&f, fourth, checks::AGGREGATE_SCOPE).conclusion,
        Some(Conclusion::Skipped)
    );
}

#[test]
fn a_manual_run_never_satisfies_the_required_aggregate() {
    let mut f = fixture();
    let (run, _) = {
        let repo = f.repo;
        create_run(&mut f, repo, false)
    };
    let rows = checks::of_run(&f.conn, f.tenant, run).unwrap();
    assert!(
        rows.is_empty(),
        "a manual run publishes nothing at all: {rows:?}"
    );
    // An event-driven run on the same repository does publish, so the rule is
    // about provenance rather than the repository.
    let (event, event_jobs) = {
        let repo = f.repo;
        create_run(&mut f, repo, true)
    };
    let rows = checks::of_run(&f.conn, f.tenant, event).unwrap();
    assert_eq!(rows.len(), 3);
    let build = publication(&f, event, &event_jobs[0].to_string());
    assert_eq!(build.name, "sentinel / build");
    assert_eq!(build.scope, event_jobs[0].to_string());
}

#[test]
fn a_settled_event_owes_a_completed_check_unless_nothing_can_be_told() {
    let mut f = fixture();
    // A refused pull request publishes a neutral aggregate on the head: the
    // pull-request view reads checks on the head, not the tested merge.
    let merge = "c".repeat(40);
    let tx = f.conn.transaction().unwrap();
    let accepted = intake::accept(
        &tx,
        f.repo,
        &NewDelivery {
            provider: "github",
            external_id: "pr-1",
            event: "pull_request",
            ref_name: REF,
            old_sha: SHA_A,
            new_sha: &merge,
        },
        Some(&PrTerms {
            number: 7,
            action: "opened",
            draft: false,
            head_ref: "feature",
            head_sha: SHA_A,
            head_repo: 999,
            base_ref: "main",
            base_sha: SHA_A,
            merge_sha: Some(&merge),
        }),
        NOW,
    )
    .unwrap()
    .id();
    tx.commit().unwrap();
    settle(&mut f, accepted, intake::Resolution::Ignored("fork_pr"));
    let row = checks::of_delivery(&f.conn, accepted).unwrap().unwrap();
    assert_eq!(row.name, checks::AGGREGATE_NAME);
    assert_eq!(row.status, Status::Completed);
    assert_eq!(row.conclusion, Some(Conclusion::Neutral));
    assert_eq!(row.head_sha, SHA_A);
    assert_eq!(row.external_id, format!("sentinel:dlv:{accepted}"));
    assert!(row.summary.contains("fork"), "{}", row.summary);
    assert!(row.run.is_none());
    let tx = f.conn.transaction().unwrap();
    assert_eq!(
        intake::purge_settled(&tx, UnixMillis(i64::MAX), 100).unwrap(),
        0
    );
    checks::published(&tx, row.id, row.seq, 42, None, NOW).unwrap();
    assert_eq!(
        intake::purge_settled(&tx, UnixMillis(i64::MAX), 100).unwrap(),
        0
    );
    tx.commit().unwrap();
    // Identity is immutable, through raw SQL too.
    for sql in [
        "UPDATE check_publications SET head_sha = 'ffffffffffffffffffffffffffffffffffffffff'",
        "UPDATE check_publications SET name = 'rewritten'",
        "UPDATE check_publications SET external_id = 'rewritten'",
    ] {
        assert!(
            f.conn.execute(sql, []).is_err(),
            "raw SQL rewrote check identity: {sql}"
        );
    }

    // A failure is a failure; a duplicate publishes nothing.
    let mut f2 = fixture();
    let failed = {
        let repo = f2.repo;
        accept(&mut f2, repo, "no-pipeline", REF)
    };
    settle(&mut f2, failed, intake::Resolution::Failed("no_pipeline"));
    let row = checks::of_delivery(&f2.conn, failed).unwrap().unwrap();
    assert_eq!(row.conclusion, Some(Conclusion::Failure));
    assert!(row.summary.contains("no_pipeline"), "{}", row.summary);
    let duplicate = {
        let repo = f2.repo;
        accept(&mut f2, repo, "duplicate", REF)
    };
    settle(&mut f2, duplicate, intake::Resolution::Ignored("duplicate"));
    assert!(
        checks::of_delivery(&f2.conn, duplicate).unwrap().is_none(),
        "a duplicate tells nobody anything"
    );
    let no_trigger = {
        let repo = f2.repo;
        accept(&mut f2, repo, "no-trigger", "refs/heads/other")
    };
    settle(
        &mut f2,
        no_trigger,
        intake::Resolution::Ignored("no_trigger"),
    );
    assert_eq!(
        checks::of_delivery(&f2.conn, no_trigger)
            .unwrap()
            .unwrap()
            .conclusion,
        Some(Conclusion::Neutral)
    );

    // A generic repository has nobody to tell.
    let plain = {
        let generic = f2.generic;
        accept(&mut f2, generic, "plain", REF)
    };
    settle(&mut f2, plain, intake::Resolution::Failed("no_pipeline"));
    assert!(checks::of_delivery(&f2.conn, plain).unwrap().is_none());

    // A binding revoked between acceptance and settlement stops the row, and
    // a tag object is not a commit a check can attach to.
    let mut f3 = fixture();
    let revoked = {
        let repo = f3.repo;
        accept(&mut f3, repo, "revoked", REF)
    };
    let repo = f3.repo;
    let actor = f3.alice.user;
    let tx = f3.conn.transaction().unwrap();
    sources::revoke(&tx, Authority::HostLocal, Some(actor), repo, 1, NOW).unwrap();
    tx.commit().unwrap();
    settle(&mut f3, revoked, intake::Resolution::Failed("no_pipeline"));
    assert!(checks::of_delivery(&f3.conn, revoked).unwrap().is_none());
    let mut f4 = fixture();
    let tag = {
        let repo = f4.repo;
        accept(&mut f4, repo, "tag-1", "refs/tags/v1")
    };
    settle(&mut f4, tag, intake::Resolution::Failed("no_pipeline"));
    assert!(
        checks::of_delivery(&f4.conn, tag).unwrap().is_none(),
        "a tag object is not a commit"
    );
}

#[test]
fn publications_are_retried_and_never_overwrite_a_newer_generation() {
    let mut f = fixture();
    let (run, jobs) = {
        let repo = f.repo;
        create_run(&mut f, repo, true)
    };
    let build = publication(&f, run, &jobs[0].to_string());
    let due = checks::due(&f.conn, NOW, 10).unwrap();
    assert_eq!(due.len(), 3);
    assert!(due.iter().any(|p| p.id == build.id));

    // A transient failure schedules a bounded retry; the row is due later.
    let tx = f.conn.transaction().unwrap();
    let retry = checks::retry(&tx, build.id, build.seq, NOW, 0).unwrap();
    tx.commit().unwrap();
    assert_eq!(
        retry,
        checks::Retry::Scheduled {
            attempts: 1,
            next_attempt_ms: NOW.0 + checks::backoff_ms(1)
        }
    );
    assert!(
        checks::due(&f.conn, NOW, 10)
            .unwrap()
            .iter()
            .all(|p| p.id != build.id)
    );
    assert_eq!(
        checks::due(&f.conn, UnixMillis(NOW.0 + 10_000), 10)
            .unwrap()
            .len(),
        3
    );

    // Publishing marks the generation; a write from a stale read changes
    // nothing once the job has moved on.
    let tx = f.conn.transaction().unwrap();
    assert!(checks::published(&tx, build.id, build.seq, 7, None, NOW).unwrap());
    tx.commit().unwrap();
    step(&mut f, jobs[0], Event::Leased(Fence(1)), NOW.0 + 20);
    let newer = publication(&f, run, &jobs[0].to_string());
    assert_eq!(newer.seq, build.seq + 1);
    assert_eq!(newer.check_run_id, Some(7));
    let tx = f.conn.transaction().unwrap();
    assert_eq!(
        checks::retry(&tx, newer.id, newer.seq, NOW, 0).unwrap(),
        checks::Retry::Scheduled {
            attempts: 1,
            next_attempt_ms: NOW.0 + checks::backoff_ms(1)
        },
        "a newer desired state receives a fresh retry budget"
    );
    tx.rollback().unwrap();
    let tx = f.conn.transaction().unwrap();
    assert!(
        !checks::published(&tx, newer.id, build.seq, 9, None, NOW).unwrap(),
        "an older generation cannot be marked published"
    );
    tx.commit().unwrap();
    // The handle is still recorded, so the next attempt updates that run
    // rather than creating a second one for the same check.
    let raced = publication(&f, run, &jobs[0].to_string());
    assert_eq!(raced.check_run_id, Some(9));
    assert!(
        raced.published_seq < raced.seq,
        "the newer state is still due"
    );
    assert!(
        checks::due(&f.conn, UnixMillis(NOW.0 + 100_000), 10)
            .unwrap()
            .iter()
            .any(|p| p.id == newer.id),
        "the newer generation is still publishable"
    );
    let tx = f.conn.transaction().unwrap();
    assert!(matches!(
        checks::retry(&tx, newer.id, build.seq, NOW, 0),
        Err(Error::Conflict)
    ));
    tx.rollback().unwrap();

    // A refusal is recorded against one generation and does not stop the
    // newest from being published (a state change starts fresh).
    let tx = f.conn.transaction().unwrap();
    checks::refused(&tx, newer.id, newer.seq, "no permission", NOW).unwrap();
    tx.commit().unwrap();
    assert!(
        checks::due(&f.conn, UnixMillis(NOW.0 + 100_000), 10)
            .unwrap()
            .iter()
            .all(|p| p.id != newer.id),
        "a refused generation is not due"
    );
    // A stale refusal cannot touch a newer generation.
    let tx = f.conn.transaction().unwrap();
    assert!(matches!(
        checks::refused(&tx, newer.id, newer.seq - 1, "stale refusal", NOW),
        Err(Error::Conflict)
    ));
    tx.rollback().unwrap();
    step_as(
        &mut f,
        jobs[0],
        Actor::Worker(Fence(1)),
        Event::PreparationStarted,
        NOW.0 + 30,
    );
    let fresh = publication(&f, run, &jobs[0].to_string());
    assert_eq!(fresh.seq, newer.seq + 1);
    assert!(
        checks::due(&f.conn, UnixMillis(NOW.0 + 100_000), 10)
            .unwrap()
            .iter()
            .any(|p| p.id == fresh.id),
        "a new generation is publishable again"
    );
}

#[test]
fn attempts_exhaust_into_a_refusal_and_identity_belongs_to_the_target() {
    let mut f = fixture();
    let (run, jobs) = {
        let repo = f.repo;
        create_run(&mut f, repo, true)
    };
    let build = publication(&f, run, &jobs[0].to_string());
    let mut attempts = 0;
    loop {
        let tx = f.conn.transaction().unwrap();
        let outcome = checks::retry(&tx, build.id, build.seq, NOW, 0).unwrap();
        tx.commit().unwrap();
        attempts += 1;
        match outcome {
            checks::Retry::Scheduled { .. } => {
                assert!(attempts < checks::MAX_ATTEMPTS, "the budget is bounded");
            }
            checks::Retry::Exhausted => break,
        }
    }
    assert_eq!(attempts, checks::MAX_ATTEMPTS);
    let row = publication(&f, run, &jobs[0].to_string());
    assert_eq!(row.status, Status::Queued);
    assert!(
        checks::due(&f.conn, UnixMillis(NOW.0 + 3_600_000), 10)
            .unwrap()
            .iter()
            .all(|p| p.id != build.id)
    );

    // A publication cannot name a run of another repository: the trigger
    // refuses it before the foreign key is even consulted.
    let accepted = {
        let repo = f.repo;
        accept(&mut f, repo, "owned", REF)
    };
    let other = RunId::new();
    f.conn
        .execute(
            "INSERT INTO runs(id, tenant_id, repo_id, source_sha, created_ms) VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![
                other.as_bytes(),
                f.tenant.as_bytes(),
                f.generic.as_bytes(),
                SHA_B,
                NOW.0
            ],
        )
        .unwrap();
    let tx = f.conn.transaction().unwrap();
    assert!(
        checks::record_job(&tx, f.tenant, jobs[0], NOW).is_ok(),
        "the legitimate write still succeeds"
    );
    let foreign_insert = tx.execute(
        "INSERT INTO check_publications(id, tenant_id, repo_id, run_id, scope, name, head_sha,
            external_id, status, title, summary, seq, state, created_ms, updated_ms)
         VALUES (?1, ?2, ?3, ?4, 'aggregate', 'sentinel / ci', ?5, 'x', 0, 't', 's', 1, 0, 1, 1)",
        rusqlite::params![
            sentinel_core::CheckId::new().as_bytes(),
            f.tenant.as_bytes(),
            f.repo.as_bytes(),
            other.as_bytes(),
            SHA_B
        ],
    );
    assert!(
        foreign_insert.is_err(),
        "a check must belong to its run's repository"
    );
    tx.rollback().unwrap();
    let _ = accepted;
}

#[test]
fn a_blank_refusal_reason_is_stored_as_a_non_empty_one() {
    let mut f = fixture();
    let (run, jobs) = {
        let repo = f.repo;
        create_run(&mut f, repo, true)
    };
    let build = publication(&f, run, &jobs[0].to_string());
    let tx = f.conn.transaction().unwrap();
    checks::refused(&tx, build.id, build.seq, " \u{7}\n ", NOW).unwrap();
    tx.commit().unwrap();
    let row = publication(&f, run, &jobs[0].to_string());
    assert_eq!(row.state, checks::State::Refused);
    assert_eq!(row.reason.as_deref(), Some("refused"));
}

#[test]
fn repeating_the_stored_content_keeps_the_generation_and_the_retry_schedule() {
    let mut f = fixture();
    let (run, jobs) = {
        let repo = f.repo;
        create_run(&mut f, repo, true)
    };
    let build = publication(&f, run, &jobs[0].to_string());
    let tx = f.conn.transaction().unwrap();
    checks::retry(&tx, build.id, build.seq, NOW, 0).unwrap();
    // The same desired state is recorded again.
    checks::record_job(&tx, f.tenant, jobs[0], UnixMillis(NOW.0 + 5)).unwrap();
    tx.commit().unwrap();
    let again = publication(&f, run, &jobs[0].to_string());
    assert_eq!(
        again.seq, build.seq,
        "identical content is not a generation"
    );
    assert!(
        checks::due(&f.conn, NOW, 10)
            .unwrap()
            .iter()
            .all(|p| p.id != build.id),
        "the back-off survives a re-record"
    );
}

#[test]
fn the_remote_run_is_dropped_only_after_a_completed_state_was_delivered() {
    let mut f = fixture();
    let (run, jobs) = {
        let repo = f.repo;
        create_run(&mut f, repo, true)
    };
    let job = jobs[0];
    step(&mut f, job, Event::Leased(Fence(1)), NOW.0 + 1);
    let running = publication(&f, run, &job.to_string());
    let tx = f.conn.transaction().unwrap();
    checks::create_started(&tx, running.id, running.seq, NOW).unwrap();
    checks::published(&tx, running.id, running.seq, 77, None, NOW).unwrap();
    tx.commit().unwrap();
    for (event, at) in [
        (Event::PreparationStarted, 2),
        (Event::StepsStarted, 3),
        (Event::FinalizationStarted, 4),
        (Event::Passed, 5),
    ] {
        step_as(&mut f, job, Actor::Worker(Fence(1)), event, NOW.0 + at);
    }
    let done = publication(&f, run, &job.to_string());
    assert_eq!(done.status, Status::Completed);
    assert_eq!(done.check_run_id, Some(77));

    // The completed state never reached GitHub: new content for the row must
    // keep the live run and its create mark instead of orphaning it.
    f.conn
        .execute(
            "UPDATE check_publications SET title = 'stale' WHERE id = ?1",
            [done.id.as_bytes()],
        )
        .unwrap();
    let tx = f.conn.transaction().unwrap();
    checks::record_job(&tx, f.tenant, job, UnixMillis(NOW.0 + 6)).unwrap();
    tx.commit().unwrap();
    let kept = publication(&f, run, &job.to_string());
    assert_eq!(kept.seq, done.seq + 1);
    assert_eq!(kept.check_run_id, Some(77));
    assert!(kept.create_started_ms.is_some());

    // Once the completed state is delivered, new work needs a fresh run.
    let tx = f.conn.transaction().unwrap();
    assert!(checks::published(&tx, kept.id, kept.seq, 77, None, NOW).unwrap());
    tx.commit().unwrap();
    f.conn
        .execute(
            "UPDATE check_publications SET title = 'stale again' WHERE id = ?1",
            [kept.id.as_bytes()],
        )
        .unwrap();
    let tx = f.conn.transaction().unwrap();
    checks::record_job(&tx, f.tenant, job, UnixMillis(NOW.0 + 7)).unwrap();
    tx.commit().unwrap();
    let fresh = publication(&f, run, &job.to_string());
    assert_eq!(fresh.check_run_id, None);
    assert!(fresh.create_started_ms.is_none());
}

#[test]
fn a_deferred_row_keeps_its_attempts_and_a_final_status_outlasts_a_long_outage() {
    let mut f = fixture();
    let (run, jobs) = {
        let repo = f.repo;
        create_run(&mut f, repo, true)
    };
    let build = publication(&f, run, &jobs[0].to_string());
    let tx = f.conn.transaction().unwrap();
    assert!(checks::defer(&tx, build.id, build.seq, NOW, NOW.0 + 120_000).unwrap());
    // A park never exceeds its cap, whatever the caller asks for.
    assert!(checks::defer(&tx, build.id, build.seq, NOW, i64::MAX).unwrap());
    assert!(!checks::defer(&tx, build.id, build.seq + 1, NOW, NOW.0 + 1).unwrap());
    tx.commit().unwrap();
    let parked: (i64, i64) = f
        .conn
        .query_row(
            "SELECT attempts, next_attempt_ms FROM check_publications WHERE id = ?1",
            [build.id.as_bytes()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(parked, (0, NOW.0 + checks::MAX_DEFER_MS));

    // A completed check keeps retrying well past the progress budget.
    f.conn
        .execute(
            "UPDATE check_publications SET status = 'completed', conclusion = 'success'
             WHERE id = ?1",
            [build.id.as_bytes()],
        )
        .unwrap();
    let (mut total_ms, mut attempts) = (0, 0);
    loop {
        let tx = f.conn.transaction().unwrap();
        let outcome = checks::retry(&tx, build.id, build.seq, NOW, 0).unwrap();
        tx.commit().unwrap();
        attempts += 1;
        match outcome {
            checks::Retry::Scheduled {
                next_attempt_ms, ..
            } => total_ms += next_attempt_ms - NOW.0,
            checks::Retry::Exhausted => break,
        }
    }
    assert_eq!(attempts, checks::MAX_TERMINAL_ATTEMPTS);
    assert!(
        total_ms >= 6 * 3_600_000,
        "a final status must survive an outage of hours: {total_ms} ms"
    );
}

#[test]
fn an_exhausted_final_status_is_rearmed_only_within_the_window() {
    let mut f = fixture();
    let (run, jobs) = {
        let repo = f.repo;
        create_run(&mut f, repo, true)
    };
    let build = publication(&f, run, &jobs[0].to_string());
    // Every row is refused; only the completed one carries the exhausted reason.
    f.conn
        .execute(
            "UPDATE check_publications SET state = 2, reason = 'forbidden', settled_ms = ?1",
            [NOW.0],
        )
        .unwrap();
    f.conn
        .execute(
            "UPDATE check_publications SET status = 'completed', conclusion = 'failure',
                reason = 'attempts', attempts = 39 WHERE id = ?1",
            [build.id.as_bytes()],
        )
        .unwrap();
    let tx = f.conn.transaction().unwrap();
    let old = UnixMillis(NOW.0 + checks::REARM_WINDOW_MS + 1);
    assert_eq!(
        checks::rearm_exhausted(&tx, old, checks::REARM_LIMIT).unwrap(),
        0,
        "a refusal older than the window stays refused"
    );
    assert_eq!(
        checks::rearm_exhausted(&tx, NOW, checks::REARM_LIMIT).unwrap(),
        1,
        "only the exhausted completed check returns"
    );
    tx.commit().unwrap();
    let row = publication(&f, run, &jobs[0].to_string());
    assert_eq!(row.state, checks::State::Pending);
    assert!(row.reason.is_none());
    assert!(
        checks::due(&f.conn, NOW, 10)
            .unwrap()
            .iter()
            .any(|p| p.id == build.id)
    );
    assert!(
        checks::of_run(&f.conn, f.tenant, run)
            .unwrap()
            .into_iter()
            .filter(|p| p.id != build.id)
            .all(|p| p.state == checks::State::Refused),
        "rows refused for other reasons are not re-armed"
    );
}
