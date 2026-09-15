//! D05 finalization behavior: terminal publication records the attempt's
//! data status in the same transaction — `log_state` says whether the log's
//! end marker was durable, every due artifact has a row (due-but-missing
//! gets `failed`), and a reported `Passed` cannot stand over a required
//! artifact that was never captured.

use sentinel_auth::secret::Secret;
use sentinel_core::{
    AttemptId, Event, FailureClass, Fence, JobId, JobState, Outcome, PoolId, RepoId, RunId,
    TenantId, UnixMillis, UserId, WorkerId,
    auth::{Namespace, Permissions as P, Principal},
};
use sentinel_pipeline::{PinnedSource, RunSpec, compile_str};
use sentinel_protocol::{
    logs::{Frame, Stream},
    negotiate::{Arch, Capabilities, Negotiated, ProtocolVersion},
};
use std::sync::Arc;

use sentinel_store::{
    Durability, Error, Store, artifacts,
    auth::{self, Authority, NamespaceKind, provisioning},
    dispatch::{self, Capacity, LogState},
    jobs,
    logs::LogStore,
    objects::{self, Objects},
    runs, status,
    tenancy::{self, PoolKind},
    workers::{self, Presentation},
};

const DIGEST: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const SHA: &str = "0123456789abcdef0123456789abcdef01234567";
const NOW: UnixMillis = UnixMillis(1_000);

fn at(ms: i64) -> UnixMillis {
    UnixMillis(ms)
}

struct Fixture {
    _dir: tempfile::TempDir,
    store: Store,
    logs: Arc<LogStore>,
    objects: Arc<Objects>,
    tenant: TenantId,
    repo: RepoId,
    pool: PoolId,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path().join("metadata.sqlite"), Durability::Normal).unwrap();
    let logs = Arc::new(LogStore::open(dir.path().join("logs")).unwrap());
    let objects = Arc::new(Objects::open(dir.path().join("objects")).unwrap());
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
    Fixture {
        _dir: dir,
        store,
        logs,
        objects,
        tenant,
        repo,
        pool,
    }
}

fn worker(f: &Fixture, capacity: Capacity) -> WorkerId {
    let id = WorkerId::new();
    let fp = Secret::generate().digest();
    let pool = f.pool;
    f.store
        .writer()
        .write(move |tx| {
            let issued = workers::issue_enrollment(tx, Authority::HostLocal, pool, 60_000, NOW)?;
            let mut text = String::new();
            issued.secret.expose(&mut text);
            workers::enroll(
                tx,
                &Secret::parse(&text).unwrap(),
                Presentation {
                    worker: id,
                    fingerprint: fp,
                    name: "w",
                    negotiated: Negotiated {
                        protocol: ProtocolVersion(1),
                        capabilities: Capabilities::REQUIRED,
                        arch: Arch::X86_64,
                    },
                },
                NOW,
            )?;
            dispatch::report_capacity(tx, id, capacity)
        })
        .unwrap();
    id
}

fn spec(yaml: &str) -> RunSpec {
    RunSpec::new(
        PinnedSource::new("https://github.com/o/r.git", SHA, Some("main")).unwrap(),
        compile_str(yaml).unwrap(),
    )
    .unwrap()
}

fn run(f: &Fixture, yaml: &str, now: UnixMillis) -> (RunId, Vec<JobId>) {
    let (tenant, repo, run) = (f.tenant, f.repo, RunId::new());
    let spec = spec(yaml);
    let ids = f
        .store
        .writer()
        .write(move |tx| {
            let ids = runs::create_run(tx, tenant, repo, run, &spec, now)?;
            for job in &ids {
                runs::resolve_image(tx, tenant, *job, DIGEST, "linux/amd64")?;
            }
            Ok(ids)
        })
        .unwrap();
    (run, ids)
}

/// Lease, acknowledge and drive an attempt to `Finalizing` — the point a
/// terminal report is legal from.
fn held(f: &Fixture, w: WorkerId, now: UnixMillis) -> (JobId, AttemptId, Fence) {
    let pool = f.pool;
    let offer = f
        .store
        .writer()
        .write(move |tx| dispatch::place(tx, w, pool, dispatch::DEFAULT_LEASE_MS, now))
        .unwrap()
        .unwrap();
    let (attempt, fence) = (offer.attempt, offer.fence);
    f.store
        .writer()
        .write(move |tx| {
            dispatch::acknowledge(tx, w, attempt, fence, now)?;
            dispatch::report(tx, w, attempt, fence, Event::StepsStarted, None, now, None)?;
            dispatch::report(
                tx,
                w,
                attempt,
                fence,
                Event::FinalizationStarted,
                None,
                now,
                None,
            )
        })
        .unwrap();
    (offer.job, attempt, fence)
}

fn state(f: &Fixture, job: JobId) -> JobState {
    f.store
        .read(|c| jobs::get_job(c, f.tenant, job))
        .unwrap()
        .state
}

fn log_state(f: &Fixture, run: RunId, job: JobId) -> Option<LogState> {
    f.store
        .read(|c| status::run(c, f.tenant, run))
        .unwrap()
        .jobs
        .into_iter()
        .find(|j| j.id == job)
        .unwrap()
        .log_state
}

fn artifact_states(f: &Fixture, run: RunId) -> Vec<(String, artifacts::State)> {
    let tenant = f.tenant;
    f.store
        .read(move |c| artifacts::for_run(c, tenant, run))
        .unwrap()
        .into_iter()
        .map(|r| (r.name, r.state))
        .collect()
}

fn frame(seq: u64) -> Frame {
    Frame {
        seq,
        step: 0,
        stream: Stream::Stdout,
        bytes: b"line\n".to_vec(),
    }
}

const CAP: Capacity = Capacity {
    cpu_millis: 4_000,
    memory_bytes: 8 << 30,
};

const ONE_JOB: &str = "schema: 1
on: [push]
jobs:
  build:
    image: alpine:3
    steps: [{ id: s, run: 'true' }]
";

const REQUIRED_ARTIFACT: &str = "schema: 1
on: [push]
jobs:
  build:
    image: alpine:3
    steps: [{ id: s, run: 'true' }]
    artifacts:
      - { name: dist, paths: ['dist/**'], required: true }
";

#[test]
fn a_durable_log_end_records_complete_and_survives_terminal_stamping() {
    let f = fixture();
    let w = worker(&f, CAP);
    let (run, _ids) = run(&f, ONE_JOB, at(2_000));
    let (job, attempt, fence) = held(&f, w, at(2_100));
    // Live attempts are pending until the marker lands.
    assert_eq!(log_state(&f, run, job), Some(LogState::Pending));
    f.logs.append(run, job, attempt, &frame(1)).unwrap();
    f.logs.append(run, job, attempt, &frame(2)).unwrap();
    f.logs.finish(run, job, attempt, 2, &[]).unwrap();
    // The row is written before the worker is acknowledged — the controller
    // calls `log_ended` in the same breath the marker becomes durable.
    f.store
        .writer()
        .write(move |tx| dispatch::log_ended(tx, attempt))
        .unwrap();
    let logs = Arc::clone(&f.logs);
    let next = f
        .store
        .writer()
        .write(move |tx| {
            dispatch::report(
                tx,
                w,
                attempt,
                fence,
                Event::Passed,
                None,
                at(2_500),
                Some(&logs),
            )
        })
        .unwrap();
    assert_eq!(next, JobState::Terminal(Outcome::Passed));
    assert_eq!(log_state(&f, run, job), Some(LogState::Complete));
}

#[test]
fn a_terminal_report_without_the_end_marker_is_incomplete_and_heals() {
    let f = fixture();
    let w = worker(&f, CAP);
    let (run, _ids) = run(&f, ONE_JOB, at(2_000));
    let (job, attempt, fence) = held(&f, w, at(2_100));
    // Frames arrived but the end never did when the report landed — the
    // terminal stamp records that truthfully.
    f.logs.append(run, job, attempt, &frame(1)).unwrap();
    let logs = Arc::clone(&f.logs);
    let next = f
        .store
        .writer()
        .write(move |tx| {
            dispatch::report(
                tx,
                w,
                attempt,
                fence,
                Event::Passed,
                None,
                at(2_500),
                Some(&logs),
            )
        })
        .unwrap();
    assert_eq!(next, JobState::Terminal(Outcome::Passed));
    assert_eq!(log_state(&f, run, job), Some(LogState::Incomplete));
    // A retransmitted end on a reconnected worker still completes the record;
    // the attempt is released but the log is evidence, not the verdict.
    f.logs.append(run, job, attempt, &frame(2)).unwrap();
    f.logs.finish(run, job, attempt, 2, &[]).unwrap();
    f.store
        .writer()
        .write(move |tx| dispatch::log_ended(tx, attempt))
        .unwrap();
    assert_eq!(log_state(&f, run, job), Some(LogState::Complete));
    assert_eq!(state(&f, job), JobState::Terminal(Outcome::Passed));
}

#[test]
fn a_terminal_stamp_never_takes_back_a_completed_log() {
    let f = fixture();
    let w = worker(&f, CAP);
    let (run, _ids) = run(&f, ONE_JOB, at(2_000));
    let (job, attempt, fence) = held(&f, w, at(2_100));
    f.logs.finish(run, job, attempt, 0, &[]).unwrap();
    f.store
        .writer()
        .write(move |tx| dispatch::log_ended(tx, attempt))
        .unwrap();
    // Even with the log store out of reach, the recorded `complete` stands.
    f.store
        .writer()
        .write(move |tx| {
            dispatch::report(tx, w, attempt, fence, Event::Passed, None, at(2_500), None)
        })
        .unwrap();
    assert_eq!(log_state(&f, run, job), Some(LogState::Complete));
    // And raw SQL cannot regress the row.
    let regressed = f.store.writer().write(move |tx| {
        tx.execute(
            "UPDATE attempts SET log_state = 1 WHERE id = ?1",
            [attempt.as_bytes().as_slice()],
        )?;
        Ok(())
    });
    assert!(matches!(regressed, Err(Error::Sqlite(_))));
    assert_eq!(log_state(&f, run, job), Some(LogState::Complete));
}

#[test]
fn a_passed_report_without_a_required_artifact_is_a_publication_failure() {
    let f = fixture();
    let w = worker(&f, CAP);
    let (run, _ids) = run(&f, REQUIRED_ARTIFACT, at(2_000));
    let (job, attempt, fence) = held(&f, w, at(2_100));
    let next = f
        .store
        .writer()
        .write(move |tx| {
            dispatch::report(tx, w, attempt, fence, Event::Passed, None, at(2_500), None)
        })
        .unwrap();
    // The worker's `Passed` cannot stand: the required artifact was due and
    // nothing was settled for it.
    assert_eq!(next, JobState::Terminal(Outcome::InfraFailed));
    assert_eq!(
        f.store
            .read(|c| jobs::get_job(c, f.tenant, job))
            .unwrap()
            .failure_class,
        Some(FailureClass::Publication)
    );
    // The missing artifact is on record, not silently absent.
    assert_eq!(
        artifact_states(&f, run),
        vec![("dist".to_string(), artifacts::State::Failed)]
    );
}

#[test]
fn an_uncaptured_required_artifact_still_downgrades_the_report() {
    let f = fixture();
    let w = worker(&f, CAP);
    let (run, _ids) = run(&f, REQUIRED_ARTIFACT, at(2_000));
    let (job, attempt, fence) = held(&f, w, at(2_100));
    // The worker reported the artifact absent (or it broke mid-stream); a
    // required declaration settles only as `captured`.
    let tenant = f.tenant;
    f.store
        .writer()
        .write(move |tx| {
            artifacts::record(
                tx,
                tenant,
                run,
                job,
                attempt,
                "dist",
                artifacts::State::Absent,
                None,
                0,
                0,
                at(2_400 + 86_400_000),
                at(2_400),
            )?;
            Ok(())
        })
        .unwrap();
    let next = f
        .store
        .writer()
        .write(move |tx| {
            dispatch::report(tx, w, attempt, fence, Event::Passed, None, at(2_500), None)
        })
        .unwrap();
    assert_eq!(next, JobState::Terminal(Outcome::InfraFailed));
    assert_eq!(
        f.store
            .read(|c| jobs::get_job(c, f.tenant, job))
            .unwrap()
            .failure_class,
        Some(FailureClass::Publication)
    );
    // The recorded row was not duplicated or rewritten.
    assert_eq!(
        artifact_states(&f, run),
        vec![("dist".to_string(), artifacts::State::Absent)]
    );
}

#[test]
fn a_captured_required_artifact_lets_the_report_stand() {
    let f = fixture();
    let w = worker(&f, CAP);
    let (run, _ids) = run(&f, REQUIRED_ARTIFACT, at(2_000));
    let (job, attempt, fence) = held(&f, w, at(2_100));
    let tenant = f.tenant;
    let objects = Arc::clone(&f.objects);
    f.store
        .writer()
        .write(move |tx| {
            let version =
                objects.commit_manifest(tx, tenant, objects::Kind::Artifact, "build/dist", &[])?;
            artifacts::record(
                tx,
                tenant,
                run,
                job,
                attempt,
                "dist",
                artifacts::State::Captured,
                Some(version),
                0,
                0,
                at(2_400 + 86_400_000),
                at(2_400),
            )?;
            Ok(())
        })
        .unwrap();
    let next = f
        .store
        .writer()
        .write(move |tx| {
            dispatch::report(tx, w, attempt, fence, Event::Passed, None, at(2_500), None)
        })
        .unwrap();
    assert_eq!(next, JobState::Terminal(Outcome::Passed));
    assert_eq!(
        artifact_states(&f, run),
        vec![("dist".to_string(), artifacts::State::Captured)]
    );
}

#[test]
fn optional_and_not_due_artifacts_never_change_the_verdict() {
    let yaml = "schema: 1
on: [push]
jobs:
  build:
    image: alpine:3
    steps: [{ id: s, run: 'true' }]
    artifacts:
      - { name: notes, paths: ['*.txt'] }
      - { name: crash, paths: ['core'], when: failure, required: true }
";
    let f = fixture();
    let w = worker(&f, CAP);
    let (run, _ids) = run(&f, yaml, at(2_000));
    let (_job, attempt, fence) = held(&f, w, at(2_100));
    let next = f
        .store
        .writer()
        .write(move |tx| {
            dispatch::report(tx, w, attempt, fence, Event::Passed, None, at(2_500), None)
        })
        .unwrap();
    // `notes` was due-but-missing and optional: recorded `failed`, verdict
    // unchanged. `crash` was not due under a pass: no row at all.
    assert_eq!(next, JobState::Terminal(Outcome::Passed));
    assert_eq!(
        artifact_states(&f, run),
        vec![("notes".to_string(), artifacts::State::Failed)]
    );
}

#[test]
fn abandonment_and_expiry_record_missing_artifacts_too() {
    let yaml = "schema: 1
on: [push]
jobs:
  build:
    image: alpine:3
    steps: [{ id: s, run: 'true' }]
    artifacts:
      - { name: report, paths: ['report/**'], when: always }
      - { name: dist, paths: ['dist/**'], when: success }
  extra:
    image: alpine:3
    steps: [{ id: s, run: 'true' }]
    artifacts:
      - { name: report, paths: ['report/**'], when: always }
";
    let f = fixture();
    let w = worker(&f, CAP);
    let (run, ids) = run(&f, yaml, at(2_000));
    let (build, extra) = (ids[0], ids[1]);
    // The first job's worker abandons its attempt after a restart; the
    // `always` artifact is due under any outcome, `dist` is not due under a
    // non-pass.
    let pool = f.pool;
    let offer = f
        .store
        .writer()
        .write(move |tx| dispatch::place(tx, w, pool, dispatch::DEFAULT_LEASE_MS, at(2_100)))
        .unwrap()
        .unwrap();
    f.store
        .writer()
        .write(move |tx| dispatch::acknowledge(tx, w, offer.attempt, offer.fence, at(2_200)))
        .unwrap();
    let logs = Arc::clone(&f.logs);
    let next = f
        .store
        .writer()
        .write(move |tx| {
            dispatch::abandon(tx, w, offer.attempt, offer.fence, at(2_300), Some(&logs))
        })
        .unwrap();
    assert_eq!(next, JobState::Terminal(Outcome::InfraFailed));
    assert_eq!(
        artifact_states(&f, run),
        vec![("report".to_string(), artifacts::State::Failed)]
    );
    assert_eq!(log_state(&f, run, offer.job), Some(LogState::Incomplete));
    // The second job's attempt outlives its lease; the sweep's expiry goes
    // through the same terminal stamping.
    let offer = f
        .store
        .writer()
        .write(move |tx| dispatch::place(tx, w, pool, dispatch::DEFAULT_LEASE_MS, at(2_400)))
        .unwrap()
        .unwrap();
    assert_eq!(offer.job, extra);
    f.store
        .writer()
        .write(move |tx| dispatch::acknowledge(tx, w, offer.attempt, offer.fence, at(2_500)))
        .unwrap();
    let lapsed = at(2_400 + dispatch::DEFAULT_LEASE_MS + 1);
    let logs = Arc::clone(&f.logs);
    f.store
        .writer()
        .write(move |tx| dispatch::expire(tx, offer.attempt, lapsed, Some(&logs)))
        .unwrap();
    assert_eq!(state(&f, extra), JobState::Terminal(Outcome::InfraFailed));
    let names: Vec<String> = artifact_states(&f, run)
        .into_iter()
        .map(|(n, _)| n)
        .collect();
    assert_eq!(names, vec!["report".to_string(), "report".to_string()]);
    // `build` was never released into the queue: its attempt's loss is the
    // truth the run reports.
    assert_eq!(state(&f, build), JobState::Terminal(Outcome::InfraFailed));
}

#[test]
fn a_held_attempts_log_end_survives_a_stale_report() {
    let f = fixture();
    let w = worker(&f, CAP);
    let (run, _ids) = run(&f, ONE_JOB, at(2_000));
    let (job, attempt, fence) = held(&f, w, at(2_100));
    f.logs.finish(run, job, attempt, 0, &[]).unwrap();
    // A stale report — wrong fence — neither finishes the job nor stains the
    // log record; the machine fences it before the stamp runs.
    let logs = Arc::clone(&f.logs);
    assert!(matches!(
        f.store.writer().write(move |tx| dispatch::report(
            tx,
            w,
            attempt,
            Fence(fence.0 + 1),
            Event::Passed,
            None,
            at(2_500),
            Some(&logs),
        )),
        Err(Error::NotFound)
    ));
    f.store
        .writer()
        .write(move |tx| dispatch::log_ended(tx, attempt))
        .unwrap();
    assert_eq!(log_state(&f, run, job), Some(LogState::Complete));
    assert_eq!(state(&f, job), JobState::Finalizing);
}
