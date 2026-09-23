//! Execution hardening (Part 04 audit): terminal edges decide dependents,
//! a recorded cancel settles an offer that goes back, hand-backs are fenced
//! and never infrastructure failures, specs wait for a durable
//! acknowledgement, expiry re-checks the lease, and every hello renegotiates.

use sentinel_auth::secret::Secret;
use sentinel_core::{
    AttemptId, Event, FailureClass, Fence, JobId, JobState, Outcome, PoolId, RepoId, RunId,
    RunState, TenantId, UnixMillis, UserId, WorkerId,
    auth::{Namespace, Permissions as P, Principal},
};
use sentinel_pipeline::{PinnedSource, RunSpec, compile_str};
use sentinel_protocol::negotiate::{Arch, Capabilities, Negotiated, ProtocolVersion};
use sentinel_store::{
    Durability, Error, Store,
    auth::{self, Authority, NamespaceKind, provisioning},
    dispatch::{self, Capacity},
    runs,
    tenancy::{self, PoolKind},
    workers::{self, Presentation},
};

const DIGEST: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const SHA: &str = "0123456789abcdef0123456789abcdef01234567";
const NOW: UnixMillis = UnixMillis(1_000);

const CHAIN: &str = "schema: 1
on: [push]
jobs:
  build:
    image: alpine:3
    resources: { cpu: 1, memory: 1GiB }
    steps: [{ id: s, run: 'true' }]
  test:
    image: alpine:3
    needs: [build]
    resources: { cpu: 1, memory: 1GiB }
    steps: [{ id: s, run: 'true' }]
";

fn at(ms: i64) -> UnixMillis {
    UnixMillis(ms)
}

struct Fixture {
    _dir: tempfile::TempDir,
    store: Store,
    tenant: TenantId,
    repo: RepoId,
    pool: PoolId,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path().join("metadata.sqlite"), Durability::Normal).unwrap();
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
            sentinel_store::jobs::insert_repo(tx, tenant, repo, "app", NOW)?;
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
        tenant,
        repo,
        pool,
    }
}

fn negotiated(protocol: u16) -> Negotiated {
    Negotiated {
        protocol: ProtocolVersion(protocol),
        capabilities: Capabilities::REQUIRED,
        arch: Arch::X86_64,
    }
}

fn worker(f: &Fixture) -> WorkerId {
    let (id, pool, fp) = (WorkerId::new(), f.pool, Secret::generate().digest());
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
                    negotiated: negotiated(6),
                },
                NOW,
            )?;
            dispatch::report_capacity(
                tx,
                id,
                Capacity {
                    cpu_millis: 8_000,
                    memory_bytes: 16 << 30,
                    disk_bytes: 0,
                },
            )
        })
        .unwrap();
    id
}

fn run(f: &Fixture, yaml: &str) -> (RunId, Vec<JobId>) {
    let (tenant, repo, run) = (f.tenant, f.repo, RunId::new());
    let spec = RunSpec::new(
        PinnedSource::new("https://github.com/o/r.git", SHA, Some("main")).unwrap(),
        compile_str(yaml).unwrap(),
    )
    .unwrap();
    let ids = f
        .store
        .writer()
        .write(move |tx| {
            let ids = runs::create_run(tx, tenant, repo, run, &spec, at(2_000))?;
            for job in &ids {
                runs::resolve_image(tx, tenant, *job, DIGEST, "linux/amd64")?;
            }
            Ok(ids)
        })
        .unwrap();
    (run, ids)
}

fn place(f: &Fixture, w: WorkerId, now: UnixMillis) -> dispatch::Offer {
    let pool = f.pool;
    f.store
        .writer()
        .write(move |tx| dispatch::place(tx, w, pool, dispatch::DEFAULT_LEASE_MS, now))
        .unwrap()
        .expect("a job to place")
}

fn ack(f: &Fixture, w: WorkerId, offer: &dispatch::Offer, now: UnixMillis) {
    let (attempt, fence) = (offer.attempt, offer.fence);
    f.store
        .writer()
        .write(move |tx| dispatch::acknowledge(tx, w, attempt, fence, now))
        .unwrap();
}

fn state(f: &Fixture, job: JobId) -> JobState {
    let tenant = f.tenant;
    f.store
        .read(|c| sentinel_store::jobs::get_job(c, tenant, job))
        .unwrap()
        .state
}

fn run_state(f: &Fixture, run: RunId) -> RunState {
    let tenant = f.tenant;
    f.store
        .read(|c| sentinel_store::jobs::run_state(c, tenant, run))
        .unwrap()
}

/// P04-3: cancelling one unstarted job decides its dependents in the same
/// transaction; the run finishes instead of waiting forever.
#[test]
fn cancelling_an_unstarted_job_skips_its_dependents_and_ends_the_run() {
    let f = fixture();
    let (run_id, ids) = run(&f, CHAIN);
    let (build, test) = (ids[0], ids[1]);
    assert_eq!(state(&f, test), JobState::Blocked);
    let tenant = f.tenant;
    assert_eq!(
        f.store
            .writer()
            .write(move |tx| dispatch::cancel(tx, tenant, build, at(2_100)))
            .unwrap(),
        dispatch::Cancelled::Terminal
    );
    assert_eq!(state(&f, build), JobState::Terminal(Outcome::Canceled));
    assert_eq!(state(&f, test), JobState::Terminal(Outcome::Skipped));
    assert_eq!(run_state(&f, run_id), RunState::Terminal(Outcome::Canceled));
}

/// P04-14: a cancel recorded while the offer is unacknowledged settles the
/// job as soon as the offer lapses or is declined; it never waits in the
/// queue for a placement it cannot get.
#[test]
fn a_cancel_recorded_while_offered_ends_the_job_when_the_offer_goes_back() {
    let f = fixture();
    let w = worker(&f);
    let tenant = f.tenant;
    for decline in [false, true] {
        let (run_id, ids) = run(&f, CHAIN);
        let offer = place(&f, w, at(2_100));
        assert_eq!(offer.job, ids[0]);
        let job = offer.job;
        assert_eq!(
            f.store
                .writer()
                .write(move |tx| dispatch::cancel(tx, tenant, job, at(2_200)))
                .unwrap(),
            dispatch::Cancelled::Requested
        );
        let (attempt, fence) = (offer.attempt, offer.fence);
        f.store
            .writer()
            .write(move |tx| {
                if decline {
                    dispatch::decline(tx, w, attempt, fence, at(2_300)).map(|_| ())
                } else {
                    dispatch::lapse(tx, attempt, at(2_300))
                }
            })
            .unwrap();
        assert_eq!(state(&f, ids[0]), JobState::Terminal(Outcome::Canceled));
        assert_eq!(state(&f, ids[1]), JobState::Terminal(Outcome::Skipped));
        assert_eq!(run_state(&f, run_id), RunState::Terminal(Outcome::Canceled));
    }
    assert_eq!(
        f.store
            .read(|c| dispatch::free_capacity(c, w))
            .unwrap()
            .cpu_millis,
        8_000
    );
}

/// P04-25 and P04-4: a decline is fenced on the holder, and an acknowledged
/// attempt the worker never started (its spec never arrived) goes back to
/// the queue: not an infrastructure failure, and not after a lease wait.
#[test]
fn a_decline_is_fenced_and_hands_back_an_acknowledged_attempt_that_never_started() {
    let f = fixture();
    let (w, other) = (worker(&f), worker(&f));
    let (_, ids) = run(&f, CHAIN);
    let offer = place(&f, w, at(2_100));
    ack(&f, w, &offer, at(2_150));
    let (attempt, fence) = (offer.attempt, offer.fence);
    // Another worker naming the attempt, or a stale fence, changes nothing.
    for (who, fence) in [(other, fence), (w, Fence(fence.0 + 1))] {
        assert!(matches!(
            f.store
                .writer()
                .write(move |tx| dispatch::decline(tx, who, attempt, fence, at(2_200))),
            Err(Error::NotFound)
        ));
    }
    assert_eq!(state(&f, offer.job), JobState::Leased);
    // The holder hands it back: queued again, capacity released, and the
    // next placement is a new attempt under a higher fence.
    assert_eq!(
        f.store
            .writer()
            .write(move |tx| dispatch::decline(tx, w, attempt, fence, at(2_300)))
            .unwrap(),
        JobState::Queued
    );
    assert!(
        f.store
            .read(|c| dispatch::expired(c, at(10_000_000)))
            .unwrap()
            .is_empty()
    );
    let again = place(&f, w, at(2_400));
    assert_eq!(again.job, ids[0]);
    assert!(again.fence.0 > fence.0);
    // Once the worker reported a phase the attempt ran: no hand-back.
    ack(&f, w, &again, at(2_500));
    let (attempt, fence) = (again.attempt, again.fence);
    f.store
        .writer()
        .write(move |tx| {
            dispatch::report(
                tx,
                w,
                attempt,
                fence,
                Event::PreparationStarted,
                None,
                at(2_600),
                None,
            )
        })
        .unwrap();
    assert!(matches!(
        f.store
            .writer()
            .write(move |tx| dispatch::decline(tx, w, attempt, fence, at(2_700))),
        Err(Error::Conflict)
    ));
    assert_eq!(state(&f, ids[0]), JobState::Preparing);
}

/// P04-10: nothing that could start work is served before the
/// acknowledgement is durable; a cancelled, unstarted attempt is named so
/// the controller settles it instead of serving it.
#[test]
fn the_spec_is_served_only_after_the_acknowledgement() {
    let f = fixture();
    let w = worker(&f);
    run(&f, CHAIN);
    let offer = place(&f, w, at(2_100));
    let (attempt, fence, job) = (offer.attempt, offer.fence, offer.job);
    let gate = |f: &Fixture| {
        f.store
            .read(|c| dispatch::spec_gate(c, w, attempt))
            .unwrap()
    };
    assert_eq!(gate(&f), dispatch::SpecGate::Unacknowledged);
    assert!(matches!(
        f.store.read(|c| dispatch::spec_bytes(c, w, attempt)),
        Err(Error::NotFound)
    ));
    assert!(matches!(
        f.store.read(|c| dispatch::job_context(c, w, attempt)),
        Err(Error::NotFound)
    ));
    assert_eq!(
        f.store
            .read(|c| dispatch::spec_gate(c, WorkerId::new(), attempt))
            .unwrap(),
        dispatch::SpecGate::NotHeld
    );
    ack(&f, w, &offer, at(2_200));
    assert_eq!(gate(&f), dispatch::SpecGate::Ready);
    assert!(
        f.store
            .read(|c| dispatch::spec_bytes(c, w, attempt))
            .is_ok()
    );
    assert!(
        f.store
            .read(|c| dispatch::job_context(c, w, attempt))
            .is_ok()
    );
    let tenant = f.tenant;
    f.store
        .writer()
        .write(move |tx| dispatch::cancel(tx, tenant, job, at(2_300)))
        .unwrap();
    assert_eq!(gate(&f), dispatch::SpecGate::Canceled(fence));
    // The controller settles it through the hand-back: canceled at once.
    f.store
        .writer()
        .write(move |tx| dispatch::decline(tx, w, attempt, fence, at(2_400)))
        .unwrap();
    assert_eq!(state(&f, job), JobState::Terminal(Outcome::Canceled));
}

/// P04-24: a renewal that commits after the sweep read the attempt as due
/// wins; the batch expiry re-checks the lease in its own write.
#[test]
fn expiry_rechecks_the_lease_in_its_write() {
    let f = fixture();
    let w = worker(&f);
    run(&f, CHAIN);
    let offer = place(&f, w, at(2_100));
    ack(&f, w, &offer, at(2_200));
    let attempt = offer.attempt;
    let late = at(2_100 + dispatch::DEFAULT_LEASE_MS + 1);
    let due = f.store.read(|c| dispatch::expired_scoped(c, late)).unwrap();
    assert_eq!(due.len(), 1);
    assert_eq!((due[0].0, due[0].2), (attempt, offer.job));
    // The worker renews at its deadline; that write commits only after the
    // sweep's read (a renewal of an already-passed lease is refused, P08-13).
    let deadline = at(late.0 - 1);
    f.store
        .writer()
        .write(move |tx| dispatch::renew(tx, w, &[attempt], dispatch::DEFAULT_LEASE_MS, deadline))
        .unwrap();
    assert_eq!(
        f.store
            .writer()
            .write(move |tx| dispatch::expire_batch(tx, &[(attempt, false)], late))
            .unwrap()
            .done,
        0
    );
    assert_eq!(state(&f, offer.job), JobState::Leased);
    // Past the renewed lease it expires, and a durable end is recorded.
    let later = at(late.0 + dispatch::DEFAULT_LEASE_MS + 1);
    assert_eq!(
        f.store
            .writer()
            .write(move |tx| dispatch::expire_batch(tx, &[(attempt, true)], later))
            .unwrap()
            .done,
        1
    );
    assert_eq!(
        state(&f, offer.job),
        JobState::Terminal(Outcome::InfraFailed)
    );
    let state_code: i64 = f
        .store
        .read(move |c| {
            Ok(c.query_row(
                "SELECT log_state FROM attempts WHERE id = ?1",
                [attempt.as_bytes()],
                |r| r.get(0),
            )?)
        })
        .unwrap();
    assert_eq!(state_code, dispatch::LogState::Complete as i64);
}

/// P04-5: a worker's `canceled` with no cancel ever requested is its own
/// infrastructure event (a watchdog, a shutdown), never the user's verdict.
#[test]
fn a_canceled_report_without_a_request_is_not_recorded_as_a_cancel() {
    let f = fixture();
    let w = worker(&f);
    run(&f, CHAIN);
    let offer = place(&f, w, at(2_100));
    ack(&f, w, &offer, at(2_200));
    let (attempt, fence) = (offer.attempt, offer.fence);
    f.store
        .writer()
        .write(move |tx| {
            dispatch::report(
                tx,
                w,
                attempt,
                fence,
                Event::Failed(FailureClass::Canceled),
                None,
                at(2_300),
                None,
            )
        })
        .unwrap();
    let tenant = f.tenant;
    let row = f
        .store
        .read(|c| sentinel_store::jobs::get_job(c, tenant, offer.job))
        .unwrap();
    assert_eq!(row.state, JobState::Terminal(Outcome::InfraFailed));
    assert_eq!(row.failure_class, Some(FailureClass::Runtime));
}

/// P04-2: every hello renegotiates; an upgrade and a rollback are both
/// recorded, a rollback below the profile protocol forgets profile-only
/// placement facts, and a different architecture is not the same worker.
#[test]
fn renegotiation_records_upgrades_and_rollbacks_but_not_a_new_architecture() {
    let f = fixture();
    let w = worker(&f);
    let read = |f: &Fixture| -> (i64, Vec<u8>) {
        f.store
            .read(move |c| {
                Ok(c.query_row(
                    "SELECT protocol, labels FROM workers WHERE id = ?1",
                    [w.as_bytes()],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )?)
            })
            .unwrap()
    };
    f.store
        .writer()
        .write(move |tx| {
            workers::renegotiate(tx, w, negotiated(7))?;
            dispatch::report_profile(
                tx,
                w,
                &dispatch::ReportedProfile {
                    labels: &["gpu".to_owned()],
                    host_id: None,
                    avail_images: &[],
                    cache_bytes: None,
                    load_ns: None,
                },
            )
        })
        .unwrap();
    assert_eq!(read(&f), (7, b"gpu".to_vec()));
    f.store
        .writer()
        .write(move |tx| workers::renegotiate(tx, w, negotiated(6)))
        .unwrap();
    assert_eq!(read(&f), (6, Vec::new()));
    let arm = Negotiated {
        arch: Arch::Aarch64,
        ..negotiated(7)
    };
    assert!(matches!(
        f.store
            .writer()
            .write(move |tx| workers::renegotiate(tx, w, arm)),
        Err(Error::Conflict)
    ));
    assert!(matches!(
        f.store
            .writer()
            .write(move |tx| workers::renegotiate(tx, WorkerId::new(), negotiated(7))),
        Err(Error::NotFound)
    ));
}

/// P04-26: a refused enrollment is audited and the audit row commits.
#[test]
fn a_refused_enrollment_is_audited() {
    let f = fixture();
    let refused = f
        .store
        .writer()
        .write(move |tx| {
            workers::redeem(
                tx,
                &Secret::generate(),
                Presentation {
                    worker: WorkerId::new(),
                    fingerprint: Secret::generate().digest(),
                    name: "w",
                    negotiated: negotiated(6),
                },
                NOW,
            )
        })
        .unwrap();
    assert!(refused.is_none());
    let audited: i64 = f
        .store
        .read(|c| {
            Ok(c.query_row(
                "SELECT COUNT(*) FROM auth_audit WHERE event = 45",
                [],
                |r| r.get(0),
            )?)
        })
        .unwrap();
    assert_eq!(audited, 1);
    let _ = (AttemptId::new(), PoolId::new());
}
