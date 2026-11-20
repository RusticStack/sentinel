//! External-resource leases: mutual exclusion, release, stale reclaim with its fence, and the bound.

use sentinel_auth::secret::Secret;
use sentinel_core::{
    Event, FailureClass, Fence, JobId, JobState, Outcome, PoolId, RepoId, RunId, TenantId,
    UnixMillis, UserId, WorkerId,
    auth::{Namespace, Permissions as P, Principal, Role},
};
use sentinel_pipeline::{PinnedSource, RunSpec, compile_str};
use sentinel_protocol::negotiate::{Arch, Capabilities, Negotiated, ProtocolVersion};
use sentinel_store::{
    Durability, Error, Store,
    auth::{self, Authority, NamespaceKind, provisioning},
    dispatch::{self, Capacity, WaitReason},
    jobs, locks, runs, status,
    tenancy::{self, PoolKind},
    workers::{self, Presentation},
};

const DIGEST: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const SHA: &str = "0123456789abcdef0123456789abcdef01234567";
const HOUR_MS: i64 = 3_600_000;

struct Fixture {
    _dir: tempfile::TempDir,
    store: Store,
    tenant: TenantId,
    repo: RepoId,
    pool: PoolId,
    worker: WorkerId,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path().join("metadata.sqlite"), Durability::Normal).unwrap();
    let now = UnixMillis::now();
    let (root, tenant, repo, pool, worker) = (
        UserId::new(),
        TenantId::new(),
        RepoId::new(),
        PoolId::new(),
        WorkerId::new(),
    );
    store
        .writer()
        .write(move |tx| {
            provisioning::insert_human(tx, root, "Root", true, now)?;
            auth::create_namespace(
                tx,
                Principal::new(root, P::ALL, None, None),
                tenant,
                Namespace::parse("acme").unwrap(),
                NamespaceKind::Organization,
                now,
            )?;
            auth::set_membership(
                tx,
                Principal::new(root, P::ALL, None, None),
                tenant,
                root,
                Role::TenantAdmin,
            )?;
            jobs::insert_repo(tx, tenant, repo, "app", now)?;
            tenancy::create_pool(
                tx,
                Authority::HostLocal,
                pool,
                "builders",
                PoolKind::Dedicated(tenant),
                now,
            )?;
            let issued = workers::issue_enrollment(tx, Authority::HostLocal, pool, 60_000, now)?;
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
                        protocol: ProtocolVersion(7),
                        capabilities: Capabilities::REQUIRED,
                        arch: Arch::X86_64,
                    },
                },
                now,
            )?;
            dispatch::report_capacity(
                tx,
                worker,
                Capacity {
                    cpu_millis: 8_000,
                    memory_bytes: 16 << 30,
                    disk_bytes: 20 << 30,
                },
            )?;
            dispatch::report_profile(
                tx,
                worker,
                &dispatch::ReportedProfile {
                    labels: &[],
                    host_id: None,
                    avail_images: &[],
                    cache_bytes: Some(0),
                    load_ns: Some(0),
                },
            )
        })
        .unwrap();
    Fixture {
        _dir: dir,
        store,
        tenant,
        repo,
        pool,
        worker,
    }
}

/// One job declaring `locks`, in a pipeline whose concurrency group is `group` and whose job is `hold`.
fn run(f: &Fixture, group: Option<&str>, locks: &str) -> (RunId, JobId) {
    let concurrency = match group {
        None => String::new(),
        Some(group) => format!("concurrency: {{ group: {group}, cancel_in_progress: true }}\n"),
    };
    let yaml = format!(
        "schema: 1\non: [push]\n{concurrency}jobs:\n  hold:\n    image: alpine:3\n    resources: {{ cpu: \"0.25\", memory: 128MiB, disk: 1GiB }}\n    locks: {locks}\n    steps: [{{ id: s, run: 'true' }}]\n"
    );
    let spec = RunSpec::new(
        PinnedSource::new("https://github.com/o/r.git", SHA, Some("main")).unwrap(),
        compile_str(&yaml).unwrap(),
    )
    .unwrap();
    let (tenant, repo) = (f.tenant, f.repo);
    let id = RunId::new();
    let job = f
        .store
        .writer()
        .write(move |tx| {
            let ids = runs::create_run(tx, tenant, repo, id, &spec, UnixMillis::now())?;
            for job in &ids {
                runs::resolve_image(tx, tenant, *job, DIGEST, "linux/amd64")?;
            }
            Ok(ids[0])
        })
        .unwrap();
    (id, job)
}

fn place(f: &Fixture, now: UnixMillis, lease_ms: i64) -> Option<dispatch::Offer> {
    let (worker, pool) = (f.worker, f.pool);
    f.store
        .writer()
        .write(move |tx| dispatch::place(tx, worker, pool, lease_ms, now))
        .unwrap()
}

fn reason(f: &Fixture, job: JobId) -> WaitReason {
    let (tenant, worker) = (f.tenant, f.worker);
    f.store
        .read(move |c| dispatch::wait_reason(c, tenant, job, &[worker]))
        .unwrap()
}

fn hold(f: &Fixture, name: &str, now: UnixMillis) -> Option<locks::Hold> {
    let tenant = f.tenant;
    let name = name.to_owned();
    f.store
        .read(move |c| locks::hold(c, tenant, &name, now))
        .unwrap()
}

/// Walks one attempt from its lease to a passing verdict, as the worker's reports would.
fn end(f: &Fixture, job: JobId, attempt: sentinel_core::AttemptId, fence: Fence, now: UnixMillis) {
    let (tenant, worker) = (f.tenant, f.worker);
    f.store
        .writer()
        .write(move |tx| {
            let actor = sentinel_core::Actor::Worker(fence);
            dispatch::acknowledge(tx, worker, attempt, fence, now)?;
            for event in [
                Event::PreparationStarted,
                Event::StepsStarted,
                Event::FinalizationStarted,
            ] {
                jobs::transition(tx, tenant, job, actor, event, now)?;
            }
            dispatch::finish(tx, attempt, actor, Event::Passed, now, None)
        })
        .unwrap();
}

fn state(f: &Fixture, job: JobId) -> JobState {
    let tenant = f.tenant;
    f.store
        .read(move |c| jobs::get_job(c, tenant, job))
        .unwrap()
        .state
}

#[test]
fn one_name_is_held_by_one_job_at_a_time() {
    let f = fixture();
    let now = UnixMillis::now();
    let (first_run, first) = run(&f, None, "[\"db/staging\"]");
    let (_, second) = run(&f, None, "[\"db/staging\"]");

    let offer = place(&f, now, HOUR_MS).expect("the first job takes the resource");
    assert_eq!(offer.job, first);
    let held = hold(&f, "db/staging", now).expect("the resource is held");
    assert_eq!(
        (held.job, held.run, held.attempt),
        (first, first_run, offer.attempt)
    );

    assert!(
        place(&f, now, HOUR_MS).is_none(),
        "a second job needing the same resource is not placed while it is held"
    );
    assert_eq!(
        reason(&f, second),
        WaitReason::ResourceLock {
            resource: "db/staging".to_owned()
        },
        "the queue names the resource, not the concurrency group it is not waiting on"
    );
    // The interlock is the store's, not the placement statement's: a lease asked for directly is
    // refused rather than running the job without the resource.
    let (tenant, worker, job) = (f.tenant, f.worker, second);
    let refused = f.store.writer().write(move |tx| {
        jobs::lease(
            tx,
            tenant,
            job,
            worker,
            UnixMillis(now.0 + HOUR_MS),
            UnixMillis(now.0 + 1_000),
        )
    });
    assert!(matches!(refused, Err(Error::Locked)), "{refused:?}");
    assert_eq!(
        state(&f, second),
        JobState::Queued,
        "a refused lease leaves the job waiting"
    );

    // The holder ends its attempt, and the resource is free in the same transaction.
    end(
        &f,
        offer.job,
        offer.attempt,
        offer.fence,
        UnixMillis(now.0 + 2_000),
    );
    assert_eq!(state(&f, first), JobState::Terminal(Outcome::Passed));
    assert!(
        hold(&f, "db/staging", UnixMillis(now.0 + 2_000)).is_none(),
        "an ended attempt holds nothing"
    );
    let next = place(&f, UnixMillis(now.0 + 2_000), HOUR_MS)
        .expect("the second job runs once the resource is free");
    assert_eq!(next.job, second);
    assert_eq!(
        hold(&f, "db/staging", UnixMillis(now.0 + 2_000)).map(|h| h.attempt),
        Some(next.attempt)
    );
}

#[test]
fn a_superseded_job_gives_its_resource_back_when_it_is_cancelled() {
    let f = fixture();
    let now = UnixMillis::now();
    let (_, first) = run(&f, Some("deploy"), "[\"staging/host\"]");
    let offer = place(&f, now, HOUR_MS).expect("the first run takes the resource");

    // A younger run of the same concurrency group supersedes it: this is the cancellation the group
    // performs, and it is not a release by itself — the attempt that holds the resource must end.
    let (_, second) = run(&f, Some("deploy"), "[\"staging/host\"]");
    let tenant = f.tenant;
    let cancelled = f
        .store
        .read(move |c| jobs::get_job(c, tenant, first))
        .unwrap();
    assert!(
        cancelled.cancel_requested,
        "the supersession asked the job to stop"
    );
    assert_eq!(
        hold(&f, "staging/host", now).map(|h| h.attempt),
        Some(offer.attempt),
        "a cancellation request does not steal the resource from a running attempt"
    );
    assert!(place(&f, now, HOUR_MS).is_none());

    f.store
        .writer()
        .write(move |tx| {
            dispatch::finish(
                tx,
                offer.attempt,
                sentinel_core::Actor::Worker(offer.fence),
                Event::Failed(FailureClass::Canceled),
                UnixMillis(now.0 + 1_000),
                None,
            )
        })
        .unwrap();
    assert_eq!(
        state(&f, first),
        JobState::Terminal(Outcome::Canceled),
        "the run's job ended as the group's cancellation asked"
    );
    assert!(hold(&f, "staging/host", UnixMillis(now.0 + 1_000)).is_none());
    let next = place(&f, UnixMillis(now.0 + 1_000), HOUR_MS).expect("the younger run takes it");
    assert_eq!(next.job, second);
}

#[test]
fn a_dead_owner_is_reclaimed_and_can_no_longer_write() {
    let f = fixture();
    let now = UnixMillis::now();
    let (_, first) = run(&f, None, "[\"gpu/rig-1\"]");
    let (_, second) = run(&f, None, "[\"gpu/rig-1\"]");
    let theme = UnixMillis(now.0 + 600_000);
    let stale = place(&f, now, 600_000).expect("the first job takes the resource");
    let (fence, worker) = (stale.fence, f.worker);
    f.store
        .writer()
        .write(move |tx| {
            dispatch::acknowledge(tx, worker, stale.attempt, fence, UnixMillis(now.0 + 1_000))
        })
        .unwrap();

    // The worker stops heartbeating: the attempt's lease deadline passes and the sweep ends it.
    f.store
        .writer()
        .write(move |tx| dispatch::expire(tx, stale.attempt, UnixMillis(theme.0 + 1_000), None))
        .unwrap();
    assert_eq!(
        state(&f, first),
        JobState::Terminal(Outcome::InfraFailed),
        "a lapsed lease ends its attempt"
    );

    let reclaimed =
        place(&f, UnixMillis(theme.0 + 2_000), HOUR_MS).expect("the resource is reclaimable");
    assert_eq!(reclaimed.job, second);
    assert_eq!(
        hold(&f, "gpu/rig-1", UnixMillis(theme.0 + 2_000)).map(|h| (h.job, h.attempt, h.fence)),
        Some((second, reclaimed.attempt, reclaimed.fence)),
        "the name now names the new attempt at its own fence"
    );

    // The stale owner's later writes are refused by the fence it presented: the heartbeat that renews
    // and the verdict that finishes both meet the attempt row it no longer holds.
    let (_, stopped) = f
        .store
        .writer()
        .write(move |tx| {
            dispatch::renew(
                tx,
                worker,
                &[stale.attempt],
                HOUR_MS,
                UnixMillis(theme.0 + 3_000),
            )
        })
        .unwrap();
    assert_eq!(
        stopped,
        vec![stale.attempt],
        "the controller tells the dead owner to stop: its renewal renews nothing"
    );
    let late = f.store.writer().write(move |tx| {
        dispatch::finish(
            tx,
            stale.attempt,
            sentinel_core::Actor::Worker(fence),
            Event::Passed,
            UnixMillis(theme.0 + 3_000),
            None,
        )
    });
    assert!(matches!(late, Err(Error::NotFound)), "{late:?}");
    assert_eq!(
        hold(&f, "gpu/rig-1", UnixMillis(theme.0 + 3_000)).map(|h| h.attempt),
        Some(reclaimed.attempt),
        "nothing the stale owner writes takes the resource back"
    );
}

#[test]
fn a_job_waits_no_longer_than_the_bound_it_declared_and_names_the_resource() {
    let f = fixture();
    let now = UnixMillis::now();
    let (_, holder) = run(&f, None, "[\"db/staging\"]");
    let held = place(&f, now, HOUR_MS).expect("the first job takes the resource");
    let (waiting_run, waiting) = run(&f, None, "[{name: db/staging, wait: 60s}]");
    let _ = holder;

    let sweep = |at: UnixMillis| {
        f.store
            .writer()
            .write(move |tx| locks::sweep_waits(tx, at))
            .unwrap()
    };
    assert_eq!(
        sweep(UnixMillis(now.0 + 30_000)),
        0,
        "inside its bound the job keeps waiting"
    );
    assert_eq!(state(&f, waiting), JobState::Queued);
    assert_eq!(
        reason(&f, waiting),
        WaitReason::ResourceLock {
            resource: "db/staging".to_owned()
        }
    );

    assert_eq!(
        sweep(UnixMillis(now.0 + 61_000)),
        1,
        "past its bound the job stops waiting"
    );
    assert_eq!(state(&f, waiting), JobState::Terminal(Outcome::TimedOut));
    let tenant = f.tenant;
    let view = f
        .store
        .read(move |c| status::run(c, tenant, waiting_run))
        .unwrap();
    let job = view.jobs.iter().find(|j| j.id == waiting).unwrap();
    assert_eq!(job.failure_class, Some(FailureClass::ResourceLock));
    assert_eq!(
        job.lock_wait.as_deref(),
        Some("db/staging"),
        "the failure names the resource"
    );
    assert_eq!(
        hold(&f, "db/staging", UnixMillis(now.0 + 61_000)).map(|h| h.attempt),
        Some(held.attempt),
        "the job that held the resource is untouched by the other job's bound"
    );

    // A job whose resource is free is never failed by the bound: this one waits only for a worker.
    let (_, free) = run(&f, None, "[{name: db/other, wait: 1s}]");
    assert_eq!(sweep(UnixMillis(now.0 + 10 * HOUR_MS)), 0);
    assert_eq!(state(&f, free), JobState::Queued);
}
