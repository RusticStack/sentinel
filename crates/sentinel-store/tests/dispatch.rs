//! W02 store behavior: the ready queue is the database, reservations are
//! attempts, placement is pool-scoped and capacity-checked, offers lapse back
//! to the queue under an advanced fence, renewal and reports are fenced, and
//! a finished job releases its capacity and decides its dependents.

use sentinel_auth::secret::Secret;
use sentinel_core::{
    Actor, AttemptId, Event, FailureClass, Fence, JobId, JobState, Outcome, PoolId, RepoId, RunId,
    TenantId, UnixMillis, UserId, WorkerId,
    auth::{Namespace, Permissions as P, Principal},
};
use sentinel_pipeline::{PinnedSource, RunSpec, compile_str};
use sentinel_protocol::negotiate::{Arch, Capabilities, Negotiated, ProtocolVersion};
use sentinel_store::{
    Durability, Error, Store,
    auth::{self, Authority, NamespaceKind, provisioning},
    dispatch::{self, Capacity, WaitReason},
    runs,
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

/// Enroll a worker into the pool with the given capacity.
fn worker(f: &Fixture, pool: PoolId, capacity: Capacity) -> WorkerId {
    let id = WorkerId::new();
    let fp = Secret::generate().digest();
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

/// Create a run from YAML with every job's image resolved; returns job IDs.
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

fn place(f: &Fixture, w: WorkerId, pool: PoolId, now: UnixMillis) -> Option<dispatch::Offer> {
    f.store
        .writer()
        .write(move |tx| dispatch::place(tx, w, pool, dispatch::DEFAULT_LEASE_MS, now))
        .unwrap()
}

fn state(f: &Fixture, job: JobId) -> JobState {
    let tenant = f.tenant;
    f.store
        .read(|c| sentinel_store::jobs::get_job(c, tenant, job))
        .unwrap()
        .state
}

const TWO_JOBS: &str = "schema: 1
on: [push]
jobs:
  a-small:
    image: alpine:3
    resources: { cpu: 1, memory: 1GiB }
    steps: [{ id: s, run: 'true' }]
  b-big:
    image: alpine:3
    resources: { cpu: 4, memory: 8GiB }
    steps: [{ id: s, run: 'true' }]
";

#[test]
fn placement_is_pool_scoped_capacity_checked_and_reserves_with_the_lease() {
    let f = fixture();
    let cap = Capacity {
        cpu_millis: 4_000,
        memory_bytes: 8 << 30,
    };
    let w = worker(&f, f.pool, cap);
    // Nothing queued: nothing offered, and the full capacity is free.
    assert_eq!(place(&f, w, f.pool, at(2_000)), None);
    assert_eq!(
        f.store.read(|c| dispatch::free_capacity(c, w)).unwrap(),
        cap
    );

    let (_, ids) = run(&f, TWO_JOBS, at(2_000));
    let (small, big) = (ids[0], ids[1]);
    let first = place(&f, w, f.pool, at(2_100)).unwrap();
    assert_eq!((first.job, first.fence), (small, Fence(1)));
    assert_eq!(first.cpu_millis, 1_000);
    assert_eq!(first.image.digest, DIGEST);
    assert_eq!(first.lease_until, at(2_100 + dispatch::DEFAULT_LEASE_MS));
    assert_eq!(state(&f, small), JobState::Leased);
    // The reservation is the attempt: capacity went with the lease.
    assert_eq!(
        f.store.read(|c| dispatch::free_capacity(c, w)).unwrap(),
        Capacity {
            cpu_millis: 3_000,
            memory_bytes: 7 << 30
        }
    );
    // The big job no longer fits this worker while the small one holds it.
    assert_eq!(place(&f, w, f.pool, at(2_200)), None);
    assert_eq!(
        f.store
            .read(|c| dispatch::wait_reason(c, f.tenant, big, &[w]))
            .unwrap(),
        WaitReason::Capacity
    );
    assert_eq!(
        f.store
            .read(|c| dispatch::wait_reason(c, f.tenant, big, &[]))
            .unwrap(),
        WaitReason::WorkerOffline
    );

    // A worker of a pool the tenant may not use sees nothing at all.
    let other = PoolId::new();
    f.store
        .writer()
        .write(move |tx| {
            tenancy::create_pool(
                tx,
                Authority::HostLocal,
                other,
                "shared",
                PoolKind::Shared,
                NOW,
            )
        })
        .unwrap();
    let outsider = worker(
        &f,
        other,
        Capacity {
            cpu_millis: 64_000,
            memory_bytes: 256 << 30,
        },
    );
    assert_eq!(place(&f, outsider, other, at(2_300)), None);
    // Granted, it places the big job; withdrawn, it stops at once.
    let (tenant, pool) = (f.tenant, other);
    f.store
        .writer()
        .write(move |tx| tenancy::grant_pool(tx, Authority::HostLocal, pool, tenant, at(2_400)))
        .unwrap();
    let placed = place(&f, outsider, other, at(2_500)).unwrap();
    assert_eq!(placed.job, big);
    f.store
        .writer()
        .write(move |tx| {
            dispatch::lapse(tx, placed.attempt, at(2_600))?;
            tenancy::revoke_pool_grant(tx, Authority::HostLocal, pool, tenant, at(2_600))
        })
        .unwrap();
    assert_eq!(place(&f, outsider, other, at(2_700)), None);
    assert!(matches!(
        f.store
            .read(|c| dispatch::wait_reason(c, f.tenant, big, &[w, outsider]))
            .unwrap(),
        WaitReason::Capacity
    ));

    // A job larger than any worker the tenant could ever use says so.
    let (_, huge) = run(
        &f,
        "schema: 1
on: [push]
jobs:
  huge:
    image: alpine:3
    resources: { cpu: 32, memory: 64GiB }
    steps: [{ id: s, run: 'true' }]
",
        at(2_800),
    );
    assert_eq!(
        f.store
            .read(|c| dispatch::wait_reason(c, f.tenant, huge[0], &[w]))
            .unwrap(),
        WaitReason::NoMatchingWorker {
            cpu_short: 28_000,
            memory_short: 56 << 30
        }
    );
    // A job that fits is passed over only by capacity, never by identity.
    assert_eq!(place(&f, w, f.pool, at(2_900)), None);
}

#[test]
fn offers_lapse_back_to_the_queue_and_stale_acknowledgements_are_refused() {
    let f = fixture();
    let w = worker(
        &f,
        f.pool,
        Capacity {
            cpu_millis: 8_000,
            memory_bytes: 16 << 30,
        },
    );
    let (_, ids) = run(&f, TWO_JOBS, at(2_000));
    let small = ids[0];
    let offer = place(&f, w, f.pool, at(2_100)).unwrap();
    let (attempt, fence) = (offer.attempt, offer.fence);
    // The sweep sees it once the ack timeout has passed, not before.
    assert!(
        f.store
            .read(|c| dispatch::unacknowledged(c, at(2_100 + dispatch::OFFER_ACK_MS - 1)))
            .unwrap()
            .is_empty()
    );
    let due = f
        .store
        .read(|c| dispatch::unacknowledged(c, at(2_100 + dispatch::OFFER_ACK_MS)))
        .unwrap();
    assert_eq!(due, vec![attempt]);
    f.store
        .writer()
        .write(move |tx| dispatch::lapse(tx, attempt, at(7_200)))
        .unwrap();
    assert_eq!(state(&f, small), JobState::Queued);
    assert_eq!(
        f.store
            .read(|c| dispatch::free_capacity(c, w))
            .unwrap()
            .cpu_millis,
        8_000
    );
    // Late acknowledgement of the lapsed offer is a conflict, and it can't
    // be lapsed twice or un-released by raw SQL.
    assert!(matches!(
        f.store
            .writer()
            .write(move |tx| dispatch::acknowledge(tx, w, attempt, fence, at(7_300))),
        Err(Error::Conflict)
    ));
    assert!(matches!(
        f.store
            .writer()
            .write(move |tx| dispatch::lapse(tx, attempt, at(7_300))),
        Err(Error::NotFound)
    ));
    let unrelease = f.store.writer().write(move |tx| {
        tx.execute("UPDATE attempts SET released_ms = NULL", [])?;
        Ok(())
    });
    assert!(matches!(unrelease, Err(Error::Sqlite(_))));

    // Re-offered under a strictly higher fence; the old fence cannot ack it.
    let again = place(&f, w, f.pool, at(7_400)).unwrap();
    assert_eq!((again.job, again.fence), (small, Fence(2)));
    let (attempt2, fence2) = (again.attempt, again.fence);
    assert!(matches!(
        f.store
            .writer()
            .write(move |tx| dispatch::acknowledge(tx, w, attempt2, fence, at(7_500))),
        Err(Error::NotFound)
    ));
    assert!(matches!(
        f.store.writer().write(move |tx| dispatch::acknowledge(
            tx,
            WorkerId::new(),
            attempt2,
            fence2,
            at(7_500)
        )),
        Err(Error::NotFound)
    ));
    let until = f
        .store
        .writer()
        .write(move |tx| dispatch::acknowledge(tx, w, attempt2, fence2, at(7_500)))
        .unwrap();
    assert_eq!(until, at(7_400 + dispatch::DEFAULT_LEASE_MS));
    // A retransmitted acknowledgement is idempotent.
    assert_eq!(
        f.store
            .writer()
            .write(move |tx| dispatch::acknowledge(tx, w, attempt2, fence2, at(7_600)))
            .unwrap(),
        until
    );
    // Acknowledged offers are not swept.
    assert!(
        f.store
            .read(|c| dispatch::unacknowledged(c, at(1 << 40)))
            .unwrap()
            .is_empty()
    );
    let held = f.store.read(|c| dispatch::held_by(c, w)).unwrap();
    assert_eq!(held.len(), 1);
    assert!(held[0].acknowledged && held[0].attempt == attempt2);
}

#[test]
fn renewal_is_fenced_per_attempt_and_names_what_to_stop() {
    let f = fixture();
    let w = worker(
        &f,
        f.pool,
        Capacity {
            cpu_millis: 8_000,
            memory_bytes: 16 << 30,
        },
    );
    let (_, ids) = run(&f, TWO_JOBS, at(2_000));
    let a = place(&f, w, f.pool, at(2_100)).unwrap();
    let b = place(&f, w, f.pool, at(2_100)).unwrap();
    assert_eq!((a.job, b.job), (ids[0], ids[1]));
    let (aa, af, ba) = (a.attempt, a.fence, b.attempt);
    f.store
        .writer()
        .write(move |tx| dispatch::acknowledge(tx, w, aa, af, at(2_200)))
        .unwrap();
    // `b` is held but unacknowledged: not renewable, so the worker is told to
    // stop it (it never started); a foreign attempt likewise.
    let ghost = AttemptId::new();
    let (until, stop) = f
        .store
        .writer()
        .write(move |tx| {
            dispatch::renew(
                tx,
                w,
                &[aa, ba, ghost],
                dispatch::DEFAULT_LEASE_MS,
                at(20_000),
            )
        })
        .unwrap();
    assert_eq!(until, at(50_000));
    assert_eq!(stop, vec![ba, ghost]);
    let lease_of = |attempt: AttemptId| {
        f.store
            .read(|c| dispatch::held_by(c, w))
            .unwrap()
            .into_iter()
            .find(|h| h.attempt == attempt)
            .unwrap()
            .lease_until
    };
    assert_eq!(lease_of(aa), at(50_000));
    assert_eq!(lease_of(ba), at(2_100 + dispatch::DEFAULT_LEASE_MS));
    // Renewal never moves a lease backwards, and another worker cannot renew it.
    let (_, stop) = f
        .store
        .writer()
        .write(move |tx| dispatch::renew(tx, w, &[aa], dispatch::DEFAULT_LEASE_MS, at(10_000)))
        .unwrap();
    assert!(stop.is_empty());
    assert_eq!(lease_of(aa), at(50_000));
    let (_, stop) = f
        .store
        .writer()
        .write(move |tx| {
            dispatch::renew(
                tx,
                WorkerId::new(),
                &[aa],
                dispatch::DEFAULT_LEASE_MS,
                at(30_000),
            )
        })
        .unwrap();
    assert_eq!(stop, vec![aa]);
    // The held list is bounded.
    let many = vec![aa; dispatch::MAX_HELD_ATTEMPTS + 1];
    assert!(matches!(
        f.store.writer().write(move |tx| dispatch::renew(
            tx,
            w,
            &many,
            dispatch::DEFAULT_LEASE_MS,
            at(30_000)
        )),
        Err(Error::InvalidInput("held attempts"))
    ));
}

#[test]
fn a_report_carries_the_job_context_and_writes_the_summary_once() {
    let f = fixture();
    let w = worker(
        &f,
        f.pool,
        Capacity {
            cpu_millis: 8_000,
            memory_bytes: 16 << 30,
        },
    );
    let (_, ids) = run(
        &f,
        "schema: 1
on: [push]
jobs:
  build:
    image: alpine:3
    steps: [{ id: s, run: 'true' }]
  test:
    image: alpine:3
    needs: [build]
    steps: [{ id: s, run: 'true' }]
",
        at(2_000),
    );
    let (build, test) = (ids[0], ids[1]);
    let offer = place(&f, w, f.pool, at(2_100)).unwrap();
    let (attempt, fence) = (offer.attempt, offer.fence);
    // Context before acknowledgement is refused only for a foreign worker;
    // the held attempt answers with its identity and no dependencies.
    assert!(matches!(
        f.store
            .read(|c| dispatch::job_context(c, WorkerId::new(), attempt)),
        Err(Error::NotFound)
    ));
    let context = f
        .store
        .read(|c| dispatch::job_context(c, w, attempt))
        .unwrap();
    assert_eq!((context.job, context.job_name.as_str()), (build, "build"));
    assert_eq!(context.repo_name, "app");
    assert_eq!(context.sha, SHA);
    assert!(context.needs.is_empty() && !context.cancelled);
    // A report from a worker that does not hold the attempt is refused;
    // the holder's terminal report stores the summary exactly once.
    let summary = vec![1u8, 2, 3];
    let stray = summary.clone();
    assert!(matches!(
        f.store.writer().write(move |tx| dispatch::report(
            tx,
            WorkerId::new(),
            attempt,
            fence,
            Event::Passed,
            Some(&stray),
            at(2_200)
        )),
        Err(Error::NotFound)
    ));
    let bytes = summary.clone();
    f.store
        .writer()
        .write(move |tx| {
            dispatch::acknowledge(tx, w, attempt, fence, at(2_200))?;
            dispatch::report(tx, w, attempt, fence, Event::StepsStarted, None, at(2_300))?;
            dispatch::report(
                tx,
                w,
                attempt,
                fence,
                Event::FinalizationStarted,
                None,
                at(2_400),
            )?;
            dispatch::report(
                tx,
                w,
                attempt,
                fence,
                Event::Passed,
                Some(&bytes),
                at(2_500),
            )
        })
        .unwrap();
    assert_eq!(
        f.store
            .read(|c| dispatch::attempt_summary(c, f.tenant, attempt))
            .unwrap(),
        Some(summary)
    );
    assert_eq!(
        f.store
            .read(|c| dispatch::latest_attempt(c, f.tenant, build))
            .unwrap(),
        Some(attempt)
    );
    // Neither the machine nor raw SQL replaces it.
    assert!(matches!(
        f.store.writer().write(move |tx| dispatch::report(
            tx,
            w,
            attempt,
            fence,
            Event::Passed,
            Some(&[9u8]),
            at(2_600)
        )),
        Err(Error::NotFound)
    ));
    let overwrite = f.store.writer().write(move |tx| {
        tx.execute("UPDATE attempts SET summary = X'00'", [])?;
        Ok(())
    });
    assert!(matches!(overwrite, Err(Error::Sqlite(_))));
    // The dependent's context names its dependency's outcome.
    let next = place(&f, w, f.pool, at(2_700)).unwrap();
    assert_eq!(next.job, test);
    let context = f
        .store
        .read(|c| dispatch::job_context(c, w, next.attempt))
        .unwrap();
    assert_eq!(context.needs, vec![("build".to_owned(), Outcome::Passed)]);
    assert_eq!(context.job_name, "test");
}

#[test]
fn finishing_releases_capacity_and_decides_dependents_in_the_same_transaction() {
    let f = fixture();
    let w = worker(
        &f,
        f.pool,
        Capacity {
            cpu_millis: 8_000,
            memory_bytes: 16 << 30,
        },
    );
    let (_, ids) = run(
        &f,
        "schema: 1
on: [push]
jobs:
  build:
    image: alpine:3
    steps: [{ id: s, run: 'true' }]
  test:
    image: alpine:3
    needs: [build]
    steps: [{ id: s, run: 'true' }]
  deploy:
    image: alpine:3
    needs: [test]
    steps: [{ id: s, run: 'true' }]
",
        at(2_000),
    );
    let (build, test, deploy) = (ids[0], ids[1], ids[2]);
    assert_eq!(state(&f, test), JobState::Blocked);
    assert_eq!(
        f.store
            .read(|c| dispatch::wait_reason(c, f.tenant, test, &[w]))
            .unwrap(),
        WaitReason::Dependency
    );
    let offer = place(&f, w, f.pool, at(2_100)).unwrap();
    assert_eq!(offer.job, build);
    // Only `build` was placeable; `test` is blocked, not queued.
    assert_eq!(place(&f, w, f.pool, at(2_100)), None);
    let (attempt, fence) = (offer.attempt, offer.fence);
    let worker_actor = Actor::Worker(fence);
    f.store
        .writer()
        .write(move |tx| {
            dispatch::acknowledge(tx, w, attempt, fence, at(2_200))?;
            dispatch::finish(tx, attempt, worker_actor, Event::StepsStarted, at(2_300))?;
            dispatch::finish(
                tx,
                attempt,
                worker_actor,
                Event::FinalizationStarted,
                at(2_400),
            )
        })
        .unwrap();
    // Not terminal yet: the reservation stays.
    assert_eq!(
        f.store
            .read(|c| dispatch::free_capacity(c, w))
            .unwrap()
            .cpu_millis,
        6_000
    );
    // A stale fence reports nothing.
    assert!(matches!(
        f.store.writer().write(move |tx| dispatch::finish(
            tx,
            attempt,
            Actor::Worker(Fence(0)),
            Event::Passed,
            at(2_500)
        )),
        Err(Error::Transition(_))
    ));
    let next = f
        .store
        .writer()
        .write(move |tx| dispatch::finish(tx, attempt, worker_actor, Event::Passed, at(2_500)))
        .unwrap();
    assert_eq!(next, JobState::Terminal(Outcome::Passed));
    assert_eq!(
        f.store
            .read(|c| dispatch::free_capacity(c, w))
            .unwrap()
            .cpu_millis,
        8_000
    );
    // `test` was queued by the completion itself; `deploy` still waits.
    assert_eq!(state(&f, test), JobState::Queued);
    assert_eq!(state(&f, deploy), JobState::Blocked);
    assert!(matches!(
        f.store.writer().write(move |tx| dispatch::finish(
            tx,
            attempt,
            worker_actor,
            Event::Passed,
            at(2_600)
        )),
        Err(Error::NotFound)
    ));

    // A failed dependency skips what needs it, transitively.
    let offer = place(&f, w, f.pool, at(2_700)).unwrap();
    assert_eq!(offer.job, test);
    let (attempt, fence) = (offer.attempt, offer.fence);
    f.store
        .writer()
        .write(move |tx| {
            dispatch::acknowledge(tx, w, attempt, fence, at(2_800))?;
            dispatch::finish(
                tx,
                attempt,
                Actor::Worker(fence),
                Event::Failed(FailureClass::CommandFailed),
                at(2_900),
            )
        })
        .unwrap();
    assert_eq!(state(&f, test), JobState::Terminal(Outcome::Failed));
    assert_eq!(state(&f, deploy), JobState::Terminal(Outcome::Skipped));
    assert_eq!(place(&f, w, f.pool, at(3_000)), None);
}
