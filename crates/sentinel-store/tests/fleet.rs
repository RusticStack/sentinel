//! Fleet placement (Q01–Q04): hard CPU/memory/disk/architecture/label
//! constraints with an explicit reason when nothing satisfies them, fair
//! queueing between tenants and repositories, a reserved path for waiting
//! large jobs and pull-request feedback, host-level reservation across
//! worker identities, drain, bounded locality waiting and supersession of
//! the live run a concurrency group replaces.

use sentinel_auth::secret::Secret;
use sentinel_core::{
    Event, JobId, JobState, Outcome, PoolId, RepoId, RunId, TenantId, UnixMillis, UserId, WorkerId,
    auth::{Namespace, Permissions as P, Principal},
};
use sentinel_pipeline::{PinnedSource, RunSpec, compile_str};
use sentinel_protocol::negotiate::{Arch, Capabilities, Negotiated, ProtocolVersion};
use sentinel_store::{
    Durability, Error, Store,
    auth::{self, Authority, NamespaceKind, provisioning},
    dispatch::{self, Capacity, WaitReason},
    jobs,
    provenance::{self, Provenance},
    runs,
    tenancy::{self, PoolKind},
    workers::{self, Presentation},
};

const DIGEST: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const SHA: &str = "0123456789abcdef0123456789abcdef01234567";
const NOW: UnixMillis = UnixMillis(1_000);
const HOST: [u8; 16] = [7u8; 16];

fn at(ms: i64) -> UnixMillis {
    UnixMillis(ms)
}

struct Fixture {
    _dir: tempfile::TempDir,
    store: Store,
    root: UserId,
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
            jobs::insert_repo(tx, tenant, repo, "app", NOW)?;
            tenancy::create_pool(
                tx,
                Authority::HostLocal,
                pool,
                "builders",
                PoolKind::Shared,
                NOW,
            )?;
            tenancy::grant_pool(tx, Authority::HostLocal, pool, tenant, NOW)
        })
        .unwrap();
    Fixture {
        _dir: dir,
        store,
        root,
        tenant,
        repo,
        pool,
    }
}

/// A second organization with its own repository, admitted to the same pool.
fn other_tenant(f: &Fixture, slug: &str) -> (TenantId, RepoId) {
    let (root, tenant, repo, pool) = (f.root, TenantId::new(), RepoId::new(), f.pool);
    let slug = slug.to_owned();
    f.store
        .writer()
        .write(move |tx| {
            auth::create_namespace(
                tx,
                Principal::new(root, P::ALL, None, None),
                tenant,
                Namespace::parse(&slug).unwrap(),
                NamespaceKind::Organization,
                NOW,
            )?;
            jobs::insert_repo(tx, tenant, repo, "app", NOW)?;
            tenancy::grant_pool(tx, Authority::HostLocal, pool, tenant, NOW)
        })
        .unwrap();
    (tenant, repo)
}

/// Enroll a worker with reported CPU/memory/disk and, optionally, labels and
/// a host identity. Disk `0` is never reported — protocol 6 — and such a
/// worker is not disk-admitted.
#[allow(clippy::too_many_arguments)]
fn worker(
    f: &Fixture,
    pool: PoolId,
    cpu_millis: i64,
    memory_bytes: i64,
    disk_bytes: i64,
    labels: &[&str],
    host_id: Option<[u8; 16]>,
    avail_images: &[[u8; 8]],
) -> WorkerId {
    let id = WorkerId::new();
    let fp = Secret::generate().digest();
    let labels: Vec<String> = labels.iter().map(|l| (*l).to_owned()).collect();
    let images = avail_images.to_vec();
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
                        protocol: ProtocolVersion(7),
                        capabilities: Capabilities::REQUIRED,
                        arch: Arch::X86_64,
                    },
                },
                NOW,
            )?;
            dispatch::report_capacity(
                tx,
                id,
                Capacity {
                    cpu_millis,
                    memory_bytes,
                    disk_bytes,
                },
            )?;
            dispatch::report_profile(
                tx,
                id,
                &dispatch::ReportedProfile {
                    labels: labels.as_slice(),
                    host_id,
                    avail_images: images.as_slice(),
                    cache_bytes: Some(0),
                    load_ns: Some(0),
                },
            )
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

/// Create a run of `yaml` for `tenant`/`repo` at `now` with every image
/// resolved; returns the run id and its jobs in compiled order.
fn run(
    f: &Fixture,
    tenant: TenantId,
    repo: RepoId,
    yaml: &str,
    now: UnixMillis,
) -> (RunId, Vec<JobId>) {
    let spec = spec(yaml);
    let run = RunId::new();
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

/// Record a run's event provenance, as an event-driven dispatch does after
/// the run row exists.
fn record_event(f: &Fixture, tenant: TenantId, repo: RepoId, run: RunId, trigger: &str) {
    let provenance = Provenance {
        tenant,
        repo,
        trigger: trigger.to_owned(),
        delivery: None,
        provider: None,
        ref_name: Some("refs/pull/7/merge".to_owned()),
        old_sha: None,
        new_sha: None,
        head_sha: None,
        base_sha: None,
        merge_sha: None,
        pipeline_sha: SHA.to_owned(),
        pipeline_path: None,
        pipeline_digest: [0u8; 16],
        pr_number: Some(7),
    };
    f.store
        .writer()
        .write(move |tx| {
            provenance::insert(tx, &provenance, run, NOW)?;
            runs::apply_concurrency(tx, tenant, run, NOW)
        })
        .unwrap();
}

fn place(f: &Fixture, w: WorkerId, pool: PoolId, now: UnixMillis) -> Option<dispatch::Offer> {
    f.store
        .writer()
        .write(move |tx| dispatch::place(tx, w, pool, dispatch::DEFAULT_LEASE_MS, now))
        .unwrap()
}

fn reason(f: &Fixture, job: JobId, connected: &[WorkerId]) -> WaitReason {
    let tenant = f.tenant;
    let connected = connected.to_vec();
    f.store
        .read(move |c| dispatch::wait_reason(c, tenant, job, &connected))
        .unwrap()
}

fn state(f: &Fixture, job: JobId) -> JobState {
    let tenant = f.tenant;
    f.store
        .read(|c| jobs::get_job(c, tenant, job))
        .unwrap()
        .state
}

/// The id of a run's job by name: the compiled order is canonical (sorted),
/// not the order the YAML lists.
fn named(f: &Fixture, run: RunId, name: &str) -> JobId {
    let (tenant, name) = (f.tenant, name.to_owned());
    f.store
        .read(move |c| {
            let bytes: [u8; 16] = c.query_row(
                "SELECT id FROM jobs WHERE run_id = ?1 AND tenant_id = ?2 AND name = ?3",
                rusqlite::params![run.as_bytes(), tenant.as_bytes(), name],
                |r| r.get(0),
            )?;
            JobId::from_bytes(bytes).map_err(|_| Error::Corrupt("job_id"))
        })
        .unwrap()
}

/// Run an offered attempt to terminal `Passed`, releasing its reservation.
fn finish(f: &Fixture, w: WorkerId, offer: &dispatch::Offer, now: UnixMillis) {
    let (attempt, fence) = (offer.attempt, offer.fence);
    f.store
        .writer()
        .write(move |tx| {
            dispatch::acknowledge(tx, w, attempt, fence, now)?;
            for (offset, event) in [
                Event::PreparationStarted,
                Event::StepsStarted,
                Event::FinalizationStarted,
                Event::Passed,
            ]
            .into_iter()
            .enumerate()
            {
                dispatch::report(
                    tx,
                    w,
                    attempt,
                    fence,
                    event,
                    None,
                    at(now.0 + offset as i64 + 1),
                    None,
                )?;
            }
            Ok(())
        })
        .unwrap();
}

/// One job of one tenant's run, with the resources it asks for.
fn single_job(cpu: u32, memory: &str, disk: &str) -> String {
    format!(
        "schema: 1
on: [push]
jobs:
  one:
    image: alpine:3
    resources: {{ cpu: {cpu}, memory: {memory}, disk: {disk} }}
    steps: [{{ id: s, run: 'true' }}]
"
    )
}

#[test]
fn unsatisfiable_jobs_name_the_constraint_that_blocks_them() {
    let f = fixture();
    let w = worker(&f, f.pool, 8_000, 16 << 30, 20 << 30, &["linux"], None, &[]);
    let (tenant, repo, pool) = (f.tenant, f.repo, f.pool);
    let (run_id, all) = run(
        &f,
        tenant,
        repo,
        "schema: 1
on: [push]
jobs:
  arm:
    image: alpine:3
    runs_on: { arch: arm64 }
    steps: [{ id: s, run: 'true' }]
  gpu:
    image: alpine:3
    runs_on: { labels: [gpu] }
    steps: [{ id: s, run: 'true' }]
  huge:
    image: alpine:3
    resources: { cpu: 32, memory: 64GiB }
    steps: [{ id: s, run: 'true' }]
  scratch:
    image: alpine:3
    resources: { cpu: 1, memory: 1GiB, disk: 40GiB }
    steps: [{ id: s, run: 'true' }]
  fits:
    image: alpine:3
    resources: { cpu: 1, memory: 1GiB, disk: 1GiB }
    steps: [{ id: s, run: 'true' }]
",
        at(2_000),
    );
    assert_eq!(all.len(), 5);
    let (arm, gpu) = (named(&f, run_id, "arm"), named(&f, run_id, "gpu"));
    let (huge, scratch) = (named(&f, run_id, "huge"), named(&f, run_id, "scratch"));
    let fits = named(&f, run_id, "fits");
    assert_eq!(reason(&f, arm, &[w]), WaitReason::ArchMismatch);
    assert_eq!(reason(&f, gpu, &[w]), WaitReason::LabelMissing);
    assert_eq!(
        reason(&f, huge, &[w]),
        WaitReason::NoMatchingWorker {
            cpu_short: 24_000,
            memory_short: 48 << 30,
        }
    );
    assert_eq!(
        reason(&f, scratch, &[w]),
        WaitReason::DiskShort {
            disk_short: 20 << 30,
        }
    );
    // The queue listing names the same reasons, oldest first, and the one
    // job that fits still places: a hard constraint is per job.
    let queue = f
        .store
        .read(move |c| dispatch::list_queue(c, tenant, &[w]))
        .unwrap();
    assert_eq!(queue.len(), 5);
    // Compiled order is alphabetical: arm, fits, gpu, huge, scratch.
    assert_eq!(queue[0].job, arm);
    assert_eq!(queue[0].reason, WaitReason::ArchMismatch);
    assert_eq!(queue[1].job, fits);
    assert_eq!(queue[1].reason, WaitReason::Capacity);
    assert_eq!(queue[3].job, huge);
    assert_eq!(queue[4].job, scratch);
    assert!(queue.iter().all(|entry| entry.age_ms > 0));
    let offer = place(&f, w, pool, at(2_100)).unwrap();
    assert_eq!(offer.job, fits);
}

#[test]
fn the_fair_queue_serves_the_tenant_time_favours() {
    let f = fixture();
    let (other, other_repo) = other_tenant(&f, "beta");
    let w = worker(&f, f.pool, 8_000, 16 << 30, 20 << 30, &[], None, &[]);
    let (tenant, repo, pool) = (f.tenant, f.repo, f.pool);
    let backlog = "schema: 1
on: [push]
jobs:
  a:
    image: alpine:3
    resources: { cpu: 1, memory: 1GiB, disk: 1GiB }
    steps: [{ id: s, run: 'true' }]
  b:
    image: alpine:3
    resources: { cpu: 1, memory: 1GiB, disk: 1GiB }
    steps: [{ id: s, run: 'true' }]
";
    let (mine, _) = run(&f, tenant, repo, backlog, at(2_000));
    let (_, theirs) = run(
        &f,
        other,
        other_repo,
        single_job(1, "1GiB", "1GiB").as_str(),
        at(2_100),
    );
    let (first_job, second_job) = (named(&f, mine, "a"), named(&f, mine, "b"));
    // The tenant with no work in flight goes first, so a one-job tenant is
    // not queued behind somebody else's backlog.
    let first = place(&f, w, pool, at(2_200)).unwrap();
    assert_eq!(first.tenant, tenant);
    assert_eq!(first.job, first_job);
    let second = place(&f, w, pool, at(2_300)).unwrap();
    assert_eq!(second.tenant, other);
    assert_eq!(second.job, theirs[0]);
    // Both tenants have one attempt in flight: the oldest repository waits
    // no longer than its own backlog.
    let third = place(&f, w, pool, at(2_400)).unwrap();
    assert_eq!(third.tenant, tenant);
    assert_eq!(third.job, second_job);
}

#[test]
fn a_waiting_large_job_keeps_its_path() {
    let f = fixture();
    let w = worker(&f, f.pool, 8_000, 16 << 30, 20 << 30, &[], None, &[]);
    let (tenant, repo, pool) = (f.tenant, f.repo, f.pool);
    let (_, first) = run(
        &f,
        tenant,
        repo,
        single_job(2, "2GiB", "2GiB").as_str(),
        at(2_000),
    );
    let (_, large) = run(
        &f,
        tenant,
        repo,
        single_job(8, "8GiB", "8GiB").as_str(),
        at(2_100),
    );
    let (_, small) = run(
        &f,
        tenant,
        repo,
        single_job(1, "1GiB", "1GiB").as_str(),
        at(2_200),
    );
    // The oldest job of the repository runs; the large job behind it does
    // not reserve capacity that is already spent.
    let offer = place(&f, w, pool, at(2_300)).unwrap();
    assert_eq!(offer.job, first[0]);
    // The large job cannot fit beside it, and the small job that could is
    // held: its placement would spend the large job's path.
    assert_eq!(place(&f, w, pool, at(2_400)), None);
    assert_eq!(reason(&f, small[0], &[w]), WaitReason::FairnessHold);
    // Release the small attempt: the path is whole and the large job goes.
    finish(&f, w, &offer, at(2_500));
    let placed = place(&f, w, pool, at(3_000)).unwrap();
    assert_eq!(placed.job, large[0]);
    assert_eq!(placed.cpu_millis, 8_000);
}

#[test]
fn pull_request_feedback_keeps_a_quarter_of_the_host() {
    let f = fixture();
    let w = worker(&f, f.pool, 8_000, 16 << 30, 20 << 30, &[], None, &[]);
    let (tenant, repo, pool) = (f.tenant, f.repo, f.pool);
    // A long manual job first, then the pull request's job behind it.
    let (_, manual) = run(
        &f,
        tenant,
        repo,
        single_job(7, "7GiB", "7GiB").as_str(),
        at(2_000),
    );
    let (pr, pr_jobs) = run(
        &f,
        tenant,
        repo,
        single_job(4, "4GiB", "4GiB").as_str(),
        at(2_100),
    );
    record_event(&f, tenant, repo, pr, "pull_request");
    // Placing the manual job would leave less than a quarter of the host
    // free, so it is held while the pull request's job — which fits — is
    // the one that goes.
    assert_eq!(reason(&f, manual[0], &[w]), WaitReason::FairnessHold);
    let offer = place(&f, w, pool, at(2_200)).unwrap();
    assert_eq!(offer.job, pr_jobs[0]);
}

#[test]
fn a_shared_host_is_not_oversubscribed_by_two_identities() {
    let f = fixture();
    let w1 = worker(&f, f.pool, 4_000, 8 << 30, 20 << 30, &[], Some(HOST), &[]);
    let w2 = worker(&f, f.pool, 4_000, 8 << 30, 20 << 30, &[], Some(HOST), &[]);
    let (tenant, repo, pool) = (f.tenant, f.repo, f.pool);
    let (run_id, _) = run(
        &f,
        tenant,
        repo,
        "schema: 1
on: [push]
jobs:
  a:
    image: alpine:3
    resources: { cpu: 3, memory: 4GiB }
    steps: [{ id: s, run: 'true' }]
  b:
    image: alpine:3
    resources: { cpu: 2, memory: 4GiB }
    steps: [{ id: s, run: 'true' }]
",
        at(2_000),
    );
    let (job_a, job_b) = (named(&f, run_id, "a"), named(&f, run_id, "b"));
    let first = place(&f, w1, pool, at(2_100)).unwrap();
    assert_eq!(first.job, job_a);
    // The host's reported millicpu is one machine's, not one per identity:
    // the second web of the same host sees what the first reserved.
    let free1 = f
        .store
        .read(move |c| dispatch::free_capacity(c, w1))
        .unwrap();
    let free2 = f
        .store
        .read(move |c| dispatch::free_capacity(c, w2))
        .unwrap();
    assert_eq!(free1.cpu_millis, 1_000);
    assert_eq!(free2.cpu_millis, 1_000);
    assert_eq!(free1.memory_bytes, 4 << 30);
    assert_eq!(place(&f, w2, pool, at(2_200)), None);
    assert_eq!(reason(&f, job_b, &[w2]), WaitReason::Capacity);
}

#[test]
fn drain_stops_new_offers_until_undrained() {
    let f = fixture();
    let w = worker(&f, f.pool, 8_000, 16 << 30, 20 << 30, &[], None, &[]);
    let (tenant, repo, pool) = (f.tenant, f.repo, f.pool);
    let (_, ids) = run(
        &f,
        tenant,
        repo,
        single_job(1, "1GiB", "1GiB").as_str(),
        at(2_000),
    );
    f.store
        .writer()
        .write(move |tx| workers::drain(tx, Authority::HostLocal, w, at(2_100)))
        .unwrap();
    // Idempotent, and the worker takes nothing while draining.
    f.store
        .writer()
        .write(move |tx| workers::drain(tx, Authority::HostLocal, w, at(2_200)))
        .unwrap();
    assert_eq!(place(&f, w, pool, at(2_300)), None);
    assert_eq!(reason(&f, ids[0], &[w]), WaitReason::Drain);
    f.store
        .writer()
        .write(move |tx| workers::undrain(tx, Authority::HostLocal, w))
        .unwrap();
    assert_eq!(place(&f, w, pool, at(2_400)).unwrap().job, ids[0]);
    // Undrain is idempotent too, and a revoked worker has no drain state.
    f.store
        .writer()
        .write(move |tx| workers::undrain(tx, Authority::HostLocal, w))
        .unwrap();
    f.store
        .writer()
        .write(move |tx| workers::revoke(tx, Authority::HostLocal, w, at(2_500)))
        .unwrap();
    assert!(matches!(
        f.store
            .writer()
            .write(move |tx| workers::drain(tx, Authority::HostLocal, w, at(2_500))),
        Err(Error::NotFound)
    ));
    assert!(matches!(
        f.store
            .writer()
            .write(move |tx| workers::undrain(tx, Authority::HostLocal, w)),
        Err(Error::NotFound)
    ));
}

#[test]
fn a_warm_worker_is_waited_for_only_inside_the_bound() {
    let f = fixture();
    let key = [0xaa_u8; 8];
    let cold = worker(&f, f.pool, 8_000, 16 << 30, 20 << 30, &[], None, &[]);
    let warm = worker(&f, f.pool, 8_000, 16 << 30, 20 << 30, &[], None, &[key]);
    let (tenant, repo, pool) = (f.tenant, f.repo, f.pool);
    let (_, filler) = run(
        &f,
        tenant,
        repo,
        single_job(1, "1GiB", "1GiB").as_str(),
        at(2_000),
    );
    let (_, target) = run(
        &f,
        tenant,
        repo,
        single_job(4, "4GiB", "4GiB").as_str(),
        at(2_100),
    );
    // The warm worker is busy but will free inside the locality window.
    let held = place(&f, warm, pool, at(2_200)).unwrap();
    assert_eq!(held.job, filler[0]);
    // The cold worker passes rather than pulling the image again.
    assert_eq!(place(&f, cold, pool, at(2_300)), None);
    // Past the bound, locality never strands the job.
    let late = at(2_100 + dispatch::LOCALITY_WAIT_MS);
    assert_eq!(place(&f, cold, pool, late).unwrap().job, target[0]);
}

#[test]
fn a_new_run_supersedes_the_live_run_it_replaces() {
    let f = fixture();
    let w = worker(&f, f.pool, 8_000, 16 << 30, 20 << 30, &[], None, &[]);
    let (tenant, repo, pool) = (f.tenant, f.repo, f.pool);
    let deploy = "schema: 1
on: [push]
concurrency: { group: deploy, cancel_in_progress: true }
jobs:
  a:
    image: alpine:3
    resources: { cpu: 1, memory: 1GiB }
    steps: [{ id: s, run: 'true' }]
  b:
    image: alpine:3
    resources: { cpu: 1, memory: 1GiB }
    steps: [{ id: s, run: 'true' }]
";
    let (_, old) = run(&f, tenant, repo, deploy, at(2_000));
    let (new_run, new) = run(&f, tenant, repo, deploy, at(2_100));
    for job in &old {
        assert_eq!(state(&f, *job), JobState::Terminal(Outcome::Canceled));
    }
    for job in &new {
        assert_eq!(state(&f, *job), JobState::Queued);
    }
    // The group is free again, and the replacement run places.
    let replacement = named(&f, new_run, "a");
    assert_eq!(place(&f, w, pool, at(2_200)).unwrap().job, replacement);
    // A group that does not cancel in progress serializes instead: the
    // newer run waits, and says why.
    let serial = "schema: 1
on: [push]
concurrency: { group: serial }
jobs:
  a:
    image: alpine:3
    resources: { cpu: 1, memory: 1GiB }
    steps: [{ id: s, run: 'true' }]
";
    let (_, earlier) = run(&f, tenant, repo, serial, at(2_300));
    let (_, later) = run(&f, tenant, repo, serial, at(2_400));
    assert_eq!(state(&f, earlier[0]), JobState::Queued);
    assert_eq!(state(&f, later[0]), JobState::Queued);
    assert_eq!(reason(&f, later[0], &[w]), WaitReason::ConcurrencyLimit);
}

/// One job with fractional CPU, as the pipeline schema writes it.
fn job_of(cpu: &str, memory: &str) -> String {
    format!(
        "schema: 1
on: [push]
jobs:
  one:
    image: alpine:3
    resources: {{ cpu: \"{cpu}\", memory: {memory}, disk: 1GiB }}
    steps: [{{ id: s, run: 'true' }}]
"
    )
}

/// Place on `w` until nothing more fits, told what the rest of the connected
/// fleet can hold, as one dispatcher visit does.
fn fill(f: &Fixture, w: WorkerId, elsewhere: Capacity, now: UnixMillis) -> Vec<dispatch::Offer> {
    let pool = f.pool;
    f.store
        .writer()
        .write(move |tx| {
            let mut placed = Vec::new();
            while let Some(offer) = dispatch::place_in_fleet(
                tx,
                w,
                pool,
                Some(elsewhere),
                dispatch::DEFAULT_LEASE_MS,
                now,
            )? {
                placed.push(offer);
            }
            Ok(placed)
        })
        .unwrap()
}

/// Q10: a two-tenant burst reaches a mixed fleet and the largest worker is
/// visited first — the order a mid-sweep enqueue or any unlucky sweep order
/// produces. The six-core job fits only that worker, and all the small work
/// is older, so the fair order puts it first. Told what the rest of the
/// fleet can hold, the large worker offers the job only it can run first and
/// the small work lands on the small workers. Plain `place` (the pre-Q10
/// behavior) spends the large worker's room on quarter-core jobs, and the
/// six-core job then waits for capacity nothing in the burst will release.
#[test]
fn a_job_only_the_largest_worker_fits_is_not_stranded_by_small_work() {
    let f = fixture();
    let (other, other_repo) = other_tenant(&f, "beta");
    let (tenant, repo, pool) = (f.tenant, f.repo, f.pool);
    let edge = worker(&f, pool, 2_500, 2 << 30, 64 << 30, &[], None, &[]);
    let standard = worker(&f, pool, 5_000, 8 << 30, 128 << 30, &[], None, &[]);
    let large = worker(&f, pool, 7_000, 16 << 30, 256 << 30, &[], None, &[]);
    for i in 0..8 {
        run(&f, tenant, repo, &job_of("0.25", "128MiB"), at(2_000 + i));
    }
    run(&f, other, other_repo, &job_of("0.25", "128MiB"), at(2_010));
    run(&f, other, other_repo, &job_of("1", "512MiB"), at(2_020));
    run(&f, tenant, repo, &job_of("1", "512MiB"), at(2_030));
    let heavy = run(&f, tenant, repo, &job_of("6", "2GiB"), at(2_100)).1[0];
    let cap = |cpu_millis: i64, memory_bytes: i64, disk_bytes: i64| Capacity {
        cpu_millis,
        memory_bytes,
        disk_bytes,
    };
    let (small, mid, big) = (
        cap(2_500, 2 << 30, 64 << 30),
        cap(5_000, 8 << 30, 128 << 30),
        cap(7_000, 16 << 30, 256 << 30),
    );

    // The rest of the fleet holds at most the standard worker's resources.
    let on_large = fill(&f, large, mid, at(3_000));
    let on_edge = fill(&f, edge, big, at(3_000));
    let on_standard = fill(&f, standard, big, at(3_000));
    assert_eq!(
        state(&f, heavy),
        JobState::Leased,
        "the six-core job is placed"
    );
    assert_eq!(on_large[0].job, heavy, "the exclusive job goes first");
    assert_eq!(
        on_large.len() + on_edge.len() + on_standard.len(),
        12,
        "every job of the burst is leased"
    );
    for (offers, room) in [(&on_large, big), (&on_edge, small), (&on_standard, mid)] {
        let used: i64 = offers.iter().map(|o| o.cpu_millis).sum();
        assert!(used <= room.cpu_millis);
    }
}
