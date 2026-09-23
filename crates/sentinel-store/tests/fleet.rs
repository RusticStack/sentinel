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
    let page = f
        .store
        .read(move |c| dispatch::list_queue(c, tenant, &[w], 100))
        .unwrap();
    assert_eq!(page.total, 5);
    let queue = page.jobs;
    assert_eq!(queue.len(), 5);
    // Compiled order is alphabetical: arm, fits, gpu, huge, scratch.
    assert_eq!(queue[0].job, arm);
    assert_eq!(queue[0].reason, WaitReason::ArchMismatch);
    assert_eq!(queue[1].job, fits);
    // The idle connected worker has the room and nothing holds the job: it
    // is not waiting for capacity, it is next.
    assert_eq!(queue[1].reason, WaitReason::Ready);
    assert_eq!(queue[3].job, huge);
    assert_eq!(queue[4].job, scratch);
    assert!(queue.iter().all(|entry| entry.age_ms > 0));
    // A bounded page is the oldest `limit` jobs, and says how many wait.
    let two = f
        .store
        .read(move |c| dispatch::list_queue(c, tenant, &[w], 2))
        .unwrap();
    assert_eq!(two.total, 5);
    assert_eq!(
        two.jobs.iter().map(|j| j.job).collect::<Vec<_>>(),
        vec![arm, fits]
    );
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
    // A short job: the warm worker is certain to free inside the window.
    let (_, filler) = run(
        &f,
        tenant,
        repo,
        "schema: 1
on: [push]
jobs:
  one:
    image: alpine:3
    timeout: 20s
    resources: { cpu: 1, memory: 1GiB, disk: 1GiB }
    steps: [{ id: s, run: 'true' }]
",
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

/// Place on `w` with plain `place` until nothing more fits (bounded).
fn fill_all(f: &Fixture, w: WorkerId, pool: PoolId, now: UnixMillis) -> Vec<dispatch::Offer> {
    let mut out = Vec::new();
    while let Some(offer) = place(f, w, pool, now) {
        out.push(offer);
        assert!(
            out.len() <= dispatch::MAX_HELD_ATTEMPTS,
            "runaway placement"
        );
    }
    out
}

/// `n` jobs of `cpu` cores each, with an optional extra job-level line.
fn n_jobs(n: usize, cpu: &str, extra: &str) -> String {
    let mut yaml = String::from("schema: 1\non: [push]\njobs:\n");
    for i in 0..n {
        yaml.push_str(&format!(
            "  j{i:03}:\n    image: alpine:3\n{extra}    resources: {{ cpu: \"{cpu}\", memory: 128MiB, disk: 1GiB }}\n    steps: [{{ id: s, run: 'true' }}]\n"
        ));
    }
    yaml
}

/// A tenant with its own dedicated pool (no grant to the fixture's pool).
fn isolated_tenant(f: &Fixture, slug: &str) -> (TenantId, RepoId, PoolId) {
    let (root, tenant, repo, pool) = (f.root, TenantId::new(), RepoId::new(), PoolId::new());
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
            tenancy::create_pool(
                tx,
                Authority::HostLocal,
                pool,
                "private",
                PoolKind::Dedicated(tenant),
                NOW,
            )
        })
        .unwrap();
    (tenant, repo, pool)
}

const SERIAL: &str = "schema: 1
on: [push]
concurrency: { group: serial }
jobs:
  a:
    image: alpine:3
    resources: { cpu: 1, memory: 1GiB }
    steps: [{ id: s, run: 'true' }]
";

/// P08-1: two queued runs of a serializing group used to exclude each other
/// (each saw the other's live job) and neither ever placed. The older run
/// goes first; the newer waits with `ConcurrencyLimit` exactly as long as the
/// older is live, then goes.
#[test]
fn two_queued_runs_of_a_serial_group_both_run_in_order() {
    let f = fixture();
    let w = worker(&f, f.pool, 8_000, 16 << 30, 20 << 30, &[], None, &[]);
    let (tenant, repo, pool) = (f.tenant, f.repo, f.pool);
    let (_, earlier) = run(&f, tenant, repo, SERIAL, at(2_300));
    let (_, later) = run(&f, tenant, repo, SERIAL, at(2_400));
    assert_eq!(reason(&f, earlier[0], &[w]), WaitReason::Ready);
    assert_eq!(reason(&f, later[0], &[w]), WaitReason::ConcurrencyLimit);
    let first = place(&f, w, pool, at(2_500)).expect("the older run places");
    assert_eq!(first.job, earlier[0]);
    // While the older run executes, the newer one waits, with its reason.
    assert_eq!(place(&f, w, pool, at(2_600)), None);
    assert_eq!(reason(&f, later[0], &[w]), WaitReason::ConcurrencyLimit);
    finish(&f, w, &first, at(2_700));
    let second = place(&f, w, pool, at(3_000)).expect("then the newer run places");
    assert_eq!(second.job, later[0]);
}

/// P08-1: a group is a (tenant, repository, key) lock, as documented — a
/// sibling repository's run of the same group name does not wait.
#[test]
fn a_concurrency_group_is_held_per_repository() {
    let f = fixture();
    let w = worker(&f, f.pool, 8_000, 16 << 30, 20 << 30, &[], None, &[]);
    let (tenant, repo, pool) = (f.tenant, f.repo, f.pool);
    let sibling = RepoId::new();
    f.store
        .writer()
        .write(move |tx| jobs::insert_repo(tx, tenant, sibling, "lib", NOW))
        .unwrap();
    let (_, mine) = run(&f, tenant, repo, SERIAL, at(2_300));
    let (_, theirs) = run(&f, tenant, sibling, SERIAL, at(2_400));
    let placed: Vec<JobId> = fill_all(&f, w, pool, at(2_500))
        .iter()
        .map(|o| o.job)
        .collect();
    assert_eq!(placed.len(), 2, "{placed:?}");
    assert!(placed.contains(&mine[0]) && placed.contains(&theirs[0]));
}

/// P08-1: two `cancel_in_progress` runs created in the same millisecond used
/// to survive together (a strict `<` cancelled neither); exactly one does.
#[test]
fn same_millisecond_superseding_runs_leave_exactly_one() {
    let f = fixture();
    let (tenant, repo) = (f.tenant, f.repo);
    let deploy = "schema: 1
on: [push]
concurrency: { group: deploy, cancel_in_progress: true }
jobs:
  a:
    image: alpine:3
    steps: [{ id: s, run: 'true' }]
";
    let (_, first) = run(&f, tenant, repo, deploy, at(2_000));
    let (_, second) = run(&f, tenant, repo, deploy, at(2_000));
    assert_eq!(
        state(&f, first[0]),
        JobState::Terminal(Outcome::Canceled),
        "the run applied first is superseded"
    );
    assert_eq!(state(&f, second[0]), JobState::Queued);
}

/// P08-2: a large job waiting in another tenant's dedicated pool used to hold
/// half of this pool's worker idle.
#[test]
fn a_large_job_in_another_pool_reserves_nothing_here() {
    let f = fixture();
    let w = worker(&f, f.pool, 16_000, 64 << 30, 100 << 30, &[], None, &[]);
    let (y, y_repo, _) = isolated_tenant(&f, "other");
    run(&f, y, y_repo, &single_job(8, "8GiB", "8GiB"), at(2_000));
    run(&f, f.tenant, f.repo, &n_jobs(16, "1", ""), at(2_100));
    assert_eq!(fill_all(&f, w, f.pool, at(2_200)).len(), 16);
}

/// P08-2: an 8-core job no worker here can ever run (arm64 on an x86_64
/// fleet) used to reserve its path for up to the six-hour queue timeout.
#[test]
fn an_unrunnable_large_job_reserves_nothing() {
    let f = fixture();
    let w = worker(&f, f.pool, 16_000, 64 << 30, 100 << 30, &[], None, &[]);
    run(
        &f,
        f.tenant,
        f.repo,
        &n_jobs(1, "8", "    runs_on: { arch: arm64 }\n"),
        at(2_000),
    );
    run(&f, f.tenant, f.repo, &n_jobs(16, "1", ""), at(2_100));
    assert_eq!(fill_all(&f, w, f.pool, at(2_200)).len(), 16);
}

/// P08-2: a pull-request job this worker cannot run (it needs a label the
/// worker lacks) used to keep a quarter of the host idle anyway.
#[test]
fn an_unrunnable_pull_request_job_reserves_nothing() {
    let f = fixture();
    let w = worker(&f, f.pool, 8_000, 64 << 30, 100 << 30, &[], None, &[]);
    let (pr, _) = run(
        &f,
        f.tenant,
        f.repo,
        &n_jobs(1, "1", "    runs_on: { labels: [gpu] }\n"),
        at(2_000),
    );
    record_event(&f, f.tenant, f.repo, pr, "pull_request");
    run(&f, f.tenant, f.repo, &n_jobs(8, "1", ""), at(2_100));
    assert_eq!(fill_all(&f, w, f.pool, at(2_200)).len(), 8);
}

/// P08-3: the pull-request reserve summed every identity on the host, so two
/// identities reserved half the machine instead of a quarter.
#[test]
fn the_pull_request_reserve_counts_the_host_once() {
    let f = fixture();
    let w1 = worker(&f, f.pool, 8_000, 64 << 30, 100 << 30, &[], Some(HOST), &[]);
    let _w2 = worker(&f, f.pool, 8_000, 64 << 30, 100 << 30, &[], Some(HOST), &[]);
    run(&f, f.tenant, f.repo, &n_jobs(8, "1", ""), at(2_000));
    let (pr, _) = run(&f, f.tenant, f.repo, &n_jobs(1, "1", ""), at(2_100));
    record_event(&f, f.tenant, f.repo, pr, "pull_request");
    let placed = fill_all(&f, w1, f.pool, at(2_200));
    let before_pr = placed.iter().take_while(|o| o.run != pr).count();
    // A quarter of one 8-core host (2 cores) stays free for the PR job.
    assert_eq!(before_pr, 6, "{} placed in all", placed.len());
    assert!(placed.iter().any(|o| o.run == pr));
}

/// P08-4: labels were filtered after a per-tenant `LIMIT 32`, so forty `gpu`
/// jobs hid a plain job from an idle worker and the explanation said
/// `Capacity`. Labels are now part of the candidate scan.
#[test]
fn label_mismatched_jobs_never_hide_a_fitting_one() {
    let f = fixture();
    let w = worker(&f, f.pool, 8_000, 64 << 30, 100 << 30, &[], None, &[]);
    run(
        &f,
        f.tenant,
        f.repo,
        &n_jobs(40, "0.25", "    runs_on: { labels: [gpu] }\n"),
        at(2_000),
    );
    let (_, plain) = run(&f, f.tenant, f.repo, &n_jobs(1, "0.25", ""), at(2_100));
    assert_eq!(reason(&f, plain[0], &[w]), WaitReason::Ready);
    let offer = place(&f, w, f.pool, at(2_200)).expect("the plain job places");
    assert_eq!(offer.job, plain[0]);
}

/// P08-4: the same head-of-line hiding for jobs held for locality: forty
/// jobs wait for a warm worker, and a job no worker has warm is still found
/// behind them by paging past the held rows.
#[test]
fn locality_held_jobs_never_hide_a_placeable_one() {
    let f = fixture();
    let key = [0xaa_u8; 8];
    let cold = worker(&f, f.pool, 8_000, 64 << 30, 100 << 30, &[], None, &[]);
    let _warm = worker(&f, f.pool, 8_000, 64 << 30, 100 << 30, &[], None, &[key]);
    let (tenant, repo) = (f.tenant, f.repo);
    run(&f, tenant, repo, &n_jobs(40, "0.25", ""), at(2_000));
    // A different image: nobody has it warm, so nothing holds it.
    let spec = spec(&n_jobs(1, "0.25", ""));
    let other = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let fresh = f
        .store
        .writer()
        .write(move |tx| {
            let ids = runs::create_run(tx, tenant, repo, RunId::new(), &spec, at(2_100))?;
            runs::resolve_image(tx, tenant, ids[0], other, "linux/amd64")?;
            Ok(ids[0])
        })
        .unwrap();
    let offer = place(&f, cold, f.pool, at(2_200)).expect("the fresh-image job places");
    assert_eq!(offer.job, fresh);
}

/// P08-5: repository fairness inside a tenant. Repository A queued twenty
/// jobs before repository B's one; B's job is placed second, not
/// twenty-first.
#[test]
fn a_repository_backlog_does_not_starve_its_siblings() {
    let f = fixture();
    let w = worker(&f, f.pool, 64_000, 64 << 30, 100 << 30, &[], None, &[]);
    let (tenant, repo) = (f.tenant, f.repo);
    let sibling = RepoId::new();
    f.store
        .writer()
        .write(move |tx| jobs::insert_repo(tx, tenant, sibling, "lib", NOW))
        .unwrap();
    run(&f, tenant, repo, &n_jobs(20, "1", ""), at(2_000));
    let (_, theirs) = run(&f, tenant, sibling, &n_jobs(1, "1", ""), at(2_500));
    let first = place(&f, w, f.pool, at(3_000)).unwrap();
    let second = place(&f, w, f.pool, at(3_000)).unwrap();
    assert_ne!(first.job, theirs[0], "the oldest head goes first");
    assert_eq!(second.job, theirs[0], "then the idle repository");
}

/// Q09's noisy tenant, with demand above capacity so the decision is
/// observable: tenant A queues forty jobs first, tenant B four; a worker
/// with room for eight gives B its four within the first eight.
#[test]
fn a_noisy_tenant_does_not_crowd_out_a_quiet_one() {
    let f = fixture();
    let (quiet, quiet_repo) = other_tenant(&f, "quiet");
    let w = worker(&f, f.pool, 8_000, 64 << 30, 100 << 30, &[], None, &[]);
    run(&f, f.tenant, f.repo, &n_jobs(40, "1", ""), at(2_000));
    run(&f, quiet, quiet_repo, &n_jobs(4, "1", ""), at(2_500));
    let placed = fill_all(&f, w, f.pool, at(3_000));
    assert_eq!(placed.len(), 8);
    assert_eq!(placed.iter().filter(|o| o.tenant == quiet).count(), 4);
}

/// P08-6: expected completion, not the lease. A warm worker running a job
/// whose timeout reaches past the locality window is not about to free —
/// renewal keeps its lease inside the window forever — so a cold worker
/// takes the job at once.
#[test]
fn a_busy_warm_worker_with_long_work_does_not_hold_a_cold_job() {
    let f = fixture();
    let key = [0xaa_u8; 8];
    let cold = worker(&f, f.pool, 8_000, 16 << 30, 20 << 30, &[], None, &[]);
    let warm = worker(&f, f.pool, 4_000, 16 << 30, 20 << 30, &[], None, &[key]);
    let (tenant, repo, pool) = (f.tenant, f.repo, f.pool);
    // An hour-long job (the default timeout) fills the warm worker.
    let (_, long) = run(&f, tenant, repo, &single_job(4, "4GiB", "4GiB"), at(2_000));
    assert_eq!(place(&f, warm, pool, at(2_100)).unwrap().job, long[0]);
    let (_, target) = run(&f, tenant, repo, &single_job(4, "4GiB", "4GiB"), at(2_200));
    assert_eq!(reason(&f, target[0], &[cold, warm]), WaitReason::Ready);
    assert_eq!(place(&f, cold, pool, at(2_300)).unwrap().job, target[0]);
}

/// P08-7: revocation fences the live session's attempts at once. The
/// revoked worker can no longer acknowledge, renew, report or publish, and
/// the dispatcher's sweep settles what it held: the acknowledged attempt
/// `Reconciled` (never replayed), the unacknowledged offer back to the queue.
#[test]
fn a_revoked_worker_holds_nothing_and_its_attempts_are_settled() {
    let f = fixture();
    let w = worker(&f, f.pool, 8_000, 16 << 30, 20 << 30, &[], None, &[]);
    let (tenant, repo, pool) = (f.tenant, f.repo, f.pool);
    run(&f, tenant, repo, &n_jobs(2, "1", ""), at(2_000));
    let acked = place(&f, w, pool, at(2_100)).unwrap();
    let offered = place(&f, w, pool, at(2_100)).unwrap();
    let (aa, af, oa, of) = (acked.attempt, acked.fence, offered.attempt, offered.fence);
    f.store
        .writer()
        .write(move |tx| {
            dispatch::acknowledge(tx, w, aa, af, at(2_200))?;
            dispatch::report(
                tx,
                w,
                aa,
                af,
                Event::PreparationStarted,
                None,
                at(2_250),
                None,
            )?;
            workers::revoke(tx, Authority::HostLocal, w, at(2_300))
        })
        .unwrap();
    let store = &f.store;
    assert!(!store.read(|c| dispatch::is_held(c, w, aa)).unwrap());
    assert!(matches!(
        store.writer().write(move |tx| dispatch::renew(
            tx,
            w,
            &[aa],
            dispatch::DEFAULT_LEASE_MS,
            at(2_400)
        )),
        Err(Error::Forbidden)
    ));
    assert!(matches!(
        store
            .writer()
            .write(move |tx| dispatch::acknowledge(tx, w, oa, of, at(2_400))),
        Err(Error::NotFound)
    ));
    assert!(matches!(
        store.writer().write(move |tx| dispatch::report(
            tx,
            w,
            aa,
            af,
            Event::StepsStarted,
            None,
            at(2_400),
            None
        )),
        Err(Error::NotFound)
    ));
    assert!(store.read(|c| dispatch::attempt_scope(c, w, aa)).is_err());
    let settled = store
        .writer()
        .write(|tx| dispatch::reconcile_revoked(tx, at(2_500), None))
        .unwrap();
    assert_eq!(settled, 2);
    assert_eq!(
        state(&f, acked.job),
        JobState::Terminal(Outcome::InfraFailed)
    );
    assert_eq!(state(&f, offered.job), JobState::Queued);
    // Nothing is left to settle.
    assert_eq!(
        store
            .writer()
            .write(|tx| dispatch::reconcile_revoked(tx, at(2_600), None))
            .unwrap(),
        0
    );
}

/// P08-13: a lease that has passed cannot be renewed back to life, and an
/// attempt renewed between the sweep's read and its write is not expired.
#[test]
fn a_passed_lease_stays_expired_and_a_renewed_one_is_not_expired() {
    let f = fixture();
    let w = worker(&f, f.pool, 8_000, 16 << 30, 20 << 30, &[], None, &[]);
    let (tenant, repo, pool) = (f.tenant, f.repo, f.pool);
    run(&f, tenant, repo, &n_jobs(2, "1", ""), at(2_000));
    let a = place(&f, w, pool, at(2_100)).unwrap();
    let b = place(&f, w, pool, at(2_100)).unwrap();
    let (aa, af, ba, bf) = (a.attempt, a.fence, b.attempt, b.fence);
    f.store
        .writer()
        .write(move |tx| {
            dispatch::acknowledge(tx, w, aa, af, at(2_200))?;
            dispatch::acknowledge(tx, w, ba, bf, at(2_200)).map(|_| ())
        })
        .unwrap();
    let lapsed = at(2_100 + dispatch::DEFAULT_LEASE_MS + 1);
    // `a`'s lease passed: a late beat does not resurrect it.
    let (_, stop) = f
        .store
        .writer()
        .write(move |tx| dispatch::renew(tx, w, &[aa], dispatch::DEFAULT_LEASE_MS, lapsed))
        .unwrap();
    assert_eq!(stop, vec![aa]);
    // `b` is renewed in time, then an expiry decided from an older snapshot
    // arrives: it is refused, and `b` keeps running.
    f.store
        .writer()
        .write(move |tx| dispatch::renew(tx, w, &[ba], dispatch::DEFAULT_LEASE_MS, at(20_000)))
        .unwrap();
    assert!(matches!(
        f.store
            .writer()
            .write(move |tx| dispatch::expire(tx, ba, lapsed, None)),
        Err(Error::Conflict)
    ));
    assert_eq!(state(&f, b.job), JobState::Leased);
    f.store
        .writer()
        .write(move |tx| dispatch::expire(tx, aa, lapsed, None))
        .unwrap();
    assert_eq!(state(&f, a.job), JobState::Terminal(Outcome::InfraFailed));
}
