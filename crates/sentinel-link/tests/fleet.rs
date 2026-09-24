//! Q09: a three-worker fleet of mixed capacity over real TLS against a real
//! `Controller`. A burst from two tenants is placed by capacity, a forced
//! partition is survived without duplicate execution, a stale fence changes
//! nothing, and a drained worker takes no new offers while keeping the work
//! it already holds.
//!
//! The executors are recorders: they acknowledge offers and report outcomes
//! by hand. No container, checkout or step ever runs, so this is link and
//! scheduler evidence, not executor evidence.

use std::{
    collections::HashSet,
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicI64, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use sentinel_auth::secret::Secret;
use sentinel_core::{
    AttemptId, Event, Fence, JobId, JobState, Outcome, PoolId, RepoId, RunId, TenantId, UnixMillis,
    UserId, WorkerId,
    auth::{Namespace, Permissions as P, Principal},
};
use sentinel_link::{
    Error,
    controller::{Controller, RECONCILE_INTERVAL},
    identity::Identity,
    session::{self, Capacity, Executor, Offer},
    worker,
};
use sentinel_pipeline::{PinnedSource, RunSpec, compile_str};
use sentinel_protocol::negotiate::{Arch, Capabilities, Hello, Profile, ProtocolVersion};
use sentinel_store::{
    Durability, Store,
    auth::{self, Authority, NamespaceKind, provisioning},
    dispatch, runs,
    tenancy::{self, PoolKind},
    workers,
};

const DIGEST: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const SHA: &str = "0123456789abcdef0123456789abcdef01234567";

/// Mixed capacities, in millicpu and bytes: the six-core job only fits the
/// largest worker, so placement is forced rather than merely plausible.
const EDGE: Capacity = Capacity {
    cpu_millis: 2_500,
    memory_bytes: 2 << 30,
};
const STANDARD: Capacity = Capacity {
    cpu_millis: 5_000,
    memory_bytes: 8 << 30,
};
const LARGE: Capacity = Capacity {
    cpu_millis: 7_000,
    memory_bytes: 16 << 30,
};
const CAPACITIES: [Capacity; 3] = [EDGE, STANDARD, LARGE];

/// Tenant A's build: three sizes, one of which only the large worker can take.
const BUILD: &str = "schema: 1
on: [push]
jobs:
  small:
    image: alpine:3
    resources: { cpu: \"0.25\", memory: 128MiB, disk: 1GiB }
    steps: [{ id: s, run: 'true' }]
  medium:
    image: alpine:3
    resources: { cpu: \"1\", memory: 512MiB, disk: 1GiB }
    steps: [{ id: s, run: 'true' }]
  heavy:
    image: alpine:3
    resources: { cpu: \"6\", memory: 2GiB, disk: 1GiB }
    steps: [{ id: s, run: 'true' }]
";

/// Tenant B's verify: small work for the other tenant on the same pool.
const VERIFY: &str = "schema: 1
on: [push]
jobs:
  b-small:
    image: alpine:3
    resources: { cpu: \"0.25\", memory: 128MiB, disk: 1GiB }
    steps: [{ id: s, run: 'true' }]
  b-medium:
    image: alpine:3
    resources: { cpu: \"1\", memory: 512MiB, disk: 1GiB }
    steps: [{ id: s, run: 'true' }]
";

/// Tenant B asks for more than every worker has: it must never be placed.
const OVERSIZED: &str = "schema: 1
on: [push]
jobs:
  b-huge:
    image: alpine:3
    resources: { cpu: \"7.5\", memory: 2GiB, disk: 1GiB }
    steps: [{ id: s, run: 'true' }]
";

/// Eight quarter-core jobs: tenant A's noisy backlog.
fn noise() -> String {
    let mut yaml = String::from("schema: 1\non: [push]\njobs:\n");
    for i in 0..8 {
        yaml.push_str(&format!(
            "  noise{i}:\n    image: alpine:3\n    resources: {{ cpu: \"0.25\", memory: 128MiB, disk: 1GiB }}\n    steps: [{{ id: s, run: 'true' }}]\n"
        ));
    }
    yaml
}

/// A single quarter-core job, for the probe and the drain phases.
fn one_job() -> String {
    String::from(
        "schema: 1
on: [push]
jobs:
  only:
    image: alpine:3
    resources: { cpu: \"0.25\", memory: 128MiB, disk: 1GiB }
    steps: [{ id: s, run: 'true' }]
",
    )
}

/// What a protocol-7 worker reports about itself. Each worker is its own
/// host here, so host-level aggregation cannot mask per-worker capacity.
fn profile(host: u8, disk_bytes: u64) -> Profile {
    let mut host_id = [0u8; 16];
    host_id[0] = host;
    Profile {
        host_id,
        disk_bytes,
        ..Profile::default()
    }
}

fn hello() -> Hello {
    Hello {
        protocol_min: ProtocolVersion(1),
        protocol_max: ProtocolVersion(7),
        capabilities: Capabilities::REQUIRED,
        arch: Arch::X86_64,
        software: "fleet".into(),
    }
}

struct Deployment {
    _dir: tempfile::TempDir,
    store: Arc<Store>,
    /// Held for the controller's lifetime; the tests read the store.
    _logs: Arc<sentinel_store::logs::LogStore>,
    _objects: Arc<sentinel_store::objects::Objects>,
    controller: Option<Controller>,
    _identity_files: (PathBuf, PathBuf),
    /// Two tenants share one platform pool.
    tenant_a: TenantId,
    tenant_b: TenantId,
    repo_a: RepoId,
    repo_b: RepoId,
    pool: PoolId,
}

fn deployment() -> Deployment {
    let dir = tempfile::tempdir().unwrap();
    let store =
        Arc::new(Store::open(dir.path().join("metadata.sqlite"), Durability::Normal).unwrap());
    let (root, tenant_a, tenant_b, repo_a, repo_b, pool) = (
        UserId::new(),
        TenantId::new(),
        TenantId::new(),
        RepoId::new(),
        RepoId::new(),
        PoolId::new(),
    );
    store
        .writer()
        .write(move |tx| {
            provisioning::insert_human(tx, root, "Root", true, UnixMillis(1))?;
            for (tenant, slug) in [(tenant_a, "acme"), (tenant_b, "beta")] {
                auth::create_namespace(
                    tx,
                    Principal::new(root, P::ALL, None, None),
                    tenant,
                    Namespace::parse(slug).unwrap(),
                    NamespaceKind::Organization,
                    UnixMillis(1),
                )?;
            }
            sentinel_store::jobs::insert_repo(tx, tenant_a, repo_a, "app", UnixMillis(1))?;
            sentinel_store::jobs::insert_repo(tx, tenant_b, repo_b, "app", UnixMillis(1))?;
            tenancy::create_pool(
                tx,
                Authority::HostLocal,
                pool,
                "farm",
                PoolKind::Shared,
                UnixMillis(1),
            )?;
            tenancy::grant_pool(tx, Authority::HostLocal, pool, tenant_a, UnixMillis(1))?;
            tenancy::grant_pool(tx, Authority::HostLocal, pool, tenant_b, UnixMillis(1))
        })
        .unwrap();
    let identity = Identity::generate("controller").unwrap();
    let files = (dir.path().join("c.crt"), dir.path().join("c.key"));
    identity.save(&files.0, &files.1).unwrap();
    let logs = Arc::new(sentinel_store::logs::LogStore::open(dir.path().join("logs")).unwrap());
    let objects =
        Arc::new(sentinel_store::objects::Objects::open(dir.path().join("objects")).unwrap());
    let controller = Controller::start(
        Arc::clone(&store),
        Arc::clone(&logs),
        Arc::clone(&objects),
        identity,
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    Deployment {
        _dir: dir,
        store,
        _logs: logs,
        _objects: objects,
        controller: Some(controller),
        _identity_files: files,
        tenant_a,
        tenant_b,
        repo_a,
        repo_b,
        pool,
    }
}

impl Deployment {
    fn controller(&self) -> &Controller {
        self.controller.as_ref().unwrap()
    }

    fn enrollment(&self) -> Secret {
        let pool = self.pool;
        self.store
            .writer()
            .write(move |tx| {
                workers::issue_enrollment(tx, Authority::HostLocal, pool, 60_000, UnixMillis::now())
            })
            .unwrap()
            .secret
    }

    /// Create runs, resolve every image, and return each run's job ids in
    /// compiled order. No wake: the caller decides when the burst is ready.
    fn runs(&self, specs: Vec<(TenantId, RepoId, String)>) -> Vec<Vec<JobId>> {
        let prepared: Vec<(TenantId, RepoId, RunSpec)> = specs
            .into_iter()
            .map(|(tenant, repo, yaml)| {
                let spec = RunSpec::new(
                    PinnedSource::new("https://github.com/o/r.git", SHA, Some("refs/heads/main"))
                        .unwrap(),
                    compile_str(&yaml).unwrap(),
                )
                .unwrap();
                (tenant, repo, spec)
            })
            .collect();
        self.store
            .writer()
            .write(move |tx| {
                let mut out = Vec::new();
                for (tenant, repo, spec) in prepared {
                    let ids =
                        runs::create_run(tx, tenant, repo, RunId::new(), &spec, UnixMillis::now())?;
                    for job in &ids {
                        runs::resolve_image(tx, tenant, *job, DIGEST, "linux/amd64")?;
                    }
                    out.push(ids);
                }
                Ok(out)
            })
            .unwrap()
    }

    fn state(&self, tenant: TenantId, job: JobId) -> JobState {
        self.store
            .read(move |c| sentinel_store::jobs::get_job(c, tenant, job))
            .unwrap()
            .state
    }

    fn held(&self, worker: WorkerId) -> Vec<dispatch::Held> {
        self.store
            .read(move |c| dispatch::held_by(c, worker))
            .unwrap()
    }
}

/// A worker process: `worker::run` on its own thread with a stop handle.
struct WorkerProcess {
    handle: Arc<worker::Handle>,
    events: Arc<Mutex<Vec<String>>>,
    thread: Option<thread::JoinHandle<Result<(), Error>>>,
}

impl WorkerProcess {
    fn start(
        d: &Deployment,
        identity: Identity,
        id: WorkerId,
        enrollment: Secret,
        capacity: Capacity,
        profile: Profile,
        executor: Arc<Recorder>,
    ) -> WorkerProcess {
        let handle = Arc::new(worker::Handle::new());
        let events = Arc::new(Mutex::new(Vec::new()));
        let config = worker::Config {
            controller: d.controller().local_addr(),
            server: d.controller().fingerprint(),
            worker: id,
            name: "builder".into(),
            hello: hello(),
            capacity,
            profile,
            // Nothing measured: the worker reports no Tailcat transport here.
            transport: Default::default(),
            remote_cache: false,
        };
        let (grip, log) = (Arc::clone(&handle), Arc::clone(&events));
        let thread = thread::spawn(move || {
            worker::run(
                config,
                identity,
                Some(enrollment),
                &*executor,
                &grip,
                &|event| {
                    log.lock().unwrap().push(format!("{event:?}"));
                },
            )
        });
        WorkerProcess {
            handle,
            events,
            thread: Some(thread),
        }
    }

    fn wait_for(&self, needle: &str, count: usize) {
        let deadline = Instant::now() + Duration::from_secs(15);
        while self
            .events
            .lock()
            .unwrap()
            .iter()
            .filter(|e| e.contains(needle))
            .count()
            < count
        {
            assert!(
                Instant::now() < deadline,
                "{:?}",
                self.events.lock().unwrap()
            );
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn stop(mut self) -> Result<(), Error> {
        let asked = Instant::now();
        self.handle.stop();
        let outcome = self.thread.take().unwrap().join().unwrap();
        assert!(asked.elapsed() < Duration::from_secs(15));
        outcome
    }
}

/// What the fleet's executors must do: acknowledge every offer and hold what
/// they accept. No work ever runs.
struct Recorder {
    offers: Mutex<Vec<Offer>>,
    held: Mutex<Vec<AttemptId>>,
    stopped: Mutex<Vec<AttemptId>>,
    renewed: AtomicI64,
    reporter: Mutex<Option<session::Reporter>>,
}

impl Recorder {
    fn new() -> Arc<Recorder> {
        Arc::new(Recorder {
            offers: Mutex::new(Vec::new()),
            held: Mutex::new(Vec::new()),
            stopped: Mutex::new(Vec::new()),
            renewed: AtomicI64::new(0),
            reporter: Mutex::new(None),
        })
    }

    fn reporter(&self) -> session::Reporter {
        self.reporter.lock().unwrap().clone().unwrap()
    }

    fn release(&self, attempt: AttemptId) {
        self.held.lock().unwrap().retain(|a| *a != attempt);
    }
}

impl Executor for Recorder {
    fn offered(&self, offer: &Offer) -> bool {
        self.held.lock().unwrap().push(offer.attempt);
        self.offers.lock().unwrap().push(offer.clone());
        true
    }
    fn stop(&self, attempt: AttemptId) {
        self.stopped.lock().unwrap().push(attempt);
        self.release(attempt);
    }
    fn cancel(&self, _: AttemptId) {}
    fn held(&self) -> Vec<AttemptId> {
        self.held.lock().unwrap().clone()
    }
    fn renewed(&self, until: UnixMillis) {
        self.renewed.store(until.0, Ordering::SeqCst);
    }
    fn attached(&self, reporter: session::Reporter) {
        *self.reporter.lock().unwrap() = Some(reporter);
    }
    fn detached(&self) {
        self.reporter.lock().unwrap().take();
    }
    fn spec(&self, _: AttemptId, _: session::JobContext, _: Vec<u8>) {}
    fn no_spec(&self, _: AttemptId) {}
    fn log_acked(&self, _: AttemptId, _: u64) {}
    fn log_refused(&self, _: AttemptId) {}
}

/// Wait until `predicate` holds, within forty-five seconds. This is a wait,
/// not a latency claim: the burst has to lease under loaded CI machines, and
/// the promptness bound out of an idle fleet is asserted separately.
fn eventually(what: &str, mut predicate: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(45);
    while !predicate() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        thread::sleep(Duration::from_millis(10));
    }
}

/// Run one attempt of `job` to `Passed` through the recorder that holds it.
fn pass(d: &Deployment, fleet: &[(WorkerId, &Arc<Recorder>)], tenant: TenantId, job: JobId) {
    let (worker, recorder) = fleet
        .iter()
        .find(|(w, _)| d.held(*w).iter().any(|h| h.job == job))
        .map(|(w, r)| (*w, Arc::clone(*r)))
        .unwrap();
    // The lease alone is not enough: the report is applied only for an
    // acknowledged attempt, exactly as a real worker would have acked first.
    eventually("the attempt acknowledged", || {
        d.held(worker)
            .iter()
            .any(|h| h.job == job && h.acknowledged)
    });
    let held = d.held(worker).into_iter().find(|h| h.job == job).unwrap();
    for event in [
        Event::StepsStarted,
        Event::FinalizationStarted,
        Event::Passed,
    ] {
        recorder
            .reporter()
            .report(held.attempt, held.fence, event)
            .unwrap();
    }
    eventually("the attempt passed", || {
        d.state(tenant, job) == JobState::Terminal(Outcome::Passed)
    });
    recorder.release(held.attempt);
}

/// `heavy` only fits the largest worker; every other job fits anywhere.
#[test]
fn a_mixed_fleet_places_a_two_tenant_burst_by_capacity_then_survives_a_partition() {
    let mut d = deployment();
    let ids = [WorkerId::new(), WorkerId::new(), WorkerId::new()];
    let recorders = [Recorder::new(), Recorder::new(), Recorder::new()];
    let fleet: Vec<(WorkerId, &Arc<Recorder>)> = ids.iter().copied().zip(&recorders).collect();
    let processes = [
        WorkerProcess::start(
            &d,
            Identity::generate("edge").unwrap(),
            ids[0],
            d.enrollment(),
            EDGE,
            profile(1, 64 << 30),
            Arc::clone(&recorders[0]),
        ),
        WorkerProcess::start(
            &d,
            Identity::generate("standard").unwrap(),
            ids[1],
            d.enrollment(),
            STANDARD,
            profile(2, 128 << 30),
            Arc::clone(&recorders[1]),
        ),
        WorkerProcess::start(
            &d,
            Identity::generate("large").unwrap(),
            ids[2],
            d.enrollment(),
            LARGE,
            profile(3, 256 << 30),
            Arc::clone(&recorders[2]),
        ),
    ];
    for process in &processes {
        process.wait_for("Connected", 1);
    }
    eventually("a three-worker fleet", || {
        let mut live = d.controller().connected();
        live.sort();
        let mut expected = ids.to_vec();
        expected.sort();
        live == expected
    });

    // Protocol 7: wait until every worker's profile (its disk, at least)
    // has reached the store, so the measured burst sees the same facts a
    // real fleet would — and the window below measures the wake alone.
    for worker in ids.iter().copied() {
        eventually("the reported disk", || {
            d.store
                .read(move |c| dispatch::free_capacity(c, worker))
                .unwrap()
                .disk_bytes
                >= 64 << 30
        });
    }

    // One probe job proves placement is live after the profiles; the burst's
    // window then measures the wake alone.
    let probe = d.runs(vec![(d.tenant_b, d.repo_b, one_job())])[0][0];
    d.controller().wake();
    eventually("a probe placement", || {
        d.state(d.tenant_b, probe) == JobState::Leased
    });
    pass(&d, &fleet, d.tenant_b, probe);

    // The burst: tenant A's build and its noisy backlog, tenant B's verify,
    // and one job no worker can ever fit — all enqueued before one wake.
    let acknowledged_before = d.controller().stats().acknowledged.load(Ordering::SeqCst);
    let runs = d.runs(vec![
        (d.tenant_a, d.repo_a, BUILD.to_owned()),
        (d.tenant_a, d.repo_a, noise()),
        (d.tenant_b, d.repo_b, VERIFY.to_owned()),
        (d.tenant_b, d.repo_b, OVERSIZED.to_owned()),
    ]);
    let fitting: Vec<(TenantId, JobId)> = runs[0]
        .iter()
        .map(|j| (d.tenant_a, *j))
        .chain(runs[1].iter().map(|j| (d.tenant_a, *j)))
        .chain(runs[2].iter().map(|j| (d.tenant_b, *j)))
        .collect();
    let huge = runs[3][0];
    let woken = Instant::now();
    d.controller().wake();
    eventually("every fitting job leased", || {
        fitting
            .iter()
            .all(|(tenant, job)| d.state(*tenant, *job) == JobState::Leased)
    });
    // One dispatch pass delivers the whole burst: the wake, not the poll.
    assert!(
        woken.elapsed() < RECONCILE_INTERVAL,
        "the burst took {:?} to place",
        woken.elapsed()
    );
    eventually("all acknowledgements", || {
        d.controller().stats().acknowledged.load(Ordering::SeqCst)
            >= acknowledged_before + fitting.len() as u64
    });

    // Mixed capacity routed deterministically: the six-core job is on the
    // large worker alone, and no worker was oversubscribed by its offers.
    for (index, recorder) in recorders.iter().enumerate() {
        let held = recorder.held();
        let offers = recorder.offers.lock().unwrap();
        let reserved = offers
            .iter()
            .filter(|o| held.contains(&o.attempt))
            .fold((0u64, 0u64), |acc, o| {
                (acc.0 + o.cpu_millis, acc.1 + o.memory_bytes)
            });
        assert!(
            reserved.0 <= CAPACITIES[index].cpu_millis,
            "{:?} offered {} millicpu",
            ids[index],
            reserved.0
        );
        assert!(
            reserved.1 <= CAPACITIES[index].memory_bytes,
            "{:?} offered {} bytes",
            ids[index],
            reserved.1
        );
        for offer in offers.iter() {
            assert!(offer.cpu_millis <= CAPACITIES[index].cpu_millis);
            if offer.cpu_millis == 6_000 {
                assert_eq!(
                    ids[index], ids[2],
                    "the six-core job must land on the large worker"
                );
            }
        }
    }
    assert_eq!(
        recorders[2]
            .offers
            .lock()
            .unwrap()
            .iter()
            .filter(|o| o.cpu_millis == 6_000)
            .count(),
        1,
        "the six-core job belongs to the large worker"
    );

    // Two tenants: every offer says whose job it is, and both tenants ran.
    let (a_offers, b_offers) = recorders.iter().fold((0usize, 0usize), |acc, r| {
        r.offers.lock().unwrap().iter().fold(acc, |acc, o| {
            if o.tenant == d.tenant_a {
                (acc.0 + 1, acc.1)
            } else {
                assert_eq!(o.tenant, d.tenant_b);
                (acc.0, acc.1 + 1)
            }
        })
    });
    assert!(a_offers >= 2 && b_offers >= 1, "{a_offers} vs {b_offers}");

    // The oversized job is unsatisfiable, and its reason says so.
    assert_eq!(d.state(d.tenant_b, huge), JobState::Queued);
    let connected = d.controller().connected();
    let reason = d
        .store
        .read(|c| dispatch::wait_reason(c, d.tenant_b, huge, &connected))
        .unwrap();
    assert!(
        matches!(reason, dispatch::WaitReason::NoMatchingWorker { .. }),
        "{reason:?}"
    );
    assert!(
        recorders
            .iter()
            .all(|r| r.offers.lock().unwrap().iter().all(|o| o.job != huge))
    );

    // A forced partition: the large worker's session is closed from the
    // controller's side, it reconnects, and its acknowledged lease survives
    // the gap — no second offer, no second execution anywhere.
    let heavy_offer = recorders[2]
        .offers
        .lock()
        .unwrap()
        .iter()
        .find(|o| o.cpu_millis == 6_000)
        .cloned()
        .expect("the six-core job was offered to the large worker");
    let large = ids[2];
    let handle = d.controller().handle();
    assert!(handle.disconnect(large));
    eventually("the fleet forgets the partition", || {
        !d.controller().connected().contains(&large)
    });
    processes[2].wait_for("Disconnected", 1);
    processes[2].wait_for("Connected", 2);
    eventually("the reconnected fleet", || {
        d.controller().connected().contains(&large)
    });
    let held = d.held(large);
    let heavy_attempt = held
        .iter()
        .find(|h| h.attempt == heavy_offer.attempt)
        .unwrap();
    assert_eq!(d.state(d.tenant_a, heavy_attempt.job), JobState::Leased);
    assert!(heavy_attempt.acknowledged);
    // The new session renews the recovered lease before anything is
    // reported through it: the reporter is live and owns the attempt.
    let lease_before = heavy_attempt.lease_until;
    eventually("the recovered lease renewed", || {
        d.held(large)
            .iter()
            .any(|h| h.attempt == heavy_attempt.attempt && h.lease_until > lease_before)
    });
    assert_eq!(
        recorders[2]
            .offers
            .lock()
            .unwrap()
            .iter()
            .filter(|o| o.attempt == heavy_offer.attempt)
            .count(),
        1,
        "a healthy-session retransmit must not execute the job twice"
    );

    // The worker holding `heavy` finishes it over the new session: the same
    // attempt, the same fence, exactly one terminal outcome.
    for event in [
        Event::StepsStarted,
        Event::FinalizationStarted,
        Event::Passed,
    ] {
        recorders[2]
            .reporter()
            .report(heavy_attempt.attempt, heavy_attempt.fence, event)
            .unwrap();
    }
    eventually("heavy passed exactly once", || {
        d.state(d.tenant_a, heavy_attempt.job) == JobState::Terminal(Outcome::Passed)
    });
    recorders[2].release(heavy_attempt.attempt);

    // A stale fence through a live session changes nothing and is counted.
    let (stale_worker, stale_recorder) = fleet
        .iter()
        .find(|(w, _)| !d.held(*w).is_empty())
        .map(|(w, r)| (*w, Arc::clone(*r)))
        .unwrap();
    let stale = d.held(stale_worker)[0];
    let stale_before = d.controller().stats().stale_reports.load(Ordering::SeqCst);
    stale_recorder
        .reporter()
        .report(stale.attempt, Fence(stale.fence.0 + 7), Event::Passed)
        .unwrap();
    eventually("stale report counted", || {
        d.controller().stats().stale_reports.load(Ordering::SeqCst) > stale_before
    });
    assert!(d.state(stale.tenant, stale.job).is_worker_owned());

    // No attempt was ever offered twice, in or across sessions.
    let mut seen = HashSet::new();
    for recorder in &recorders {
        for offer in recorder.offers.lock().unwrap().iter() {
            assert!(
                seen.insert(offer.attempt),
                "duplicate offer {:?}",
                offer.attempt
            );
        }
    }

    for process in processes {
        process.stop().unwrap();
    }
    eventually("an empty fleet", || d.controller().connected().is_empty());
    assert!(
        d.controller
            .take()
            .unwrap()
            .shutdown(Duration::from_secs(5))
    );
}

/// A drained worker takes no new offers, keeps the attempt it already holds,
/// and resumes placing when undrained. The wait reason names the drain.
#[test]
fn a_drained_worker_takes_no_new_offers_and_keeps_its_held_attempt() {
    let mut d = deployment();
    let id = WorkerId::new();
    let recorder = Recorder::new();
    let process = WorkerProcess::start(
        &d,
        Identity::generate("drain").unwrap(),
        id,
        d.enrollment(),
        STANDARD,
        profile(1, 128 << 30),
        Arc::clone(&recorder),
    );
    process.wait_for("Connected", 1);
    eventually("fleet", || d.controller().connected() == vec![id]);

    // The only worker takes and acknowledges one job before the drain.
    let first = d.runs(vec![(d.tenant_a, d.repo_a, one_job())])[0][0];
    d.controller().wake();
    eventually("the first job leased", || {
        d.state(d.tenant_a, first) == JobState::Leased
    });
    eventually("the first job acknowledged", || {
        d.controller().stats().acknowledged.load(Ordering::SeqCst) == 1
    });
    assert_eq!(d.held(id).len(), 1);

    // Drained: a second job waits with the drain as its reason, the held
    // attempt is not released and the worker is not told to stop.
    d.store
        .writer()
        .write(move |tx| workers::drain(tx, Authority::HostLocal, id, UnixMillis::now()))
        .unwrap();
    let second = d.runs(vec![(d.tenant_a, d.repo_a, one_job())])[0][0];
    d.controller().wake();
    eventually("the drain reason", || {
        let tenant = d.tenant_a;
        let connected = d.controller().connected();
        d.store
            .read(|c| dispatch::wait_reason(c, tenant, second, &connected))
            .unwrap()
            == dispatch::WaitReason::Drain
    });
    assert_eq!(
        recorder.offers.lock().unwrap().len(),
        1,
        "a draining worker took a new offer"
    );
    assert_eq!(d.held(id).len(), 1, "draining must not release held work");
    assert!(recorder.stopped.lock().unwrap().is_empty());

    // Undrained, the waiting job is placed under a fresh attempt.
    d.store
        .writer()
        .write(move |tx| workers::undrain(tx, Authority::HostLocal, id))
        .unwrap();
    d.controller().wake();
    eventually("the second job leased after undrain", || {
        d.state(d.tenant_a, second) == JobState::Leased
    });
    // Leased is written with the offer; the worker records the offer when
    // it arrives.
    eventually("the second offer delivered", || {
        recorder.offers.lock().unwrap().len() >= 2
    });
    assert_eq!(recorder.offers.lock().unwrap().len(), 2);
    assert_eq!(d.held(id).len(), 2);

    process.stop().unwrap();
    assert!(
        d.controller
            .take()
            .unwrap()
            .shutdown(Duration::from_secs(5))
    );
}

/// Start `n` identical protocol-7 workers, each its own host, and wait until
/// all are connected with their profiles recorded.
fn identical_fleet(
    d: &Deployment,
    n: usize,
) -> (Vec<WorkerId>, Vec<Arc<Recorder>>, Vec<WorkerProcess>) {
    let ids: Vec<WorkerId> = (0..n).map(|_| WorkerId::new()).collect();
    let recorders: Vec<Arc<Recorder>> = (0..n).map(|_| Recorder::new()).collect();
    let processes: Vec<WorkerProcess> = ids
        .iter()
        .zip(&recorders)
        .enumerate()
        .map(|(i, (id, recorder))| {
            WorkerProcess::start(
                d,
                Identity::generate(&format!("same-{i}")).unwrap(),
                *id,
                d.enrollment(),
                STANDARD,
                profile(10 + i as u8, 128 << 30),
                Arc::clone(recorder),
            )
        })
        .collect();
    for process in &processes {
        process.wait_for("Connected", 1);
    }
    eventually("the fleet", || d.controller().connected().len() == n);
    for worker in ids.iter().copied() {
        eventually("the reported disk", || {
            d.store
                .read(move |c| dispatch::free_capacity(c, worker))
                .unwrap()
                .disk_bytes
                >= 64 << 30
        });
    }
    (ids, recorders, processes)
}

/// P08-6: the sweep used to fill one worker to capacity before asking the
/// next, so a burst of three quarter-core jobs landed on whichever idle
/// worker came first while two identical peers idled. Placement now goes in
/// rounds ranked by commitment and measured load: each worker gets one.
#[test]
fn a_burst_spreads_over_identical_workers() {
    let mut d = deployment();
    let (_, recorders, processes) = identical_fleet(&d, 3);
    let burst = d.runs(vec![(d.tenant_a, d.repo_a, noise_of(3))]);
    d.controller().wake();
    eventually("the burst leased", || {
        burst[0]
            .iter()
            .all(|job| d.state(d.tenant_a, *job) == JobState::Leased)
    });
    // A job is leased when its offer is written; the worker records the
    // offer only when it arrives. Wait for all three to arrive, then judge
    // where they went.
    eventually("every offer delivered", || {
        recorders
            .iter()
            .map(|r| r.offers.lock().unwrap().len())
            .sum::<usize>()
            >= 3
    });
    let per_worker: Vec<usize> = recorders
        .iter()
        .map(|r| r.offers.lock().unwrap().len())
        .collect();
    assert_eq!(per_worker, vec![1, 1, 1], "offers per worker");
    for process in processes {
        process.stop().unwrap();
    }
    assert!(
        d.controller
            .take()
            .unwrap()
            .shutdown(Duration::from_secs(5))
    );
}

/// P08-7: revocation is written by another process (the host-local admin
/// command); the controller notices within a reconciliation pass, closes the
/// revoked worker's live session, and fences what it held — the
/// acknowledged attempt ends `Reconciled` rather than renewing forever — and
/// the worker cannot come back.
#[test]
fn revoking_a_connected_worker_ends_its_session_and_fences_its_work() {
    let mut d = deployment();
    let (ids, recorders, mut processes) = identical_fleet(&d, 1);
    let worker = ids[0];
    let job = d.runs(vec![(d.tenant_a, d.repo_a, one_job())])[0][0];
    d.controller().wake();
    eventually("the job acknowledged", || {
        d.held(worker)
            .iter()
            .any(|h| h.job == job && h.acknowledged)
    });
    let revoked_at = Instant::now();
    d.store
        .writer()
        .write(move |tx| workers::revoke(tx, Authority::HostLocal, worker, UnixMillis::now()))
        .unwrap();
    eventually("the attempt fenced", || {
        d.state(d.tenant_a, job) == JobState::Terminal(Outcome::InfraFailed)
    });
    eventually("the session closed", || {
        !d.controller().connected().contains(&worker)
    });
    assert!(
        revoked_at.elapsed() < RECONCILE_INTERVAL * 3,
        "revocation took {:?} to take effect",
        revoked_at.elapsed()
    );
    assert_eq!(
        d.controller()
            .stats()
            .revoked_sessions
            .load(Ordering::SeqCst),
        1
    );
    assert_eq!(
        d.store
            .read(|c| sentinel_store::jobs::get_job(c, d.tenant_a, job))
            .unwrap()
            .failure_class,
        Some(sentinel_core::FailureClass::Reconciled)
    );
    assert!(d.held(worker).is_empty());
    // The worker is refused on reconnect: its loop ends with the rejection.
    let process = processes.pop().unwrap();
    let outcome = process.stop();
    assert!(
        matches!(outcome, Err(Error::Rejected(_)) | Ok(())),
        "{outcome:?}"
    );
    drop(recorders);
    assert!(
        d.controller
            .take()
            .unwrap()
            .shutdown(Duration::from_secs(5))
    );
}

/// `n` quarter-core jobs of one run.
fn noise_of(n: usize) -> String {
    let mut yaml = String::from("schema: 1\non: [push]\njobs:\n");
    for i in 0..n {
        yaml.push_str(&format!(
            "  n{i}:\n    image: alpine:3\n    resources: {{ cpu: \"0.25\", memory: 128MiB, disk: 1GiB }}\n    steps: [{{ id: s, run: 'true' }}]\n"
        ));
    }
    yaml
}

/// P08-15: a store error in placement used to be dropped silently, so a
/// fleet that stopped placing left no evidence. Break the schema under a
/// running controller: the failure is counted (and logged by kind), the
/// loop keeps running, and nothing is offered.
#[test]
fn a_failing_placement_is_counted_not_swallowed() {
    let mut d = deployment();
    let (_, recorders, processes) = identical_fleet(&d, 1);
    d.store
        .writer()
        .raw(|c| {
            c.execute_batch("ALTER TABLE jobs RENAME COLUMN pull_request TO pull_request_gone")?;
            Ok(())
        })
        .unwrap();
    d.runs(vec![(d.tenant_a, d.repo_a, one_job())]);
    d.controller().wake();
    eventually("the placement failure counted", || {
        d.controller()
            .stats()
            .placement_errors
            .load(Ordering::SeqCst)
            > 0
    });
    assert!(recorders[0].offers.lock().unwrap().is_empty());
    for process in processes {
        process.stop().unwrap();
    }
    assert!(
        d.controller
            .take()
            .unwrap()
            .shutdown(Duration::from_secs(5))
    );
}

/// T2 (Q07): transport telemetry used to be measured once at process start
/// and replayed on every session. With a live source on the worker handle
/// (the Tailcat helper's latest probe), each session reports what the helper
/// last measured — here a relayed path, then, after the helper re-measures
/// and the session reconnects, a direct one — and the controller exposes it
/// per worker.
#[test]
fn each_session_reports_the_helpers_latest_transport_measurement() {
    use sentinel_link::session::{Path, TransportStats};
    let mut d = deployment();
    let id = WorkerId::new();
    let measured = Arc::new(Mutex::new(Path::Relay));
    let handle = Arc::new(worker::Handle::new());
    {
        let measured = Arc::clone(&measured);
        handle.set_transport_source(Arc::new(move || TransportStats {
            path: *measured.lock().unwrap(),
            rtt_ns: Some(5_000_000),
            helper_version: Some("tailcat 0.6.0".into()),
            ..TransportStats::default()
        }));
    }
    let config = worker::Config {
        controller: d.controller().local_addr(),
        server: d.controller().fingerprint(),
        worker: id,
        name: "measured".into(),
        hello: hello(),
        capacity: STANDARD,
        profile: profile(40, 128 << 30),
        // What a process without a live source would send: never used here.
        transport: TransportStats::default(),
        remote_cache: false,
    };
    let (enrollment, recorder, grip) = (d.enrollment(), Recorder::new(), Arc::clone(&handle));
    let identity = Identity::generate("measured").unwrap();
    let thread = thread::spawn(move || {
        worker::run(
            config,
            identity,
            Some(enrollment),
            &*recorder,
            &grip,
            &|_| {},
        )
    });
    let link = d.controller().handle();
    eventually("the relayed path reported", || {
        link.transport(id).is_some_and(|t| t.path == Path::Relay)
    });
    let first = link.transport(id).unwrap();
    assert_eq!(first.helper_version.as_deref(), Some("tailcat 0.6.0"));
    assert_eq!(first.reconnects, 0);

    // The helper re-measures a direct path; the next session reports it.
    *measured.lock().unwrap() = Path::Direct;
    assert!(link.disconnect(id));
    eventually("the re-measured path reported", || {
        link.transport(id)
            .is_some_and(|t| t.path == Path::Direct && t.reconnects == 1)
    });

    handle.stop();
    thread.join().unwrap().unwrap();
    assert!(
        d.controller
            .take()
            .unwrap()
            .shutdown(Duration::from_secs(5))
    );
}
