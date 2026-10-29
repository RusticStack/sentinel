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
    controller::{Controller, OrderFactor, PlacementOrder, RECONCILE_INTERVAL},
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

const OVERSIZED: &str = "schema: 1
on: [push]
jobs:
  b-huge:
    image: alpine:3
    resources: { cpu: \"7.5\", memory: 2GiB, disk: 1GiB }
    steps: [{ id: s, run: 'true' }]
";

fn noise() -> String {
    let mut yaml = String::from("schema: 1\non: [push]\njobs:\n");
    for i in 0..8 {
        yaml.push_str(&format!(
            "  noise{i}:\n    image: alpine:3\n    resources: {{ cpu: \"0.25\", memory: 128MiB, disk: 1GiB }}\n    steps: [{{ id: s, run: 'true' }}]\n"
        ));
    }
    yaml
}

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
    _logs: Arc<sentinel_store::logs::LogStore>,
    _objects: Arc<sentinel_store::objects::Objects>,
    controller: Option<Controller>,
    _identity_files: (PathBuf, PathBuf),
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

    fn enrollment_with(&self, policy: workers::HostPolicy) -> Secret {
        self.enrollment_in(self.pool, policy)
    }

    fn enrollment_in(&self, pool: PoolId, policy: workers::HostPolicy) -> Secret {
        let terms = workers::EnrollmentTerms {
            pool,
            lifetime_ms: 60_000,
            policy,
            tailcat: false,
        };
        self.store
            .writer()
            .write(move |tx| {
                workers::issue_enrollment_with(tx, Authority::HostLocal, terms, UnixMillis::now())
            })
            .unwrap()
            .secret
    }

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
            also_pinned: Vec::new(),
            worker: id,
            name: "builder".into(),
            hello: hello(),
            capacity,
            profile,
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

fn eventually(what: &str, mut predicate: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(45);
    while !predicate() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        thread::sleep(Duration::from_millis(10));
    }
}

fn pass(d: &Deployment, fleet: &[(WorkerId, &Arc<Recorder>)], tenant: TenantId, job: JobId) {
    let (worker, recorder) = fleet
        .iter()
        .find(|(w, _)| d.held(*w).iter().any(|h| h.job == job))
        .map(|(w, r)| (*w, Arc::clone(*r)))
        .unwrap();
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

    for worker in ids.iter().copied() {
        eventually("the reported disk", || {
            d.store
                .read(move |c| dispatch::free_capacity(c, worker))
                .unwrap()
                .disk_bytes
                >= 64 << 30
        });
    }

    let probe = d.runs(vec![(d.tenant_b, d.repo_b, one_job())])[0][0];
    d.controller().wake();
    eventually("a probe placement", || {
        d.state(d.tenant_b, probe) == JobState::Leased
    });
    pass(&d, &fleet, d.tenant_b, probe);

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
    assert!(
        woken.elapsed() < RECONCILE_INTERVAL,
        "the burst took {:?} to place",
        woken.elapsed()
    );
    eventually("all acknowledgements", || {
        d.controller().stats().acknowledged.load(Ordering::SeqCst)
            >= acknowledged_before + fitting.len() as u64
    });

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

    let first = d.runs(vec![(d.tenant_a, d.repo_a, one_job())])[0][0];
    d.controller().wake();
    eventually("the first job leased", || {
        d.state(d.tenant_a, first) == JobState::Leased
    });
    eventually("the first job acknowledged", || {
        d.controller().stats().acknowledged.load(Ordering::SeqCst) == 1
    });
    assert_eq!(d.held(id).len(), 1);

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

    d.store
        .writer()
        .write(move |tx| workers::undrain(tx, Authority::HostLocal, id))
        .unwrap();
    d.controller().wake();
    eventually("the second job leased after undrain", || {
        d.state(d.tenant_a, second) == JobState::Leased
    });
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
    // The worker redials after its shortest back-off and is told why it is refused, not just that it is.
    eventually("the redial refused as revoked", || {
        d.controller()
            .stats()
            .revoked_refused
            .load(Ordering::SeqCst)
            >= 1
    });
    let process = processes.pop().unwrap();
    let outcome = process.stop();
    assert!(
        matches!(outcome, Err(Error::Rejected(session::Rejection::Revoked))),
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

fn noise_of(n: usize) -> String {
    let mut yaml = String::from("schema: 1\non: [push]\njobs:\n");
    for i in 0..n {
        yaml.push_str(&format!(
            "  n{i}:\n    image: alpine:3\n    resources: {{ cpu: \"0.25\", memory: 128MiB, disk: 1GiB }}\n    steps: [{{ id: s, run: 'true' }}]\n"
        ));
    }
    yaml
}

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
        also_pinned: Vec::new(),
        worker: id,
        name: "measured".into(),
        hello: hello(),
        capacity: STANDARD,
        profile: profile(40, 128 << 30),
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

/// A profile that also reports the measured load and warm cache the ranking reads.
fn measured(host: u8, load_ns: u64, cache_bytes: u64) -> Profile {
    let mut p = profile(host, 128 << 30);
    p.availability.load_ns = load_ns;
    p.availability.cache_bytes = cache_bytes;
    p
}

fn start_fleet(
    d: &Deployment,
    profiles: Vec<Profile>,
) -> (Vec<WorkerId>, Vec<Arc<Recorder>>, Vec<WorkerProcess>) {
    let members = profiles
        .into_iter()
        .map(|profile| (profile, d.enrollment()))
        .collect();
    start_members(d, members)
}

/// Workers that each bring their own enrollment (so their own pool, ceilings and priority).
fn start_members(
    d: &Deployment,
    members: Vec<(Profile, Secret)>,
) -> (Vec<WorkerId>, Vec<Arc<Recorder>>, Vec<WorkerProcess>) {
    let n = members.len();
    let ids: Vec<WorkerId> = (0..n).map(|_| WorkerId::new()).collect();
    let recorders: Vec<Arc<Recorder>> = (0..n).map(|_| Recorder::new()).collect();
    let processes: Vec<WorkerProcess> = members
        .into_iter()
        .enumerate()
        .map(|(i, (profile, enrollment))| {
            WorkerProcess::start(
                d,
                Identity::generate(&format!("ranked-{i}")).unwrap(),
                ids[i],
                enrollment,
                STANDARD,
                profile,
                Arc::clone(&recorders[i]),
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

fn offered(recorders: &[Arc<Recorder>]) -> Vec<usize> {
    recorders
        .iter()
        .map(|r| r.offers.lock().unwrap().len())
        .collect()
}

fn finish(mut d: Deployment, processes: Vec<WorkerProcess>) {
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

/// Two worker identities on one machine each report the whole machine. A burst smaller than the
/// number of identities must not give that one machine two jobs while another machine idles.
#[test]
fn identities_sharing_a_host_do_not_take_a_burst_together() {
    let d = deployment();
    let (_, recorders, processes) = start_fleet(
        &d,
        vec![
            profile(40, 128 << 30),
            profile(40, 128 << 30),
            profile(41, 128 << 30),
        ],
    );
    let burst = d.runs(vec![(d.tenant_a, d.repo_a, noise_of(2))]);
    d.controller().wake();
    eventually("the burst leased", || {
        burst[0]
            .iter()
            .all(|job| d.state(d.tenant_a, *job) == JobState::Leased)
    });
    eventually("every offer delivered", || {
        offered(&recorders).iter().sum::<usize>() >= 2
    });
    let per_identity = offered(&recorders);
    assert_eq!(
        per_identity[0] + per_identity[1],
        1,
        "the shared host holds one job: {per_identity:?}"
    );
    assert_eq!(per_identity[2], 1, "the other host takes the other");
    finish(d, processes);
}

const FIVE_CORES_NS: u64 = 5 * 100_000_000;

/// A warm cache outweighs a half-busy host (the job still has cores to itself) but not a host the
/// job would oversubscribe: locality is bounded and cannot strand work behind a saturated machine.
#[test]
fn locality_offsets_moderate_load_but_not_a_saturated_host() {
    for (warm_load_ns, warm_wins) in [(FIVE_CORES_NS / 2, true), (FIVE_CORES_NS, false)] {
        let d = deployment();
        let (_, recorders, processes) = start_fleet(
            &d,
            vec![measured(50, warm_load_ns, 4 << 30), measured(51, 0, 0)],
        );
        let burst = d.runs(vec![(d.tenant_a, d.repo_a, noise_of(1))]);
        d.controller().wake();
        eventually("the job leased", || {
            d.state(d.tenant_a, burst[0][0]) == JobState::Leased
        });
        eventually("the offer delivered", || {
            offered(&recorders).iter().sum::<usize>() >= 1
        });
        let got = offered(&recorders);
        let expected = if warm_wins { vec![1, 0] } else { vec![0, 1] };
        assert_eq!(got, expected, "warm host load {warm_load_ns} ns");
        finish(d, processes);
    }
}

/// Measured load that no attempt of ours explains still counts: a busy machine yields to an idle one.
#[test]
fn measured_throughput_steers_a_job_to_the_idle_worker() {
    let d = deployment();
    let (_, recorders, processes) = start_fleet(
        &d,
        vec![
            measured(60, FIVE_CORES_NS, 0),
            measured(61, 0, 0),
            measured(62, FIVE_CORES_NS, 0),
        ],
    );
    let burst = d.runs(vec![(d.tenant_a, d.repo_a, noise_of(1))]);
    d.controller().wake();
    eventually("the job leased", || {
        d.state(d.tenant_a, burst[0][0]) == JobState::Leased
    });
    eventually("the offer delivered", || {
        offered(&recorders).iter().sum::<usize>() >= 1
    });
    assert_eq!(offered(&recorders), vec![0, 1, 0]);
    finish(d, processes);
}

/// An uninstall is not an eviction: the worker finishes what it accepted, takes nothing new, and is
/// then revoked by the controller's own pass, which ends its session.
#[test]
fn an_uninstalled_worker_finishes_its_attempt_then_is_revoked() {
    let mut d = deployment();
    let id = WorkerId::new();
    let recorder = Recorder::new();
    let process = WorkerProcess::start(
        &d,
        Identity::generate("uninstall").unwrap(),
        id,
        d.enrollment(),
        STANDARD,
        profile(70, 128 << 30),
        Arc::clone(&recorder),
    );
    process.wait_for("Connected", 1);
    eventually("fleet", || d.controller().connected() == vec![id]);

    let first = d.runs(vec![(d.tenant_a, d.repo_a, one_job())])[0][0];
    d.controller().wake();
    eventually("the first job leased", || {
        d.state(d.tenant_a, first) == JobState::Leased
    });
    eventually("the first job acknowledged", || {
        d.controller().stats().acknowledged.load(Ordering::SeqCst) == 1
    });

    d.store
        .writer()
        .write(move |tx| {
            workers::request_uninstall(tx, Authority::HostLocal, id, UnixMillis::now())
        })
        .unwrap();
    let second = d.runs(vec![(d.tenant_a, d.repo_a, one_job())])[0][0];
    d.controller().wake();
    thread::sleep(Duration::from_millis(300));
    assert_eq!(
        d.controller().connected(),
        vec![id],
        "revoked with work held"
    );
    assert_eq!(d.held(id).len(), 1);
    assert_eq!(
        recorder.offers.lock().unwrap().len(),
        1,
        "an uninstalling worker took a new offer"
    );
    assert_eq!(d.state(d.tenant_a, second), JobState::Queued);

    pass(&d, &[(id, &recorder)], d.tenant_a, first);
    d.controller().wake();
    eventually("the uninstall settled", || {
        d.store.read(move |c| workers::revoked(c, id)).unwrap()
    });
    eventually("the session ended", || {
        d.controller().connected().is_empty()
    });
    let _ = process.stop();
    assert!(
        d.controller
            .take()
            .unwrap()
            .shutdown(Duration::from_secs(5))
    );
}

/// The ceiling is the controller's: a worker whose hello claims 5 cores is offered work for the 1 core it
/// was approved for, and a raised ceiling is used at once, up to the host's own claim and no further.
#[test]
fn a_worker_that_claims_more_than_its_approved_ceiling_is_offered_no_more() {
    let mut d = deployment();
    let id = WorkerId::new();
    let recorder = Recorder::new();
    let process = WorkerProcess::start(
        &d,
        Identity::generate("capped").unwrap(),
        id,
        d.enrollment_with(workers::HostPolicy {
            cpu_millis: Some(1_000),
            priority: 40,
            ..workers::HostPolicy::default()
        }),
        STANDARD,
        profile(80, 128 << 30),
        Arc::clone(&recorder),
    );
    process.wait_for("Connected", 1);
    eventually("fleet", || d.controller().connected() == vec![id]);

    // Eight quarter-core jobs: 5 cores would take them all; the approved core takes four.
    let jobs = d.runs(vec![(d.tenant_a, d.repo_a, noise())])[0].clone();
    assert_eq!(jobs.len(), 8);
    d.controller().wake();
    eventually("four offers", || recorder.offers.lock().unwrap().len() == 4);
    thread::sleep(Duration::from_millis(300));
    assert_eq!(
        recorder.offers.lock().unwrap().len(),
        4,
        "the worker was offered more than its approved CPU"
    );
    let known = d
        .store
        .read(|c| workers::host_view(c, Authority::HostLocal, id))
        .unwrap();
    assert_eq!(known.policy.cpu_millis, Some(1_000));
    assert_eq!(known.policy.priority, 40);
    assert_eq!(known.reported_cpu_millis, 5_000);
    assert_eq!(known.effective_cpu_millis, 1_000);

    // Doubling the ceiling needs no new hello: the remaining four jobs go out.
    d.store
        .writer()
        .write(move |tx| {
            workers::set_policy(
                tx,
                Authority::HostLocal,
                id,
                workers::HostPolicy {
                    cpu_millis: Some(2_000),
                    priority: 40,
                    ..workers::HostPolicy::default()
                },
            )
        })
        .unwrap();
    d.controller().wake();
    eventually("eight offers", || {
        recorder.offers.lock().unwrap().len() == 8
    });

    assert_eq!(d.held(id).len(), 8);
    process.stop().unwrap();
    assert!(
        d.controller
            .take()
            .unwrap()
            .shutdown(Duration::from_secs(5))
    );
}

const GPU_JOB: &str = "schema: 1
on: [push]
jobs:
  needs-gpu:
    image: alpine:3
    runs_on: { labels: [gpu] }
    resources: { cpu: \"0.25\", memory: 128MiB, disk: 1GiB }
    steps: [{ id: s, run: 'true' }]
";

const TWO_CORES: &str = "schema: 1
on: [push]
jobs:
  wide:
    image: alpine:3
    resources: { cpu: \"2\", memory: 256MiB, disk: 1GiB }
    steps: [{ id: s, run: 'true' }]
";

fn priority(priority: i32) -> workers::HostPolicy {
    workers::HostPolicy {
        priority,
        ..workers::HostPolicy::default()
    }
}

/// The operator's priority is an explicit policy that orders the free workers ahead of speed. By
/// default the fastest eligible host wins, whatever priority it was given.
#[test]
fn priority_orders_free_workers_ahead_of_speed_only_when_the_policy_is_on() {
    for (order, prefers_busy_priority_host) in [
        (PlacementOrder::Fastest, false),
        (PlacementOrder::Priority, true),
    ] {
        let d = deployment();
        d.controller().set_placement_order(order);
        // Host 100 is idle and neutral; host 101 is saturated by work we did not place and has priority 20.
        let (ids, recorders, processes) = start_members(
            &d,
            vec![
                (measured(100, 0, 0), d.enrollment_with(priority(0))),
                (
                    measured(101, FIVE_CORES_NS, 0),
                    d.enrollment_with(priority(20)),
                ),
            ],
        );
        assert_eq!(d.controller().handle().placement_order(), order);
        let ranking = d.controller().handle().placement_ranking();
        assert_eq!(ranking.len(), 2);
        let (idle, busy) = (ids[0], ids[1]);
        let ahead = if prefers_busy_priority_host {
            busy
        } else {
            idle
        };
        assert_eq!(ranking[0].worker, ahead, "{order:?}");
        assert_eq!(
            ranking[0].ahead_because,
            Some(if prefers_busy_priority_host {
                OrderFactor::Priority
            } else {
                OrderFactor::ExpectedFinish
            }),
            "{order:?}: the explanation names what decided the order"
        );
        assert_eq!(ranking[1].ahead_because, None);
        let finish_of = |worker: WorkerId| {
            ranking
                .iter()
                .find(|r| r.worker == worker)
                .unwrap()
                .expected_finish_ns
        };
        assert!(
            finish_of(idle) < finish_of(busy),
            "the idle host is faster either way"
        );

        let job = d.runs(vec![(d.tenant_a, d.repo_a, noise_of(1))]);
        d.controller().wake();
        eventually("the job leased", || {
            d.state(d.tenant_a, job[0][0]) == JobState::Leased
        });
        eventually("the offer delivered", || {
            offered(&recorders).iter().sum::<usize>() >= 1
        });
        let want = if prefers_busy_priority_host {
            vec![0, 1]
        } else {
            vec![1, 0]
        };
        assert_eq!(offered(&recorders), want, "{order:?}");
        finish(d, processes);
    }
}

/// Priority is an ordering of workers that already passed hard admission, never a way around it:
/// a pool the tenant does not own or share, a label the worker lacks, a CPU ceiling and the host's
/// capacity all still refuse the job on the highest-priority host.
#[test]
fn priority_cannot_bypass_ownership_capabilities_or_capacity() {
    let d = deployment();
    d.controller().set_placement_order(PlacementOrder::Priority);

    // A private pool only tenant A may use.
    let private = PoolId::new();
    let tenant_a = d.tenant_a;
    d.store
        .writer()
        .write(move |tx| {
            tenancy::create_pool(
                tx,
                Authority::HostLocal,
                private,
                "private",
                PoolKind::Shared,
                UnixMillis(1),
            )?;
            tenancy::grant_pool(tx, Authority::HostLocal, private, tenant_a, UnixMillis(1))
        })
        .unwrap();

    // 0: the highest priority, in the private pool, one approved core, no labels.
    // 1: neutral, in the shared pool, five cores, labelled gpu.
    let mut gpu = profile(111, 128 << 30);
    gpu.labels = vec!["gpu".into()];
    let capped = workers::HostPolicy {
        cpu_millis: Some(1_000),
        priority: 100,
        ..workers::HostPolicy::default()
    };
    let (ids, recorders, processes) = start_members(
        &d,
        vec![
            (profile(110, 128 << 30), d.enrollment_in(private, capped)),
            (gpu, d.enrollment_with(priority(0))),
        ],
    );
    let ranking = d.controller().handle().placement_ranking();
    assert_eq!(ranking[0].worker, ids[0], "the capped host is ranked first");
    assert_eq!(ranking[0].priority, 100);

    // Ownership: tenant B has no grant on the private pool, so its job goes to the neutral host.
    let by_b = d.runs(vec![(d.tenant_b, d.repo_b, noise_of(1))])[0][0];
    // Capability: a job that needs the gpu label cannot run on the unlabeled priority host.
    let labeled = d.runs(vec![(d.tenant_a, d.repo_a, GPU_JOB.to_owned())])[0][0];
    // Capacity: two cores exceed the one approved core, though the hello claimed five.
    let wide = d.runs(vec![(d.tenant_a, d.repo_a, TWO_CORES.to_owned())])[0][0];
    d.controller().wake();
    eventually("the three jobs leased", || {
        d.state(d.tenant_b, by_b) == JobState::Leased
            && d.state(d.tenant_a, labeled) == JobState::Leased
            && d.state(d.tenant_a, wide) == JobState::Leased
    });
    eventually("every offer delivered", || {
        offered(&recorders).iter().sum::<usize>() >= 3
    });
    assert_eq!(
        offered(&recorders),
        vec![0, 3],
        "none of them may land on the priority host"
    );
    assert!(d.held(ids[0]).is_empty());

    // Where the priority host is eligible it is used first, and it is never oversubscribed: of eight
    // quarter-core jobs it takes four (its approved core), not eight; the rest overflows.
    let burst = d.runs(vec![(d.tenant_a, d.repo_a, noise())])[0].clone();
    assert_eq!(burst.len(), 8);
    d.controller().wake();
    eventually("the burst leased", || {
        burst
            .iter()
            .all(|job| d.state(d.tenant_a, *job) == JobState::Leased)
    });
    eventually("every offer delivered", || {
        offered(&recorders).iter().sum::<usize>() >= 11
    });
    let got = offered(&recorders);
    assert_eq!(
        got[0], 4,
        "the priority host takes its approved core and no more: {got:?}"
    );
    assert_eq!(got[1], 7, "the rest goes to the other host: {got:?}");
    finish(d, processes);
}

/// Lowering a ceiling below what a host already holds is not an eviction: nothing new is placed on it
/// at once, every accepted attempt keeps running, the over-cap state is visible, and placement resumes
/// only when the accepted work has settled enough to fit under the new ceiling.
#[test]
fn lowering_a_ceiling_blocks_new_placements_and_lets_accepted_work_finish() {
    let mut d = deployment();
    let id = WorkerId::new();
    let recorder = Recorder::new();
    let process = WorkerProcess::start(
        &d,
        Identity::generate("lowered").unwrap(),
        id,
        d.enrollment_with(workers::HostPolicy {
            cpu_millis: Some(2_000),
            ..workers::HostPolicy::default()
        }),
        STANDARD,
        profile(120, 128 << 30),
        Arc::clone(&recorder),
    );
    process.wait_for("Connected", 1);
    eventually("fleet", || d.controller().connected() == vec![id]);
    let view = |d: &Deployment| {
        d.store
            .read(move |c| workers::host_view(c, Authority::HostLocal, id))
            .unwrap()
    };

    // Four quarter-core jobs are accepted under the 2-core ceiling.
    let first = d.runs(vec![(d.tenant_a, d.repo_a, noise_of(4))])[0].clone();
    d.controller().wake();
    eventually("four offers", || recorder.offers.lock().unwrap().len() == 4);
    eventually("all four acknowledged", || {
        d.held(id).iter().filter(|h| h.acknowledged).count() == 4
    });
    assert!(!view(&d).over_cap().is_over());
    assert_eq!(view(&d).reserved_cpu_millis, 1_000);

    // The ceiling drops to half a core: the host now holds twice what it is offered.
    d.store
        .writer()
        .write(move |tx| {
            workers::set_policy(
                tx,
                Authority::HostLocal,
                id,
                workers::HostPolicy {
                    cpu_millis: Some(500),
                    ..workers::HostPolicy::default()
                },
            )
        })
        .unwrap();
    let over = view(&d).over_cap();
    assert!(over.is_over());
    assert_eq!(
        (over.cpu_millis, over.memory_bytes, over.disk_bytes),
        (500, 0, 0)
    );

    // New work is not placed, and the accepted attempts are untouched.
    let more = d.runs(vec![(d.tenant_a, d.repo_a, noise_of(4))])[0].clone();
    d.controller().wake();
    thread::sleep(Duration::from_millis(400));
    assert_eq!(
        recorder.offers.lock().unwrap().len(),
        4,
        "placed while over the cap"
    );
    for job in &more {
        assert_eq!(d.state(d.tenant_a, *job), JobState::Queued);
    }
    assert_eq!(d.held(id).len(), 4);
    assert!(
        recorder.stopped.lock().unwrap().is_empty(),
        "accepted work was stopped"
    );
    for job in &first {
        assert_eq!(d.state(d.tenant_a, *job), JobState::Leased);
    }
    assert!(view(&d).over_cap().is_over());

    // Two of the four settle: exactly at the cap is not over it, and still no room for a new job.
    pass(&d, &[(id, &recorder)], d.tenant_a, first[0]);
    pass(&d, &[(id, &recorder)], d.tenant_a, first[1]);
    d.controller().wake();
    thread::sleep(Duration::from_millis(300));
    assert_eq!(view(&d).reserved_cpu_millis, 500);
    assert!(!view(&d).over_cap().is_over());
    assert_eq!(
        recorder.offers.lock().unwrap().len(),
        4,
        "placed with no room left"
    );

    // One more settles: a quarter core is free under the new ceiling, so exactly one job is placed.
    pass(&d, &[(id, &recorder)], d.tenant_a, first[2]);
    d.controller().wake();
    eventually("one new offer", || {
        recorder.offers.lock().unwrap().len() == 5
    });
    thread::sleep(Duration::from_millis(300));
    assert_eq!(
        recorder.offers.lock().unwrap().len(),
        5,
        "the ceiling holds"
    );
    assert_eq!(view(&d).reserved_cpu_millis, 500);
    assert_eq!(
        more.iter()
            .filter(|job| d.state(d.tenant_a, **job) == JobState::Leased)
            .count(),
        1
    );

    process.stop().unwrap();
    assert!(
        d.controller
            .take()
            .unwrap()
            .shutdown(Duration::from_secs(5))
    );
}
