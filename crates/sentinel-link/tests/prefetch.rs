//! K05 bounded image prefetch over the real link: a controller and worker
//! processes on loopback TLS, recorder executors whose "pull" is a short
//! sleep that then reports the image warm, exactly as the worker's
//! `Images` record does after a real pull.
//!
//! - A protocol-9 worker that a locality hold passes over is hinted the
//!   held job's image, pulls it, reports it warm, and is offered the job
//!   within seconds instead of after `LOCALITY_WAIT_MS`.
//! - A protocol-8 worker is never sent a hint (older-peer negotiation).
//!
//! `prefetch_placement_latency` (ignored) measures the same scenario with
//! and without the hint.

use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use sentinel_auth::secret::Secret;
use sentinel_core::{
    AttemptId, JobId, PoolId, RepoId, RunId, TenantId, UnixMillis, UserId, WorkerId,
    auth::{Namespace, Permissions as P, Principal},
};
use sentinel_link::{
    controller::Controller,
    identity::Identity,
    session::{self, Capacity, Executor, Offer},
    worker,
};
use sentinel_pipeline::{PinnedSource, RunSpec, compile_str};
use sentinel_protocol::negotiate::{
    Arch, Availability, Capabilities, Hello, PREFETCH_MIN, Profile, ProtocolVersion,
};
use sentinel_store::{
    Durability, Store,
    auth::{self, Authority, NamespaceKind, provisioning},
    dispatch, runs,
    tenancy::{self, PoolKind},
    workers,
};

const DIGEST: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const KEY: [u8; 8] = [0xaa; 8];
const SHA: &str = "0123456789abcdef0123456789abcdef01234567";

/// Holds the warm worker's only core: the job's timeout puts its end inside
/// the locality window, so the cold worker is held off.
const FILLER: &str = "schema: 1
on: [push]
jobs:
  filler:
    image: alpine:3
    timeout: 20s
    resources: { cpu: 1, memory: 256MiB, disk: 1GiB }
    steps: [{ id: s, run: 'true' }]
";

const TARGET: &str = "schema: 1
on: [push]
jobs:
  target:
    image: alpine:3
    resources: { cpu: 1, memory: 256MiB, disk: 1GiB }
    steps: [{ id: s, run: 'true' }]
";

struct Deployment {
    _dir: tempfile::TempDir,
    store: Arc<Store>,
    _logs: Arc<sentinel_store::logs::LogStore>,
    _objects: Arc<sentinel_store::objects::Objects>,
    controller: Controller,
    tenant: TenantId,
    repo: RepoId,
    pool: PoolId,
}

fn deployment() -> Deployment {
    let dir = tempfile::tempdir().unwrap();
    let store =
        Arc::new(Store::open(dir.path().join("metadata.sqlite"), Durability::Normal).unwrap());
    let (root, tenant, repo, pool) = (UserId::new(), TenantId::new(), RepoId::new(), PoolId::new());
    store
        .writer()
        .write(move |tx| {
            provisioning::insert_human(tx, root, "Root", true, UnixMillis(1))?;
            auth::create_namespace(
                tx,
                Principal::new(root, P::ALL, None, None),
                tenant,
                Namespace::parse("acme").unwrap(),
                NamespaceKind::Organization,
                UnixMillis(1),
            )?;
            sentinel_store::jobs::insert_repo(tx, tenant, repo, "app", UnixMillis(1))?;
            tenancy::create_pool(
                tx,
                Authority::HostLocal,
                pool,
                "farm",
                PoolKind::Shared,
                UnixMillis(1),
            )?;
            tenancy::grant_pool(tx, Authority::HostLocal, pool, tenant, UnixMillis(1))
        })
        .unwrap();
    let identity = Identity::generate("controller").unwrap();
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
        controller,
        tenant,
        repo,
        pool,
    }
}

impl Deployment {
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

    /// One run of `yaml` with its image resolved; then the dispatcher wakes.
    fn run(&self, yaml: &str) -> JobId {
        let spec = RunSpec::new(
            PinnedSource::new("https://github.com/o/r.git", SHA, Some("refs/heads/main")).unwrap(),
            compile_str(yaml).unwrap(),
        )
        .unwrap();
        let (tenant, repo) = (self.tenant, self.repo);
        let job = self
            .store
            .writer()
            .write(move |tx| {
                let ids =
                    runs::create_run(tx, tenant, repo, RunId::new(), &spec, UnixMillis::now())?;
                runs::resolve_image(tx, tenant, ids[0], DIGEST, "linux/amd64")?;
                Ok(ids[0])
            })
            .unwrap();
        self.controller.wake();
        job
    }
}

/// A recorder executor. It holds what it is offered (nothing ever runs),
/// reports `warm` images in its profile, and "pulls" a hinted image by
/// sleeping `pull` and then reporting it warm — the availability change
/// the link sends as a profile refresh.
struct Recorder {
    offers: Mutex<Vec<(Offer, Instant)>>,
    held: Mutex<Vec<AttemptId>>,
    hints: Mutex<Vec<Vec<String>>>,
    store: Arc<Warm>,
    pull: Duration,
}

/// The "image store": what the recorder reports warm, and the version the
/// link's profile refresh watches.
struct Warm {
    keys: Mutex<Vec<[u8; 8]>>,
    version: AtomicU64,
}

impl Recorder {
    fn new(warm: &[[u8; 8]], pull: Duration) -> Arc<Recorder> {
        Arc::new(Recorder {
            offers: Mutex::new(Vec::new()),
            held: Mutex::new(Vec::new()),
            hints: Mutex::new(Vec::new()),
            store: Arc::new(Warm {
                keys: Mutex::new(warm.to_vec()),
                version: AtomicU64::new(1),
            }),
            pull,
        })
    }

    fn offered_job(&self, job: JobId) -> Option<Instant> {
        self.offers
            .lock()
            .unwrap()
            .iter()
            .find(|(o, _)| o.job == job)
            .map(|(_, at)| *at)
    }
}

impl Executor for Recorder {
    fn offered(&self, offer: &Offer) -> bool {
        self.held.lock().unwrap().push(offer.attempt);
        self.offers
            .lock()
            .unwrap()
            .push((offer.clone(), Instant::now()));
        true
    }
    fn stop(&self, attempt: AttemptId) {
        self.held.lock().unwrap().retain(|a| *a != attempt);
    }
    fn cancel(&self, _: AttemptId) {}
    fn held(&self) -> Vec<AttemptId> {
        self.held.lock().unwrap().clone()
    }
    fn renewed(&self, _: UnixMillis) {}
    fn attached(&self, _: session::Reporter) {}
    fn detached(&self) {}
    fn spec(&self, _: AttemptId, _: session::JobContext, _: Vec<u8>) {}
    fn no_spec(&self, _: AttemptId) {}
    fn log_acked(&self, _: AttemptId, _: u64) {}
    fn log_refused(&self, _: AttemptId) {}
    fn availability(&self) -> Option<(u64, Availability)> {
        Some((
            self.store.version.load(Ordering::SeqCst),
            Availability {
                images: self.store.keys.lock().unwrap().clone(),
                cache_bytes: 0,
                load_ns: 0,
            },
        ))
    }
    fn prefetch(&self, images: &[String]) {
        self.hints.lock().unwrap().push(images.to_vec());
        if images.is_empty() {
            return;
        }
        let (store, pull) = (Arc::clone(&self.store), self.pull);
        thread::spawn(move || {
            thread::sleep(pull);
            store.keys.lock().unwrap().push(KEY);
            store.version.fetch_add(1, Ordering::SeqCst);
        });
    }
}

struct WorkerProcess {
    handle: Arc<worker::Handle>,
    thread: Option<thread::JoinHandle<()>>,
}

impl WorkerProcess {
    fn start(
        d: &Deployment,
        protocol_max: u16,
        cpu_millis: u64,
        executor: Arc<Recorder>,
    ) -> (WorkerProcess, WorkerId) {
        let handle = Arc::new(worker::Handle::new());
        let id = WorkerId::new();
        let config = worker::Config {
            controller: d.controller.local_addr(),
            server: d.controller.fingerprint(),
            worker: id,
            name: "builder".into(),
            hello: Hello {
                protocol_min: ProtocolVersion(1),
                protocol_max: ProtocolVersion(protocol_max),
                capabilities: Capabilities::REQUIRED,
                arch: Arch::X86_64,
                software: "prefetch".into(),
            },
            capacity: Capacity {
                cpu_millis,
                memory_bytes: 8 << 30,
            },
            profile: Profile {
                disk_bytes: 50 << 30,
                ..Profile::default()
            },
            transport: Default::default(),
            remote_cache: false,
        };
        let enrollment = d.enrollment();
        let grip = Arc::clone(&handle);
        let thread = thread::spawn(move || {
            let _ = worker::run(
                config,
                Identity::generate("w").unwrap(),
                Some(enrollment),
                &*executor,
                &grip,
                &|_| {},
            );
        });
        (
            WorkerProcess {
                handle,
                thread: Some(thread),
            },
            id,
        )
    }
}

impl Drop for WorkerProcess {
    fn drop(&mut self) {
        self.handle.stop();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn eventually(what: &str, within: Duration, mut predicate: impl FnMut() -> bool) {
    let deadline = Instant::now() + within;
    while !predicate() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        thread::sleep(Duration::from_millis(10));
    }
}

/// The scenario both tests share: the warm worker (one core, the image
/// warm) takes the filler; then a cold worker speaking `protocol_max`
/// joins and the target is queued. Returns the cold worker's recorder,
/// when the target was queued, and the processes (kept alive by the
/// caller).
fn held_for_locality(
    d: &Deployment,
    protocol_max: u16,
) -> (Arc<Recorder>, JobId, Instant, Vec<WorkerProcess>) {
    let warm = Recorder::new(&[KEY], Duration::ZERO);
    let (warm_process, _) = WorkerProcess::start(d, 9, 1_000, Arc::clone(&warm));
    let filler = d.run(FILLER);
    eventually(
        "the warm worker takes the filler",
        Duration::from_secs(20),
        || warm.offered_job(filler).is_some(),
    );
    let cold = Recorder::new(&[], Duration::from_millis(300));
    let (cold_process, cold_id) = WorkerProcess::start(d, protocol_max, 4_000, Arc::clone(&cold));
    eventually("the cold worker connected", Duration::from_secs(20), || {
        d.controller.connected().contains(&cold_id)
    });
    let queued = Instant::now();
    let target = d.run(TARGET);
    (cold, target, queued, vec![warm_process, cold_process])
}

#[test]
fn a_hinted_worker_prefetches_and_takes_the_job_a_locality_hold_kept_from_it() {
    let d = deployment();
    let (cold, target, queued, _processes) = held_for_locality(&d, PREFETCH_MIN.0);
    eventually("the hint", Duration::from_secs(10), || {
        !cold.hints.lock().unwrap().is_empty()
    });
    assert_eq!(
        cold.hints.lock().unwrap()[0],
        vec![format!("alpine@{DIGEST}")],
        "the queued job's image, name and digest"
    );
    eventually(
        "the prefetching worker is offered the job",
        Duration::from_secs(dispatch::LOCALITY_WAIT_MS as u64 / 1000 - 10),
        || cold.offered_job(target).is_some(),
    );
    let waited = cold.offered_job(target).unwrap() - queued;
    eprintln!("prefetch: offered after {} ms", waited.as_millis());
    assert!(
        waited < Duration::from_millis(dispatch::LOCALITY_WAIT_MS as u64 / 2),
        "{waited:?}"
    );
    assert!(d.controller.stats().prefetch_hints.load(Ordering::Relaxed) >= 1);
}

#[test]
fn a_protocol_8_worker_is_never_hinted() {
    let d = deployment();
    let (cold, target, _, _processes) = held_for_locality(&d, 8);
    // Several prefetch passes and a profile beat later: no hint, and the
    // job is still held for the warm worker.
    thread::sleep(Duration::from_secs(7));
    assert!(cold.hints.lock().unwrap().is_empty());
    assert!(cold.offered_job(target).is_none());
    assert_eq!(
        d.controller.stats().prefetch_hints.load(Ordering::Relaxed),
        1,
        "only the warm protocol-9 worker's opening (empty) set"
    );
}

/// Measurement: time from queueing the target to its offer on the cold
/// worker, with the hint (protocol 9) and without it (protocol 8, where
/// only the end of the locality hold releases it).
#[test]
#[ignore = "measurement: waits out a locality hold"]
fn prefetch_placement_latency() {
    for protocol in [PREFETCH_MIN.0, 8] {
        let d = deployment();
        let (cold, target, queued, _processes) = held_for_locality(&d, protocol);
        eventually("the offer", Duration::from_secs(60), || {
            cold.offered_job(target).is_some()
        });
        let waited = cold.offered_job(target).unwrap() - queued;
        eprintln!(
            "protocol {protocol}: target offered to the cold worker after {} ms",
            waited.as_millis()
        );
    }
}
