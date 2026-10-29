//! A worker that measures its own disk keeps the controller's figure current: a host whose caches, mirrors
//! and images grow (or shrink) re-sends the scratch disk it can offer, and an operator-stated figure is never
//! replaced. Identities of one machine share the file system, so the figure each measures already excludes
//! what the others keep there.

use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use sentinel_auth::secret::Secret;
use sentinel_core::{AttemptId, PoolId, UnixMillis, WorkerId};
use sentinel_link::{
    controller::Controller,
    identity::Identity,
    session::{self, Capacity, Executor, Offer},
    worker,
};
use sentinel_protocol::negotiate::{Arch, Capabilities, Hello, Profile, ProtocolVersion};
use sentinel_store::{
    Durability, Store,
    auth::Authority,
    dispatch,
    tenancy::{self, PoolKind},
    workers,
};

const GIB: u64 = 1 << 30;

struct Deployment {
    _dir: tempfile::TempDir,
    store: Arc<Store>,
    _logs: Arc<sentinel_store::logs::LogStore>,
    _objects: Arc<sentinel_store::objects::Objects>,
    controller: Controller,
    pool: PoolId,
}

fn deployment() -> Deployment {
    let dir = tempfile::tempdir().unwrap();
    let store =
        Arc::new(Store::open(dir.path().join("metadata.sqlite"), Durability::Normal).unwrap());
    let pool = PoolId::new();
    store
        .writer()
        .write(move |tx| {
            tenancy::create_pool(
                tx,
                Authority::HostLocal,
                pool,
                "farm",
                PoolKind::Shared,
                UnixMillis(1),
            )
        })
        .unwrap();
    let logs = Arc::new(sentinel_store::logs::LogStore::open(dir.path().join("logs")).unwrap());
    let objects =
        Arc::new(sentinel_store::objects::Objects::open(dir.path().join("objects")).unwrap());
    let controller = Controller::start(
        Arc::clone(&store),
        Arc::clone(&logs),
        Arc::clone(&objects),
        Identity::generate("controller").unwrap(),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    Deployment {
        _dir: dir,
        store,
        _logs: logs,
        _objects: objects,
        controller,
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

    /// The disk the controller offers `worker`, once the worker is enrolled.
    fn offered_disk(&self, worker: WorkerId) -> Option<i64> {
        self.store
            .read(move |c| dispatch::free_capacity(c, worker))
            .ok()
            .map(|free| free.disk_bytes)
    }
}

/// An executor that holds nothing and reports whatever disk room the test sets (`None`: a fixed statement).
struct Measured {
    room: AtomicU64,
    fixed: bool,
    held: Mutex<Vec<AttemptId>>,
}

impl Measured {
    fn new(room: u64, fixed: bool) -> Arc<Measured> {
        Arc::new(Measured {
            room: AtomicU64::new(room),
            fixed,
            held: Mutex::new(Vec::new()),
        })
    }
}

impl Executor for Measured {
    fn offered(&self, _: &Offer) -> bool {
        false
    }
    fn stop(&self, _: AttemptId) {}
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
    fn disk_room(&self) -> Option<u64> {
        (!self.fixed).then(|| self.room.load(Ordering::SeqCst))
    }
}

struct WorkerProcess {
    handle: Arc<worker::Handle>,
    thread: Option<thread::JoinHandle<()>>,
}

fn start(d: &Deployment, executor: Arc<Measured>, connect_disk: u64) -> (WorkerProcess, WorkerId) {
    let handle = Arc::new(worker::Handle::new());
    let id = WorkerId::new();
    let config = worker::Config {
        controller: d.controller.local_addr(),
        server: d.controller.fingerprint(),
        also_pinned: Vec::new(),
        worker: id,
        name: "builder".into(),
        hello: Hello {
            protocol_min: ProtocolVersion(1),
            protocol_max: sentinel_protocol::negotiate::SUPPORTED_MAX,
            capabilities: Capabilities::REQUIRED,
            arch: Arch::X86_64,
            software: "host-disk".into(),
        },
        capacity: Capacity {
            cpu_millis: 4_000,
            memory_bytes: 8 * GIB,
        },
        profile: Profile {
            disk_bytes: connect_disk,
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
        thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn a_measured_disk_follows_the_host_as_its_caches_grow_and_shrink() {
    let d = deployment();
    let executor = Measured::new(100 * GIB, false);
    let (_process, id) = start(&d, Arc::clone(&executor), 100 * GIB);
    eventually("the connect-time disk", Duration::from_secs(20), || {
        d.offered_disk(id) == Some((100 * GIB) as i64)
    });
    // Caches, mirrors and images fill the file system: the next heartbeat carries the smaller room.
    executor.room.store(60 * GIB, Ordering::SeqCst);
    eventually("the shrunken disk", Duration::from_secs(30), || {
        d.offered_disk(id) == Some((60 * GIB) as i64)
    });
    // A small wobble is not worth a profile message; the controller keeps the last figure it was sent.
    executor.room.store(60 * GIB + (10 << 20), Ordering::SeqCst);
    thread::sleep(Duration::from_secs(7));
    assert_eq!(d.offered_disk(id), Some((60 * GIB) as i64));
    // Space returning is offered again.
    executor.room.store(90 * GIB, Ordering::SeqCst);
    eventually("the recovered disk", Duration::from_secs(30), || {
        d.offered_disk(id) == Some((90 * GIB) as i64)
    });
}

#[test]
fn a_stated_disk_is_never_replaced_by_a_measurement() {
    let d = deployment();
    let executor = Measured::new(10 * GIB, true);
    let (_process, id) = start(&d, Arc::clone(&executor), 40 * GIB);
    eventually("the stated disk", Duration::from_secs(20), || {
        d.offered_disk(id) == Some((40 * GIB) as i64)
    });
    executor.room.store(5 * GIB, Ordering::SeqCst);
    thread::sleep(Duration::from_secs(7));
    assert_eq!(d.offered_disk(id), Some((40 * GIB) as i64));
}
