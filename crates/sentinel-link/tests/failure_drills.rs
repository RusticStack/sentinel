#![cfg(target_os = "linux")]

//! R07: what the controller and the worker survive at runtime. A controller process killed mid-run and restarted, a
//! worker process killed mid-attempt, the link cut under a running attempt, and a database that will not take the
//! terminal report. Each drill asserts what [resilience](../docs/resilience.md) promises afterwards: no acknowledged
//! state lost, nothing settled or published twice, leases fenced, nothing served that cannot be verified. Every wait
//! is bounded, and every drill that would need a real host (a power cut, `dm-flakey`, an OOM kill, a fleet of hosts)
//! is left unasserted rather than faked.

use std::{
    env,
    io::{Read, Write},
    net::{Shutdown, SocketAddr, TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use sentinel_auth::secret::Secret;
use sentinel_core::{
    AttemptId, Event, JobId, JobState, Outcome, PoolId, RepoId, RunId, TenantId, UnixMillis,
    UserId, WorkerId,
    auth::{Namespace, Permissions as P, Principal},
};
use sentinel_link::{
    Error,
    controller::Controller,
    identity::Identity,
    session::{self, Capacity, Executor, Offer, Reporter},
    worker,
};
use sentinel_pipeline::{PinnedSource, RunSpec, compile_str};
use sentinel_protocol::logs::{Frame, Stream};
use sentinel_protocol::negotiate::{Arch, Capabilities, Hello, ProtocolVersion};
use sentinel_store::{
    Durability, Store,
    auth::{self, Authority, NamespaceKind, provisioning},
    dispatch, jobs,
    logs::LogStore,
    objects::Objects,
    runs,
    tenancy::{self, PoolKind},
    workers,
};

const DIGEST: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const SHA: &str = "0123456789abcdef0123456789abcdef01234567";
const CAPACITY: Capacity = Capacity {
    cpu_millis: 4_000,
    memory_bytes: 8 << 30,
};
const CONTROLLER_CHILD: &str = "SENTINEL_R07_CONTROLLER_CHILD";
const WORKER_CHILD: &str = "SENTINEL_R07_WORKER_CHILD";

const ONE_JOB: &str = "schema: 1
on: [push]
jobs:
  build:
    image: alpine:3
    resources: { cpu: 1, memory: 1GiB }
    steps: [{ id: s, run: 'true' }]
";

fn hello() -> Hello {
    Hello {
        protocol_min: ProtocolVersion(1),
        protocol_max: ProtocolVersion(3),
        capabilities: Capabilities::REQUIRED,
        arch: Arch::X86_64,
        software: "test".into(),
    }
}

fn open(dir: &Path) -> (Arc<Store>, Arc<LogStore>, Arc<Objects>) {
    (
        Arc::new(Store::open(dir.join("metadata.sqlite"), Durability::Normal).unwrap()),
        Arc::new(LogStore::open(dir.join("logs")).unwrap()),
        Arc::new(Objects::open(dir.join("data")).unwrap()),
    )
}

struct Seed {
    tenant: TenantId,
    pool: PoolId,
    run: RunId,
    job: JobId,
    enrollment: Secret,
    worker: WorkerId,
    worker_identity: (PathBuf, PathBuf),
}

/// A tenant, a pool, one run of one job and an enrollment for one worker, committed before any controller runs.
fn seed(dir: &Path) -> Seed {
    let (store, _, _) = open(dir);
    let (root, tenant, repo, pool) = (UserId::new(), TenantId::new(), RepoId::new(), PoolId::new());
    let run = RunId::new();
    let worker = WorkerId::new();
    let spec = RunSpec::new(
        PinnedSource::new("https://github.com/o/r.git", SHA, Some("main")).unwrap(),
        compile_str(ONE_JOB).unwrap(),
    )
    .unwrap();
    let (job, enrollment) = store
        .writer()
        .write(move |tx| {
            provisioning::insert_human(tx, root, "Root", true, UnixMillis::now())?;
            auth::create_namespace(
                tx,
                Principal::new(root, P::ALL, None, None),
                tenant,
                Namespace::parse("acme").unwrap(),
                NamespaceKind::Organization,
                UnixMillis::now(),
            )?;
            jobs::insert_repo(tx, tenant, repo, "app", UnixMillis::now())?;
            tenancy::create_pool(
                tx,
                Authority::HostLocal,
                pool,
                "builders",
                PoolKind::Dedicated(tenant),
                UnixMillis::now(),
            )?;
            let ids = runs::create_run(tx, tenant, repo, run, &spec, UnixMillis::now())?;
            runs::resolve_image(tx, tenant, ids[0], DIGEST, "linux/amd64")?;
            Ok((
                ids[0],
                workers::issue_enrollment(
                    tx,
                    Authority::HostLocal,
                    pool,
                    3_600_000,
                    UnixMillis::now(),
                )?
                .secret,
            ))
        })
        .unwrap();
    let controller = Identity::generate("controller").unwrap();
    let files = (dir.join("controller.crt"), dir.join("controller.key"));
    controller.save(&files.0, &files.1).unwrap();
    let worker_identity = Identity::generate("worker").unwrap();
    let worker_files = (dir.join("worker.crt"), dir.join("worker.key"));
    worker_identity
        .save(&worker_files.0, &worker_files.1)
        .unwrap();
    Seed {
        tenant,
        pool,
        run,
        job,
        enrollment,
        worker,
        worker_identity: worker_files,
    }
}

struct Fixture {
    dir: PathBuf,
    store: Arc<Store>,
    logs: Arc<LogStore>,
    tenant: TenantId,
    run: RunId,
    job: JobId,
    controller: Option<Controller>,
}

impl Fixture {
    fn deploy(dir: &Path, seed: &Seed) -> Fixture {
        let dir = dir.to_path_buf();
        let (store, logs, objects) = open(&dir);
        let controller = Controller::start(
            Arc::clone(&store),
            Arc::clone(&logs),
            Arc::clone(&objects),
            Identity::load(&dir.join("controller.crt"), &dir.join("controller.key")).unwrap(),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        Fixture {
            dir,
            store,
            logs,
            tenant: seed.tenant,
            run: seed.run,
            job: seed.job,
            controller: Some(controller),
        }
    }

    fn controller(&self) -> &Controller {
        self.controller.as_ref().unwrap()
    }

    fn state(&self, job: JobId) -> JobState {
        let tenant = self.tenant;
        self.store
            .read(|c| jobs::get_job(c, tenant, job))
            .unwrap()
            .state
    }

    fn held(&self, worker: WorkerId) -> Vec<dispatch::Held> {
        self.store.read(|c| dispatch::held_by(c, worker)).unwrap()
    }

    fn tail(&self, attempt: AttemptId) -> sentinel_store::logs::Tail {
        self.logs
            .tail(self.run, self.job, attempt, 0, 16, None)
            .unwrap()
    }
}

fn hex_of(digest: &sentinel_auth::secret::Digest) -> String {
    digest.0.iter().map(|b| format!("{b:02x}")).collect()
}

fn digest_of(text: &str) -> sentinel_auth::secret::Digest {
    let mut bytes = [0u8; 32];
    for (byte, pair) in bytes.iter_mut().zip(text.as_bytes().chunks_exact(2)) {
        *byte = u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap();
    }
    sentinel_auth::secret::Digest(bytes)
}

/// The controller identity a worker pins: the process that serves it is killed and restarted in between.
fn server_of(dir: &Path) -> sentinel_auth::secret::Digest {
    Identity::load(&dir.join("controller.crt"), &dir.join("controller.key"))
        .unwrap()
        .fingerprint()
}

fn exposed(secret: &Secret) -> String {
    let mut text = String::new();
    secret.expose(&mut text);
    text
}

/// The executor for a drill: it takes every offer, keeps the reporter the session hands it, and records what the
/// controller said, so the drill can drive the attempt from a thread the session does not own.
struct Rig {
    offers: Mutex<Vec<Offer>>,
    held: Mutex<Vec<AttemptId>>,
    reporter: Mutex<Option<Reporter>>,
    attached: AtomicUsize,
    detached: AtomicUsize,
    acks: Mutex<Vec<u64>>,
    renewed: Mutex<Vec<UnixMillis>>,
    specs: Mutex<Vec<AttemptId>>,
    ends: Mutex<Vec<AttemptId>>,
}

impl Rig {
    fn new() -> Arc<Rig> {
        Arc::new(Rig {
            offers: Mutex::new(Vec::new()),
            held: Mutex::new(Vec::new()),
            reporter: Mutex::new(None),
            attached: AtomicUsize::new(0),
            detached: AtomicUsize::new(0),
            acks: Mutex::new(Vec::new()),
            renewed: Mutex::new(Vec::new()),
            specs: Mutex::new(Vec::new()),
            ends: Mutex::new(Vec::new()),
        })
    }

    fn reporter(&self) -> Option<Reporter> {
        self.reporter.lock().unwrap().clone()
    }

    fn offer(&self) -> Offer {
        self.offers.lock().unwrap()[0].clone()
    }

    fn acked_through(&self) -> u64 {
        self.acks.lock().unwrap().last().copied().unwrap_or(0)
    }
}

impl Executor for Rig {
    fn offered(&self, offer: &Offer) -> bool {
        self.held.lock().unwrap().push(offer.attempt);
        self.offers.lock().unwrap().push(offer.clone());
        true
    }
    fn stop(&self, attempt: AttemptId) {
        self.held.lock().unwrap().retain(|a| *a != attempt);
    }
    fn cancel(&self, _: AttemptId) {}
    fn held(&self) -> Vec<AttemptId> {
        self.held.lock().unwrap().clone()
    }
    fn renewed(&self, until: UnixMillis) {
        self.renewed.lock().unwrap().push(until);
    }
    fn attached(&self, reporter: Reporter) {
        self.attached.fetch_add(1, Ordering::SeqCst);
        *self.reporter.lock().unwrap() = Some(reporter);
    }
    fn detached(&self) {
        self.detached.fetch_add(1, Ordering::SeqCst);
        self.reporter.lock().unwrap().take();
    }
    fn spec(&self, attempt: AttemptId, _: session::JobContext, _: Vec<u8>) {
        self.specs.lock().unwrap().push(attempt);
    }
    fn no_spec(&self, _: AttemptId) {}
    fn log_acked(&self, _: AttemptId, through: u64) {
        self.acks.lock().unwrap().push(through);
    }
    fn log_refused(&self, _: AttemptId) {}
    fn log_ended(&self, attempt: AttemptId) {
        self.ends.lock().unwrap().push(attempt);
    }
}

struct Runner {
    handle: Arc<worker::Handle>,
    thread: Option<thread::JoinHandle<Result<(), Error>>>,
    events: Arc<Mutex<Vec<String>>>,
}

impl Runner {
    fn start(
        addr: SocketAddr,
        server: sentinel_auth::secret::Digest,
        identity: Identity,
        worker: WorkerId,
        enrollment: Secret,
        rig: Arc<Rig>,
    ) -> Runner {
        let handle = Arc::new(worker::Handle::new());
        let events = Arc::new(Mutex::new(Vec::new()));
        let config = worker::Config {
            controller: addr,
            server,
            also_pinned: Vec::new(),
            worker,
            name: "builder-1".into(),
            hello: hello(),
            capacity: CAPACITY,
            profile: sentinel_protocol::negotiate::Profile {
                disk_bytes: 64 << 30,
                ..sentinel_protocol::negotiate::Profile::default()
            },
            transport: session::TransportStats::default(),
            remote_cache: false,
        };
        let (grip, log) = (Arc::clone(&handle), Arc::clone(&events));
        let thread = thread::spawn(move || {
            worker::run(config, identity, Some(enrollment), &*rig, &grip, &|event| {
                log.lock().unwrap().push(format!("{event:?}"));
            })
        });
        Runner {
            handle,
            thread: Some(thread),
            events,
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
                "no {count}th {needle}: {:?}",
                self.events.lock().unwrap()
            );
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn stop(mut self) {
        self.handle.stop();
        let outcome = self.thread.take().unwrap().join().unwrap();
        assert!(outcome.is_ok(), "the worker loop ended: {outcome:?}");
    }
}

fn eventually(what: &str, mut predicate: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(20);
    while !predicate() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        thread::sleep(Duration::from_millis(10));
    }
}

fn frame(seq: u64, text: &str) -> Frame {
    Frame {
        seq,
        step: 0,
        stream: Stream::Stdout,
        bytes: text.as_bytes().to_vec(),
    }
}

/// A controller in its own process, on a port it reports in `<dir>/listen`, releasing its store lock only when the
/// process dies: what a killed controller is.
fn serve_as_controller(dir: &Path) {
    let (store, logs, objects) = open(dir);
    let identity =
        Identity::load(&dir.join("controller.crt"), &dir.join("controller.key")).unwrap();
    let controller = Controller::start(
        store,
        logs,
        objects,
        identity,
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    std::fs::write(dir.join("listen"), controller.local_addr().to_string()).unwrap();
    loop {
        thread::sleep(Duration::from_millis(50));
    }
}

fn spawn_controller(child: &str, dir: &Path) -> Child {
    Command::new(env::current_exe().unwrap())
        .args(["--exact", child, "--nocapture"])
        .env(CONTROLLER_CHILD, dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap()
}

fn listening(dir: &Path) -> SocketAddr {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if let Ok(text) = std::fs::read_to_string(dir.join("listen"))
            && let Ok(addr) = text.trim().parse()
        {
            return addr;
        }
        assert!(
            Instant::now() < deadline,
            "the child controller never listened"
        );
        thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn a_controller_killed_mid_run_restarts_and_settles_the_attempt_once_without_losing_a_frame() {
    if let Some(dir) = env::var_os(CONTROLLER_CHILD) {
        serve_as_controller(Path::new(&dir));
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let seed = seed(dir.path());
    let mut child = spawn_controller(
        "a_controller_killed_mid_run_restarts_and_settles_the_attempt_once_without_losing_a_frame",
        dir.path(),
    );
    let addr = listening(dir.path());
    let rig = Rig::new();
    let runner = Runner::start(
        addr,
        server_of(dir.path()),
        Identity::load(&seed.worker_identity.0, &seed.worker_identity.1).unwrap(),
        seed.worker,
        Secret::parse(&exposed(&seed.enrollment)).unwrap(),
        Arc::clone(&rig),
    );
    runner.wait_for("Connected", 1);
    eventually("an offer", || !rig.offers.lock().unwrap().is_empty());
    let offer = rig.offer();
    let (attempt, fence) = (offer.attempt, offer.fence);

    // The attempt is held, acknowledged and streaming when the controller process is cut off.
    eventually("an acknowledged hold", || {
        rig.reporter().is_some() && !rig.renewed.lock().unwrap().is_empty()
    });
    rig.reporter().unwrap().need_spec(attempt).unwrap();
    eventually("the spec", || rig.specs.lock().unwrap().contains(&attempt));
    let reporter = rig.reporter().unwrap();
    for i in 1..=3 {
        reporter
            .log(attempt, &frame(i, &format!("line {i}\n")))
            .unwrap();
    }
    eventually("three acknowledged frames", || rig.acked_through() == 3);

    child.kill().unwrap();
    child.wait().unwrap();
    runner.wait_for("Disconnected", 1);

    // What the killed controller left on disk: the acknowledged attempt and every frame, nothing half-written.
    let (store, logs, objects) = open(dir.path());
    let held = store.read(|c| dispatch::held_by(c, seed.worker)).unwrap();
    assert_eq!(held.len(), 1, "{held:?}");
    assert!(held[0].acknowledged && held[0].attempt == attempt);
    let tail = logs.tail(seed.run, seed.job, attempt, 0, 16, None).unwrap();
    assert_eq!(tail.frames.len(), 3, "{tail:?}");
    assert!(!tail.complete);
    let identity = Identity::load(
        &dir.path().join("controller.crt"),
        &dir.path().join("controller.key"),
    )
    .unwrap();
    let controller = Controller::start(
        Arc::clone(&store),
        Arc::clone(&logs),
        Arc::clone(&objects),
        identity,
        addr,
    )
    .unwrap();

    // The worker redials on its own; its lease still holds, so nothing is re-offered and nothing re-runs.
    runner.wait_for("Connected", 2);
    eventually("the session again", || {
        rig.attached.load(Ordering::SeqCst) == 2
    });
    eventually("a renewed lease", || {
        !rig.renewed.lock().unwrap().is_empty()
    });
    assert_eq!(rig.offers.lock().unwrap().len(), 1, "nothing re-offered");
    let reporter = rig.reporter().unwrap();
    reporter.log(attempt, &frame(4, "line 4\n")).unwrap();
    reporter.log_end(attempt, 4, &[]).unwrap();
    eventually("the last frame", || rig.acked_through() == 4);
    eventually("the log closed", || {
        logs.tail(seed.run, seed.job, attempt, 0, 16, None)
            .unwrap()
            .complete
    });

    rig.held.lock().unwrap().clear();
    for event in [
        Event::StepsStarted,
        Event::FinalizationStarted,
        Event::Passed,
    ] {
        reporter.report(attempt, fence, event).unwrap();
    }
    eventually("the terminal job", || {
        store
            .read(|c| jobs::get_job(c, seed.tenant, seed.job))
            .unwrap()
            .state
            == JobState::Terminal(Outcome::Passed)
    });
    // A second report for a settled attempt is stale: the settlement happened once.
    reporter.report(attempt, fence, Event::Passed).unwrap();
    eventually("the stale report", || {
        controller.stats().stale_reports.load(Ordering::SeqCst) == 1
    });

    let tail = logs.tail(seed.run, seed.job, attempt, 0, 16, None).unwrap();
    let seqs: Vec<u64> = tail.frames.iter().map(|f| f.seq).collect();
    assert_eq!(seqs, vec![1, 2, 3, 4], "every frame stored exactly once");
    assert!(tail.gaps.is_empty());
    let recovery = store.read(|c| objects.recover(c)).unwrap();
    assert!(recovery.missing.is_empty() && recovery.corrupt.is_empty());

    runner.stop();
    assert!(controller.shutdown(Duration::from_secs(5)));
}

#[test]
fn a_worker_killed_mid_attempt_is_settled_once_by_its_lease_and_never_replayed() {
    if let Some(dir) = env::var_os(WORKER_CHILD) {
        serve_as_worker(Path::new(&dir));
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let seed = seed(dir.path());
    let fixture = Fixture::deploy(dir.path(), &seed);
    let addr = fixture.controller().local_addr();
    let fingerprint = server_of(dir.path());
    let mut child = Command::new(env::current_exe().unwrap())
        .args([
            "--exact",
            "a_worker_killed_mid_attempt_is_settled_once_by_its_lease_and_never_replayed",
            "--nocapture",
        ])
        .env(WORKER_CHILD, &fixture.dir)
        .env("SENTINEL_R07_ADDR", addr.to_string())
        .env("SENTINEL_R07_SERVER", hex_of(&fingerprint))
        .env("SENTINEL_R07_WORKER", seed.worker.to_string())
        .env("SENTINEL_R07_SECRET", exposed(&seed.enrollment))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();

    eventually("the child's acknowledged hold", || {
        fixture.held(seed.worker).iter().any(|h| h.acknowledged)
    });
    let held = fixture.held(seed.worker);
    let (attempt, lease) = (held[0].attempt, held[0].lease_until);

    child.kill().unwrap();
    child.wait().unwrap();
    fixture.controller().wake();
    eventually("the session gone", || {
        fixture.controller().connected().is_empty()
    });

    // The killed worker's lease is still in the rows: the controller does not decide on its own that the work
    // never happened, and it does not hand the job to anyone else while the lease stands.
    let rig = Rig::new();
    let second = {
        let pool = seed.pool;
        fixture
            .store
            .writer()
            .write(move |tx| {
                workers::issue_enrollment(
                    tx,
                    Authority::HostLocal,
                    pool,
                    600_000,
                    UnixMillis::now(),
                )
            })
            .unwrap()
            .secret
    };
    let runner = Runner::start(
        addr,
        fingerprint,
        Identity::generate("second").unwrap(),
        WorkerId::new(),
        second,
        Arc::clone(&rig),
    );
    runner.wait_for("Connected", 1);
    thread::sleep(Duration::from_millis(1_500));
    assert!(rig.offers.lock().unwrap().is_empty(), "nothing re-offered");
    assert_eq!(fixture.state(seed.job), JobState::Leased);
    assert_eq!(fixture.held(seed.worker).len(), 1);

    // The deadline clock is advanced past the lease rather than waited out; the sweep then settles the attempt the
    // way `reconcile_startup` would: one infrastructure failure, no replay.
    let after = UnixMillis(lease.0 + 1);
    assert_eq!(
        fixture.store.read(|c| dispatch::expired(c, after)).unwrap(),
        vec![attempt]
    );
    let state = fixture
        .store
        .writer()
        .write(move |tx| dispatch::expire(tx, attempt, after, None))
        .unwrap();
    assert_eq!(state, JobState::Terminal(Outcome::InfraFailed));
    assert_eq!(
        fixture.state(seed.job),
        JobState::Terminal(Outcome::InfraFailed)
    );

    let attempts: i64 = fixture
        .store
        .read(move |c| {
            Ok(c.query_row(
                "SELECT COUNT(*) FROM attempts WHERE job_id = ?1",
                [seed.job.as_bytes().as_slice()],
                |r| r.get(0),
            )?)
        })
        .unwrap();
    assert_eq!(attempts, 1, "the attempt was not run again");
    let log_state: i64 = fixture
        .store
        .read(move |c| {
            Ok(c.query_row(
                "SELECT log_state FROM attempts WHERE id = ?1",
                [attempt.as_bytes().as_slice()],
                |r| r.get(0),
            )?)
        })
        .unwrap();
    assert_eq!(
        log_state,
        dispatch::LogState::Incomplete as i64,
        "a lost tail is never reported complete"
    );

    // After the settlement the job is no longer work anyone is offered.
    fixture.controller().wake();
    thread::sleep(Duration::from_millis(1_500));
    assert!(
        rig.offers.lock().unwrap().is_empty(),
        "the job was replayed"
    );
    runner.stop();
}

fn serve_as_worker(dir: &Path) {
    let addr: SocketAddr = env::var("SENTINEL_R07_ADDR").unwrap().parse().unwrap();
    let server = digest_of(&env::var("SENTINEL_R07_SERVER").unwrap());
    let worker: WorkerId = env::var("SENTINEL_R07_WORKER").unwrap().parse().unwrap();
    let secret = Secret::parse(&env::var("SENTINEL_R07_SECRET").unwrap()).unwrap();
    let identity = Identity::load(&dir.join("worker.crt"), &dir.join("worker.key")).unwrap();
    let rig = Rig::new();
    let handle = Arc::new(worker::Handle::new());
    let config = worker::Config {
        controller: addr,
        server,
        also_pinned: Vec::new(),
        worker,
        name: "builder-1".into(),
        hello: hello(),
        capacity: CAPACITY,
        profile: sentinel_protocol::negotiate::Profile {
            disk_bytes: 64 << 30,
            ..sentinel_protocol::negotiate::Profile::default()
        },
        transport: session::TransportStats::default(),
        remote_cache: false,
    };
    let _ = worker::run(config, identity, Some(secret), &*rig, &handle, &|_| {});
}

/// A transparent relay the worker dials instead of the controller, so a drill can cut the link without touching
/// either process.
struct Proxy {
    addr: SocketAddr,
    sockets: Arc<Mutex<Vec<TcpStream>>>,
}

impl Proxy {
    fn to(target: SocketAddr) -> Proxy {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let sockets: Arc<Mutex<Vec<TcpStream>>> = Arc::new(Mutex::new(Vec::new()));
        let held = Arc::clone(&sockets);
        thread::spawn(move || {
            for accepted in listener.incoming() {
                let Ok(client) = accepted else { return };
                let Ok(server) = TcpStream::connect(target) else {
                    continue;
                };
                for socket in [client.try_clone().unwrap(), server.try_clone().unwrap()] {
                    held.lock().unwrap().push(socket);
                }
                for (mut from, mut into) in [
                    (client.try_clone().unwrap(), server.try_clone().unwrap()),
                    (server, client),
                ] {
                    thread::spawn(move || {
                        let mut buf = vec![0u8; 16 << 10];
                        while let Ok(n) = from.read(&mut buf) {
                            if n == 0 || into.write_all(&buf[..n]).is_err() {
                                break;
                            }
                        }
                        let _ = into.shutdown(Shutdown::Both);
                    });
                }
            }
        });
        Proxy { addr, sockets }
    }

    /// Drops every byte path at once: both ends see a closed connection, and nothing is half-delivered to either.
    fn cut(&self) {
        for socket in self.sockets.lock().unwrap().drain(..) {
            let _ = socket.shutdown(Shutdown::Both);
        }
    }
}

#[test]
fn a_link_dropped_mid_attempt_is_redialled_and_the_log_resumes_past_its_cursor() {
    let dir = tempfile::tempdir().unwrap();
    let seed = seed(dir.path());
    let fixture = Fixture::deploy(dir.path(), &seed);
    let proxy = Proxy::to(fixture.controller().local_addr());
    let identity = Identity::load(&seed.worker_identity.0, &seed.worker_identity.1).unwrap();
    let rig = Rig::new();
    let runner = Runner::start(
        proxy.addr,
        fixture.controller().fingerprint(),
        identity,
        seed.worker,
        Secret::parse(&exposed(&seed.enrollment)).unwrap(),
        Arc::clone(&rig),
    );
    runner.wait_for("Connected", 1);
    eventually("an offer", || !rig.offers.lock().unwrap().is_empty());
    let offer = rig.offer();
    let (attempt, fence) = (offer.attempt, offer.fence);
    eventually("the session attached", || rig.reporter().is_some());
    let reporter = rig.reporter().unwrap();
    reporter.log(attempt, &frame(1, "one\n")).unwrap();
    reporter.log(attempt, &frame(2, "two\n")).unwrap();
    eventually("two acknowledged frames", || rig.acked_through() == 2);
    let lease = fixture.held(seed.worker)[0].lease_until;

    proxy.cut();
    runner.wait_for("Disconnected", 1);
    runner.wait_for("Connected", 2);
    eventually("the session again", || {
        rig.attached.load(Ordering::SeqCst) == 2
    });
    eventually("a renewed lease past the cut", || {
        fixture.held(seed.worker)[0].lease_until > lease
    });

    // Everything acknowledged before the cut is still there, once each, and the stream continues from the cursor.
    let before = fixture.tail(attempt);
    assert_eq!(
        before.frames.iter().map(|f| f.seq).collect::<Vec<_>>(),
        vec![1, 2]
    );
    let reporter = rig.reporter().unwrap();
    reporter.log(attempt, &frame(3, "three\n")).unwrap();
    reporter.log_end(attempt, 3, &[]).unwrap();
    eventually("the frame after the redial", || rig.acked_through() == 3);
    eventually("the log closed", || fixture.tail(attempt).complete);
    let after = fixture.tail(attempt);
    assert_eq!(
        after.frames.iter().map(|f| f.seq).collect::<Vec<_>>(),
        vec![1, 2, 3]
    );
    assert!(after.gaps.is_empty());

    rig.held.lock().unwrap().clear();
    for event in [
        Event::StepsStarted,
        Event::FinalizationStarted,
        Event::Passed,
    ] {
        reporter.report(attempt, fence, event).unwrap();
    }
    eventually("the terminal job", || {
        fixture.state(seed.job) == JobState::Terminal(Outcome::Passed)
    });
    assert_eq!(
        fixture
            .controller()
            .stats()
            .stale_reports
            .load(Ordering::SeqCst),
        0
    );
    runner.stop();
}

#[test]
fn a_locked_database_keeps_a_terminal_report_deferred_and_settles_it_once_the_lock_is_gone() {
    let dir = tempfile::tempdir().unwrap();
    let seed = seed(dir.path());
    let fixture = Fixture::deploy(dir.path(), &seed);
    let identity = Identity::load(&seed.worker_identity.0, &seed.worker_identity.1).unwrap();
    let rig = Rig::new();
    let runner = Runner::start(
        fixture.controller().local_addr(),
        fixture.controller().fingerprint(),
        identity,
        seed.worker,
        Secret::parse(&exposed(&seed.enrollment)).unwrap(),
        Arc::clone(&rig),
    );
    runner.wait_for("Connected", 1);
    eventually("an offer", || !rig.offers.lock().unwrap().is_empty());
    let offer = rig.offer();
    let (attempt, fence) = (offer.attempt, offer.fence);
    eventually("the session attached", || rig.reporter().is_some());
    let reporter = rig.reporter().unwrap();
    reporter.log(attempt, &frame(1, "one\n")).unwrap();
    reporter.log_end(attempt, 1, &[]).unwrap();
    eventually("an acknowledged frame", || rig.acked_through() == 1);

    // Another process's claim on the database: every write the controller attempts is refused `busy`.
    let blocker = rusqlite::Connection::open(dir.path().join("metadata.sqlite")).unwrap();
    blocker.busy_timeout(Duration::from_millis(0)).unwrap();
    blocker.execute_batch("BEGIN EXCLUSIVE").unwrap();

    rig.held.lock().unwrap().clear();
    for event in [
        Event::StepsStarted,
        Event::FinalizationStarted,
        Event::Passed,
    ] {
        reporter.report(attempt, fence, event).unwrap();
    }
    eventually("the report deferred", || {
        fixture
            .controller()
            .stats()
            .deferred_worker_messages
            .load(Ordering::SeqCst)
            > 0
    });
    assert_eq!(
        fixture.state(seed.job),
        JobState::Leased,
        "a refused write acknowledges nothing"
    );

    blocker.execute_batch("ROLLBACK").unwrap();
    drop(blocker);
    eventually("the settled job", || {
        fixture.state(seed.job) == JobState::Terminal(Outcome::Passed)
    });
    assert_eq!(
        fixture
            .controller()
            .stats()
            .deferred_dropped
            .load(Ordering::SeqCst),
        0
    );
    let tail = fixture.tail(attempt);
    assert!(tail.complete);
    assert_eq!(tail.frames.len(), 1, "one frame, delivered once");
    runner.stop();
}
