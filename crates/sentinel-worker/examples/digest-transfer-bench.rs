//! Digest-first artifact transfer measured end to end: one real worker link, one real controller, and a counting
//! TCP relay between them, so the bytes in the record are the bytes on the socket rather than an estimate.
//!
//! Every sample is a real `artifacts::capture` against a real artifact declaration. The only thing that changes
//! between the two modes is the worker protocol the session negotiated: `bodies` (protocol 11) sends every file's
//! contents on every publication, `digest` (protocol 12) offers each file's digest first, so a publication whose
//! content the tenant already holds sends none of it. Both modes publish the same files into the same tenant, in
//! ABBA order per round, and each sample records the link bytes and elapsed nanoseconds of the publication window
//! plus the saving against the `bodies` sample of its round.
//!
//!   cargo build --release --locked -p sentinel-worker --example digest-transfer-bench
//!   SENTINEL_SRC=$PWD SENTINEL_BIN=target/release/examples/digest-transfer-bench \
//!     SENTINEL_BENCH_HOST_LABEL=<label> DIR=/var/tmp/digest-transfer bench/digest-transfer.sh
//!
//! The relay, the controller and both workers are on one loopback address, so the figures say what the transfer
//! saves on a local link, not on a fleet.

use std::{
    collections::HashMap,
    fs,
    io::{Read, Write},
    net::{Shutdown, SocketAddr, TcpListener, TcpStream},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicU64, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use sentinel_core::{
    AttemptId, Event, FailureClass, Fence, JobId, PoolId, RepoId, RunId, TenantId, UnixMillis,
    UserId, WorkerId,
    auth::{Namespace, Permissions as P, Principal},
};
use sentinel_link::{
    controller::Controller,
    identity::Identity,
    session::{self, ArtifactCode, Capacity, Executor, Offer, Offered, Reporter},
    worker::{self, Handle},
};
use sentinel_pipeline::schema::{Artifact, ArtifactWhen};
use sentinel_pipeline::{PinnedSource, RunSpec, compile_str};
use sentinel_protocol::negotiate::{Arch, Capabilities, Hello, ProtocolVersion};
use sentinel_store::{
    Durability, Store,
    auth::{self, Authority, NamespaceKind, provisioning},
    logs::LogStore,
    objects::Objects,
    runs,
    tenancy::{self, PoolKind},
    workers,
};
use sentinel_worker::artifacts::{self, Outcome, Sink};

const SHA: &str = "0123456789abcdef0123456789abcdef01234567";
const IMAGE: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

/// One pipeline per mode, pinned to its worker's label: the two sessions are both eligible otherwise, and a
/// publication measured on the wrong protocol would say nothing.
fn pipeline(label: &str) -> String {
    format!(
        "schema: 1
on: [push]
jobs:
  build:
    image: alpine:3
    runs_on: {{ labels: [{label}] }}
    resources: {{ cpu: 1, memory: 1GiB }}
    steps: [{{ id: s, run: 'true' }}]
    artifacts:
      - {{ name: dist, paths: ['out/**'], when: always }}
"
    )
}

/// The label the worker at `protocol` advertises and the pipeline at that protocol asks for.
fn label(protocol: u16) -> String {
    format!("mode-{protocol}")
}

/// Bytes each way through the relay: what the link actually put on the socket.
#[derive(Default)]
struct Counters {
    to_controller: AtomicU64,
    to_worker: AtomicU64,
}

impl Counters {
    fn snapshot(&self) -> (u64, u64) {
        (
            self.to_controller.load(Ordering::Relaxed),
            self.to_worker.load(Ordering::Relaxed),
        )
    }
}

fn relay(at: SocketAddr) -> (SocketAddr, Arc<Counters>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let counters = Arc::new(Counters::default());
    let counted = Arc::clone(&counters);
    thread::spawn(move || {
        for client in listener.incoming() {
            let Ok(client) = client else { break };
            let Ok(upstream) = TcpStream::connect(at) else {
                continue;
            };
            let (mut from_worker, mut to_worker) = (client.try_clone().unwrap(), client);
            let (mut from_controller, mut to_controller) =
                (upstream.try_clone().unwrap(), upstream);
            let up = Arc::clone(&counted);
            thread::spawn(move || {
                let mut buf = vec![0u8; 64 << 10];
                while let Ok(n) = from_worker.read(&mut buf) {
                    if n == 0 {
                        break;
                    }
                    up.to_controller.fetch_add(n as u64, Ordering::Relaxed);
                    if to_controller.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
                let _ = to_controller.shutdown(Shutdown::Write);
            });
            let down = Arc::clone(&counted);
            thread::spawn(move || {
                let mut buf = vec![0u8; 64 << 10];
                while let Ok(n) = from_controller.read(&mut buf) {
                    if n == 0 {
                        break;
                    }
                    down.to_worker.fetch_add(n as u64, Ordering::Relaxed);
                    if to_worker.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
                let _ = to_worker.shutdown(Shutdown::Write);
            });
        }
    });
    (addr, counters)
}

struct Publisher {
    weak: Weak<Publisher>,
    workspace: PathBuf,
    state: Mutex<State>,
}

struct State {
    reporter: Option<Reporter>,
    fences: HashMap<AttemptId, Fence>,
    held: HashMap<AttemptId, Vec<u32>>,
    verdicts: HashMap<AttemptId, ArtifactCode>,
    outcomes: HashMap<AttemptId, (Outcome, u64)>,
}

impl Publisher {
    fn reporter(&self) -> Option<Reporter> {
        self.state.lock().unwrap().reporter.clone()
    }
}

/// The worker's publication side, exactly as `Inner` sends it.
impl Sink for Publisher {
    fn capable(&self) -> bool {
        self.reporter().is_some_and(|r| r.artifacts())
    }
    fn digests(&self) -> bool {
        self.reporter().is_some_and(|r| r.digests())
    }
    fn begin(&self, attempt: AttemptId, name: &str) -> Option<ArtifactCode> {
        self.reporter()?.artifact_begin(attempt, name).ok()?;
        None
    }
    fn offer(&self, attempt: AttemptId, name: &str, entries: &[Offered], last: bool) -> bool {
        self.reporter()
            .is_some_and(|r| r.artifact_offer(attempt, name, entries, last).is_ok())
    }
    fn held(&self, attempt: AttemptId, _name: &str) -> Option<Vec<u32>> {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if let Some(held) = self.state.lock().unwrap().held.get(&attempt).cloned() {
                return Some(held);
            }
            if Instant::now() > deadline {
                return None;
            }
            thread::sleep(Duration::from_millis(1));
        }
    }
    fn file(&self, attempt: AttemptId, path: &str, len: u64, mode: u32) -> bool {
        self.reporter()
            .is_some_and(|r| r.artifact_file(attempt, path, len, mode).is_ok())
    }
    fn data(&self, attempt: AttemptId, seq: u32, bytes: &[u8]) -> bool {
        self.reporter()
            .is_some_and(|r| r.artifact_data(attempt, seq, bytes).is_ok())
    }
    fn end(&self, attempt: AttemptId, name: &str) -> ArtifactCode {
        let Some(reporter) = self.reporter() else {
            return ArtifactCode::Store;
        };
        if reporter.artifact_end(attempt, name).is_err() {
            return ArtifactCode::Store;
        }
        self.verdict(attempt)
    }
    fn absent(&self, attempt: AttemptId, name: &str, reason: u8) -> ArtifactCode {
        let _ = self
            .reporter()
            .map(|r| r.artifact_absent(attempt, name, reason));
        ArtifactCode::Absent
    }
    fn settle(&self, attempt: AttemptId, _name: &str) -> ArtifactCode {
        self.verdict(attempt)
    }
}

impl Publisher {
    fn verdict(&self, attempt: AttemptId) -> ArtifactCode {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if let Some(code) = self.state.lock().unwrap().verdicts.get(&attempt).copied() {
                return code;
            }
            if Instant::now() > deadline {
                return ArtifactCode::Store;
            }
            thread::sleep(Duration::from_millis(1));
        }
    }
}

impl Executor for Publisher {
    fn accepted(&self, attempt: AttemptId) {
        if let Some(reporter) = self.reporter() {
            let _ = reporter.need_spec(attempt);
        }
    }
    fn offered(&self, offer: &Offer) -> bool {
        self.state
            .lock()
            .unwrap()
            .fences
            .insert(offer.attempt, offer.fence);
        true
    }
    fn stop(&self, _attempt: AttemptId) {}
    fn cancel(&self, _attempt: AttemptId) {}
    fn held(&self) -> Vec<AttemptId> {
        Vec::new()
    }
    fn renewed(&self, _until: UnixMillis) {}
    fn attached(&self, reporter: Reporter) {
        self.state.lock().unwrap().reporter = Some(reporter);
    }
    fn detached(&self) {
        self.state.lock().unwrap().reporter = None;
    }
    fn no_spec(&self, _attempt: AttemptId) {}
    fn log_acked(&self, _attempt: AttemptId, _through: u64) {}
    fn log_refused(&self, _attempt: AttemptId) {}
    fn artifact_held(&self, attempt: AttemptId, _name: &str, held: &[u32]) {
        self.state
            .lock()
            .unwrap()
            .held
            .insert(attempt, held.to_vec());
    }
    fn artifact_verdict(&self, attempt: AttemptId, _name: &str, code: ArtifactCode) {
        self.state.lock().unwrap().verdicts.insert(attempt, code);
    }
    fn spec(&self, attempt: AttemptId, _context: session::JobContext, _bytes: Vec<u8>) {
        let Some(this) = self.weak.upgrade() else {
            return;
        };
        // The publication window opens when the spec is served and closes when capture() returns, so both modes
        // pay the same scheduling and both are measured the same way.
        let started = Instant::now();
        thread::spawn(move || {
            let decl = Artifact {
                name: "dist".into(),
                paths: vec!["out/**".into()],
                when: ArtifactWhen::Always,
                retain_secs: 3_600,
                required: true,
                class: None,
            };
            let outcome = artifacts::capture(&this.workspace, &decl, &*this, attempt);
            let elapsed = started.elapsed().as_nanos() as u64;
            this.state
                .lock()
                .unwrap()
                .outcomes
                .insert(attempt, (outcome, elapsed));
            let fence = this.state.lock().unwrap().fences.get(&attempt).copied();
            if let (Some(fence), Some(reporter)) = (fence, this.reporter()) {
                let event = match outcome {
                    Outcome::Published => Event::Passed,
                    _ => Event::Failed(FailureClass::Publication),
                };
                let _ = reporter.report(attempt, fence, event);
            }
        });
    }
}

struct Fleet {
    _dir: tempfile::TempDir,
    store: Arc<Store>,
    controller: Option<Controller>,
    tenant: TenantId,
    repo: RepoId,
    pool: PoolId,
    workers: Vec<Arc<Publisher>>,
    handles: Vec<Arc<Handle>>,
}

impl Fleet {
    /// The store and the controller, before any worker exists: the relay in front of the controller needs its
    /// address, and the workers need the relay's.
    fn open() -> Fleet {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir(dir.path().join("workspace")).unwrap();
        let store =
            Arc::new(Store::open(dir.path().join("metadata.sqlite"), Durability::Normal).unwrap());
        let (root, tenant, repo, pool) =
            (UserId::new(), TenantId::new(), RepoId::new(), PoolId::new());
        store
            .writer()
            .write(move |tx| {
                provisioning::insert_human(tx, root, "Root", true, UnixMillis(1))?;
                auth::create_namespace(
                    tx,
                    Principal::new(root, P::ALL, None, None),
                    tenant,
                    Namespace::parse("bench").unwrap(),
                    NamespaceKind::Organization,
                    UnixMillis(1),
                )?;
                sentinel_store::jobs::insert_repo(tx, tenant, repo, "outputs", UnixMillis(1))?;
                tenancy::create_pool(
                    tx,
                    Authority::HostLocal,
                    pool,
                    "builders",
                    PoolKind::Dedicated(tenant),
                    UnixMillis(1),
                )
            })
            .unwrap();
        let logs = Arc::new(LogStore::open(dir.path().join("logs")).unwrap());
        let objects = Arc::new(Objects::open(dir.path().join("objects")).unwrap());
        let controller = Controller::start(
            Arc::clone(&store),
            logs,
            objects,
            Identity::generate("controller").unwrap(),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        Fleet {
            _dir: dir,
            store,
            controller: Some(controller),
            tenant,
            repo,
            pool,
            workers: Vec::new(),
            handles: Vec::new(),
        }
    }

    fn controller(&self) -> &Controller {
        self.controller.as_ref().expect("running")
    }

    fn workspace(&self) -> PathBuf {
        self._dir.path().join("workspace")
    }

    /// One worker session per mode: protocol 11 sends bodies, protocol 12 offers digests. Both connect through the
    /// relay, and both publish into the same tenant.
    fn connect(&mut self, at: SocketAddr) {
        let pool = self.pool();
        for protocol in [11u16, 12] {
            let enrollment = self
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
                .secret;
            let publisher = Arc::new_cyclic(|weak| Publisher {
                weak: weak.clone(),
                workspace: self.workspace(),
                state: Mutex::new(State {
                    reporter: None,
                    fences: HashMap::new(),
                    held: HashMap::new(),
                    verdicts: HashMap::new(),
                    outcomes: HashMap::new(),
                }),
            });
            let handle = Arc::new(Handle::new());
            let config = worker::Config {
                // The pinned fingerprint is the controller's and the address is the relay's: TLS runs end to end
                // and the relay only counts.
                controller: at,
                server: self.controller().fingerprint(),
                also_pinned: Vec::new(),
                worker: WorkerId::new(),
                name: format!("bench-{protocol}"),
                hello: Hello {
                    protocol_min: ProtocolVersion(1),
                    protocol_max: ProtocolVersion(protocol),
                    capabilities: Capabilities::REQUIRED,
                    arch: Arch::X86_64,
                    software: "sentinel-bench".into(),
                },
                capacity: Capacity {
                    cpu_millis: 8_000,
                    memory_bytes: 8 << 30,
                },
                profile: sentinel_protocol::negotiate::Profile {
                    labels: vec![label(protocol)],
                    disk_bytes: 1 << 40,
                    ..sentinel_protocol::negotiate::Profile::default()
                },
                transport: session::TransportStats::default(),
                remote_cache: false,
            };
            let executor = Arc::clone(&publisher);
            let stopper = Arc::clone(&handle);
            thread::spawn(move || {
                worker::run(
                    config,
                    Identity::generate("bench").unwrap(),
                    Some(enrollment),
                    &*executor,
                    &stopper,
                    &|_| {},
                )
            });
            self.workers.push(publisher);
            self.handles.push(handle);
        }
        let deadline = Instant::now() + Duration::from_secs(60);
        while self.controller().connected().len() < 2 {
            assert!(
                Instant::now() < deadline,
                "the bench workers never connected"
            );
            thread::sleep(Duration::from_millis(5));
        }
    }

    fn pool(&self) -> PoolId {
        self.pool
    }

    /// Enqueue one run and let the given mode's worker publish it: the publication's outcome and nanoseconds, and
    /// the artifact's recorded byte count.
    fn publish(&self, mode: usize) -> ((Outcome, u64), u64) {
        let publisher = Arc::clone(&self.workers[mode]);
        let (tenant, repo, run) = (self.tenant, self.repo, RunId::new());
        let protocol = if mode == 0 { 11 } else { 12 };
        let spec = RunSpec::new(
            PinnedSource::new(
                "https://example.invalid/outputs.git",
                SHA,
                Some("refs/heads/main"),
            )
            .unwrap(),
            compile_str(&pipeline(&label(protocol))).unwrap(),
        )
        .unwrap();
        let jobs: Vec<JobId> = self
            .store
            .writer()
            .write(move |tx| {
                let ids = runs::create_run(tx, tenant, repo, run, &spec, UnixMillis::now())?;
                for job in &ids {
                    runs::resolve_image(tx, tenant, *job, IMAGE, "linux/amd64")?;
                }
                Ok(ids)
            })
            .unwrap();
        self.controller().wake();
        let job = jobs[0];
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            let attempt = self
                .store
                .read(move |c| sentinel_store::dispatch::latest_attempt(c, tenant, job))
                .unwrap();
            if let Some((outcome, ns)) = attempt.and_then(|attempt| {
                publisher
                    .state
                    .lock()
                    .unwrap()
                    .outcomes
                    .get(&attempt)
                    .copied()
            }) {
                let bytes = self
                    .store
                    .read(move |c| sentinel_store::artifacts::for_run(c, tenant, run))
                    .unwrap()
                    .first()
                    .map(|row| row.bytes)
                    .unwrap_or(0);
                let _ = tenant;
                return ((outcome, ns), bytes);
            }
            assert!(
                Instant::now() < deadline,
                "the bench publication never finished"
            );
            thread::sleep(Duration::from_millis(1));
        }
    }

    fn stop(&mut self) {
        for handle in self.handles.drain(..) {
            handle.stop();
        }
        if let Some(controller) = self.controller.take() {
            let _ = controller.shutdown(Duration::from_secs(10));
        }
    }
}

fn write_outputs(workspace: &Path, files: usize, bytes: usize) {
    let out = workspace.join("out");
    fs::create_dir_all(&out).unwrap();
    let body: Vec<u8> = (0..bytes).map(|i| (i % 251) as u8).collect();
    for i in 0..files {
        // Distinct content per file, so every file is an object of its own.
        let mut file = body.clone();
        file[..8].copy_from_slice(&(i as u64).to_le_bytes());
        fs::write(out.join(format!("lane-{i:04}.bin")), &file).unwrap();
    }
}

struct Args {
    files: usize,
    file_bytes: usize,
    rounds: usize,
}

fn args() -> Args {
    let mut args = Args {
        files: 48,
        file_bytes: 256 << 10,
        rounds: 5,
    };
    let mut argv = std::env::args().skip(1).collect::<Vec<_>>().into_iter();
    while let Some(flag) = argv.next() {
        let value = argv
            .next()
            .unwrap_or_else(|| panic!("{flag} needs a value"))
            .parse::<usize>()
            .unwrap_or_else(|_| panic!("{flag} needs a number"));
        match flag.as_str() {
            "--files" => args.files = value,
            "--file-bytes" => args.file_bytes = value,
            "--rounds" => args.rounds = value,
            other => panic!("unknown argument {other}"),
        }
    }
    args
}

fn main() {
    let args = args();
    let mut fleet = Fleet::open();
    let (relay_addr, counters) = relay(fleet.controller().local_addr());
    fleet.connect(relay_addr);
    write_outputs(&fleet.workspace(), args.files, args.file_bytes);

    // Seed the tenant's objects and bring both bulk connections up outside every measured window.
    let ((seeded, _), artifact_bytes) = fleet.publish(1);
    assert_eq!(seeded, Outcome::Published, "the seeding publication failed");
    for mode in [0, 1] {
        let ((outcome, _), _) = fleet.publish(mode);
        assert_eq!(outcome, Outcome::Published, "a warm-up publication failed");
    }

    let modes = ["bodies", "digest"];
    let mut seq = 0u32;
    for round in 1..=args.rounds {
        // ABBA: the bodies sample comes first on odd rounds and last on even ones, so drift cannot favour one mode.
        let order = if round % 2 == 1 { [0usize, 1] } else { [1, 0] };
        let mut measured: Vec<(usize, usize, u64, u64)> = Vec::with_capacity(2);
        for (place, mode) in order.into_iter().enumerate() {
            // An unmeasured publication of the same mode first: the first publication after an idle round pays a
            // wake-up that says nothing about the transfer, and it would land on whichever mode came first.
            let ((warm, _), _) = fleet.publish(mode);
            assert_eq!(warm, Outcome::Published, "a warm-up publication failed");
            let before = counters.snapshot();
            let ((outcome, ns), _bytes) = fleet.publish(mode);
            let after = counters.snapshot();
            assert_eq!(outcome, Outcome::Published, "a measured publication failed");
            measured.push((mode, place, (after.0 - before.0) + (after.1 - before.1), ns));
        }
        let bodies = measured
            .iter()
            .find(|(mode, ..)| *mode == 0)
            .map(|(_, _, bytes, ns)| (*bytes, *ns));
        for (mode, place, link_bytes, ns) in measured {
            seq += 1;
            let mut sample = serde_json::json!({
                "schema": "sentinel-bench/digest-transfer/1",
                "seq": seq,
                "round": round,
                "position": place,
                "mode": modes[mode],
                "files": args.files,
                "file_bytes": args.file_bytes,
                "artifact_bytes": artifact_bytes,
                "link_bytes": link_bytes,
                "ns": ns,
            });
            if mode == 1
                && let Some((bodies_bytes, bodies_ns)) = bodies
            {
                sample["saved"] = serde_json::json!({
                    "link_bytes": bodies_bytes.saturating_sub(link_bytes),
                    "ns": bodies_ns.saturating_sub(ns),
                });
            }
            println!("{sample}");
        }
    }
    fleet.stop();
}
