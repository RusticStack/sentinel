//! Streaming publication measured end to end: one real worker link, one real controller, and the same
//! `artifacts::StepPublications` the executor uses at a step's end.
//!
//! Each sample publishes one declared artifact of `--files` files of `--file-bytes` bytes and models a later step of
//! `--later-ms`. In mode `step` the publication starts when the first step ends and the later step runs while it
//! uploads, which is what `when: step:<id>` does; in mode `finalize` the later step runs first and the publication
//! follows it, which is what every artifact did before it. Both modes run the same capture, over the same files,
//! through the same link, in ABBA order per round, and each records the publication's own window and the tail of the
//! attempt after the first step ended.
//!
//! The session asks for protocol 11 on purpose: every sample then sends the whole output, so both modes move the same
//! bytes and what a digest-first publication saves is not what this measures (E02 measures that).
//!
//!   cargo build --release --locked -p sentinel-worker --example step-publication-bench
//!   SENTINEL_SRC=$PWD SENTINEL_BIN=target/release/examples/step-publication-bench \
//!     SENTINEL_BENCH_HOST_LABEL=<label> bench/step-publication-record.sh
//!
//! The controller and the worker are on one loopback address, so the figures say what overlap saves on a local link,
//! not on a fleet.

use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use sentinel_core::{
    AttemptId, Event, Fence, JobId, PoolId, RepoId, RunId, TenantId, UnixMillis, UserId, WorkerId,
    auth::{Namespace, Permissions as P, Principal},
};
use sentinel_link::{
    controller::Controller,
    identity::Identity,
    session::{self, ArtifactCode, Capacity, Executor, Offer, Reporter},
    worker::{self, Handle},
};
use sentinel_pipeline::{
    PinnedSource, RunSpec, compile_str,
    schema::{Artifact, ArtifactWhen, Step},
};
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
use sentinel_worker::artifacts::{Sink, StepPublications};

const SHA: &str = "0123456789abcdef0123456789abcdef01234567";
const IMAGE: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

const STEP: usize = 0;
const FINALIZE: usize = 1;

const PIPELINE: &str = "schema: 1
on: [push]
jobs:
  build:
    image: alpine:3
    resources: { cpu: 1, memory: 1GiB }
    steps: [{ id: build, run: 'true' }, { id: later, run: 'true' }]
    artifacts:
      - { name: dist, paths: ['out/**'], when: 'step:build' }
";

fn steps() -> [Step; 2] {
    let step = |id: &str| Step {
        id: id.to_owned(),
        run: "true".to_owned(),
        condition: None,
        shell: sentinel_pipeline::schema::Shell::Sh,
        env: Vec::new(),
        secrets: Vec::new(),
        secret_files: Vec::new(),
        workdir: None,
        timeout_secs: None,
    };
    [step("build"), step("later")]
}

fn declaration() -> Artifact {
    Artifact {
        name: "dist".to_owned(),
        paths: vec!["out/**".to_owned()],
        when: ArtifactWhen::Step(0),
        retain_secs: 3_600,
        required: true,
        class: None,
    }
}

/// What one sample measured, in monotonic nanoseconds.
#[derive(Clone, Copy, Debug)]
struct Sample {
    /// The publication's own window: from the first request to the link until the verdict came back.
    published_ns: u64,
    /// The later step.
    later_ns: u64,
    /// Everything after the first step ended: the later step and whatever of the publication was still running.
    tail_ns: u64,
}

struct Publisher {
    weak: Weak<Publisher>,
    workspace: PathBuf,
    mode: AtomicUsize,
    later_ms: u64,
    state: Mutex<State>,
}

struct State {
    reporter: Option<Reporter>,
    fences: HashMap<AttemptId, Fence>,
    verdicts: HashMap<AttemptId, ArtifactCode>,
    opened: Option<Instant>,
    published_ns: u64,
    samples: HashMap<AttemptId, Sample>,
}

impl Publisher {
    fn reporter(&self) -> Option<Reporter> {
        self.state.lock().unwrap().reporter.clone()
    }

    /// The recorded verdict of an attempt's artifact, once the controller has answered.
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

    /// One sample: the two steps, with the publication either behind the first or after both.
    fn run_sample(&self, attempt: AttemptId) {
        let mode = self.mode.load(Ordering::Acquire);
        let later = Duration::from_millis(self.later_ms);
        let decl = declaration();
        let sink: Arc<dyn Sink> = self
            .weak
            .upgrade()
            .expect("the fleet outlives its attempts");
        let declared = [decl.clone()];
        let tail = Instant::now();
        let mut publications = StepPublications::default();
        let later_started = Instant::now();
        if mode == STEP {
            // The step's end publishes; the later step runs during the upload.
            publications.publish(0, &decl, &self.workspace, &sink, attempt);
            thread::sleep(later);
        } else {
            thread::sleep(later);
            publications.publish(0, &decl, &self.workspace, &sink, attempt);
        }
        let later_ns = later_started.elapsed().as_nanos() as u64;
        publications.settle(&declared, &steps(), true);
        let tail_ns = tail.elapsed().as_nanos() as u64;
        let published_ns;
        {
            let mut state = self.state.lock().unwrap();
            published_ns = state.published_ns;
            state.samples.insert(
                attempt,
                Sample {
                    published_ns,
                    later_ns,
                    tail_ns,
                },
            );
        }
        let fence = self.state.lock().unwrap().fences.get(&attempt).copied();
        if let (Some(fence), Some(reporter)) = (fence, self.reporter()) {
            let event = if published_ns > 0 {
                Event::Passed
            } else {
                Event::Failed(sentinel_core::FailureClass::Publication)
            };
            let _ = reporter.report(attempt, fence, event);
        }
    }
}

/// The worker's publication side, exactly as `Inner` sends it.
impl Sink for Publisher {
    fn capable(&self) -> bool {
        self.reporter().is_some_and(|r| r.artifacts())
    }
    fn begin(&self, attempt: AttemptId, name: &str) -> Option<ArtifactCode> {
        self.state.lock().unwrap().opened = Some(Instant::now());
        self.reporter()?.artifact_begin(attempt, name).ok()?;
        None
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
        let code = self.verdict(attempt);
        let opened = self.state.lock().unwrap().opened.take();
        if let Some(opened) = opened {
            let ns = opened.elapsed().as_nanos() as u64;
            self.state.lock().unwrap().published_ns = ns;
        }
        code
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
    fn artifact_held(&self, _attempt: AttemptId, _name: &str, _held: &[u32]) {}
    fn artifact_verdict(&self, attempt: AttemptId, _name: &str, code: ArtifactCode) {
        self.state.lock().unwrap().verdicts.insert(attempt, code);
    }
    fn spec(&self, attempt: AttemptId, _context: session::JobContext, _bytes: Vec<u8>) {
        // The attempt's steps run on their own thread, as the executor's do.
        if let Some(this) = self.weak.upgrade() {
            thread::spawn(move || this.run_sample(attempt));
        }
    }
}

struct Fleet {
    _dir: tempfile::TempDir,
    store: Arc<Store>,
    controller: Option<Controller>,
    tenant: TenantId,
    repo: RepoId,
    pool: PoolId,
    publisher: Arc<Publisher>,
    handle: Arc<Handle>,
}

impl Fleet {
    fn open(later_ms: u64) -> Fleet {
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
        let publisher = Arc::new_cyclic(|weak| Publisher {
            weak: weak.clone(),
            workspace: dir.path().join("workspace"),
            mode: AtomicUsize::new(STEP),
            later_ms,
            state: Mutex::new(State {
                reporter: None,
                fences: HashMap::new(),
                verdicts: HashMap::new(),
                opened: None,
                published_ns: 0,
                samples: HashMap::new(),
            }),
        });
        Fleet {
            _dir: dir,
            store,
            controller: Some(controller),
            tenant,
            repo,
            pool,
            publisher,
            handle: Arc::new(Handle::new()),
        }
    }

    fn controller(&self) -> &Controller {
        self.controller.as_ref().expect("running")
    }

    fn connect(&mut self) {
        let pool = self.pool;
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
        let config = worker::Config {
            controller: self.controller().local_addr(),
            server: self.controller().fingerprint(),
            also_pinned: Vec::new(),
            worker: WorkerId::new(),
            name: "bench".into(),
            hello: Hello {
                protocol_min: ProtocolVersion(1),
                // Protocol 11 sends every body, so both modes move the same bytes.
                protocol_max: ProtocolVersion(11),
                capabilities: Capabilities::REQUIRED,
                arch: Arch::X86_64,
                software: "sentinel-bench".into(),
            },
            capacity: Capacity {
                cpu_millis: 8_000,
                memory_bytes: 8 << 30,
            },
            profile: sentinel_protocol::negotiate::Profile {
                labels: Vec::new(),
                disk_bytes: 1 << 40,
                ..sentinel_protocol::negotiate::Profile::default()
            },
            transport: session::TransportStats::default(),
            remote_cache: false,
        };
        let executor = Arc::clone(&self.publisher);
        let stopper = Arc::clone(&self.handle);
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
        let deadline = Instant::now() + Duration::from_secs(60);
        while self.controller().connected().is_empty() {
            assert!(
                Instant::now() < deadline,
                "the bench worker never connected"
            );
            thread::sleep(Duration::from_millis(5));
        }
    }

    /// Enqueue one run in `mode` and wait for its sample.
    fn publish(&self, mode: usize) -> Sample {
        let (tenant, repo, run) = (self.tenant, self.repo, RunId::new());
        let spec = RunSpec::new(
            PinnedSource::new(
                "https://example.invalid/outputs.git",
                SHA,
                Some("refs/heads/main"),
            )
            .unwrap(),
            compile_str(PIPELINE).unwrap(),
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
        self.publisher.mode.store(mode, Ordering::Release);
        self.controller().wake();
        let job = jobs[0];
        let deadline = Instant::now() + Duration::from_secs(120);
        loop {
            let attempt = self
                .store
                .read(move |c| sentinel_store::dispatch::latest_attempt(c, tenant, job))
                .unwrap();
            if let Some(sample) = attempt.and_then(|attempt| {
                self.publisher
                    .state
                    .lock()
                    .unwrap()
                    .samples
                    .get(&attempt)
                    .copied()
            }) {
                return sample;
            }
            assert!(Instant::now() < deadline, "the bench sample never finished");
            thread::sleep(Duration::from_millis(1));
        }
    }

    fn stop(&mut self) {
        self.handle.stop();
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
    later_ms: u64,
    rounds: usize,
}

fn args() -> Args {
    let mut args = Args {
        files: 48,
        file_bytes: 1 << 20,
        later_ms: 250,
        rounds: 5,
    };
    let mut argv = std::env::args().skip(1).collect::<Vec<_>>().into_iter();
    while let Some(flag) = argv.next() {
        let value = argv
            .next()
            .unwrap_or_else(|| panic!("{flag} needs a value"))
            .parse::<u64>()
            .unwrap_or_else(|_| panic!("{flag} needs a number"));
        match flag.as_str() {
            "--files" => args.files = value as usize,
            "--file-bytes" => args.file_bytes = value as usize,
            "--later-ms" => args.later_ms = value,
            "--rounds" => args.rounds = value as usize,
            other => panic!("unknown argument {other}"),
        }
    }
    args
}

fn main() {
    let args = args();
    let mut fleet = Fleet::open(args.later_ms);
    fleet.connect();
    write_outputs(
        &fleet.publisher.workspace.clone(),
        args.files,
        args.file_bytes,
    );
    let artifact_bytes = (args.files * args.file_bytes) as u64;

    // One unmeasured sample per mode, so neither mode's first run pays a wake-up.
    for mode in [STEP, FINALIZE] {
        let warm = fleet.publish(mode);
        assert!(warm.published_ns > 0, "a warm-up publication failed");
    }

    let modes = ["step", "finalize"];
    let mut seq = 0u32;
    for round in 1..=args.rounds {
        // ABBA: the `step` sample comes first on odd rounds and last on even ones, so drift cannot favour a mode.
        let order = if round % 2 == 1 {
            [STEP, FINALIZE]
        } else {
            [FINALIZE, STEP]
        };
        let mut measured: Vec<(usize, usize, Sample)> = Vec::with_capacity(2);
        for (place, mode) in order.into_iter().enumerate() {
            // An unmeasured sample of the same mode first: the first publication of a round pays a wake-up.
            let warm = fleet.publish(mode);
            assert!(warm.published_ns > 0, "a warm-up publication failed");
            let sample = fleet.publish(mode);
            assert!(sample.published_ns > 0, "a measured publication failed");
            measured.push((mode, place, sample));
        }
        let step = measured.iter().find(|(mode, ..)| *mode == STEP).copied();
        let finalized = measured
            .iter()
            .find(|(mode, ..)| *mode == FINALIZE)
            .copied();
        for (mode, place, sample) in measured {
            seq += 1;
            let mut record = serde_json::json!({
                "schema": "sentinel-bench/step-publication/1",
                "seq": seq,
                "round": round,
                "position": place,
                "mode": modes[mode],
                "files": args.files,
                "file_bytes": args.file_bytes,
                "artifact_bytes": artifact_bytes,
                "later_ns": sample.later_ns,
                "published_ns": sample.published_ns,
                "tail_ns": sample.tail_ns,
            });
            if mode == STEP
                && let (Some((_, _, step)), Some((_, _, fin))) = (step, finalized)
            {
                record["overlap_ns"] = serde_json::json!(sample.published_ns.min(sample.later_ns));
                record["saved"] = serde_json::json!({
                    "tail_ns": fin.tail_ns.saturating_sub(step.tail_ns),
                });
            }
            println!("{record}");
        }
    }
    fleet.stop();
}
