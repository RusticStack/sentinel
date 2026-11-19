#![cfg(target_os = "linux")]

//! Digest-first artifact transfer (E02) through the real wire: a loopback worker link, the real controller and
//! `artifacts::capture`, with every file the worker sends journalled so a body the tenant already held can be
//! shown to have stayed on the worker.

use std::{
    collections::{HashMap, HashSet},
    fs,
    path::PathBuf,
    sync::{Arc, Mutex, Weak},
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
    objects::{self, Expect, Objects},
    runs,
    tenancy::{self, PoolKind},
    workers,
};
use sentinel_worker::artifacts::{self, Outcome, Sink};

const SHA: &str = "0123456789abcdef0123456789abcdef01234567";
const IMAGE: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

const PIPELINE: &str = "schema: 1
on: [push]
jobs:
  build:
    image: alpine:3
    resources: { cpu: 1, memory: 1GiB }
    steps: [{ id: s, run: 'true' }]
    artifacts:
      - { name: dist, paths: ['out/**'], when: always }
";

#[derive(Clone, Debug, PartialEq, Eq)]
enum Seen {
    Sent(String),
    Held(Vec<u32>),
    Offered(usize),
}

struct Publisher {
    workspace: PathBuf,
    weak: Weak<Publisher>,
    state: Mutex<State>,
}

struct State {
    reporter: Option<Reporter>,
    fences: HashMap<AttemptId, Fence>,
    seen: HashMap<AttemptId, Vec<Seen>>,
    held: HashMap<AttemptId, Vec<u32>>,
    verdicts: HashMap<AttemptId, ArtifactCode>,
    granted: HashSet<AttemptId>,
    outcomes: HashMap<AttemptId, Outcome>,
    /// A test drives this attempt's publication itself instead of letting `capture` run.
    manual: bool,
}

impl Publisher {
    fn record(&self, attempt: AttemptId, seen: Seen) {
        self.state
            .lock()
            .unwrap()
            .seen
            .entry(attempt)
            .or_default()
            .push(seen);
    }

    fn reporter(&self) -> Reporter {
        self.state
            .lock()
            .unwrap()
            .reporter
            .clone()
            .expect("a connected session")
    }

    fn seen(&self, attempt: AttemptId) -> Vec<Seen> {
        self.state
            .lock()
            .unwrap()
            .seen
            .get(&attempt)
            .cloned()
            .unwrap_or_default()
    }

    fn sent(&self, attempt: AttemptId) -> Vec<String> {
        let seen = self.seen(attempt);
        seen.into_iter()
            .filter_map(|s| match s {
                Seen::Sent(path) => Some(path),
                _ => None,
            })
            .collect()
    }

    fn held(&self, attempt: AttemptId) -> Vec<u32> {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if let Some(held) = self.state.lock().unwrap().held.get(&attempt).cloned() {
                return held;
            }
            assert!(Instant::now() < deadline, "no held answer for {attempt}");
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn verdict(&self, attempt: AttemptId) -> ArtifactCode {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if let Some(code) = self.state.lock().unwrap().verdicts.get(&attempt).copied() {
                return code;
            }
            assert!(Instant::now() < deadline, "no verdict for {attempt}");
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn finish(&self, attempt: AttemptId, event: Event) {
        let fence = self.state.lock().unwrap().fences.get(&attempt).copied();
        let Some(fence) = fence else { return };
        let _ = self.reporter().report(attempt, fence, event);
    }
}

/// The publication side of a worker, as `Inner` sends it, plus the journal the assertions read.
impl Sink for Publisher {
    fn capable(&self) -> bool {
        self.reporter().artifacts()
    }

    fn digests(&self) -> bool {
        self.reporter().digests()
    }

    fn begin(&self, attempt: AttemptId, name: &str) -> Option<ArtifactCode> {
        self.reporter().artifact_begin(attempt, name).unwrap();
        None
    }

    fn offer(&self, attempt: AttemptId, name: &str, entries: &[Offered], last: bool) -> bool {
        self.record(attempt, Seen::Offered(entries.len()));
        self.reporter()
            .artifact_offer(attempt, name, entries, last)
            .is_ok()
    }

    fn held(&self, attempt: AttemptId, _name: &str) -> Option<Vec<u32>> {
        Some(self.held(attempt))
    }

    fn file(&self, attempt: AttemptId, path: &str, len: u64, mode: u32) -> bool {
        self.record(attempt, Seen::Sent(path.to_owned()));
        self.reporter()
            .artifact_file(attempt, path, len, mode)
            .is_ok()
    }

    fn data(&self, attempt: AttemptId, seq: u32, bytes: &[u8]) -> bool {
        self.reporter().artifact_data(attempt, seq, bytes).is_ok()
    }

    fn end(&self, attempt: AttemptId, name: &str) -> ArtifactCode {
        self.reporter().artifact_end(attempt, name).unwrap();
        self.verdict(attempt)
    }

    fn absent(&self, attempt: AttemptId, name: &str, reason: u8) -> ArtifactCode {
        self.reporter()
            .artifact_absent(attempt, name, reason)
            .unwrap();
        ArtifactCode::Absent
    }

    fn settle(&self, attempt: AttemptId, _name: &str) -> ArtifactCode {
        self.verdict(attempt)
    }
}

impl Executor for Publisher {
    fn accepted(&self, attempt: AttemptId) {
        // Only an accepted offer is served a spec, and only a spec leads to publication.
        if let Some(reporter) = self.state.lock().unwrap().reporter.clone() {
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
    fn artifact_granted(&self, attempt: AttemptId, _name: &str) {
        self.state.lock().unwrap().granted.insert(attempt);
    }
    fn artifact_held(&self, attempt: AttemptId, _name: &str, held: &[u32]) {
        let mut state = self.state.lock().unwrap();
        state
            .seen
            .entry(attempt)
            .or_default()
            .push(Seen::Held(held.to_vec()));
        state.held.insert(attempt, held.to_vec());
    }
    fn artifact_verdict(&self, attempt: AttemptId, _name: &str, code: ArtifactCode) {
        self.state.lock().unwrap().verdicts.insert(attempt, code);
    }
    fn spec(&self, attempt: AttemptId, _context: session::JobContext, _bytes: Vec<u8>) {
        if self.state.lock().unwrap().manual {
            return;
        }
        // The real executor runs an attempt on its own thread; publishing inside the session's read loop would
        // wait for answers that loop has to deliver.
        let Some(this) = self.weak.upgrade() else {
            return;
        };
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
            this.state.lock().unwrap().outcomes.insert(attempt, outcome);
            match outcome {
                Outcome::Published => this.finish(attempt, Event::Passed),
                _ => this.finish(attempt, Event::Failed(FailureClass::Publication)),
            }
        });
    }
}

struct Fixture {
    _dir: tempfile::TempDir,
    store: Arc<Store>,
    objects: Arc<Objects>,
    controller: Option<Controller>,
    tenant: TenantId,
    other: TenantId,
    repo: RepoId,
    worker: WorkerId,
    workspace: PathBuf,
    publisher: Arc<Publisher>,
}

impl Fixture {
    fn start(protocol_max: u16) -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let workspace = dir.path().join("workspace");
        fs::create_dir(&workspace).unwrap();
        let store =
            Arc::new(Store::open(dir.path().join("metadata.sqlite"), Durability::Normal).unwrap());
        let (root, tenant, other, repo, pool) = (
            UserId::new(),
            TenantId::new(),
            TenantId::new(),
            RepoId::new(),
            PoolId::new(),
        );
        store
            .writer()
            .write(move |tx| {
                provisioning::insert_human(tx, root, "Root", true, UnixMillis(1))?;
                for (id, slug) in [(tenant, "acme"), (other, "other")] {
                    auth::create_namespace(
                        tx,
                        Principal::new(root, P::ALL, None, None),
                        id,
                        Namespace::parse(slug).unwrap(),
                        NamespaceKind::Organization,
                        UnixMillis(1),
                    )?;
                }
                sentinel_store::jobs::insert_repo(tx, tenant, repo, "app", UnixMillis(1))?;
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
            Arc::clone(&objects),
            Identity::generate("controller").unwrap(),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let enrollment = store
            .writer()
            .write(move |tx| {
                workers::issue_enrollment(tx, Authority::HostLocal, pool, 60_000, UnixMillis::now())
            })
            .unwrap()
            .secret;
        let worker_id = WorkerId::new();
        let publisher = Arc::new_cyclic(|weak| Publisher {
            workspace: workspace.clone(),
            weak: weak.clone(),
            state: Mutex::new(State {
                reporter: None,
                fences: HashMap::new(),
                seen: HashMap::new(),
                held: HashMap::new(),
                verdicts: HashMap::new(),
                granted: HashSet::new(),
                outcomes: HashMap::new(),
                manual: false,
            }),
        });
        let handle = Arc::new(Handle::new());
        let config = worker::Config {
            controller: controller.local_addr(),
            server: controller.fingerprint(),
            also_pinned: Vec::new(),
            worker: worker_id,
            name: "builder-1".into(),
            hello: Hello {
                protocol_min: ProtocolVersion(1),
                protocol_max: ProtocolVersion(protocol_max),
                capabilities: Capabilities::REQUIRED,
                arch: Arch::X86_64,
                software: "test".into(),
            },
            capacity: Capacity {
                cpu_millis: 4_000,
                memory_bytes: 4 << 30,
            },
            profile: sentinel_protocol::negotiate::Profile {
                disk_bytes: 64 << 30,
                ..sentinel_protocol::negotiate::Profile::default()
            },
            transport: session::TransportStats::default(),
            remote_cache: false,
        };
        let executor = Arc::clone(&publisher);
        thread::spawn(move || {
            worker::run(
                config,
                Identity::generate("worker").unwrap(),
                Some(enrollment),
                &*executor,
                &handle,
                &|_| {},
            )
        });
        Fixture {
            _dir: dir,
            store,
            objects,
            controller: Some(controller),
            tenant,
            other,
            repo,
            worker: worker_id,
            workspace,
            publisher,
        }
    }

    fn controller(&self) -> &Controller {
        self.controller.as_ref().expect("running")
    }

    fn write(&self, path: &str, bytes: &[u8]) {
        let full = self.workspace.join(path);
        fs::create_dir_all(full.parent().unwrap()).unwrap();
        fs::write(full, bytes).unwrap();
    }

    /// A run whose only job declares `dist`, and the attempt the worker publishes for.
    fn publish(&self) -> (RunId, Vec<JobId>, AttemptId, Outcome) {
        let (tenant, repo, run) = (self.tenant, self.repo, RunId::new());
        let spec = RunSpec::new(
            PinnedSource::new(
                "https://example.invalid/app.git",
                SHA,
                Some("refs/heads/main"),
            )
            .unwrap(),
            compile_str(PIPELINE).unwrap(),
        )
        .unwrap();
        let jobs = self
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
        let deadline = Instant::now() + Duration::from_secs(30);
        let (attempt, outcome) = loop {
            let attempt = self
                .store
                .read(|c| sentinel_store::dispatch::latest_attempt(c, tenant, jobs[0]))
                .unwrap();
            if let Some(attempt) = attempt
                && let Some(outcome) = self
                    .publisher
                    .state
                    .lock()
                    .unwrap()
                    .outcomes
                    .get(&attempt)
                    .copied()
            {
                break (attempt, outcome);
            }
            if Instant::now() > deadline {
                let job = self
                    .store
                    .read(move |c| sentinel_store::jobs::get_job(c, tenant, jobs[0]))
                    .unwrap();
                let held = self
                    .store
                    .read(move |c| sentinel_store::dispatch::held_by(c, self.worker))
                    .unwrap();
                let state = self.publisher.state.lock().unwrap();
                panic!(
                    "the run never published: job {:?} held {:?} reporter {} granted {:?} verdicts {:?} outcomes {:?}",
                    job.state,
                    held.iter()
                        .map(|h| (h.attempt, h.acknowledged))
                        .collect::<Vec<_>>(),
                    state.reporter.is_some(),
                    state.granted,
                    state.verdicts,
                    state.outcomes,
                );
            }
            thread::sleep(Duration::from_millis(10));
        };
        (run, jobs, attempt, outcome)
    }

    /// A run whose attempt the worker holds, with `capture` kept out of the way so a test can drive the
    /// publication itself.
    fn manual_attempt(&self) -> (RunId, AttemptId) {
        self.publisher.state.lock().unwrap().manual = true;
        let (tenant, repo, run) = (self.tenant, self.repo, RunId::new());
        let spec = RunSpec::new(
            PinnedSource::new(
                "https://example.invalid/app.git",
                SHA,
                Some("refs/heads/main"),
            )
            .unwrap(),
            compile_str(PIPELINE).unwrap(),
        )
        .unwrap();
        let jobs = self
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
        let (worker, job) = (self.worker, jobs[0]);
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let held = self
                .store
                .read(move |c| sentinel_store::dispatch::held_by(c, worker))
                .unwrap();
            if let Some(held) = held
                .iter()
                .find(|h| h.job == job && h.acknowledged)
                .map(|h| h.attempt)
                && self.publisher.state.lock().unwrap().reporter.is_some()
            {
                return (run, held);
            }
            if Instant::now() > deadline {
                let job = self
                    .store
                    .read(move |c| sentinel_store::jobs::get_job(c, tenant, jobs[0]))
                    .unwrap();
                let held = self
                    .store
                    .read(move |c| sentinel_store::dispatch::held_by(c, worker))
                    .unwrap();
                panic!(
                    "the attempt was never held: job {:?} held {:?}",
                    job.state,
                    held.iter()
                        .map(|h| (h.attempt, h.acknowledged))
                        .collect::<Vec<_>>(),
                );
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn rows(&self, run: RunId) -> Vec<sentinel_store::artifacts::Row> {
        let tenant = self.tenant;
        self.store
            .read(move |c| sentinel_store::artifacts::for_run(c, tenant, run))
            .unwrap()
    }

    fn manifest(&self, job: JobId, version: u64) -> Vec<objects::Entry> {
        let tenant = self.tenant;
        self.store
            .read(move |c| {
                self.objects.manifest(
                    c,
                    tenant,
                    objects::Kind::Artifact,
                    &sentinel_store::artifacts::manifest_name(job, "dist"),
                    Some(version),
                )
            })
            .unwrap()
            .entries
    }

    /// Commit bytes straight into a tenant's objects, as an earlier publication would have.
    fn hold(&self, tenant: TenantId, bytes: &[u8]) -> objects::Digest {
        let digest = objects::Digest::from_bytes(*blake3::hash(bytes).as_bytes());
        let staged = self
            .objects
            .stage(
                tenant,
                bytes,
                1 << 20,
                Expect {
                    len: Some(bytes.len() as u64),
                    digest: Some(digest),
                },
            )
            .unwrap();
        let objects = Arc::clone(&self.objects);
        self.store
            .writer()
            .write(move |tx| {
                objects.commit(tx, &staged)?;
                Ok(())
            })
            .unwrap();
        digest
    }

    fn holds(&self, tenant: TenantId, digest: objects::Digest, len: u64) -> bool {
        self.store
            .read(move |c| Objects::holds(c, tenant, digest, len))
            .unwrap()
    }
}

fn digest_of(bytes: &[u8]) -> objects::Digest {
    objects::Digest::from_bytes(*blake3::hash(bytes).as_bytes())
}

#[test]
fn a_fresh_artifact_offers_every_file_and_travels_every_body() {
    let fixture = Fixture::start(12);
    fixture.write("out/a.txt", b"alpha");
    fixture.write("out/b.txt", b"beta");
    let (run, jobs, attempt, outcome) = fixture.publish();
    assert_eq!(outcome, Outcome::Published);
    let seen = fixture.publisher.seen(attempt);
    assert!(seen.contains(&Seen::Offered(2)), "{seen:?}");
    assert!(seen.contains(&Seen::Held(Vec::new())), "{seen:?}");
    assert_eq!(fixture.publisher.sent(attempt), ["out/a.txt", "out/b.txt"]);

    let rows = fixture.rows(run);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].state, sentinel_store::artifacts::State::Captured);
    assert_eq!((rows[0].entries, rows[0].bytes), (2, 9));
    let entries = fixture.manifest(jobs[0], rows[0].manifest_version.unwrap());
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].digest, digest_of(b"alpha"));
    assert_eq!(entries[0].len, 5);
    assert_eq!(entries[1].digest, digest_of(b"beta"));
    assert!(fixture.holds(fixture.tenant, digest_of(b"alpha"), 5));
}

#[test]
fn a_repeated_artifact_travels_no_body_the_tenant_already_holds() {
    let fixture = Fixture::start(12);
    fixture.write("out/a.txt", b"alpha");
    fixture.write("out/b.txt", b"beta");
    let (first, _, attempt, outcome) = fixture.publish();
    assert_eq!(outcome, Outcome::Published);
    assert!(fixture.publisher.held(attempt).is_empty());
    assert_eq!(fixture.publisher.sent(attempt).len(), 2);

    let (second, jobs, attempt, outcome) = fixture.publish();
    assert_eq!(outcome, Outcome::Published);
    assert_eq!(fixture.publisher.held(attempt), [0, 1]);
    assert!(
        fixture.publisher.sent(attempt).is_empty(),
        "{:?}",
        fixture.publisher.seen(attempt)
    );
    let rows = fixture.rows(second);
    assert_eq!(rows[0].state, sentinel_store::artifacts::State::Captured);
    // The artifact's own size is unchanged: dedup is about the bytes that travel and are stored, not about what
    // the artifact is made of.
    assert_eq!((rows[0].entries, rows[0].bytes), (2, 9));
    let entries = fixture.manifest(jobs[0], rows[0].manifest_version.unwrap());
    assert_eq!(entries[0].digest, digest_of(b"alpha"));
    assert_eq!(entries[1].digest, digest_of(b"beta"));

    // Both artifacts read back the same bytes, from one object each.
    let mut alpha = Vec::new();
    fixture
        .store
        .read(|c| {
            fixture
                .objects
                .read(c, fixture.tenant, digest_of(b"alpha"), &mut alpha)
        })
        .unwrap();
    assert_eq!(alpha, b"alpha");
    assert_ne!(first, second);
}

#[test]
fn a_partial_offer_sends_only_the_bodies_that_are_missing() {
    let fixture = Fixture::start(12);
    let held = fixture.hold(fixture.tenant, b"middle");
    fixture.write("out/a.txt", b"alpha");
    fixture.write("out/m.txt", b"middle");
    fixture.write("out/z.txt", b"zeta");
    let (run, jobs, attempt, outcome) = fixture.publish();
    assert_eq!(outcome, Outcome::Published);
    assert_eq!(fixture.publisher.held(attempt), [1]);
    assert_eq!(fixture.publisher.sent(attempt), ["out/a.txt", "out/z.txt"]);
    let rows = fixture.rows(run);
    assert_eq!((rows[0].entries, rows[0].bytes), (3, 15));
    let entries = fixture.manifest(jobs[0], rows[0].manifest_version.unwrap());
    assert_eq!(
        entries.iter().map(|e| e.path.as_str()).collect::<Vec<_>>(),
        ["out/a.txt", "out/m.txt", "out/z.txt"]
    );
    assert_eq!(entries[1].digest, held);
    assert_eq!(entries[1].len, 6);
}

#[test]
fn a_digest_another_tenant_holds_is_never_short_circuited() {
    let fixture = Fixture::start(12);
    let shared = b"shared queue report";
    let digest = fixture.hold(fixture.other, shared);
    fixture.write("out/report.txt", shared);
    let (run, jobs, attempt, outcome) = fixture.publish();
    assert_eq!(outcome, Outcome::Published);
    // The probe reveals nothing: this tenant does not hold it, so its body travels and no answer names it.
    assert!(fixture.publisher.held(attempt).is_empty());
    assert_eq!(fixture.publisher.sent(attempt), ["out/report.txt"]);
    assert!(fixture.holds(fixture.other, digest, shared.len() as u64));
    assert!(fixture.holds(fixture.tenant, digest, shared.len() as u64));
    let rows = fixture.rows(run);
    assert_eq!(rows[0].bytes, shared.len() as u64);
    let entries = fixture.manifest(jobs[0], rows[0].manifest_version.unwrap());
    assert_eq!(entries[0].digest, digest);

    // The control the probe is read against: once this tenant holds the bytes itself, its body stays home.
    let (_, _, attempt, outcome) = fixture.publish();
    assert_eq!(outcome, Outcome::Published);
    assert_eq!(fixture.publisher.held(attempt), [0]);
    assert!(fixture.publisher.sent(attempt).is_empty());
}

#[test]
fn a_body_that_does_not_hash_to_the_offered_digest_fails_the_artifact() {
    let fixture = Fixture::start(12);
    fixture.write("out/a.txt", b"right");
    let (run, attempt) = fixture.manual_attempt();
    let reporter = fixture.publisher.reporter();
    let promised = digest_of(b"other");
    reporter.artifact_begin(attempt, "dist").unwrap();
    reporter
        .artifact_offer(
            attempt,
            "dist",
            &[Offered {
                path: "out/a.txt".into(),
                digest: *promised.as_bytes(),
                len: 5,
                mode: 0o644,
            }],
            true,
        )
        .unwrap();
    assert!(fixture.publisher.held(attempt).is_empty());
    reporter
        .artifact_file(attempt, "out/a.txt", 5, 0o644)
        .unwrap();
    reporter.artifact_data(attempt, 0, b"right").unwrap();
    reporter.artifact_end(attempt, "dist").unwrap();
    assert_eq!(fixture.publisher.verdict(attempt), ArtifactCode::Invalid);
    let rows = fixture.rows(run);
    assert_eq!(rows[0].state, sentinel_store::artifacts::State::Failed);
    assert_eq!((rows[0].entries, rows[0].bytes), (0, 0));
    // The bytes that arrived were never made this tenant's, and nothing references the offered digest.
    assert!(!fixture.holds(fixture.tenant, promised, 5));
    assert!(!fixture.holds(fixture.tenant, digest_of(b"right"), 5));
}

#[test]
fn a_session_below_protocol_12_publishes_every_body_and_refuses_an_offer() {
    let fixture = Fixture::start(11);
    fixture.write("out/a.txt", b"alpha");
    let (run, jobs, attempt, outcome) = fixture.publish();
    assert_eq!(outcome, Outcome::Published);
    assert!(
        !fixture
            .publisher
            .seen(attempt)
            .iter()
            .any(|s| matches!(s, Seen::Offered(_) | Seen::Held(_)))
    );
    assert_eq!(fixture.publisher.sent(attempt), ["out/a.txt"]);
    let rows = fixture.rows(run);
    assert_eq!(rows[0].state, sentinel_store::artifacts::State::Captured);
    let entries = fixture.manifest(jobs[0], rows[0].manifest_version.unwrap());
    assert_eq!(entries[0].digest, digest_of(b"alpha"));

    // A peer that cannot speak 12 refuses the offer instead of sending a message the other side cannot parse.
    let reporter = fixture.publisher.reporter();
    assert!(!reporter.digests());
    let refused = reporter.artifact_offer(
        attempt,
        "dist",
        &[Offered {
            path: "out/a.txt".into(),
            digest: [0u8; 32],
            len: 5,
            mode: 0o644,
        }],
        true,
    );
    assert!(refused.is_err(), "{refused:?}");
}

#[test]
fn an_offer_larger_than_one_batch_is_answered_once() {
    let fixture = Fixture::start(12);
    for i in 0..(sentinel_protocol::limits::MAX_ARTIFACT_OFFER_ENTRIES * 2 + 4) {
        fixture.write(&format!("out/f{i:03}.bin"), &[i as u8; 8]);
    }
    let (run, jobs, attempt, outcome) = fixture.publish();
    assert_eq!(outcome, Outcome::Published);
    let offered: usize = fixture
        .publisher
        .seen(attempt)
        .iter()
        .filter_map(|s| match s {
            Seen::Offered(n) => Some(*n),
            _ => None,
        })
        .sum();
    assert_eq!(
        offered,
        sentinel_protocol::limits::MAX_ARTIFACT_OFFER_ENTRIES * 2 + 4
    );
    assert!(fixture.publisher.held(attempt).is_empty());
    let rows = fixture.rows(run);
    assert_eq!(rows[0].entries as usize, offered);
    let entries = fixture.manifest(jobs[0], rows[0].manifest_version.unwrap());
    assert_eq!(entries.len(), offered);

    // The same artifact again: every entry is held, including those of every batch before the last, and no body
    // of it travels.
    let (second, jobs, attempt, outcome) = fixture.publish();
    assert_eq!(outcome, Outcome::Published);
    assert_eq!(fixture.publisher.held(attempt).len(), offered);
    assert!(fixture.publisher.sent(attempt).is_empty());
    let rows = fixture.rows(second);
    assert_eq!(rows[0].entries as usize, offered);
    let entries = fixture
        .manifest(jobs[0], rows[0].manifest_version.unwrap())
        .len();
    assert_eq!(entries, offered);
}

#[test]
fn many_files_publish_as_bodies_on_a_protocol_11_session() {
    let fixture = Fixture::start(11);
    for i in 0..48 {
        fixture.write(&format!("out/f{i:03}.bin"), &[i as u8; 8]);
    }
    let (run, jobs, attempt, outcome) = fixture.publish();
    assert_eq!(
        outcome,
        Outcome::Published,
        "verdict {:?}",
        fixture.publisher.verdict(attempt)
    );
    let rows = fixture.rows(run);
    assert_eq!((rows[0].entries, rows[0].bytes), (48, 48 * 8));
    let entries = fixture.manifest(jobs[0], rows[0].manifest_version.unwrap());
    assert_eq!(entries.len(), 48);
}
