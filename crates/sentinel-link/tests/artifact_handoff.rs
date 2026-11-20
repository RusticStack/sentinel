//! I04's gate on artifact handoff: a job's worker takes an earlier job's published artifact from the controller,
//! entry by entry, over the worker link — the same publication, digests and retention the artifact system already
//! records, with no second copy of anything.

use std::{
    sync::{Arc, Mutex, mpsc},
    thread,
    time::{Duration, Instant},
};

use sentinel_core::{
    AttemptId, Event, JobId, PoolId, RepoId, RunId, TenantId, UnixMillis, UserId, WorkerId,
    auth::{Namespace, Permissions as P, Principal},
};
use sentinel_link::{
    controller::Controller,
    identity::Identity,
    session::{self, Capacity, Executor, HandoffError, HandoffSink, Offer},
    worker,
};
use sentinel_pipeline::{PinnedSource, RunSpec, compile_str};
use sentinel_protocol::{
    handoff::{Entry, Refusal},
    negotiate::{Arch, Capabilities, Hello, Profile, ProtocolVersion},
};
use sentinel_store::{
    Durability, Store,
    artifacts::{self, State},
    auth::{self, Authority, NamespaceKind, provisioning},
    logs::LogStore,
    objects::{self, Kind},
    runs,
    tenancy::{self, PoolKind},
    workers,
};

const DIGEST: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const SHA: &str = "0123456789abcdef0123456789abcdef01234567";
/// The producer publishes `dist`; the consumer declares it as a handoff into `incoming`.
const PIPELINE: &str = "schema: 1\non: [push]\njobs:\n  build:\n    image: alpine:3\n    steps: [{id: s, run: 'true'}]\n    artifacts: [{name: dist, paths: [out]}]\n  publish:\n    image: alpine:3\n    needs: [build]\n    steps: [{id: s, run: 'true'}]\n    handoff: [{from: build, artifact: dist, into: incoming}]\n";
/// A consumer that names an artifact it never declares: the controller refuses it whatever it asks for.
const UNDECLARED: &str = "schema: 1\non: [push]\njobs:\n  build:\n    image: alpine:3\n    steps: [{id: s, run: 'true'}]\n    artifacts: [{name: dist, paths: [out]}]\n  publish:\n    image: alpine:3\n    needs: [build]\n    steps: [{id: s, run: 'true'}]\n";
const BODY: &[u8] = b"release 1.4.0";

/// What a handoff streamed, entry by entry, and what the fetch answered.
type Files = Arc<Mutex<Vec<(String, Vec<u8>)>>>;
type Requests = Arc<Mutex<Vec<(AttemptId, Result<(), HandoffError>)>>>;

struct Deployment {
    _dir: tempfile::TempDir,
    store: Arc<Store>,
    objects: Arc<objects::Objects>,
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
                "builders",
                PoolKind::Dedicated(tenant),
                UnixMillis(1),
            )
        })
        .unwrap();
    let logs = Arc::new(LogStore::open(dir.path().join("logs")).unwrap());
    let objects = Arc::new(objects::Objects::open(dir.path().join("objects")).unwrap());
    let controller = Controller::start(
        Arc::clone(&store),
        logs,
        Arc::clone(&objects),
        Identity::generate("controller").unwrap(),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    Deployment {
        _dir: dir,
        store,
        objects,
        controller,
        tenant,
        repo,
        pool,
    }
}

impl Deployment {
    fn enrollment(&self) -> sentinel_auth::secret::Secret {
        let pool = self.pool;
        self.store
            .writer()
            .write(move |tx| {
                workers::issue_enrollment(tx, Authority::HostLocal, pool, 60_000, UnixMillis::now())
            })
            .unwrap()
            .secret
    }

    /// Creates the run and answers the build job's id, so the producer's artifact can be published for it.
    fn run(&self, pipeline: &str) -> (Vec<JobId>, RunId) {
        let (tenant, repo, run) = (self.tenant, self.repo, RunId::new());
        let spec = RunSpec::new(
            PinnedSource::new("https://github.com/o/r.git", SHA, Some("refs/heads/main")).unwrap(),
            compile_str(pipeline).unwrap(),
        )
        .unwrap();
        let ids = self
            .store
            .writer()
            .write(move |tx| {
                let ids = runs::create_run(tx, tenant, repo, run, &spec, UnixMillis::now())?;
                for job in &ids {
                    runs::resolve_image(tx, tenant, *job, DIGEST, "linux/amd64")?;
                }
                Ok(ids)
            })
            .unwrap();
        self.controller.wake();
        (ids, run)
    }

    /// Publishes `dist` the way a finished build attempt does: the object, the manifest, and the row that names it.
    fn publish(&self, run: RunId, job: JobId, attempt: AttemptId) {
        let tenant = self.tenant;
        let staged = self
            .objects
            .stage(tenant, BODY, u64::MAX, objects::Expect::default())
            .unwrap();
        let (digest, len) = (staged.digest(), staged.len());
        let manifest = artifacts::manifest_name(job, "dist");
        let objects = Arc::clone(&self.objects);
        self.store
            .writer()
            .write(move |tx| {
                objects.commit(tx, &staged)?;
                let version = objects.commit_manifest(
                    tx,
                    tenant,
                    Kind::Artifact,
                    &manifest,
                    &[objects::Entry {
                        path: "bin/app".into(),
                        digest,
                        len,
                        mode: 0o644,
                    }],
                )?;
                artifacts::record(
                    tx,
                    tenant,
                    run,
                    job,
                    attempt,
                    "dist",
                    State::Captured,
                    Some(version),
                    1,
                    len,
                    UnixMillis(UnixMillis::now().0 + 86_400_000),
                    UnixMillis::now(),
                )
            })
            .unwrap();
    }
}

/// What the worker's executor did with a handoff: the stream's outcome, and the entries it wrote.
struct Holder {
    offers: Mutex<mpsc::Sender<Offer>>,
    held: Mutex<Vec<AttemptId>>,
    reporter: Mutex<Option<session::Reporter>>,
    /// The attempt whose spec arrived for the consuming job, and what the handoff did.
    requested: Requests,
    files: Files,
    /// The artifact name to ask for, so one test can name one the job never declares.
    ask: (String, String),
}

impl Holder {
    fn new(ask: (&str, &str)) -> (Arc<Holder>, mpsc::Receiver<Offer>) {
        let (tx, rx) = mpsc::channel();
        (
            Arc::new(Holder {
                offers: Mutex::new(tx),
                held: Mutex::new(Vec::new()),
                reporter: Mutex::new(None),
                requested: Arc::new(Mutex::new(Vec::new())),
                files: Arc::new(Mutex::new(Vec::new())),
                ask: (ask.0.to_owned(), ask.1.to_owned()),
            }),
            rx,
        )
    }

    fn reporter(&self) -> session::Reporter {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(reporter) = self.reporter.lock().unwrap().clone() {
                return reporter;
            }
            assert!(Instant::now() < deadline, "no session");
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn wait(&self, deadline: Instant) {
        while self.requested.lock().unwrap().is_empty() {
            assert!(Instant::now() < deadline, "no handoff was requested");
            thread::sleep(Duration::from_millis(10));
        }
    }
}

/// A sink that keeps what arrived, keyed by the entry path, so the test can compare it with the publication.
struct Collect {
    files: Files,
    current: Option<(String, Vec<u8>, [u8; 32])>,
    entries: u32,
    declared: u32,
}

impl HandoffSink for Collect {
    fn begin(&mut self, entries: u32, _bytes: u64) -> bool {
        self.declared = entries;
        true
    }
    fn entry(&mut self, entry: &Entry) -> bool {
        self.current = Some((entry.path.clone(), Vec::new(), entry.digest));
        true
    }
    fn body(&mut self, _seq: u32, bytes: &[u8]) -> bool {
        let Some((_, held, _)) = &mut self.current else {
            return false;
        };
        held.extend_from_slice(bytes);
        true
    }
    fn end(&mut self) -> bool {
        if let Some((path, held, digest)) = self.current.take() {
            if *blake3::hash(&held).as_bytes() != digest {
                return false;
            }
            self.entries += 1;
            self.files.lock().unwrap().push((path, held));
        }
        self.entries == self.declared
    }
}

impl Executor for Holder {
    fn offered(&self, offer: &Offer) -> bool {
        self.held.lock().unwrap().push(offer.attempt);
        let _ = self.offers.lock().unwrap().send(offer.clone());
        true
    }
    fn accepted(&self, attempt: AttemptId) {
        // The worker asks for the spec as soon as it takes the attempt, which is what makes `spec` arrive.
        let reporter = self.reporter();
        let _ = reporter.need_spec(attempt);
    }
    fn stop(&self, attempt: AttemptId) {
        self.held.lock().unwrap().retain(|a| *a != attempt);
    }
    fn cancel(&self, _: AttemptId) {}
    fn held(&self) -> Vec<AttemptId> {
        self.held.lock().unwrap().clone()
    }
    fn renewed(&self, _: UnixMillis) {}
    fn attached(&self, reporter: session::Reporter) {
        *self.reporter.lock().unwrap() = Some(reporter);
    }
    fn detached(&self) {}
    fn spec(&self, attempt: AttemptId, context: session::JobContext, _: Vec<u8>) {
        self.held.lock().unwrap().push(attempt);
        // Only the consuming job asks for anything; the producer's spec is just run. The fetch runs on its own
        // thread, as the worker's preparation does: the session's reader thread is what routes the stream.
        if context.job_name != "publish" {
            return;
        }
        let files = Arc::clone(&self.files);
        let requested = Arc::clone(&self.requested);
        let reporter = self.reporter();
        let ask = self.ask.clone();
        thread::spawn(move || {
            let mut sink = Collect {
                files,
                current: None,
                entries: 0,
                declared: 0,
            };
            let outcome = reporter.fetch_handoff(
                attempt,
                &ask.0,
                &ask.1,
                Instant::now() + Duration::from_secs(10),
                &mut sink,
            );
            requested.lock().unwrap().push((attempt, outcome));
        });
    }
    fn no_spec(&self, _: AttemptId) {}
    fn spec_with_secrets(
        &self,
        attempt: AttemptId,
        context: session::JobContext,
        bytes: Vec<u8>,
        _: sentinel_protocol::secrets::DeliveryBundle,
    ) {
        self.spec(attempt, context, bytes);
    }
    fn log_acked(&self, _: AttemptId, _: u64) {}
    fn log_refused(&self, _: AttemptId) {}
    fn availability(&self) -> Option<(u64, sentinel_protocol::negotiate::Availability)> {
        None
    }
    fn log_ended(&self, _: AttemptId) {}
}

struct WorkerProcess {
    handle: Arc<worker::Handle>,
    thread: Option<thread::JoinHandle<Result<(), sentinel_link::Error>>>,
}

impl WorkerProcess {
    fn start(d: &Deployment, id: WorkerId, executor: Arc<Holder>) -> WorkerProcess {
        let handle = Arc::new(worker::Handle::new());
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
                software: "test".into(),
            },
            capacity: Capacity {
                cpu_millis: 4_000,
                memory_bytes: 8 << 30,
            },
            profile: Profile {
                disk_bytes: 64 << 30,
                ..Profile::default()
            },
            transport: session::TransportStats::default(),
            remote_cache: true,
        };
        let enrollment = Some(d.enrollment());
        let grip = Arc::clone(&handle);
        let thread = thread::spawn(move || {
            worker::run(
                config,
                Identity::generate("w").unwrap(),
                enrollment,
                &*executor,
                &grip,
                &|_| {},
            )
        });
        WorkerProcess {
            handle,
            thread: Some(thread),
        }
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

/// Reports the producer's attempt as passed, so the controller releases the job that needs it.
fn pass(holder: &Holder, offer: &Offer) {
    let reporter = holder.reporter();
    for event in [
        Event::PreparationStarted,
        Event::StepsStarted,
        Event::FinalizationStarted,
        Event::Passed,
    ] {
        reporter.report(offer.attempt, offer.fence, event).unwrap();
    }
}

/// Answers one offer so the session takes the attempt; without it the attempt is never acked and the handoff is
/// refused as a fence the worker does not hold.
fn accept(d: &Deployment, offers: &mpsc::Receiver<Offer>) -> Offer {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        d.controller.wake();
        match offers.recv_timeout(Duration::from_millis(200)) {
            Ok(offer) => return offer,
            Err(mpsc::RecvTimeoutError::Timeout) => {
                assert!(Instant::now() < deadline, "no offer");
            }
            Err(e) => panic!("{e}"),
        }
    }
}

#[test]
fn a_consuming_job_takes_the_producers_published_artifact_over_the_link() {
    let d = deployment();
    let (holder, offers) = Holder::new(("build", "dist"));
    let _worker = WorkerProcess::start(&d, WorkerId::new(), Arc::clone(&holder));
    let (jobs, run) = d.run(PIPELINE);
    let offer = accept(&d, &offers);
    assert_eq!(offer.job, jobs[0], "the build job is offered first");
    d.publish(run, jobs[0], offer.attempt);
    pass(&holder, &offer);

    // The consumer is offered next; its spec makes the worker ask for `build/dist`.
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        match offers.recv_timeout(Duration::from_millis(200)) {
            Ok(next) if next.job == jobs[1] => break,
            Ok(_) => continue,
            Err(mpsc::RecvTimeoutError::Timeout) => {
                d.controller.wake();
                assert!(Instant::now() < deadline, "no offer for the consuming job");
            }
            Err(_) => panic!("no offer for the consuming job"),
        }
    }
    holder.wait(deadline);
    let requested = holder.requested.lock().unwrap().clone();
    let (_, outcome) = requested
        .first()
        .expect("the consumer asked for its handoff");
    assert_eq!(*outcome, Ok(()), "the artifact arrived and verified");
    let files = holder.files.lock().unwrap().clone();
    assert_eq!(
        files,
        vec![("bin/app".to_owned(), BODY.to_vec())],
        "the entry is the producer's own path and bytes"
    );
}

#[test]
fn an_artifact_the_consuming_job_never_declared_is_refused() {
    let d = deployment();
    let (holder, offers) = Holder::new(("build", "dist"));
    let _worker = WorkerProcess::start(&d, WorkerId::new(), Arc::clone(&holder));
    let (jobs, run) = d.run(UNDECLARED);
    let offer = accept(&d, &offers);
    assert_eq!(offer.job, jobs[0]);
    d.publish(run, jobs[0], offer.attempt);
    pass(&holder, &offer);

    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        match offers.recv_timeout(Duration::from_millis(200)) {
            Ok(next) if next.job == jobs[1] => break,
            Ok(_) => continue,
            Err(mpsc::RecvTimeoutError::Timeout) => {
                d.controller.wake();
                assert!(Instant::now() < deadline, "no offer for the consuming job");
            }
            Err(_) => panic!("no offer for the consuming job"),
        }
    }
    holder.wait(deadline);
    let (_, outcome) = holder.requested.lock().unwrap()[0];
    assert_eq!(
        outcome,
        Err(HandoffError::Refused(Refusal::Denied)),
        "a job cannot read an artifact it never declared"
    );
    assert!(holder.files.lock().unwrap().is_empty());
}
