//! Q08 remote cache end to end over real TLS against a running
//! `Controller` and its on-disk store — the paths the in-memory fakes of
//! `sentinel-cache/tests/remote.rs` cannot reach:
//!
//! - an offer sent after the attempt's terminal report is stored, and a
//!   later attempt of the same repository hydrates it (P07-7 / P08-C1);
//! - an offer from a worker that does not own the attempt is `denied`;
//! - a fetch the worker abandons is cancelled on the controller, and the
//!   next fetch of the same attempt gets a clean stream (P08-C2/C3);
//! - the worker's profile carries the executor's measured availability and
//!   refreshes it as it changes (P07-6).

use std::{
    io::Cursor,
    sync::{Arc, Mutex, mpsc},
    thread,
    time::{Duration, Instant},
};

use sentinel_cache::remote::{Chunk, Grant, Need, Refusal, Sink, Upload};
use sentinel_core::{
    AttemptId, Event, JobId, PoolId, RepoId, RunId, TenantId, UnixMillis, UserId, WorkerId,
    auth::{Namespace, Permissions as P, Principal},
};
use sentinel_link::{
    controller::Controller,
    identity::Identity,
    session::{self, Capacity, Executor, Offer},
    worker,
};
use sentinel_pipeline::{PinnedSource, RunSpec, compile_str};
use sentinel_protocol::{
    cache::{Class, Trust},
    negotiate::{Arch, Availability, Capabilities, Hello, ProtocolVersion},
};
use sentinel_store::{
    Durability, Store,
    auth::{self, Authority, NamespaceKind, provisioning},
    logs::LogStore,
    runs,
    tenancy::{self, PoolKind},
    workers,
};

const DIGEST: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const SHA: &str = "0123456789abcdef0123456789abcdef01234567";
const PIPELINE: &str = "schema: 1\non: [push]\njobs:\n  build:\n    image: alpine:3\n    steps: [{ id: s, run: 'true' }]\n";

struct Deployment {
    dir: tempfile::TempDir,
    store: Arc<Store>,
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
    let objects =
        Arc::new(sentinel_store::objects::Objects::open(dir.path().join("objects")).unwrap());
    let controller = Controller::start(
        Arc::clone(&store),
        logs,
        objects,
        Identity::generate("controller").unwrap(),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    controller.set_remote_cache(dir.path().join("remote-cache"));
    Deployment {
        dir,
        store,
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

    fn run(&self) {
        let (tenant, repo, run) = (self.tenant, self.repo, RunId::new());
        let spec = RunSpec::new(
            PinnedSource::new("https://github.com/o/r.git", SHA, Some("refs/heads/main")).unwrap(),
            compile_str(PIPELINE).unwrap(),
        )
        .unwrap();
        self.store
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
    }
}

/// An executor that holds what it is offered, hands out its reporter and
/// reports whatever availability a test sets.
struct Holder {
    offers: Mutex<mpsc::Sender<Offer>>,
    held: Mutex<Vec<AttemptId>>,
    reporter: Mutex<Option<session::Reporter>>,
    availability: Mutex<Option<(u64, Availability)>>,
}

impl Holder {
    fn new() -> (Arc<Holder>, mpsc::Receiver<Offer>) {
        let (tx, rx) = mpsc::channel();
        (
            Arc::new(Holder {
                offers: Mutex::new(tx),
                held: Mutex::new(Vec::new()),
                reporter: Mutex::new(None),
                availability: Mutex::new(None),
            }),
            rx,
        )
    }

    fn reporter(&self) -> session::Reporter {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(r) = self.reporter.lock().unwrap().clone() {
                return r;
            }
            assert!(Instant::now() < deadline, "no session");
            thread::sleep(Duration::from_millis(10));
        }
    }
}

impl Executor for Holder {
    fn offered(&self, offer: &Offer) -> bool {
        self.held.lock().unwrap().push(offer.attempt);
        let _ = self.offers.lock().unwrap().send(offer.clone());
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
    fn availability(&self) -> Option<(u64, Availability)> {
        self.availability.lock().unwrap().clone()
    }
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
            profile: sentinel_protocol::negotiate::Profile::default(),
            transport: sentinel_link::session::TransportStats::default(),
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

fn eventually(what: &str, mut predicate: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(20);
    while !predicate() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        thread::sleep(Duration::from_millis(20));
    }
}

/// The cache boundary a manual run of the deployment's repository has on
/// a protocol-8 worker: its tenant and repository, `unprotected` trust.
fn upload(d: &Deployment, attempt: AttemptId, stream: &[u8]) -> Upload {
    Upload {
        attempt: *attempt.as_bytes(),
        tenant: *d.tenant.as_bytes(),
        repo: *d.repo.as_bytes(),
        class: Class::Dependencies.to_u8(),
        trust: Trust::Unprotected.to_u8(),
        os: sentinel_cache::remote::OS_LINUX,
        arch: sentinel_cache::remote::ARCH_X86_64,
        toolchain: [5; 32],
        name: "deps".into(),
        key: "deps-remote".into(),
        total: stream.len() as u64,
        digest: *blake3::hash(stream).as_bytes(),
    }
}

fn need(u: &Upload, attempt: AttemptId) -> Need {
    Need {
        attempt: *attempt.as_bytes(),
        tenant: u.tenant,
        repo: u.repo,
        class: u.class,
        trust: u.trust,
        os: u.os,
        arch: u.arch,
        toolchain: u.toolchain,
        name: u.name.clone(),
        key: u.key.clone(),
        offset: 0,
        have: *blake3::Hasher::new().finalize().as_bytes(),
    }
}

/// Collects a fetched stream; optionally stops after `stop_after` chunks.
#[derive(Default)]
struct Collect {
    grant: Option<Grant>,
    bytes: Vec<u8>,
    chunks: usize,
    stop_after: Option<usize>,
}

impl Sink for Collect {
    fn plan(&mut self, grant: &Grant) -> Result<(), Refusal> {
        self.grant = Some(*grant);
        Ok(())
    }
    fn chunk(&mut self, chunk: &Chunk) -> Result<(), Refusal> {
        if chunk.offset != self.bytes.len() as u64 {
            return Err(Refusal::Store);
        }
        self.bytes.extend_from_slice(&chunk.bytes);
        if chunk.prefix != *blake3::hash(&self.bytes).as_bytes() {
            return Err(Refusal::Store);
        }
        self.chunks += 1;
        if self.stop_after.is_some_and(|n| self.chunks >= n) {
            return Err(Refusal::Aborted);
        }
        Ok(())
    }
}

fn next_attempt(d: &Deployment, offers: &mpsc::Receiver<Offer>) -> Offer {
    d.run();
    offers.recv_timeout(Duration::from_secs(10)).unwrap()
}

/// P07-7 / P08-C1: the worker offers after its terminal report released
/// the attempt, and the controller stores it; a later attempt of the same
/// repository fetches it byte for byte, a transfer the worker abandons is
/// cancelled and the attempt's next fetch is clean, and another worker can
/// never offer under an attempt it does not own.
#[test]
fn an_offer_after_the_terminal_report_is_stored_and_serves_the_next_attempt() {
    let d = deployment();
    let (holder, offers) = Holder::new();
    let _worker = WorkerProcess::start(&d, WorkerId::new(), Arc::clone(&holder));
    let offer = next_attempt(&d, &offers);
    let first = offer.attempt;
    let reporter = holder.reporter();
    eventually("the offer acknowledged", || {
        d.store
            .read(|c| {
                Ok(c.query_row(
                    "SELECT acked_ms IS NOT NULL FROM attempts WHERE id = ?1",
                    [first.as_bytes()],
                    |r| r.get::<_, bool>(0),
                )?)
            })
            .unwrap_or(false)
    });
    for event in [
        Event::PreparationStarted,
        Event::StepsStarted,
        Event::FinalizationStarted,
        Event::Passed,
    ] {
        reporter.report(first, offer.fence, event).unwrap();
    }
    eventually("the attempt released", || {
        d.store
            .read(|c| {
                Ok(c.query_row(
                    "SELECT released_ms IS NOT NULL FROM attempts WHERE id = ?1",
                    [first.as_bytes()],
                    |r| r.get::<_, bool>(0),
                )?)
            })
            .unwrap_or(false)
    });
    let remote = reporter
        .remote_cache()
        .expect("protocol 8 exposes the cache");
    let stream: Vec<u8> = (0..600_000u32).map(|i| (i % 251) as u8).collect();
    let offered = upload(&d, first, &stream);
    remote
        .offer(
            &offered,
            Instant::now() + Duration::from_secs(20),
            &mut Cursor::new(stream.clone()),
        )
        .expect("an offer of a just-released attempt is stored");

    // The next attempt of the repository hydrates exactly those bytes.
    holder.held.lock().unwrap().retain(|a| *a != first);
    let second = next_attempt(&d, &offers).attempt;
    let mut full = Collect::default();
    remote
        .fetch(
            &need(&offered, second),
            Instant::now() + Duration::from_secs(20),
            &mut full,
        )
        .unwrap();
    assert_eq!(full.bytes, stream);

    // Abandoned after one chunk: the controller is told, stops, and the
    // next fetch of the same attempt is a clean, complete stream — none of
    // the abandoned transfer's tail is routed into it.
    let mut cut = Collect {
        stop_after: Some(1),
        ..Collect::default()
    };
    assert_eq!(
        remote.fetch(
            &need(&offered, second),
            Instant::now() + Duration::from_secs(20),
            &mut cut
        ),
        Err(Refusal::Aborted)
    );
    let started = Instant::now();
    let clean = loop {
        let mut again = Collect::default();
        match remote.fetch(
            &need(&offered, second),
            Instant::now() + Duration::from_secs(20),
            &mut again,
        ) {
            Ok(()) => break again,
            // Still draining the cancelled transfer's terminal.
            Err(Refusal::Busy) => {
                assert!(started.elapsed() < Duration::from_secs(10), "never drained");
                thread::sleep(Duration::from_millis(20));
            }
            Err(other) => panic!("a clean fetch after a cancel failed: {other}"),
        }
    };
    assert_eq!(clean.bytes, stream);

    // A worker that does not own the attempt is refused.
    let denied_before = d
        .controller
        .stats()
        .cache_denied
        .load(std::sync::atomic::Ordering::Relaxed);
    let (other_holder, _other_offers) = Holder::new();
    let _other = WorkerProcess::start(&d, WorkerId::new(), Arc::clone(&other_holder));
    let intruder = other_holder.reporter().remote_cache().unwrap();
    let stolen = upload(&d, second, b"not yours");
    assert_eq!(
        intruder.offer(
            &stolen,
            Instant::now() + Duration::from_secs(10),
            &mut Cursor::new(b"not yours".to_vec())
        ),
        Err(Refusal::Denied)
    );
    assert!(
        d.controller
            .stats()
            .cache_denied
            .load(std::sync::atomic::Ordering::Relaxed)
            > denied_before
    );

    // Protocol 9 (P08-C8): the offer names its digest only in its end
    // marker — the worker reads the stream once and hashes it on the way
    // out — and the controller stores it under the digest the bytes prove.
    assert!(remote.digest_at_end());
    let restream: Vec<u8> = (0..300_000u32).map(|i| (i % 239) as u8).collect();
    let mut late = upload(&d, first, &restream);
    late.digest = sentinel_cache::remote::DIGEST_AT_END;
    let stored = remote
        .offer(
            &late,
            Instant::now() + Duration::from_secs(20),
            &mut Cursor::new(restream.clone()),
        )
        .expect("a digest-at-end offer is stored");
    assert_eq!(stored, *blake3::hash(&restream).as_bytes());
    let mut refetched = Collect::default();
    remote
        .fetch(
            &need(&late, second),
            Instant::now() + Duration::from_secs(20),
            &mut refetched,
        )
        .unwrap();
    assert_eq!(refetched.bytes, restream);
    assert_eq!(refetched.grant.unwrap().digest, stored);
    let _ = JobId::new();
}

/// P07-6: the profile opens with the executor's measured availability —
/// not an empty placeholder — and a protocol-8 session refreshes it when
/// the executor's version moves; placement reads it from the worker row.
#[test]
fn the_profile_carries_and_refreshes_measured_availability() {
    let d = deployment();
    let (holder, _offers) = Holder::new();
    *holder.availability.lock().unwrap() = Some((
        1,
        Availability {
            images: vec![[0xaa; 8]],
            cache_bytes: 4096,
            load_ns: 0,
        },
    ));
    let id = WorkerId::new();
    let _worker = WorkerProcess::start(&d, id, Arc::clone(&holder));
    let row = |store: &Store| -> (Vec<u8>, i64) {
        store
            .read(|c| {
                Ok(c.query_row(
                    "SELECT avail_images, cache_bytes FROM workers WHERE id = ?1",
                    [id.as_bytes()],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )?)
            })
            .unwrap_or_default()
    };
    eventually("the opening profile", || row(&d.store).0 == vec![0xaa; 8]);
    assert_eq!(row(&d.store).1, 4096);
    *holder.availability.lock().unwrap() = Some((
        2,
        Availability {
            images: vec![[0xbb; 8], [0xaa; 8]],
            cache_bytes: 8192,
            load_ns: 0,
        },
    ));
    eventually("the refreshed profile", || {
        let (images, bytes) = row(&d.store);
        images.len() == 16 && bytes == 8192
    });
    let _ = &d.dir;
}
