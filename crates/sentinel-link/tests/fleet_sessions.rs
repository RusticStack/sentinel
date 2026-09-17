//! Q09: one hundred concurrent worker sessions over real TLS against a real
//! `Controller`, each ending in a simulated executor.
//!
//! What this covers is the link and the scheduler at fleet scale: one hundred
//! mutual-TLS handshakes, admission, fleet bookkeeping, profile reporting,
//! heartbeat renewal and placement of a burst that exactly fills every
//! session. The executors are simulations — they acknowledge offers and hold
//! attempts, and no container, checkout or step ever runs, so this is TLS
//! and scheduler evidence, not executor evidence.

use std::{
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicI64, Ordering},
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
    Error,
    controller::Controller,
    identity::Identity,
    session::{self, Capacity, Executor, Offer},
    tls,
};
use sentinel_pipeline::{PinnedSource, RunSpec, compile_str};
use sentinel_protocol::negotiate::{Arch, Capabilities, Hello, Profile, ProtocolVersion};
use sentinel_store::{
    Durability, Store,
    auth::{self, Authority, NamespaceKind, provisioning},
    runs,
    tenancy::{self, PoolKind},
    workers,
};

const SESSIONS: usize = 100;
/// Each session takes exactly two quarter-core jobs: the burst is sized so
/// a hundred healthy sessions all receive work and none is oversubscribed.
const JOBS: usize = 200;
const JOBS_PER_RUN: usize = 50;
const RUNS: usize = JOBS / JOBS_PER_RUN;
const SHA: &str = "0123456789abcdef0123456789abcdef01234567";
const DIGEST: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

/// A session that reports its disk and its own host, so host-scoped
/// accounting never aggregates two simulated machines into one.
fn profile(index: usize) -> Profile {
    let mut host_id = [0u8; 16];
    host_id[..4].copy_from_slice(&(index as u32).to_be_bytes());
    Profile {
        host_id,
        disk_bytes: 64 << 30,
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

fn capacity() -> Capacity {
    Capacity {
        cpu_millis: 500,
        memory_bytes: 1 << 30,
    }
}

fn jobs_yaml() -> String {
    let mut yaml = String::from("schema: 1\non: [push]\njobs:\n");
    for i in 0..JOBS_PER_RUN {
        yaml.push_str(&format!(
            "  j{i:03}:\n    image: alpine:3\n    resources: {{ cpu: \"0.25\", memory: 128MiB, disk: 1GiB }}\n    steps: [{{ id: s, run: 'true' }}]\n"
        ));
    }
    yaml
}

struct Deployment {
    _dir: tempfile::TempDir,
    store: Arc<Store>,
    /// Held for the controller's lifetime; the test reads the store.
    _logs: Arc<sentinel_store::logs::LogStore>,
    _objects: Arc<sentinel_store::objects::Objects>,
    controller: Option<Controller>,
    _identity_files: (PathBuf, PathBuf),
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
                PoolKind::Dedicated(tenant),
                UnixMillis(1),
            )
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
        tenant,
        repo,
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

    /// Create the burst: several runs because a pipeline is capped at 64 jobs.
    fn run(&self) -> Vec<JobId> {
        let (tenant, repo) = (self.tenant, self.repo);
        let spec = RunSpec::new(
            PinnedSource::new("https://github.com/o/r.git", SHA, Some("refs/heads/main")).unwrap(),
            compile_str(&jobs_yaml()).unwrap(),
        )
        .unwrap();
        let ids = self
            .store
            .writer()
            .write(move |tx| {
                let mut ids = Vec::with_capacity(JOBS);
                for _ in 0..RUNS {
                    let run_ids =
                        runs::create_run(tx, tenant, repo, RunId::new(), &spec, UnixMillis::now())?;
                    for job in &run_ids {
                        runs::resolve_image(tx, tenant, *job, DIGEST, "linux/amd64")?;
                    }
                    ids.extend(run_ids);
                }
                Ok(ids)
            })
            .unwrap();
        self.controller().wake();
        ids
    }
}

/// A simulated executor: acknowledges every offer, holds the attempt, and
/// never runs anything.
struct Sim {
    held: Mutex<Vec<AttemptId>>,
    jobs: Mutex<Vec<JobId>>,
    offers: Mutex<Vec<Offer>>,
    renewed: AtomicI64,
}

impl Sim {
    fn new() -> Arc<Sim> {
        Arc::new(Sim {
            held: Mutex::new(Vec::new()),
            jobs: Mutex::new(Vec::new()),
            offers: Mutex::new(Vec::new()),
            renewed: AtomicI64::new(0),
        })
    }
}

impl Executor for Sim {
    fn offered(&self, offer: &Offer) -> bool {
        self.held.lock().unwrap().push(offer.attempt);
        self.jobs.lock().unwrap().push(offer.job);
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
        self.renewed.store(until.0, Ordering::SeqCst);
    }
    fn attached(&self, _: session::Reporter) {}
    fn detached(&self) {}
    fn spec(&self, _: AttemptId, _: session::JobContext, _: Vec<u8>) {}
    fn no_spec(&self, _: AttemptId) {}
    fn log_acked(&self, _: AttemptId, _: u64) {}
    fn log_refused(&self, _: AttemptId) {}
}

/// Wait until `predicate` holds, within `within`.
fn eventually(what: &str, within: Duration, mut predicate: impl FnMut() -> bool) {
    let deadline = Instant::now() + within;
    while !predicate() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn one_hundred_sessions_connect_and_take_their_share_of_the_burst() {
    let mut d = deployment();
    let stop = Arc::new(AtomicBool::new(false));
    let enrollments: Vec<Secret> = (0..SESSIONS).map(|_| d.enrollment()).collect();
    let mut sims: Vec<Arc<Sim>> = Vec::with_capacity(SESSIONS);
    let mut ids: Vec<WorkerId> = Vec::with_capacity(SESSIONS);
    let mut threads = Vec::with_capacity(SESSIONS);
    let addr = d.controller().local_addr();
    let fingerprint = d.controller().fingerprint();
    let connected_at = Instant::now();
    for (index, secret) in enrollments.into_iter().enumerate() {
        let id = WorkerId::new();
        let sim = Sim::new();
        ids.push(id);
        sims.push(Arc::clone(&sim));
        let stop = Arc::clone(&stop);
        threads.push(thread::spawn(move || -> Result<(), Error> {
            let identity = Identity::generate(&format!("session-{index}")).unwrap();
            let config = tls::client_config(identity, fingerprint).unwrap();
            let mut link = session::connect(
                addr,
                config,
                id,
                "fleet",
                hello(),
                Some(&secret),
                capacity(),
            )?;
            // Protocol 7: the profile carries what a hello cannot.
            link.send_profile(&profile(index))?;
            link.run(&*sim, || stop.load(Ordering::Relaxed))
        }));
    }

    eventually(
        "one hundred admitted sessions",
        Duration::from_secs(30),
        || d.controller().connected().len() == SESSIONS,
    );
    assert!(
        connected_at.elapsed() < Duration::from_secs(30),
        "a hundred handshakes took {:?}",
        connected_at.elapsed()
    );
    assert_eq!(
        d.controller().stats().admitted.load(Ordering::SeqCst),
        SESSIONS as u64
    );
    assert_eq!(d.controller().stats().rejected.load(Ordering::SeqCst), 0);
    let mut live = d.controller().connected();
    live.sort();
    ids.sort();
    assert_eq!(live, ids, "every enrolled identity holds a session");

    // The burst exactly fills every session: 500 millicpu each against 200
    // quarter-core jobs means two jobs per session, no session idle and no
    // session oversubscribed.
    let jobs = d.run();
    assert_eq!(jobs.len(), JOBS);
    eventually("every job acknowledged", Duration::from_secs(30), || {
        d.controller().stats().acknowledged.load(Ordering::SeqCst) == JOBS as u64
    });
    assert_eq!(
        d.controller().stats().offers.load(Ordering::SeqCst),
        JOBS as u64
    );
    for sim in &sims {
        assert_eq!(sim.jobs.lock().unwrap().len(), 2);
        assert_eq!(sim.held.lock().unwrap().len(), 2);
    }

    // No attempt or job reached two sessions: at this scale a retransmit or
    // a stale fleet entry must never become duplicate execution.
    let mut attempts = std::collections::HashSet::new();
    let mut placed_jobs = std::collections::HashSet::new();
    for sim in &sims {
        for offer in sim.offers.lock().unwrap().iter() {
            assert!(attempts.insert(offer.attempt), "attempt offered twice");
            assert!(placed_jobs.insert(offer.job), "job offered twice");
        }
    }
    assert_eq!(placed_jobs.len(), JOBS);

    // The sessions are still alive under load: every one answers a fresh
    // heartbeat after this point, renewing its lease.
    let renewals: Vec<i64> = sims
        .iter()
        .map(|s| s.renewed.load(Ordering::SeqCst))
        .collect();
    eventually(
        "a fresh heartbeat on every session",
        Duration::from_secs(15),
        || {
            sims.iter()
                .zip(&renewals)
                .all(|(sim, before)| sim.renewed.load(Ordering::SeqCst) > *before)
        },
    );

    // A clean stop closes every session and leaves an empty fleet.
    stop.store(true, Ordering::Relaxed);
    for (index, thread) in threads.into_iter().enumerate() {
        thread.join().unwrap().unwrap_or_else(|error| {
            panic!("session {index} ended badly: {error:?}");
        });
    }
    eventually("an empty fleet", Duration::from_secs(15), || {
        d.controller().connected().is_empty()
    });
    assert_eq!(
        d.controller().stats().sessions_ended.load(Ordering::SeqCst),
        SESSIONS as u64
    );
    assert!(
        d.controller
            .take()
            .unwrap()
            .shutdown(Duration::from_secs(10))
    );
}
