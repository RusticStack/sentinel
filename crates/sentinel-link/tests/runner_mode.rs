//! Runner mode end to end on the link: a queued GitHub job becomes demand, the scheduler leases a
//! worker's capacity for it, the configuration is made through the App and delivered once, and a
//! runner nobody handed work to is de-registered and stopped at its bound.
//!
//! GitHub is a recorded fake on loopback; the worker is a real session process in this test.

use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use sentinel_auth::sealed::Key;
use sentinel_auth::secret::Secret;
use sentinel_core::{
    AttemptId, PoolId, RepoId, RunnerClass, TenantId, UnixMillis, UserId, WorkerId,
    auth::{Namespace, Permissions as P, Principal},
};
use sentinel_link::{
    Error,
    controller::Controller,
    identity::Identity,
    runner::Policy,
    session::{self, ArtifactCode, Capacity, Executor, Offer, RunnerLeaseWire},
    worker,
};
use sentinel_protocol::{
    negotiate::{Arch, Capabilities, Hello, Profile, ProtocolVersion},
    source::{Binding, Credential},
};
use sentinel_store::{
    Durability, Store,
    auth::{self, Authority, NamespaceKind, provisioning},
    registration,
    sources::{self, Update},
    sources_forge, tenancy, workers,
};

const CLASS: &str = "sentinel-4vcpu-ubuntu-2404";
const REMOTE: &str = "https://github.com/acme/app.git";

fn at(ms: i64) -> UnixMillis {
    UnixMillis(ms)
}

// ---------------------------------------------------------------- GitHub, recorded

struct Github {
    addr: SocketAddr,
    data: Arc<Mutex<Scripted>>,
    stop: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}

#[derive(Default)]
struct Scripted {
    /// What the fake GitHub puts in the configuration it issues, when set.
    canary: Option<String>,
    requests: Vec<(String, String, String)>,
    queued_runs: Vec<serde_json::Value>,
    queued_jobs: Vec<serde_json::Value>,
    generated: AtomicUsize,
    removed: AtomicUsize,
}

impl Github {
    fn start() -> Github {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let addr = listener.local_addr().unwrap();
        let data = Arc::new(Mutex::new(Scripted::default()));
        let stop = Arc::new(AtomicBool::new(false));
        let thread = {
            let (data, stop) = (Arc::clone(&data), Arc::clone(&stop));
            thread::spawn(move || {
                while !stop.load(Ordering::Acquire) {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            let _ = stream.set_nonblocking(false);
                            let data = Arc::clone(&data);
                            thread::spawn(move || serve(stream, &data));
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(5));
                        }
                        Err(_) => break,
                    }
                }
            })
        };
        Github {
            addr,
            data,
            stop,
            thread: Some(thread),
        }
    }

    fn endpoint(&self) -> String {
        format!("http://{}", self.addr)
    }

    fn generated(&self) -> usize {
        self.data.lock().unwrap().generated.load(Ordering::SeqCst)
    }

    fn removed(&self) -> usize {
        self.data.lock().unwrap().removed.load(Ordering::SeqCst)
    }

    /// Every request the fake GitHub was asked, in order.
    fn requests(&self) -> Vec<(String, String, String)> {
        self.data.lock().unwrap().requests.clone()
    }

    /// Issues a configuration containing `canary`, the way a real one carries a token.
    fn with_canary(&self, canary: &str) {
        self.data.lock().unwrap().canary = Some(canary.to_owned());
    }

    fn queue(&self, runs: Vec<serde_json::Value>, jobs: Vec<serde_json::Value>) {
        let mut data = self.data.lock().unwrap();
        data.queued_runs = runs;
        data.queued_jobs = jobs;
    }
}

impl Drop for Github {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn serve(mut stream: TcpStream, data: &Arc<Mutex<Scripted>>) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(30)));
    loop {
        let Some((method, path, _body)) = read_request(&mut stream) else {
            return;
        };
        let (status, reply) = answer(data, &method, &path);
        let text = if status == 204 {
            String::new()
        } else {
            reply.to_string()
        };
        let response = format!(
            "HTTP/1.1 {status} X\r\ncontent-length: {}\r\ncontent-type: application/json\r\nconnection: keep-alive\r\n\r\n",
            text.len()
        );
        if stream.write_all(response.as_bytes()).is_err()
            || stream.write_all(text.as_bytes()).is_err()
        {
            return;
        }
    }
}

fn answer(data: &Arc<Mutex<Scripted>>, method: &str, path: &str) -> (u16, serde_json::Value) {
    let mut data = data.lock().unwrap();
    data.requests
        .push((method.to_owned(), path.to_owned(), String::new()));
    if method == "GET" && path.starts_with("/app/installations/") {
        return (
            200,
            serde_json::json!({
                "id": 7,
                "app_id": 1,
                "suspended_at": null,
                "account": {"id": 73, "login": "acme", "type": "Organization"},
                "permissions": {
                    "contents": "read",
                    "checks": "write",
                    "actions": "read",
                    "organization_self_hosted_runners": "write",
                },
            }),
        );
    }
    if method == "POST" && path.ends_with("/access_tokens") {
        let expiry = (time::OffsetDateTime::now_utc() + time::Duration::minutes(55))
            .format(&time::format_description::well_known::Rfc3339)
            .expect("expiry");
        return (
            201,
            serde_json::json!({
                "token": "ghs_runner_token",
                "expires_at": expiry,
                "permissions": {
                    "organization_self_hosted_runners": "write",
                    "metadata": "read",
                },
            }),
        );
    }
    if method == "GET" && path.starts_with("/repositories/") {
        return (
            200,
            serde_json::json!({"id": 42, "owner": {"id": 73}, "clone_url": REMOTE}),
        );
    }
    if method == "POST" && path.ends_with("/actions/runners/generate-jitconfig") {
        let serial = data.generated.fetch_add(1, Ordering::SeqCst) + 1;
        return (
            201,
            serde_json::json!({
                "runner": {"id": 90 + serial},
                "encoded_jit_config": match &data.canary {
                    Some(canary) => canary.clone(),
                    None => format!("jit-config-{serial}"),
                },
            }),
        );
    }
    if method == "DELETE" && path.contains("/actions/runners/") {
        data.removed.fetch_add(1, Ordering::SeqCst);
        return (204, serde_json::Value::Null);
    }
    if method == "GET" && path.starts_with("/repos/acme/app/actions/runs?") {
        return (
            200,
            serde_json::json!({"total_count": data.queued_runs.len(), "workflow_runs": data.queued_runs}),
        );
    }
    if method == "GET" && path.contains("/jobs?filter=queued") {
        return (
            200,
            serde_json::json!({"total_count": data.queued_jobs.len(), "jobs": data.queued_jobs}),
        );
    }
    (404, serde_json::json!({"message": "Not Found"}))
}

fn read_request(stream: &mut TcpStream) -> Option<(String, String, String)> {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => return None,
            Ok(n) => buffer.extend_from_slice(&chunk[..n]),
        }
        if buffer.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }
    let text = String::from_utf8_lossy(&buffer).to_string();
    let (head, rest) = text.split_once("\r\n\r\n")?;
    let mut lines = head.lines();
    let mut parts = lines.next()?.split(' ');
    let method = parts.next()?.to_owned();
    let path = parts.next()?.to_owned();
    let length = lines
        .filter_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().ok())
                .flatten()
        })
        .next()
        .unwrap_or(0);
    let mut body = rest.as_bytes()[..rest.len().min(length)].to_vec();
    while body.len() < length {
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => body.extend_from_slice(&chunk[..n]),
        }
    }
    Some((method, path, String::from_utf8_lossy(&body).to_string()))
}

// ---------------------------------------------------------------- Sentinel, seeded

struct Deployment {
    _dir: tempfile::TempDir,
    store: Arc<Store>,
    controller: Controller,
    _files: (PathBuf, PathBuf),
    tenant: TenantId,
    repo: RepoId,
    pool: PoolId,
    github: Github,
}

fn test_key() -> &'static str {
    static KEY: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    KEY.get_or_init(|| {
        let out = std::process::Command::new("openssl")
            .args([
                "genpkey",
                "-algorithm",
                "RSA",
                "-pkeyopt",
                "rsa_keygen_bits:2048",
            ])
            .output()
            .expect("the openssl CLI must be installed to generate the test-only App key");
        assert!(out.status.success(), "openssl genpkey failed");
        String::from_utf8(out.stdout).expect("PEM is ASCII")
    })
}

fn deployment(github: Github) -> Deployment {
    let dir = tempfile::tempdir().unwrap();
    let store =
        Arc::new(Store::open(dir.path().join("metadata.sqlite"), Durability::Normal).unwrap());
    let (root, tenant, repo, pool) = (UserId::new(), TenantId::new(), RepoId::new(), PoolId::new());
    let key_path = dir.path().join("master.key");
    Key::create(&key_path).unwrap();
    let key = Arc::new(Key::load(&key_path).unwrap());
    store
        .writer()
        .write({
            let key = Arc::clone(&key);
            move |tx| {
                provisioning::insert_human(tx, root, "Root", true, at(1))?;
                auth::create_namespace(
                    tx,
                    Principal::new(root, P::ALL, None, None),
                    tenant,
                    Namespace::parse("acme").unwrap(),
                    NamespaceKind::Organization,
                    at(1),
                )?;
                sentinel_store::jobs::insert_repo(tx, tenant, repo, "app", at(1))?;
                tenancy::create_pool(
                    tx,
                    Authority::HostLocal,
                    pool,
                    "farm",
                    tenancy::PoolKind::Shared,
                    at(1),
                )?;
                tenancy::grant_pool(tx, Authority::HostLocal, pool, tenant, at(1))?;
                let installation = sources_forge::refresh(
                    tx,
                    sources_forge::Snapshot {
                        external_id: 7,
                        account_id: 73,
                        login: "acme",
                        personal: false,
                        suspended: false,
                        permissions_valid: true,
                        runner: sentinel_core::RunnerPermissions::ALL,
                        migration: sentinel_core::MigrationPermissions::ALL,
                        expected: 0,
                    },
                    at(1),
                )?;
                registration::bind_installation_trusted(tx, installation, tenant, at(1))?;
                let binding = Binding {
                    remote: REMOTE.into(),
                    allowed_refs: vec!["refs/heads/main".into()],
                    pipeline_path: ".sentinel.yml".into(),
                    trust: String::new(),
                };
                sources::bind(
                    tx,
                    Authority::HostLocal,
                    Some(root),
                    Update {
                        repo,
                        expected: 0,
                        binding: &binding,
                        credential: &Credential::Public,
                        forge: Some((installation, 42)),
                    },
                    &["https://github.com".into()],
                    &key,
                    at(1),
                )?;
                tx.execute(
                    "UPDATE tenants SET runner_mode = 1 WHERE id = ?1",
                    [tenant.as_bytes()],
                )?;
                Ok(())
            }
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
        logs,
        objects,
        identity,
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    let app = sentinel_github::app::App::new(1, test_key())
        .unwrap()
        .with_endpoint(&github.endpoint())
        .unwrap();
    controller.set_source_app(Arc::new(app));
    controller.set_source_key(key);
    Deployment {
        _dir: dir,
        store,
        controller,
        _files: files,
        tenant,
        repo,
        pool,
        github,
    }
}

impl Deployment {
    fn serve(&self, idle_ms: i64, reconcile_ms: i64) {
        self.controller.set_runner_policy(Policy {
            classes: Arc::from(vec![RunnerClass::parse(CLASS).unwrap()]),
            runner_group: 3,
            idle_ms,
            reconcile_ms,
        });
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

    fn queued(&self, job: u64) {
        let (tenant, repo) = (self.tenant, self.repo);
        self.store
            .writer()
            .write(move |tx| {
                sentinel_store::runner_provision::observe(
                    tx,
                    tenant,
                    repo,
                    job,
                    job + 1_000,
                    CLASS,
                    UnixMillis::now(),
                )
            })
            .unwrap();
    }

    fn observer(&self) -> impl Fn(u64) -> bool + '_ {
        let store = Arc::clone(&self.store);
        let (tenant, repo) = (self.tenant, self.repo);
        move |job| {
            store
                .read(move |c| sentinel_store::runner::job(c, tenant, repo, job))
                .unwrap()
                .is_some()
        }
    }
}

// ---------------------------------------------------------------- the worker

struct Runners {
    offers: Mutex<Vec<RunnerLeaseWire>>,
    configs: Mutex<Vec<([u8; 16], Vec<u8>)>>,
    stopped: Mutex<Vec<[u8; 16]>>,
    held: Mutex<Vec<[u8; 16]>>,
    /// Any pipeline-secret bundle that reached this worker, which runner mode never sends.
    bundles: AtomicUsize,
    reporter: Mutex<Option<session::Reporter>>,
    /// What the controller answered about a runner-mode artifact, in arrival order.
    verdicts: Mutex<Vec<([u8; 16], ArtifactCode)>>,
    /// The repositories the controller asked this worker to give up its runner-mode caches for.
    evicted: Mutex<Vec<[u8; 16]>>,
}

impl Runners {
    fn new() -> Arc<Runners> {
        Arc::new(Runners {
            offers: Mutex::new(Vec::new()),
            configs: Mutex::new(Vec::new()),
            stopped: Mutex::new(Vec::new()),
            held: Mutex::new(Vec::new()),
            bundles: AtomicUsize::new(0),
            reporter: Mutex::new(None),
            verdicts: Mutex::new(Vec::new()),
            evicted: Mutex::new(Vec::new()),
        })
    }

    fn offers(&self) -> Vec<RunnerLeaseWire> {
        self.offers.lock().unwrap().clone()
    }

    fn configs(&self) -> Vec<([u8; 16], Vec<u8>)> {
        self.configs.lock().unwrap().clone()
    }

    fn stopped(&self) -> Vec<[u8; 16]> {
        self.stopped.lock().unwrap().clone()
    }

    fn bundles(&self) -> usize {
        self.bundles.load(Ordering::SeqCst)
    }

    fn verdicts(&self) -> Vec<([u8; 16], ArtifactCode)> {
        self.verdicts.lock().unwrap().clone()
    }

    fn evicted(&self) -> Vec<[u8; 16]> {
        self.evicted.lock().unwrap().clone()
    }
}

impl Executor for Runners {
    fn runner_offered(&self, lease: &RunnerLeaseWire) -> bool {
        self.offers.lock().unwrap().push(lease.clone());
        self.held.lock().unwrap().push(lease.lease);
        true
    }
    fn runner_config(&self, lease: [u8; 16], config: Vec<u8>) {
        self.configs.lock().unwrap().push((lease, config));
    }
    fn runner_stopped(&self, lease: [u8; 16]) {
        self.stopped.lock().unwrap().push(lease);
        self.held.lock().unwrap().retain(|l| *l != lease);
    }
    fn runner_held(&self) -> Vec<[u8; 16]> {
        self.held.lock().unwrap().clone()
    }
    fn offered(&self, _: &Offer) -> bool {
        false
    }
    fn stop(&self, _: AttemptId) {}
    fn cancel(&self, _: AttemptId) {}
    fn held(&self) -> Vec<AttemptId> {
        Vec::new()
    }
    fn renewed(&self, _: UnixMillis) {}
    fn actions_cache_evict(&self, repos: &[[u8; 16]]) {
        self.evicted.lock().unwrap().extend_from_slice(repos);
    }
    fn runner_artifact_answered(&self, lease: [u8; 16], _name: &str, code: ArtifactCode) {
        self.verdicts.lock().unwrap().push((lease, code));
    }
    fn attached(&self, reporter: session::Reporter) {
        *self.reporter.lock().unwrap() = Some(reporter);
    }
    fn detached(&self) {
        self.reporter.lock().unwrap().take();
    }
    fn spec(&self, _: AttemptId, _: session::JobContext, _: Vec<u8>) {}
    fn spec_with_secrets(
        &self,
        _: AttemptId,
        _: session::JobContext,
        _: Vec<u8>,
        secrets: sentinel_protocol::secrets::DeliveryBundle,
    ) {
        if !secrets.is_empty() {
            self.bundles.fetch_add(1, Ordering::SeqCst);
        }
    }
    fn no_spec(&self, _: AttemptId) {}
    fn log_acked(&self, _: AttemptId, _: u64) {}
    fn log_refused(&self, _: AttemptId) {}
}

struct WorkerProcess {
    id: WorkerId,
    handle: Arc<worker::Handle>,
    events: Arc<Mutex<Vec<String>>>,
    thread: Option<thread::JoinHandle<Result<(), Error>>>,
}

impl WorkerProcess {
    fn start(d: &Deployment, executor: Arc<Runners>, labels: &[&str]) -> WorkerProcess {
        let handle = Arc::new(worker::Handle::new());
        let id = WorkerId::new();
        let profile = Profile {
            labels: labels.iter().map(|l| (*l).to_owned()).collect(),
            ..Profile::default()
        };
        let config = worker::Config {
            controller: d.controller.local_addr(),
            server: d.controller.fingerprint(),
            also_pinned: Vec::new(),
            worker: id,
            name: "builder".into(),
            hello: Hello {
                protocol_min: ProtocolVersion(1),
                protocol_max: ProtocolVersion(19),
                capabilities: Capabilities::REQUIRED,
                arch: Arch::X86_64,
                software: "runner".into(),
            },
            capacity: Capacity {
                cpu_millis: 16_000,
                memory_bytes: 64 << 30,
            },
            profile,
            transport: Default::default(),
            remote_cache: false,
        };
        let enrollment = d.enrollment();
        let grip = Arc::clone(&handle);
        let events = Arc::new(Mutex::new(Vec::new()));
        let log = Arc::clone(&events);
        let thread = thread::spawn(move || {
            worker::run(
                config,
                Identity::generate("builder").unwrap(),
                Some(enrollment),
                &*executor,
                &grip,
                &|event| log.lock().unwrap().push(format!("{event:?}")),
            )
        });
        WorkerProcess {
            id,
            handle,
            events,
            thread: Some(thread),
        }
    }

    fn stop(mut self) {
        self.handle.stop();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// The worker has run a lease of the repository, which is what lets its cache report charge the tenant.
fn served(d: &Deployment, worker: WorkerId) {
    let (tenant, repo, pool) = (d.tenant, d.repo, d.pool);
    d.store
        .writer()
        .write(move |tx| {
            tx.execute(
                "INSERT INTO runner_leases(id, tenant_id, repo_id, class, pool_id, worker_id, fence,
                    state_code, cpu_millis, memory_bytes, runner_name, offered_ms, lease_until_ms,
                    released_ms, reason)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, 1, 2, 4000, 8589934592, 'sentinel-cache-1', ?7, ?7,
                    ?7, 'job_completed')",
                rusqlite::params![
                    sentinel_core::RunnerLeaseId::new().as_bytes(),
                    tenant.as_bytes(),
                    repo.as_bytes(),
                    CLASS,
                    pool.as_bytes(),
                    worker.as_bytes(),
                    UnixMillis::now().0
                ],
            )?;
            Ok(())
        })
        .unwrap();
}

/// A tenant quota of 100 bytes whose hard threshold is the quota itself.
fn quota_of_100(d: &Deployment) {
    let tenant = d.tenant;
    d.store
        .writer()
        .write(move |tx| {
            tx.execute(
                "INSERT INTO storage_policies(tenant_id, repo_id, quota_bytes, soft_percent,
                    hard_percent, updated_ms) VALUES(?1, X'', 100, 80, 100, ?2)",
                rusqlite::params![tenant.as_bytes(), UnixMillis::now().0],
            )?;
            Ok(())
        })
        .unwrap();
}

fn charged(d: &Deployment, bytes: u64) {
    let tenant = d.tenant;
    eventually("charged", || {
        d.store
            .read(move |c| sentinel_store::classes::tenant(c, tenant))
            .is_ok_and(|classes| classes.actions_cache == bytes)
    });
}

fn attach(d: &Deployment) -> (Arc<Runners>, session::Reporter, WorkerProcess) {
    let runners = Runners::new();
    let process = WorkerProcess::start(d, Arc::clone(&runners), &[CLASS]);
    eventually("connected", || runners.reporter.lock().unwrap().is_some());
    let reporter = runners.reporter.lock().unwrap().clone().expect("session");
    (runners, reporter, process)
}

#[test]
fn an_idle_worker_holding_the_tenants_cache_is_asked_to_give_it_up_at_the_hard_threshold() {
    let github = Github::start();
    let d = deployment(github);
    d.serve(120_000, 60_000);
    let (idle, idle_reporter, idle_process) = attach(&d);
    let (busy, busy_reporter, busy_process) = attach(&d);
    served(&d, idle_process.id);
    served(&d, busy_process.id);
    quota_of_100(&d);

    // The idle host's bytes alone are under the line: nothing gives way.
    idle_reporter.actions_cache(&[(d.repo, 60)]).unwrap();
    charged(&d, 60);
    assert!(
        idle.evicted().is_empty(),
        "nothing gives way below the line"
    );

    // Another host's report takes the tenant past it. The idle host sends nothing further on its own, so it
    // is the controller that must ask it.
    busy_reporter.actions_cache(&[(d.repo, 60)]).unwrap();
    charged(&d, 120);
    eventually("the reporter evicted", || {
        busy.evicted() == vec![*d.repo.as_bytes()]
    });
    eventually("the idle host evicted", || {
        idle.evicted() == vec![*d.repo.as_bytes()]
    });
    idle_process.stop();
    busy_process.stop();
}

#[test]
fn an_upload_refused_at_the_hard_threshold_makes_the_tenants_caches_give_way() {
    let github = Github::start();
    let d = deployment(github);
    d.serve(120_000, 60_000);
    let (runners, reporter, process) = attach(&d);
    served(&d, process.id);
    quota_of_100(&d);
    reporter.actions_cache(&[(d.repo, 60)]).unwrap();
    charged(&d, 60);
    let handle = d.controller.handle();

    // An upload that would still fit under the line asks nothing of the caches.
    handle.upload_refused(d.tenant, 40);
    thread::sleep(Duration::from_millis(200));
    assert!(
        runners.evicted().is_empty(),
        "a fitting upload evicts nothing"
    );

    // One that would pass it was refused because of what the caches hold: they give way first.
    handle.upload_refused(d.tenant, 41);
    eventually("evicted", || runners.evicted() == vec![*d.repo.as_bytes()]);
    process.stop();
}

fn eventually(what: &str, mut predicate: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(60);
    while !predicate() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        thread::sleep(Duration::from_millis(20));
    }
}

/// The gate: a burst of queued jobs gets one runner each, and each one's configuration is asked of
/// GitHub exactly once, delivered once, and never written anywhere the worker could not read it.
#[test]
fn a_burst_of_queued_jobs_gets_one_runner_each() {
    let github = Github::start();
    let d = deployment(github);
    d.serve(120_000, 60_000);
    let workers: Vec<(Arc<Runners>, WorkerProcess)> = (0..3)
        .map(|_| {
            let runners = Runners::new();
            let process = WorkerProcess::start(&d, Arc::clone(&runners), &[CLASS]);
            (runners, process)
        })
        .collect();
    for job in 1..=3 {
        d.queued(job);
    }
    eventually("every worker connected", || {
        workers
            .iter()
            .all(|(_, process)| !process.events.lock().unwrap().is_empty())
    });
    // Three queued jobs, three runners — one each, wherever the fleet puts them: a worker with the
    // room may host several, which is what its capacity says and what the store's own test holds to.
    eventually("a runner for each queued job", || {
        workers.iter().map(|(r, _)| r.offers().len()).sum::<usize>() == 3
    });
    eventually("a configuration for each of them", || {
        workers
            .iter()
            .map(|(r, _)| r.configs().len())
            .sum::<usize>()
            == 3
    });
    assert_eq!(d.github.generated(), 3, "one JIT configuration per runner");
    let mut names: Vec<[u8; 16]> = workers
        .iter()
        .flat_map(|(r, _)| r.offers().into_iter().map(|lease| lease.lease))
        .collect();
    names.sort_unstable();
    names.dedup();
    assert_eq!(names.len(), 3, "three different runners, one lease each");
    let classes: Vec<String> = workers
        .iter()
        .flat_map(|(r, _)| r.offers().into_iter().map(|lease| lease.class))
        .collect();
    assert!(classes.iter().all(|class| class == CLASS));
    // A fourth runner: the three queued jobs are covered, so nothing more is placed.
    thread::sleep(Duration::from_secs(2));
    assert_eq!(d.github.generated(), 3, "demand is covered");
    for (_, process) in workers {
        process.stop();
    }
}

/// A `queued` delivery that never arrived is recovered by the reconciliation pass, from the queue
/// GitHub states.
#[test]
fn a_lost_queued_event_is_recovered_by_reconciliation() {
    let github = Github::start();
    github.queue(
        vec![serde_json::json!({"id": 900})],
        vec![
            serde_json::json!({"id": 51, "run_id": 900, "labels": [CLASS]}),
            serde_json::json!({"id": 52, "run_id": 900, "labels": ["ubuntu-latest"]}),
        ],
    );
    let d = deployment(github);
    d.serve(120_000, 1_000);
    let runners = Runners::new();
    let process = WorkerProcess::start(&d, Arc::clone(&runners), &[CLASS]);
    eventually("the queued job GitHub states is recorded", || {
        d.observer()(51)
    });
    // The other job names no Sentinel class and stays where it is.
    thread::sleep(Duration::from_millis(200));
    assert!(!d.observer()(52));
    eventually("the recovered job is placed", || {
        !runners.offers().is_empty()
    });
    process.stop();
}

/// No runner outlives its bound idle: a lease no job took is released, its registration removed at
/// GitHub, and its worker told to stop.
#[test]
fn an_idle_runner_is_stopped_and_de_registered_at_its_bound() {
    let github = Github::start();
    let d = deployment(github);
    d.serve(1_500, 60_000);
    let runners = Runners::new();
    let process = WorkerProcess::start(&d, Arc::clone(&runners), &[CLASS]);
    d.queued(7);
    eventually("the lease is held and configured", || {
        runners.configs().len() == 1
    });
    eventually("the runner is de-registered", || d.github.removed() >= 1);
    eventually("the worker is told to stop", || {
        !runners.stopped().is_empty()
    });
    assert!(runners.held().is_empty());
    process.stop();
}

/// A worker that does not name the class is never offered one, and the job stays demand for a
/// worker that does.
#[test]
fn a_worker_without_the_class_label_is_never_given_a_runner() {
    let github = Github::start();
    let d = deployment(github);
    d.serve(120_000, 60_000);
    let plain = Runners::new();
    let plain_process = WorkerProcess::start(&d, Arc::clone(&plain), &["egress"]);
    d.queued(9);
    thread::sleep(Duration::from_secs(2));
    assert!(plain.offers().is_empty());
    assert_eq!(d.github.generated(), 0);
    plain_process.stop();
}

/// The configuration is a credential: it travels once, and a lease that already took it is never
/// sent it again even after the worker reconnects.
#[test]
fn a_configuration_is_delivered_once_and_never_again() {
    let github = Github::start();
    let d = deployment(github);
    d.serve(120_000, 60_000);
    let runners = Runners::new();
    let process = WorkerProcess::start(&d, Arc::clone(&runners), &[CLASS]);
    d.queued(11);
    eventually("one configuration", || runners.configs().len() == 1);
    assert_eq!(d.github.generated(), 1);
    // The lease the worker lost is stopped when its session ends, and no second configuration is
    // asked for while the first one is still bound to that runner.
    thread::sleep(Duration::from_secs(1));
    assert_eq!(runners.configs().len(), 1);
    process.stop();
    eventually("the session's runner is released", || {
        d.store
            .read(move |c| {
                sentinel_store::runner_provision::live(c, d.tenant, d.repo).map(|l| l.is_empty())
            })
            .unwrap()
    });
    assert_eq!(d.github.generated(), 1);
    assert!(d.github.removed() >= 1, "and its registration goes with it");
}

/// What a sandbox's `upload-artifact` sealed is the tenant's artifact: published under the boundary its
/// lease named, it is one row of the GitHub run and job, with the store's own bytes, charged against the
/// repository and tenant, and it refuses a name the job already holds rather than storing it twice.
#[test]
fn a_runner_artifact_is_published_into_the_tenants_store_under_its_github_job() {
    let github = Github::start();
    let d = deployment(github);
    d.serve(120_000, 60_000);
    let runners = Runners::new();
    let process = WorkerProcess::start(&d, Arc::clone(&runners), &[CLASS]);
    d.queued(7);
    eventually("a lease is held", || !runners.runner_held().is_empty());
    let lease = runners.runner_held()[0];
    let runner_name = d
        .store
        .read(move |c| {
            sentinel_store::runner_provision::get(
                c,
                sentinel_core::RunnerLeaseId::from_bytes(lease).unwrap(),
            )
        })
        .unwrap()
        .expect("the lease row")
        .runner_name;
    let (tenant, repo) = (d.tenant, d.repo);
    let bound = d
        .store
        .writer()
        .write(move |tx| {
            sentinel_store::runner_provision::bind(
                tx,
                tenant,
                repo,
                &runner_name,
                7,
                UnixMillis::now(),
            )
        })
        .unwrap();
    assert!(bound.is_some(), "the lease was bound to job 7");
    let reporter = runners
        .reporter
        .lock()
        .unwrap()
        .clone()
        .expect("the worker's session");
    let bytes = b"PK\x03\x04runner artifact";
    let digest = *blake3::hash(bytes).as_bytes();
    reporter
        .runner_artifact_begin(lease, "dist", bytes.len() as u64, digest)
        .unwrap();
    reporter.runner_artifact_data(lease, 0, bytes).unwrap();
    reporter.runner_artifact_end(lease, "dist").unwrap();
    eventually("the offer is answered", || !runners.verdicts().is_empty());
    assert_eq!(
        runners.verdicts().first().map(|(_, code)| *code),
        Some(ArtifactCode::Stored),
        "the begin is granted"
    );
    eventually("answered twice", || runners.verdicts().len() >= 2);
    let answered = runners.verdicts();
    assert_eq!(
        answered.last().map(|(_, code)| *code),
        Some(ArtifactCode::Stored),
        "{answered:?}"
    );
    let rows = d
        .store
        .read(move |c| sentinel_store::artifacts::for_runner_run(c, tenant, repo, 1007))
        .unwrap();
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].name, "dist");
    assert_eq!(rows[0].bytes, bytes.len() as u64);
    assert_eq!(rows[0].github_job, Some(7));
    assert_eq!(rows[0].class, "standard");
    assert_eq!(rows[0].state, sentinel_store::artifacts::State::Captured);
    assert!(rows[0].manifest_version.is_some());

    // The same name again is a duplicate rather than a second row: a runner job's artifact is one
    // artifact of that GitHub job.
    reporter
        .runner_artifact_begin(lease, "dist", bytes.len() as u64, digest)
        .unwrap();
    eventually("refused as a duplicate", || {
        runners
            .verdicts()
            .iter()
            .any(|(_, code)| *code == ArtifactCode::Duplicate)
    });
    let rows = d
        .store
        .read(move |c| sentinel_store::artifacts::for_runner_run(c, tenant, repo, 1007))
        .unwrap();
    assert_eq!(rows.len(), 1, "a duplicate holds no second row");
    process.stop();
}

/// What a worker's runner-mode cache tree holds is charged to the tenant that caused it, and a tenant at
/// its hard threshold is answered with its repositories so its caches give way — before any of its
/// artifacts are refused, which is the order retention.md states.
#[test]
fn a_workers_actions_cache_is_charged_to_its_tenant_and_gives_way_at_the_hard_threshold() {
    let github = Github::start();
    let d = deployment(github);
    d.serve(120_000, 60_000);
    let runners = Runners::new();
    let process = WorkerProcess::start(&d, Arc::clone(&runners), &[CLASS]);
    eventually("connected", || runners.reporter.lock().unwrap().is_some());
    let reporter = runners.reporter.lock().unwrap().clone().expect("session");
    let (tenant, repo, pool, worker) = (d.tenant, d.repo, d.pool, process.id);
    // A tenant quota of 100 bytes at the deployment's default thresholds: 80 warns, 100 is the line. The
    // worker has run a lease of the repository, which is what lets its report charge the tenant.
    d.store
        .writer()
        .write(move |tx| {
            let lease = sentinel_core::RunnerLeaseId::new();
            tx.execute(
                "INSERT INTO runner_leases(id, tenant_id, repo_id, class, pool_id, worker_id, fence,
                    state_code, cpu_millis, memory_bytes, runner_name, offered_ms, lease_until_ms,
                    released_ms, reason)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, 1, 2, 4000, 8589934592, 'sentinel-cache-1', ?7, ?7,
                    ?7, 'job_completed')",
                rusqlite::params![
                    lease.as_bytes(),
                    tenant.as_bytes(),
                    repo.as_bytes(),
                    CLASS,
                    pool.as_bytes(),
                    worker.as_bytes(),
                    UnixMillis::now().0
                ],
            )?;
            tx.execute(
                "INSERT INTO storage_policies(tenant_id, repo_id, quota_bytes, soft_percent,
                    hard_percent, updated_ms) VALUES(?1, X'', 100, 80, 100, ?2)",
                rusqlite::params![tenant.as_bytes(), UnixMillis::now().0],
            )?;
            Ok(())
        })
        .unwrap();

    // Under the line: the class is charged and nothing is given up.
    reporter.actions_cache(&[(repo, 50)]).unwrap();
    eventually("charged", || {
        d.store
            .read(move |c| sentinel_store::classes::tenant(c, tenant))
            .is_ok_and(|classes| classes.actions_cache == 50)
    });
    assert!(
        runners.evicted().is_empty(),
        "nothing gives way below the line"
    );
    assert_eq!(
        d.store
            .read(move |c| sentinel_store::classes::tenant(c, tenant))
            .unwrap()
            .stored(),
        50,
        "the class is what the tenant's quota counts"
    );

    // At it: the tenant's cache gives way, and the answer names its repositories.
    reporter.actions_cache(&[(repo, 120)]).unwrap();
    eventually("charged again", || {
        d.store
            .read(move |c| sentinel_store::classes::tenant(c, tenant))
            .is_ok_and(|classes| classes.actions_cache == 120)
    });
    let standing = d
        .store
        .read(move |c| {
            let deployment = sentinel_store::retention::Deployment::default();
            sentinel_store::retention::standing(c, &deployment, tenant)
        })
        .unwrap();
    assert_eq!(
        standing.state,
        sentinel_store::retention::State::Hard,
        "{standing:?}"
    );
    eventually("evicted", || runners.evicted() == vec![*repo.as_bytes()]);
    assert_eq!(
        d.store
            .read(move |c| sentinel_store::classes::tenant(c, tenant))
            .unwrap()
            .actions_cache,
        120,
        "the figure is the walk's, not the eviction's"
    );
    process.stop();
}

/// The numbers behind the demand-source decision (docs/intake.md): what the webhook path costs
/// from a committed `queued` row to an offer in a worker's hands, and what one reconciliation pass
/// over one repository costs. It asserts nothing about time — it prints a distribution — so it is
/// `#[ignore]`d and run by hand when the numbers are recorded.
#[test]
#[ignore = "measurement: run by hand, its numbers are recorded in docs/intake.md"]
fn demand_source_numbers() {
    fn percentile(values: &mut [Duration], p: f64) -> Duration {
        values.sort_unstable();
        let at = ((values.len() as f64 - 1.0) * p).round() as usize;
        values[at]
    }
    let github = Github::start();
    let d = deployment(github);
    d.serve(120_000, 60_000);
    let runners = Runners::new();
    let process = WorkerProcess::start(&d, Arc::clone(&runners), &[CLASS]);
    eventually("connected", || !process.events.lock().unwrap().is_empty());

    let mut webhook = Vec::with_capacity(50);
    for job in 1..=50 {
        let before = Instant::now();
        d.queued(job);
        let deadline = Instant::now() + Duration::from_secs(10);
        let seen = runners.offers().len();
        while runners.offers().len() == seen {
            assert!(Instant::now() < deadline, "no offer for job {job}");
            thread::sleep(Duration::from_millis(1));
        }
        webhook.push(before.elapsed());
        // The job ran: it stops being demand and its lease's capacity comes back, so the next
        // measurement starts from a fleed with room, as a stream of short jobs does.
        let (tenant, repo) = (d.tenant, d.repo);
        let worker = process.id;
        d.store
            .writer()
            .write(move |tx| {
                tx.execute(
                    "UPDATE runner_jobs SET state_code = 2, completed_ms = ?3
                     WHERE tenant_id = ?1 AND repo_id = ?2 AND job_id = ?4",
                    rusqlite::params![
                        tenant.as_bytes(),
                        repo.as_bytes(),
                        UnixMillis::now().0,
                        job as i64
                    ],
                )?;
                sentinel_store::runner_provision::release_worker(
                    tx,
                    worker,
                    sentinel_store::runner_provision::JOB_COMPLETED,
                    UnixMillis::now(),
                )?;
                Ok(())
            })
            .unwrap();
    }

    // A lost event: no delivery at all, only GitHub's own queue states the job. The pass interval
    // the deployment sets is the outer half of the recovery bound, so it is measured with it
    // (one second here, against the sixty a deployment defaults to).
    d.serve(120_000, 1_000);
    let mut lost = Vec::with_capacity(20);
    for n in 1..=20u64 {
        let job = 700 + n;
        d.github.queue(
            vec![serde_json::json!({"id": 900 + n})],
            vec![serde_json::json!({"id": job, "run_id": 900 + n, "labels": [CLASS]})],
        );
        let before = Instant::now();
        let observed = d.observer();
        let deadline = Instant::now() + Duration::from_secs(10);
        while !observed(job) {
            assert!(Instant::now() < deadline, "job {job} was never recovered");
            thread::sleep(Duration::from_millis(1));
        }
        lost.push(before.elapsed());
    }

    // What one repository's queue read costs on its own: the two requests a pass makes of it.
    let app = sentinel_github::app::App::new(1, test_key())
        .unwrap()
        .with_endpoint(&d.github.endpoint())
        .unwrap();
    let token = app
        .runner_token(
            7,
            73,
            42,
            REMOTE,
            &sentinel_github::runner::Scope::Organization("acme"),
            UnixMillis::now().0,
        )
        .unwrap();
    let mut reads = Vec::with_capacity(20);
    for _ in 0..20 {
        let before = Instant::now();
        let jobs = app
            .queued_jobs(&token, "acme", "app", 1, 50)
            .expect("the queue read");
        assert_eq!(jobs.len(), 1);
        reads.push(before.elapsed());
    }
    println!(
        "webhook queued->offer: n={} p50={:?} p95={:?} max={:?}\n\
         lost->recorded (reconcile_ms=1000): n={} p50={:?} p95={:?} max={:?}\n\
         one repository's queue read: n={} p50={:?} p95={:?}",
        webhook.len(),
        percentile(&mut webhook.clone(), 0.5),
        percentile(&mut webhook.clone(), 0.95),
        webhook.iter().max().copied().unwrap_or_default(),
        lost.len(),
        percentile(&mut lost.clone(), 0.5),
        percentile(&mut lost.clone(), 0.95),
        lost.iter().max().copied().unwrap_or_default(),
        reads.len(),
        percentile(&mut reads.clone(), 0.5),
        percentile(&mut reads.clone(), 0.95),
    );
    process.stop();
}

// ---------------------------------------------------------------- the canary

/// A log sink that keeps every event this process emits, at every level.
struct LogSink(Arc<Mutex<Vec<u8>>>);

struct LogWriter(Arc<Mutex<Vec<u8>>>);

impl Write for LogWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogSink {
    type Writer = LogWriter;
    fn make_writer(&'a self) -> LogWriter {
        LogWriter(Arc::clone(&self.0))
    }
}

impl LogSink {
    /// The process's only subscriber, so every thread's events land here. One test per process
    /// (nextest), so nothing else has installed one.
    fn install() -> LogSink {
        let sink = LogSink(Arc::new(Mutex::new(Vec::new())));
        let subscriber = tracing_subscriber::fmt()
            .with_writer(LogSink(Arc::clone(&sink.0)))
            .with_max_level(tracing::Level::TRACE)
            .with_ansi(false)
            .finish();
        tracing::subscriber::set_global_default(subscriber)
            .expect("the log sink is this test process's subscriber");
        sink
    }

    fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
    }
}

/// Every file under `dir`, as paths.
fn files(dir: &std::path::Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        match entry.file_type() {
            Ok(kind) if kind.is_dir() => files(&path, out),
            Ok(_) => out.push(path),
            Err(_) => {}
        }
    }
}

fn contains(haystack: &[u8], needle: &str) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle.as_bytes())
}

/// AR09's first gate: the just-in-time configuration never appears in a log, a bundle, a record, an
/// environment listing or a workspace. The worker that holds the lease is given it, once, on the
/// frame that exists for it; every other sink this deployment has is walked here.
#[test]
fn the_just_in_time_configuration_reaches_no_log_a_record_a_bundle_or_a_workspace() {
    const CANARY: &str = "sentinel-canary-9f4c1e7a2b6d31";
    let logs = LogSink::install();
    // A marker of this test's own: it proves the sink is live, so "the canary is absent" is a fact
    // about the deployment's logging and not about an empty buffer.
    tracing::info!(
        marker = "canary-sink-live",
        "the log sink of the canary test is recording"
    );
    let github = Github::start();
    github.with_canary(CANARY);
    let d = deployment(github);
    d.serve(120_000, 60_000);
    let runners = Runners::new();
    let process = WorkerProcess::start(&d, Arc::clone(&runners), &[CLASS]);
    d.queued(1);
    eventually(
        "the configuration is delivered to the lease's worker",
        || runners.configs().len() == 1,
    );
    let (lease, config) = runners.configs().first().cloned().expect("delivered");
    // The credential exists and travelled: this is the one place the test lets it appear.
    assert!(
        contains(&config, CANARY),
        "the delivered frame is the configuration GitHub issued"
    );

    // 1. A log: every event of this process at TRACE, from the controller and from the link.
    let logged = logs.text();
    assert!(
        logged.contains("canary-sink-live"),
        "the sink captured nothing to judge:\n{logged}"
    );
    assert!(
        !logged.contains(CANARY),
        "the configuration reached a log:\n{logged}"
    );

    // 2. A bundle: runner mode sends no pipeline secret, so no delivery bundle exists to carry it.
    assert_eq!(
        runners.bundles(),
        0,
        "a secret bundle reached the worker for a runner lease"
    );

    // 6. Actions secrets: a provisioning and delivery pass asks GitHub for a runner configuration
    // and, on release, its removal — never for a secret.
    let requests = d.github.requests();
    assert!(
        requests
            .iter()
            .any(|(_, path, _)| path.ends_with("/actions/runners/generate-jitconfig")),
        "the pass made the registration call: {requests:?}"
    );
    for (method, path, _) in &requests {
        assert!(
            !path.contains("secret"),
            "a runner-mode pass asked GitHub for a secret ({method} {path})"
        );
    }

    // 3. An environment listing: what a controller can ask this worker to list holds lease ids and
    // classes, never a configuration; and the only copy the worker holds is the frame above.
    assert_eq!(runners.runner_held(), vec![lease]);
    // The configuration is delivered once: a moment later there is still exactly one copy.
    thread::sleep(Duration::from_millis(500));
    assert_eq!(
        runners.configs().len(),
        1,
        "the configuration was delivered more than once"
    );

    // 4. A record: every byte the deployment keeps — the database, the logs, the object store — and
    // the row the store wrote. The configuration is sealed at rest and cleared by its one delivery.
    let (present, taken): (i64, i64) = d
        .store
        .read(|c| {
            Ok(c.query_row(
                "SELECT count(sealed_jit), count(taken_ms) FROM runner_leases",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?)
        })
        .unwrap();
    assert_eq!((present, taken), (0, 1), "the configuration is single-use");
    let mut paths = Vec::new();
    files(d._dir.path(), &mut paths);
    assert!(
        paths.len() > 1,
        "the deployment has files to judge: {paths:?}"
    );
    for path in &paths {
        let bytes = std::fs::read(path).unwrap_or_default();
        assert!(
            !contains(&bytes, CANARY),
            "the configuration reached {}",
            path.display()
        );
    }

    // 5. A workspace: runner mode has none on this side. The deployment's every file is walked
    // above — the database, the logs and the object store — and the worker's own sandbox keeps the
    // configuration out of its one scratch directory too, where the sandbox tests hold it to the
    // tmpfs inside the container (`the_runner_takes_one_job_and_its_configuration_is_not_on_the_command_line`).
    assert!(
        !d._dir.path().join("workspaces").exists(),
        "a runner-mode job left a workspace on the controller"
    );
    process.stop();
}
