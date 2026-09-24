//! A controller with a store, a local repository with one commit, and a
//! worker link over loopback TLS running whatever executor a test hands it —
//! the setup of `end_to_end.rs`, for tests that drive the real executor
//! (rootless Podman, `SENTINEL_PODMAN_TESTS=1`). Shared by
//! `tests/executor_faults.rs` and the executor's own unit tests, so it names
//! no `sentinel_worker` item.

#![allow(dead_code)]

use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    sync::Arc,
    thread,
    time::{Duration, Instant},
};

use sentinel_core::{
    AttemptId, JobId, PoolId, RepoId, RunId, TenantId, UnixMillis, UserId, WorkerId,
    auth::{Namespace, Permissions as P, Principal},
};
use sentinel_link::{
    controller::Controller,
    identity::Identity,
    session::{Capacity, Executor},
    worker::{self, Handle},
};
use sentinel_pipeline::{PinnedSource, RunSpec, compile_str};
use sentinel_protocol::negotiate::{Arch, Capabilities, Hello, ProtocolVersion};
use sentinel_store::{
    Durability, Store,
    auth::{self, Authority, NamespaceKind, provisioning},
    dispatch,
    jobs::JobRow,
    logs::LogStore,
    runs,
    tenancy::{self, PoolKind},
    workers,
};

pub const IMAGE: &str = "docker.io/library/busybox";
pub const DIGEST: &str = "sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662";

/// Whether this run may use rootless Podman.
pub fn podman_enabled() -> bool {
    if std::env::var_os("SENTINEL_PODMAN_TESTS").is_some() {
        return true;
    }
    eprintln!("skipped: set SENTINEL_PODMAN_TESTS=1 as a rootless Podman account to run");
    false
}

/// Wait for `predicate`, failing the test with `what` after `within`.
pub fn eventually(what: &str, within: Duration, mut predicate: impl FnMut() -> bool) {
    let deadline = Instant::now() + within;
    while !predicate() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        thread::sleep(Duration::from_millis(25));
    }
}

fn git(dir: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .args(args)
        .current_dir(dir)
        .env("GIT_AUTHOR_NAME", "t")
        .env("GIT_AUTHOR_EMAIL", "t@example.com")
        .env("GIT_COMMITTER_NAME", "t")
        .env("GIT_COMMITTER_EMAIL", "t@example.com")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .output()
        .unwrap();
    assert!(output.status.success());
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}

pub struct Live {
    pub temp: tempfile::TempDir,
    pub store: Arc<Store>,
    pub logs: Arc<LogStore>,
    pub controller: Option<Controller>,
    pub tenant: TenantId,
    pub repo_id: RepoId,
    pub pool: PoolId,
    pub worker: WorkerId,
    pub worker_dir: PathBuf,
    pub repo: PathBuf,
    pub sha: String,
    handle: Arc<Handle>,
    link: Option<thread::JoinHandle<sentinel_link::Result<()>>>,
    /// Set once [`Live::stop`] has checked that nothing leaked.
    settled: bool,
}

/// Every container the runtime still knows under `worker`'s ownership
/// label, running or not: `sentinel-<attempt>` for each of the test's
/// attempts, since the worker id is the test's own. `None` when `podman`
/// could not be asked. Asked of `podman` directly: this file names no
/// `sentinel_worker` item.
pub fn containers_of(worker: WorkerId) -> Option<Vec<String>> {
    let output = Command::new("podman")
        .args(["ps", "-a", "--filter"])
        .arg(format!("label=io.sentinel.worker={worker}"))
        .args(["--format", "{{.Names}}"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    Some(
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .map(str::to_owned)
            .collect(),
    )
}

impl Live {
    /// Start the controller, then a worker link running the executor
    /// `make` builds from the worker's data directory and id; returns once
    /// the worker is connected.
    pub fn start<E: Executor + Send + Sync + 'static>(
        make: impl FnOnce(&Path, WorkerId) -> E,
    ) -> (Live, Arc<E>) {
        let temp = tempfile::tempdir().unwrap();
        let repo = temp.path().join("origin");
        fs::create_dir(&repo).unwrap();
        git(&repo, &["init", "-q", "--initial-branch=main"]);
        fs::write(repo.join("greeting.txt"), "hello from git\n").unwrap();
        git(&repo, &["add", "."]);
        git(&repo, &["commit", "-q", "-m", "one"]);
        let sha = git(&repo, &["rev-parse", "HEAD"]);

        let store =
            Arc::new(Store::open(temp.path().join("metadata.sqlite"), Durability::Normal).unwrap());
        let (root, tenant, repo_id, pool) =
            (UserId::new(), TenantId::new(), RepoId::new(), PoolId::new());
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
                sentinel_store::jobs::insert_repo(tx, tenant, repo_id, "app", UnixMillis(1))?;
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
        let logs = Arc::new(LogStore::open(temp.path().join("logs")).unwrap());
        let objects =
            Arc::new(sentinel_store::objects::Objects::open(temp.path().join("objects")).unwrap());
        let controller = Controller::start(
            Arc::clone(&store),
            Arc::clone(&logs),
            objects,
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

        let worker_dir = temp.path().join("worker");
        fs::create_dir(&worker_dir).unwrap();
        let worker_id = WorkerId::new();
        let executor = Arc::new(make(&worker_dir, worker_id));
        let handle = Arc::new(Handle::new());
        let link = {
            let (executor, handle) = (Arc::clone(&executor), Arc::clone(&handle));
            let config = worker::Config {
                controller: controller.local_addr(),
                server: controller.fingerprint(),
                worker: worker_id,
                name: "builder-1".into(),
                hello: Hello {
                    protocol_min: ProtocolVersion(1),
                    protocol_max: ProtocolVersion(5),
                    capabilities: Capabilities::REQUIRED,
                    arch: Arch::X86_64,
                    software: "test".into(),
                },
                capacity: Capacity {
                    cpu_millis: 4_000,
                    memory_bytes: 4 << 30,
                },
                profile: sentinel_protocol::negotiate::Profile::default(),
                transport: sentinel_link::session::TransportStats::default(),
                remote_cache: false,
            };
            let identity = Identity::generate("worker").unwrap();
            thread::spawn(move || {
                worker::run(
                    config,
                    identity,
                    Some(enrollment),
                    &*executor,
                    &handle,
                    &|_| {},
                )
            })
        };
        eventually("worker connected", Duration::from_secs(60), || {
            controller.connected() == vec![worker_id]
        });
        (
            Live {
                temp,
                store,
                logs,
                controller: Some(controller),
                tenant,
                repo_id,
                pool,
                worker: worker_id,
                worker_dir,
                repo,
                sha,
                handle,
                link: Some(link),
                settled: false,
            },
            executor,
        )
    }

    pub fn controller(&self) -> &Controller {
        self.controller.as_ref().expect("running")
    }

    /// Enqueue a run of `yaml` (every job on the pinned busybox) and wake
    /// the dispatcher. Returns the run and its jobs in compiled order.
    pub fn enqueue(&self, yaml: &str) -> (RunId, Vec<JobId>) {
        let spec = RunSpec::new(
            PinnedSource::new(self.repo.to_str().unwrap(), &self.sha, Some("main")).unwrap(),
            compile_str(yaml).unwrap(),
        )
        .unwrap();
        let (tenant, repo_id, run) = (self.tenant, self.repo_id, RunId::new());
        let ids = self
            .store
            .writer()
            .write(move |tx| {
                let ids = runs::create_run(tx, tenant, repo_id, run, &spec, UnixMillis::now())?;
                for job in &ids {
                    runs::resolve_image(tx, tenant, *job, DIGEST, "linux/amd64")?;
                }
                Ok(ids)
            })
            .unwrap();
        self.controller().wake();
        (run, ids)
    }

    pub fn job(&self, job: JobId) -> JobRow {
        self.store
            .read(|c| sentinel_store::jobs::get_job(c, self.tenant, job))
            .unwrap()
    }

    pub fn attempt(&self, job: JobId) -> Option<AttemptId> {
        self.store
            .read(|c| dispatch::latest_attempt(c, self.tenant, job))
            .unwrap()
    }

    /// Whether the job's latest attempt has printed `needle` into the
    /// controller's log.
    pub fn printed(&self, run: RunId, job: JobId, needle: &str) -> bool {
        self.attempt(job).is_some_and(|attempt| {
            self.logs
                .tail(run, job, attempt, 0, 1_000, None)
                .map(|t| {
                    t.frames
                        .iter()
                        .any(|f| String::from_utf8_lossy(&f.bytes).contains(needle))
                })
                .unwrap_or(false)
        })
    }

    /// Stop the worker link and the controller, then assert that no
    /// container of the test's attempts survives the test: the executor
    /// tears down every container it started, whatever ended the attempt.
    pub fn stop(mut self) {
        self.handle.stop();
        if let Some(link) = self.link.take() {
            let _ = link.join();
        }
        if let Some(controller) = self.controller.take() {
            assert!(controller.shutdown(Duration::from_secs(10)));
        }
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let left = containers_of(self.worker).expect("podman ps");
            if left.is_empty() {
                break;
            }
            assert!(Instant::now() < deadline, "containers left: {left:?}");
            thread::sleep(Duration::from_millis(100));
        }
        self.settled = true;
    }
}

/// A test that fails ends while its attempts may still run: the process
/// exits before their threads tear their containers down, and no later
/// worker start reconciles a test's one-off worker id (W07 does, for a
/// real worker). Force-remove them here, so a failing test leaves nothing
/// running behind it.
impl Drop for Live {
    fn drop(&mut self) {
        if self.settled {
            return;
        }
        self.handle.stop();
        for name in containers_of(self.worker).unwrap_or_default() {
            let _ = Command::new("podman")
                .args(["rm", "-f", "-t", "0", "--", &name])
                .output();
        }
    }
}
