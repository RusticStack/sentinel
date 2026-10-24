//! Shared by several test binaries, so it names no `sentinel_worker` item and asks `podman` directly.

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
    provenance::{self, Provenance},
    runs,
    tenancy::{self, PoolKind},
    workers,
};

pub const IMAGE: &str = "docker.io/library/busybox";
pub const DIGEST: &str = "sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662";

pub fn podman_enabled() -> bool {
    if std::env::var_os("SENTINEL_PODMAN_TESTS").is_some() {
        return true;
    }
    eprintln!("skipped: set SENTINEL_PODMAN_TESTS=1 as a rootless Podman account to run");
    false
}

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
    pub root: UserId,
    pub worker: WorkerId,
    pub worker_dir: PathBuf,
    pub repo: PathBuf,
    pub sha: String,
    handle: Arc<Handle>,
    link: Option<thread::JoinHandle<sentinel_link::Result<()>>>,
    settled: bool,
}

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
    pub fn start<E: Executor + Send + Sync + 'static>(
        make: impl FnOnce(&Path, WorkerId) -> E,
    ) -> (Live, Arc<E>) {
        Self::start_with(make, 5, Capabilities::REQUIRED, None)
    }

    pub fn start_with<E: Executor + Send + Sync + 'static>(
        make: impl FnOnce(&Path, WorkerId) -> E,
        protocol_max: u16,
        capabilities: Capabilities,
        key: Option<Arc<sentinel_auth::sealed::Key>>,
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
                auth::set_membership(
                    tx,
                    Principal::new(root, P::ALL, None, None),
                    tenant,
                    root,
                    sentinel_core::auth::Role::TenantAdmin,
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
        if let Some(key) = key {
            controller.set_source_key(key);
        }
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
                also_pinned: Vec::new(),
                worker: worker_id,
                name: "builder-1".into(),
                hello: Hello {
                    protocol_min: ProtocolVersion(1),
                    protocol_max: ProtocolVersion(protocol_max),
                    capabilities,
                    arch: Arch::X86_64,
                    software: "test".into(),
                },
                capacity: Capacity {
                    cpu_millis: 4_000,
                    memory_bytes: 4 << 30,
                },
                profile: sentinel_protocol::negotiate::Profile {
                    // A profile-protocol worker must state its scratch disk; zero offers none and every job declares some.
                    disk_bytes: 64 << 30,
                    ..sentinel_protocol::negotiate::Profile::default()
                },
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
                root,
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

    pub fn enqueue(&self, yaml: &str) -> (RunId, Vec<JobId>) {
        self.enqueue_pinned(yaml, DIGEST)
    }

    pub fn enqueue_pinned(&self, yaml: &str, digest: &str) -> (RunId, Vec<JobId>) {
        self.enqueue_with(yaml, digest, None)
    }

    /// A push run: secrets reach push runs and never manual ones, so a test of their delivery needs this provenance.
    pub fn enqueue_push(&self, yaml: &str) -> (RunId, Vec<JobId>) {
        self.enqueue_with(yaml, DIGEST, Some("push"))
    }

    pub fn enqueue_with(
        &self,
        yaml: &str,
        digest: &str,
        trigger: Option<&'static str>,
    ) -> (RunId, Vec<JobId>) {
        let digest = digest.to_owned();
        let sha = self.sha.clone();
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
                    runs::resolve_image(tx, tenant, *job, &digest, "linux/amd64")?;
                }
                if let Some(trigger) = trigger {
                    provenance::insert(
                        tx,
                        &Provenance {
                            tenant,
                            repo: repo_id,
                            trigger: trigger.into(),
                            delivery: None,
                            provider: None,
                            ref_name: Some("refs/heads/main".into()),
                            old_sha: None,
                            new_sha: Some(sha.clone()),
                            head_sha: None,
                            base_sha: None,
                            merge_sha: None,
                            pipeline_sha: sha,
                            pipeline_path: Some(".sentinel.yml".into()),
                            pipeline_digest: [0; 16],
                            pr_number: None,
                        },
                        run,
                        UnixMillis::now(),
                    )?;
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
