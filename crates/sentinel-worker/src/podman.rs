use std::{
    path::Path,
    process::Command,
    time::{Duration, Instant},
};

use sentinel_core::{AttemptId, WorkerId};
use sentinel_pipeline::run::StepCommand;

use crate::{Error, Result, process};

pub const IMAGE_PULL_TIMEOUT: Duration = Duration::from_secs(15 * 60);
pub const CONTAINER_START_TIMEOUT: Duration = Duration::from_secs(60);
pub const STOP_TIMEOUT: Duration = Duration::from_secs(10);
pub const DEFAULT_PIDS_LIMIT: u32 = 4096;
pub const KEEPALIVE_SLACK_SECS: u64 = 5 * 60;
pub const KEEPALIVE_MAX_SECS: u64 = 24 * 60 * 60 + KEEPALIVE_SLACK_SECS;
pub const WORKSPACE_MOUNT: &str = "/workspace";
pub const LABEL_WORKER: &str = "io.sentinel.worker";
pub const LABEL_ATTEMPT: &str = "io.sentinel.attempt";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Runtime {
    pub version: String,
    pub oci_runtime: String,
    pub cgroup_version: String,
    pub cgroup_manager: String,
}

// Credentialed pulls go to the tenant's own store: containers/image reuses resident layers without asking the registry, so a shared store would leak one tenant's private layers to another.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Store {
    Shared,
    Private {
        graph: std::path::PathBuf,
        run: std::path::PathBuf,
    },
}

pub const STORES_DIR: &str = "image-stores";

impl Store {
    pub fn private(root: &Path, tenant: [u8; 16]) -> Result<Store> {
        let name: String = tenant.iter().map(|b| format!("{b:02x}")).collect();
        let graph = root.join(STORES_DIR).join(&name).join("graph");
        let store = Store::Private {
            run: run_root(&graph),
            graph,
        };
        if let Store::Private { graph, run } = &store {
            for dir in [graph, run] {
                private_dirs(dir)?;
            }
        }
        Ok(store)
    }

    pub fn all(root: &Path) -> Vec<Store> {
        let mut stores = vec![Store::Shared];
        if let Ok(entries) = std::fs::read_dir(root.join(STORES_DIR)) {
            for entry in entries
                .flatten()
                .take(sentinel_protocol::limits::MAX_LIST_ITEMS)
            {
                let name = entry.file_name();
                let Some(name) = name.to_str() else { continue };
                if name.len() != 32 || !name.bytes().all(|b| b.is_ascii_hexdigit()) {
                    continue;
                }
                if entry.file_type().is_ok_and(|t| t.is_dir()) {
                    let graph = entry.path().join("graph");
                    stores.push(Store::Private {
                        run: run_root(&graph),
                        graph,
                    });
                }
            }
        }
        stores
    }

    fn apply(&self, cmd: &mut Command) {
        if let Store::Private { graph, run } = self {
            cmd.arg("--root").arg(graph).arg("--runroot").arg(run);
        }
    }
}

fn run_root(graph: &Path) -> std::path::PathBuf {
    use std::os::unix::ffi::OsStrExt;
    let key = blake3::hash(graph.as_os_str().as_bytes()).to_hex();
    crate::xdg_runtime_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("/tmp"))
        .join(format!("sentinel-sr-{}", &key[..12]))
}

fn private_dirs(dir: &Path) -> Result<()> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)?;
    let meta = std::fs::symlink_metadata(dir)?;
    if !meta.is_dir()
        || meta.file_type().is_symlink()
        || meta.uid() != crate::euid()
        || meta.mode() & 0o077 != 0
    {
        return Err(Error::Preparation("image store directory".into()));
    }
    Ok(())
}

fn podman() -> Command {
    let mut cmd = Command::new("podman");
    cmd.env_remove("DOCKER_HOST");
    cmd.env_remove("REGISTRY_AUTH_FILE");
    cmd
}

pub(crate) fn podman_in(store: &Store) -> Command {
    let mut cmd = podman();
    store.apply(&mut cmd);
    cmd
}

fn podman_executable() -> Result<std::path::PathBuf> {
    let Some(path) = std::env::var_os("PATH") else {
        return Err(Error::Preparation(
            "podman executable is unavailable".into(),
        ));
    };
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join("podman");
        let Ok(metadata) = std::fs::metadata(&candidate) else {
            continue;
        };
        if !metadata.is_file() {
            continue;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o111 == 0 {
                continue;
            }
        }
        return Ok(candidate);
    }
    Err(Error::Preparation(
        "podman executable is unavailable".into(),
    ))
}

fn podman_for_pull() -> Result<Command> {
    // Resolved before PATH is cleared: the credential-helper lookup uses PATH, so a host-wide helper could authorize a tenant's pull.
    let mut cmd = Command::new(podman_executable()?);
    cmd.env_remove("DOCKER_HOST");
    cmd.env_remove("REGISTRY_AUTH_FILE");
    cmd.env_remove("DOCKER_CONFIG");
    cmd.env("PATH", "");
    Ok(cmd)
}

fn podman_pull_command(image: &str, authfile: &Path, store: &Store) -> Result<Command> {
    let mut cmd = podman_for_pull()?;
    store.apply(&mut cmd);
    cmd.args(["pull", "--authfile"])
        .arg(authfile)
        .args(["-q", "--", image]);
    Ok(cmd)
}

fn deadline(timeout: Duration) -> Instant {
    Instant::now() + timeout
}

pub fn probe() -> Result<Runtime> {
    let mut cmd = podman();
    cmd.args([
        "info",
        "--format",
        "{{.Host.Security.Rootless}} {{.Host.CgroupsVersion}} {{.Host.OCIRuntime.Name}} {{.Host.CgroupManager}} {{.Version.Version}}",
    ]);
    let output = process::run(cmd, deadline(Duration::from_secs(30)), "podman info")?;
    if !output.success() {
        return Err(Error::Runtime(format!(
            "podman info: {}",
            output.stderr_excerpt()
        )));
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let mut fields = text.split_whitespace();
    let (rootless, cgroups, oci, manager, version) = (
        fields.next().unwrap_or(""),
        fields.next().unwrap_or(""),
        fields.next().unwrap_or(""),
        fields.next().unwrap_or(""),
        fields.next().unwrap_or(""),
    );
    if rootless != "true" {
        return Err(Error::Runtime(
            "podman is not rootless for this user; run the worker as an unprivileged account with subordinate ids".into(),
        ));
    }
    if cgroups != "v2" {
        return Err(Error::Runtime(format!(
            "cgroup {cgroups} is not supported; cgroup v2 is required for enforced limits"
        )));
    }
    Ok(Runtime {
        version: version.to_owned(),
        oci_runtime: oci.to_owned(),
        cgroup_version: cgroups.to_owned(),
        cgroup_manager: manager.to_owned(),
    })
}

pub fn graph_root() -> Result<std::path::PathBuf> {
    let mut cmd = podman();
    cmd.args(["info", "--format", "{{.Store.GraphRoot}}"]);
    let output = process::run(cmd, deadline(Duration::from_secs(30)), "podman info")?;
    let text = String::from_utf8_lossy(&output.stdout);
    let root = text.trim();
    if !output.success() || root.is_empty() {
        return Err(Error::Runtime(format!(
            "podman info: {}",
            output.stderr_excerpt()
        )));
    }
    Ok(std::path::PathBuf::from(root))
}

pub fn image_bytes(image: &str) -> Option<u64> {
    let mut cmd = podman();
    cmd.args(["image", "inspect", "--format", "{{.Size}}", "--", image]);
    let output = process::run(
        cmd,
        deadline(Duration::from_secs(30)),
        "podman image inspect",
    )
    .ok()?;
    if !output.success() {
        return None;
    }
    String::from_utf8_lossy(&output.stdout).trim().parse().ok()
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredImage {
    pub id: String,
    pub bytes: u64,
    pub containers: u32,
    pub digest: String,
}

pub fn list_images(store: &Store) -> Result<Vec<StoredImage>> {
    let mut cmd = podman_in(store);
    cmd.args([
        "images",
        "--noheading",
        "--no-trunc",
        "--format",
        "{{.Id}} {{.VirtualSize}} {{.Containers}} {{.Digest}}",
    ]);
    let output = process::run(cmd, deadline(Duration::from_secs(30)), "podman images")?;
    if !output.success() {
        return Err(Error::Preparation(format!(
            "image list: {}",
            output.stderr_excerpt()
        )));
    }
    Ok(parse_images(&output.stdout))
}

fn parse_images(stdout: &[u8]) -> Vec<StoredImage> {
    String::from_utf8_lossy(stdout)
        .lines()
        .take(sentinel_protocol::limits::MAX_LIST_ITEMS)
        .filter_map(|line| {
            let mut fields = line.split_ascii_whitespace();
            let id = fields.next()?;
            let bytes = fields.next()?.parse().ok()?;
            let containers = fields.next()?.parse().ok()?;
            let digest = fields.next()?;
            (id.bytes().all(|b| b.is_ascii_hexdigit()) && digest.starts_with("sha256:")).then(
                || StoredImage {
                    id: id.to_owned(),
                    bytes,
                    containers,
                    digest: digest.to_owned(),
                },
            )
        })
        .collect()
}

pub fn remove_image(store: &Store, id: &str) -> bool {
    if id.is_empty() || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
        return false;
    }
    let mut cmd = podman_in(store);
    cmd.args(["rmi", "--", id]);
    process::run(cmd, deadline(Duration::from_secs(60)), "podman rmi").is_ok_and(|o| o.success())
}

pub fn pull(
    image: &str,
    authfile: &Path,
    store: &Store,
    timeout: Duration,
    cancel: &std::sync::atomic::AtomicBool,
) -> Result<bool> {
    pull_checked(image, authfile, store, timeout, cancel, true)
}

pub fn registry_check_needed(anonymous: bool, store: &Store) -> bool {
    !(anonymous && *store == Store::Shared)
}

pub fn pull_checked(
    image: &str,
    authfile: &Path,
    store: &Store,
    timeout: Duration,
    cancel: &std::sync::atomic::AtomicBool,
    recheck: bool,
) -> Result<bool> {
    if !image.contains("@sha256:") {
        return Err(Error::Preparation("image is not pinned by digest".into()));
    }
    let mut exists = podman_in(store);
    exists.args(["image", "exists", "--", image]);
    let present = process::run(
        exists,
        deadline(Duration::from_secs(30)),
        "podman image exists",
    )?
    .success();
    if present && !recheck {
        return Ok(true);
    }
    let cmd = podman_pull_command(image, authfile, store)?;
    let output = process::run_canceled(cmd, deadline(timeout), "podman pull", None, Some(cancel))?;
    if output.success() {
        Ok(present)
    } else {
        Err(Error::Preparation(format!(
            "image pull: {}",
            output.stderr_excerpt()
        )))
    }
}

/// A job container's network. `None` is loopback only. `Egress` is outbound through rootless pasta with the
/// gateway-to-host mapping off, so the container cannot reach the worker host's loopback services; an
/// operator grants it per worker (`job_network = "egress"`) for trusted code that fetches dependencies.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Network {
    #[default]
    None,
    Egress,
}

impl Network {
    fn argument(self) -> &'static str {
        match self {
            Network::None => "none",
            Network::Egress => "pasta:--no-map-gw",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    pub cpu_millis: u32,
    pub memory_bytes: u64,
    pub pids: u32,
    pub disk_bytes: u64,
    pub lifetime_secs: u64,
}

impl Limits {
    fn keepalive_secs(&self) -> u64 {
        match self.lifetime_secs {
            0 => KEEPALIVE_MAX_SECS,
            secs => secs,
        }
    }
}

const KEEPALIVE: &str =
    "trap 'exit 0' TERM INT; n=$1; while [ \"$n\" -gt 0 ]; do sleep 1; n=$((n-1)); done";

/// Where a job sees its scratch directory; a [`Mount`] at this path replaces the default tmpfs.
pub const TMP_MOUNT: &str = "/tmp";

#[derive(Clone, Debug)]
pub struct Mount {
    pub host: std::path::PathBuf,
    pub container: String,
    pub read_only: bool,
}

#[derive(Debug)]
pub struct Container {
    name: String,
    attempt: AttemptId,
    cgroup: Option<std::path::PathBuf>,
    init_pid: Option<i32>,
    store: Store,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Terminated {
    Graceful,
    Forced,
    Gone,
}

fn inspect_named(name: &str, store: &Store) -> Result<(Option<i32>, Option<std::path::PathBuf>)> {
    let mut inspect = podman_in(store);
    inspect.args([
        "inspect",
        "--format",
        "{{.State.Pid}} {{.State.CgroupPath}}",
        "--",
        name,
    ]);
    let output = process::run(inspect, deadline(Duration::from_secs(30)), "podman inspect")?;
    if !output.success() {
        return Err(Error::Runtime(format!(
            "podman inspect: {}",
            output.stderr_excerpt()
        )));
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let mut fields = text.split_whitespace();
    let pid = fields
        .next()
        .and_then(|p| p.parse::<i32>().ok())
        .filter(|p| *p > 0);
    let cgroup = fields
        .next()
        .and_then(|path| path.strip_prefix('/').map(str::to_owned))
        .map(|rel| std::path::Path::new("/sys/fs/cgroup").join(rel))
        .filter(|full| full.join("cgroup.procs").exists());
    Ok((pid, cgroup))
}

fn step_pids(cgroup: &std::path::Path, init: Option<i32>) -> Vec<i32> {
    cgroup_pids(cgroup, init).0
}

fn cgroup_pids(cgroup: &std::path::Path, init: Option<i32>) -> (Vec<i32>, bool) {
    const MAX_DEPTH: usize = 8;
    const MAX_CGROUPS: usize = 256;
    let mut pids = Vec::new();
    let mut complete = true;
    let mut pending = vec![(cgroup.to_path_buf(), 0usize)];
    let mut seen = 0;
    while let Some((dir, depth)) = pending.pop() {
        seen += 1;
        match std::fs::read_to_string(dir.join("cgroup.procs")) {
            Ok(text) => pids.extend(
                text.lines()
                    .filter_map(|l| l.trim().parse::<i32>().ok())
                    .filter(|pid| Some(*pid) != init),
            ),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => complete = false,
        }
        let entries = match std::fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => {
                complete = false;
                continue;
            }
        };
        for entry in entries.flatten() {
            if !entry.file_type().is_ok_and(|t| t.is_dir()) {
                continue;
            }
            if depth >= MAX_DEPTH || seen + pending.len() >= MAX_CGROUPS {
                complete = false;
                break;
            }
            pending.push((entry.path(), depth + 1));
        }
    }
    (pids, complete)
}

fn exited(pid: i32) -> bool {
    let Ok(stat) = std::fs::read(format!("/proc/{pid}/stat")) else {
        return true;
    };
    // The state follows the last ')', as comm may contain one.
    let Some(close) = stat.iter().rposition(|b| *b == b')') else {
        return false;
    };
    matches!(stat.get(close + 2), Some(b'Z' | b'X'))
}

pub const CLEAR_TIMEOUT: Duration = Duration::from_secs(5);

pub fn terminate_named(name: &str, store: &Store, grace: Duration) -> Result<Terminated> {
    let (init, cgroup) = match inspect_named(name, store) {
        Ok(found) => found,
        Err(_) => return Ok(Terminated::Gone),
    };
    let Some(cgroup) = cgroup else {
        remove_named(name, store)?;
        return Ok(Terminated::Forced);
    };
    let frozen = freeze(&cgroup, true, Instant::now() + CLEAR_TIMEOUT);
    let pids = step_pids(&cgroup, init);
    for pid in &pids {
        // SAFETY: a plain signal to a pid read from the container's own
        // cgroup while it is frozen, so it cannot have exited and been
        // reused; unfrozen, a pid that exited meanwhile makes kill fail.
        unsafe {
            libc::kill(*pid, libc::SIGTERM);
        }
    }
    if frozen {
        freeze(&cgroup, false, Instant::now() + CLEAR_TIMEOUT);
    }
    if pids.is_empty() {
        return Ok(Terminated::Gone);
    }
    let deadline_at = Instant::now() + grace;
    while Instant::now() < deadline_at {
        if step_pids(&cgroup, init).is_empty() {
            return Ok(Terminated::Graceful);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    remove_named(name, store)?;
    Ok(Terminated::Forced)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Exit {
    pub code: Option<i32>,
    pub signal: Option<i32>,
    pub timed_out: bool,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

impl Drop for Exit {
    fn drop(&mut self) {
        self.stdout.fill(0);
        self.stderr.fill(0);
        core::hint::black_box((&mut self.stdout, &mut self.stderr));
    }
}

impl Exit {
    pub fn stderr_excerpt(&self) -> String {
        crate::redact::excerpt(&self.stderr)
    }
}

impl Container {
    pub fn name(&self) -> &str {
        &self.name
    }

    #[allow(clippy::too_many_arguments)]
    pub fn start(
        worker: WorkerId,
        attempt: AttemptId,
        image: &str,
        limits: Limits,
        workspace: &Path,
        mounts: &[Mount],
        store: &Store,
        network: Network,
    ) -> Result<Container> {
        Self::start_canceled(
            worker,
            attempt,
            image,
            limits,
            workspace,
            mounts,
            store,
            network,
            &std::sync::atomic::AtomicBool::new(false),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn start_canceled(
        worker: WorkerId,
        attempt: AttemptId,
        image: &str,
        limits: Limits,
        workspace: &Path,
        mounts: &[Mount],
        store: &Store,
        network: Network,
        cancel: &std::sync::atomic::AtomicBool,
    ) -> Result<Container> {
        if cancel.load(std::sync::atomic::Ordering::Acquire) {
            return Err(Error::Preparation("container create canceled".into()));
        }
        let name = format!("sentinel-{attempt}");
        let mut cmd = podman_in(store);
        cmd.args(["create", "--name", &name])
            .arg("--label")
            .arg(format!("{LABEL_WORKER}={worker}"))
            .arg("--label")
            .arg(format!("{LABEL_ATTEMPT}={attempt}"))
            .arg("--cpus")
            .arg(format!(
                "{}.{:03}",
                limits.cpu_millis / 1000,
                limits.cpu_millis % 1000
            ))
            .arg("--memory")
            .arg(format!("{}b", limits.memory_bytes))
            .arg("--memory-swap")
            .arg(format!("{}b", limits.memory_bytes))
            .arg("--pids-limit")
            .arg(limits.pids.to_string())
            .args(["--network", network.argument()])
            .args([
                "--read-only",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges",
                "--ulimit",
                "core=0:0",
                "--entrypoint",
                "/bin/sh",
                "--workdir",
                WORKSPACE_MOUNT,
                "--pull",
                "never",
            ])
            .arg("--volume")
            .arg(format!("{}:{WORKSPACE_MOUNT}", workspace.display()));
        // A job's `/tmp` is a directory on the workspace disk when the caller supplies one (the executor always
        // does), so it draws on the job's disk budget like the workspace. Without one it is a tmpfs, which the
        // container's memory limit already bounds, so it is sized to that limit and no smaller.
        if !mounts.iter().any(|mount| mount.container == TMP_MOUNT) {
            cmd.arg("--tmpfs").arg(format!(
                "{TMP_MOUNT}:rw,nosuid,nodev,size={}",
                limits.memory_bytes
            ));
        }
        // Caches declared at absolute paths keep their bytes in the workspace's private directory; an empty
        // read-only tmpfs over it keeps tools that walk the tree (gofmt, linters, globs) from finding them twice.
        // `notmpcopyup`: Podman otherwise copies the directory's contents into a new tmpfs.
        let private = sentinel_cache::attach::PRIVATE_DIR;
        if workspace.join(private).exists() {
            cmd.arg("--tmpfs").arg(format!(
                "{WORKSPACE_MOUNT}/{private}:ro,size=4k,mode=0555,notmpcopyup"
            ));
        }
        if limits.disk_bytes > 0 {
            cmd.arg("--ulimit")
                .arg(format!("fsize={0}:{0}", limits.disk_bytes));
        }
        for mount in mounts {
            let options = match (mount.read_only, mount.container == TMP_MOUNT) {
                (true, _) => "ro",
                (false, true) => "rw,nosuid,nodev",
                (false, false) => "rw",
            };
            cmd.arg("--volume").arg(format!(
                "{}:{}:{options}",
                mount.host.display(),
                mount.container
            ));
        }
        cmd.arg("--")
            .arg(image)
            .args(["-c", KEEPALIVE, "sentinel-keepalive"])
            .arg(limits.keepalive_secs().to_string());
        let created = match process::run_canceled(
            cmd,
            deadline(CONTAINER_START_TIMEOUT),
            "podman create",
            None,
            Some(cancel),
        ) {
            Ok(created) => created,
            Err(error) => {
                // The service may have created the container before a canceled or timed-out client exited.
                let _ = remove_named(&name, store);
                return Err(error);
            }
        };
        if !created.success() {
            return Err(Error::Preparation(format!(
                "container create: {}",
                created.stderr_excerpt()
            )));
        }
        let mut container = Container {
            name,
            attempt,
            cgroup: None,
            init_pid: None,
            store: store.clone(),
        };
        if cancel.load(std::sync::atomic::Ordering::Acquire) {
            let _ = container.remove();
            return Err(Error::Preparation("container create canceled".into()));
        }
        let mut start = podman_in(store);
        start.args(["start", "--", &container.name]);
        let started = match process::run_canceled(
            start,
            deadline(CONTAINER_START_TIMEOUT),
            "podman start",
            None,
            Some(cancel),
        ) {
            Ok(started) => started,
            Err(error) => {
                let _ = container.remove();
                return Err(error);
            }
        };
        if !started.success() {
            let why = started.stderr_excerpt();
            let _ = container.remove();
            return Err(Error::Preparation(format!("container start: {why}")));
        }
        if cancel.load(std::sync::atomic::Ordering::Acquire) {
            let _ = container.remove();
            return Err(Error::Preparation("container start canceled".into()));
        }
        if let Ok((init, cgroup)) = inspect_named(&container.name, store) {
            container.init_pid = init;
            container.cgroup = cgroup.filter(|c| c.join("memory.events").exists());
        }
        Ok(container)
    }

    pub fn exec(&self, step: &StepCommand, extra: &[(String, String)]) -> Result<Exit> {
        self.exec_streaming(step, extra, None)
    }

    pub fn exec_streaming(
        &self,
        step: &StepCommand,
        extra: &[(String, String)],
        sink: Option<process::Sink>,
    ) -> Result<Exit> {
        let mut cmd = podman_in(&self.store);
        cmd.args(["exec", "--workdir"]);
        cmd.arg(match &step.workdir {
            Some(dir) => format!("{WORKSPACE_MOUNT}/{dir}"),
            None => WORKSPACE_MOUNT.to_owned(),
        });
        for (k, v) in step.env.iter().chain(extra) {
            cmd.arg("--env").arg(format!("{k}={v}"));
        }
        cmd.arg("--").arg(&self.name).args(&step.argv);
        let timeout = Duration::from_secs(step.timeout_secs.max(1));
        match process::run_with(cmd, deadline(timeout), "step", sink) {
            Ok(mut output) => Ok(Exit {
                signal: output.code.filter(|c| *c > 128).map(|c| c - 128),
                code: output.code.filter(|c| *c <= 128),
                timed_out: false,
                stdout: std::mem::take(&mut output.stdout),
                stderr: std::mem::take(&mut output.stderr),
            }),
            Err(Error::Timeout(_)) => {
                let _ = self.stop(Duration::ZERO);
                Ok(Exit {
                    code: None,
                    signal: None,
                    timed_out: true,
                    stdout: Vec::new(),
                    stderr: Vec::new(),
                })
            }
            Err(e) => Err(e),
        }
    }

    pub fn oom_kills(&self) -> Result<u64> {
        let text = match &self.cgroup {
            Some(dir) => std::fs::read_to_string(dir.join("memory.events"))?,
            None => {
                let mut cmd = podman_in(&self.store);
                cmd.args([
                    "exec",
                    "--",
                    &self.name,
                    "cat",
                    "/sys/fs/cgroup/memory.events",
                ]);
                let output = process::run(cmd, deadline(Duration::from_secs(30)), "memory.events")?;
                if !output.success() {
                    return Err(Error::Runtime(format!(
                        "memory.events: {}",
                        output.stderr_excerpt()
                    )));
                }
                String::from_utf8_lossy(&output.stdout).into_owned()
            }
        };
        Ok(text
            .lines()
            .find_map(|line| line.strip_prefix("oom_kill "))
            .and_then(|n| n.trim().parse().ok())
            .unwrap_or(0))
    }

    pub fn stop(&self, grace: Duration) -> Result<()> {
        let mut cmd = podman_in(&self.store);
        cmd.args(["stop", "-t"])
            .arg(grace.as_secs().to_string())
            .args(["--", &self.name]);
        let output = process::run(cmd, deadline(grace + STOP_TIMEOUT), "podman stop")?;
        if output.success() {
            Ok(())
        } else {
            Err(Error::Runtime(format!(
                "container stop: {}",
                output.stderr_excerpt()
            )))
        }
    }

    fn remove(&self) -> Result<()> {
        let mut cmd = podman_in(&self.store);
        cmd.args(["rm", "-f", "--", &self.name]);
        let output = process::run(cmd, deadline(STOP_TIMEOUT), "podman rm")?;
        if output.success() {
            Ok(())
        } else {
            Err(Error::Runtime(format!(
                "container remove: {}",
                output.stderr_excerpt()
            )))
        }
    }

    pub fn destroy(self) -> Result<()> {
        let stopped = self.stop(Duration::from_secs(2));
        let removed = self.remove();
        removed.and(stopped)
    }

    pub fn attempt(&self) -> AttemptId {
        self.attempt
    }

    pub fn store(&self) -> &Store {
        &self.store
    }

    // All steps share one PID namespace, so a leftover process could read a later step's secrets through /proc.
    pub fn clear_strays(&self) -> Result<usize> {
        let cgroup = self.cgroup.as_ref().ok_or_else(|| {
            Error::Runtime("the container's cgroup is not visible; secrets are refused".into())
        })?;
        let deadline_at = Instant::now() + CLEAR_TIMEOUT;
        let frozen = freeze(cgroup, true, deadline_at);
        let mut killed = 0usize;
        let outcome = loop {
            let (pids, complete) = cgroup_pids(cgroup, self.init_pid);
            if !complete {
                break Err(Error::Runtime(
                    "the container's process tree could not be listed whole".into(),
                ));
            }
            let live: Vec<i32> = pids.into_iter().filter(|pid| !exited(*pid)).collect();
            if live.is_empty() {
                break Ok(killed);
            }
            for pid in &live {
                // SAFETY: a plain signal to a pid read from the container's
                // own cgroup while it is frozen, so the process cannot have
                // exited and its pid been reused; unfrozen (the freeze could
                // not be used) a pid that exited meanwhile makes kill fail.
                if unsafe { libc::kill(*pid, libc::SIGKILL) } == 0 {
                    killed += 1;
                }
            }
            if Instant::now() >= deadline_at {
                break Err(Error::Runtime(
                    "processes left by earlier steps would not end".into(),
                ));
            }
            std::thread::sleep(Duration::from_millis(2));
        };
        if frozen {
            freeze(cgroup, false, Instant::now() + CLEAR_TIMEOUT);
        }
        outcome
    }
}

fn freeze(cgroup: &Path, on: bool, until: Instant) -> bool {
    if std::fs::write(cgroup.join("cgroup.freeze"), if on { "1" } else { "0" }).is_err() {
        return false;
    }
    let want = if on { "frozen 1" } else { "frozen 0" };
    loop {
        match std::fs::read_to_string(cgroup.join("cgroup.events")) {
            Ok(events) if events.lines().any(|l| l.trim() == want) => return true,
            Ok(_) => {}
            Err(_) => return false,
        }
        if Instant::now() >= until {
            return false;
        }
        std::thread::sleep(Duration::from_micros(200));
    }
}

pub fn owned(worker: WorkerId) -> Result<Vec<(AttemptId, String)>> {
    owned_in(worker, &Store::Shared)
}

pub fn owned_in(worker: WorkerId, store: &Store) -> Result<Vec<(AttemptId, String)>> {
    let mut cmd = podman_in(store);
    cmd.args(["ps", "-a", "--filter"])
        .arg(format!("label={LABEL_WORKER}={worker}"))
        .args([
            "--format",
            r#"{{.Names}} {{index .Labels "io.sentinel.attempt"}}"#,
        ]);
    let output = process::run(cmd, deadline(Duration::from_secs(30)), "podman ps")?;
    if !output.success() {
        return Err(Error::Runtime(format!(
            "podman ps: {}",
            output.stderr_excerpt()
        )));
    }
    let text = String::from_utf8_lossy(&output.stdout);
    Ok(text
        .lines()
        .filter_map(|line| {
            let (name, attempt) = line.split_once(' ')?;
            Some((attempt.trim().parse().ok()?, name.to_owned()))
        })
        .collect())
}

pub fn remove_named(name: &str, store: &Store) -> Result<()> {
    Container {
        name: name.to_owned(),
        attempt: AttemptId::new(),
        cgroup: None,
        init_pid: None,
        store: store.clone(),
    }
    .remove()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_an_anonymous_shared_pull_skips_the_registry_for_a_resident_image() {
        let private = Store::Private {
            graph: std::path::PathBuf::from("/g"),
            run: std::path::PathBuf::from("/r"),
        };
        assert!(!registry_check_needed(true, &Store::Shared));
        assert!(registry_check_needed(false, &Store::Shared));
        assert!(registry_check_needed(true, &private));
        assert!(registry_check_needed(false, &private));
    }

    #[test]
    fn the_image_listing_parses_and_skips_what_it_cannot_trust() {
        let out = b"b116e155 4660174 0 sha256:73aa\n\
            ffff 10 2 sha256:beef\n\
            not-hex 5 0 sha256:dead\n\
            abcd twelve 0 sha256:dead\n\
            abcd 7 0 md5:dead\n\
            \n";
        let images = parse_images(out);
        assert_eq!(
            images,
            vec![
                StoredImage {
                    id: "b116e155".into(),
                    bytes: 4_660_174,
                    containers: 0,
                    digest: "sha256:73aa".into(),
                },
                StoredImage {
                    id: "ffff".into(),
                    bytes: 10,
                    containers: 2,
                    digest: "sha256:beef".into(),
                },
            ]
        );
        assert!(!remove_image(&Store::Shared, "not-hex; rm -rf /"));
        assert!(!remove_image(&Store::Shared, ""));
    }

    #[test]
    fn ordinary_podman_commands_remove_daemon_override() {
        let cmd = podman();
        let overrides: Vec<(String, Option<String>)> = cmd
            .get_envs()
            .map(|(name, value)| {
                (
                    name.to_string_lossy().into_owned(),
                    value.map(|v| v.to_string_lossy().into_owned()),
                )
            })
            .collect();
        assert_eq!(
            overrides,
            vec![
                ("DOCKER_HOST".to_owned(), None),
                ("REGISTRY_AUTH_FILE".to_owned(), None),
            ]
        );
    }

    #[test]
    fn registry_pull_uses_only_the_explicit_authfile_and_disables_helpers() {
        let Ok(cmd) = podman_pull_command(
            "ghcr.io/example/app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            Path::new("/worker/tenant/auth.json"),
            &Store::Shared,
        ) else {
            return;
        };
        let env: std::collections::HashMap<_, _> = cmd
            .get_envs()
            .map(|(name, value)| (name.to_string_lossy().into_owned(), value))
            .collect();
        assert_eq!(
            env.get("PATH").copied().flatten(),
            Some(std::ffi::OsStr::new(""))
        );
        assert_eq!(env.get("REGISTRY_AUTH_FILE"), Some(&None));
        assert_eq!(env.get("DOCKER_CONFIG"), Some(&None));
        assert_eq!(env.get("DOCKER_HOST"), Some(&None));
        let args: Vec<_> = cmd.get_args().map(|arg| arg.to_string_lossy()).collect();
        assert!(
            args.windows(2)
                .any(|pair| pair == ["--authfile", "/worker/tenant/auth.json"])
        );
        assert!(args.iter().any(|arg| arg == "pull"));
        assert!(!args.iter().any(|arg| arg.starts_with("--policy")));
        assert!(!args.iter().any(|arg| arg == "--root" || arg == "--runroot"));
    }

    #[test]
    fn a_private_store_is_per_tenant_and_named_on_every_command() {
        let temp = tempfile::tempdir().unwrap();
        let a = Store::private(temp.path(), [0xaa; 16]).unwrap();
        let b = Store::private(temp.path(), [0xbb; 16]).unwrap();
        assert_ne!(a, b);
        let Store::Private { graph, run } = &a else {
            panic!("private");
        };
        assert!(graph.starts_with(temp.path().join(STORES_DIR)));
        assert!(graph.is_dir() && run.is_dir());
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(graph).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o700);
        }
        let args = |cmd: &Command| -> Vec<String> {
            cmd.get_args()
                .map(|a| a.to_string_lossy().into_owned())
                .collect()
        };
        let exec = args(&podman_in(&a));
        assert_eq!(
            exec,
            vec![
                "--root".to_owned(),
                graph.display().to_string(),
                "--runroot".to_owned(),
                run.display().to_string()
            ]
        );
        if let Ok(pull) = podman_pull_command("x@sha256:abc", Path::new("a.json"), &a) {
            let pull = args(&pull);
            assert_eq!(&pull[..4], exec.as_slice(), "global flags precede `pull`");
        }
        let all = Store::all(temp.path());
        assert_eq!(all.len(), 3);
        assert!(all.contains(&Store::Shared) && all.contains(&a) && all.contains(&b));
    }

    #[test]
    fn pull_command_resolves_podman_before_clearing_path() {
        if let Ok(cmd) =
            podman_pull_command("example@sha256:abc", Path::new("auth.json"), &Store::Shared)
        {
            assert!(std::path::Path::new(cmd.get_program()).is_absolute());
        }
    }
}
