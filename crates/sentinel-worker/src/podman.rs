//! Rootless Podman containers for one attempt each.
//!
//! The baseline the F07 probe proved enforceable, applied to every container:
//! `--cpus`, `--memory` with swap capped at the same value, `--pids-limit`,
//! `--network none`, a read-only root filesystem with a tmpfs `/tmp`, every
//! capability dropped, `no-new-privileges`, and the user namespace rootless
//! Podman gives (uid 0 inside is the worker user outside). The writable bind
//! mounts are the workspace and the attempt's private cache views (K02) —
//! nothing shared, nothing of the host beyond them. There is no Docker
//! socket, no privileged flag and nothing a pipeline can set to loosen any
//! of this.
//!
//! Ownership is tracked by labels: every container is `sentinel-<attempt>`
//! and carries `io.sentinel.worker` and `io.sentinel.attempt`, so what this
//! worker owns can be listed from the runtime after a restart (W07).

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
/// Graceful stop budget before SIGKILL; the keepalive process exits on TERM.
pub const STOP_TIMEOUT: Duration = Duration::from_secs(10);
/// Default process budget per container: enough for any build, small enough
/// that a fork bomb ends inside its cgroup.
pub const DEFAULT_PIDS_LIMIT: u32 = 4096;
/// Where the workspace is mounted inside every container.
pub const WORKSPACE_MOUNT: &str = "/workspace";
pub const LABEL_WORKER: &str = "io.sentinel.worker";
pub const LABEL_ATTEMPT: &str = "io.sentinel.attempt";

/// The runtime as probed at start. Rootless is required, not preferred.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Runtime {
    pub version: String,
    pub oci_runtime: String,
    pub cgroup_version: String,
    pub cgroup_manager: String,
}

/// Where an image and the containers made from it live (P10D-5).
///
/// containers/image reuses a layer already present in the store it pulls
/// into without fetching it from the source registry: an authorized pull
/// is checked per manifest, not per layer. A tenant that replays another
/// tenant's manifest and config from a registry of its own would then get
/// that tenant's private layers out of a shared store. So an image pulled
/// with a tenant's `registry_auth` goes to that tenant's own store, and the
/// shared store only ever receives anonymously pulled — public — layers.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Store {
    /// The worker account's default rootless store.
    Shared,
    /// One tenant's private store: `--root`/`--runroot` on every command.
    Private {
        graph: std::path::PathBuf,
        run: std::path::PathBuf,
    },
}

/// Private stores live under `<data_dir>/image-stores/<tenant>/graph`,
/// their run roots under the worker's runtime directory.
pub const STORES_DIR: &str = "image-stores";

impl Store {
    /// `tenant`'s private store under the worker data directory `root`,
    /// created owner-only on first use.
    pub fn private(root: &Path, tenant: [u8; 16]) -> Result<Store> {
        let name: String = tenant.iter().map(|b| format!("{b:02x}")).collect();
        let store = Store::Private {
            graph: root.join(STORES_DIR).join(&name).join("graph"),
            run: crate::runtime_dir(root).join("stores").join(&name),
        };
        if let Store::Private { graph, run } = &store {
            for dir in [graph, run] {
                private_dirs(dir)?;
            }
        }
        Ok(store)
    }

    /// The shared store and every private one this data directory holds —
    /// what restart reconciliation lists containers in. Bounded by
    /// `MAX_LIST_ITEMS` stores.
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
                    stores.push(Store::Private {
                        graph: entry.path().join("graph"),
                        run: crate::runtime_dir(root).join("stores").join(name),
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

/// Create `dir` and its missing parents owner-only; an existing component
/// that is a symlink or not a directory is refused.
fn private_dirs(dir: &Path) -> Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)?;
    let meta = std::fs::symlink_metadata(dir)?;
    if !meta.is_dir() || meta.file_type().is_symlink() {
        return Err(Error::Preparation("image store directory".into()));
    }
    Ok(())
}

/// `DOCKER_HOST` is removed so a stray daemon address cannot redirect a
/// rootless operation. The pull path also removes auth-file overrides.
fn podman() -> Command {
    let mut cmd = Command::new("podman");
    cmd.env_remove("DOCKER_HOST");
    cmd.env_remove("REGISTRY_AUTH_FILE");
    cmd
}

/// [`podman`] against `store`.
fn podman_in(store: &Store) -> Command {
    let mut cmd = podman();
    store.apply(&mut cmd);
    cmd
}

/// Find the executable before `pull` clears PATH. The containers/image
/// credential-helper lookup uses PATH, so leaving it populated would let a
/// host-wide helper authorize a tenant's pull outside its scoped auth file.
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

/// A pull is authorized solely by its explicit auth file. Keeping external
/// credential-helper binaries off the subprocess PATH prevents worker-wide
/// helper credentials from overriding the tenant-scoped file.
fn podman_for_pull() -> Result<Command> {
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

/// Ask the runtime what it is; refuse anything but rootless Podman on
/// cgroup v2, because the limits above are only known to hold there.
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

/// Where the image store keeps its layers (`GraphRoot`): the filesystem a
/// prefetch's disk reserve is measured on.
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

/// Bytes `image` takes in the local store (`podman image inspect`'s
/// `Size`), `None` when it is not there or cannot be read.
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

/// Make `image` (a `name@sha256:…` reference) available in `store`.
/// The returned bool is whether `podman image exists` found the digest
/// before the pull (`image_present`); the explicit pull still runs with
/// the attempt's auth file so a resident manifest cannot bypass
/// authorization. Resident *layers* are reused by the runtime without a
/// fetch, which is why a credentialed pull goes to the tenant's private
/// [`Store`]. `cancel` kills a pull under way.
pub fn pull(
    image: &str,
    authfile: &Path,
    store: &Store,
    timeout: Duration,
    cancel: &std::sync::atomic::AtomicBool,
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
    let cmd = podman_pull_command(image, authfile, store)?;
    // Even a resident digest must pass the registry's current authorization
    // check for this tenant before a container can use it.
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

/// The job's budget, from its compiled resources.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    pub cpu_millis: u32,
    pub memory_bytes: u64,
    pub pids: u32,
}

/// One extra writable bind mount: `host` appears at `container`. Cache
/// entries that declare an absolute path use it (K02) — the workspace
/// mount already covers every relative path, so nothing else asks.
#[derive(Clone, Debug)]
pub struct Mount {
    /// The host directory bound in; must exist.
    pub host: std::path::PathBuf,
    /// The absolute path the container sees (`/cache`, …).
    pub container: String,
    /// Secret mounts are read-only; cache mount views remain writable.
    pub read_only: bool,
}

/// One running container, created with the limits and torn down whole.
#[derive(Debug)]
pub struct Container {
    name: String,
    attempt: AttemptId,
    /// The container's cgroup on the host (`/sys/fs/cgroup<path>`), read
    /// after start so its counters can be inspected without placing a
    /// process inside a cgroup that may already be at its limit.
    cgroup: Option<std::path::PathBuf>,
    /// Host pid of the container's keepalive, spared by a graceful stop.
    init_pid: Option<i32>,
    /// The store the container (and its image) lives in.
    store: Store,
}

/// How a termination ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Terminated {
    /// Every step process left within the grace period after `SIGTERM`.
    Graceful,
    /// The grace period passed; the container was stopped and removed.
    Forced,
    /// Nothing was running any more.
    Gone,
}

/// Inspect a container by name: (host pid of its init, host cgroup path).
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

/// Host pids of every process in the container's cgroup — and in every
/// cgroup nested under it, where a runtime may place the exec'd step —
/// except its init. The walk is bounded in depth and in directories.
fn step_pids(cgroup: &std::path::Path, init: Option<i32>) -> Vec<i32> {
    cgroup_pids(cgroup, init).0
}

/// [`step_pids`], and whether the walk saw the whole tree: `false` when a
/// bound cut it short or a `cgroup.procs` could not be read, so a caller
/// that must know the container is empty can refuse to trust the list.
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
            // A cgroup removed under the walk — or the whole container's,
            // once it is gone — has no processes.
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

/// Whether `pid` has exited and only waits to be reaped (or is gone): a
/// zombie holds no memory, environment or open file any more.
fn exited(pid: i32) -> bool {
    let Ok(stat) = std::fs::read(format!("/proc/{pid}/stat")) else {
        return true;
    };
    // `pid (comm) S …`: the state follows the last `)`, as comm may hold one.
    let Some(close) = stat.iter().rposition(|b| *b == b')') else {
        return false;
    };
    matches!(stat.get(close + 2), Some(b'Z' | b'X'))
}

/// How long clearing a container of stray processes may take before the
/// secret step it guards is refused.
pub const CLEAR_TIMEOUT: Duration = Duration::from_secs(5);

/// Graceful then forced termination of a container by name (W06): `SIGTERM`
/// to every step process in the container's cgroup — the keepalive is
/// spared so the container stays up for the signal to be handled — then,
/// if any is still there after `grace`, `podman stop -t 0` and removal.
/// Rootless: the processes are the worker account's, so the signal needs
/// no privilege.
pub fn terminate_named(name: &str, store: &Store, grace: Duration) -> Result<Terminated> {
    let (init, cgroup) = match inspect_named(name, store) {
        Ok(found) => found,
        Err(_) => return Ok(Terminated::Gone),
    };
    let Some(cgroup) = cgroup else {
        remove_named(name, store)?;
        return Ok(Terminated::Forced);
    };
    let pids = step_pids(&cgroup, init);
    if pids.is_empty() {
        return Ok(Terminated::Gone);
    }
    for pid in &pids {
        // SAFETY: a plain signal to a pid we just read from the container's
        // own cgroup; a pid that exited meanwhile makes kill fail harmlessly.
        unsafe {
            libc::kill(*pid, libc::SIGTERM);
        }
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

/// How one step's process ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Exit {
    /// Exit status; `None` when the process was killed by a signal.
    pub code: Option<i32>,
    /// The signal number when killed, decoded from Podman's `128 + n`.
    pub signal: Option<i32>,
    /// The step ran past its timeout and the container was stopped.
    pub timed_out: bool,
    /// Bounded tails of the process's output.
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
    /// The last non-empty stderr line, printable characters only, **not
    /// redacted**: a step's own failure detail goes through the attempt's
    /// [`crate::attempt::Output::excerpt`] instead.
    pub fn stderr_excerpt(&self) -> String {
        crate::redact::excerpt(&self.stderr)
    }
}

impl Container {
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Create and start the attempt's container with `workspace` mounted at
    /// `/workspace` and a keepalive as its main process. Steps then run in
    /// it with [`Container::exec`]; the image must provide `/bin/sh`.
    /// `mounts` are extra writable binds (cache paths declared absolute);
    /// a mount whose `container` is not absolute makes `create` fail.
    #[allow(clippy::too_many_arguments)]
    pub fn start(
        worker: WorkerId,
        attempt: AttemptId,
        image: &str,
        limits: Limits,
        workspace: &Path,
        mounts: &[Mount],
        store: &Store,
    ) -> Result<Container> {
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
            .args([
                "--network",
                "none",
                "--read-only",
                "--tmpfs",
                "/tmp:rw,nosuid,nodev,size=1g",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges",
                // No core dumps (P10D-9): a crashing step would otherwise
                // hand its memory — delivered secrets included — to the
                // host's core handler. Soft and hard, so nothing inside
                // can raise it back.
                "--ulimit",
                "core=0:0",
                "--workdir",
                WORKSPACE_MOUNT,
                "--pull",
                "never",
            ])
            .arg("--volume")
            .arg(format!("{}:{WORKSPACE_MOUNT}", workspace.display()));
        for mount in mounts {
            cmd.arg("--volume").arg(format!(
                "{}:{}:{}",
                mount.host.display(),
                mount.container,
                if mount.read_only { "ro" } else { "rw" }
            ));
        }
        cmd.arg("--").arg(image).args([
            "/bin/sh",
            "-c",
            "trap 'exit 0' TERM INT; while :; do sleep 1; done",
        ]);
        let created = process::run(cmd, deadline(CONTAINER_START_TIMEOUT), "podman create")?;
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
        let mut start = podman_in(store);
        start.args(["start", "--", &container.name]);
        let started = process::run(start, deadline(CONTAINER_START_TIMEOUT), "podman start")?;
        if !started.success() {
            let why = started.stderr_excerpt();
            let _ = container.remove();
            return Err(Error::Preparation(format!("container start: {why}")));
        }
        if let Ok((init, cgroup)) = inspect_named(&container.name, store) {
            container.init_pid = init;
            container.cgroup = cgroup.filter(|c| c.join("memory.events").exists());
        }
        Ok(container)
    }

    /// Run one step inside the container: its argv, its environment (the
    /// worker's `extra` last so a pipeline cannot spoof it), its working
    /// directory under the workspace, its timeout. A timeout stops the
    /// whole container: steps are sequential and the attempt is over.
    pub fn exec(&self, step: &StepCommand, extra: &[(String, String)]) -> Result<Exit> {
        self.exec_streaming(step, extra, None)
    }

    /// [`Container::exec`] with the step's output streamed to `sink` as it
    /// is produced, in addition to the bounded tails. Secret environment
    /// values never pass through here: Podman would write them into the
    /// exec session's spec on disk (P10D-8). The attempt delivers them in
    /// a file on the step's private mount instead and wraps `argv`.
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
                // Podman reports a signal death as 128 + n; 125–127 are the
                // client's own failures, which we surface as-is.
                signal: output.code.filter(|c| *c > 128).map(|c| c - 128),
                code: output.code.filter(|c| *c <= 128),
                timed_out: false,
                stdout: std::mem::take(&mut output.stdout),
                stderr: std::mem::take(&mut output.stderr),
            }),
            Err(Error::Timeout(_)) => {
                // The step is over either way; a stop that fails here is
                // settled by the teardown's forced removal.
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

    /// The cgroup's OOM-kill counter, compared before and after a failed
    /// step to tell a memory kill from any other death by `SIGKILL`. Read
    /// from the host's view of the cgroup: after an OOM the pages that
    /// caused it (a tmpfs, say) stay charged, and a process exec'd inside
    /// to read the counter could be the next victim.
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

    /// `podman stop`: TERM to the container's processes, KILL after `grace`.
    /// A stop the runtime refused or that timed out is an error.
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

    /// Stop and remove. Nothing of the attempt survives in the runtime:
    /// the removal (`rm -f`, which kills what is left) runs even when the
    /// graceful stop failed or timed out, and the first failure is what is
    /// returned.
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

    /// Kill every process in the container but its keepalive, and wait
    /// until none is left (P10D-1). All steps run as one user in one PID
    /// namespace, so a process an earlier step left running — a daemon, a
    /// `setsid` watcher — could read a later step's environment through
    /// `/proc` or its files under the secret mount. The attempt clears the
    /// container before it materializes a step's secrets and again when
    /// that step ends, which is what makes secrets step-scoped.
    ///
    /// Host-side, no exec: the cgroup is frozen so nothing can fork or exit
    /// (and free its pid for reuse) between listing and signalling, every
    /// process but the keepalive gets `SIGKILL` — which reaches frozen tasks
    /// — and the cgroup is thawed. A process that already exited and only
    /// awaits its reaper counts as gone. Refused (fail closed) when the
    /// cgroup is not visible, the tree is past the walk's bounds, or the
    /// container is not empty within [`CLEAR_TIMEOUT`].
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

/// Freeze (or thaw) a cgroup v2 subtree and wait until the kernel says it
/// is; `false` when the freezer could not be used or did not settle.
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

/// Every container this worker created in the shared store that the
/// runtime still knows about, running or not.
pub fn owned(worker: WorkerId) -> Result<Vec<(AttemptId, String)>> {
    owned_in(worker, &Store::Shared)
}

/// [`owned`] in `store` — the ownership record W07 reconciles against,
/// asked of every store the data directory holds.
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

/// Remove a container by name from `store`, whatever its state: the
/// reaper's tool.
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

    /// Ordinary Podman commands remove only the daemon override. Pulls use
    /// an explicit per-attempt auth file and a cleared PATH, so neither
    /// environment auth overrides nor host credential helpers can provide
    /// worker-wide credentials.
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
            // Portable checks need not have Podman installed.
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
        // The shared store takes no store flags.
        assert!(!args.iter().any(|arg| arg == "--root" || arg == "--runroot"));
    }

    /// P10D-5: a credentialed pull and every later command on its
    /// container name the tenant's private store, whose graph root lives
    /// under the data directory and whose run root under the runtime one;
    /// two tenants never share one.
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
        // Reconciliation finds both private stores and the shared one.
        let all = Store::all(temp.path());
        assert_eq!(all.len(), 3);
        assert!(all.contains(&Store::Shared) && all.contains(&a) && all.contains(&b));
    }

    /// The worker's own registry login must not be able to provide a pull
    /// credential after PATH has been cleared.
    #[test]
    fn pull_command_resolves_podman_before_clearing_path() {
        if let Ok(cmd) =
            podman_pull_command("example@sha256:abc", Path::new("auth.json"), &Store::Shared)
        {
            assert!(std::path::Path::new(cmd.get_program()).is_absolute());
        }
    }
}
