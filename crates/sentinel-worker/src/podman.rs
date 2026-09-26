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

/// `DOCKER_HOST` is removed so a stray daemon address cannot redirect a
/// rootless operation. The pull path also removes auth-file overrides.
fn podman() -> Command {
    let mut cmd = Command::new("podman");
    cmd.env_remove("DOCKER_HOST");
    cmd.env_remove("REGISTRY_AUTH_FILE");
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

fn podman_pull_command(image: &str, authfile: &Path) -> Result<Command> {
    let mut cmd = podman_for_pull()?;
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

/// Make `image` (a `name@sha256:…` reference) available locally.
/// The returned bool is whether `podman image exists` found the digest
/// before the pull (`image_present`); the explicit pull still runs with
/// the attempt's auth file so resident layers cannot bypass authorization.
/// `cancel` kills a pull under way.
pub fn pull(
    image: &str,
    authfile: &Path,
    timeout: Duration,
    cancel: &std::sync::atomic::AtomicBool,
) -> Result<bool> {
    if !image.contains("@sha256:") {
        return Err(Error::Preparation("image is not pinned by digest".into()));
    }
    let mut exists = podman();
    exists.args(["image", "exists", "--", image]);
    let present = process::run(
        exists,
        deadline(Duration::from_secs(30)),
        "podman image exists",
    )?
    .success();
    let cmd = podman_pull_command(image, authfile)?;
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
fn inspect_named(name: &str) -> Result<(Option<i32>, Option<std::path::PathBuf>)> {
    let mut inspect = podman();
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
    const MAX_DEPTH: usize = 8;
    const MAX_CGROUPS: usize = 256;
    let mut pids = Vec::new();
    let mut pending = vec![(cgroup.to_path_buf(), 0usize)];
    let mut seen = 0;
    while let Some((dir, depth)) = pending.pop() {
        seen += 1;
        if let Ok(text) = std::fs::read_to_string(dir.join("cgroup.procs")) {
            pids.extend(
                text.lines()
                    .filter_map(|l| l.trim().parse::<i32>().ok())
                    .filter(|pid| Some(*pid) != init),
            );
        }
        if depth >= MAX_DEPTH {
            continue;
        }
        if let Ok(entries) = std::fs::read_dir(&dir) {
            for entry in entries.flatten() {
                if seen + pending.len() >= MAX_CGROUPS {
                    break;
                }
                if entry.file_type().is_ok_and(|t| t.is_dir()) {
                    pending.push((entry.path(), depth + 1));
                }
            }
        }
    }
    pids
}

/// Graceful then forced termination of a container by name (W06): `SIGTERM`
/// to every step process in the container's cgroup — the keepalive is
/// spared so the container stays up for the signal to be handled — then,
/// if any is still there after `grace`, `podman stop -t 0` and removal.
/// Rootless: the processes are the worker account's, so the signal needs
/// no privilege.
pub fn terminate_named(name: &str, grace: Duration) -> Result<Terminated> {
    let (init, cgroup) = match inspect_named(name) {
        Ok(found) => found,
        Err(_) => return Ok(Terminated::Gone),
    };
    let Some(cgroup) = cgroup else {
        remove_named(name)?;
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
    remove_named(name)?;
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
    /// The last non-empty stderr line, printable characters only.
    pub fn stderr_excerpt(&self) -> String {
        let text = String::from_utf8_lossy(&self.stderr);
        text.lines()
            .rev()
            .find(|l| !l.trim().is_empty())
            .unwrap_or("no diagnostic output")
            .chars()
            .filter(|c| !c.is_control())
            .take(200)
            .collect()
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
    pub fn start(
        worker: WorkerId,
        attempt: AttemptId,
        image: &str,
        limits: Limits,
        workspace: &Path,
        mounts: &[Mount],
    ) -> Result<Container> {
        let name = format!("sentinel-{attempt}");
        let mut cmd = podman();
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
        };
        let mut start = podman();
        start.args(["start", "--", &container.name]);
        let started = process::run(start, deadline(CONTAINER_START_TIMEOUT), "podman start")?;
        if !started.success() {
            let why = started.stderr_excerpt();
            let _ = container.remove();
            return Err(Error::Preparation(format!("container start: {why}")));
        }
        if let Ok((init, cgroup)) = inspect_named(&container.name) {
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
    /// is produced, in addition to the bounded tails.
    pub fn exec_streaming(
        &self,
        step: &StepCommand,
        extra: &[(String, String)],
        sink: Option<process::Sink>,
    ) -> Result<Exit> {
        self.exec_streaming_with_env_file(step, extra, None, sink)
    }

    /// Execute with secrets supplied from a short-lived host env file. The
    /// values never appear in Podman's argv or its inherited environment.
    pub fn exec_streaming_with_env_file(
        &self,
        step: &StepCommand,
        extra: &[(String, String)],
        env_file: Option<&Path>,
        sink: Option<process::Sink>,
    ) -> Result<Exit> {
        let mut cmd = podman();
        cmd.args(["exec", "--workdir"]);
        cmd.arg(match &step.workdir {
            Some(dir) => format!("{WORKSPACE_MOUNT}/{dir}"),
            None => WORKSPACE_MOUNT.to_owned(),
        });
        for (k, v) in step.env.iter().chain(extra) {
            cmd.arg("--env").arg(format!("{k}={v}"));
        }
        if let Some(env_file) = env_file {
            cmd.arg("--env-file").arg(env_file);
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
                let mut cmd = podman();
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
        let mut cmd = podman();
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
        let mut cmd = podman();
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
}

/// Every container this worker created that the runtime still knows about,
/// running or not — the ownership record W07 reconciles against.
pub fn owned(worker: WorkerId) -> Result<Vec<(AttemptId, String)>> {
    let mut cmd = podman();
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

/// Remove a container by name, whatever its state: the reaper's tool.
pub fn remove_named(name: &str) -> Result<()> {
    Container {
        name: name.to_owned(),
        attempt: AttemptId::new(),
        cgroup: None,
        init_pid: None,
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
    }

    /// The worker's own registry login must not be able to provide a pull
    /// credential after PATH has been cleared.
    #[test]
    fn pull_command_resolves_podman_before_clearing_path() {
        if let Ok(cmd) = podman_pull_command("example@sha256:abc", Path::new("auth.json")) {
            assert!(std::path::Path::new(cmd.get_program()).is_absolute());
        }
    }
}
