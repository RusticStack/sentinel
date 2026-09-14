//! Rootless Podman containers for one attempt each.
//!
//! The baseline the F07 probe proved enforceable, applied to every container:
//! `--cpus`, `--memory` with swap capped at the same value, `--pids-limit`,
//! `--network none`, a read-only root filesystem with a tmpfs `/tmp`, every
//! capability dropped, `no-new-privileges`, and the user namespace rootless
//! Podman gives (uid 0 inside is the worker user outside). The workspace is
//! the only writable bind mount. There is no Docker socket, no privileged
//! flag and nothing a pipeline can set to loosen any of this.
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

fn podman() -> Command {
    let mut cmd = Command::new("podman");
    cmd.env_remove("DOCKER_HOST");
    cmd
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

/// Make `image` (a `name@sha256:…` reference) available locally.
pub fn pull(image: &str, timeout: Duration) -> Result<()> {
    if !image.contains("@sha256:") {
        return Err(Error::Preparation("image is not pinned by digest".into()));
    }
    let mut exists = podman();
    exists.args(["image", "exists", "--", image]);
    if process::run(
        exists,
        deadline(Duration::from_secs(30)),
        "podman image exists",
    )?
    .success()
    {
        return Ok(());
    }
    let mut cmd = podman();
    cmd.args(["pull", "-q", "--", image]);
    let output = process::run(cmd, deadline(timeout), "podman pull")?;
    if output.success() {
        Ok(())
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

/// One running container, created with the limits and torn down whole.
#[derive(Debug)]
pub struct Container {
    name: String,
    attempt: AttemptId,
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

impl Container {
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Create and start the attempt's container with `workspace` mounted at
    /// `/workspace` and a keepalive as its main process. Steps then run in
    /// it with [`Container::exec`]; the image must provide `/bin/sh`.
    pub fn start(
        worker: WorkerId,
        attempt: AttemptId,
        image: &str,
        limits: Limits,
        workspace: &Path,
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
            .arg(format!("{}:{WORKSPACE_MOUNT}", workspace.display()))
            .arg("--")
            .arg(image)
            .args([
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
        let container = Container { name, attempt };
        let mut start = podman();
        start.args(["start", "--", &container.name]);
        let started = process::run(start, deadline(CONTAINER_START_TIMEOUT), "podman start")?;
        if !started.success() {
            let why = started.stderr_excerpt();
            let _ = container.remove();
            return Err(Error::Preparation(format!("container start: {why}")));
        }
        Ok(container)
    }

    /// Run one step inside the container: its argv, its environment (the
    /// worker's `extra` last so a pipeline cannot spoof it), its working
    /// directory under the workspace, its timeout. A timeout stops the
    /// whole container: steps are sequential and the attempt is over.
    pub fn exec(&self, step: &StepCommand, extra: &[(String, String)]) -> Result<Exit> {
        let mut cmd = podman();
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
        match process::run(cmd, deadline(timeout), "step") {
            Ok(output) => Ok(Exit {
                // Podman reports a signal death as 128 + n; 125–127 are the
                // client's own failures, which we surface as-is.
                signal: output.code.filter(|c| *c > 128).map(|c| c - 128),
                code: output.code.filter(|c| *c <= 128),
                timed_out: false,
                stdout: output.stdout,
                stderr: output.stderr,
            }),
            Err(Error::Timeout(_)) => {
                self.stop(Duration::ZERO)?;
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

    /// `podman stop`: TERM to the container's processes, KILL after `grace`.
    pub fn stop(&self, grace: Duration) -> Result<()> {
        let mut cmd = podman();
        cmd.args(["stop", "-t"])
            .arg(grace.as_secs().to_string())
            .args(["--", &self.name]);
        let _ = process::run(cmd, deadline(grace + STOP_TIMEOUT), "podman stop")?;
        Ok(())
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

    /// Stop and remove. Nothing of the attempt survives in the runtime.
    pub fn destroy(self) -> Result<()> {
        self.stop(Duration::from_secs(2))?;
        self.remove()
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
    }
    .remove()
}
