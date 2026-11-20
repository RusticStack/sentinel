//! Runner mode's sandbox on a worker (AR03's start, AR09's guarantees): one ephemeral GitHub Actions
//! runner, in one container, with the just-in-time configuration GitHub issued for it.
//!
//! The configuration is a credential and this module is where it is spent. It never reaches a
//! command line, an environment listing, a host file or the job's workspace: it is written to the
//! runner's standard input, and the image's entry point ([`START`]) reads one line of it into a
//! tmpfs inside the container ([`CONFIG_MOUNT`]) that no host path backs, then execs the runner with
//! `--jitconfig`. Nothing on the host can read it, and the container is removed with it.
//!
//! The sandbox is what makes the rest of AR09 true:
//!
//! - **One runner per job.** The configuration is single-use at GitHub and at the store, and the
//!   container runs the runner with `--ephemeral`, so the runner takes one job and exits by itself.
//!   Killing it is therefore always safe: the job cannot come back to it.
//! - **Nothing writable survives.** The image's root filesystem is read-only, every writable path
//!   is a tmpfs or the scratch directory this module makes under the worker's data root, and
//!   [`Plan::destroy`] removes the container and that directory. A worker that died leaves a named
//!   container whose keepalive ends it and `--rm` removes it, plus one directory under the worker's
//!   data root for the sweep to find; neither holds the configuration.
//! - **No route to the host.** A granted egress is the operator's (`job_network = "egress"`), and
//!   even then the container's namespace gets nftables refusals installed before the runner starts
//!   (`rules_for`): the host's own addresses, loopback off `lo`, link-local and cloud metadata
//!   addresses, and the controller's link endpoint by address and port. Failing to install them
//!   fails the start rather than running without them.
//! - **No Actions secrets.** Sentinel asks GitHub for the runner's configuration and nothing else;
//!   the image's environment and this sandbox carry no secret, so a job's secrets exist only inside
//!   the runner process for the job's life ([docs](../../../docs/runner-mode.md#actions-secrets-are-githubs)).

use std::{
    fmt::Write as _,
    fs,
    net::Ipv4Addr,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

use sentinel_core::{RunnerLeaseId, WorkerId};

use crate::{
    Error, Result,
    microvm::net,
    podman::{self, LABEL_WORKER, Limits, Network},
    process, workspace,
};

/// The label every runner container carries, beside [`LABEL_WORKER`].
pub const LABEL_RUNNER: &str = "io.sentinel.runner";

/// Where the runner works inside its container. A job's checkout, its caches and its build output
/// are this container's own: mounted from a directory of this lease that [`Plan::destroy`] removes.
pub const WORK_MOUNT: &str = "/home/runner/_work";

/// Where the runner writes its diagnostics. A tmpfs, sized to hold a day of the runner's own logs
/// without becoming a host file: Sentinel captures no job output, so nothing here should survive.
pub const DIAG_MOUNT: &str = "/home/runner/_diag";
pub const DIAG_BYTES: u64 = 64 << 20;

/// The tmpfs the configuration is read into, inside the container and nowhere else. It is 0700,
/// `noexec` and unmounted when the container goes, so the credential outlives neither.
pub const CONFIG_MOUNT: &str = "/runner";
pub const CONFIG_BYTES: u64 = 128 * 1024;

/// The image's entry point: read one line of the encoded configuration from standard input into
/// [`CONFIG_MOUNT`], unlink it, and exec the runner as `run.sh --jitconfig <config> --ephemeral`, so
/// the runner takes one job and exits. The flags are the image's contract (AR05); the worker never
/// passes the configuration as an argument.
pub const START: &str = "/usr/local/bin/sentinel-runner";

/// Where a sandbox's cache and artifact endpoint lives inside it: the anchor a client's Node runtime is
/// told about, and the two names it answers. The clients dial 443, so that is the port the endpoint
/// serves on the address the operator states.
pub use sentinel_actions::ca::{CA_ENV, CA_PATH};

/// The port the pinned clients dial: `https://<host>/` with no port stated is 443.
pub const ACTIONS_PORT: u16 = 443;

/// How many addresses one worker's block may hold runners at once: one listener serves one boundary,
/// so the block needs one address per concurrent sandbox, starting at the stated one.
pub const ACTIONS_ADDRESSES: u8 = 16;

/// The pids one runner container may have: the runner, a step's shell and what a step forks.
pub const PIDS: u32 = 4096;

/// The least memory a runner lease may reserve: below this the runner itself, let alone a job, does
/// not fit, so the offer is declined rather than accepted and then failed.
pub const MIN_MEMORY_BYTES: u64 = 1 << 30;

/// The bound on one runner's life when the caller states none: a sandbox nobody hands work to is
/// also retired by the controller's idle bound, so this is the backstop for a controller that
/// stopped, not the scheduling policy.
pub const MAX_LIFETIME_SECS: u64 = 6 * 60 * 60;

/// How long the container has to be created and started.
pub const CREATE_TIMEOUT: Duration = Duration::from_secs(60);
const STOP_TIMEOUT: Duration = Duration::from_secs(10);

/// The largest configuration a runner is started with, the same bound the link's frame carries.
pub const MAX_CONFIG_BYTES: usize = sentinel_link::session::MAX_RUNNER_CONFIG_BYTES;

const KEEPALIVE: &str =
    "trap 'exit 0' TERM INT; n=$1; while [ \"$n\" -gt 0 ]; do sleep 1; n=$((n-1)); done";

/// The runner image, pinned by digest: what a worker states it starts runners from, and nothing a
/// repository can influence. A tag alone is refused, because the same tag is a different image
/// tomorrow and a runner image is the code the job's steps run under.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Image(String);

impl Image {
    /// A `registry/repository@sha256:<64 hex>` reference, or `None`. The digest is what is checked:
    /// a reference without one names whatever the registry serves today.
    pub fn parse(reference: &str) -> Option<Image> {
        let (name, digest) = reference.split_once('@')?;
        let hex = digest.strip_prefix("sha256:")?;
        let named = !name.is_empty()
            && name.len() <= 255
            && !name.bytes().any(|b| b < 33 || b == 127)
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._/:@-+".contains(&b));
        (named && hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit()))
            .then(|| Image(reference.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// What a worker states about the runners it starts: the image, and the endpoints its own sandboxes
/// must never reach. An absent image is a worker that serves no runner at all, which is the default.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Policy {
    pub image: Option<Image>,
    pub guard: net::Guard,
    /// The address a sandbox reaches this worker's cache and artifact endpoint on, as the operator
    /// states it (the sandbox network's host address). Absent, this worker declines every runner lease:
    /// a runner whose cache and artifacts would silently go to GitHub's storage is not one AR06 serves.
    pub actions: Option<Ipv4Addr>,
}

impl Policy {
    /// Whether this worker may take an offer of that reservation. A worker that states no image
    /// starts no runner, and one whose lease reserves less memory than a runner itself needs would
    /// only fail after GitHub had registered it, so both are declined before anything is asked for.
    pub fn admits(&self, cpu_millis: u64, memory_bytes: u64) -> bool {
        self.image.is_some()
            && self.actions.is_some()
            && cpu_millis > 0
            && u32::try_from(cpu_millis).is_ok()
            && memory_bytes >= MIN_MEMORY_BYTES
    }
}

/// One runner sandbox as it is built and then torn down. The plan is data: it touches no filesystem
/// until it is staged, so a configuration that cannot be used costs nothing.
#[derive(Debug)]
pub struct Plan {
    name: String,
    dir: PathBuf,
    args: Vec<String>,
    rules: Option<String>,
    lifetime_secs: u64,
}

/// What one sandbox is told about its cache and artifact endpoint: the address to resolve the two
/// service hosts to, and the anchor file on the host that the sandbox mounts read-only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Actions {
    pub address: Ipv4Addr,
    pub anchor: PathBuf,
}

/// What the worker grants one sandbox: the network its operator gave it, the endpoints it must never
/// reach, and the cache and artifact endpoint (if any) it is served from.
pub struct Grant<'a> {
    pub network: Network,
    pub guard: &'a net::Guard,
    pub actions: Option<&'a Actions>,
}

impl Actions {
    /// Where this sandbox's anchor is staged: under the lease's own directory, so the sandbox's
    /// teardown removes it with everything else it wrote.
    pub fn anchor_of(dir: &Path) -> PathBuf {
        dir.join("ca.crt")
    }
}

impl Plan {
    /// The sandbox one lease gets. `network` is the worker's operator decision; `guard` is what its
    /// own endpoints are.
    pub fn new(
        root: &Path,
        worker: WorkerId,
        lease: RunnerLeaseId,
        image: &Image,
        limits: Limits,
        grant: &Grant<'_>,
    ) -> Result<Plan> {
        let Grant {
            network,
            guard,
            actions,
        } = *grant;
        let name = container_name(lease);
        let dir = dir_of(root, lease);
        let lifetime_secs = match limits.lifetime_secs {
            0 => MAX_LIFETIME_SECS,
            secs => secs.min(MAX_LIFETIME_SECS),
        };
        let pids = if limits.pids == 0 { PIDS } else { limits.pids };
        let mut args = Vec::with_capacity(32);
        let text = |args: &mut Vec<String>, value: String| args.push(value);
        text(&mut args, "create".to_owned());
        text(&mut args, "--name".to_owned());
        text(&mut args, name.clone());
        for label in [
            format!("{LABEL_WORKER}={worker}"),
            format!("{LABEL_RUNNER}={}", hex16(lease)),
        ] {
            text(&mut args, "--label".to_owned());
            text(&mut args, label);
        }
        for (flag, value) in [
            (
                "--cpus",
                format!(
                    "{}.{:03}",
                    limits.cpu_millis / 1000,
                    limits.cpu_millis % 1000
                ),
            ),
            ("--memory", format!("{}b", limits.memory_bytes)),
            ("--memory-swap", format!("{}b", limits.memory_bytes)),
            ("--pids-limit", pids.to_string()),
            ("--network", network_argument(network).to_owned()),
        ] {
            text(&mut args, flag.to_owned());
            text(&mut args, value);
        }
        for pair in [
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--ulimit",
            "core=0:0",
            "--interactive",
            "--rm",
            "--pull",
            "never",
            "--workdir",
            WORK_MOUNT,
            "--entrypoint",
            "/bin/sh",
        ] {
            text(&mut args, pair.to_owned());
        }
        if limits.disk_bytes > 0 {
            text(&mut args, "--ulimit".to_owned());
            text(&mut args, format!("fsize={0}:{0}", limits.disk_bytes));
        }
        for tmpfs in [
            format!("{CONFIG_MOUNT}:rw,nosuid,nodev,noexec,mode=0700,size={CONFIG_BYTES}"),
            format!("{DIAG_MOUNT}:rw,nosuid,nodev,size={DIAG_BYTES}"),
        ] {
            text(&mut args, "--tmpfs".to_owned());
            text(&mut args, tmpfs);
        }
        text(&mut args, "--volume".to_owned());
        text(
            &mut args,
            format!("{}:{WORK_MOUNT}:rw", work_dir(&dir).display()),
        );
        if let Some(actions) = actions {
            // The two service names resolve to this worker and nothing else does: `/etc/hosts` is
            // the sandbox's own, so GitHub's other hosts keep their own answers.
            for host in sentinel_actions::HOSTS {
                text(&mut args, "--add-host".to_owned());
                text(&mut args, format!("{host}:{}", actions.address));
            }
            // The anchor is this sandbox's alone: a read-only file in this container, and a path the
            // clients' Node runtime appends to its own roots. It is a path, never a secret, so the
            // container still carries no secret of ours in its environment.
            text(&mut args, "--volume".to_owned());
            text(
                &mut args,
                format!("{}:{CA_PATH}:ro", actions.anchor.display()),
            );
            text(&mut args, "--env".to_owned());
            text(&mut args, format!("{CA_ENV}={CA_PATH}"));
        }
        text(&mut args, "--".to_owned());
        text(&mut args, image.as_str().to_owned());
        for arg in ["-c", KEEPALIVE, "sentinel-runner-keepalive"] {
            text(&mut args, arg.to_owned());
        }
        text(&mut args, lifetime_secs.to_string());
        let rules = match network {
            Network::Egress => Some(rules_for_guard(guard, actions.map(|a| a.address))?),
            Network::None => None,
        };
        Ok(Plan {
            name,
            dir,
            args,
            rules,
            lifetime_secs,
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn args(&self) -> &[String] {
        &self.args
    }

    pub fn lifetime_secs(&self) -> u64 {
        self.lifetime_secs
    }

    /// Whether this sandbox installs refusals before its runner starts, which is the same question
    /// as whether the worker granted it egress.
    pub fn guarded(&self) -> bool {
        self.rules.is_some()
    }

    /// Makes the scratch directory and, for a sandbox with egress, its rules. Idempotent: a stage
    /// interrupted by a worker crash is finished by the next one.
    pub fn stage(&self) -> Result<()> {
        let work = work_dir(&self.dir);
        for dir in [&self.dir, &work] {
            fs::create_dir_all(dir).map_err(|e| Error::Preparation(format!("runner dir: {e}")))?;
            fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
                .map_err(|e| Error::Preparation(format!("runner dir: {e}")))?;
        }
        if let Some(rules) = &self.rules {
            let path = self.dir.join("egress.nft");
            fs::write(&path, rules)
                .map_err(|e| Error::Preparation(format!("runner rules: {e}")))?;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
                .map_err(|e| Error::Preparation(format!("runner rules: {e}")))?;
        }
        Ok(())
    }

    /// Creates the sandbox, installs what confines it and starts the runner with `config` on its
    /// standard input. Returns when the runner exits, which for an ephemeral runner is its one job.
    ///
    /// The container's own process is a keepalive: the runner is an `exec` into it, so the refusals
    /// can be installed between the two, and a cancel stops the runner's process group.
    pub fn start(&self, config: &[u8], cancel: &AtomicBool) -> Result<Exit> {
        if config.is_empty() || config.len() > MAX_CONFIG_BYTES {
            return Err(Error::Preparation("runner configuration".into()));
        }
        self.stage()?;
        let store = podman::Store::Shared;
        let mut create = podman::podman_in(&store);
        create.args(&self.args);
        let created = process::run_canceled(
            create,
            deadline(CREATE_TIMEOUT),
            "runner create",
            None,
            Some(cancel),
        )
        .and_then(|out| {
            if out.success() {
                Ok(())
            } else {
                Err(Error::Preparation(format!(
                    "runner create: {}",
                    out.stderr_excerpt()
                )))
            }
        });
        if let Err(e) = created {
            // The runtime may have made the container before a timed-out or canceled client left.
            let _ = self.remove();
            return Err(e);
        }
        // The container's own process is a keepalive that touches nothing, so the refusals are
        // installed into its namespace between the start and the runner's exec: a job never runs
        // with egress whose policy is not in place, and a policy that cannot be installed fails the
        // start rather than being skipped.
        let started = {
            let mut start = podman::podman_in(&store);
            start.args(["start", "--", &self.name]);
            process::run_canceled(
                start,
                deadline(CREATE_TIMEOUT),
                "runner start",
                None,
                Some(cancel),
            )
            .and_then(|out| {
                if out.success() {
                    Ok(())
                } else {
                    Err(Error::Preparation(format!(
                        "runner start: {}",
                        out.stderr_excerpt()
                    )))
                }
            })
            .and_then(|()| self.guard(&store, cancel))
        };
        if let Err(e) = started {
            let _ = self.remove();
            return Err(e);
        }
        let mut exec = podman::podman_in(&store);
        exec.args(["exec", "--interactive", "--", &self.name, START]);
        let outcome = process::run_canceled_input(
            exec,
            deadline(Duration::from_secs(self.lifetime_secs)),
            "runner",
            config,
            Some(cancel),
        );
        let removed = self.remove();
        let out = outcome?;
        removed?;
        Ok(Exit {
            code: out.code,
            canceled: cancel.load(Ordering::Acquire),
        })
    }

    /// Removes the container and everything the sandbox made writable. A container the runtime no
    /// longer knows is the outcome `--rm` already produced, not a leak.
    pub fn destroy(&self) -> Result<()> {
        self.remove()?;
        workspace::remove_tree(&self.dir)
    }

    fn remove(&self) -> Result<()> {
        let store = podman::Store::Shared;
        // `--rm` removes the container when its keepalive ends, so "no such container" is the
        // expected answer for a runner that finished, and a real failure is what is left.
        if podman::remove_named(&self.name, &store).is_ok() || absent(&self.name, &store) {
            return Ok(());
        }
        Err(Error::Runtime(format!(
            "the runner container {} could not be removed",
            self.name
        )))
    }

    /// Puts the refusals into the container's namespace before anything in it can reach out.
    fn guard(&self, store: &podman::Store, cancel: &AtomicBool) -> Result<()> {
        let Some(_) = self.rules else {
            return Ok(());
        };
        let pid = self.init_pid(store)?;
        let mut cmd = podman::unshare_command();
        cmd.args(["nsenter", "--net"])
            .arg(format!("/proc/{pid}/ns/net"))
            .args(["nft", "-f"])
            .arg(self.dir.join("egress.nft"));
        let out = process::run_canceled(
            cmd,
            deadline(CREATE_TIMEOUT),
            "runner rules",
            None,
            Some(cancel),
        )?;
        if out.success() {
            Ok(())
        } else {
            Err(Error::Preparation(format!(
                "runner rules were not installed: {}",
                out.stderr_excerpt()
            )))
        }
    }

    fn init_pid(&self, store: &podman::Store) -> Result<i32> {
        let mut cmd = podman::podman_in(store);
        cmd.args(["inspect", "--format", "{{.State.Pid}}", "--", &self.name]);
        let out = process::run(cmd, deadline(CREATE_TIMEOUT), "runner inspect")?;
        let pid = String::from_utf8_lossy(&out.stdout)
            .trim()
            .parse::<i32>()
            .ok()
            .filter(|pid| *pid > 0);
        pid.ok_or_else(|| Error::Runtime(format!("runner inspect: {}", out.stderr_excerpt())))
    }
}

/// What one runner's process ended with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Exit {
    pub code: Option<i32>,
    pub canceled: bool,
}

impl Exit {
    /// Whether the runner took its one job and ended by itself.
    pub fn completed(self) -> bool {
        !self.canceled && self.code.is_some()
    }
}

/// Whether the runtime reports that no container of this name exists (`podman container exists`
/// exits 1); any other answer counts as still there, so a real failure is never hidden.
fn absent(name: &str, store: &podman::Store) -> bool {
    let mut cmd = podman::podman_in(store);
    cmd.args(["container", "exists", "--", name]);
    process::run(cmd, deadline(STOP_TIMEOUT), "runner exists")
        .is_ok_and(|output| output.code == Some(1))
}

fn deadline(after: Duration) -> Instant {
    Instant::now() + after
}

/// The container a lease's runner runs in: named for the lease, so a worker that died leaves
/// something a sweep can find and a second start cannot quietly take the same name.
fn container_name(lease: RunnerLeaseId) -> String {
    format!("sentinel-runner-{}", hex16(lease))
}

fn dir_of(root: &Path, lease: RunnerLeaseId) -> PathBuf {
    root.join("runners").join(hex16(lease))
}

fn work_dir(dir: &Path) -> PathBuf {
    dir.join("work")
}

pub(crate) fn hex16(lease: RunnerLeaseId) -> String {
    let mut text = String::with_capacity(32);
    for byte in lease.as_bytes() {
        let _ = write!(text, "{byte:02x}");
    }
    text
}

/// `--network` for a runner container: the same egress the operator grants a pipeline job.
fn network_argument(network: Network) -> &'static str {
    match network {
        Network::None => "none",
        Network::Egress => "pasta:--no-map-gw",
    }
}

fn rules_for_guard(guard: &net::Guard, endpoint: Option<Ipv4Addr>) -> Result<String> {
    let host = net::host_addresses()
        .map_err(|e| Error::Preparation(format!("the host's addresses: {e}")))?;
    Ok(rules_for(&host, guard, endpoint))
}

/// The refusals of a container granted egress, as the nftables script its namespace loads.
fn rules_for(host: &[Ipv4Addr], guard: &net::Guard, endpoint: Option<Ipv4Addr>) -> String {
    let nets = net::denied_nets(host, []);
    let endpoints = net::denied_endpoints(guard);
    let mut list = String::new();
    for (addr, prefix) in &nets {
        if !list.is_empty() {
            list.push_str(", ");
        }
        let _ = write!(list, "{}/{}", Ipv4Addr::from(*addr), prefix);
    }
    let mut ports = String::new();
    for (addr, port) in &endpoints {
        if !ports.is_empty() {
            ports.push_str(", ");
        }
        let _ = write!(ports, "{} . {}", Ipv4Addr::from(*addr), port);
    }
    let mut out = String::with_capacity(960);
    let _ = writeln!(out, "table ip sentinel_runner {{");
    let _ = writeln!(out, "\tset denied_nets {{");
    let _ = writeln!(out, "\t\ttype ipv4_addr");
    let _ = writeln!(out, "\t\tflags interval");
    let _ = writeln!(out, "\t\telements = {{ {list} }}");
    let _ = writeln!(out, "\t}}");
    let _ = writeln!(out, "\tset denied_endpoints {{");
    let _ = writeln!(out, "\t\ttype ipv4_addr . inet_service");
    if !ports.is_empty() {
        let _ = writeln!(out, "\t\telements = {{ {ports} }}");
    }
    let _ = writeln!(out, "\t}}");
    // The container's own sockets are where its traffic is made, so the refusals are on output.
    // Loopback inside the namespace stays usable: a job's tools talk to their own local sockets.
    let _ = writeln!(out, "\tchain output {{");
    let _ = writeln!(
        out,
        "\t\ttype filter hook output priority filter; policy accept;"
    );
    // The sandbox's cache and artifact endpoint is the one address the host must serve it on, so the
    // accept comes before every refusal: the endpoint is the worker's own, by address and port.
    if let Some(endpoint) = endpoint {
        let _ = writeln!(
            out,
            "\t\toifname != \"lo\" ip daddr {endpoint} tcp dport {ACTIONS_PORT} accept"
        );
    }
    let _ = writeln!(out, "\t\toifname != \"lo\" ip daddr @denied_nets drop");
    let _ = writeln!(
        out,
        "\t\toifname != \"lo\" ip daddr . th dport @denied_endpoints drop"
    );
    let _ = writeln!(out, "\t}}");
    let _ = writeln!(out, "}}");
    // A runner has no IPv6 route of its own: nothing leaves except through loopback.
    let _ = writeln!(out, "table ip6 sentinel_runner6 {{");
    let _ = writeln!(out, "\tchain output {{");
    let _ = writeln!(
        out,
        "\t\ttype filter hook output priority filter; policy accept;"
    );
    // The sandbox's cache and artifact endpoint is the one address the host must serve it on, so the
    // accept comes before every refusal: the endpoint is the worker's own, by address and port.
    if let Some(endpoint) = endpoint {
        let _ = writeln!(
            out,
            "\t\toifname != \"lo\" ip daddr {endpoint} tcp dport {ACTIONS_PORT} accept"
        );
    }
    let _ = writeln!(out, "\t\toifname != \"lo\" drop");
    let _ = writeln!(out, "\t}}");
    let _ = writeln!(out, "}}");
    out
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use super::*;

    fn guard() -> net::Guard {
        net::Guard {
            link: vec![
                "198.51.100.9:7443".parse::<SocketAddr>().unwrap(),
                "[2001:db8::1]:7443".parse().unwrap(),
            ],
        }
    }

    fn image() -> Image {
        Image::parse("ghcr.io/rusticstack/sentinel-runner@sha256:0000000000000000000000000000000000000000000000000000000000000000").unwrap()
    }

    fn actions() -> Actions {
        Actions {
            address: Ipv4Addr::new(10, 0, 2, 2),
            anchor: PathBuf::from("/var/lib/sentinel-worker/runners/x/ca.crt"),
        }
    }

    fn limits() -> Limits {
        Limits {
            cpu_millis: 4_000,
            memory_bytes: 8 << 30,
            pids: PIDS,
            disk_bytes: 40 << 30,
            lifetime_secs: 0,
        }
    }

    fn plan(network: Network, guard: &net::Guard) -> Plan {
        Plan::new(
            Path::new("/var/lib/sentinel-worker"),
            WorkerId::new(),
            RunnerLeaseId::new(),
            &image(),
            limits(),
            &Grant {
                network,
                guard,
                actions: Some(&actions()),
            },
        )
        .unwrap()
    }

    fn joined(args: &[String]) -> String {
        args.join(" ")
    }

    #[test]
    fn a_lease_names_one_container_and_one_directory() {
        let lease = RunnerLeaseId::new();
        let guard = net::Guard::default();
        let a = Plan::new(
            Path::new("/root"),
            WorkerId::new(),
            lease,
            &image(),
            Limits {
                lifetime_secs: 60,
                ..limits()
            },
            &Grant {
                network: Network::None,
                guard: &guard,
                actions: None,
            },
        )
        .unwrap();
        let b = Plan::new(
            Path::new("/root"),
            WorkerId::new(),
            lease,
            &image(),
            Limits {
                lifetime_secs: 60,
                ..limits()
            },
            &Grant {
                network: Network::None,
                guard: &guard,
                actions: None,
            },
        )
        .unwrap();
        // Two plans for one lease are the same sandbox: the lease decides the name and the path, so a
        // second start cannot register a second runner under a new name.
        assert_eq!((a.name(), a.dir()), (b.name(), b.dir()));
        assert!(a.name().starts_with("sentinel-runner-"));
        assert!(a.dir().ends_with(hex16(lease)));
    }

    #[test]
    fn a_worker_without_an_image_or_an_endpoint_or_for_a_reservation_too_small_takes_no_runner() {
        assert!(!Policy::default().admits(4_000, 8 << 30));
        let named = Policy {
            image: Some(image()),
            guard: net::Guard::default(),
            actions: Some(Ipv4Addr::new(10, 0, 2, 2)),
        };
        assert!(named.admits(4_000, 8 << 30));
        assert!(!named.admits(0, 8 << 30));
        assert!(!named.admits(4_000, MIN_MEMORY_BYTES - 1));
        assert!(!named.admits(u64::from(u32::MAX) + 1, 8 << 30));
        // An image and no endpoint address is a worker whose runners would cache at GitHub.
        let no_endpoint = Policy {
            actions: None,
            ..named
        };
        assert!(!no_endpoint.admits(4_000, 8 << 30));
    }

    #[test]
    fn a_runner_image_must_be_pinned_by_digest() {
        assert!(Image::parse("ghcr.io/x/runner@sha256:0000000000000000000000000000000000000000000000000000000000000000").is_some());
        for unpinned in [
            "ghcr.io/x/runner:latest",
            "ghcr.io/x/runner",
            "ghcr.io/x/runner@sha256:00",
            "ghcr.io/x/runner@md5:0000000000000000000000000000000000000000000000000000000000000000",
            "@sha256:0000000000000000000000000000000000000000000000000000000000000000",
        ] {
            assert!(Image::parse(unpinned).is_none(), "{unpinned}");
        }
    }

    #[test]
    fn the_runner_takes_one_job_and_its_configuration_is_not_on_the_command_line() {
        let plan = plan(Network::None, &guard());
        let args = joined(plan.args());
        // The container is removed with the runner, and its writable paths are tmpfs or scratch.
        assert!(args.contains("--rm"), "{args}");
        assert!(args.contains("--read-only"), "{args}");
        assert!(args.contains(CONFIG_MOUNT), "{args}");
        assert!(args.contains(&format!("{WORK_MOUNT}:rw")), "{args}");
        assert!(args.contains("--network none"), "{args}");
        assert!(args.contains("--entrypoint /bin/sh"), "{args}");
        assert!(!args.contains("--env-file"), "{args}");
        assert!(!args.contains("--jitconfig"), "{args}");
        // The container's keepalive is bounded, so a sandbox nobody stops cannot outlive it.
        assert!(args.ends_with("sentinel-runner-keepalive 21600"), "{args}");
    }

    /// A sandbox resolves the cache and result hosts to its own worker and carries one anchor — its
    /// own — as a path, never as a secret and never as a second environment variable.
    #[test]
    fn a_sandbox_names_the_two_service_hosts_and_carries_only_its_own_anchor() {
        let dir = tempfile::tempdir().unwrap();
        let wiring = Actions {
            address: Ipv4Addr::new(10, 0, 2, 2),
            anchor: dir.path().join("ca.crt"),
        };
        let plan = Plan::new(
            dir.path(),
            WorkerId::new(),
            RunnerLeaseId::new(),
            &image(),
            limits(),
            &Grant {
                network: Network::Egress,
                guard: &guard(),
                actions: Some(&wiring),
            },
        )
        .unwrap();
        let args = plan.args();
        let hosts: Vec<&String> = args
            .iter()
            .enumerate()
            .filter(|(i, _)| i > &0 && args[i - 1] == "--add-host")
            .map(|(_, value)| value)
            .collect();
        assert_eq!(
            hosts,
            vec![
                &"artifactcache.actions.githubusercontent.com:10.0.2.2".to_owned(),
                &"results-receiver.actions.githubusercontent.com:10.0.2.2".to_owned(),
            ]
        );
        let joined = args.join(" ");
        assert!(
            joined.contains(&format!(
                "{}:{CA_PATH}:ro",
                dir.path().join("ca.crt").display()
            )),
            "{joined}"
        );
        assert!(joined.contains(&format!("{CA_ENV}={CA_PATH}")), "{joined}");
        // The one environment variable this sandbox carries is a path.
        let env: Vec<&String> = args
            .iter()
            .enumerate()
            .filter(|(i, _)| i > &0 && args[i - 1] == "--env")
            .map(|(_, value)| value)
            .collect();
        assert_eq!(env.len(), 1, "{env:?}");
        assert!(!joined.contains("TOKEN"), "{joined}");
    }

    #[test]
    fn nothing_of_the_host_is_mounted_but_the_leases_own_scratch_and_its_anchor() {
        let plan = plan(Network::None, &guard());
        let volumes: Vec<&String> = plan
            .args()
            .iter()
            .enumerate()
            .filter(|(i, _)| plan.args()[i.saturating_sub(1)] == "--volume")
            .map(|(_, v)| v)
            .collect();
        assert_eq!(volumes.len(), 2, "{volumes:?}");
        assert!(
            volumes[0].ends_with(&format!(":{WORK_MOUNT}:rw")),
            "{volumes:?}"
        );
        assert!(volumes[0].starts_with(plan.dir().join("work").to_str().unwrap()));
        assert!(
            volumes[1].ends_with(&format!(":{CA_PATH}:ro")),
            "{volumes:?}"
        );
    }

    #[test]
    fn a_worker_without_egress_installs_no_rules_and_a_granted_one_installs_them_first() {
        let g = guard();
        assert!(
            !Plan::new(
                Path::new("/d"),
                WorkerId::new(),
                RunnerLeaseId::new(),
                &image(),
                Limits {
                    cpu_millis: 1_000,
                    memory_bytes: 1 << 30,
                    ..limits()
                },
                &Grant {
                    network: Network::None,
                    guard: &g,
                    actions: None,
                },
            )
            .unwrap()
            .guarded()
        );
        assert!(plan(Network::Egress, &g).guarded());
    }

    #[test]
    fn the_refusals_cover_the_host_loopback_off_lo_and_the_metadata_addresses() {
        let rules = rules_for(
            &[Ipv4Addr::new(192, 168, 7, 20), Ipv4Addr::new(127, 0, 0, 1)],
            &guard(),
            Some(Ipv4Addr::new(10, 0, 2, 2)),
        );
        for net in [
            "0.0.0.0/8",
            "127.0.0.0/8",
            "169.254.0.0/16",
            "100.100.100.200/32",
            "192.0.0.0/24",
            "224.0.0.0/4",
            "240.0.0.0/4",
            "192.168.7.20/32",
        ] {
            assert!(rules.contains(net), "{net} is not refused:\n{rules}");
        }
        // The VM's own tap network is not a container's business: a job may legitimately use it.
        assert!(!rules.contains("10.211.0.0/30"), "{rules}");
        // Loopback is refused off `lo` only, so a job's own local sockets still work.
        assert!(
            rules.contains("oifname != \"lo\" ip daddr @denied_nets drop"),
            "{rules}"
        );
        assert!(rules.contains("198.51.100.9 . 7443"), "{rules}");
        assert!(
            rules.contains("oifname != \"lo\" ip daddr . th dport @denied_endpoints drop"),
            "{rules}"
        );
        // The sandbox's own cache and artifact endpoint is accepted ahead of every refusal.
        let accept = "oifname != \"lo\" ip daddr 10.0.2.2 tcp dport 443 accept";
        assert!(rules.contains(accept), "{rules}");
        assert!(
            rules.find(accept).unwrap() < rules.find("@denied_nets drop").unwrap(),
            "the endpoint accept must come before the refusals:\n{rules}"
        );
        assert!(!rules.contains("2001:db8"), "{rules}");
        assert!(rules.contains("table ip6 sentinel_runner6"), "{rules}");
        assert!(rules.contains("oifname != \"lo\" drop"), "{rules}");
    }

    #[test]
    fn staging_makes_only_the_leases_scratch_and_the_rules_it_will_load() {
        let dir = tempfile::tempdir().unwrap();
        let lease = RunnerLeaseId::new();
        let g = guard();
        let mut created = Plan::new(
            dir.path(),
            WorkerId::new(),
            lease,
            &image(),
            Limits {
                cpu_millis: 1_000,
                memory_bytes: 1 << 30,
                lifetime_secs: 60,
                ..limits()
            },
            &Grant {
                network: Network::Egress,
                guard: &g,
                actions: None,
            },
        )
        .unwrap();
        created.dir = dir.path().join("runners").join(hex16(lease));
        created.stage().unwrap();
        created.stage().unwrap();
        let work = created.dir().join("work");
        assert!(work.is_dir());
        assert_eq!(
            fs::metadata(work).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert!(created.dir().join("egress.nft").is_file());
        // Nothing else: no configuration, no environment file, no host directory.
        let entries: Vec<String> = fs::read_dir(created.dir())
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(entries.len(), 2, "{entries:?}");
        assert!(created.name().starts_with("sentinel-runner-"));
        assert!(created.name().ends_with(&hex16(lease)));
        assert_eq!(created.lifetime_secs(), 60);
    }

    #[test]
    fn nothing_writable_survives_the_teardown() {
        let dir = tempfile::tempdir().unwrap();
        let plan_dir = dir.path().join("runners").join("x");
        fs::create_dir_all(plan_dir.join("work")).unwrap();
        fs::write(plan_dir.join("egress.nft"), b"table ip x {}\n").unwrap();
        fs::write(plan_dir.join("work").join("checkout"), b"job output").unwrap();
        workspace::remove_tree(&plan_dir).unwrap();
        assert!(!plan_dir.exists());
    }
}
