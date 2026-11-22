//! A runner in a microVM (plan 16.8 and 16.10, AR04): one Firecracker guest per lease, booted from the
//! runner guest image, with the listener started by the image's own entry point.
//!
//! The guest is the generic job VM of [`crate::microvm`], so its isolation, its egress policy, its
//! snapshot warm start and its reconciliation after a worker restart are the ones a pipeline job gets.
//! What is the runner's own:
//!
//! - the VM is named for the lease (a lease id read as an attempt id: both are 16 random bytes, and a
//!   VM directory is all that either names here), so startup reconciliation removes a runner guest a
//!   dead worker left exactly as it removes a job's;
//! - the just-in-time configuration goes into the guest's in-memory secret directory, from memory, and
//!   is removed from it when the listener ends. It is never an argument, an environment value or a
//!   host file;
//! - with a cache and artifact endpoint, the guest's egress policy admits that one address and port of
//!   the host, and the guest is told the address, the names it answers and the anchor to trust.
//!
//! Only Linux guests exist: a Windows guest needs the Cloud Hypervisor executor (M07), which this
//! build does not have.

use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};

use sentinel_core::{AttemptId, RunnerLeaseId};
use sentinel_pipeline::run::StepCommand;

use super::{
    ACTIONS_PORT, Actions, CA_ENV, Exit, Grant, Image, MAX_CONFIG_BYTES, MAX_LIFETIME_SECS, dir_of,
    hex16, work_dir,
};
use crate::{
    Error, Result,
    microvm::{self, StartReport, Vm},
    podman::{Limits, Mount, Network, Store},
    workspace,
};

/// The guest image's entry point, started as the image's user (root) with no input: it reads the
/// configuration from [`ENV_CONFIG`], starts the guest's Docker daemon and runs the listener as the
/// `runner` user. The image's contract (`examples/Containerfile.runner-guest`).
pub const START: &str = "/usr/local/bin/sentinel-runner-guest";

/// The name of the configuration inside the guest's secret directory.
pub const CONFIG_FILE: &str = "jitconfig";

/// Tells the entry point where the configuration is: a path, never the value.
pub const ENV_CONFIG: &str = "SENTINEL_RUNNER_CONFIG";
/// The address the cache and artifact names resolve to, and those names, space separated.
pub const ENV_ACTIONS_ADDRESS: &str = "SENTINEL_ACTIONS_ADDRESS";
pub const ENV_ACTIONS_HOSTS: &str = "SENTINEL_ACTIONS_HOSTS";

/// Where the guest finds the endpoint's anchor.
pub const ANCHOR_MOUNT: &str = "/etc/sentinel-runner";
pub const ANCHOR_FILE: &str = "ca.crt";

/// The guest's writable disk: the job's checkout and build output, and the images its Docker daemon
/// pulls. A sparse file of the lease, removed with the VM.
pub const DISK_BYTES: u64 = 16 << 30;

/// How long the listener has to stop on a cancel before the guest's processes are killed.
const STOP_GRACE: Duration = Duration::from_secs(10);
/// How often a running guest's cancel flag is looked at.
const CANCEL_POLL: Duration = Duration::from_millis(200);

/// One runner guest as it is started and then torn down. Data until [`Plan::start`]: a plan that is
/// never started made nothing.
#[derive(Debug)]
pub struct Plan {
    name: String,
    root: PathBuf,
    dir: PathBuf,
    setup: Arc<microvm::Setup>,
    attempt: AttemptId,
    image: Image,
    limits: Limits,
    network: Network,
    actions: Option<Actions>,
    lifetime_secs: u64,
}

impl Plan {
    pub fn new(
        root: &Path,
        setup: Arc<microvm::Setup>,
        lease: RunnerLeaseId,
        image: &Image,
        limits: Limits,
        grant: &Grant<'_>,
    ) -> Result<Plan> {
        let attempt = AttemptId::from_bytes(*lease.as_bytes())
            .map_err(|_| Error::Preparation("runner lease".into()))?;
        let lifetime_secs = match limits.lifetime_secs {
            0 => MAX_LIFETIME_SECS,
            secs => secs.min(MAX_LIFETIME_SECS),
        };
        Ok(Plan {
            name: format!("sentinel-runner-vm-{}", hex16(lease)),
            root: root.to_path_buf(),
            dir: dir_of(root, lease),
            setup,
            attempt,
            image: image.clone(),
            limits: Limits {
                disk_bytes: DISK_BYTES,
                lifetime_secs,
                ..limits
            },
            network: grant.network,
            actions: grant.actions.cloned(),
            lifetime_secs,
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn lifetime_secs(&self) -> u64 {
        self.lifetime_secs
    }

    /// What the entry point is started with: where the configuration is and, with an endpoint, where
    /// the cache and artifact names resolve and which anchor signs them.
    pub fn environment(&self) -> Vec<(String, String)> {
        let mut env = Vec::with_capacity(4);
        env.push((
            ENV_CONFIG.to_owned(),
            format!(
                "{}/{CONFIG_FILE}",
                sentinel_protocol::agent::SECRET_MOUNTS[0]
            ),
        ));
        if let Some(actions) = &self.actions {
            env.push((ENV_ACTIONS_ADDRESS.to_owned(), actions.address.to_string()));
            env.push((
                ENV_ACTIONS_HOSTS.to_owned(),
                sentinel_actions::HOSTS.join(" "),
            ));
            env.push((CA_ENV.to_owned(), format!("{ANCHOR_MOUNT}/{ANCHOR_FILE}")));
        }
        env
    }

    /// Boots the guest, hands the listener its configuration and waits for it to end. The guest is gone
    /// when this returns, whatever it returns. `started`, when the guest came up, is told how: the
    /// start mode and time a warm start is measured by (AR08).
    pub fn start(
        &self,
        config: &[u8],
        cancel: &AtomicBool,
        started: &dyn Fn(&StartReport),
    ) -> Result<Exit> {
        if config.is_empty() || config.len() > MAX_CONFIG_BYTES {
            return Err(Error::Preparation("runner configuration".into()));
        }
        let (work, anchors) = self.stage()?;
        let mounts = [Mount {
            host: anchors,
            container: ANCHOR_MOUNT.to_owned(),
            read_only: true,
        }];
        let serve = match self.network {
            Network::Egress => self
                .actions
                .as_ref()
                .map(|actions| (actions.address, ACTIONS_PORT)),
            Network::None => None,
        };
        let vm = Vm::start_serving(
            &self.root,
            &self.setup,
            self.attempt,
            self.image.as_str(),
            self.limits,
            &work,
            &mounts,
            &Store::Shared,
            self.network,
            serve,
            cancel,
        )?;
        started(vm.start_report());
        let outcome = vm
            .deliver_secret_file(CONFIG_FILE, config)
            .and_then(|()| self.listen(&vm, cancel));
        // The configuration is spent or refused by now; a guest that still answers drops its copy
        // before it is powered off, and one that does not loses it with its memory.
        let _ = vm.retract_secrets();
        let destroyed = vm.destroy();
        let exit = outcome?;
        destroyed?;
        Ok(exit)
    }

    /// Runs the entry point to its end, with a watcher that stops the guest's processes on a cancel.
    fn listen(&self, vm: &Vm, cancel: &AtomicBool) -> Result<Exit> {
        let command = StepCommand {
            argv: vec![START.to_owned()],
            env: self.environment(),
            secrets: Vec::new(),
            secret_files: Vec::new(),
            workdir: None,
            timeout_secs: self.lifetime_secs,
        };
        let done = AtomicBool::new(false);
        let exit = thread::scope(|scope| {
            let watcher = scope.spawn(|| {
                while !done.load(Ordering::Acquire) {
                    if cancel.load(Ordering::Acquire) {
                        // A guest that does not stop in time loses its VM, which ends the exec below.
                        let _ = microvm::terminate_named(&self.root, self.attempt, STOP_GRACE);
                        return;
                    }
                    thread::park_timeout(CANCEL_POLL);
                }
            });
            let exit = vm.exec(&command, &[]);
            done.store(true, Ordering::Release);
            watcher.thread().unpark();
            exit
        });
        let canceled = cancel.load(Ordering::Acquire);
        match exit {
            Ok(exit) => Ok(Exit {
                code: if exit.timed_out { None } else { exit.code },
                canceled,
            }),
            // A cancel that had to take the VM away ends the exec with an error; it is still a cancel.
            Err(_) if canceled => Ok(Exit {
                code: None,
                canceled,
            }),
            Err(e) => Err(e),
        }
    }

    /// The lease's directories: the (empty) workspace the VM is given and the directory holding the
    /// endpoint's anchor, both the worker account's alone.
    fn stage(&self) -> Result<(PathBuf, PathBuf)> {
        let work = work_dir(&self.dir);
        let anchors = self.dir.join("guest");
        for dir in [&self.dir, &work, &anchors] {
            fs::create_dir_all(dir).map_err(|e| Error::Preparation(format!("runner dir: {e}")))?;
            fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
                .map_err(|e| Error::Preparation(format!("runner dir: {e}")))?;
        }
        if let Some(actions) = &self.actions {
            fs::copy(&actions.anchor, anchors.join(ANCHOR_FILE))
                .map_err(|e| Error::Preparation(format!("runner anchor: {e}")))?;
        }
        Ok((work, anchors))
    }

    /// Removes the guest (if a start left one) and everything the lease wrote on the host.
    pub fn destroy(&self) -> Result<()> {
        if microvm::exists(&self.root, self.attempt) {
            microvm::remove_named(&self.root, self.attempt)?;
        }
        workspace::remove_tree(&self.dir)
    }
}
