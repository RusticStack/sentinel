//! Where an attempt's steps run: a rootless container or a microVM, behind the calls the attempt makes.

use std::{path::Path, time::Duration};

use sentinel_core::AttemptId;
use sentinel_pipeline::run::StepCommand;

use crate::{
    Result, microvm,
    podman::{self, Container, Exit, Store, Terminated},
    process,
};

#[derive(Debug)]
pub enum Sandbox {
    Container(Container),
    Vm(Box<microvm::Vm>),
}

impl Sandbox {
    pub fn exec_streaming(
        &self,
        step: &StepCommand,
        extra: &[(String, String)],
        sink: Option<process::Sink>,
    ) -> Result<Exit> {
        match self {
            Sandbox::Container(c) => c.exec_streaming(step, extra, sink),
            Sandbox::Vm(vm) => vm.exec_streaming(step, extra, sink),
        }
    }

    pub fn exec(&self, step: &StepCommand, extra: &[(String, String)]) -> Result<Exit> {
        self.exec_streaming(step, extra, None)
    }

    pub fn oom_kills(&self) -> Result<u64> {
        match self {
            Sandbox::Container(c) => c.oom_kills(),
            Sandbox::Vm(vm) => vm.oom_kills(),
        }
    }

    pub fn clear_strays(&self) -> Result<usize> {
        match self {
            Sandbox::Container(c) => c.clear_strays(),
            Sandbox::Vm(vm) => vm.clear_strays(),
        }
    }

    /// Makes what the host reads after the steps current on the host: a container shares the host's
    /// directories already; a VM copies the artifact paths, the `replaced` workspace directories (cache
    /// views) and its writable mounts back.
    pub fn sync_out(
        &self,
        workspace: &Path,
        artifact_paths: &[String],
        replaced: &[String],
    ) -> Result<()> {
        match self {
            Sandbox::Container(_) => Ok(()),
            Sandbox::Vm(vm) => vm.sync_out(workspace, artifact_paths, replaced),
        }
    }

    /// Puts directories of the host (a step's secret files and environment file) into the guest at their
    /// container paths; a container has them bind-mounted already.
    pub fn deliver_secrets(&self, dirs: &[(&Path, &str)]) -> Result<()> {
        match self {
            Sandbox::Container(_) => Ok(()),
            Sandbox::Vm(vm) => vm.deliver_secrets(dirs),
        }
    }

    /// Takes what [`Sandbox::deliver_secrets`] put into the guest out of it again.
    pub fn retract_secrets(&self) -> Result<()> {
        match self {
            Sandbox::Container(_) => Ok(()),
            Sandbox::Vm(vm) => vm.retract_secrets(),
        }
    }

    /// Brings the workspace files matching `patterns` current on the host (a VM's workspace is a copy; a
    /// container shares the host's directory already): what a step `if:` reads after earlier steps ran.
    pub fn pull_workspace(&self, workspace: &Path, patterns: &[&str]) -> Result<()> {
        match self {
            Sandbox::Container(_) => Ok(()),
            Sandbox::Vm(vm) => vm.pull_workspace(workspace, patterns),
        }
    }

    pub fn destroy(self) -> Result<()> {
        match self {
            Sandbox::Container(c) => c.destroy(),
            Sandbox::Vm(vm) => vm.destroy(),
        }
    }

    /// Watches the attempt's workspace and its job `/tmp` together against `limit` bytes while its steps run, when
    /// the sandbox has no size bound of its own. A container's workspace and `/tmp` are bind mounts that rootless
    /// Podman cannot bound, so the guard measures them ([`crate::quota`]); a microVM's disk is a scratch image of
    /// exactly the declared size.
    pub fn guard_storage(&self, workspace: &Path, limit: u64) -> Option<crate::quota::Guard> {
        match self {
            Sandbox::Container(c) => Some(crate::quota::Guard::start(
                vec![
                    workspace.to_path_buf(),
                    crate::workspace::tmp_beside(workspace),
                ],
                limit,
                c.stopper(),
            )),
            Sandbox::Vm(_) => None,
        }
    }

    pub fn attempt(&self) -> AttemptId {
        match self {
            Sandbox::Container(c) => c.attempt(),
            Sandbox::Vm(vm) => vm.attempt(),
        }
    }
}

/// A cancel by attempt, from another thread: the VM if one exists for it, else the container.
pub fn terminate(
    root: &Path,
    attempt: AttemptId,
    store: &Store,
    grace: Duration,
) -> Result<Terminated> {
    if microvm::exists(root, attempt) {
        microvm::terminate_named(root, attempt, grace)
    } else {
        podman::terminate_named(&format!("sentinel-{attempt}"), store, grace)
    }
}

/// Removes an attempt's sandbox by name: shutdown and lease loss.
pub fn remove(root: &Path, attempt: AttemptId, store: &Store) -> Result<()> {
    if microvm::exists(root, attempt) {
        microvm::remove_named(root, attempt)
    } else {
        podman::remove_named(&format!("sentinel-{attempt}"), store)
    }
}
