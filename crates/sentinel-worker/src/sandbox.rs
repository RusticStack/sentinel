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
    Vm(microvm::Vm),
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
    /// directories already; a VM copies the artifact paths and its writable mounts back.
    pub fn sync_out(&self, workspace: &Path, artifact_paths: &[String]) -> Result<()> {
        match self {
            Sandbox::Container(_) => Ok(()),
            Sandbox::Vm(vm) => vm.sync_out(workspace, artifact_paths),
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
