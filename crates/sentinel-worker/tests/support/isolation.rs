//! Which isolation a worker test runs its jobs under (TODO M04).
//!
//! The same test runs under rootless Podman by default and under Firecracker microVMs when
//! `SENTINEL_MICROVM_TESTS` is set, with the setup in `SENTINEL_FIRECRACKER`, `SENTINEL_GUEST_KERNEL` and
//! `SENTINEL_GUEST_AGENT` (a KVM host, an account that can use `/dev/kvm`). Both need Podman: the image
//! is pulled into its store, and the microVM executor builds the guest root file system from it.

#![allow(dead_code)]

use std::{path::Path, process::Command, sync::Arc};

use sentinel_core::{AttemptId, WorkerId};
use sentinel_worker::{
    attempt::Runtime,
    executor::Executor,
    host::Isolation,
    microvm::{self, Setup},
    podman::{self, Limits, Network, Store},
    sandbox::Sandbox,
};

/// Whether this run puts jobs in microVMs.
pub fn microvm() -> bool {
    std::env::var_os("SENTINEL_MICROVM_TESTS").is_some()
}

/// "container" or "microvm", for messages.
pub fn name() -> &'static str {
    if microvm() { "microvm" } else { "container" }
}

/// Whether the test may run: a rootless Podman account, or a KVM host for the microVM run.
pub fn enabled() -> bool {
    if std::env::var_os("SENTINEL_PODMAN_TESTS").is_some() || microvm() {
        return true;
    }
    eprintln!(
        "skipped: set SENTINEL_PODMAN_TESTS=1 as a rootless Podman account to run, or SENTINEL_MICROVM_TESTS=1 on a KVM host"
    );
    false
}

fn setup() -> Option<Arc<Setup>> {
    if !microvm() {
        return None;
    }
    let path = |name: &str| {
        std::path::PathBuf::from(
            std::env::var_os(name).unwrap_or_else(|| panic!("{name} is required")),
        )
    };
    let setup = Setup {
        firecracker: path("SENTINEL_FIRECRACKER"),
        kernel: path("SENTINEL_GUEST_KERNEL"),
        agent: path("SENTINEL_GUEST_AGENT"),
        snapshots: true,
        guard: Default::default(),
    };
    setup.check().unwrap();
    Some(Arc::new(setup))
}

/// The worker's runtime for this run: microVMs as the default executor, or `None` for the container default.
pub fn runtime() -> Option<Runtime> {
    Some(Runtime {
        default: Some(Isolation::Microvm),
        microvm: Some(setup()?),
    })
}

/// Puts an executor under this run's isolation.
pub fn apply(executor: &Executor) {
    if let Some(runtime) = runtime() {
        executor.set_runtime(runtime);
    }
}

/// The worker's live sandboxes: its containers and its microVMs.
pub fn sandboxes(worker: WorkerId, worker_dir: &Path) -> usize {
    podman::owned(worker).unwrap().len() + microvm::owned(worker_dir).len()
}

/// Whether the attempt's sandbox still exists.
pub fn sandbox_exists(worker: WorkerId, worker_dir: &Path, attempt: AttemptId) -> bool {
    if microvm() {
        return microvm::exists(worker_dir, attempt);
    }
    let _ = worker;
    Command::new("podman")
        .args(["container", "exists", &format!("sentinel-{attempt}")])
        .status()
        .unwrap()
        .success()
}

/// Starts one sandbox of this run's kind outside an attempt.
#[allow(clippy::too_many_arguments)]
pub fn start_sandbox(
    worker_dir: &Path,
    worker: WorkerId,
    attempt: AttemptId,
    image: &str,
    limits: Limits,
    workspace: &Path,
    store: &Store,
) -> Sandbox {
    match setup() {
        Some(setup) => Sandbox::Vm(
            microvm::Vm::start(
                worker_dir,
                &setup,
                worker,
                attempt,
                image,
                limits,
                workspace,
                &[],
                store,
                Network::None,
            )
            .unwrap(),
        ),
        None => Sandbox::Container(
            podman::Container::start(
                worker,
                attempt,
                image,
                limits,
                workspace,
                &[],
                store,
                Network::None,
            )
            .unwrap(),
        ),
    }
}
