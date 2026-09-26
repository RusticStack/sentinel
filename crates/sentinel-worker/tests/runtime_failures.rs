//! The container runtime failing under the worker, with `podman` replaced
//! on `PATH` by a shim: teardown still removes a container whose graceful
//! stop failed (P04-6), and recovery refuses to abandon attempts when it
//! cannot list or remove what the previous process left running (P04-7).
//!
//! The shim's behavior is switched per container name or worker id by
//! files in its directory, so the tests here run in parallel safely.

#![cfg(target_os = "linux")]

#[path = "support/shim_dir.rs"]
mod shim_dir;

use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf, sync::OnceLock};

use sentinel_core::{AttemptId, Fence, WorkerId};
use sentinel_worker::{
    podman::{self, Container, Limits},
    recovery,
};

const SHIM: &str = r#"#!/bin/sh
dir="$(dirname "$0")"
case "$1" in
  ps)
    id="${4##*=}"
    if [ -e "$dir/fail-ps-$id" ]; then echo "Error: cannot list containers" >&2; exit 1; fi
    cat "$dir/owned-$id" 2>/dev/null
    exit 0 ;;
  rm)
    name="$4"
    if [ -e "$dir/fail-rm-$name" ]; then echo "Error: cannot remove" >&2; exit 1; fi
    echo "$name" >> "$dir/removed"
    exit 0 ;;
  stop)
    name="$5"
    if [ -e "$dir/fail-stop-$name" ]; then echo "Error: stop timed out" >&2; exit 125; fi
    exit 0 ;;
  create|start) exit 0 ;;
  *) exit 1 ;;
esac
"#;

/// The shim directory, first on `PATH` for this whole test binary.
fn shim() -> &'static PathBuf {
    static DIR: OnceLock<PathBuf> = OnceLock::new();
    DIR.get_or_init(|| {
        let dir = shim_dir::create("runtime-failures");
        let path = dir.join("podman");
        fs::write(&path, SHIM).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        let joined = format!(
            "{}:{}",
            dir.display(),
            std::env::var("PATH").unwrap_or_default()
        );
        // SAFETY: set once, before any test in this binary spawns a helper
        // (every test calls `shim()` first, and `OnceLock` serializes it).
        unsafe {
            std::env::set_var("PATH", joined);
        }
        dir
    })
}

fn removed() -> Vec<String> {
    fs::read_to_string(shim().join("removed"))
        .unwrap_or_default()
        .lines()
        .map(str::to_owned)
        .collect()
}

#[test]
fn teardown_removes_the_container_even_when_its_stop_fails() {
    let dir = shim();
    let (worker, attempt) = (WorkerId::new(), AttemptId::new());
    let name = format!("sentinel-{attempt}");
    fs::write(dir.join(format!("fail-stop-{name}")), "").unwrap();
    let workspace = tempfile::tempdir().unwrap();
    let container = Container::start(
        worker,
        attempt,
        "example.org/image@sha256:0000000000000000000000000000000000000000000000000000000000000000",
        Limits {
            cpu_millis: 1_000,
            memory_bytes: 1 << 30,
            pids: 64,
        },
        workspace.path(),
        &[],
        &podman::Store::Shared,
    )
    .unwrap();
    // The stop's failure is reported, and the removal ran anyway.
    assert!(container.destroy().is_err());
    assert!(removed().contains(&name), "{:?}", removed());
}

#[test]
fn recovery_fails_when_the_runtime_cannot_list_what_it_owns() {
    let dir = shim();
    let root = tempfile::tempdir().unwrap();
    let worker = WorkerId::new();
    let attempt = AttemptId::new();
    recovery::mark(root.path(), attempt, Fence(2)).unwrap();
    fs::write(dir.join(format!("fail-ps-{worker}")), "").unwrap();
    assert!(recovery::recover(root.path(), worker).is_err());
    // The marker stays: nothing was abandoned on a guess.
    assert_eq!(recovery::leftovers(root.path()).unwrap().len(), 1);
}

#[test]
fn recovery_fails_when_a_leftover_container_cannot_be_removed() {
    let dir = shim();
    let root = tempfile::tempdir().unwrap();
    let (worker, attempt) = (WorkerId::new(), AttemptId::new());
    let name = format!("sentinel-{attempt}");
    fs::write(
        dir.join(format!("owned-{worker}")),
        format!("{name} {attempt}\n"),
    )
    .unwrap();
    fs::write(dir.join(format!("fail-rm-{name}")), "").unwrap();
    assert!(recovery::recover(root.path(), worker).is_err());
    // And once the runtime can remove it, recovery completes.
    fs::remove_file(dir.join(format!("fail-rm-{name}"))).unwrap();
    let (recovered, _) = recovery::recover(root.path(), worker).unwrap();
    assert_eq!(recovered.containers_removed, 1);
    assert!(removed().contains(&name));
}
