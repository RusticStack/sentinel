//! Shim behavior is switched per container or worker id, so tests run in parallel.

#![cfg(target_os = "linux")]

#[path = "support/shim_dir.rs"]
mod shim_dir;

use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    sync::{
        Arc, OnceLock,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use sentinel_core::{AttemptId, Fence, WorkerId};
use sentinel_worker::{
    podman::{self, Container, Limits},
    recovery,
};

const SHIM: &str = r#"#!/bin/sh
dir="$(dirname "$0")"
# Global flags (`--log-level=error` and, for a private store, `--root` and `--runroot`) precede the subcommand, so
# find it before relying on the positions below.
while [ "$#" -gt 0 ]; do
  case "$1" in ps|container|rm|stop|create|start|info) break ;; esac
  shift
done
case "$1" in
  info)
    if [ -e "$dir/info-error" ]; then echo "Error: cannot connect to the Podman socket" >&2; exit 125; fi
    cat "$dir/info" 2>/dev/null
    exit 0 ;;
  ps)
    id="${4##*=}"
    if [ -e "$dir/fail-ps-$id" ]; then echo "Error: cannot list containers" >&2; exit 1; fi
    cat "$dir/owned-$id" 2>/dev/null
    exit 0 ;;
  container)
    name="$4"
    if [ -e "$dir/gone-$name" ]; then exit 1; fi
    exit 0 ;;
  rm)
    name="$4"
    if [ -e "$dir/gone-$name" ]; then echo "Error: no container with name or ID $name found: no such container" >&2; exit 1; fi
    if [ -e "$dir/fail-rm-$name" ]; then echo "Error: cannot remove" >&2; exit 1; fi
    echo "$name" >> "$dir/removed"
    exit 0 ;;
  stop)
    name="$5"
    if [ -e "$dir/gone-$name" ]; then echo "Error: no such container" >&2; exit 125; fi
    if [ -e "$dir/fail-stop-$name" ]; then echo "Error: stop timed out" >&2; exit 125; fi
    exit 0 ;;
  create)
    echo "$3" >> "$dir/created"
    exit 0 ;;
  start)
    name="$3"
    if [ -e "$dir/hold-start-$name" ]; then
      echo "$name" >> "$dir/started"
      while [ -e "$dir/hold-start-$name" ]; do sleep 0.05; done
    fi
    exit 0 ;;
  *) exit 1 ;;
esac
"#;

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
fn a_canceled_attempt_never_invokes_container_create() {
    let dir = shim();
    let attempt = AttemptId::new();
    let name = format!("sentinel-{attempt}");
    let workspace = tempfile::tempdir().unwrap();
    let outcome = Container::start_canceled(
        WorkerId::new(),
        attempt,
        "example.org/image@sha256:0000000000000000000000000000000000000000000000000000000000000000",
        Limits {
            cpu_millis: 1_000,
            memory_bytes: 1 << 30,
            pids: 64,
            disk_bytes: 0,
            lifetime_secs: 0,
        },
        workspace.path(),
        &[],
        &podman::Store::Shared,
        sentinel_worker::podman::Network::None,
        &AtomicBool::new(true),
    );
    assert!(outcome.is_err());
    let created = fs::read_to_string(dir.join("created")).unwrap_or_default();
    assert!(
        !created.lines().any(|created| created == name),
        "canceled attempt invoked podman create: {created}"
    );
}

#[test]
fn canceling_container_start_removes_the_created_container() {
    let dir = shim();
    let attempt = AttemptId::new();
    let name = format!("sentinel-{attempt}");
    fs::write(dir.join(format!("hold-start-{name}")), "").unwrap();
    let workspace = tempfile::tempdir().unwrap();
    let cancel = Arc::new(AtomicBool::new(false));
    let canceled = Arc::clone(&cancel);
    let starting = std::thread::spawn(move || {
        Container::start_canceled(
            WorkerId::new(),
            attempt,
            "example.org/image@sha256:0000000000000000000000000000000000000000000000000000000000000000",
            Limits {
                cpu_millis: 1_000,
                memory_bytes: 1 << 30,
                pids: 64,
                disk_bytes: 0,
                lifetime_secs: 0,
            },
            workspace.path(),
            &[],
            &podman::Store::Shared,
            sentinel_worker::podman::Network::None,
            &canceled,
        )
        .is_err()
    });
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let started = fs::read_to_string(dir.join("started")).unwrap_or_default();
        if started.lines().any(|started| started == name) {
            break;
        }
        assert!(Instant::now() < deadline, "podman start was not invoked");
        std::thread::sleep(Duration::from_millis(10));
    }
    cancel.store(true, Ordering::Release);
    assert!(starting.join().unwrap(), "start cancellation succeeded");
    assert!(removed().contains(&name), "{:?}", removed());
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
            disk_bytes: 0,
            lifetime_secs: 0,
        },
        workspace.path(),
        &[],
        &podman::Store::Shared,
        sentinel_worker::podman::Network::None,
    )
    .unwrap();
    assert!(container.destroy().is_err());
    assert!(removed().contains(&name), "{:?}", removed());
}

#[test]
fn teardown_of_a_container_already_removed_is_not_a_failure() {
    let dir = shim();
    let (worker, attempt) = (WorkerId::new(), AttemptId::new());
    let name = format!("sentinel-{attempt}");
    let workspace = tempfile::tempdir().unwrap();
    let container = Container::start(
        worker,
        attempt,
        "example.org/image@sha256:0000000000000000000000000000000000000000000000000000000000000000",
        Limits {
            cpu_millis: 1_000,
            memory_bytes: 1 << 30,
            pids: 64,
            disk_bytes: 0,
            lifetime_secs: 0,
        },
        workspace.path(),
        &[],
        &podman::Store::Shared,
        sentinel_worker::podman::Network::None,
    )
    .unwrap();
    // A cancel, a lease loss or the storage guard removed it by name first: both the stop and the remove now
    // fail with "no such container", and that is the outcome teardown wanted.
    fs::write(dir.join(format!("gone-{name}")), "").unwrap();
    container.destroy().unwrap();
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
    fs::remove_file(dir.join(format!("fail-rm-{name}"))).unwrap();
    let (recovered, _) = recovery::recover(root.path(), worker).unwrap();
    assert_eq!(recovered.containers_removed, 1);
    assert!(removed().contains(&name));
}

/// One `podman info` answer at a time: the shim reads a single file, so the probe tests take turns.
static INFO: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// What the shim answers for `podman info`: the five fields the probe reads, or `None` for a runtime that
/// cannot be reached at all.
fn probe_with(answer: Option<&str>) -> std::result::Result<podman::Runtime, String> {
    let _turn = INFO.lock().unwrap_or_else(|p| p.into_inner());
    let dir = shim();
    let error = dir.join("info-error");
    let info = dir.join("info");
    let _ = fs::remove_file(&error);
    let _ = fs::remove_file(&info);
    match answer {
        Some(fields) => fs::write(&info, fields).unwrap(),
        None => fs::write(&error, "").unwrap(),
    }
    let outcome = podman::probe().map_err(|e| e.to_string());
    let _ = fs::remove_file(&error);
    let _ = fs::remove_file(&info);
    outcome
}

#[test]
fn a_runtime_that_is_not_rootless_on_cgroup_v2_is_refused_with_the_reason() {
    let rootless_refused = probe_with(Some("false v2 runc systemd 5.0.0")).unwrap_err();
    assert!(
        rootless_refused.to_string().contains("not rootless"),
        "{rootless_refused}"
    );
    let cgroup_refused = probe_with(Some("true v1 runc systemd 5.0.0")).unwrap_err();
    assert!(
        cgroup_refused
            .to_string()
            .contains("cgroup v1 is not supported"),
        "{cgroup_refused}"
    );
    let probed = probe_with(Some("true v2 crun cgroupfs 5.1.0")).unwrap();
    assert_eq!(probed.version, "5.1.0");
    assert_eq!(probed.oci_runtime, "crun");
    assert_eq!(probed.cgroup_manager, "cgroupfs");
    assert_eq!(probed.cgroup_version, "v2");
}

#[test]
fn a_runtime_that_cannot_be_asked_is_a_failure_never_a_permissive_default() {
    let error = probe_with(None).unwrap_err();
    let text = error.to_string();
    assert!(text.contains("podman info:"), "{text}");
    assert!(
        text.contains("cannot connect to the Podman socket"),
        "{text}"
    );
    // An answer missing the fields the probe decides on is refused, not read as rootless.
    assert!(probe_with(Some("")).is_err());
    assert!(probe_with(Some("true")).is_err());
}
