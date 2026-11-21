#![cfg(target_os = "linux")]

//! AR03: the runner sandbox's lifecycle on a container runtime — one container per lease, the
//! runner's only interface to its configuration is its standard input, and nothing of that
//! configuration reaches a host path the worker manages.
//!
//! Skipped unless `SENTINEL_PODMAN_TESTS` is set (as the other sandbox suites are) and
//! `SENTINEL_RUNNER_IMAGE` names a digest-pinned runner image the runtime already holds, because
//! [`Plan`] pulls never: what a worker runs is the digest its operator recorded.

use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    sync::atomic::AtomicBool,
    time::{Duration, Instant},
};

use sentinel_core::{RunnerLeaseId, WorkerId};
use sentinel_worker::{
    microvm::net,
    podman::{self, Limits, Network},
    runner::{Grant, Image, MAX_CONFIG_BYTES, Plan},
};

/// The canary this suite looks for in every sink. It is the marker a real answer would carry: a fake
/// configuration is still a credential-shaped value, so how far it travels is the question.
const MARKER: &str = "SENTINEL-AR03-CANARY-marker-9137";

fn enabled() -> bool {
    if std::env::var_os("SENTINEL_PODMAN_TESTS").is_some() {
        return true;
    }
    eprintln!("skipped: set SENTINEL_PODMAN_TESTS=1 as a container-runtime account to run");
    false
}

/// The image the operator pinned, and only a pinned one: a tag is refused before anything is created.
fn image() -> Option<Image> {
    let Some(reference) = std::env::var_os("SENTINEL_RUNNER_IMAGE") else {
        eprintln!("skipped: set SENTINEL_RUNNER_IMAGE to a digest-pinned runner image to run");
        return None;
    };
    let reference = reference.to_string_lossy();
    let image = Image::parse(&reference)
        .unwrap_or_else(|| panic!("SENTINEL_RUNNER_IMAGE is not pinned by digest: {reference}"));
    // `--pull never` is the plan's: a worker runs an image it already holds, so a suite that would
    // have to pull is not running the sandbox a worker runs.
    if !Command::new("podman")
        .args(["image", "exists"])
        .arg(image.as_str())
        .status()
        .is_ok_and(|status| status.success())
    {
        eprintln!(
            "skipped: the runtime does not hold {}; pull it first",
            image.as_str()
        );
        return None;
    }
    Some(image)
}

fn plan(root: &Path, image: &Image) -> Plan {
    Plan::new(
        root,
        WorkerId::new(),
        RunnerLeaseId::new(),
        image,
        Limits {
            cpu_millis: 1_000,
            memory_bytes: 1 << 30,
            pids: 256,
            // No `--ulimit fsize`: the listener's own .NET runtime sizes a file on startup and dies of
            // SIGXFSZ under any file-size cap a disk budget would state.
            disk_bytes: 0,
            lifetime_secs: 120,
        },
        &Grant {
            network: Network::None,
            guard: &net::Guard::default(),
            actions: None,
        },
    )
    .expect("a runner sandbox is planned from a lease")
}

/// A configuration the listener accepts as base64 and then cannot use, so it ends by itself instead
/// of retrying a server that does not exist: one encoded file the JIT reader materializes into the
/// runner's installation directory, carrying the marker, and no settings at all.
fn configuration() -> Vec<u8> {
    let body = format!("{{\"sentinel-ar03\":\"{}\"}}", base64(MARKER.as_bytes()));
    base64(body.as_bytes()).into_bytes()
}

/// Standard base64 with padding, which is what the runner's `--jitconfig` takes.
fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for group in bytes.chunks(3) {
        let n = group
            .iter()
            .enumerate()
            .fold(0u32, |n, (i, byte)| n | (u32::from(*byte) << (16 - 8 * i)));
        for i in 0..4 {
            if i <= group.len() {
                out.push(char::from(ALPHABET[((n >> (18 - 6 * i)) & 0x3f) as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// Whether the runtime holds a container of that name: `podman container exists` answers 0 when it
/// does and 1 when it does not, and any other answer counts as present so a broken runtime is never
/// read as a clean teardown.
fn present(name: &str) -> bool {
    !Command::new("podman")
        .args(["container", "exists", name])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|status| status.code() == Some(1))
}

fn inspect(name: &str, format: &str) -> String {
    let output = Command::new("podman")
        .args(["inspect", "--format", format, "--", name])
        .output()
        .expect("podman inspect runs");
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// Whether any file below `dir` holds `needle`: the whole lease directory is one sink, and a file the
/// job wrote is as much of one as a file the worker wrote.
fn contains(dir: &Path, needle: &str) -> Option<PathBuf> {
    let mut pending = vec![dir.to_path_buf()];
    while let Some(path) = pending.pop() {
        let Ok(entries) = fs::read_dir(&path) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            match entry.file_type() {
                Ok(kind) if kind.is_dir() => pending.push(path),
                Ok(_) => {
                    if fs::read(&path).is_ok_and(|bytes| {
                        bytes
                            .windows(needle.len())
                            .any(|window| window == needle.as_bytes())
                    }) {
                        return Some(path);
                    }
                }
                Err(_) => continue,
            }
        }
    }
    None
}

/// Removes what a failed assertion left: a sandbox's teardown is the thing under test, so a panic
/// must not leave the container or the directory for the next run.
struct Lease(String, PathBuf);

impl Drop for Lease {
    fn drop(&mut self) {
        if std::thread::panicking() {
            let _ = podman::remove_named(&self.0, &podman::Store::Shared);
            let _ = fs::remove_dir_all(&self.1);
        }
    }
}

#[test]
fn a_runner_sandbox_runs_once_and_leaves_nothing_behind() {
    if !enabled() {
        return;
    }
    let Some(image) = image() else {
        return;
    };
    let temp = tempfile::tempdir().unwrap();
    let plan = plan(temp.path(), &image);
    let _lease = Lease(plan.name().to_owned(), plan.dir().to_path_buf());
    let config = configuration();
    let cancel = AtomicBool::new(false);

    // The container exists while the runner runs, and neither its environment nor its command line
    // carries the configuration: those are the two sinks a process listing would expose.
    let outcome = std::thread::scope(|scope| {
        let start = scope.spawn(|| plan.start(&config, &cancel));
        let deadline = Instant::now() + Duration::from_secs(60);
        while !present(plan.name()) {
            assert!(Instant::now() < deadline, "the container was never created");
            std::thread::sleep(Duration::from_millis(10));
        }
        for (field, format) in [
            ("environment", "{{json .Config.Env}}"),
            ("command", "{{json .Config.Cmd}}"),
            ("arguments", "{{json .Args}}"),
        ] {
            let seen = inspect(plan.name(), format);
            assert!(
                !seen.contains(MARKER),
                "the sandbox's {field} holds the configuration: {seen}"
            );
        }
        start.join().unwrap()
    });

    // The run ends by itself, with a code, and nobody killing it: the configuration is one the
    // listener cannot use, which is the honest fake — a plausible one has it retrying a server that
    // does not exist until the sandbox's lifetime ends it.
    let exit = outcome.expect("the runner sandbox starts and its runner ends");
    assert!(!exit.canceled, "{exit:?}");
    assert!(
        matches!(exit.code, Some(code) if code != 0),
        "the runner did not end with a failure of its own: {exit:?}"
    );

    // `--rm` removed it with the runner, so nothing outlives the lease.
    assert!(!present(plan.name()), "the container outlived its runner");
    if let Some(path) = contains(plan.dir(), MARKER) {
        panic!("the configuration reached {}", path.display());
    }
    let dir = plan.dir().to_path_buf();
    plan.destroy().expect("the sandbox is torn down");
    assert!(!dir.exists(), "the lease directory outlived the sandbox");
    assert!(!present(plan.name()), "the container outlived its teardown");
}

#[test]
fn a_configuration_over_the_workers_bound_is_refused_before_anything_exists() {
    if !enabled() {
        return;
    }
    let Some(image) = image() else {
        return;
    };
    let temp = tempfile::tempdir().unwrap();
    let plan = plan(temp.path(), &image);
    let cancel = AtomicBool::new(false);
    for config in [Vec::new(), vec![b'A'; MAX_CONFIG_BYTES + 1]] {
        let refused = plan.start(&config, &cancel);
        let bytes = config.len();
        assert!(refused.is_err(), "a {bytes}-byte configuration was started");
        assert!(
            !present(plan.name()),
            "a refused configuration made a container"
        );
        assert!(
            !plan.dir().exists(),
            "a refused {bytes}-byte configuration made a directory"
        );
    }
}
