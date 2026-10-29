#![cfg(target_os = "linux")]
//! The microVM executor end to end (TODO M04): a Firecracker guest per attempt on a KVM host.
//! Runs only with SENTINEL_MICROVM_TESTS=1 and the setup in SENTINEL_FIRECRACKER, SENTINEL_GUEST_KERNEL and
//! SENTINEL_GUEST_AGENT, as an account that can use /dev/kvm and rootless Podman.

use std::{
    fs,
    path::PathBuf,
    sync::{Arc, Mutex, atomic::AtomicBool},
    time::{Duration, Instant},
};

use sentinel_core::{AttemptId, WorkerId};
use sentinel_pipeline::run::StepCommand;
use sentinel_worker::{
    microvm::{self, Setup, Vm},
    podman::{self, Limits, Mount, Network, Store, Terminated},
};

const IMAGE: &str = "docker.io/library/busybox@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662";

fn setup() -> Option<Setup> {
    if std::env::var_os("SENTINEL_MICROVM_TESTS").is_none() {
        eprintln!(
            "skipped: set SENTINEL_MICROVM_TESTS=1 and the SENTINEL_FIRECRACKER, SENTINEL_GUEST_KERNEL, SENTINEL_GUEST_AGENT paths on a KVM host"
        );
        return None;
    }
    let path = |name: &str| {
        PathBuf::from(std::env::var_os(name).unwrap_or_else(|| panic!("{name} is required")))
    };
    let setup = Setup {
        firecracker: path("SENTINEL_FIRECRACKER"),
        kernel: path("SENTINEL_GUEST_KERNEL"),
        agent: path("SENTINEL_GUEST_AGENT"),
    };
    setup.check().unwrap();
    Some(setup)
}

fn pull() {
    let temp = tempfile::tempdir().unwrap();
    let authfile = sentinel_worker::images::prepare_anonymous_authfile(temp.path()).unwrap();
    podman::pull(
        IMAGE,
        &authfile,
        &Store::Shared,
        Duration::from_secs(600),
        &AtomicBool::new(false),
    )
    .unwrap();
}

fn sh(script: &str, timeout_secs: u64) -> StepCommand {
    StepCommand {
        argv: vec!["/bin/sh".into(), "-e".into(), "-c".into(), script.into()],
        env: vec![("STEP".into(), "step-env".into())],
        secrets: Vec::new(),
        secret_files: Vec::new(),
        workdir: None,
        timeout_secs,
    }
}

fn limits() -> Limits {
    Limits {
        cpu_millis: 1000,
        memory_bytes: 512 << 20,
        pids: 1024,
        disk_bytes: 1 << 30,
        lifetime_secs: 600,
    }
}

fn start(
    root: &std::path::Path,
    setup: &Setup,
    workspace: &std::path::Path,
    mounts: &[Mount],
) -> (AttemptId, Vm) {
    let attempt = AttemptId::new();
    let vm = Vm::start(
        root,
        setup,
        WorkerId::new(),
        attempt,
        IMAGE,
        limits(),
        workspace,
        mounts,
        &Store::Shared,
        Network::None,
    )
    .unwrap();
    (attempt, vm)
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).trim().to_owned()
}

#[test]
fn a_guest_runs_steps_with_the_workspace_and_brings_back_what_the_host_reads() {
    let Some(setup) = setup() else { return };
    pull();
    let root = tempfile::tempdir().unwrap();
    let workspace = tempfile::tempdir().unwrap();
    fs::write(workspace.path().join("source.txt"), "checked out\n").unwrap();
    fs::create_dir_all(workspace.path().join("sub/dir")).unwrap();
    fs::write(workspace.path().join(".sentinel-cache"), "never shipped").unwrap();
    let cache = tempfile::tempdir().unwrap();
    fs::write(cache.path().join("restored"), "from the host").unwrap();
    let mounts = [Mount {
        host: cache.path().to_path_buf(),
        container: "/cache/c".into(),
        read_only: false,
    }];
    let started = Instant::now();
    let (attempt, vm) = start(root.path(), &setup, workspace.path(), &mounts);
    eprintln!(
        "start (image build on first use, boot, put): {:?}",
        started.elapsed()
    );
    assert!(microvm::exists(root.path(), attempt));

    let seen = Arc::new(Mutex::new(Vec::new()));
    let sink: sentinel_worker::OutputSink = {
        let seen = Arc::clone(&seen);
        Arc::new(move |_, bytes: &[u8]| seen.lock().unwrap().extend_from_slice(bytes))
    };
    let exit = vm
        .exec_streaming(
            &sh("cat source.txt; pwd; echo $STEP $EXTRA; test ! -e .sentinel-cache; cat /cache/c/restored; ls /sub 2>/dev/null || true", 60),
            &[("EXTRA".into(), "worker-env".into())],
            Some(sink),
        )
        .unwrap();
    assert_eq!(exit.code, Some(0), "{}", text(&exit.stderr));
    let out = text(&exit.stdout);
    assert_eq!(
        out.lines().collect::<Vec<_>>(),
        [
            "checked out",
            "/workspace",
            "step-env worker-env",
            "from the host"
        ]
    );
    assert_eq!(
        text(&seen.lock().unwrap()),
        out,
        "the sink saw the same output"
    );

    let failed = vm.exec(&sh("echo to-stderr >&2; exit 7", 60), &[]).unwrap();
    assert_eq!(
        (failed.code, text(&failed.stderr).as_str()),
        (Some(7), "to-stderr")
    );
    let in_dir = vm
        .exec(
            &StepCommand {
                workdir: Some("sub/dir".into()),
                ..sh("pwd", 60)
            },
            &[],
        )
        .unwrap();
    assert_eq!(text(&in_dir.stdout), "/workspace/sub/dir");

    let made = vm
        .exec(&sh("mkdir -p out && echo built > out/app && echo cached > /cache/c/new && rm /cache/c/restored && echo scratch > notanartifact", 60), &[])
        .unwrap();
    assert_eq!(made.code, Some(0));
    vm.sync_out(workspace.path(), &["out/app".into(), "missing".into()])
        .unwrap();
    assert_eq!(
        fs::read_to_string(workspace.path().join("out/app")).unwrap(),
        "built\n"
    );
    assert!(
        !workspace.path().join("notanartifact").exists(),
        "only declared paths come back"
    );
    assert_eq!(
        fs::read_to_string(cache.path().join("new")).unwrap(),
        "cached\n"
    );
    assert!(
        !cache.path().join("restored").exists(),
        "the mount mirrors the guest's view"
    );

    let timed = vm.exec(&sh("sleep 30", 1), &[]).unwrap();
    assert!(timed.timed_out);
    let after = vm.exec(&sh("echo alive", 60), &[]).unwrap();
    assert_eq!(
        text(&after.stdout),
        "alive",
        "the guest serves steps after a timeout"
    );

    vm.destroy().unwrap();
    assert!(!microvm::exists(root.path(), attempt));
    assert!(microvm::owned(root.path()).is_empty());
}

#[test]
fn strays_are_cleared_and_oom_kills_counted() {
    let Some(setup) = setup() else { return };
    pull();
    let root = tempfile::tempdir().unwrap();
    let workspace = tempfile::tempdir().unwrap();
    let (_, vm) = start(root.path(), &setup, workspace.path(), &[]);
    let bg = vm
        .exec(&sh("(sleep 300 &) ; echo started", 60), &[])
        .unwrap();
    assert_eq!(text(&bg.stdout), "started");
    let count = |vm: &Vm| {
        text(&vm.exec(&sh("ps -o pid= | wc -l", 60), &[]).unwrap().stdout)
            .parse::<u32>()
            .unwrap()
    };
    let with_stray = count(&vm);
    vm.clear_strays().unwrap();
    assert!(count(&vm) < with_stray, "the background sleep is gone");
    let before = vm.oom_kills().unwrap();
    let oom = vm
        .exec(
            &sh("head -c 2000000000 /dev/zero | tail > /dev/null", 120),
            &[],
        )
        .unwrap();
    assert_ne!(oom.code, Some(0));
    assert!(
        vm.oom_kills().unwrap() > before,
        "the guest kernel counted the OOM kill"
    );
    vm.destroy().unwrap();
}

#[test]
fn a_cancel_by_name_ends_the_running_step_and_removal_leaves_nothing() {
    let Some(setup) = setup() else { return };
    pull();
    let root = tempfile::tempdir().unwrap();
    let workspace = tempfile::tempdir().unwrap();
    let (attempt, vm) = start(root.path(), &setup, workspace.path(), &[]);
    let vm = Arc::new(vm);
    let running = {
        let vm = Arc::clone(&vm);
        std::thread::spawn(move || {
            vm.exec(
                &sh("trap 'echo bye; exit 3' TERM; sleep 600 & wait", 600),
                &[],
            )
            .unwrap()
        })
    };
    std::thread::sleep(Duration::from_millis(500));
    let started = Instant::now();
    let outcome =
        microvm::terminate_named(root.path(), attempt, Duration::from_millis(500)).unwrap();
    assert_eq!(outcome, Terminated::Forced);
    let exit = running.join().unwrap();
    eprintln!("cancel -> step ended: {:?}", started.elapsed());
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "cancel within the B03 budget"
    );
    assert!(exit.code == Some(3) || exit.signal.is_some(), "{exit:?}");
    microvm::remove_named(root.path(), attempt).unwrap();
    assert!(!microvm::exists(root.path(), attempt));
    let unit = format!("sentinel-vm-{attempt}.scope");
    let status = std::process::Command::new("systemctl")
        .args(["--user", "is-active", &unit])
        .output()
        .unwrap();
    assert_ne!(text(&status.stdout), "active", "the VM's scope is gone");
}

#[test]
fn a_guest_cannot_write_past_its_declared_scratch_disk() {
    let Some(setup) = setup() else { return };
    pull();
    let root = tempfile::tempdir().unwrap();
    let workspace = tempfile::tempdir().unwrap();
    // `limits()` declares 1 GiB of disk: the guest's writable layer is a scratch image of that size, so the
    // write below runs out of room inside the guest and no host-side guard is involved.
    let (_, vm) = start(root.path(), &setup, workspace.path(), &[]);
    let exit = vm
        .exec(
            &sh(
                "dd if=/dev/zero of=/workspace/big bs=1M count=1600 2>&1",
                120,
            ),
            &[],
        )
        .unwrap();
    assert_ne!(exit.code, Some(0), "{}", text(&exit.stdout));
    assert!(
        text(&exit.stdout).contains("No space left on device"),
        "{}",
        text(&exit.stdout)
    );
    let _ = vm.destroy();
}
