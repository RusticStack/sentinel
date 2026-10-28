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
        snapshots: true,
        guard: Default::default(),
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
    assert_scope_gone(root.path(), attempt);
}

fn assert_scope_gone(root: &std::path::Path, attempt: AttemptId) {
    let status = std::process::Command::new("systemctl")
        .args(["--user", "is-active", &microvm::scope_name(root, attempt)])
        .output()
        .unwrap();
    assert_ne!(text(&status.stdout), "active", "the VM's scope is gone");
}

const IMAGE_DIGEST: &str =
    "sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662";

#[test]
fn the_digest_a_guest_ran_is_the_pinned_one_and_its_image_is_reused() {
    let Some(setup) = setup() else { return };
    pull();
    let root = tempfile::tempdir().unwrap();
    let workspace = tempfile::tempdir().unwrap();
    let (_, first) = start(root.path(), &setup, workspace.path(), &[]);
    let record = first.guest_image().clone();
    assert_eq!(record.digest, IMAGE_DIGEST);
    assert!(record.built && record.build_ns.is_some() && record.rootfs_bytes > 0);
    first.destroy().unwrap();
    let (_, second) = start(root.path(), &setup, workspace.path(), &[]);
    let reused = second.guest_image();
    assert_eq!(reused.digest, IMAGE_DIGEST);
    assert!(!reused.built && reused.build_ns.is_none());
    assert_eq!(reused.rootfs_bytes, record.rootfs_bytes);
    second.destroy().unwrap();
    let cached = microvm::guest_images(root.path());
    assert_eq!(cached.len(), 1);
    assert_eq!(cached[0].digest, IMAGE_DIGEST);
    assert!(microvm::remove_guest_image(root.path(), &cached[0].key));
    assert!(microvm::guest_images(root.path()).is_empty());
}

#[test]
fn the_guest_has_no_kvm() {
    let Some(setup) = setup() else { return };
    pull();
    let root = tempfile::tempdir().unwrap();
    let workspace = tempfile::tempdir().unwrap();
    let (_, vm) = start(root.path(), &setup, workspace.path(), &[]);
    let exit = vm
        .exec(
            &sh(
                "test ! -e /dev/kvm && ! grep -Eqw 'vmx|svm' /proc/cpuinfo",
                60,
            ),
            &[],
        )
        .unwrap();
    assert_eq!(exit.code, Some(0), "{}", text(&exit.stderr));
    vm.destroy().unwrap();
}

#[test]
fn reconciliation_removes_a_vm_a_crashed_worker_left_running() {
    let Some(setup) = setup() else { return };
    pull();
    let root = tempfile::tempdir().unwrap();
    let workspace = tempfile::tempdir().unwrap();
    let (attempt, vm) = start(root.path(), &setup, workspace.path(), &[]);
    // The worker dies without tearing the VM down: nothing runs its destroy.
    std::mem::forget(vm);
    assert!(microvm::exists(root.path(), attempt));
    assert_eq!(microvm::reconcile(root.path()).unwrap(), 1);
    assert!(!microvm::exists(root.path(), attempt));
    assert!(microvm::owned(root.path()).is_empty());
    assert_scope_gone(root.path(), attempt);
    // systemd unloads a killed scope a moment after it stops; a pass that sees it still listed removes nothing.
    let mut left = usize::MAX;
    for _ in 0..50 {
        left = microvm::reconcile(root.path()).unwrap();
        if left == 0 {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert_eq!(left, 0, "a second pass finds nothing left");
}

#[test]
fn losing_the_lease_kills_the_vm_and_ends_the_running_step() {
    let Some(setup) = setup() else { return };
    pull();
    let root = tempfile::tempdir().unwrap();
    let workspace = tempfile::tempdir().unwrap();
    let (attempt, vm) = start(root.path(), &setup, workspace.path(), &[]);
    let vm = Arc::new(vm);
    let running = {
        let vm = Arc::clone(&vm);
        std::thread::spawn(move || vm.exec(&sh("sleep 600", 600), &[]))
    };
    std::thread::sleep(Duration::from_millis(500));
    let started = Instant::now();
    microvm::remove_named(root.path(), attempt).unwrap();
    assert!(
        running.join().unwrap().is_err(),
        "the step is cut off with its VM"
    );
    assert!(started.elapsed() < Duration::from_secs(5));
    assert!(!microvm::exists(root.path(), attempt));
    assert_scope_gone(root.path(), attempt);
    let _ = Arc::try_unwrap(vm).map(|vm| vm.destroy());
}

#[test]
fn a_cancel_during_the_start_leaves_no_vm() {
    let Some(setup) = setup() else { return };
    pull();
    let root = tempfile::tempdir().unwrap();
    let workspace = tempfile::tempdir().unwrap();
    let attempt = AttemptId::new();
    let cancel = Arc::new(AtomicBool::new(false));
    let starting = {
        let (root, workspace, cancel) = (
            root.path().to_path_buf(),
            workspace.path().to_path_buf(),
            Arc::clone(&cancel),
        );
        std::thread::spawn(move || {
            // A fresh data root: the guest image is built first, which takes long enough to cancel.
            Vm::start_canceled(
                &root,
                &setup,
                WorkerId::new(),
                attempt,
                IMAGE,
                limits(),
                &workspace,
                &[],
                &Store::Shared,
                Network::None,
                &cancel,
            )
        })
    };
    std::thread::sleep(Duration::from_millis(50));
    assert!(
        microvm::exists(root.path(), attempt),
        "the VM is found by name from the start of its start"
    );
    cancel.store(true, std::sync::atomic::Ordering::Release);
    microvm::remove_named(root.path(), attempt).unwrap();
    assert!(starting.join().unwrap().is_err());
    assert!(!microvm::exists(root.path(), attempt));
    assert_scope_gone(root.path(), attempt);
}

// ---------------------------------------------------------------- M06: snapshot warm start

fn start_net(
    root: &std::path::Path,
    setup: &Setup,
    workspace: &std::path::Path,
    network: Network,
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
        &[],
        &Store::Shared,
        network,
    )
    .unwrap();
    eprintln!("start report: {:?}", vm.start_report());
    (attempt, vm)
}

fn snapshots(root: &std::path::Path) -> Vec<PathBuf> {
    let dir = root.join(microvm::DIR).join("snapshots");
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut all: Vec<PathBuf> = entries.flatten().map(|e| e.path()).collect();
    all.sort();
    all
}

fn nothing_left(root: &std::path::Path, attempts: &[AttemptId]) {
    assert!(microvm::owned(root).is_empty(), "no VM directory remains");
    for attempt in attempts {
        assert_scope_gone(root, *attempt);
    }
    let run = root.join(microvm::DIR).join("run");
    assert!(
        run.read_dir()
            .map(|mut d| d.next().is_none())
            .unwrap_or(true),
        "the fixed run path is an empty directory on the host"
    );
    assert!(
        snapshots(root)
            .iter()
            .all(|p| !p.file_name().unwrap().to_string_lossy().starts_with('.')),
        "no snapshot build is left half done"
    );
}

#[test]
fn the_first_vm_of_a_shape_builds_a_snapshot_and_the_next_ones_restore_it_with_their_own_state() {
    let Some(setup) = setup() else { return };
    pull();
    let root = tempfile::tempdir().unwrap();
    let workspace = tempfile::tempdir().unwrap();
    let (a_id, a) = start_net(root.path(), &setup, workspace.path(), Network::None);
    let first = a.start_report().clone();
    assert_eq!(first.mode, microvm::Start::Restored, "{first:?}");
    assert!(
        first.snapshot_built && first.fallback.is_none(),
        "{first:?}"
    );
    assert_eq!(snapshots(root.path()).len(), 1);

    // State this attempt writes: into the image overlay (the scratch disk), its memory and its random stream.
    let wrote = a
        .exec(
            &sh("echo mine > /etc/attempt-a; echo mem > /tmp/a; head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n'", 60),
            &[],
        )
        .unwrap();
    assert_eq!(wrote.code, Some(0), "{}", text(&wrote.stderr));
    let rand_a = text(&wrote.stdout);

    let started = Instant::now();
    let (b_id, b) = start_net(root.path(), &setup, workspace.path(), Network::None);
    eprintln!("second start (restore): {:?}", started.elapsed());
    let second = b.start_report().clone();
    assert_eq!(second.mode, microvm::Start::Restored, "{second:?}");
    assert!(
        !second.snapshot_built && second.fallback.is_none(),
        "{second:?}"
    );
    assert_eq!(snapshots(root.path()).len(), 1, "the snapshot is shared");
    let seen = b
        .exec(
            &sh("test ! -e /etc/attempt-a && test ! -e /tmp/a && head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n'; echo; date +%s", 60),
            &[],
        )
        .unwrap();
    assert_eq!(
        seen.code,
        Some(0),
        "A's state leaked into B: {}",
        text(&seen.stderr)
    );
    let out = text(&seen.stdout);
    let mut lines = out.lines();
    let rand_b = lines.next().unwrap();
    let clock: i64 = lines.next().unwrap().parse().unwrap();
    assert_ne!(
        rand_a, rand_b,
        "two restores must not share a random stream"
    );
    let host = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    assert!(
        (host - clock).abs() <= 5,
        "guest clock {clock} vs host {host}"
    );

    // A's own state is intact while B runs.
    let still = a.exec(&sh("cat /etc/attempt-a /tmp/a", 60), &[]).unwrap();
    assert_eq!(text(&still.stdout), "mine\nmem");

    a.destroy().unwrap();
    b.destroy().unwrap();
    nothing_left(root.path(), &[a_id, b_id]);
    // The snapshot itself holds no attempt's data.
    let snap = &snapshots(root.path())[0];
    assert!(
        !fs::read(snap.join("scratch.ext4"))
            .unwrap()
            .windows(9)
            .any(|w| w == b"attempt-a")
    );
}

#[test]
fn with_snapshots_off_every_vm_boots_cold_and_makes_none() {
    let Some(mut setup) = setup() else { return };
    setup.snapshots = false;
    pull();
    let root = tempfile::tempdir().unwrap();
    let workspace = tempfile::tempdir().unwrap();
    let (id, vm) = start_net(root.path(), &setup, workspace.path(), Network::None);
    let report = vm.start_report().clone();
    assert_eq!(report.mode, microvm::Start::Cold);
    assert!(report.fallback.is_none() && !report.snapshot_built);
    assert!(snapshots(root.path()).is_empty());
    vm.destroy().unwrap();
    nothing_left(root.path(), &[id]);
}

#[test]
fn a_snapshot_that_cannot_be_restored_falls_back_to_a_cold_boot_and_is_rebuilt() {
    let Some(setup) = setup() else { return };
    pull();
    let root = tempfile::tempdir().unwrap();
    let workspace = tempfile::tempdir().unwrap();
    let (id, first) = start_net(root.path(), &setup, workspace.path(), Network::None);
    first.destroy().unwrap();
    let snap = snapshots(root.path()).remove(0);
    // Damage the saved VM state in a way the marker and the sizes do not show.
    let state = snap.join("state");
    let len = fs::metadata(&state).unwrap().len() as usize;
    fs::write(&state, vec![0xA5u8; len]).unwrap();

    let (b_id, b) = start_net(root.path(), &setup, workspace.path(), Network::None);
    let report = b.start_report().clone();
    assert_eq!(report.mode, microvm::Start::Cold, "{report:?}");
    assert!(
        report
            .fallback
            .as_deref()
            .is_some_and(|f| f.contains("restoring the snapshot failed")),
        "{report:?}"
    );
    let ran = b.exec(&sh("echo cold-and-working", 60), &[]).unwrap();
    assert_eq!(text(&ran.stdout), "cold-and-working");
    b.destroy().unwrap();
    assert!(
        snapshots(root.path()).is_empty(),
        "the unusable snapshot is gone"
    );

    let (c_id, c) = start_net(root.path(), &setup, workspace.path(), Network::None);
    assert_eq!(c.start_report().mode, microvm::Start::Restored);
    assert!(c.start_report().snapshot_built);
    c.destroy().unwrap();
    nothing_left(root.path(), &[id, b_id, c_id]);
}

#[test]
fn simultaneous_first_starts_of_a_shape_publish_one_snapshot_and_both_run() {
    let Some(setup) = setup() else { return };
    pull();
    let root = tempfile::tempdir().unwrap();
    let workspace = tempfile::tempdir().unwrap();
    // The image is built once up front so the race is about the snapshot.
    let (id, warm) = start_net(root.path(), &setup, workspace.path(), Network::None);
    warm.destroy().unwrap();
    for entry in snapshots(root.path()) {
        fs::remove_dir_all(entry).unwrap();
    }
    let starts: Vec<_> = (0..2)
        .map(|_| {
            let (root, workspace, setup) = (
                root.path().to_path_buf(),
                workspace.path().to_path_buf(),
                setup.clone(),
            );
            std::thread::spawn(move || start_net(&root, &setup, &workspace, Network::None))
        })
        .collect();
    let mut ids = vec![id];
    for start in starts {
        let (attempt, vm) = start.join().unwrap();
        let ran = vm.exec(&sh("echo ok", 60), &[]).unwrap();
        assert_eq!(text(&ran.stdout), "ok");
        vm.destroy().unwrap();
        ids.push(attempt);
    }
    assert_eq!(snapshots(root.path()).len(), 1);
    nothing_left(root.path(), &ids);
}

#[test]
fn removing_a_guest_image_removes_its_snapshots() {
    let Some(setup) = setup() else { return };
    pull();
    let root = tempfile::tempdir().unwrap();
    let workspace = tempfile::tempdir().unwrap();
    let (_, vm) = start_net(root.path(), &setup, workspace.path(), Network::None);
    vm.destroy().unwrap();
    let image = microvm::guest_images(root.path()).remove(0);
    assert!(
        image.bytes > vm_image_bytes(root.path()),
        "the budget counts the snapshot beside the root file system"
    );
    assert_eq!(snapshots(root.path()).len(), 1);
    assert!(microvm::remove_guest_image(root.path(), &image.key));
    assert!(snapshots(root.path()).is_empty());
}

/// The root file system's own size, as the image directory holds it.
fn vm_image_bytes(root: &std::path::Path) -> u64 {
    fs::read_dir(root.join(microvm::DIR).join("images"))
        .unwrap()
        .flatten()
        .filter(|e| e.path().extension().is_some_and(|x| x == "ext4"))
        .map(|e| e.metadata().unwrap().len())
        .sum()
}

// ---------------------------------------------------------------- M05: network

/// A listener the guest must never reach; it records whether anything connected.
fn listener(addr: &str) -> (std::net::TcpListener, std::net::SocketAddr) {
    let listener = std::net::TcpListener::bind(format!("{addr}:0")).unwrap();
    listener.set_nonblocking(true).unwrap();
    let bound = listener.local_addr().unwrap();
    (listener, bound)
}

fn connects(vm: &Vm, host: &str, port: u16) -> bool {
    let exit = vm
        .exec(&sh(&format!("nc -w 2 {host} {port} < /dev/null"), 30), &[])
        .unwrap();
    exit.code == Some(0)
}

fn egress_target() -> (String, u16) {
    let target =
        std::env::var("SENTINEL_MICROVM_EGRESS_TARGET").unwrap_or_else(|_| "1.1.1.1:443".into());
    let (host, port) = target.rsplit_once(':').unwrap();
    (host.to_owned(), port.parse().unwrap())
}

#[test]
fn the_rules_are_accepted_by_nft() {
    if std::env::var_os("SENTINEL_MICROVM_TESTS").is_none() {
        eprintln!(
            "skipped: set SENTINEL_MICROVM_TESTS=1 as an account with rootless Podman and nft"
        );
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let host = microvm::net::host_addresses().unwrap();
    let guard = microvm::net::Guard {
        link: vec![
            "198.51.100.9:7443".parse().unwrap(),
            "127.0.0.1:9000".parse().unwrap(),
        ],
    };
    let rules = microvm::net::Policy::new(&host, &guard).rules();
    let file = dir.path().join("egress.nft");
    fs::write(&file, &rules).unwrap();
    let out = std::process::Command::new("podman")
        .args(["unshare", "unshare", "--net", "nft", "-c", "-f"])
        .arg(&file)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "nft refused the rules: {}\n{rules}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn a_guest_without_egress_has_no_network_interface() {
    let Some(setup) = setup() else { return };
    pull();
    let root = tempfile::tempdir().unwrap();
    let workspace = tempfile::tempdir().unwrap();
    let (id, vm) = start_net(root.path(), &setup, workspace.path(), Network::None);
    let exit = vm.exec(&sh("ls /sys/class/net", 30), &[]).unwrap();
    assert_eq!(text(&exit.stdout), "lo", "{}", text(&exit.stderr));
    assert!(!connects(&vm, "1.1.1.1", 443));
    vm.destroy().unwrap();
    nothing_left(root.path(), &[id]);
}

#[test]
fn a_granted_guest_reaches_out_but_not_the_host_the_link_or_metadata() {
    let Some(mut setup) = setup() else { return };
    pull();
    // What the guest must not reach: a service on loopback, one on each non-loopback address of the host, and
    // the worker's own link endpoint (here a listener standing for the controller).
    let (loopback, loopback_addr) = listener("127.0.0.1");
    let (link, link_addr) = listener("127.0.0.1");
    setup.guard.link = vec![link_addr];
    let mut watched = vec![loopback, link];
    let mut targets = vec![
        ("127.0.0.1".to_owned(), loopback_addr.port()),
        ("127.0.0.1".to_owned(), link_addr.port()),
    ];
    for address in microvm::net::host_addresses().unwrap() {
        if address.is_loopback() {
            continue;
        }
        let (l, bound) = listener(&address.to_string());
        watched.push(l);
        targets.push((address.to_string(), bound.port()));
    }
    let root = tempfile::tempdir().unwrap();
    let workspace = tempfile::tempdir().unwrap();
    let (id, vm) = start_net(root.path(), &setup, workspace.path(), Network::Egress);
    let net = vm
        .exec(&sh("ip -4 -o addr show eth0; ip route", 30), &[])
        .unwrap();
    eprintln!("guest network:\n{}", text(&net.stdout));
    for (host, port) in &targets {
        assert!(
            !connects(&vm, host, *port),
            "the guest reached {host}:{port}"
        );
    }
    // The namespace's own side of the tap and the link-local range with the metadata endpoints.
    for (host, port) in [
        ("10.211.0.1", 22u16),
        ("169.254.169.254", 80),
        ("169.254.170.2", 80),
    ] {
        assert!(
            !connects(&vm, host, port),
            "the guest reached {host}:{port}"
        );
    }
    for listener in &watched {
        assert!(
            listener.accept().is_err(),
            "something connected to a service the guest must not reach"
        );
    }
    // Egress works where granted: a name resolves and a public address answers.
    let (host, port) = egress_target();
    assert!(connects(&vm, &host, port), "no egress to {host}:{port}");
    let dns = vm.exec(&sh("nslookup example.com", 30), &[]).unwrap();
    assert_eq!(
        dns.code,
        Some(0),
        "{}{}",
        text(&dns.stdout),
        text(&dns.stderr)
    );
    vm.destroy().unwrap();
    nothing_left(root.path(), &[id]);
}

#[test]
fn a_restored_guest_keeps_its_network_and_its_policy() {
    let Some(mut setup) = setup() else { return };
    pull();
    let (link, link_addr) = listener("127.0.0.1");
    setup.guard.link = vec![link_addr];
    let root = tempfile::tempdir().unwrap();
    let workspace = tempfile::tempdir().unwrap();
    let (a_id, a) = start_net(root.path(), &setup, workspace.path(), Network::Egress);
    a.destroy().unwrap();
    let (b_id, b) = start_net(root.path(), &setup, workspace.path(), Network::Egress);
    assert_eq!(
        b.start_report().mode,
        microvm::Start::Restored,
        "{:?}",
        b.start_report()
    );
    let (host, port) = egress_target();
    assert!(connects(&b, &host, port), "no egress after a restore");
    assert!(!connects(&b, "127.0.0.1", link_addr.port()));
    assert!(link.accept().is_err());
    b.destroy().unwrap();
    nothing_left(root.path(), &[a_id, b_id]);
}

// ---------------------------------------------------------------- M06: the warm-start measurement

/// The nearest-rank percentile of a sorted sample.
fn percentile(sorted: &[u64], p: f64) -> u64 {
    let rank = ((p / 100.0) * sorted.len() as f64).ceil() as usize;
    sorted[rank.clamp(1, sorted.len()) - 1]
}

/// One sample series: for each VM, the time from the call of `Vm::start` until the first user process (`true`)
/// has exited, and the guest-ready time the start report itself measured. Every VM is destroyed before the next
/// starts, so the series is the serial per-attempt cost, not a stampede.
fn start_samples(
    root: &std::path::Path,
    setup: &Setup,
    workspace: &std::path::Path,
    n: usize,
    network: Network,
) -> (Vec<u64>, Vec<u64>) {
    let mut first_process = Vec::with_capacity(n);
    let mut ready = Vec::with_capacity(n);
    for _ in 0..n {
        let started = Instant::now();
        let (id, vm) = start_net(root, setup, workspace, network);
        let exit = vm.exec(&sh("true", 60), &[]).unwrap();
        let total = started.elapsed().as_nanos() as u64;
        assert_eq!(exit.code, Some(0));
        let report = vm.start_report().clone();
        assert!(report.fallback.is_none(), "{report:?}");
        first_process.push(total);
        ready.push(report.ready_ns);
        vm.destroy().unwrap();
        nothing_left(root, &[id]);
    }
    first_process.sort_unstable();
    ready.sort_unstable();
    (first_process, ready)
}

/// The M06 gate's measurement (TODO M06): `SENTINEL_MICROVM_BENCH=<n>` takes `n` cold and `n` restored starts of
/// the same shape on the KVM host and writes one record per path to `SENTINEL_MICROVM_BENCH_OUT` (default: the
/// test's stderr). The restored series follows a warm-up start that builds the snapshot, so it contains only
/// restores. It measures the worker's `Vm::start` plus the first step, not the controller's queue time: the
/// end-to-end figure of the budget (`bench/b03-latency.py` against a microVM worker) is the one that is
/// published against p95 < 2 s; this one attributes the time. The host label, load and binaries' digests are
/// the caller's to add when the record is committed.
#[test]
fn the_cold_and_restored_start_to_first_process_distributions() {
    let Some(setup) = setup() else { return };
    let Some(n) = std::env::var("SENTINEL_MICROVM_BENCH")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|n| *n > 0)
    else {
        eprintln!("skipped: set SENTINEL_MICROVM_BENCH=<samples per path> on a quiet KVM host");
        return;
    };
    pull();
    let cpu_pressure = fs::read_to_string("/proc/pressure/cpu").unwrap_or_default();
    let loadavg = fs::read_to_string("/proc/loadavg").unwrap_or_default();
    let workspace = tempfile::tempdir().unwrap();
    let mut lines = Vec::new();
    for (mode, snapshots) in [("cold", false), ("restore", true)] {
        let mut setup = setup.clone();
        setup.snapshots = snapshots;
        let root = tempfile::tempdir().unwrap();
        if snapshots {
            // The warm-up builds the snapshot; its cost is the first attempt of a shape, not a restore.
            let (id, vm) = start_net(root.path(), &setup, workspace.path(), Network::None);
            assert!(vm.start_report().snapshot_built);
            vm.destroy().unwrap();
            nothing_left(root.path(), &[id]);
        }
        let (first, ready) = start_samples(root.path(), &setup, workspace.path(), n, Network::None);
        let stats = |s: &[u64]| {
            serde_json::json!({
                "p50_ns": percentile(s, 50.0),
                "p95_ns": percentile(s, 95.0),
                "p99_ns": percentile(s, 99.0),
                "max_ns": s[s.len() - 1],
            })
        };
        lines.push(
            serde_json::json!({
                "schema": "sentinel-bench/m06/1",
                "mode": mode,
                "samples": n,
                "start_to_first_process": stats(&first),
                "guest_ready": stats(&ready),
                "host": { "loadavg": loadavg.trim(), "cpu_pressure": cpu_pressure.trim() },
            })
            .to_string(),
        );
    }
    let out = lines.join("\n") + "\n";
    match std::env::var_os("SENTINEL_MICROVM_BENCH_OUT") {
        Some(path) => fs::write(path, &out).unwrap(),
        None => eprintln!("{out}"),
    }
}
