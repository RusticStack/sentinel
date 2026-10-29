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
    // The image is pinned by digest, so a copy in the store is the image: the registry is asked only once.
    let present = std::process::Command::new("podman")
        .args(["image", "exists", IMAGE])
        .status()
        .is_ok_and(|status| status.success());
    if present {
        return;
    }
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
    // A cache view declared by a relative path: restored into the workspace before the steps run.
    fs::create_dir_all(workspace.path().join("vendor")).unwrap();
    fs::write(workspace.path().join("vendor/old"), "restored\n").unwrap();
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
        .exec(&sh("mkdir -p out && echo built > out/app && echo cached > /cache/c/new && rm /cache/c/restored && echo scratch > notanartifact && rm vendor/old && echo fresh > vendor/new", 60), &[])
        .unwrap();
    assert_eq!(made.code, Some(0));
    vm.sync_out(
        workspace.path(),
        &["out/app".into(), "missing".into()],
        &["vendor".into()],
    )
    .unwrap();
    assert_eq!(
        fs::read_to_string(workspace.path().join("vendor/new")).unwrap(),
        "fresh\n"
    );
    assert!(
        !workspace.path().join("vendor/old").exists(),
        "a replaced view mirrors the guest, so a file the job deleted is gone"
    );
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
    assert_eq!(
        outcome,
        Terminated::Graceful,
        "the step ended on SIGTERM within the grace period"
    );
    let exit = running.join().unwrap();
    eprintln!("cancel -> step ended: {:?}", started.elapsed());
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "cancel within the B03 budget"
    );
    assert_eq!(exit.code, Some(3), "{exit:?}");
    microvm::remove_named(root.path(), attempt).unwrap();
    assert!(!microvm::exists(root.path(), attempt));
    assert_scope_gone(root.path(), attempt);
}

#[test]
fn a_step_that_ignores_the_polite_signal_is_killed_when_the_grace_period_ends() {
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
                &sh("trap '' TERM; echo up; while :; do sleep 1; done", 600),
                &[],
            )
            .unwrap()
        })
    };
    std::thread::sleep(Duration::from_millis(500));
    let grace = Duration::from_millis(700);
    let started = Instant::now();
    let outcome = microvm::terminate_named(root.path(), attempt, grace).unwrap();
    assert_eq!(outcome, Terminated::Forced);
    let exit = running.join().unwrap();
    assert!(
        started.elapsed() >= grace,
        "the step had its whole grace period"
    );
    assert_eq!(exit.signal, Some(libc::SIGKILL), "{exit:?}");
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
fn a_steps_secrets_live_in_guest_memory_and_are_gone_after_it() {
    let Some(setup) = setup() else { return };
    pull();
    let root = tempfile::tempdir().unwrap();
    let workspace = tempfile::tempdir().unwrap();
    let (_, vm) = start(root.path(), &setup, workspace.path(), &[]);
    let (files, env) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    fs::create_dir(files.path().join("deep")).unwrap();
    fs::write(files.path().join("deep/token"), "file-secret").unwrap();
    fs::write(env.path().join("step-0.sh"), "export TOKEN='env-secret'\n").unwrap();
    vm.deliver_secrets(&[
        (files.path(), "/run/sentinel-secrets"),
        (env.path(), "/run/sentinel-env"),
    ])
    .unwrap();
    let seen = vm
        .exec(
            &sh(
                ". /run/sentinel-env/step-0.sh && echo \"$TOKEN $(cat /run/sentinel-secrets/deep/token)\"; \
                 grep -c '^tmpfs /run/sentinel-\\(env\\|secrets\\) tmpfs' /proc/mounts",
                60,
            ),
            &[],
        )
        .unwrap();
    assert_eq!(
        text(&seen.stdout),
        "env-secret file-secret\n2",
        "{}",
        text(&seen.stderr)
    );
    vm.retract_secrets().unwrap();
    let after = vm
        .exec(
            &sh(
                "ls -A /run/sentinel-env /run/sentinel-secrets | grep -c . ; true",
                60,
            ),
            &[],
        )
        .unwrap();
    // Only the two directory headers `ls` prints remain: nothing the step was given.
    assert_eq!(text(&after.stdout), "2", "{}", text(&after.stderr));
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

// ---------------------------------------------------------------- M04: lifecycle (cancel, lease loss, crashes)

/// Records a functional observation: on stderr, and as a JSON line in `SENTINEL_MICROVM_LIFECYCLE_OUT` when set.
/// These are single runs on a host that does other work, not benchmarks.
fn observe(name: &str, millis: u128) {
    eprintln!("m04 observation: {name} = {millis} ms");
    if let Some(out) = std::env::var_os("SENTINEL_MICROVM_LIFECYCLE_OUT") {
        use std::io::Write as _;
        let line = format!("{{\"observation\":\"{name}\",\"ms\":{millis}}}\n");
        if let Ok(mut file) = fs::OpenOptions::new().create(true).append(true).open(out) {
            let _ = file.write_all(line.as_bytes());
        }
    }
}

/// The processes whose command line mentions `needle` (the namespace holder and `pasta` name the VM's
/// directory) or whose root directory is below it (the VMM runs in a chroot that is the VM's directory), other
/// than this one.
fn processes_mentioning(needle: &str) -> Vec<u32> {
    let me = std::process::id();
    let mut found = Vec::new();
    let Ok(entries) = fs::read_dir("/proc") else {
        return found;
    };
    for entry in entries.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        else {
            continue;
        };
        if pid == me {
            continue;
        }
        let chrooted = fs::read_link(entry.path().join("root"))
            .is_ok_and(|root| root.to_string_lossy().contains(needle));
        let named = fs::read(entry.path().join("cmdline"))
            .is_ok_and(|cmdline| String::from_utf8_lossy(&cmdline).contains(needle));
        if chrooted || named {
            found.push(pid);
        }
    }
    found
}

fn scope_active(root: &std::path::Path, attempt: AttemptId) -> bool {
    let status = std::process::Command::new("systemctl")
        .args(["--user", "is-active", &microvm::scope_name(root, attempt)])
        .output()
        .unwrap();
    text(&status.stdout) == "active"
}

/// The pids of the VM's network namespace holder and `pasta`, as the launch script recorded them.
fn network_pids(root: &std::path::Path, attempt: AttemptId) -> Vec<u32> {
    let dir = root
        .join(microvm::DIR)
        .join("vms")
        .join(attempt.to_string());
    ["netns.pid", "pasta.pid"]
        .iter()
        .filter_map(|name| fs::read_to_string(dir.join(name)).ok()?.trim().parse().ok())
        .collect()
}

fn pid_alive(pid: u32) -> bool {
    std::path::Path::new(&format!("/proc/{pid}")).exists()
}

/// Everything a VM can leave behind, checked after its removal: no directory (so no scratch overlay, console
/// log, rules or socket), no scope, no process of the VM's (VMM, namespace holder, `pasta`), hence no tap and
/// no network namespace and no `vmtap` on the host.
fn assert_vm_left_nothing(root: &std::path::Path, attempt: AttemptId, pids: &[u32]) {
    assert!(!microvm::exists(root, attempt), "the VM directory remains");
    assert!(microvm::owned(root).is_empty(), "a VM directory remains");
    assert_scope_gone(root, attempt);
    let deadline = Instant::now() + Duration::from_secs(5);
    let needle = root.to_string_lossy().into_owned();
    loop {
        let alive: Vec<u32> = pids.iter().copied().filter(|p| pid_alive(*p)).collect();
        let named = processes_mentioning(&needle);
        if alive.is_empty() && named.is_empty() {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "processes of the VM remain: {alive:?} {named:?}"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    let links = std::process::Command::new("ip")
        .args(["-o", "link", "show", "vmtap"])
        .output()
        .unwrap();
    assert!(
        !links.status.success(),
        "a tap named vmtap exists on the host"
    );
}

/// A cancel to a running step, then the attempt's own teardown of the VM: the outcome and the time from the
/// cancel until the VM is gone.
fn cancel_to_gone(
    setup: &Setup,
    network: Network,
    script: &str,
    grace: Duration,
) -> (Terminated, Duration) {
    pull();
    let root = tempfile::tempdir().unwrap();
    let workspace = tempfile::tempdir().unwrap();
    // The first VM of a shape builds its snapshot; the measured one restores it, as a worker's VMs do.
    let (_, warm) = start_net(root.path(), setup, workspace.path(), network);
    warm.destroy().unwrap();
    let (attempt, vm) = start_net(root.path(), setup, workspace.path(), network);
    let vm = Arc::new(vm);
    let running = {
        let vm = Arc::clone(&vm);
        let script = script.to_owned();
        std::thread::spawn(move || vm.exec(&sh(&script, 600), &[]))
    };
    std::thread::sleep(Duration::from_millis(500));
    let pids = network_pids(root.path(), attempt);
    let started = Instant::now();
    let outcome = microvm::terminate_named(root.path(), attempt, grace).unwrap();
    let ended = running.join().unwrap();
    assert!(ended.is_ok(), "{ended:?}");
    // The attempt thread's teardown once its step has ended.
    Arc::try_unwrap(vm)
        .expect("the step's thread has ended")
        .destroy()
        .unwrap();
    let gone = started.elapsed();
    assert_vm_left_nothing(root.path(), attempt, &pids);
    (outcome, gone)
}

#[test]
fn a_polite_cancel_has_the_vm_gone_within_two_seconds() {
    let Some(setup) = setup() else { return };
    for (name, network) in [("none", Network::None), ("egress", Network::Egress)] {
        let (outcome, gone) = cancel_to_gone(
            &setup,
            network,
            "trap 'exit 3' TERM; sleep 600 & wait",
            Duration::from_secs(5),
        );
        assert_eq!(outcome, Terminated::Graceful);
        observe(
            &format!("polite_cancel_to_vm_gone_{name}"),
            gone.as_millis(),
        );
        assert!(
            gone < Duration::from_secs(2),
            "cancel to VM gone took {gone:?} ({name})"
        );
    }
}

#[test]
fn a_stubborn_step_costs_its_grace_period_and_then_under_two_seconds() {
    let Some(setup) = setup() else { return };
    let grace = Duration::from_millis(700);
    let (outcome, gone) = cancel_to_gone(
        &setup,
        Network::None,
        "trap '' TERM; while :; do sleep 1; done",
        grace,
    );
    assert_eq!(outcome, Terminated::Forced);
    observe("forced_cancel_to_vm_gone_none_grace_700", gone.as_millis());
    assert!(
        gone >= grace && gone < grace + Duration::from_secs(2),
        "forced cancel to VM gone took {gone:?}"
    );
}

#[test]
fn a_cancel_to_an_unresponsive_guest_still_has_the_vm_gone_within_two_seconds() {
    let Some(setup) = setup() else { return };
    pull();
    let root = tempfile::tempdir().unwrap();
    let workspace = tempfile::tempdir().unwrap();
    let (attempt, vm) = start_net(root.path(), &setup, workspace.path(), Network::None);
    let vm = Arc::new(vm);
    let running = {
        let vm = Arc::clone(&vm);
        std::thread::spawn(move || vm.exec(&sh("sleep 600", 600), &[]))
    };
    std::thread::sleep(Duration::from_millis(300));
    // Freeze the VMM, so the guest agent cannot answer.
    let needle = root.path().to_string_lossy().into_owned();
    let vmm: Vec<u32> = processes_mentioning(&needle)
        .into_iter()
        .filter(|pid| {
            fs::read_to_string(format!("/proc/{pid}/comm"))
                .map(|comm| comm.trim() == "firecracker")
                .unwrap_or(false)
        })
        .collect();
    assert_eq!(vmm.len(), 1, "one VMM: {vmm:?}");
    // SAFETY: stopping a process this test started.
    unsafe { libc::kill(i32::try_from(vmm[0]).unwrap(), libc::SIGSTOP) };
    let started = Instant::now();
    let outcome =
        microvm::terminate_named(root.path(), attempt, Duration::from_millis(500)).unwrap();
    assert_eq!(outcome, Terminated::Forced);
    assert!(running.join().unwrap().is_err());
    let _ = Arc::try_unwrap(vm).map(|vm| vm.destroy());
    let gone = started.elapsed();
    observe("unresponsive_guest_cancel_to_vm_gone", gone.as_millis());
    assert_vm_left_nothing(root.path(), attempt, &vmm);
    assert!(
        gone < Duration::from_secs(2),
        "a cancel to a frozen guest took {gone:?}"
    );
}

#[test]
fn losing_the_lease_has_the_vm_gone_within_two_seconds_with_or_without_a_network() {
    let Some(setup) = setup() else { return };
    pull();
    for (name, network) in [("none", Network::None), ("egress", Network::Egress)] {
        let root = tempfile::tempdir().unwrap();
        let workspace = tempfile::tempdir().unwrap();
        let (attempt, vm) = start_net(root.path(), &setup, workspace.path(), network);
        let vm = Arc::new(vm);
        let running = {
            let vm = Arc::clone(&vm);
            std::thread::spawn(move || vm.exec(&sh("sleep 600", 600), &[]))
        };
        std::thread::sleep(Duration::from_millis(500));
        let pids = network_pids(root.path(), attempt);
        let started = Instant::now();
        // What the executor's lease watchdog does.
        sentinel_worker::sandbox::remove(root.path(), attempt, &Store::Shared).unwrap();
        let gone = started.elapsed();
        assert!(
            running.join().unwrap().is_err(),
            "the step is cut off with its VM"
        );
        observe(&format!("lease_loss_to_vm_gone_{name}"), gone.as_millis());
        assert!(
            gone < Duration::from_secs(2),
            "lease loss to VM gone took {gone:?} ({name})"
        );
        assert_vm_left_nothing(root.path(), attempt, &pids);
        // The attempt thread still holds the handle: dropping it after the removal changes nothing.
        drop(vm);
        assert_vm_left_nothing(root.path(), attempt, &pids);
    }
}

#[test]
fn a_handle_dropped_without_destroy_takes_its_vm_with_it() {
    let Some(setup) = setup() else { return };
    pull();
    for network in [Network::None, Network::Egress] {
        let root = tempfile::tempdir().unwrap();
        let workspace = tempfile::tempdir().unwrap();
        let (attempt, vm) = start_net(root.path(), &setup, workspace.path(), network);
        let pids = network_pids(root.path(), attempt);
        // An attempt thread that panics drops the handle on its way out.
        let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            let _held = vm;
            panic!("the attempt failed");
        }));
        assert!(panicked.is_err());
        assert_vm_left_nothing(root.path(), attempt, &pids);
    }
}

/// The role of a re-executed copy of this test binary: a worker that starts a VM, runs a step in it and waits
/// to be killed by the parent. `SENTINEL_M04_VICTIM` is `<data root>|<egress 0 or 1>|<ready file>`.
fn run_as_victim(spec: &str) {
    let mut parts = spec.splitn(3, '|');
    let root = PathBuf::from(parts.next().unwrap());
    let network = if parts.next() == Some("1") {
        Network::Egress
    } else {
        Network::None
    };
    let ready = PathBuf::from(parts.next().unwrap());
    let setup = setup().expect("the victim runs with the parent's environment");
    let workspace = tempfile::tempdir().unwrap();
    let attempt = AttemptId::new();
    let vm = Vm::start(
        &root,
        &setup,
        WorkerId::new(),
        attempt,
        IMAGE,
        limits(),
        workspace.path(),
        &[],
        &Store::Shared,
        network,
    )
    .unwrap();
    let vm = Arc::new(vm);
    {
        let vm = Arc::clone(&vm);
        std::thread::spawn(move || {
            let _ = vm.exec(&sh("sleep 600", 600), &[]);
        });
    }
    std::thread::sleep(Duration::from_millis(300));
    fs::write(&ready, attempt.to_string()).unwrap();
    // The parent kills this process: it must never reach a destructor.
    std::thread::sleep(Duration::from_secs(600));
}

/// A re-executed copy of this test binary playing a worker, killed with SIGKILL by the test.
struct Victim {
    child: std::process::Child,
}

impl Victim {
    fn spawn(
        test: &str,
        root: &std::path::Path,
        network: Network,
        ready: &std::path::Path,
    ) -> Self {
        let spec = format!(
            "{}|{}|{}",
            root.display(),
            u8::from(network == Network::Egress),
            ready.display()
        );
        let child = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", test, "--nocapture", "--test-threads=1"])
            .env("SENTINEL_M04_VICTIM", spec)
            .stdin(std::process::Stdio::null())
            .spawn()
            .unwrap();
        Victim { child }
    }

    fn kill9(&mut self) {
        // SAFETY: SIGKILL to the child this test started.
        unsafe { libc::kill(i32::try_from(self.child.id()).unwrap(), libc::SIGKILL) };
        let status = self.child.wait().unwrap();
        assert_eq!(
            std::os::unix::process::ExitStatusExt::signal(&status),
            Some(libc::SIGKILL),
            "the victim was killed, not exited: {status:?}"
        );
    }
}

impl Drop for Victim {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Removes whatever a failed test left, so one failure does not leak VMs.
struct Sweep<'a>(&'a std::path::Path);

impl Drop for Sweep<'_> {
    fn drop(&mut self) {
        let _ = microvm::reconcile(self.0);
    }
}

#[test]
fn a_worker_killed_with_sigkill_mid_attempt_leaves_only_what_recovery_removes() {
    const NAME: &str = "a_worker_killed_with_sigkill_mid_attempt_leaves_only_what_recovery_removes";
    if let Ok(spec) = std::env::var("SENTINEL_M04_VICTIM") {
        run_as_victim(&spec);
        return;
    }
    let Some(_setup) = setup() else { return };
    pull();
    for (name, network) in [("none", Network::None), ("egress", Network::Egress)] {
        let root = tempfile::tempdir().unwrap();
        let _sweep = Sweep(root.path());
        let ready = root.path().join("ready");
        let mut victim = Victim::spawn(NAME, root.path(), network, &ready);
        let deadline = Instant::now() + Duration::from_secs(300);
        while !ready.exists() {
            assert!(Instant::now() < deadline, "the victim never became ready");
            assert!(
                victim.child.try_wait().unwrap().is_none(),
                "the victim ended early"
            );
            std::thread::sleep(Duration::from_millis(100));
        }
        let attempt: AttemptId = fs::read_to_string(&ready).unwrap().parse().unwrap();
        let pids = network_pids(root.path(), attempt);
        if network == Network::Egress {
            assert_eq!(pids.len(), 2, "a namespace holder and pasta: {pids:?}");
        }
        victim.kill9();
        // The VM outlives its worker (it runs in a scope of its own): this is what recovery exists for.
        assert!(scope_active(root.path(), attempt));
        assert!(microvm::exists(root.path(), attempt));
        let started = Instant::now();
        let (recovered, _) =
            sentinel_worker::recovery::recover(root.path(), WorkerId::new()).unwrap();
        let took = started.elapsed();
        assert_eq!(recovered.containers_removed, 1, "{recovered:?}");
        observe(&format!("recovery_after_kill9_{name}"), took.as_millis());
        assert!(took < Duration::from_secs(5), "recovery took {took:?}");
        assert_vm_left_nothing(root.path(), attempt, &pids);
        // A second pass finds nothing.
        let (again, _) = sentinel_worker::recovery::recover(root.path(), WorkerId::new()).unwrap();
        assert_eq!(again.containers_removed, 0, "{again:?}");
    }
}

#[test]
fn a_worker_killed_at_any_point_of_a_vm_start_leaves_nothing_after_recovery() {
    const NAME: &str = "a_worker_killed_at_any_point_of_a_vm_start_leaves_nothing_after_recovery";
    if let Ok(spec) = std::env::var("SENTINEL_M04_VICTIM") {
        run_as_victim(&spec);
        return;
    }
    let Some(setup) = setup() else { return };
    pull();
    let root = tempfile::tempdir().unwrap();
    let _sweep = Sweep(root.path());
    let workspace = tempfile::tempdir().unwrap();
    // The guest image and a snapshot of each network shape exist, so the victim's start is a restore of
    // under a second and the kills land in different phases of it.
    for network in [Network::None, Network::Egress] {
        let (_, warm) = start_net(root.path(), &setup, workspace.path(), network);
        warm.destroy().unwrap();
    }
    let mut round = 0u64;
    for network in [Network::None, Network::Egress] {
        for delay_ms in [0u64, 20, 60, 120, 250, 500] {
            round += 1;
            let ready = root.path().join(format!("ready-{round}"));
            let mut victim = Victim::spawn(NAME, root.path(), network, &ready);
            let deadline = Instant::now() + Duration::from_secs(120);
            while microvm::owned(root.path()).is_empty() && !ready.exists() {
                assert!(Instant::now() < deadline, "the victim never started a VM");
                std::thread::sleep(Duration::from_millis(2));
            }
            std::thread::sleep(Duration::from_millis(delay_ms));
            victim.kill9();
            let started = Instant::now();
            let (recovered, _) =
                sentinel_worker::recovery::recover(root.path(), WorkerId::new()).unwrap();
            let took = started.elapsed();
            eprintln!(
                "round {round}: killed {delay_ms} ms after the VM directory appeared (network {network:?}, step {}), recovery removed {} in {took:?}",
                if ready.exists() {
                    "running"
                } else {
                    "not yet running"
                },
                recovered.containers_removed
            );
            assert!(took < Duration::from_secs(10), "recovery took {took:?}");
            let deadline = Instant::now() + Duration::from_secs(5);
            let needle = root.path().to_string_lossy().into_owned();
            while !processes_mentioning(&needle).is_empty() {
                assert!(
                    Instant::now() < deadline,
                    "round {round}: processes of the killed worker's VM remain: {:?}",
                    processes_mentioning(&needle)
                );
                std::thread::sleep(Duration::from_millis(50));
            }
            nothing_left(root.path(), &[]);
            assert_eq!(
                microvm::reconcile(root.path()).unwrap(),
                0,
                "round {round}: a second pass found something"
            );
        }
    }
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

// ---------------------------------------------------------------- M06: isolation between restored attempts

/// A random marker no file of the guest or the host has any reason to hold.
fn marker() -> String {
    let mut bytes = [0u8; 16];
    std::io::Read::read_exact(&mut fs::File::open("/dev/urandom").unwrap(), &mut bytes).unwrap();
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    format!("sentinel-m06-secret-{hex}")
}

/// The guest-side pattern for any marker [`marker`] makes. The pattern is not a marker itself, so a step that
/// carries it does not match its own search.
const MARKER_PATTERN: &str = "sentinel-m06-secret-[0-9a-f]{32}";

/// Whether `needle` occurs anywhere in the file, read in blocks that overlap by the needle's length.
fn file_holds(path: &std::path::Path, needle: &[u8]) -> bool {
    use std::io::Read as _;
    let mut file = fs::File::open(path).unwrap();
    let mut block = vec![0u8; 8 << 20];
    let mut kept = 0;
    loop {
        let read = file.read(&mut block[kept..]).unwrap();
        if read == 0 {
            return false;
        }
        let end = kept + read;
        if block[..end].windows(needle.len()).any(|w| w == needle) {
            return true;
        }
        kept = (needle.len() - 1).min(end);
        block.copy_within(end - kept..end, 0);
    }
}

fn digest_of(path: &std::path::Path) -> String {
    use std::io::Read as _;
    let mut file = fs::File::open(path).unwrap();
    let mut hasher = blake3::Hasher::new();
    let mut block = vec![0u8; 8 << 20];
    loop {
        let read = file.read(&mut block).unwrap();
        if read == 0 {
            return hasher.finalize().to_hex().to_string();
        }
        hasher.update(&block[..read]);
    }
}

/// The files that make a snapshot and what is in them.
fn snapshot_digests(snapshot: &std::path::Path) -> Vec<(&'static str, String)> {
    ["state", "mem", "scratch.ext4"]
        .into_iter()
        .map(|file| (file, digest_of(&snapshot.join(file))))
        .collect()
}

#[test]
fn two_restored_attempts_share_no_writable_state_and_no_secrets() {
    use std::os::unix::fs::MetadataExt as _;
    let Some(setup) = setup() else { return };
    pull();
    let root = tempfile::tempdir().unwrap();
    let (wa, wb) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (a_id, a) = start_net(root.path(), &setup, wa.path(), Network::None);
    assert_eq!(a.start_report().mode, microvm::Start::Restored);
    let snapshot = snapshots(root.path()).remove(0);
    let pristine = snapshot_digests(&snapshot);
    let (b_id, b) = start_net(root.path(), &setup, wb.path(), Network::None);
    assert_eq!(b.start_report().mode, microvm::Start::Restored);
    assert!(!b.start_report().snapshot_built && b.start_report().fallback.is_none());

    // Each attempt's scratch disk is a file of its own, not the snapshot's.
    let vms = root.path().join(microvm::DIR).join("vms");
    let scratch = |id: AttemptId| vms.join(id.to_string()).join("scratch.ext4");
    let inodes = [
        fs::metadata(snapshot.join("scratch.ext4")).unwrap().ino(),
        fs::metadata(scratch(a_id)).unwrap().ino(),
        fs::metadata(scratch(b_id)).unwrap().ino(),
    ];
    assert!(
        inodes[0] != inodes[1] && inodes[0] != inodes[2] && inodes[1] != inodes[2],
        "a scratch disk is shared: {inodes:?}"
    );

    // A is given a secret (a file and an environment file, both in guest memory), uses it, and keeps it while B runs.
    let secret = marker();
    let (files, env) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    fs::write(files.path().join("token"), &secret).unwrap();
    fs::write(
        env.path().join("step-0.sh"),
        format!("export TOKEN='{secret}'\n"),
    )
    .unwrap();
    a.deliver_secrets(&[
        (files.path(), "/run/sentinel-secrets"),
        (env.path(), "/run/sentinel-env"),
    ])
    .unwrap();
    let used = a
        .exec(
            &sh(
                ". /run/sentinel-env/step-0.sh; test \"$TOKEN\" = \"$(cat /run/sentinel-secrets/token)\"; \
                 echo \"$TOKEN\" > /tmp/a-copy; echo \"$TOKEN\" > /dev/shm/a-copy; \
                 echo mine-a > /tmp/same; echo mine-a > /dev/shm/same",
                60,
            ),
            &[],
        )
        .unwrap();
    assert_eq!(used.code, Some(0), "{}", text(&used.stderr));

    // B writes the same names with other content, and looks for A's secret and files everywhere it can.
    let mine = b
        .exec(
            &sh("echo mine-b > /tmp/same; echo mine-b > /dev/shm/same", 60),
            &[],
        )
        .unwrap();
    assert_eq!(mine.code, Some(0), "{}", text(&mine.stderr));
    let looked = b
        .exec(
            &sh(
                &format!(
                    "for f in /tmp/a-copy /dev/shm/a-copy; do [ ! -e $f ] || echo \"LEAK $f\"; done; \
                     [ \"$(cat /tmp/same)\" = mine-b ] || echo LEAK tmp-same; \
                     [ \"$(cat /dev/shm/same)\" = mine-b ] || echo LEAK shm-same; \
                     env | grep -c '{MARKER_PATTERN}' || true; \
                     grep -rEsl '{MARKER_PATTERN}' /etc /tmp /run /var /root /dev/shm /job /workspace || true; \
                     echo looked"
                ),
                120,
            ),
            &[],
        )
        .unwrap();
    assert_eq!(
        text(&looked.stdout),
        "0\nlooked",
        "B saw A's state or secret: {}{}",
        text(&looked.stdout),
        text(&looked.stderr)
    );
    // A's own state is intact, B's writes did not reach it.
    let own = a
        .exec(&sh("cat /tmp/same /dev/shm/same /tmp/a-copy", 60), &[])
        .unwrap();
    assert_eq!(text(&own.stdout), format!("mine-a\nmine-a\n{secret}"));

    // While A still holds the secret in its memory, the snapshot's files are what they were: the guest memory
    // is a private mapping, so no page A dirtied went back to the file, and the disk A writes is a clone.
    assert_eq!(snapshot_digests(&snapshot), pristine);
    for file in ["state", "mem", "scratch.ext4"] {
        assert!(
            !file_holds(&snapshot.join(file), secret.as_bytes()),
            "A's secret is in the snapshot's {file}"
        );
    }
    a.retract_secrets().unwrap();
    a.destroy().unwrap();
    b.destroy().unwrap();

    // A later restore of the same snapshot starts from the pristine state: nothing of A or B.
    let (c_id, c) = start_net(root.path(), &setup, wa.path(), Network::None);
    assert_eq!(c.start_report().mode, microvm::Start::Restored);
    let fresh = c
        .exec(
            &sh(
                &format!(
                    "for f in /tmp/same /dev/shm/same /tmp/a-copy; do [ ! -e $f ] || echo \"LEAK $f\"; done; \
                     grep -rEsl '{MARKER_PATTERN}' /etc /tmp /run /var /root /dev/shm /job /workspace || true; \
                     echo clean"
                ),
                120,
            ),
            &[],
        )
        .unwrap();
    assert_eq!(text(&fresh.stdout), "clean", "{}", text(&fresh.stderr));
    c.destroy().unwrap();
    assert_eq!(snapshot_digests(&snapshot), pristine);
    nothing_left(root.path(), &[a_id, b_id, c_id]);
}

#[test]
fn a_snapshot_restores_after_the_data_directory_moved() {
    let Some(setup) = setup() else { return };
    pull();
    let parent = tempfile::tempdir().unwrap();
    let (before, after) = (parent.path().join("before"), parent.path().join("after"));
    fs::create_dir(&before).unwrap();
    let workspace = tempfile::tempdir().unwrap();
    let (a_id, a) = start_net(&before, &setup, workspace.path(), Network::None);
    assert!(a.start_report().snapshot_built);
    a.destroy().unwrap();
    assert_eq!(snapshots(&before).len(), 1);

    // The whole data directory (guest image, initramfs and snapshot) now lives at another path.
    fs::rename(&before, &after).unwrap();
    let (b_id, b) = start_net(&after, &setup, workspace.path(), Network::None);
    let report = b.start_report().clone();
    assert_eq!(report.mode, microvm::Start::Restored, "{report:?}");
    assert!(
        !report.snapshot_built && report.fallback.is_none(),
        "the moved snapshot was not used as it was: {report:?}"
    );
    assert_eq!(snapshots(&after).len(), 1);
    let ran = b
        .exec(&sh("echo restored-after-the-move", 60), &[])
        .unwrap();
    assert_eq!(text(&ran.stdout), "restored-after-the-move");
    b.destroy().unwrap();
    nothing_left(&after, &[a_id, b_id]);
}

#[test]
fn a_changed_agent_or_kernel_makes_a_new_snapshot_and_never_a_stale_hit() {
    let Some(setup) = setup() else { return };
    pull();
    let root = tempfile::tempdir().unwrap();
    let scratch = tempfile::tempdir().unwrap();
    let workspace = tempfile::tempdir().unwrap();
    let (a_id, a) = start_net(root.path(), &setup, workspace.path(), Network::None);
    assert!(a.start_report().snapshot_built);
    a.destroy().unwrap();
    assert_eq!(snapshots(root.path()).len(), 1);

    // An agent with other bytes is another initramfs and so another snapshot.
    let mut changed = setup.clone();
    changed.agent = scratch.path().join("agent");
    let mut bytes = fs::read(&setup.agent).unwrap();
    bytes.push(0);
    fs::write(&changed.agent, bytes).unwrap();
    fs::set_permissions(
        &changed.agent,
        std::os::unix::fs::PermissionsExt::from_mode(0o755),
    )
    .unwrap();
    let (b_id, b) = start_net(root.path(), &changed, workspace.path(), Network::None);
    assert!(
        b.start_report().snapshot_built,
        "a changed agent restored the old snapshot: {:?}",
        b.start_report()
    );
    b.destroy().unwrap();
    assert_eq!(snapshots(root.path()).len(), 2);

    // A kernel file that is not the one the snapshot was taken with is a miss as well.
    let mut other = setup.clone();
    other.kernel = scratch.path().join("vmlinux");
    fs::copy(&setup.kernel, &other.kernel).unwrap();
    let (c_id, c) = start_net(root.path(), &other, workspace.path(), Network::None);
    assert!(
        c.start_report().snapshot_built,
        "a different kernel file restored the old snapshot: {:?}",
        c.start_report()
    );
    c.destroy().unwrap();
    assert_eq!(snapshots(root.path()).len(), 3);

    // And the original setup still finds its own.
    let (d_id, d) = start_net(root.path(), &setup, workspace.path(), Network::None);
    assert!(!d.start_report().snapshot_built && d.start_report().fallback.is_none());
    d.destroy().unwrap();
    nothing_left(root.path(), &[a_id, b_id, c_id, d_id]);
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

// ---------------------------------------------------------------- M05: the boundary, probed from inside

/// The pids of a VM's network namespace holder, as the launch script recorded them (see [`network_pids`]).
fn netns_id(root: &std::path::Path, attempt: AttemptId) -> String {
    let pid = network_pids(root, attempt)[0];
    fs::read_link(format!("/proc/{pid}/ns/net"))
        .unwrap()
        .to_string_lossy()
        .into_owned()
}

#[test]
fn two_granted_guests_share_no_network_and_cannot_reach_each_other() {
    let Some(setup) = setup() else { return };
    pull();
    let root = tempfile::tempdir().unwrap();
    let (wa, wb) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (a_id, a) = start_net(root.path(), &setup, wa.path(), Network::Egress);
    let (b_id, b) = start_net(root.path(), &setup, wb.path(), Network::Egress);
    // Two VMs, two network namespaces: the same guest address in each is a different host to the other.
    assert_ne!(
        netns_id(root.path(), a_id),
        netns_id(root.path(), b_id),
        "two VMs share a network namespace"
    );
    for vm in [&a, &b] {
        let addr = vm.exec(&sh("ip -4 -o addr show eth0", 30), &[]).unwrap();
        assert!(
            text(&addr.stdout).contains("10.211.0.2/30"),
            "{}",
            text(&addr.stdout)
        );
    }

    // B listens on all its addresses (in the background: a guest runs one step at a time); A tries every address
    // either of them has; then B proves with a connection of its own that the listener was up the whole time.
    let up = b
        .exec(
            &sh(
                "nohup timeout 60 nc -l -p 9000 > /tmp/heard 2>/dev/null < /dev/null & sleep 1; echo up",
                30,
            ),
            &[],
        )
        .unwrap();
    assert_eq!(text(&up.stdout), "up", "{}", text(&up.stderr));
    for target in ["10.211.0.2", "10.211.0.1"] {
        let sent = a
            .exec(
                &sh(
                    &format!("echo from-a | nc -w 2 {target} 9000 && echo SENT || echo REFUSED"),
                    30,
                ),
                &[],
            )
            .unwrap();
        assert!(
            text(&sent.stdout).ends_with("REFUSED"),
            "A reached {target}:9000: {}",
            text(&sent.stdout)
        );
    }
    let before = b.exec(&sh("cat /tmp/heard", 30), &[]).unwrap();
    assert_eq!(text(&before.stdout), "", "B's listener heard A");
    let control = b
        .exec(
            &sh(
                "echo control | nc -w 2 127.0.0.1 9000; sleep 1; cat /tmp/heard",
                30,
            ),
            &[],
        )
        .unwrap();
    assert_eq!(
        text(&control.stdout),
        "control",
        "the listener was not up: {}",
        text(&control.stderr)
    );
    a.destroy().unwrap();
    b.destroy().unwrap();
    nothing_left(root.path(), &[a_id, b_id]);
}

#[test]
fn a_granted_guest_reaches_no_controller_or_control_service_on_the_worker_host() {
    let Some(mut setup) = setup() else { return };
    pull();
    // A controller on the worker's own host, listening on every address: the API, the link port and the
    // worker's admin socket's TCP stand-ins. The link endpoint is the one the worker would be configured with.
    let control = std::net::TcpListener::bind("0.0.0.0:0").unwrap();
    control.set_nonblocking(true).unwrap();
    let port = control.local_addr().unwrap().port();
    let hosts: Vec<std::net::Ipv4Addr> = microvm::net::host_addresses().unwrap();
    let link = hosts
        .iter()
        .find(|a| !a.is_loopback())
        .copied()
        .unwrap_or(std::net::Ipv4Addr::LOCALHOST);
    setup.guard.link = vec![std::net::SocketAddr::from((link, port))];
    let control6 = std::net::TcpListener::bind("[::1]:0").ok();
    if let Some(listener) = &control6 {
        listener.set_nonblocking(true).unwrap();
    }

    let root = tempfile::tempdir().unwrap();
    let workspace = tempfile::tempdir().unwrap();
    let (id, vm) = start_net(root.path(), &setup, workspace.path(), Network::Egress);
    for host in &hosts {
        assert!(
            !connects(&vm, &host.to_string(), port),
            "the guest reached the control service at {host}:{port}"
        );
    }
    // The guest has no IPv6 address or route at all.
    let v6 = vm
        .exec(
            &sh(
                "ip -6 -o addr | grep -c global || true; ip -6 route | grep -c default || true",
                30,
            ),
            &[],
        )
        .unwrap();
    let lines: Vec<String> = text(&v6.stdout).lines().map(str::to_owned).collect();
    assert_eq!(
        lines[..2],
        ["0", "0"],
        "the guest has IPv6 routing: {lines:?}"
    );
    if let Some(listener) = &control6 {
        let port6 = listener.local_addr().unwrap().port();
        assert!(
            !connects(&vm, "::1", port6),
            "the guest reached a service on the host's IPv6 loopback"
        );
        assert!(listener.accept().is_err());
    }
    // The namespace's own side of the link answers nothing on any port a worker or controller commonly uses.
    for probe in [22u16, 80, 443, 7443, 8080, port] {
        assert!(
            !connects(&vm, "10.211.0.1", probe),
            "the guest reached its gateway's port {probe}"
        );
    }
    assert!(
        control.accept().is_err(),
        "something connected to the control service the guest must not reach"
    );
    vm.destroy().unwrap();
    nothing_left(root.path(), &[id]);
}

/// What a job step can observe of its network, one `key=verdict` per probe, the same script in a container and in a guest.
fn network_view(
    run: &dyn Fn(&str) -> String,
    loopback_port: u16,
    egress: &(String, u16),
) -> Vec<String> {
    let script = format!(
        "nics=$(ls /sys/class/net | grep -vx lo | wc -l); echo nics=$nics; \
         if ip route | grep -q '^default'; then echo route=yes; else echo route=no; fi; \
         gw=$(ip route | awk '/^default/ {{print $3}}'); \
         try() {{ if nc -w 2 \"$1\" \"$2\" </dev/null >/dev/null 2>&1; then echo \"$3=reached\"; else echo \"$3=refused\"; fi; }}; \
         try 127.0.0.1 {loopback_port} loopback; \
         if [ -n \"$gw\" ]; then try \"$gw\" {loopback_port} gateway; else echo gateway=none; fi; \
         try 169.254.169.254 80 metadata; \
         try {} {} egress",
        egress.0, egress.1
    );
    run(&script).lines().map(str::to_owned).collect()
}

#[test]
fn the_container_and_the_microvm_job_networks_agree() {
    let Some(setup) = setup() else { return };
    pull();
    let (loopback, loopback_addr) = listener("127.0.0.1");
    let port = loopback_addr.port();
    let egress = egress_target();
    let temp = tempfile::tempdir().unwrap();
    let mut views = Vec::new();
    for network in [Network::None, Network::Egress] {
        // The container.
        let attempt = AttemptId::new();
        let ws = sentinel_worker::workspace::Workspace::create(temp.path(), attempt).unwrap();
        let container = podman::Container::start(
            WorkerId::new(),
            attempt,
            IMAGE,
            Limits {
                cpu_millis: 500,
                memory_bytes: 128 << 20,
                pids: 64,
                disk_bytes: 0,
                lifetime_secs: 0,
            },
            ws.path(),
            &[],
            &Store::Shared,
            network,
        )
        .unwrap();
        let in_container = network_view(
            &|script| {
                let exit = container.exec(&sh(script, 60), &[]).unwrap();
                assert_eq!(exit.code, Some(0), "{}", text(&exit.stderr));
                text(&exit.stdout)
            },
            port,
            &egress,
        );
        container.destroy().unwrap();

        // The guest, with the host's addresses guarded as a worker would.
        let root = tempfile::tempdir().unwrap();
        let workspace = tempfile::tempdir().unwrap();
        let (id, vm) = start_net(root.path(), &setup, workspace.path(), network);
        let in_guest = network_view(
            &|script| {
                let exit = vm.exec(&sh(script, 60), &[]).unwrap();
                assert_eq!(exit.code, Some(0), "{}", text(&exit.stderr));
                text(&exit.stdout)
            },
            port,
            &egress,
        );
        vm.destroy().unwrap();
        nothing_left(root.path(), &[id]);
        eprintln!("{network:?}: container {in_container:?}, guest {in_guest:?}");
        assert_eq!(
            in_container, in_guest,
            "the container and the guest see different job networks under {network:?}"
        );
        views.push(in_guest);
    }
    // And the views are what the policy says: nothing without a grant, a route out but no host, link or metadata with one.
    assert_eq!(
        views[0],
        [
            "nics=0",
            "route=no",
            "loopback=refused",
            "gateway=none",
            "metadata=refused",
            "egress=refused"
        ]
    );
    assert_eq!(views[1][0], "nics=1");
    assert_eq!(
        views[1][1..],
        [
            "route=yes",
            "loopback=refused",
            "gateway=refused",
            "metadata=refused",
            "egress=reached"
        ]
    );
    assert!(loopback.accept().is_err());
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
        // Appended, never truncated: a second run must not erase the record of the first.
        Some(path) => {
            use std::io::Write;
            fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .unwrap()
                .write_all(out.as_bytes())
                .unwrap();
        }
        None => eprintln!("{out}"),
    }
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
