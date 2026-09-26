//! W03 isolation with real rootless Podman. Runs only with
//! `SENTINEL_PODMAN_TESTS=1` as an account with rootless Podman (see
//! docs/development.md); otherwise it reports that it was skipped, never a
//! false pass.

#![cfg(target_os = "linux")]

use std::{fs, time::Duration};

use sentinel_core::{AttemptId, WorkerId};
use sentinel_pipeline::run::StepCommand;
use sentinel_worker::{
    podman::{self, Container, Limits},
    workspace::Workspace,
};

pub const IMAGE: &str = "docker.io/library/busybox@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662";

fn authfile(root: &std::path::Path) -> std::path::PathBuf {
    sentinel_worker::images::prepare_anonymous_authfile(root).unwrap()
}

fn enabled() -> bool {
    if std::env::var_os("SENTINEL_PODMAN_TESTS").is_some() {
        return true;
    }
    eprintln!("skipped: set SENTINEL_PODMAN_TESTS=1 as a rootless Podman account to run");
    false
}

/// A resident digest still contacts its registry under the scoped auth file;
/// `true` reports that it was present before this authorization check.
#[test]
fn a_present_image_still_checks_registry_authorization() {
    if !enabled() {
        return;
    }
    let temp = tempfile::tempdir().unwrap();
    let authfile = authfile(temp.path());
    podman::pull(
        IMAGE,
        &authfile,
        Duration::from_secs(600),
        &std::sync::atomic::AtomicBool::new(false),
    )
    .unwrap();
    // The image was resident, but this pull still authorizes with the file.
    assert!(
        podman::pull(
            IMAGE,
            &authfile,
            Duration::from_secs(600),
            &std::sync::atomic::AtomicBool::new(false)
        )
        .unwrap()
    );
}

fn sh(script: &str, timeout_secs: u64) -> StepCommand {
    StepCommand {
        argv: vec!["/bin/sh".into(), "-e".into(), "-c".into(), script.into()],
        env: Vec::new(),
        secrets: Vec::new(),
        secret_files: Vec::new(),
        workdir: None,
        timeout_secs,
    }
}

#[test]
fn a_container_is_limited_unprivileged_offline_read_only_and_owned() {
    if !enabled() {
        return;
    }
    let runtime = podman::probe().unwrap();
    assert_eq!(runtime.cgroup_version, "v2");
    let temp = tempfile::tempdir().unwrap();
    let authfile = authfile(temp.path());
    podman::pull(
        IMAGE,
        &authfile,
        Duration::from_secs(600),
        &std::sync::atomic::AtomicBool::new(false),
    )
    .unwrap();
    assert!(
        podman::pull(
            "docker.io/library/busybox:latest",
            &authfile,
            Duration::from_secs(1),
            &std::sync::atomic::AtomicBool::new(false)
        )
        .is_err()
    );

    let (worker, attempt) = (WorkerId::new(), AttemptId::new());
    let ws = Workspace::create(temp.path(), attempt).unwrap();
    let container = Container::start(
        worker,
        attempt,
        IMAGE,
        Limits {
            cpu_millis: 500,
            memory_bytes: 64 << 20,
            pids: 32,
        },
        ws.path(),
        &[],
    )
    .unwrap();
    assert_eq!(container.name(), format!("sentinel-{attempt}"));
    assert_eq!(
        podman::owned(worker).unwrap(),
        vec![(attempt, container.name().to_owned())]
    );

    // Limits as seen from inside the cgroup, capabilities all dropped, no
    // network but loopback, root filesystem read-only, /tmp and the
    // workspace writable, and the workspace file visible on the host.
    let exit = container
        .exec(
            &sh(
                "cat /sys/fs/cgroup/cpu.max; cat /sys/fs/cgroup/memory.max; cat /sys/fs/cgroup/pids.max; \
                 grep CapEff /proc/self/status; ls /sys/class/net; \
                 (touch /etc/x && echo ROOT_WRITABLE) || echo ROOT_RO; \
                 touch /tmp/x && echo TMP_OK; echo hello > /workspace/out.txt && echo WS_OK; \
                 echo $SENTINEL_ATTEMPT; pwd",
                30,
            ),
            &[("SENTINEL_ATTEMPT".into(), attempt.to_string())],
        )
        .unwrap();
    let text = String::from_utf8_lossy(&exit.stdout).to_string();
    assert_eq!(
        exit.code,
        Some(0),
        "{text} {}",
        String::from_utf8_lossy(&exit.stderr)
    );
    let mut lines = text.lines();
    assert_eq!(lines.next().unwrap(), "50000 100000", "cpu.max");
    assert_eq!(
        lines.next().unwrap(),
        (64u64 << 20).to_string(),
        "memory.max"
    );
    assert_eq!(lines.next().unwrap(), "32", "pids.max");
    assert_eq!(lines.next().unwrap().trim(), "CapEff:\t0000000000000000");
    assert_eq!(lines.next().unwrap(), "lo");
    assert_eq!(lines.next().unwrap(), "ROOT_RO");
    assert_eq!(lines.next().unwrap(), "TMP_OK");
    assert_eq!(lines.next().unwrap(), "WS_OK");
    assert_eq!(lines.next().unwrap(), attempt.to_string());
    assert_eq!(lines.next().unwrap(), "/workspace");
    assert_eq!(
        fs::read_to_string(ws.path().join("out.txt")).unwrap(),
        "hello\n"
    );

    // Exit statuses and signals are reported as such; a workdir applies.
    fs::create_dir(ws.path().join("sub")).unwrap();
    let mut cmd = sh("pwd; exit 3", 30);
    cmd.workdir = Some("sub".into());
    let exit = container.exec(&cmd, &[]).unwrap();
    assert_eq!(exit.code, Some(3));
    assert_eq!(
        String::from_utf8_lossy(&exit.stdout).trim(),
        "/workspace/sub"
    );
    let exit = container.exec(&sh("kill -9 $$", 30), &[]).unwrap();
    assert_eq!((exit.code, exit.signal), (None, Some(9)));
    // `sh -e`: the first failing command ends the script with its status.
    let exit = container
        .exec(&sh("echo before; false; echo after", 30), &[])
        .unwrap();
    assert_eq!(exit.code, Some(1));
    assert_eq!(String::from_utf8_lossy(&exit.stdout).trim(), "before");
    // A missing command inside the shell is the command's failure (127 with
    // the shell's message), not the runtime's (`Error:` from Podman).
    let exit = container
        .exec(&sh("no-such-command-here", 30), &[])
        .unwrap();
    assert_eq!(exit.code, Some(127));
    assert!(
        !exit.stderr_excerpt().starts_with("Error:"),
        "{}",
        exit.stderr_excerpt()
    );
    let mut missing_workdir = sh("true", 30);
    missing_workdir.workdir = Some("does-not-exist".into());
    let exit = container.exec(&missing_workdir, &[]).unwrap();
    assert!(matches!(exit.code, Some(125..=127)), "{exit:?}");
    assert!(
        exit.stderr_excerpt().starts_with("Error:"),
        "{}",
        exit.stderr_excerpt()
    );
    // The cgroup's OOM counter is readable and starts at zero.
    assert_eq!(container.oom_kills().unwrap(), 0);
    // The pipeline's environment cannot override the worker's context.
    let mut cmd = sh("echo $SENTINEL_ATTEMPT", 30);
    cmd.env = vec![("SENTINEL_ATTEMPT".into(), "spoofed".into())];
    let exit = container
        .exec(&cmd, &[("SENTINEL_ATTEMPT".into(), "real".into())])
        .unwrap();
    assert_eq!(String::from_utf8_lossy(&exit.stdout).trim(), "real");

    // A step past its timeout stops the container; nothing runs after it.
    let exit = container.exec(&sh("sleep 30", 1), &[]).unwrap();
    assert!(exit.timed_out);
    let after = container.exec(&sh("true", 5), &[]).unwrap();
    assert_ne!(after.code, Some(0));

    container.destroy().unwrap();
    assert!(podman::owned(worker).unwrap().is_empty());
    ws.destroy().unwrap();
}

/// The container's cgroup on the host, as Podman reports it.
fn host_cgroup(name: &str) -> std::path::PathBuf {
    let output = std::process::Command::new("podman")
        .args(["inspect", "--format", "{{.State.CgroupPath}}", "--", name])
        .output()
        .unwrap();
    assert!(output.status.success());
    let path = String::from_utf8(output.stdout).unwrap();
    std::path::Path::new("/sys/fs/cgroup").join(path.trim().trim_start_matches('/'))
}

/// Removes the container when a failed assertion unwinds past it, which
/// also ends a step still running in it — a scoped thread blocked in that
/// step would otherwise hold the failure until the step's timeout.
struct RemoveOnFailure(String);

impl Drop for RemoveOnFailure {
    fn drop(&mut self) {
        if std::thread::panicking() {
            let _ = podman::remove_named(&self.0);
        }
    }
}

fn procs(cgroup: &std::path::Path) -> Vec<i32> {
    fs::read_to_string(cgroup.join("cgroup.procs"))
        .unwrap()
        .lines()
        .map(|l| l.trim().parse().unwrap())
        .collect()
}

/// P04-15. A runtime may run an exec'd step in a cgroup nested under the
/// container's own, which then holds only the keepalive. A cancel decides
/// from the cgroup tree whether a step is running: reading the container's
/// cgroup alone, it found nothing, answered `Gone`, and the step ran on.
/// Here the step is moved two levels down a real nested cgroup (cgroup v2,
/// delegated to the rootless account); termination must find it there,
/// signal it and see it leave — and once the nested cgroups are empty,
/// report that nothing is running.
#[test]
fn a_step_in_a_nested_cgroup_is_found_and_terminated() {
    if !enabled() {
        return;
    }
    let temp = tempfile::tempdir().unwrap();
    let authfile = authfile(temp.path());
    podman::pull(
        IMAGE,
        &authfile,
        Duration::from_secs(600),
        &std::sync::atomic::AtomicBool::new(false),
    )
    .unwrap();
    let (worker, attempt) = (WorkerId::new(), AttemptId::new());
    let ws = Workspace::create(temp.path(), attempt).unwrap();
    let container = Container::start(
        worker,
        attempt,
        IMAGE,
        Limits {
            cpu_millis: 500,
            memory_bytes: 64 << 20,
            pids: 32,
        },
        ws.path(),
        &[],
    )
    .unwrap();
    let _outer = RemoveOnFailure(container.name().to_owned());
    let cgroup = host_cgroup(container.name());
    let init = procs(&cgroup);
    assert_eq!(init.len(), 1, "only the keepalive before the step");

    let exit = std::thread::scope(|scope| {
        let _inner = RemoveOnFailure(container.name().to_owned());
        let step = scope.spawn(|| {
            let sleep = StepCommand {
                argv: vec!["sleep".into(), "300".into()],
                env: Vec::new(),
                secrets: Vec::new(),
                secret_files: Vec::new(),
                workdir: None,
                timeout_secs: 120,
            };
            container.exec(&sleep, &[]).unwrap()
        });
        // The step's host pid, once the runtime has exec'd `sleep` in it.
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        let pid = loop {
            let found = procs(&cgroup).into_iter().find(|pid| {
                !init.contains(pid)
                    && fs::read_to_string(format!("/proc/{pid}/comm"))
                        .is_ok_and(|comm| comm.trim() == "sleep")
            });
            if let Some(pid) = found {
                break pid;
            }
            assert!(std::time::Instant::now() < deadline, "the step never ran");
            std::thread::sleep(Duration::from_millis(25));
        };
        let nested = cgroup.join("step").join("inner");
        fs::create_dir_all(&nested).unwrap();
        fs::write(nested.join("cgroup.procs"), pid.to_string()).unwrap();
        assert_eq!(
            procs(&cgroup),
            init,
            "the container's cgroup holds only init"
        );
        assert_eq!(procs(&nested), vec![pid]);

        assert_eq!(
            podman::terminate_named(container.name(), Duration::from_secs(10)).unwrap(),
            podman::Terminated::Graceful
        );
        step.join().unwrap()
    });
    assert_eq!((exit.code, exit.signal), (None, Some(15)), "{exit:?}");
    // The nested cgroups are still there, empty: nothing runs any more.
    assert!(cgroup.join("step").join("inner").exists());
    assert_eq!(
        podman::terminate_named(container.name(), Duration::from_secs(1)).unwrap(),
        podman::Terminated::Gone
    );

    container.destroy().unwrap();
    assert!(podman::owned(worker).unwrap().is_empty());
    ws.destroy().unwrap();
}
