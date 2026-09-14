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

fn enabled() -> bool {
    if std::env::var_os("SENTINEL_PODMAN_TESTS").is_some() {
        return true;
    }
    eprintln!("skipped: set SENTINEL_PODMAN_TESTS=1 as a rootless Podman account to run");
    false
}

fn sh(script: &str, timeout_secs: u64) -> StepCommand {
    StepCommand {
        argv: vec!["/bin/sh".into(), "-e".into(), "-c".into(), script.into()],
        env: Vec::new(),
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
    podman::pull(IMAGE, Duration::from_secs(600)).unwrap();
    assert!(podman::pull("docker.io/library/busybox:latest", Duration::from_secs(1)).is_err());

    let temp = tempfile::tempdir().unwrap();
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
