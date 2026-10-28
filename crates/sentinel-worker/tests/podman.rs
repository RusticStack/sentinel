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
        &podman::Store::Shared,
        Duration::from_secs(600),
        &std::sync::atomic::AtomicBool::new(false),
    )
    .unwrap();
    assert!(
        podman::pull(
            IMAGE,
            &authfile,
            &podman::Store::Shared,
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
        &podman::Store::Shared,
        Duration::from_secs(600),
        &std::sync::atomic::AtomicBool::new(false),
    )
    .unwrap();
    assert!(
        podman::pull(
            "docker.io/library/busybox:latest",
            &authfile,
            &podman::Store::Shared,
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
            disk_bytes: 0,
            lifetime_secs: 0,
        },
        ws.path(),
        &[],
        &podman::Store::Shared,
        sentinel_worker::podman::Network::None,
    )
    .unwrap();
    assert_eq!(container.name(), format!("sentinel-{attempt}"));
    assert_eq!(
        podman::owned(worker).unwrap(),
        vec![(attempt, container.name().to_owned())]
    );

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
    let exit = container
        .exec(&sh("echo before; false; echo after", 30), &[])
        .unwrap();
    assert_eq!(exit.code, Some(1));
    assert_eq!(String::from_utf8_lossy(&exit.stdout).trim(), "before");
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
    assert_eq!(container.oom_kills().unwrap(), 0);
    // The pipeline's environment cannot override the worker's context.
    let mut cmd = sh("echo $SENTINEL_ATTEMPT", 30);
    cmd.env = vec![("SENTINEL_ATTEMPT".into(), "spoofed".into())];
    let exit = container
        .exec(&cmd, &[("SENTINEL_ATTEMPT".into(), "real".into())])
        .unwrap();
    assert_eq!(String::from_utf8_lossy(&exit.stdout).trim(), "real");

    let exit = container.exec(&sh("sleep 30", 1), &[]).unwrap();
    assert!(exit.timed_out);
    let after = container.exec(&sh("true", 5), &[]).unwrap();
    assert_ne!(after.code, Some(0));

    container.destroy().unwrap();
    assert!(podman::owned(worker).unwrap().is_empty());
    ws.destroy().unwrap();
}

fn host_cgroup(name: &str) -> std::path::PathBuf {
    let output = std::process::Command::new("podman")
        .args(["inspect", "--format", "{{.State.CgroupPath}}", "--", name])
        .output()
        .unwrap();
    assert!(output.status.success());
    let path = String::from_utf8(output.stdout).unwrap();
    std::path::Path::new("/sys/fs/cgroup").join(path.trim().trim_start_matches('/'))
}

struct RemoveOnFailure(String);

impl Drop for RemoveOnFailure {
    fn drop(&mut self) {
        if std::thread::panicking() {
            let _ = podman::remove_named(&self.0, &podman::Store::Shared);
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

/// A runtime may nest an exec'd step in a child cgroup, so cancel must search the whole tree.
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
        &podman::Store::Shared,
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
            disk_bytes: 0,
            lifetime_secs: 0,
        },
        ws.path(),
        &[],
        &podman::Store::Shared,
        sentinel_worker::podman::Network::None,
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
            podman::terminate_named(
                container.name(),
                &podman::Store::Shared,
                Duration::from_secs(10)
            )
            .unwrap(),
            podman::Terminated::Graceful
        );
        step.join().unwrap()
    });
    assert_eq!((exit.code, exit.signal), (None, Some(15)), "{exit:?}");
    assert!(cgroup.join("step").join("inner").exists());
    assert_eq!(
        podman::terminate_named(
            container.name(),
            &podman::Store::Shared,
            Duration::from_secs(1)
        )
        .unwrap(),
        podman::Terminated::Gone
    );

    container.destroy().unwrap();
    assert!(podman::owned(worker).unwrap().is_empty());
    ws.destroy().unwrap();
}

#[test]
fn an_image_a_container_holds_is_never_reclaimed() {
    if !enabled() {
        return;
    }
    let temp = tempfile::tempdir().unwrap();
    let store = podman::Store::private(&temp.path().join("stores"), [0x5e; 16]).unwrap();
    let podman::Store::Private { graph, run } = &store else {
        unreachable!("a private store")
    };
    let in_store = |args: &[&str]| {
        std::process::Command::new("podman")
            .arg("--root")
            .arg(graph)
            .arg("--runroot")
            .arg(run)
            .args(args)
            .output()
            .unwrap()
    };
    podman::pull(
        IMAGE,
        &authfile(temp.path()),
        &store,
        Duration::from_secs(600),
        &std::sync::atomic::AtomicBool::new(false),
    )
    .unwrap();
    let listed = podman::list_images(&store).unwrap();
    assert_eq!(listed.len(), 1, "{listed:?}");
    let image = listed[0].clone();
    assert_eq!(format!("docker.io/library/busybox@{}", image.digest), IMAGE);
    assert!(image.bytes > 0);
    assert_eq!(image.containers, 0);

    assert!(
        in_store(&["create", "--name", "r01-holder", IMAGE, "true"])
            .status
            .success()
    );
    assert_eq!(podman::list_images(&store).unwrap()[0].containers, 1);
    assert!(!podman::remove_image(&store, &image.id), "in use: kept");
    assert_eq!(podman::list_images(&store).unwrap().len(), 1);

    assert!(in_store(&["rm", "r01-holder"]).status.success());
    assert!(podman::remove_image(&store, &image.id));
    assert!(podman::list_images(&store).unwrap().is_empty());
    for dir in [graph, run] {
        let _ = std::process::Command::new("podman")
            .args(["unshare", "rm", "-rf"])
            .arg(dir)
            .output();
    }
}

#[test]
fn a_granted_egress_container_has_a_route_out_but_cannot_reach_the_hosts_loopback() {
    if !enabled() {
        return;
    }
    let temp = tempfile::tempdir().unwrap();
    let authfile = authfile(temp.path());
    podman::pull(
        IMAGE,
        &authfile,
        &podman::Store::Shared,
        Duration::from_secs(600),
        &std::sync::atomic::AtomicBool::new(false),
    )
    .unwrap();
    let host = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    host.set_nonblocking(true).unwrap();
    let port = host.local_addr().unwrap().port();
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
            disk_bytes: 0,
            lifetime_secs: 0,
        },
        ws.path(),
        &[],
        &podman::Store::Shared,
        podman::Network::Egress,
    )
    .unwrap();
    let script = format!(
        "ls /sys/class/net | grep -vx lo | head -1; ip route | grep -q '^default' && echo ROUTE; \
         gw=$(ip route | awk '/^default/ {{print $3}}'); \
         for a in 127.0.0.1 $gw; do nc -w 2 $a {port} </dev/null && echo REACHED $a || echo REFUSED; done"
    );
    let exit = container.exec(&sh(&script, 30), &[]).unwrap();
    let text = String::from_utf8_lossy(&exit.stdout).to_string();
    let lines: Vec<&str> = text.lines().collect();
    assert!(
        lines.first().is_some_and(|l| !l.is_empty()),
        "no interface besides lo: {text}"
    );
    assert_eq!(lines.get(1), Some(&"ROUTE"), "{text}");
    assert!(!text.contains("REACHED"), "{text}");
    assert!(
        host.accept().is_err(),
        "the host's loopback listener took a connection"
    );
}

#[test]
fn a_mounted_cache_is_seen_where_declared_and_never_under_the_workspace() {
    if !enabled() {
        return;
    }
    let temp = tempfile::tempdir().unwrap();
    let authfile = authfile(temp.path());
    podman::pull(
        IMAGE,
        &authfile,
        &podman::Store::Shared,
        Duration::from_secs(600),
        &std::sync::atomic::AtomicBool::new(false),
    )
    .unwrap();
    let (worker, attempt) = (WorkerId::new(), AttemptId::new());
    let ws = Workspace::create(temp.path(), attempt).unwrap();
    let cache = ws
        .path()
        .join(sentinel_cache::attach::PRIVATE_DIR)
        .join("gomod")
        .join("0");
    fs::create_dir_all(&cache).unwrap();
    fs::write(cache.join("restored.go"), "package cached\n").unwrap();
    let container = Container::start(
        worker,
        attempt,
        IMAGE,
        Limits {
            cpu_millis: 500,
            memory_bytes: 64 << 20,
            pids: 32,
            disk_bytes: 0,
            lifetime_secs: 0,
        },
        ws.path(),
        &[podman::Mount {
            host: cache.clone(),
            container: "/cache/gomod".into(),
            read_only: false,
        }],
        &podman::Store::Shared,
        podman::Network::None,
    )
    .unwrap();
    let script = "cat /cache/gomod/restored.go; echo built > /cache/gomod/new.go && echo WROTE; \
                  find /workspace -name '*.go' | wc -l; \
                  touch /workspace/.sentinel-cache/x 2>/dev/null && echo PLANTED || echo SEALED";
    let exit = container.exec(&sh(script, 30), &[]).unwrap();
    let text = String::from_utf8_lossy(&exit.stdout).to_string();
    assert_eq!(
        text.lines().collect::<Vec<_>>(),
        ["package cached", "WROTE", "0", "SEALED"],
        "{text}"
    );
    assert_eq!(fs::read_to_string(cache.join("new.go")).unwrap(), "built\n");
}

fn started_sandbox(
    temp: &std::path::Path,
    disk_bytes: u64,
) -> (sentinel_worker::sandbox::Sandbox, Workspace) {
    let authfile = authfile(temp);
    podman::pull(
        IMAGE,
        &authfile,
        &podman::Store::Shared,
        Duration::from_secs(600),
        &std::sync::atomic::AtomicBool::new(false),
    )
    .unwrap();
    let attempt = AttemptId::new();
    let ws = Workspace::create(temp, attempt).unwrap();
    let container = Container::start(
        WorkerId::new(),
        attempt,
        IMAGE,
        Limits {
            cpu_millis: 500,
            memory_bytes: 512 << 20,
            pids: 32,
            disk_bytes,
            lifetime_secs: 0,
        },
        ws.path(),
        &[],
        &podman::Store::Shared,
        podman::Network::None,
    )
    .unwrap();
    (sentinel_worker::sandbox::Sandbox::Container(container), ws)
}

#[test]
fn a_workspace_that_passes_its_declared_disk_stops_the_container() {
    if !enabled() {
        return;
    }
    let temp = tempfile::tempdir().unwrap();
    let limit: u64 = 64 << 20;
    let (sandbox, ws) = started_sandbox(temp.path(), limit);
    let guard = sandbox
        .guard_storage(ws.path(), limit)
        .expect("a container's workspace is guarded");
    // Many files, not one: `--ulimit fsize` only stops a single file past the limit. Two GiB are asked for;
    // the guard must end the step long before they are written.
    let started = std::time::Instant::now();
    let exit = sandbox.exec(
        &sh(
            "i=0; while [ $i -lt 64 ]; do dd if=/dev/zero of=/workspace/part$i bs=1M count=32 conv=fsync 2>/dev/null; \
             i=$((i+1)); done; echo WROTE_ALL",
            120,
        ),
        &[],
    );
    let took = started.elapsed();
    let used = guard
        .exceeded()
        .expect("the workspace passed its limit and the guard noticed");
    assert!(used > limit, "{used}");
    // The step was cut short: it did not reach its last line, and not by timing out.
    // (An `Err` is the container removed under the exec, which is the same stop.)
    if let Ok(exit) = exit {
        assert!(!String::from_utf8_lossy(&exit.stdout).contains("WROTE_ALL"));
        assert!(!exit.timed_out);
    }
    assert!(took < Duration::from_secs(60), "{took:?}");
    let written = fs::read_dir(ws.path()).unwrap().count() as u64;
    assert!(written < 64, "{written} parts were written");
    drop(guard);
    // The guard already removed the container, so there is nothing left for the teardown to stop.
    let _ = sandbox.destroy();
}

#[test]
fn a_workspace_under_its_declared_disk_is_left_alone() {
    if !enabled() {
        return;
    }
    let temp = tempfile::tempdir().unwrap();
    let limit: u64 = 256 << 20;
    let (sandbox, ws) = started_sandbox(temp.path(), limit);
    let guard = sandbox.guard_storage(ws.path(), limit).unwrap();
    let exit = sandbox
        .exec(
            &sh(
                "dd if=/dev/zero of=/workspace/data bs=1M count=16 2>/dev/null; sleep 2; echo DONE",
                60,
            ),
            &[],
        )
        .unwrap();
    assert_eq!(exit.code, Some(0));
    assert!(String::from_utf8_lossy(&exit.stdout).contains("DONE"));
    assert_eq!(guard.exceeded(), None);
    drop(guard);
    sandbox.destroy().unwrap();
}
