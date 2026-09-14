//! W03 end to end: a controller with a store, a worker with the real
//! executor over loopback TLS, a local repository and a busybox image by
//! digest. A run is enqueued; the worker enrolls, takes the offer, fetches
//! the spec, checks out the pinned commit, runs the steps in a rootless
//! container and reports; the controller records `Passed` (or the failure
//! class), releases the capacity and leaves nothing behind. Gated like the
//! Podman test: `SENTINEL_PODMAN_TESTS=1` as a rootless Podman account.

#![cfg(target_os = "linux")]

use std::{
    fs,
    path::Path,
    process::Command,
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant},
};

use sentinel_core::{
    JobState, Outcome, PoolId, RepoId, RunId, TenantId, UnixMillis, UserId, WorkerId,
    auth::{Namespace, Permissions as P, Principal},
};
use sentinel_link::{
    controller::Controller,
    identity::Identity,
    session::Capacity,
    worker::{self, Handle},
};
use sentinel_pipeline::{PinnedSource, RunSpec, compile_str};
use sentinel_protocol::negotiate::{Arch, Capabilities, Hello, ProtocolVersion};
use sentinel_protocol::summary::{AttemptSummary, StepOutcome};
use sentinel_store::{
    Durability, Store,
    auth::{self, Authority, NamespaceKind, provisioning},
    dispatch,
    logs::LogStore,
    runs,
    tenancy::{self, PoolKind},
    workers,
};
use sentinel_worker::{
    executor::{Executor, Notice},
    podman,
    workspace::Workspace,
};

const IMAGE: &str = "docker.io/library/busybox";
const DIGEST: &str = "sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662";

fn enabled() -> bool {
    if std::env::var_os("SENTINEL_PODMAN_TESTS").is_some() {
        return true;
    }
    eprintln!("skipped: set SENTINEL_PODMAN_TESTS=1 as a rootless Podman account to run");
    false
}

fn git(dir: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .args(args)
        .current_dir(dir)
        .env("GIT_AUTHOR_NAME", "t")
        .env("GIT_AUTHOR_EMAIL", "t@example.com")
        .env("GIT_COMMITTER_NAME", "t")
        .env("GIT_COMMITTER_EMAIL", "t@example.com")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .output()
        .unwrap();
    assert!(output.status.success());
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}

fn spec_names(yaml: &str) -> Vec<String> {
    compile_str(yaml)
        .unwrap()
        .jobs
        .iter()
        .map(|j| j.name.clone())
        .collect()
}

fn eventually(what: &str, mut predicate: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(120);
    while !predicate() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        thread::sleep(Duration::from_millis(25));
    }
}

#[test]
fn a_job_runs_in_a_rootless_container_and_its_verdict_reaches_the_controller() {
    if !enabled() {
        return;
    }
    let temp = tempfile::tempdir().unwrap();
    // A repository with one commit the pipeline will inspect.
    let repo = temp.path().join("origin");
    fs::create_dir(&repo).unwrap();
    git(&repo, &["init", "-q", "--initial-branch=main"]);
    fs::write(repo.join("greeting.txt"), "hello from git\n").unwrap();
    git(&repo, &["add", "."]);
    git(&repo, &["commit", "-q", "-m", "one"]);
    let sha = git(&repo, &["rev-parse", "HEAD"]);

    // Controller.
    let store =
        Arc::new(Store::open(temp.path().join("metadata.sqlite"), Durability::Normal).unwrap());
    let (root, tenant, repo_id, pool) =
        (UserId::new(), TenantId::new(), RepoId::new(), PoolId::new());
    store
        .writer()
        .write(move |tx| {
            provisioning::insert_human(tx, root, "Root", true, UnixMillis(1))?;
            auth::create_namespace(
                tx,
                Principal::new(root, P::ALL, None, None),
                tenant,
                Namespace::parse("acme").unwrap(),
                NamespaceKind::Organization,
                UnixMillis(1),
            )?;
            sentinel_store::jobs::insert_repo(tx, tenant, repo_id, "app", UnixMillis(1))?;
            tenancy::create_pool(
                tx,
                Authority::HostLocal,
                pool,
                "builders",
                PoolKind::Dedicated(tenant),
                UnixMillis(1),
            )
        })
        .unwrap();
    let logs = Arc::new(LogStore::open(temp.path().join("logs")).unwrap());
    let controller = Controller::start(
        Arc::clone(&store),
        Arc::clone(&logs),
        Identity::generate("controller").unwrap(),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    let enrollment = store
        .writer()
        .write(move |tx| {
            workers::issue_enrollment(tx, Authority::HostLocal, pool, 60_000, UnixMillis::now())
        })
        .unwrap()
        .secret;

    // Worker with the real executor.
    let worker_dir = temp.path().join("worker");
    fs::create_dir(&worker_dir).unwrap();
    let notices = Arc::new(Mutex::new(Vec::<String>::new()));
    let log = Arc::clone(&notices);
    let worker_id = WorkerId::new();
    let executor = Executor::start(worker_dir.clone(), worker_id, move |notice: Notice| {
        log.lock().unwrap().push(format!("{notice:?}"));
    })
    .unwrap();
    // The value a secret binding would inject (S05); registered before any
    // attempt starts, it never reaches a log.
    executor.register_secret(b"hunter2-super-secret");
    let handle = Arc::new(Handle::new());
    let link_thread = {
        let (executor, handle) = (executor.clone(), Arc::clone(&handle));
        let config = worker::Config {
            controller: controller.local_addr(),
            server: controller.fingerprint(),
            worker: worker_id,
            name: "builder-1".into(),
            hello: Hello {
                protocol_min: ProtocolVersion(1),
                protocol_max: ProtocolVersion(1),
                capabilities: Capabilities::REQUIRED,
                arch: Arch::X86_64,
                software: "test".into(),
            },
            capacity: Capacity {
                cpu_millis: 4_000,
                memory_bytes: 4 << 30,
            },
        };
        thread::spawn(move || {
            worker::run(
                config,
                Identity::generate("worker").unwrap(),
                Some(enrollment),
                &executor,
                &handle,
                &|_| {},
            )
        })
    };
    eventually("worker connected", || {
        controller.connected() == vec![worker_id]
    });

    // A run: one job that reads the checkout and writes into the workspace,
    // then one that fails on purpose.
    let yaml = format!(
        "schema: 1
on: [push]
jobs:
  inspect:
    image: {IMAGE}@{DIGEST}
    resources: {{ cpu: 1, memory: 256MiB }}
    steps:
      - id: read
        run: 'test \"$(cat greeting.txt)\" = \"hello from git\" && test \"$SENTINEL_SHA\" = {sha}'
      - id: write
        run: 'echo built > out.txt && test -f out.txt && id -u'
      - id: chatty
        run: 'echo \"token=hunter2-super-secret ok\"; echo warned >&2; i=0; while [ $i -lt 2000 ]; do echo \"line $i of the log\"; i=$((i+1)); done'
  broken:
    image: {IMAGE}@{DIGEST}
    resources: {{ cpu: 1, memory: 256MiB }}
    steps:
      - id: fail
        run: 'echo about to fail; false; echo never'
      - id: after
        run: 'true'
  gated:
    image: {IMAGE}@{DIGEST}
    needs: [inspect]
    resources: {{ cpu: 1, memory: 256MiB }}
    steps:
      - id: skipped
        if: ${{{{ job.name == 'nope' }}}}
        run: 'exit 9'
      - id: runs
        if: ${{{{ needs.inspect.result == 'passed' && hash_files('greeting.txt') != '' && event.sha == '{sha}' && success() }}}}
        run: 'true'
  unknown:
    image: {IMAGE}@{DIGEST}
    resources: {{ cpu: 1, memory: 256MiB }}
    steps:
      - id: needs-intake
        if: ${{{{ event.name == 'push' }}}}
        run: 'true'
  oom:
    image: {IMAGE}@{DIGEST}
    resources: {{ cpu: 1, memory: 128MiB }}
    steps:
      - id: fill
        run: 'dd if=/dev/zero of=/tmp/x bs=1M count=300'
  slow:
    image: {IMAGE}@{DIGEST}
    resources: {{ cpu: 1, memory: 128MiB }}
    timeout: 2s
    steps:
      - id: sleep
        run: 'sleep 30'
      - id: never
        run: 'true'
"
    );
    let spec = RunSpec::new(
        PinnedSource::new(repo.to_str().unwrap(), &sha, Some("main")).unwrap(),
        compile_str(&yaml).unwrap(),
    )
    .unwrap();
    let run = RunId::new();
    let ids = store
        .writer()
        .write(move |tx| {
            let ids = runs::create_run(tx, tenant, repo_id, run, &spec, UnixMillis::now())?;
            for job in &ids {
                runs::resolve_image(tx, tenant, *job, DIGEST, "linux/amd64")?;
            }
            Ok(ids)
        })
        .unwrap();
    controller.wake();
    let state = |job| {
        store
            .read(|c| sentinel_store::jobs::get_job(c, tenant, job))
            .unwrap()
    };
    // Compiled order is dependencies first, then by name.
    let compiled = spec_names(&yaml);
    let by_name = |name: &str| ids[compiled.iter().position(|n| n == name).unwrap()];
    let (broken, inspect, gated, unknown, oom, slow) = (
        by_name("broken"),
        by_name("inspect"),
        by_name("gated"),
        by_name("unknown"),
        by_name("oom"),
        by_name("slow"),
    );
    eventually("inspect passed", || {
        state(inspect).state == JobState::Terminal(Outcome::Passed)
    });
    eventually("broken failed", || {
        state(broken).state == JobState::Terminal(Outcome::Failed)
    });
    let failed = state(broken);
    assert_eq!(
        failed.failure_class,
        Some(sentinel_core::FailureClass::CommandFailed)
    );
    // `sh -e`: the first failing command ends the step with its status and
    // the following step never starts; the summary says so per step.
    let summary_of = |job| {
        let attempt = store
            .read(|c| dispatch::latest_attempt(c, tenant, job))
            .unwrap()
            .unwrap();
        let bytes = store
            .read(|c| dispatch::attempt_summary(c, tenant, attempt))
            .unwrap()
            .expect("summary stored with the terminal report");
        AttemptSummary::decode(&bytes).unwrap()
    };
    let broken_summary = summary_of(broken);
    assert_eq!(
        broken_summary
            .steps
            .iter()
            .map(|s| (s.id.as_str(), s.outcome))
            .collect::<Vec<_>>(),
        vec![
            ("fail", StepOutcome::Failed { code: 1 }),
            ("after", StepOutcome::NotRun)
        ]
    );
    assert!(broken_summary.steps[0].duration_ns.is_some());
    assert!(broken_summary.steps[1].duration_ns.is_none());
    assert!(broken_summary.detail.contains("step 0 exited with 1"));
    // The log reached the controller through the spool and the window,
    // redacted before it left the worker, complete, in order, with the
    // streams told apart, and the spool is gone.
    let inspect_attempt = store
        .read(|c| dispatch::latest_attempt(c, tenant, inspect))
        .unwrap()
        .unwrap();
    let tail = logs.tail(inspect_attempt, 0, 100_000).unwrap();
    assert!(tail.complete && tail.gaps.is_empty());
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut last_seq = 0;
    for f in &tail.frames {
        assert_eq!(f.seq, last_seq + 1, "frames in sequence");
        last_seq = f.seq;
        match f.stream {
            sentinel_protocol::logs::Stream::Stdout => stdout.extend(&f.bytes),
            sentinel_protocol::logs::Stream::Stderr => stderr.extend(&f.bytes),
        }
    }
    let stdout = String::from_utf8(stdout).unwrap();
    assert!(stdout.contains("token=*** ok\n"), "{stdout}");
    assert!(!stdout.contains("hunter2"));
    assert!(stdout.contains("line 1999 of the log\n"));
    assert_eq!(stdout.matches(" of the log\n").count(), 2000);
    assert_eq!(String::from_utf8(stderr).unwrap(), "warned\n");
    assert!(tail.frames.iter().any(|f| f.step == 2));
    let inspect_summary = summary_of(inspect);
    assert!(inspect_summary.checkout_ns.is_some());
    assert!(inspect_summary.image_pull_ns.is_some());
    assert!(inspect_summary.container_start_ns.is_some());
    assert!(inspect_summary.steps_ns.is_some());
    assert!(inspect_summary.finalize_ns.is_some());
    assert!(inspect_summary.detail.is_empty());
    assert!(
        inspect_summary
            .steps
            .iter()
            .all(|s| s.outcome == StepOutcome::Passed)
    );

    // Conditions: a false `if` skips; dependency results, hash_files on the
    // checkout, event.sha and success() resolve on the worker; an event field
    // intake has not recorded is a preparation failure, never a default.
    eventually("gated passed", || {
        state(gated).state == JobState::Terminal(Outcome::Passed)
    });
    assert_eq!(
        summary_of(gated)
            .steps
            .iter()
            .map(|s| s.outcome)
            .collect::<Vec<_>>(),
        vec![StepOutcome::Skipped, StepOutcome::Passed]
    );
    eventually("unknown infra-failed", || {
        state(unknown).state == JobState::Terminal(Outcome::InfraFailed)
    });
    assert_eq!(
        state(unknown).failure_class,
        Some(sentinel_core::FailureClass::Preparation)
    );
    assert!(summary_of(unknown).detail.contains("step 0 `if`"));

    // The memory limit is an OOM, not a plain signal; the job timeout bounds
    // the steps and is a timeout, not a failed command.
    eventually("oom failed", || {
        state(oom).state == JobState::Terminal(Outcome::Failed)
    });
    assert_eq!(
        state(oom).failure_class,
        Some(sentinel_core::FailureClass::OutOfMemory)
    );
    assert_eq!(summary_of(oom).steps[0].outcome, StepOutcome::OutOfMemory);
    eventually("slow timed out", || {
        state(slow).state == JobState::Terminal(Outcome::TimedOut)
    });
    assert_eq!(
        state(slow).failure_class,
        Some(sentinel_core::FailureClass::ExecutionTimeout)
    );
    let slow_summary = summary_of(slow);
    assert_eq!(slow_summary.steps[0].outcome, StepOutcome::TimedOut);
    assert_eq!(slow_summary.steps[1].outcome, StepOutcome::NotRun);
    assert!(slow_summary.steps[0].duration_ns.unwrap() < 10_000_000_000);
    // Every phase was stamped by the worker's reports, in order.
    let stamps = state(inspect).timestamps;
    assert!(stamps.leased <= stamps.preparing);
    assert!(stamps.preparing <= stamps.running);
    assert!(stamps.running <= stamps.finalizing);
    assert!(stamps.finalizing <= stamps.terminal);
    assert!(stamps.preparing.is_some() && stamps.finalizing.is_some());
    // Six jobs: four full lifecycles (4 reports) and two preparation
    // failures (2 reports each: unknown fails inside the steps phase, so it
    // is a full lifecycle too).
    let reports = controller
        .stats()
        .reports
        .load(std::sync::atomic::Ordering::SeqCst);
    assert_eq!(reports, 6 * 4, "every report was applied");
    assert_eq!(
        controller
            .stats()
            .stale_reports
            .load(std::sync::atomic::Ordering::SeqCst),
        0
    );

    // Capacity is released, nothing is left in the runtime or on disk.
    eventually("capacity released", || {
        store
            .read(|c| dispatch::free_capacity(c, worker_id))
            .unwrap()
            .cpu_millis
            == 4_000
    });
    assert!(executor.state_is_idle());
    assert!(podman::owned(worker_id).unwrap().is_empty());
    assert!(Workspace::leftovers(&worker_dir).unwrap().is_empty());
    // Every spool was acknowledged, closed and removed.
    assert!(
        sentinel_worker::spool::Spool::leftovers(&worker_dir)
            .unwrap()
            .is_empty()
    );
    let log = notices.lock().unwrap().clone();
    assert!(
        log.iter()
            .any(|n| n.contains("Finished") && n.contains("Passed")),
        "{log:?}"
    );
    assert!(log.iter().any(|n| n.contains("CommandFailed")), "{log:?}");

    handle.stop();
    link_thread.join().unwrap().unwrap();
    assert!(controller.shutdown(Duration::from_secs(5)));
}
