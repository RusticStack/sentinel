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
use sentinel_store::{
    Durability, Store,
    auth::{self, Authority, NamespaceKind, provisioning},
    dispatch, runs,
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
    let controller = Controller::start(
        Arc::clone(&store),
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
  broken:
    image: {IMAGE}@{DIGEST}
    resources: {{ cpu: 1, memory: 256MiB }}
    steps:
      - id: fail
        run: 'echo about to fail; exit 3'
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
    // Compiled order is by name: broken, inspect.
    let (broken, inspect) = (ids[0], ids[1]);
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
    // Every phase was stamped by the worker's reports, in order.
    let stamps = state(inspect).timestamps;
    assert!(stamps.leased <= stamps.preparing);
    assert!(stamps.preparing <= stamps.running);
    assert!(stamps.running <= stamps.finalizing);
    assert!(stamps.finalizing <= stamps.terminal);
    assert!(stamps.preparing.is_some() && stamps.finalizing.is_some());
    assert_eq!(
        controller
            .stats()
            .reports
            .load(std::sync::atomic::Ordering::SeqCst),
        8
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
