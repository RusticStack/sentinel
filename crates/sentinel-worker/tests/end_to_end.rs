#![cfg(target_os = "linux")]

use std::{
    fs,
    path::Path,
    process::Command,
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant},
};

use sentinel_auth::sealed::Key;
use sentinel_core::{
    JobId, JobState, Outcome, PoolId, RepoId, RunId, TenantId, UnixMillis, UserId, WorkerId,
    auth::{Namespace, Permissions as P, Principal, Role},
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
    secrets::{self, Binding, Scope},
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

/// SENTINEL_E2E_MICROVM=1 runs this suite with microVMs as the worker's default executor (TODO M04's gate),
/// with the setup in SENTINEL_FIRECRACKER, SENTINEL_GUEST_KERNEL and SENTINEL_GUEST_AGENT.
fn microvm_runtime() -> Option<sentinel_worker::attempt::Runtime> {
    std::env::var_os("SENTINEL_E2E_MICROVM")?;
    let path = |name: &str| {
        std::path::PathBuf::from(
            std::env::var_os(name).unwrap_or_else(|| panic!("{name} is required")),
        )
    };
    let setup = sentinel_worker::microvm::Setup {
        firecracker: path("SENTINEL_FIRECRACKER"),
        kernel: path("SENTINEL_GUEST_KERNEL"),
        agent: path("SENTINEL_GUEST_AGENT"),
    };
    setup.check().unwrap();
    Some(sentinel_worker::attempt::Runtime {
        default: Some(sentinel_worker::host::Isolation::Microvm),
        microvm: Some(Arc::new(setup)),
    })
}

/// The worker's live sandboxes: its containers and its microVMs.
fn sandboxes(worker: WorkerId, worker_dir: &Path) -> usize {
    podman::owned(worker).unwrap().len() + sentinel_worker::microvm::owned(worker_dir).len()
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

fn attempt_detail(store: &Store, tenant: TenantId, job: JobId) -> Option<String> {
    let attempt = store
        .read(|c| dispatch::latest_attempt(c, tenant, job))
        .ok()??;
    let bytes = store
        .read(|c| dispatch::attempt_summary(c, tenant, attempt))
        .ok()??;
    AttemptSummary::decode(&bytes)
        .ok()
        .map(|summary| summary.detail)
}

fn latest_attempt_acked(store: &Store, tenant: TenantId, job: JobId) -> Option<bool> {
    let attempt = store
        .read(|c| dispatch::latest_attempt(c, tenant, job))
        .ok()??;
    store
        .read(|c| {
            Ok(c.query_row(
                "SELECT acked_ms IS NOT NULL FROM attempts WHERE id=?1 AND tenant_id=?2",
                rusqlite::params![attempt.as_bytes(), tenant.as_bytes()],
                |row| row.get(0),
            )?)
        })
        .ok()
}

fn notice_kinds(notices: &Mutex<Vec<String>>) -> Vec<String> {
    notices
        .lock()
        .unwrap()
        .iter()
        .map(|notice| notice.split(['(', '{']).next().unwrap_or(notice).to_owned())
        .collect()
}

#[test]
fn a_job_runs_in_a_rootless_container_and_its_verdict_reaches_the_controller() {
    if !enabled() {
        return;
    }
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("origin");
    fs::create_dir(&repo).unwrap();
    git(&repo, &["init", "-q", "--initial-branch=main"]);
    fs::write(repo.join("greeting.txt"), "hello from git\n").unwrap();
    git(&repo, &["add", "."]);
    git(&repo, &["commit", "-q", "-m", "one"]);
    let sha = git(&repo, &["rev-parse", "HEAD"]);

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
            auth::set_membership(
                tx,
                Principal::new(root, P::ALL, None, None),
                tenant,
                root,
                Role::TenantAdmin,
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
    let objects =
        Arc::new(sentinel_store::objects::Objects::open(temp.path().join("objects")).unwrap());
    let controller = Controller::start(
        Arc::clone(&store),
        Arc::clone(&logs),
        objects,
        Identity::generate("controller").unwrap(),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    let master_key_path = temp.path().join("master.key");
    Key::create(&master_key_path).unwrap();
    let secret_key = Arc::new(Key::load(&master_key_path).unwrap());
    controller.set_source_key(Arc::clone(&secret_key));
    let root_principal = Principal::new(root, P::ALL, None, None);
    let token = store
        .writer()
        .write({
            let secret_key = Arc::clone(&secret_key);
            move |tx| {
                secrets::put(
                    tx,
                    root_principal,
                    secrets::Update {
                        scope: Scope::Repo(repo_id),
                        name: "TOKEN",
                        expected: 0,
                        value: b"managed-only-plaintext-value",
                    },
                    &secret_key,
                    UnixMillis::now(),
                )
            }
        })
        .unwrap();
    store
        .writer()
        .write(move |tx| {
            secrets::bind(
                tx,
                root_principal,
                &Binding {
                    repo: repo_id,
                    job: "secret_use".into(),
                    step: "read".into(),
                    name: "TOKEN".into(),
                    secret: token.id,
                    override_tenant: false,
                },
                UnixMillis::now(),
            )
        })
        .unwrap();
    let enrollment = store
        .writer()
        .write(move |tx| {
            workers::issue_enrollment(tx, Authority::HostLocal, pool, 60_000, UnixMillis::now())
        })
        .unwrap()
        .secret;

    let worker_dir = temp.path().join("worker");
    fs::create_dir(&worker_dir).unwrap();
    let notices = Arc::new(Mutex::new(Vec::<String>::new()));
    let log = Arc::clone(&notices);
    let worker_id = WorkerId::new();
    // Registered before each attempt, so redaction covers its first output.
    let registrar: Arc<std::sync::OnceLock<Executor>> = Arc::new(std::sync::OnceLock::new());
    let hook = Arc::clone(&registrar);
    let executor = Executor::start(
        worker_dir.clone(),
        worker_id,
        move |notice: Notice| {
            if let Notice::Started(attempt) = &notice
                && let Some(executor) = hook.get()
            {
                assert!(executor.register_secret(*attempt, b"hunter2-super-secret"));
            }
            log.lock().unwrap().push(format!("{notice:?}"));
        },
        true,
    )
    .unwrap();
    let _ = registrar.set(executor.clone());
    executor.set_cancel_grace(Duration::from_secs(2));
    if let Some(runtime) = microvm_runtime() {
        executor.set_runtime(runtime);
    }
    let handle = Arc::new(Handle::new());
    let (worker_cert, worker_key) = (temp.path().join("w.crt"), temp.path().join("w.key"));
    let link_thread = {
        let (executor, handle) = (executor.clone(), Arc::clone(&handle));
        let config = worker::Config {
            controller: controller.local_addr(),
            server: controller.fingerprint(),
            also_pinned: Vec::new(),
            worker: worker_id,
            name: "builder-1".into(),
            hello: Hello {
                protocol_min: ProtocolVersion(1),
                protocol_max: ProtocolVersion(10),
                capabilities: Capabilities(
                    Capabilities::REQUIRED.0 | Capabilities::SECRET_DELIVERY.0,
                ),
                arch: Arch::X86_64,
                software: "test".into(),
            },
            capacity: Capacity {
                cpu_millis: 4_000,
                memory_bytes: 4 << 30,
            },
            profile: sentinel_protocol::negotiate::Profile {
                disk_bytes: 64 << 30,
                ..sentinel_protocol::negotiate::Profile::default()
            },
            transport: sentinel_link::session::TransportStats::default(),
            remote_cache: false,
        };
        let identity = Identity::generate("worker").unwrap();
        identity.save(&worker_cert, &worker_key).unwrap();
        thread::spawn(move || {
            worker::run(
                config,
                identity,
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
  secret_use:
    image: {IMAGE}@{DIGEST}
    resources: {{ cpu: 1, memory: 128MiB }}
    secrets: [TOKEN]
    steps:
      - id: read
        run: 'test \"$TOKEN\" = \"managed-only-plaintext-value\" && echo \"secret=$TOKEN\"'
        secrets: [TOKEN]
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
      - id: poison
        run: 'ln -s /etc/passwd escape'
      - id: needs-eval
        if: ${{{{ hash_files('*') != '' }}}}
        run: 'true'
  oom:
    image: {IMAGE}@{DIGEST}
    resources: {{ cpu: 1, memory: 128MiB }}
    steps:
      - id: fill
        run: 'dd if=/dev/zero of=/tmp/x bs=1M count=300'
  fat:
    image: {IMAGE}@{DIGEST}
    resources: {{ cpu: 1, memory: 512MiB, disk: 1GiB }}
    steps:
      - id: fill
        run: 'i=0; while [ $i -lt 128 ]; do dd if=/dev/zero of=part$i bs=1M count=32 conv=fsync 2>/dev/null; i=$((i+1)); done'
      - id: never
        run: 'true'
  slow:
    image: {IMAGE}@{DIGEST}
    resources: {{ cpu: 1, memory: 128MiB }}
    timeout: 2s
    steps:
      - id: sleep
        run: 'sleep 30'
      - id: never
        run: 'true'
  polite:
    image: {IMAGE}@{DIGEST}
    resources: {{ cpu: 1, memory: 128MiB }}
    steps:
      - id: wait
        run: 'echo polite-started; sleep 300'
      - id: never
        run: 'true'
  stubborn:
    image: {IMAGE}@{DIGEST}
    resources: {{ cpu: 1, memory: 128MiB }}
    steps:
      - id: wait
        run: 'trap \"\" TERM; echo stubborn-started; while :; do sleep 1; done'
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
            sentinel_store::provenance::insert(
                tx,
                &sentinel_store::provenance::Provenance {
                    tenant,
                    repo: repo_id,
                    trigger: "push".into(),
                    delivery: None,
                    provider: None,
                    ref_name: Some("refs/heads/main".into()),
                    old_sha: None,
                    new_sha: None,
                    head_sha: None,
                    base_sha: None,
                    merge_sha: None,
                    pipeline_sha: "0123456789abcdef0123456789abcdef01234567".into(),
                    pipeline_path: Some(".sentinel.yml".into()),
                    pipeline_digest: [0; 16],
                    pr_number: None,
                },
                run,
                UnixMillis::now(),
            )?;
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
    let compiled = spec_names(&yaml);
    let by_name = |name: &str| ids[compiled.iter().position(|n| n == name).unwrap()];
    let (broken, inspect, secret_use, gated, unknown, oom, slow, polite, stubborn) = (
        by_name("broken"),
        by_name("inspect"),
        by_name("secret_use"),
        by_name("gated"),
        by_name("unknown"),
        by_name("oom"),
        by_name("slow"),
        by_name("polite"),
        by_name("stubborn"),
    );
    let fat = by_name("fat");
    let inspect_deadline = Instant::now() + Duration::from_secs(120);
    loop {
        let current = state(inspect);
        if current.state == JobState::Terminal(Outcome::Passed) {
            break;
        }
        assert!(
            Instant::now() < inspect_deadline,
            "timed out waiting for inspect passed: state={:?}, failure={:?}, worker_notices={}, detail={:?}",
            current.state,
            current.failure_class,
            notices.lock().unwrap().len(),
            attempt_detail(&store, tenant, inspect)
        );
        thread::sleep(Duration::from_millis(25));
    }
    let secret_deadline = Instant::now() + Duration::from_secs(120);
    loop {
        let current = state(secret_use);
        if current.state == JobState::Terminal(Outcome::Passed) {
            break;
        }
        assert!(
            Instant::now() < secret_deadline,
            "timed out waiting for secret job passed: state={:?}, failure={:?}, attempt_acked={:?}, connected_workers={}, handed_back={}, sessions_ended={}, worker_notices={:?}, detail={:?}",
            current.state,
            current.failure_class,
            latest_attempt_acked(&store, tenant, secret_use),
            controller.connected().len(),
            controller
                .stats()
                .handed_back
                .load(std::sync::atomic::Ordering::Relaxed),
            controller
                .stats()
                .sessions_ended
                .load(std::sync::atomic::Ordering::Relaxed),
            notice_kinds(&notices),
            attempt_detail(&store, tenant, secret_use)
        );
        thread::sleep(Duration::from_millis(25));
    }
    eventually("broken failed", || {
        state(broken).state == JobState::Terminal(Outcome::Failed)
    });
    let failed = state(broken);
    assert_eq!(
        failed.failure_class,
        Some(sentinel_core::FailureClass::CommandFailed)
    );
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
    let inspect_attempt = store
        .read(|c| dispatch::latest_attempt(c, tenant, inspect))
        .unwrap()
        .unwrap();
    let tail = logs
        .tail(run, inspect, inspect_attempt, 0, 100_000, None)
        .unwrap();
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
    let secret_attempt = store
        .read(|c| dispatch::latest_attempt(c, tenant, secret_use))
        .unwrap()
        .unwrap();
    let secret_tail = logs
        .tail(run, secret_use, secret_attempt, 0, 1000, None)
        .unwrap();
    let secret_log = secret_tail
        .frames
        .iter()
        .flat_map(|frame| frame.bytes.iter().copied())
        .collect::<Vec<_>>();
    let secret_log = String::from_utf8(secret_log).unwrap();
    assert!(secret_log.contains("secret=***"), "{secret_log}");
    assert!(!secret_log.contains("managed-only-plaintext-value"));
    let use_version: i64 = store
        .read(|c| {
            Ok(c.query_row(
                "SELECT version FROM secret_audit WHERE secret_id=?1 AND attempt_id=?2 AND action='use'",
                rusqlite::params![token.id.as_bytes(), secret_attempt.as_bytes()],
                |row| row.get(0),
            )?)
        })
        .unwrap();
    assert_eq!(use_version, 1);

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
    assert!(summary_of(unknown).detail.contains("step 1 `if`"));

    eventually("oom failed", || {
        state(oom).state == JobState::Terminal(Outcome::Failed)
    });
    assert_eq!(
        state(oom).failure_class,
        Some(sentinel_core::FailureClass::OutOfMemory)
    );
    assert_eq!(summary_of(oom).steps[0].outcome, StepOutcome::OutOfMemory);
    // 4 GiB are written 32 MiB at a time against a declared 1 GiB: no single file passes `fsize`, so only the
    // storage guard can end it. The verdict names the limit; the class stays the job's own `command_failed`.
    eventually("fat failed", || {
        state(fat).state == JobState::Terminal(Outcome::Failed)
    });
    assert_eq!(
        state(fat).failure_class,
        Some(sentinel_core::FailureClass::CommandFailed)
    );
    let fat_summary = summary_of(fat);
    // A microVM job meets its size-bound scratch disk instead (`ENOSPC` in the guest), which has no guard text.
    if microvm_runtime().is_none() {
        assert!(
            fat_summary.detail.contains("disk limit"),
            "{}",
            fat_summary.detail
        );
    }
    assert!(matches!(
        fat_summary.steps[0].outcome,
        StepOutcome::Failed { .. }
    ));
    assert_eq!(fat_summary.steps[1].outcome, StepOutcome::NotRun);
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
    let started = |job| {
        let attempt = store
            .read(|c| dispatch::latest_attempt(c, tenant, job))
            .unwrap();
        attempt.is_some_and(|attempt| {
            logs.tail(run, job, attempt, 0, 1000, None)
                .map(|t| t.frames.iter().any(|f| !f.bytes.is_empty()))
                .unwrap_or(false)
        })
    };
    eventually("polite started", || started(polite));
    eventually("stubborn started", || started(stubborn));
    let asked = Instant::now();
    store
        .writer()
        .write(move |tx| {
            dispatch::cancel(tx, tenant, polite, UnixMillis::now())?;
            dispatch::cancel(tx, tenant, stubborn, UnixMillis::now())
        })
        .unwrap();
    eventually("polite canceled", || {
        state(polite).state == JobState::Terminal(Outcome::Canceled)
    });
    eventually("stubborn canceled", || {
        state(stubborn).state == JobState::Terminal(Outcome::Canceled)
    });
    let took = asked.elapsed();
    assert!(took < Duration::from_secs(30), "cancellation took {took:?}");
    for job in [polite, stubborn] {
        assert_eq!(
            state(job).failure_class,
            Some(sentinel_core::FailureClass::Canceled)
        );
        let summary = summary_of(job);
        assert!(summary.detail.contains("canceled"), "{}", summary.detail);
        assert!(
            summary.steps[1..]
                .iter()
                .all(|s| s.outcome == StepOutcome::NotRun)
        );
    }
    let log = notices.lock().unwrap().clone();
    assert!(
        log.iter()
            .any(|n| n.contains("Canceled") && n.contains("forced: false")),
        "{log:?}"
    );
    assert!(
        log.iter()
            .any(|n| n.contains("Canceled") && n.contains("forced: true")),
        "{log:?}"
    );
    eventually("sandboxes gone", || sandboxes(worker_id, &worker_dir) == 0);

    let stamps = state(inspect).timestamps;
    assert!(stamps.leased <= stamps.preparing);
    assert!(stamps.preparing <= stamps.running);
    assert!(stamps.running <= stamps.finalizing);
    assert!(stamps.finalizing <= stamps.terminal);
    assert!(stamps.preparing.is_some() && stamps.finalizing.is_some());
    let reports = controller
        .stats()
        .reports
        .load(std::sync::atomic::Ordering::SeqCst);
    assert_eq!(reports, 10 * 4, "every report was applied");
    assert_eq!(
        controller
            .stats()
            .stale_reports
            .load(std::sync::atomic::Ordering::SeqCst),
        0
    );

    eventually("capacity released", || {
        store
            .read(|c| dispatch::free_capacity(c, worker_id))
            .unwrap()
            .cpu_millis
            == 4_000
    });
    assert!(executor.state_is_idle());
    assert_eq!(sandboxes(worker_id, &worker_dir), 0);
    assert!(Workspace::leftovers(&worker_dir).unwrap().is_empty());
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

    let orphan_yaml = format!(
        "schema: 1\non: [push]\njobs:\n  orphan:\n    image: {IMAGE}@{DIGEST}\n    steps: [{{ id: s, run: 'true' }}]\n"
    );
    let orphan_spec = RunSpec::new(
        PinnedSource::new(repo.to_str().unwrap(), &sha, Some("main")).unwrap(),
        compile_str(&orphan_yaml).unwrap(),
    )
    .unwrap();
    let (orphan_run, ids) = store
        .writer()
        .write(move |tx| {
            let run = RunId::new();
            let ids = runs::create_run(tx, tenant, repo_id, run, &orphan_spec, UnixMillis::now())?;
            runs::resolve_image(tx, tenant, ids[0], DIGEST, "linux/amd64")?;
            Ok((run, ids))
        })
        .unwrap();
    let orphan = ids[0];
    let offer = store
        .writer()
        .write(move |tx| {
            let offer = dispatch::place(
                tx,
                worker_id,
                pool,
                dispatch::DEFAULT_LEASE_MS,
                UnixMillis::now(),
            )?
            .expect("orphan placed");
            dispatch::acknowledge(tx, worker_id, offer.attempt, offer.fence, UnixMillis::now())?;
            Ok(offer)
        })
        .unwrap();
    assert_eq!(offer.job, orphan);
    let (attempt, fence) = (offer.attempt, offer.fence);
    sentinel_worker::recovery::mark(&worker_dir, attempt, fence).unwrap();
    let ws = Workspace::create(&worker_dir, attempt).unwrap();
    fs::write(ws.path().join("partial"), "x").unwrap();
    let limits = sentinel_worker::podman::Limits {
        cpu_millis: 500,
        memory_bytes: 128 << 20,
        pids: 64,
        disk_bytes: 0,
        lifetime_secs: 0,
    };
    match microvm_runtime().and_then(|r| r.microvm) {
        Some(setup) => std::mem::forget(
            sentinel_worker::microvm::Vm::start(
                &worker_dir,
                &setup,
                worker_id,
                attempt,
                &format!("{IMAGE}@{DIGEST}"),
                limits,
                ws.path(),
                &[],
                &podman::Store::Shared,
                sentinel_worker::podman::Network::None,
            )
            .unwrap(),
        ),
        None => std::mem::forget(
            sentinel_worker::podman::Container::start(
                worker_id,
                attempt,
                &format!("{IMAGE}@{DIGEST}"),
                limits,
                ws.path(),
                &[],
                &podman::Store::Shared,
                sentinel_worker::podman::Network::None,
            )
            .unwrap(),
        ),
    }
    {
        let mut spool = sentinel_worker::spool::Spool::open(&worker_dir, attempt).unwrap();
        spool
            .append(
                0,
                sentinel_protocol::logs::Stream::Stdout,
                b"printed before the crash\n",
            )
            .unwrap()
            .unwrap();
        spool.sync().unwrap();
    }
    assert_eq!(sandboxes(worker_id, &worker_dir), 1);

    let notices2 = Arc::new(Mutex::new(Vec::<String>::new()));
    let log2 = Arc::clone(&notices2);
    let executor2 = Executor::start(
        worker_dir.clone(),
        worker_id,
        move |notice: Notice| {
            log2.lock().unwrap().push(format!("{notice:?}"));
        },
        true,
    )
    .unwrap();
    if let Some(runtime) = microvm_runtime() {
        executor2.set_runtime(runtime);
    }
    let recovered = executor2.recovered();
    assert_eq!(recovered.leftovers, vec![(attempt, fence)]);
    assert_eq!(recovered.containers_removed, 1);
    assert_eq!(recovered.workspaces_removed, 1);
    assert_eq!(sandboxes(worker_id, &worker_dir), 0);
    assert!(Workspace::leftovers(&worker_dir).unwrap().is_empty());
    assert_eq!(executor2.leftovers_pending(), 1);
    let handle2 = Arc::new(Handle::new());
    let link2 = {
        let (executor, handle) = (executor2.clone(), Arc::clone(&handle2));
        let config = worker::Config {
            controller: controller.local_addr(),
            server: controller.fingerprint(),
            also_pinned: Vec::new(),
            worker: worker_id,
            name: "builder-1".into(),
            hello: Hello {
                protocol_min: ProtocolVersion(1),
                protocol_max: ProtocolVersion(3),
                capabilities: Capabilities::REQUIRED,
                arch: Arch::X86_64,
                software: "test".into(),
            },
            capacity: Capacity {
                cpu_millis: 4_000,
                memory_bytes: 4 << 30,
            },
            profile: sentinel_protocol::negotiate::Profile {
                disk_bytes: 64 << 30,
                ..sentinel_protocol::negotiate::Profile::default()
            },
            transport: sentinel_link::session::TransportStats::default(),
            remote_cache: false,
        };
        let identity = Identity::load(&worker_cert, &worker_key).unwrap();
        thread::spawn(move || worker::run(config, identity, None, &executor, &handle, &|_| {}))
    };
    eventually("orphan reconciled", || {
        state(orphan).state == JobState::Terminal(Outcome::InfraFailed)
    });
    assert_eq!(
        state(orphan).failure_class,
        Some(sentinel_core::FailureClass::Reconciled)
    );
    // The gap is the output printed after the last durable frame, which the controller never received.
    let tail = logs.tail(orphan_run, orphan, attempt, 0, 10, None).unwrap();
    assert!(tail.complete);
    assert_eq!(tail.frames.len(), 1);
    assert_eq!(tail.frames[0].bytes, b"printed before the crash\n");
    assert_eq!(tail.gaps, vec![(2, 2)]);
    eventually("leftover settled", || {
        notices2
            .lock()
            .unwrap()
            .iter()
            .any(|n| n.contains("Abandoned") && n.contains("log_delivered: true"))
    });
    assert!(
        sentinel_worker::recovery::leftovers(&worker_dir)
            .unwrap()
            .is_empty()
    );
    assert!(
        sentinel_worker::spool::Spool::leftovers(&worker_dir)
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        controller
            .stats()
            .abandoned
            .load(std::sync::atomic::Ordering::SeqCst),
        1
    );
    assert!(executor2.state_is_idle());
    handle2.stop();
    link2.join().unwrap().unwrap();
    assert!(controller.shutdown(Duration::from_secs(5)));
}
