#![cfg(target_os = "linux")]

//! An opted-in task is served from the worker's own store without running; an unopted one always runs.
//!
//! Gated like the rest of the executor suite: rootless containers, or Firecracker microVMs with
//! `SENTINEL_MICROVM_TESTS=1`.

#[path = "support/isolation.rs"]
mod isolation;

use std::{
    fs,
    path::Path,
    process::Command,
    sync::{Arc, Mutex, atomic::AtomicBool},
    time::Duration,
};

use sentinel_core::{AttemptId, Event, Fence, JobId, RepoId, RunId, WorkerId};
use sentinel_link::session::{EventContext, JobContext};
use sentinel_pipeline::{PinnedSource, RunSpec, compile_str};
use sentinel_protocol::{cache::Trust, summary::AttemptSummary};
use sentinel_worker::{
    artifacts::NoSink,
    attempt::{self, Job, Output, Report, Verdict},
    images::Images,
    podman::{Network, Store},
};

const IMAGE: &str = "docker.io/library/busybox";
const DIGEST: &str = "sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662";

fn enabled() -> bool {
    isolation::enabled()
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

fn make_repo(dir: &Path) -> String {
    fs::create_dir(dir).unwrap();
    git(dir, &["init", "-q", "--initial-branch=main"]);
    fs::write(dir.join("seed.txt"), "seed\n").unwrap();
    git(dir, &["add", "."]);
    git(dir, &["commit", "-q", "-m", "one"]);
    git(dir, &["rev-parse", "HEAD"])
}

/// Every byte a step printed, so a test can tell an executed attempt from a served one.
#[derive(Default)]
struct Recording {
    bytes: Mutex<Vec<u8>>,
}

impl Output for Recording {
    fn write(&self, _: u32, _: sentinel_protocol::logs::Stream, bytes: &[u8]) {
        self.bytes.lock().unwrap().extend_from_slice(bytes);
    }
    fn complete(&self) -> bool {
        true
    }
}

impl Recording {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.bytes.lock().unwrap()).into_owned()
    }
}

#[derive(Default)]
struct Silent;

impl Report for Silent {
    fn event(&self, _: AttemptId, _: Fence, _: Event) {}
    fn finish(&self, _: AttemptId, _: Fence, _: Event, _: Vec<u8>) {}
}

fn pipeline(reuse: bool) -> String {
    let reuse = if reuse {
        "    reuse:\n      inputs: [seed.txt]\n      paths: [dist]\n"
    } else {
        ""
    };
    format!(
        r#"
schema: 1
on: [push]
jobs:
  build:
    image: {IMAGE}:1.36
    resources: {{ cpu: 1, memory: 128MiB }}
    timeout: 5m
{reuse}    steps:
      - id: work
        run: 'echo ran-step && mkdir -p dist && echo payload > dist/app'
"#
    )
}

fn make_job(worker_dir: &Path, repo_dir: &Path, sha: &str, repo: RepoId, yaml: &str) -> Job {
    fs::create_dir_all(worker_dir).unwrap();
    let compiled = compile_str(yaml).unwrap();
    let source = PinnedSource::new(repo_dir.to_str().unwrap(), sha, Some("main")).unwrap();
    Job {
        worker: WorkerId::new(),
        attempt: AttemptId::new(),
        fence: Fence(1),
        job_index: 0,
        digest: DIGEST.to_owned(),
        spec: RunSpec::new(source, compiled).unwrap(),
        context: JobContext {
            source: None,
            source_valid_until: None,
            run: RunId::new(),
            repo,
            repo_name: "reuse-worker".to_owned(),
            job: JobId::new(),
            job_name: "build".to_owned(),
            sha: sha.to_owned(),
            event: EventContext {
                name: "push".into(),
                ref_name: "refs/heads/main".into(),
                base_ref: None,
                pr_number: None,
                key: "main".into(),
            },
            cancelled: false,
            needs: Vec::new(),
            tenant: None,
            trust: Trust::Protected,
            outputs: Vec::new(),
            reuse_fresh: false,
        },
        images: Images::for_worker_data_dir(worker_dir).unwrap(),
        secret_bundle: sentinel_protocol::secrets::DeliveryBundle::empty(),
        caches: Vec::new(),
        reuse_seal: None,
        reuse_fresh: false,
        cache_budget_bytes: sentinel_cache::gc::DEFAULT_BUDGET_BYTES,
        mirrors: None,
        prepare_hold: Duration::ZERO,
        network: Network::None,
        runtime: isolation::runtime().unwrap_or_default(),
        store: Store::Shared,
    }
}

/// One attempt whose step output is captured, so "did it run" is answered by the job's own bytes.
fn run_captured(worker_dir: &Path, job: &mut Job) -> (Verdict, AttemptSummary, String) {
    struct Shared(Arc<Recording>);
    impl Output for Shared {
        fn write(&self, step: u32, stream: sentinel_protocol::logs::Stream, bytes: &[u8]) {
            self.0.write(step, stream, bytes);
        }
        fn complete(&self) -> bool {
            true
        }
    }
    let recording = Arc::new(Recording::default());
    let cancel: Arc<AtomicBool> = Arc::new(AtomicBool::new(false));
    let (verdict, summary) = attempt::run(
        worker_dir,
        job,
        &Silent,
        Arc::new(Shared(Arc::clone(&recording))),
        Arc::new(NoSink),
        &cancel,
    );
    (verdict, summary, recording.text())
}

#[test]
fn a_passed_opted_in_task_is_served_without_running_again() {
    if !enabled() {
        return;
    }
    let temp = tempfile::tempdir().unwrap();
    let repo_dir = temp.path().join("origin");
    let sha = make_repo(&repo_dir);
    let repo = RepoId::new();
    let worker_dir = temp.path().join("worker");

    let mut job = make_job(&worker_dir, &repo_dir, &sha, repo, &pipeline(true));
    let (verdict, summary, printed) = run_captured(&worker_dir, &mut job);
    assert_eq!(verdict, Verdict::Passed);
    assert!(
        summary.reuse.is_none(),
        "the first run has nothing to serve"
    );
    assert_eq!(summary.steps.len(), 1, "the step ran");
    assert!(printed.contains("ran-step"));

    let mut job = make_job(&worker_dir, &repo_dir, &sha, repo, &pipeline(true));
    let (verdict, summary, printed) = run_captured(&worker_dir, &mut job);
    assert_eq!(
        verdict,
        Verdict::Passed,
        "a served result is a passing attempt"
    );
    let record = summary
        .reuse
        .as_ref()
        .expect("the attempt must say it reused a result");
    assert_eq!(record.entry, "build");
    assert_eq!(record.key.len(), 64);
    assert!(record.generation.starts_with("gen-"));
    assert!(record.files >= 1);
    assert!(summary.steps.is_empty(), "no step of a served task runs");
    assert!(
        !printed.contains("ran-step"),
        "the job printed nothing: nothing of it ran"
    );
    assert!(
        summary.container_start_ns.is_none(),
        "a served result starts no sandbox"
    );
}

#[test]
fn an_unopted_task_runs_every_time() {
    if !enabled() {
        return;
    }
    let temp = tempfile::tempdir().unwrap();
    let repo_dir = temp.path().join("origin");
    let sha = make_repo(&repo_dir);
    let repo = RepoId::new();
    let worker_dir = temp.path().join("worker");

    for attempt in 0..2 {
        let mut job = make_job(&worker_dir, &repo_dir, &sha, repo, &pipeline(false));
        let (verdict, summary, printed) = run_captured(&worker_dir, &mut job);
        assert_eq!(verdict, Verdict::Passed);
        assert!(
            summary.reuse.is_none(),
            "attempt {attempt}: a task that did not opt in is never served"
        );
        assert_eq!(summary.steps.len(), 1, "attempt {attempt}: the step ran");
        assert!(printed.contains("ran-step"), "attempt {attempt}");
    }
}

#[test]
fn a_forced_run_executes_a_task_it_would_have_served() {
    if !enabled() {
        return;
    }
    let temp = tempfile::tempdir().unwrap();
    let repo_dir = temp.path().join("origin");
    let sha = make_repo(&repo_dir);
    let repo = RepoId::new();
    let worker_dir = temp.path().join("worker");

    let mut job = make_job(&worker_dir, &repo_dir, &sha, repo, &pipeline(true));
    let (verdict, _, _) = run_captured(&worker_dir, &mut job);
    assert_eq!(verdict, Verdict::Passed);

    // The same task would be served now; a forced run executes it instead and seals nothing new.
    let mut job = make_job(&worker_dir, &repo_dir, &sha, repo, &pipeline(true));
    job.reuse_fresh = true;
    let (verdict, summary, printed) = run_captured(&worker_dir, &mut job);
    assert_eq!(verdict, Verdict::Passed);
    assert!(summary.reuse.is_none(), "a forced run serves nothing");
    assert_eq!(summary.steps.len(), 1);
    assert!(printed.contains("ran-step"));

    // The entry it bypassed is untouched, so the next ordinary run still serves it.
    let mut job = make_job(&worker_dir, &repo_dir, &sha, repo, &pipeline(true));
    let (_, summary, printed) = run_captured(&worker_dir, &mut job);
    assert!(summary.reuse.is_some());
    assert!(!printed.contains("ran-step"));
}
