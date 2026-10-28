#![cfg(target_os = "linux")]

//! Cache publication under the isolation of the run: rootless containers, or Firecracker microVMs with
//! `SENTINEL_MICROVM_TESTS=1` (see `support/isolation.rs`; TODO M04's gate).

#[path = "support/isolation.rs"]
mod isolation;

use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    sync::{Arc, Mutex, atomic::AtomicBool},
    time::Duration,
};

use sentinel_cache::{
    Os, Platform, Scope,
    attach::{self, ROOT_DIR, UNKNOWN_TENANT},
    scope,
};
use sentinel_core::{AttemptId, Event, Fence, JobId, RepoId, RunId, WorkerId};
use sentinel_link::session::{EventContext, JobContext};
use sentinel_pipeline::{PinnedSource, RunSpec, compile_str};
use sentinel_protocol::{
    cache::{Class, Trust},
    negotiate::Arch,
    summary::AttemptSummary,
};
use sentinel_worker::{
    artifacts::NoSink,
    attempt::{self, CacheNote, CacheOutcome, Job, NoOutput, Report, Verdict},
    images::Images,
};

const IMAGE: &str = "docker.io/library/busybox";
const DIGEST: &str = "sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662";
const KEY: &str = "k09-deps";
const REPO_NAME: &str = "k09-worker";

const PIPELINE: &str = r#"
schema: 1
on: [push]
jobs:
  build:
    image: docker.io/library/busybox:1.36
    resources: { cpu: 1, memory: 128MiB }
    timeout: 5m
    cache:
      - name: deps
        key: k09-deps
        paths: [vendor]
    steps:
      - id: work
        run: 'mkdir -p vendor && echo payload > vendor/lib'
"#;

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

/// A one-commit local repository the attempt checks out.
fn make_repo(dir: &Path) -> String {
    fs::create_dir(dir).unwrap();
    git(dir, &["init", "-q", "--initial-branch=main"]);
    fs::write(dir.join("seed.txt"), "seed\n").unwrap();
    git(dir, &["add", "."]);
    git(dir, &["commit", "-q", "-m", "one"]);
    git(dir, &["rev-parse", "HEAD"])
}

/// Keeps the cache notes that the default `Report::cache_note` drops.
#[derive(Default)]
struct Notes {
    cache: Mutex<Vec<CacheNote>>,
}

impl Report for Notes {
    fn event(&self, _: AttemptId, _: Fence, _: Event) {}
    fn finish(&self, _: AttemptId, _: Fence, _: Event, _: Vec<u8>) {}
    fn cache_note(&self, _: AttemptId, note: CacheNote) {
        self.cache.lock().unwrap().push(note);
    }
}

fn entry_dir(worker_dir: &Path, repo: RepoId, trust: Trust) -> PathBuf {
    let image = format!("{IMAGE}@{DIGEST}");
    let scope = Scope::new(
        UNKNOWN_TENANT,
        repo,
        Class::Dependencies,
        trust,
        Platform {
            os: Os::Linux,
            arch: if cfg!(target_arch = "aarch64") {
                Arch::Aarch64
            } else {
                Arch::X86_64
            },
        },
        Scope::toolchain_digest(image.as_bytes()),
        "deps",
    )
    .unwrap();
    scope.entry_dir(
        &worker_dir.join(ROOT_DIR),
        attach::entry_key(Class::Dependencies, KEY),
    )
}

fn make_job(worker_dir: &Path, repo_dir: &Path, sha: &str, repo: RepoId, trust: Trust) -> Job {
    // The worker's data directory exists before a worker prepares its image authority, as it does in service.
    std::fs::create_dir_all(worker_dir).unwrap();
    let compiled = compile_str(PIPELINE).unwrap();
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
            run: RunId::new(),
            repo,
            repo_name: REPO_NAME.to_owned(),
            job: JobId::new(),
            job_name: "build".to_owned(),
            sha: sha.to_owned(),
            event: EventContext {
                name: "push".into(),
                ref_name: "refs/heads/main".into(),
                base_ref: None,
                pr_number: None,
                key: "k09".into(),
            },
            cancelled: false,
            needs: Vec::new(),
            tenant: None,
            trust,
        },
        images: Images::for_worker_data_dir(worker_dir).unwrap(),
        secret_bundle: sentinel_protocol::secrets::DeliveryBundle::empty(),
        caches: Vec::new(),
        cache_budget_bytes: sentinel_cache::gc::DEFAULT_BUDGET_BYTES,
        mirrors: None,
        prepare_hold: Duration::ZERO,
        network: sentinel_worker::podman::Network::None,
        runtime: isolation::runtime().unwrap_or_default(),
    }
}

fn run_attempt(worker_dir: &Path, job: &mut Job) -> (Verdict, AttemptSummary, Vec<CacheNote>) {
    let notes = Notes::default();
    let cancel: Arc<AtomicBool> = Arc::new(AtomicBool::new(false));
    let (verdict, summary) = attempt::run(
        worker_dir,
        job,
        &notes,
        Arc::new(NoOutput),
        &NoSink,
        &cancel,
    );
    (verdict, summary, notes.cache.lock().unwrap().clone())
}

#[test]
fn a_failing_publish_is_a_note_never_the_verdict() {
    if !enabled() {
        return;
    }
    let temp = tempfile::tempdir().unwrap();
    let repo_dir = temp.path().join("origin");
    let sha = make_repo(&repo_dir);
    let repo = RepoId::new();
    let worker_dir = temp.path().join("worker");

    let mut job = make_job(&worker_dir, &repo_dir, &sha, repo, Trust::Protected);
    let (verdict, summary, notes) = run_attempt(&worker_dir, &mut job);
    assert_eq!(verdict, Verdict::Passed);
    assert_eq!(summary.caches.len(), 1);
    assert_eq!(summary.caches[0].publish.as_deref(), Some("sealed"));
    assert!(matches!(notes[0].outcome, CacheOutcome::Sealed { .. }));
    let entry = entry_dir(&worker_dir, repo, Trust::Protected);

    fs::write(entry.join(scope::WRITING_NAME), b"not a directory").unwrap();

    let mut job = make_job(&worker_dir, &repo_dir, &sha, repo, Trust::Protected);
    let (verdict, summary, notes) = run_attempt(&worker_dir, &mut job);
    assert_eq!(
        verdict,
        Verdict::Passed,
        "a cache failure must never decide the verdict"
    );
    assert_eq!(summary.caches.len(), 1);
    let record = &summary.caches[0];
    assert_eq!(record.outcome, "hit", "the sabotaged lane is write-only");
    assert_eq!(record.publish.as_deref(), Some("failed"));
    assert!(matches!(notes[0].outcome, CacheOutcome::Failed(_)));
    assert!(
        summary
            .steps
            .iter()
            .all(|s| s.outcome == sentinel_protocol::summary::StepOutcome::Passed),
        "the steps ran and passed on restored bytes"
    );
}

#[test]
fn a_pull_request_attempt_never_touches_protected_state() {
    if !enabled() {
        return;
    }
    let temp = tempfile::tempdir().unwrap();
    let repo_dir = temp.path().join("origin");
    let sha = make_repo(&repo_dir);
    let repo = RepoId::new();
    let worker_dir = temp.path().join("worker");

    let mut job = make_job(&worker_dir, &repo_dir, &sha, repo, Trust::Protected);
    let (verdict, _, _) = run_attempt(&worker_dir, &mut job);
    assert_eq!(verdict, Verdict::Passed);
    let protected = entry_dir(&worker_dir, repo, Trust::Protected);
    let pr = entry_dir(&worker_dir, repo, Trust::PullRequest);
    let before = tree_snapshot(&protected);

    let mut job = make_job(&worker_dir, &repo_dir, &sha, repo, Trust::PullRequest);
    let (verdict, summary, notes) = run_attempt(&worker_dir, &mut job);
    assert_eq!(verdict, Verdict::Passed);
    assert_eq!(summary.caches[0].outcome, "absent");
    assert_eq!(summary.caches[0].publish.as_deref(), Some("sealed"));
    assert!(matches!(notes[0].outcome, CacheOutcome::Sealed { .. }));
    assert!(pr.is_dir(), "the PR publish sealed under its own scope");

    assert_eq!(tree_snapshot(&protected), before);
    assert!(pr.join(scope::CURRENT_NAME).exists());
}

#[test]
fn publish_runs_with_the_container_stopped() {
    if !enabled() {
        return;
    }
    struct Probe {
        worker: WorkerId,
        worker_dir: PathBuf,
        container_alive_at_publish: Mutex<Vec<bool>>,
    }
    impl Report for Probe {
        fn event(&self, _: AttemptId, _: Fence, _: Event) {}
        fn finish(&self, _: AttemptId, _: Fence, _: Event, _: Vec<u8>) {}
        fn cache_note(&self, attempt: AttemptId, _: CacheNote) {
            let alive = isolation::sandbox_exists(self.worker, &self.worker_dir, attempt);
            self.container_alive_at_publish.lock().unwrap().push(alive);
        }
    }
    let temp = tempfile::tempdir().unwrap();
    let repo_dir = temp.path().join("origin");
    let sha = make_repo(&repo_dir);
    let worker_dir = temp.path().join("worker");
    let mut job = make_job(
        &worker_dir,
        &repo_dir,
        &sha,
        RepoId::new(),
        Trust::Protected,
    );
    let yaml = PIPELINE.replace(
        "run: 'mkdir -p vendor && echo payload > vendor/lib'",
        "run: 'mkdir -p vendor && echo payload > vendor/lib && (while :; do date > vendor/churn; done) >/dev/null 2>&1 &'",
    );
    job.spec = RunSpec::new(job.spec.source.clone(), compile_str(&yaml).unwrap()).unwrap();
    let probe = Probe {
        worker: job.worker,
        worker_dir: worker_dir.clone(),
        container_alive_at_publish: Mutex::new(Vec::new()),
    };
    let cancel: Arc<AtomicBool> = Arc::new(AtomicBool::new(false));
    let (verdict, summary) = attempt::run(
        &worker_dir,
        &mut job,
        &probe,
        Arc::new(NoOutput),
        &NoSink,
        &cancel,
    );
    assert_eq!(verdict, Verdict::Passed);
    assert_eq!(summary.caches[0].publish.as_deref(), Some("sealed"));
    assert_eq!(
        *probe.container_alive_at_publish.lock().unwrap(),
        [false],
        "the {} must be gone before publication reads the views",
        isolation::name()
    );
}

fn tree_snapshot(dir: &Path) -> std::collections::BTreeMap<String, Vec<u8>> {
    let mut out = std::collections::BTreeMap::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in fs::read_dir(&d).unwrap() {
            let path = e.unwrap().path();
            let rel = path
                .strip_prefix(dir)
                .unwrap()
                .to_string_lossy()
                .into_owned();
            if path.is_dir() {
                stack.push(path);
            } else {
                out.insert(rel, fs::read(&path).unwrap());
            }
        }
    }
    out
}
