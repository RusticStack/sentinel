//! K04 checkout routing on Linux: with a mirrors handle the checkout goes
//! through the repository's local mirror and says so; a mirror that cannot
//! serve falls back to the direct fetch with the reason on record; the
//! remote's own answer never retries.
#![cfg(target_os = "linux")]

use std::{
    fs,
    os::fd::AsRawFd,
    path::Path,
    process::Command,
    time::{Duration, Instant},
};

use sentinel_core::{AttemptId, RepoId};
use sentinel_pipeline::PinnedSource;
use sentinel_protocol::summary::CheckoutRoute;
use sentinel_worker::{
    Error,
    checkout::{self, Mirrors},
    workspace::Workspace,
};

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
    assert!(
        output.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}

/// A repository with two commits; returns (path, first sha, second sha).
fn repository(root: &Path) -> (std::path::PathBuf, String, String) {
    let repo = root.join("origin");
    fs::create_dir(&repo).unwrap();
    git(&repo, &["init", "-q", "--initial-branch=main"]);
    fs::write(repo.join("file.txt"), "one\n").unwrap();
    git(&repo, &["add", "."]);
    git(&repo, &["commit", "-q", "-m", "one"]);
    let first = git(&repo, &["rev-parse", "HEAD"]);
    fs::write(repo.join("file.txt"), "two\n").unwrap();
    git(&repo, &["commit", "-q", "-am", "two"]);
    let second = git(&repo, &["rev-parse", "HEAD"]);
    (repo, first, second)
}

#[test]
fn a_mirrored_checkout_reports_its_route_and_separate_phases() {
    let temp = tempfile::tempdir().unwrap();
    let (repo, first, _) = repository(temp.path());
    let mirrors = Mirrors::open(&temp.path().join("mirrors")).unwrap();
    let repo_id = RepoId::new();
    let ws = Workspace::create(temp.path(), AttemptId::new()).unwrap();
    let source =
        PinnedSource::new(repo.to_str().unwrap(), &first, Some("refs/heads/main")).unwrap();
    let out = checkout::through_mirror(
        ws.path(),
        &mirrors,
        &repo_id,
        &source,
        None,
        "att_route",
        Duration::from_secs(60),
    )
    .unwrap();
    assert_eq!(out.route, CheckoutRoute::Mirror);
    assert_eq!(out.fallback_reason, None);
    assert_eq!(out.checkout.sha, first);
    assert!(out.checkout.fetch_ns > 0);
    assert!(out.checkout.materialize_ns > 0);
    assert_eq!(git(ws.path(), &["rev-parse", "HEAD"]), first);
    assert_eq!(
        fs::read_to_string(ws.path().join("file.txt")).unwrap(),
        "one\n"
    );
    ws.destroy().unwrap();
}

#[test]
fn a_mirror_that_cannot_serve_falls_back_with_the_reason_on_record() {
    let temp = tempfile::tempdir().unwrap();
    let (repo, first, _) = repository(temp.path());
    let mirrors = Mirrors::open(&temp.path().join("mirrors")).unwrap();
    let repo_id = RepoId::new();
    // A held writer lock is a mirror that cannot serve inside its bound:
    // the attempt must still get its workspace, by the direct route, with
    // the reason recorded — not silently, and not after hanging.
    let lock_path = temp.path().join(format!("mirrors/{repo_id}.lock"));
    let lock = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)
        .unwrap();
    // SAFETY: flock on the test's own fd, released when `lock` closes.
    assert_eq!(
        unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
        0
    );
    let ws = Workspace::create(temp.path(), AttemptId::new()).unwrap();
    let source = PinnedSource::new(repo.to_str().unwrap(), &first, None).unwrap();
    let started = Instant::now();
    let out = checkout::through_mirror(
        ws.path(),
        &mirrors,
        &repo_id,
        &source,
        None,
        "att_fallback",
        // The lock wait is bounded by the smaller of the mirror bound and
        // this timeout: four seconds is far under the 120 s bound, so the
        // fallback path is what the test actually exercises.
        Duration::from_secs(4),
    )
    .unwrap();
    assert_eq!(out.route, CheckoutRoute::MirrorFallback);
    let reason = out.fallback_reason.expect("the reason is on record");
    assert!(reason.contains("lock"), "{reason}");
    assert!(started.elapsed() < Duration::from_secs(15));
    // The direct fetch produced a truthful checkout anyway.
    assert_eq!(out.checkout.sha, first);
    assert_eq!(
        fs::read_to_string(ws.path().join("file.txt")).unwrap(),
        "one\n"
    );
    drop(lock);
    ws.destroy().unwrap();
}

#[test]
fn without_a_mirror_the_route_is_direct_and_honest() {
    let temp = tempfile::tempdir().unwrap();
    let (repo, first, _) = repository(temp.path());
    let ws = Workspace::create(temp.path(), AttemptId::new()).unwrap();
    let source = PinnedSource::new(repo.to_str().unwrap(), &first, None).unwrap();
    let out = checkout::checkout_mirrored(
        ws.path(),
        None,
        &RepoId::new(),
        &source,
        None,
        "att_direct",
        Duration::from_secs(60),
    )
    .unwrap();
    assert_eq!(out.route, CheckoutRoute::Direct);
    assert_eq!(out.fallback_reason, None);
    // The direct path measures its own fetch; materialization is measured
    // too, so nothing is claimed absent when it was in fact measured.
    assert!(out.checkout.fetch_ns > 0);
    assert!(out.checkout.materialize_ns > 0);
    assert_eq!(out.checkout.sha, first);
    ws.destroy().unwrap();
}

#[test]
fn an_absent_commit_is_a_preparation_failure_not_a_fallback() {
    let temp = tempfile::tempdir().unwrap();
    let (repo, _, _) = repository(temp.path());
    let mirrors = Mirrors::open(&temp.path().join("mirrors")).unwrap();
    let ws = Workspace::create(temp.path(), AttemptId::new()).unwrap();
    let missing = "0123456789abcdef0123456789abcdef01234567";
    let source = PinnedSource::new(repo.to_str().unwrap(), missing, None).unwrap();
    let error = checkout::through_mirror(
        ws.path(),
        &mirrors,
        &RepoId::new(),
        &source,
        None,
        "att_absent",
        Duration::from_secs(60),
    )
    .unwrap_err();
    // The remote's answer propagates as the preparation failure it is;
    // falling back would only re-ask the same question.
    assert!(matches!(error, Error::Preparation(_)), "{error:?}");
    ws.destroy().unwrap();
}

/// P07-17: a manual run names its own remote — here a local path, which
/// could as well be another repository's mirror — so it never goes through
/// (or fills) a mirror: the route is direct and no store is created.
#[test]
fn a_manual_run_never_reads_or_feeds_a_mirror() {
    let temp = tempfile::tempdir().unwrap();
    let (repo, first, _) = repository(temp.path());
    let mirrors = Mirrors::open(&temp.path().join("mirrors")).unwrap();
    let repo_id = RepoId::new();
    let ws = Workspace::create(temp.path(), AttemptId::new()).unwrap();
    let source = PinnedSource::new(repo.to_str().unwrap(), &first, None).unwrap();
    let out = checkout::checkout_mirrored(
        ws.path(),
        Some(&mirrors),
        &repo_id,
        &source,
        None,
        "att_manual",
        Duration::from_secs(60),
    )
    .unwrap();
    assert_eq!(out.route, CheckoutRoute::Direct);
    assert!(!mirrors.path(&repo_id).exists(), "no mirror was built");
    assert_eq!(out.checkout.sha, first);
    ws.destroy().unwrap();
}

/// P07-18: when the mirror cannot serve, the direct fallback runs within
/// what is left of the one deadline — never a fresh one.
#[test]
fn a_fallback_spends_the_remaining_deadline_not_a_new_one() {
    let temp = tempfile::tempdir().unwrap();
    let (repo, first, _) = repository(temp.path());
    let mirrors = Mirrors::open(&temp.path().join("mirrors")).unwrap();
    let repo_id = RepoId::new();
    let lock = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(temp.path().join(format!("mirrors/{repo_id}.lock")))
        .unwrap();
    // SAFETY: flock on the test's own fd, released when `lock` closes.
    assert_eq!(
        unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
        0
    );
    let ws = Workspace::create(temp.path(), AttemptId::new()).unwrap();
    let source = PinnedSource::new(repo.to_str().unwrap(), &first, None).unwrap();
    let started = Instant::now();
    let out = checkout::through_mirror(
        ws.path(),
        &mirrors,
        &repo_id,
        &source,
        None,
        "att_budget",
        Duration::from_secs(6),
    )
    .unwrap();
    assert_eq!(out.route, CheckoutRoute::MirrorFallback);
    assert!(
        started.elapsed() < Duration::from_secs(6),
        "lock wait plus fallback stayed inside the one 6 s deadline: {:?}",
        started.elapsed()
    );
    drop(lock);
    ws.destroy().unwrap();
}
