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
use sentinel_protocol::source::{Access, Binding, Credential as SourceCredential};
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
        None,
        "att_fallback",
        // Four seconds is well under the mirror's 120 s bound, so the fallback is what runs.
        Duration::from_secs(4),
    )
    .unwrap();
    assert_eq!(out.route, CheckoutRoute::MirrorFallback);
    let reason = out.fallback_reason.expect("the reason is on record");
    assert!(reason.contains("lock"), "{reason}");
    assert!(started.elapsed() < Duration::from_secs(15));
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
        None,
        "att_direct",
        Duration::from_secs(60),
    )
    .unwrap();
    assert_eq!(out.route, CheckoutRoute::Direct);
    assert_eq!(out.fallback_reason, None);
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
        None,
        "att_absent",
        Duration::from_secs(60),
    )
    .unwrap_err();
    // Falling back would only ask the remote the same question again.
    assert!(matches!(error, Error::Preparation(_)), "{error:?}");
    ws.destroy().unwrap();
}

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

/// A public HTTPS access to a local listener that never answers: any connection that reaches it is observable.
fn silent_access() -> (std::net::TcpListener, Access) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();
    let access = Access {
        binding: Binding {
            remote: format!("https://127.0.0.1:{port}/team/repo.git"),
            allowed_refs: vec!["refs/heads/main".into()],
            pipeline_path: ".sentinel.yml".into(),
            trust: String::new(),
        },
        version: 1,
        // The controller's wall clock says the access is live for a minute; only the monotonic expiry differs.
        expires_ms: sentinel_core::UnixMillis::now().0 + 60_000,
        credential: SourceCredential::Public,
    };
    (listener, access)
}

#[test]
fn an_expired_source_validity_refuses_the_mirrored_and_direct_routes_before_any_io() {
    let temp = tempfile::tempdir().unwrap();
    let mirrors = Mirrors::open(&temp.path().join("mirrors")).unwrap();
    let (listener, access) = silent_access();
    let source = PinnedSource::new(
        &access.binding.remote,
        &"a".repeat(40),
        Some("refs/heads/main"),
    )
    .unwrap();
    let expired = Some(Instant::now());
    for (name, mirrors) in [("mirrored", Some(&mirrors)), ("direct", None)] {
        let repo_id = RepoId::new();
        let ws = Workspace::create(temp.path(), AttemptId::new()).unwrap();
        let error = checkout::checkout_mirrored(
            ws.path(),
            mirrors,
            &repo_id,
            &source,
            Some(&access),
            expired,
            "att_expired",
            Duration::from_secs(60),
        )
        .unwrap_err();
        assert!(
            matches!(&error, Error::Preparation(what) if what == "source access expired"),
            "{name}: {error:?}"
        );
        assert!(!ws.path().join(".git").exists(), "{name}: no git state");
        assert!(
            !mirrors.is_some_and(|m| m.path(&repo_id).exists()),
            "{name}"
        );
        ws.destroy().unwrap();
    }
    let ws = Workspace::create(temp.path(), AttemptId::new()).unwrap();
    let error = checkout::through_mirror(
        ws.path(),
        &mirrors,
        &RepoId::new(),
        &source,
        Some(&access),
        expired,
        "att_expired_mirror",
        Duration::from_secs(60),
    )
    .unwrap_err();
    assert!(
        matches!(&error, Error::Preparation(what) if what == "source access expired"),
        "{error:?}"
    );
    ws.destroy().unwrap();
    assert!(
        matches!(
            listener.accept(),
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock
        ),
        "an expired access opened a connection"
    );
}

#[test]
fn the_remaining_validity_caps_the_mirror_attempt_and_its_fallback() {
    let temp = tempfile::tempdir().unwrap();
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
    let (listener, access) = silent_access();
    let source = PinnedSource::new(
        &access.binding.remote,
        &"a".repeat(40),
        Some("refs/heads/main"),
    )
    .unwrap();
    let ws = Workspace::create(temp.path(), AttemptId::new()).unwrap();
    let started = Instant::now();
    // The caller's budget is a minute; the access has four seconds left. The mirror lock is held, so the
    // fallback reaches the silent remote and must still stop with the access.
    let error = checkout::through_mirror(
        ws.path(),
        &mirrors,
        &repo_id,
        &source,
        Some(&access),
        Some(Instant::now() + Duration::from_secs(4)),
        "att_capped",
        Duration::from_secs(60),
    )
    .unwrap_err();
    assert!(
        started.elapsed() < Duration::from_secs(20),
        "{error:?} after {:?}",
        started.elapsed()
    );
    assert!(
        listener.accept().is_ok(),
        "the fallback never reached the remote"
    );
    drop(lock);
    ws.destroy().unwrap();
}
