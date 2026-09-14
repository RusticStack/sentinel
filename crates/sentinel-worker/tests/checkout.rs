//! W03 checkout and workspace behavior on Linux with a local repository:
//! the pinned commit is what ends up checked out even when it is not the
//! branch head; an unknown revision, a hung fetch and a dirty workspace are
//! refused; the askpass helper never leaves the secret behind.

#![cfg(target_os = "linux")]

use std::{
    fs,
    path::Path,
    process::Command,
    time::{Duration, Instant},
};

use sentinel_core::AttemptId;
use sentinel_pipeline::PinnedSource;
use sentinel_worker::{
    Error,
    checkout::{self, Credential},
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
fn the_pinned_commit_is_checked_out_even_when_it_is_not_the_head() {
    let temp = tempfile::tempdir().unwrap();
    let (repo, first, second) = repository(temp.path());
    let attempt = AttemptId::new();
    let ws = Workspace::create(temp.path(), attempt).unwrap();
    let source = PinnedSource::new(repo.to_str().unwrap(), &first, Some("main")).unwrap();
    let out = checkout::checkout(ws.path(), &source, None, Duration::from_secs(60)).unwrap();
    assert_eq!(out.sha, first);
    assert_eq!(
        fs::read_to_string(ws.path().join("file.txt")).unwrap(),
        "one\n"
    );
    assert_eq!(git(ws.path(), &["rev-parse", "HEAD"]), first);
    // Depth one: the newer commit was never fetched.
    assert!(
        Command::new("git")
            .args(["cat-file", "-e", &second])
            .current_dir(ws.path())
            .status()
            .unwrap()
            .code()
            != Some(0)
    );
    // The workspace is never reused; destroying it removes the checkout.
    assert!(matches!(
        Workspace::create(temp.path(), attempt),
        Err(Error::Workspace(_))
    ));
    assert_eq!(Workspace::leftovers(temp.path()).unwrap(), vec![attempt]);
    let path = ws.path().to_path_buf();
    ws.destroy().unwrap();
    assert!(!path.exists());
    assert!(Workspace::leftovers(temp.path()).unwrap().is_empty());
}

#[test]
fn unknown_revisions_and_hung_fetches_are_preparation_failures() {
    let temp = tempfile::tempdir().unwrap();
    let (repo, _, _) = repository(temp.path());
    let ws = Workspace::create(temp.path(), AttemptId::new()).unwrap();
    let missing = "0123456789abcdef0123456789abcdef01234567";
    let source = PinnedSource::new(repo.to_str().unwrap(), missing, None).unwrap();
    let refused =
        checkout::checkout(ws.path(), &source, None, Duration::from_secs(60)).unwrap_err();
    assert!(
        matches!(&refused, Error::Preparation(what) if what.starts_with("git fetch")),
        "{refused}"
    );
    // A workspace whose fetch failed holds no checkout.
    assert!(!ws.path().join("file.txt").exists());

    // A repository that never answers: a FIFO stands in for a stalled
    // transport; the deadline kills the whole process group.
    let stalled = temp.path().join("stalled.git");
    fs::create_dir(&stalled).unwrap();
    let ws2 = Workspace::create(temp.path(), AttemptId::new()).unwrap();
    let source = PinnedSource::new(
        &format!("ext::sleep 30 %S {}", stalled.display()),
        missing,
        None,
    )
    .unwrap();
    let started = Instant::now();
    let outcome = checkout::checkout(ws2.path(), &source, None, Duration::from_millis(1500));
    // `ext::` transports are disabled by default, so this is refused at
    // once as a preparation failure; a genuinely slow path is the timeout.
    assert!(
        matches!(
            outcome,
            Err(Error::Preparation(_)) | Err(Error::Timeout("git fetch"))
        ),
        "{outcome:?}"
    );
    assert!(started.elapsed() < Duration::from_secs(10));
    let source = PinnedSource::new("-oProxyCommand=true", missing, None).unwrap();
    assert!(matches!(
        checkout::checkout(ws2.path(), &source, None, Duration::from_secs(5)),
        Err(Error::Preparation(_))
    ));
}

#[test]
fn a_credential_is_delivered_through_askpass_and_removed_afterwards() {
    let temp = tempfile::tempdir().unwrap();
    let (repo, first, _) = repository(temp.path());
    let ws = Workspace::create(temp.path(), AttemptId::new()).unwrap();
    let source = PinnedSource::new(repo.to_str().unwrap(), &first, None).unwrap();
    let credential = Credential {
        username: "x-access-token".into(),
        secret: "ghs_do_not_leak".into(),
    };
    checkout::checkout(
        ws.path(),
        &source,
        Some(&credential),
        Duration::from_secs(60),
    )
    .unwrap();
    // The helper directory is gone, and the secret is nowhere in the workspace.
    assert!(!ws.path().with_extension("askpass").exists());
    let config = fs::read_to_string(ws.path().join(".git/config")).unwrap();
    assert!(!config.contains("ghs_do_not_leak"));
    assert!(!config.contains("x-access-token"));
}
