//! The reordered-push rule's Git question — is this revision already in the
//! tip's history? — answered over a real remote with only commits fetched,
//! and the transport discipline for fetches that carry no source access.
#![cfg(unix)]

use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};

use sentinel_git::{Error, checkout, file_at, is_ancestor, ls_remote};
use sentinel_pipeline::PinnedSource;

fn git(dir: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .args(args)
        .current_dir(dir)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_AUTHOR_NAME", "t")
        .env("GIT_AUTHOR_EMAIL", "t@example.com")
        .env("GIT_COMMITTER_NAME", "t")
        .env("GIT_COMMITTER_EMAIL", "t@example.com")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}

/// A linear history `commits[0] → … → commits[4]` on main, plus a side
/// branch off `commits[1]` that main never merged.
struct Repo {
    dir: tempfile::TempDir,
    path: PathBuf,
    commits: Vec<String>,
    side: String,
}

fn repository() -> Repo {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("origin");
    fs::create_dir(&path).unwrap();
    git(&path, &["init", "-q", "--initial-branch=main"]);
    git(&path, &["config", "uploadpack.allowFilter", "true"]);
    let mut commits = Vec::new();
    for n in 0..5 {
        fs::write(path.join("file.txt"), format!("{n}\n")).unwrap();
        git(&path, &["add", "."]);
        git(&path, &["commit", "-qm", &n.to_string()]);
        commits.push(git(&path, &["rev-parse", "HEAD"]));
    }
    git(&path, &["checkout", "-qb", "side", &commits[1]]);
    fs::write(path.join("side.txt"), "side\n").unwrap();
    git(&path, &["add", "."]);
    git(&path, &["commit", "-qm", "side"]);
    let side = git(&path, &["rev-parse", "HEAD"]);
    git(&path, &["checkout", "-q", "main"]);
    Repo {
        dir,
        path,
        commits,
        side,
    }
}

fn work(repo: &Repo, name: &str) -> PathBuf {
    let dir = repo.dir.path().join(format!("work-{name}"));
    fs::create_dir(&dir).unwrap();
    dir
}

fn ancestor(repo: &Repo, name: &str, ancestor: &str, tip: &str, depth: u32) -> bool {
    is_ancestor(
        &work(repo, name),
        repo.path.to_str().unwrap(),
        None,
        ancestor,
        tip,
        depth,
        Duration::from_secs(30),
    )
    .unwrap()
}

#[test]
fn an_older_commit_is_in_the_tip_history_and_a_newer_or_unrelated_one_is_not() {
    let repo = repository();
    let c = &repo.commits;
    assert!(ancestor(&repo, "older", &c[1], &c[4], 64));
    assert!(ancestor(&repo, "same", &c[4], &c[4], 64));
    // The other direction: the tip is not in an older commit's history.
    assert!(!ancestor(&repo, "newer", &c[4], &c[1], 64));
    // A branch that main never merged is not stale relative to main.
    assert!(!ancestor(&repo, "side", &repo.side, &c[4], 64));
    // Beyond the window nothing is proven: the answer stays conservative.
    assert!(!ancestor(&repo, "window", &c[0], &c[4], 2));
    assert!(ancestor(&repo, "edge", &c[2], &c[4], 3));
}

#[test]
fn a_tip_the_remote_no_longer_has_proves_nothing_and_an_unreachable_remote_is_an_error() {
    let repo = repository();
    // Force-pushed away (or never there): not an error, just not proven.
    assert!(!ancestor(
        &repo,
        "gone",
        &repo.commits[1],
        &"1".repeat(40),
        64
    ));
    let missing = repo.dir.path().join("missing.git");
    let outcome = is_ancestor(
        &work(&repo, "unreachable"),
        missing.to_str().unwrap(),
        None,
        &repo.commits[1],
        &repo.commits[4],
        64,
        Duration::from_secs(30),
    );
    assert!(matches!(outcome, Err(Error::Preparation(_))), "{outcome:?}");
    // Malformed requests never reach Git.
    let outcome = is_ancestor(
        &work(&repo, "malformed"),
        repo.path.to_str().unwrap(),
        None,
        "HEAD",
        &repo.commits[4],
        64,
        Duration::from_secs(30),
    );
    assert!(matches!(outcome, Err(Error::Preparation(_))), "{outcome:?}");
}

/// A fetch with no source access is a remote a client named: it never uses
/// `ssh` (the worker account's own identity and configuration), `git://`,
/// plain `http://` or a remote helper, and it never follows redirects.
#[test]
fn an_unauthenticated_fetch_refuses_ambient_credential_and_plaintext_transports() {
    let repo = repository();
    let sha = &repo.commits[4];
    for (n, remote) in [
        "ssh://git@127.0.0.1:9/origin.git",
        "git://127.0.0.1:9/origin.git",
        "http://127.0.0.1:9/origin.git",
    ]
    .into_iter()
    .enumerate()
    {
        let outcome = file_at(
            &work(&repo, &format!("file-{n}")),
            remote,
            None,
            sha,
            "file.txt",
            1024,
            Duration::from_secs(30),
        );
        let Err(Error::Preparation(why)) = outcome else {
            panic!("{remote}: {outcome:?}");
        };
        assert!(why.contains("not allowed"), "{remote}: {why}");
        let source = PinnedSource::new(remote, sha, None).unwrap();
        let outcome = checkout(
            &work(&repo, &format!("checkout-{n}")),
            &source,
            None,
            Duration::from_secs(30),
        );
        let Err(Error::Preparation(why)) = outcome else {
            panic!("{remote}: {outcome:?}");
        };
        assert!(why.contains("not allowed"), "{remote}: {why}");
        let outcome = ls_remote(
            &work(&repo, &format!("list-{n}")),
            remote,
            None,
            16,
            Duration::from_secs(30),
        );
        let Err(Error::Preparation(why)) = outcome else {
            panic!("{remote}: {outcome:?}");
        };
        assert!(why.contains("not allowed"), "{remote}: {why}");
    }
    // A local path still works unauthenticated (worker-local mirrors and
    // tests); the controller refuses one as a client-named manual source.
    let fetched = file_at(
        &work(&repo, "local"),
        repo.path.to_str().unwrap(),
        None,
        sha,
        "file.txt",
        1024,
        Duration::from_secs(30),
    )
    .unwrap();
    assert_eq!(fetched.bytes, b"4\n");
}
