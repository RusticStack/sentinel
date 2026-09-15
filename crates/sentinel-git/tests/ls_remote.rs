//! G07 ref discovery over a real remote: `git ls-remote` advertises heads
//! and tags, annotated tags arrive with their peeled commit, and the result
//! and its budgets are bounded.
#![cfg(unix)]

use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};

use sentinel_git::{Error, ls_remote};

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

struct Repo {
    _dir: tempfile::TempDir,
    path: PathBuf,
    work: tempfile::TempDir,
    main: String,
    tag_object: String,
    tag_commit: String,
}

fn repository() -> Repo {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("origin");
    fs::create_dir(&path).unwrap();
    git(&path, &["init", "-q", "--initial-branch=main"]);
    fs::write(path.join("file"), "one").unwrap();
    git(&path, &["add", "."]);
    git(&path, &["commit", "-qm", "one"]);
    let main = git(&path, &["rev-parse", "HEAD"]);
    git(&path, &["tag", "-a", "v1", "-m", "release one"]);
    git(&path, &["tag", "light"]);
    let tag_object = git(&path, &["rev-parse", "refs/tags/v1"]);
    let tag_commit = git(&path, &["rev-parse", "refs/tags/v1^{commit}"]);
    Repo {
        work: tempfile::tempdir().unwrap(),
        _dir: dir,
        path,
        main,
        tag_object,
        tag_commit,
    }
}

#[test]
fn heads_and_tags_are_advertised_with_annotated_peels() {
    let repo = repository();
    let remote = repo.path.to_str().unwrap();
    let tips = ls_remote(repo.work.path(), remote, None, 64, Duration::from_secs(30)).unwrap();
    let by_name = |name: &str| tips.iter().find(|t| t.name == name);
    assert_eq!(by_name("refs/heads/main").unwrap().oid, repo.main);
    // The annotated tag's ref names its tag object; the commit it peels to
    // arrives alongside.
    let v1 = by_name("refs/tags/v1").unwrap();
    assert_eq!(v1.oid, repo.tag_object);
    assert_eq!(v1.peeled.as_deref(), Some(repo.tag_commit.as_str()));
    // A lightweight tag has nothing to peel.
    assert_eq!(by_name("refs/tags/light").unwrap().peeled, None);
    // HEAD is not a head or tag advertisement.
    assert!(tips.iter().all(|t| t.name != "HEAD"));
}

#[test]
fn advertisement_budgets_and_failures_are_explicit() {
    let repo = repository();
    let remote = repo.path.to_str().unwrap();
    // More refs than the cap is a bounded refusal, not a truncation.
    assert!(matches!(
        ls_remote(repo.work.path(), remote, None, 1, Duration::from_secs(30)),
        Err(Error::TooLarge("git ls-remote"))
    ));
    // A remote that is not a repository is a preparation failure.
    assert!(matches!(
        ls_remote(
            repo.work.path(),
            repo.work.path().to_str().unwrap(),
            None,
            64,
            Duration::from_secs(30)
        ),
        Err(Error::Preparation(_))
    ));
    // An option-shaped remote never reaches the process.
    assert!(matches!(
        ls_remote(
            repo.work.path(),
            "--upload-pack=x",
            None,
            64,
            Duration::from_secs(1)
        ),
        Err(Error::Preparation(_))
    ));
    // An unresolvable remote inside a tiny budget fails within it.
    let started = std::time::Instant::now();
    let _ = ls_remote(
        repo.work.path(),
        "https://192.0.2.1:1/x.git",
        None,
        64,
        Duration::from_millis(500),
    );
    assert!(started.elapsed() < Duration::from_secs(10));
}
