//! Helpers shared by the mirror suites: throwaway `file://` origins and
//! workspaces.
#![allow(dead_code)] // each suite uses its own subset

use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use sentinel_pipeline::PinnedSource;

pub fn git(dir: &Path, args: &[&str]) -> String {
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
        "git {args:?} in {}: {}",
        dir.display(),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}

/// `git` in `dir` that may legitimately fail — for `cat-file -e` probes.
pub fn git_ok(dir: &Path, args: &[&str]) -> bool {
    Command::new("git")
        .args(args)
        .current_dir(dir)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .output()
        .unwrap()
        .status
        .success()
}

pub struct Repo {
    _dir: tempfile::TempDir,
    pub path: PathBuf,
    pub first: String,
    pub second: String,
}

/// Two commits on `main`, one file that changes between them.
pub fn repository(root: &Path) -> Repo {
    let dir = tempfile::tempdir_in(root).unwrap();
    let path = dir.path().join("origin");
    fs::create_dir(&path).unwrap();
    git(&path, &["init", "-q", "--initial-branch=main"]);
    fs::write(path.join("file.txt"), "one\n").unwrap();
    git(&path, &["add", "."]);
    git(&path, &["commit", "-qm", "one"]);
    let first = git(&path, &["rev-parse", "HEAD"]);
    fs::write(path.join("file.txt"), "two\n").unwrap();
    git(&path, &["commit", "-qam", "two"]);
    let second = git(&path, &["rev-parse", "HEAD"]);
    Repo {
        _dir: dir,
        path,
        first,
        second,
    }
}

pub fn source(repo: &Repo, sha: &str, ref_name: Option<&str>) -> PinnedSource {
    PinnedSource::new(repo.path.to_str().unwrap(), sha, ref_name).unwrap()
}

pub fn work(root: &Path, name: &str) -> PathBuf {
    let dir = root.join(format!("ws-{name}"));
    fs::create_dir(&dir).unwrap();
    dir
}
