//! G03 source resolution over a local repository: read one file at one
//! revision, peel annotated tags to their commit, and refuse unsafe paths,
//! oversized files and inconsistent access.
#![cfg(unix)]

use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};

use sentinel_git::{Error, Merge, file_at, file_at_merge};
use sentinel_protocol::source::{Access, Binding, Credential};

struct Repo {
    dir: tempfile::TempDir,
    path: PathBuf,
    first: String,
    second: String,
    tag_object: String,
    tag_commit: String,
    big: String,
}

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

fn repository() -> Repo {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("origin");
    fs::create_dir(&path).unwrap();
    git(&path, &["init", "-q", "--initial-branch=main"]);
    fs::write(path.join(".sentinel.yml"), "schema: 1 # first\n").unwrap();
    git(&path, &["add", "."]);
    git(&path, &["commit", "-qm", "one"]);
    let first = git(&path, &["rev-parse", "HEAD"]);
    git(&path, &["tag", "-a", "v1", "-m", "release one"]);
    let tag_object = git(&path, &["rev-parse", "refs/tags/v1"]);
    let tag_commit = git(&path, &["rev-parse", "refs/tags/v1^{commit}"]);
    fs::write(path.join(".sentinel.yml"), "schema: 1 # second\n").unwrap();
    git(&path, &["commit", "-qam", "two"]);
    let second = git(&path, &["rev-parse", "HEAD"]);
    // A file far larger than any pipeline may be.
    fs::write(path.join("big.yml"), vec![b'x'; 2 * 1024 * 1024]).unwrap();
    git(&path, &["add", "big.yml"]);
    git(&path, &["commit", "-qm", "big"]);
    let big = git(&path, &["rev-parse", "HEAD"]);
    Repo {
        dir,
        path,
        first,
        second,
        tag_object,
        tag_commit,
        big,
    }
}

fn work(repo: &Repo, name: &str) -> PathBuf {
    let dir = repo.dir.path().join(format!("work-{name}"));
    fs::create_dir(&dir).unwrap();
    dir
}

#[test]
fn a_file_is_read_at_the_exact_revision_and_tags_are_peeled() {
    let repo = repository();
    let remote = repo.path.to_str().unwrap();

    // The revision asked for is the one read, not the branch head.
    let fetched = file_at(
        &work(&repo, "second"),
        remote,
        None,
        &repo.second,
        ".sentinel.yml",
        64 * 1024,
        Duration::from_secs(30),
    )
    .unwrap();
    assert_eq!(fetched.commit, repo.second);
    assert_eq!(fetched.bytes, b"schema: 1 # second\n");
    assert_ne!(repo.first, repo.second, "the commits differ");

    let fetched = file_at(
        &work(&repo, "first"),
        remote,
        None,
        &repo.first,
        ".sentinel.yml",
        64 * 1024,
        Duration::from_secs(30),
    )
    .unwrap();
    assert_eq!(fetched.commit, repo.first);
    assert_eq!(fetched.bytes, b"schema: 1 # first\n");

    // An annotated tag object resolves to the commit it points at.
    let fetched = file_at(
        &work(&repo, "tag"),
        remote,
        None,
        &repo.tag_object,
        ".sentinel.yml",
        64 * 1024,
        Duration::from_secs(30),
    )
    .unwrap();
    assert_eq!(fetched.commit, repo.tag_commit);
    assert_eq!(fetched.bytes, b"schema: 1 # first\n");
}

#[test]
fn missing_oversized_and_unsafe_inputs_are_refused_explicitly() {
    let repo = repository();
    let remote = repo.path.to_str().unwrap();
    let timeout = Duration::from_secs(30);

    // A path that is not in the revision.
    assert!(matches!(
        file_at(
            &work(&repo, "missing"),
            remote,
            None,
            &repo.second,
            "ci/.sentinel.yml",
            4096,
            timeout
        ),
        Err(Error::Missing)
    ));
    // A file larger than the caller allows is refused without being read.
    assert!(matches!(
        file_at(
            &work(&repo, "big"),
            remote,
            None,
            &repo.big,
            "big.yml",
            4096,
            timeout
        ),
        Err(Error::TooLarge(_))
    ));
    // Unsafe paths never reach Git.
    for (index, path) in [
        "",
        "/etc/passwd",
        "../secret",
        "a/../../b",
        "a//b",
        "x:y",
        "a/./b",
    ]
    .into_iter()
    .enumerate()
    {
        assert!(
            matches!(
                file_at(
                    &work(&repo, &format!("path-{index}")),
                    remote,
                    None,
                    &repo.second,
                    path,
                    4096,
                    timeout
                ),
                Err(Error::Preparation(_))
            ),
            "{path:?}"
        );
    }
    // A revision that is not a full object id, and a repository that looks
    // like an option, are preparation failures.
    assert!(matches!(
        file_at(
            &work(&repo, "sha"),
            remote,
            None,
            "main",
            ".sentinel.yml",
            4096,
            timeout
        ),
        Err(Error::Preparation(_))
    ));
    assert!(matches!(
        file_at(
            &work(&repo, "remote"),
            "-oProxyCommand=true",
            None,
            &repo.second,
            ".sentinel.yml",
            4096,
            timeout
        ),
        Err(Error::Preparation(_))
    ));
}

#[test]
fn a_merge_ref_is_read_only_when_it_names_the_delivered_head() {
    let repo = repository();
    let remote = repo.path.to_str().unwrap();
    let timeout = Duration::from_secs(30);
    // A pull-request merge ref: a head commit on a branch merged into main.
    git(&repo.path, &["checkout", "-qb", "feature", &repo.second]);
    fs::write(repo.path.join("feature.txt"), "the head's change\n").unwrap();
    git(&repo.path, &["add", "feature.txt"]);
    git(&repo.path, &["commit", "-qm", "head"]);
    let head = git(&repo.path, &["rev-parse", "HEAD"]);
    git(&repo.path, &["checkout", "-q", "main"]);
    git(
        &repo.path,
        &["merge", "-q", "--no-ff", "-m", "test merge", "feature"],
    );
    let merge = git(&repo.path, &["rev-parse", "HEAD"]);
    git(&repo.path, &["update-ref", "refs/pull/7/merge", &merge]);

    // The merge's own file contents are served, at the merge commit.
    let fetched = file_at_merge(
        &work(&repo, "merge"),
        remote,
        None,
        Merge {
            r#ref: "refs/pull/7/merge",
            head: &head,
        },
        "feature.txt",
        64 * 1024,
        timeout,
    )
    .unwrap();
    assert_eq!(fetched.commit, merge);
    assert_eq!(fetched.bytes, b"the head's change\n");

    // A merge ref that does not name the delivered head is not trusted — it
    // may still name a merge the forge computed for an older head.
    assert!(matches!(
        file_at_merge(
            &work(&repo, "stale"),
            remote,
            None,
            Merge {
                r#ref: "refs/pull/7/merge",
                head: &repo.second,
            },
            ".sentinel.yml",
            64 * 1024,
            timeout,
        ),
        Err(Error::Merge)
    ));
    // A ref that does not exist at all is the same class: not computed yet.
    assert!(matches!(
        file_at_merge(
            &work(&repo, "absent"),
            remote,
            None,
            Merge {
                r#ref: "refs/pull/9/merge",
                head: &head,
            },
            ".sentinel.yml",
            64 * 1024,
            timeout,
        ),
        Err(Error::Merge)
    ));
    // Inputs that are not a ref under refs/ and a full head id never reach Git.
    for (index, (merge_ref, head_sha)) in [("pull/7/merge", &*head), ("refs/pull/7/merge", "main")]
        .into_iter()
        .enumerate()
    {
        assert!(matches!(
            file_at_merge(
                &work(&repo, &format!("unsafe-{index}")),
                remote,
                None,
                Merge {
                    r#ref: merge_ref,
                    head: head_sha,
                },
                ".sentinel.yml",
                64 * 1024,
                timeout,
            ),
            Err(Error::Preparation(_))
        ));
    }
}

#[test]
fn a_source_access_must_match_the_remote_it_is_used_for() {
    let repo = repository();
    let remote = repo.path.to_str().unwrap();
    let mut access = Access {
        binding: Binding {
            remote: "https://git.example:8443/team/repo.git".into(),
            allowed_refs: vec!["refs/heads/main".into()],
            pipeline_path: ".sentinel.yml".into(),
            trust: String::new(),
        },
        version: 1,
        expires_ms: sentinel_core::UnixMillis::now().0 + 60_000,
        credential: Credential::Public,
    };
    assert!(matches!(
        file_at(
            &work(&repo, "access"),
            remote,
            Some(&access),
            &repo.second,
            ".sentinel.yml",
            4096,
            Duration::from_secs(30)
        ),
        Err(Error::Preparation(_))
    ));
    // Even with a matching remote, an expired access is refused.
    access.binding.remote = remote.to_owned();
    access.expires_ms = sentinel_core::UnixMillis::now().0 - 1;
    assert!(matches!(
        file_at(
            &work(&repo, "expired"),
            remote,
            Some(&access),
            &repo.second,
            ".sentinel.yml",
            4096,
            Duration::from_secs(30)
        ),
        Err(Error::Preparation(_))
    ));
}

/// B04: a server that honours partial-clone filters sends the commit, its
/// trees and the one blob the pipeline is — never the rest of the tree.
#[test]
fn a_filtering_server_sends_only_the_pipeline_blob() {
    let repo = repository();
    git(&repo.path, &["config", "uploadpack.allowFilter", "true"]);
    git(
        &repo.path,
        &["config", "uploadpack.allowAnySHA1InWant", "true"],
    );
    let big_blob = git(&repo.path, &["rev-parse", &format!("{}:big.yml", repo.big)]);
    let dir = work(&repo, "filtered");
    let fetched = file_at(
        &dir,
        repo.path.to_str().unwrap(),
        None,
        &repo.big,
        ".sentinel.yml",
        64 * 1024,
        Duration::from_secs(30),
    )
    .unwrap();
    assert_eq!(fetched.commit, repo.big);
    assert_eq!(fetched.bytes, b"schema: 1 # second\n");
    let absent = Command::new("git")
        .args(["cat-file", "-e", &big_blob])
        .current_dir(&dir)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        // The work repository is a partial clone: asking must not fetch.
        .env("GIT_NO_LAZY_FETCH", "1")
        .status()
        .unwrap();
    assert!(!absent.success(), "the 2 MiB blob was never fetched");
}
