//! K04 worker-local Git mirrors over local `file://` repositories: the
//! pinned commit is what lands in the workspace, fetches serialize and stay
//! incremental, a reader lease holds GC off, a job cannot mutate shared
//! objects, and a damaged mirror is rebuilt rather than served.
#![cfg(unix)]

use std::{
    collections::BTreeMap,
    fs,
    io::Read,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Command,
    thread,
    time::{Duration, Instant},
};

use sentinel_core::RepoId;
use sentinel_git::{Error, mirror::Mirrors};
use sentinel_pipeline::PinnedSource;
use sentinel_protocol::source::{Access, Binding};

mod support;
use support::{git, git_ok, repository, source, work};

/// path → content hash for every regular file under `dir`.
fn manifest(dir: &Path) -> BTreeMap<PathBuf, u64> {
    let mut out = BTreeMap::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for entry in fs::read_dir(&d).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            if entry.file_type().unwrap().is_dir() {
                stack.push(path);
            } else if entry.file_type().unwrap().is_file() {
                let mut file = fs::File::open(&path).unwrap();
                let mut hash = 0xcbf29ce484222325u64;
                let mut chunk = [0u8; 8192];
                loop {
                    let n = file.read(&mut chunk).unwrap();
                    if n == 0 {
                        break;
                    }
                    for &b in &chunk[..n] {
                        hash = (hash ^ u64::from(b)).wrapping_mul(0x100000001b3);
                    }
                }
                out.insert(path.strip_prefix(dir).unwrap().to_path_buf(), hash);
            }
        }
    }
    out
}

#[test]
fn the_pinned_commit_lands_with_separate_phases_and_a_private_store() {
    let temp = tempfile::tempdir().unwrap();
    let repo = repository(temp.path());
    let mirrors = Mirrors::open(&temp.path().join("mirrors")).unwrap();
    let repo_id = RepoId::new();
    let ws = work(temp.path(), "a");
    // The mirror serves a commit that is not the branch head exactly.
    let out = mirrors
        .checkout(
            &ws,
            &repo_id,
            &source(&repo, &repo.first, Some("refs/heads/main")),
            None,
            "att_one",
            Duration::from_secs(60),
        )
        .unwrap();
    assert_eq!(out.sha, repo.first);
    assert_eq!(git(&ws, &["rev-parse", "HEAD"]), repo.first);
    assert_eq!(fs::read_to_string(ws.join("file.txt")).unwrap(), "one\n");
    // Fetch and materialization are measured separately, never zero.
    assert!(out.fetch_ns > 0);
    assert!(out.materialize_ns > 0);

    let mirror = mirrors.path(&repo_id);
    // One stable bare mirror per repository, plus its lock and leases.
    assert!(mirror.join("HEAD").is_file());
    assert!(mirror.join("objects").is_dir());
    assert!(
        temp.path()
            .join(format!("mirrors/{repo_id}.lock"))
            .is_file()
    );
    // The event ref enriches mirror history with the ref's own tip — the
    // pinned commit is `first`, the ref has since moved to `second`.
    assert_eq!(
        git(&mirror, &["rev-parse", "refs/sentinel/event"]),
        repo.second
    );
    // The workspace's object store is private: no alternates pointer, and
    // it still verifies with the mirror removed entirely.
    assert!(!ws.join(".git/objects/info/alternates").exists());
    fs::rename(&mirror, temp.path().join("mirror-away")).unwrap();
    assert!(git_ok(&ws, &["fsck", "--strict"]));
    assert_eq!(git(&ws, &["cat-file", "-p", "HEAD:file.txt"]), "one");
    fs::rename(temp.path().join("mirror-away"), &mirror).unwrap();
}

#[test]
fn fetches_are_incremental_and_accumulate_history() {
    let temp = tempfile::tempdir().unwrap();
    let repo = repository(temp.path());
    let mirrors = Mirrors::open(&temp.path().join("mirrors")).unwrap();
    let repo_id = RepoId::new();

    mirrors
        .checkout(
            &work(temp.path(), "one"),
            &repo_id,
            &source(&repo, &repo.first, None),
            None,
            "att_one",
            Duration::from_secs(60),
        )
        .unwrap();
    let mirror = mirrors.path(&repo_id);
    let objects_before = manifest(&mirror.join("objects"));

    // A second commit arrives upstream; the next checkout updates the same
    // mirror — nothing is re-cloned, the earlier objects are still served.
    let second_ws = work(temp.path(), "two");
    let out = mirrors
        .checkout(
            &second_ws,
            &repo_id,
            &source(&repo, &repo.second, Some("refs/heads/main")),
            None,
            "att_two",
            Duration::from_secs(60),
        )
        .unwrap();
    assert_eq!(out.sha, repo.second);
    assert!(git_ok(&mirror, &["cat-file", "-e", &repo.first]));
    assert!(git_ok(&mirror, &["cat-file", "-e", &repo.second]));
    let objects_after = manifest(&mirror.join("objects"));
    for (path, hash) in &objects_before {
        assert_eq!(
            objects_after.get(path),
            Some(hash),
            "incremental fetch must not rewrite {} ",
            path.display()
        );
    }
    assert_eq!(
        git(&mirror, &["rev-parse", "refs/sentinel/event"]),
        repo.second
    );
    // The mirror serves full history: the parent chain is complete.
    assert_eq!(
        git(&mirror, &["rev-list", "--count", repo.second.as_str()]),
        "2"
    );
}

#[test]
fn concurrent_checkouts_serialize_writes_and_each_lands_its_sha() {
    let temp = tempfile::tempdir().unwrap();
    let repo = repository(temp.path());
    let mirrors = Mirrors::open(&temp.path().join("mirrors")).unwrap();
    let repo_id = RepoId::new();

    let mut handles = Vec::new();
    for i in 0..8u32 {
        let mirrors = mirrors.clone();
        let sha = if i % 2 == 0 {
            &repo.first
        } else {
            &repo.second
        };
        let want = sha.clone();
        let source =
            PinnedSource::new(repo.path.to_str().unwrap(), sha, Some("refs/heads/main")).unwrap();
        let ws = work(temp.path(), &format!("c{i}"));
        handles.push(thread::spawn(move || {
            let out = mirrors
                .checkout(
                    &ws,
                    &repo_id,
                    &source,
                    None,
                    &format!("att_{i}"),
                    Duration::from_secs(120),
                )
                .unwrap_or_else(|e| panic!("checkout {i}: {e}"));
            assert_eq!(out.sha, want);
            assert_eq!(git(&ws, &["rev-parse", "HEAD"]), want);
            let expect = if i % 2 == 0 { "one\n" } else { "two\n" };
            assert_eq!(fs::read_to_string(ws.join("file.txt")).unwrap(), expect);
        }));
    }
    for handle in handles {
        handle.join().unwrap();
    }
    // The mirror is a consistent store after the interleaving.
    assert!(git_ok(&mirrors.path(&repo_id), &["fsck", "--strict"]));
    // Leases were released with each materialization.
    let leases = temp.path().join(format!("mirrors/{repo_id}.leases"));
    assert!(
        fs::read_dir(&leases)
            .map(|mut d| d.next().is_none())
            .unwrap_or(true)
    );
}

#[test]
fn a_reader_lease_holds_gc_off_and_an_expired_one_is_swept() {
    let temp = tempfile::tempdir().unwrap();
    let repo = repository(temp.path());
    // Tuned so any object at all trips the GC trigger.
    let mirrors = Mirrors::open_tuned(&temp.path().join("mirrors"), 0, 0).unwrap();
    let repo_id = RepoId::new();
    mirrors
        .checkout(
            &work(temp.path(), "seed"),
            &repo_id,
            &source(&repo, &repo.first, None),
            None,
            "att_seed",
            Duration::from_secs(60),
        )
        .unwrap();
    let mirror = mirrors.path(&repo_id);
    // An unreachable loose object stands in for garbage a GC would collect.
    let garbage = {
        use std::io::Write;
        let mut child = Command::new("git")
            .args(["hash-object", "-w", "--stdin"])
            .current_dir(&mirror)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(b"orphaned bytes")
            .unwrap();
        let out = child.wait_with_output().unwrap();
        assert!(out.status.success());
        String::from_utf8(out.stdout).unwrap().trim().to_owned()
    };
    assert!(git_ok(&mirror, &["cat-file", "-e", &garbage]));

    // A live reader lease blocks GC: the next checkout leaves the garbage.
    let leases = temp.path().join(format!("mirrors/{repo_id}.leases"));
    fs::create_dir_all(&leases).unwrap();
    let lease = leases.join("att_holder");
    fs::write(
        &lease,
        format!("{}\n", sentinel_core::UnixMillis::now().0 + 3_600_000),
    )
    .unwrap();
    mirrors
        .checkout(
            &work(temp.path(), "held"),
            &repo_id,
            &source(&repo, &repo.second, None),
            None,
            "att_held",
            Duration::from_secs(60),
        )
        .unwrap();
    assert!(
        git_ok(&mirror, &["cat-file", "-e", &garbage]),
        "GC must not run while a reader lease is live"
    );
    assert!(lease.is_file(), "a live lease is left alone");

    // Expire it: the sweep removes it and the next writer's GC prunes.
    fs::write(&lease, "1\n").unwrap();
    mirrors
        .checkout(
            &work(temp.path(), "swept"),
            &repo_id,
            &source(&repo, &repo.second, None),
            None,
            "att_swept",
            Duration::from_secs(60),
        )
        .unwrap();
    assert!(!lease.exists(), "an expired lease is swept");
    assert!(
        !git_ok(&mirror, &["cat-file", "-e", &garbage]),
        "GC ran once no reader lease remained"
    );
}

#[test]
fn a_workspace_cannot_mutate_the_mirror() {
    let temp = tempfile::tempdir().unwrap();
    let repo = repository(temp.path());
    let mirrors = Mirrors::open(&temp.path().join("mirrors")).unwrap();
    let repo_id = RepoId::new();
    let ws = work(temp.path(), "mut");
    mirrors
        .checkout(
            &ws,
            &repo_id,
            &source(&repo, &repo.second, None),
            None,
            "att_mut",
            Duration::from_secs(60),
        )
        .unwrap();
    let mirror = mirrors.path(&repo_id);
    let before = manifest(&mirror.join("objects"));

    // The job scribbles over every object file it can reach — permission
    // bits first, since Git writes them read-only.
    let objects = ws.join(".git/objects");
    let mut stack = vec![objects.clone()];
    while let Some(d) = stack.pop() {
        for entry in fs::read_dir(&d).unwrap() {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_dir() {
                stack.push(entry.path());
            } else {
                let _ = fs::set_permissions(entry.path(), fs::Permissions::from_mode(0o644));
                let _ = fs::write(entry.path(), b"corrupted by the job");
            }
        }
    }
    // The mirror's bytes did not move, and Git still finds it sound.
    assert_eq!(manifest(&mirror.join("objects")), before);
    assert!(git_ok(&mirror, &["fsck", "--strict"]));
    // And the mirror still serves the pinned commit.
    let ws2 = work(temp.path(), "after");
    let out = mirrors
        .checkout(
            &ws2,
            &repo_id,
            &source(&repo, &repo.second, None),
            None,
            "att_after",
            Duration::from_secs(60),
        )
        .unwrap();
    assert_eq!(out.sha, repo.second);
}

#[test]
fn a_missing_commit_is_a_preparation_failure_naming_the_sha() {
    let temp = tempfile::tempdir().unwrap();
    let repo = repository(temp.path());
    let mirrors = Mirrors::open(&temp.path().join("mirrors")).unwrap();
    let repo_id = RepoId::new();
    let missing = "0123456789abcdef0123456789abcdef01234567";
    let error = mirrors
        .checkout(
            &work(temp.path(), "absent"),
            &repo_id,
            &source(&repo, missing, None),
            None,
            "att_absent",
            Duration::from_secs(60),
        )
        .unwrap_err();
    // Not a mirror failure (no fallback to another revision would be
    // honest); the remote's answer is a preparation error naming the SHA.
    match error {
        Error::Preparation(what) => assert!(what.contains(missing), "{what}"),
        other => panic!("expected Preparation, got {other:?}"),
    }
    // The mirror is not poisoned by the refusal.
    mirrors
        .checkout(
            &work(temp.path(), "good"),
            &repo_id,
            &source(&repo, &repo.first, None),
            None,
            "att_good",
            Duration::from_secs(60),
        )
        .unwrap();
}

#[test]
fn a_damaged_or_partial_mirror_is_rebuilt() {
    let temp = tempfile::tempdir().unwrap();
    let repo = repository(temp.path());
    let mirrors = Mirrors::open(&temp.path().join("mirrors")).unwrap();
    let repo_id = RepoId::new();
    let source = source(&repo, &repo.first, None);
    let timeout = Duration::from_secs(60);
    let mirror = mirrors.path(&repo_id);

    // Half-initialized: objects exist but no HEAD — created, crashed, never
    // finished. The next checkout rebuilds and serves.
    fs::create_dir_all(mirror.join("objects")).unwrap();
    let out = mirrors
        .checkout(
            &work(temp.path(), "a"),
            &repo_id,
            &source,
            None,
            "att_a",
            timeout,
        )
        .unwrap();
    assert_eq!(out.sha, repo.first);

    // The whole mirror removed: rebuilt from scratch.
    fs::remove_dir_all(&mirror).unwrap();
    let out = mirrors
        .checkout(
            &work(temp.path(), "b"),
            &repo_id,
            &source,
            None,
            "att_b",
            timeout,
        )
        .unwrap();
    assert_eq!(out.sha, repo.first);

    // The mirror marked suspect (as a failed materialization would): the
    // next writer rebuilds before fetching. A canary inside the directory
    // proves the rebuild actually happened.
    fs::write(mirror.join("CANARY"), b"x").unwrap();
    fs::write(
        temp.path().join(format!("mirrors/{repo_id}.suspect")),
        b"bad\n",
    )
    .unwrap();
    let out = mirrors
        .checkout(
            &work(temp.path(), "c"),
            &repo_id,
            &source,
            None,
            "att_c",
            timeout,
        )
        .unwrap();
    assert_eq!(out.sha, repo.first);
    assert!(!mirror.join("CANARY").exists(), "the store was rebuilt");

    // A leftover from an interrupted fetch is skipped, not served.
    fs::write(mirror.join("objects/pack/tmp_pack_leftover"), b"partial").unwrap();
    let ws = work(temp.path(), "d");
    let out = mirrors
        .checkout(&ws, &repo_id, &source, None, "att_d", timeout)
        .unwrap();
    assert_eq!(out.sha, repo.first);
    assert!(!work_dir_git_objects_has_tmp(&ws));
}

fn work_dir_git_objects_has_tmp(ws: &Path) -> bool {
    let mut found = false;
    let mut stack = vec![ws.join(".git/objects")];
    while let Some(d) = stack.pop() {
        for entry in fs::read_dir(&d).unwrap().flatten() {
            if entry.file_type().unwrap().is_dir() {
                stack.push(entry.path());
            } else if entry
                .file_name()
                .to_str()
                .is_some_and(|n| n.starts_with("tmp_"))
            {
                found = true;
            }
        }
    }
    found
}

#[test]
fn the_writer_lock_bounds_the_wait() {
    let temp = tempfile::tempdir().unwrap();
    let repo = repository(temp.path());
    let mirrors = Mirrors::open(&temp.path().join("mirrors")).unwrap();
    let repo_id = RepoId::new();
    // Hold the mirror's writer lock from a second descriptor: the waiter
    // must give up inside its bound, not hang.
    let lock_path = temp.path().join(format!("mirrors/{repo_id}.lock"));
    let lock = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)
        .unwrap();
    use std::os::fd::AsRawFd;
    // SAFETY: flock on the test's own fd, released when `lock` closes.
    assert_eq!(
        unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
        0
    );
    let started = Instant::now();
    let error = mirrors
        .checkout(
            &work(temp.path(), "locked"),
            &repo_id,
            &source(&repo, &repo.first, None),
            None,
            "att_locked",
            Duration::from_millis(900),
        )
        .unwrap_err();
    assert!(matches!(error, Error::Mirror(_)), "{error:?}");
    assert!(started.elapsed() < Duration::from_secs(30));
    drop(lock);
    // Released, the same checkout completes.
    mirrors
        .checkout(
            &work(temp.path(), "free"),
            &repo_id,
            &source(&repo, &repo.first, None),
            None,
            "att_free",
            Duration::from_secs(60),
        )
        .unwrap();
}

#[test]
fn an_authorized_checkout_still_enforces_the_access() {
    let temp = tempfile::tempdir().unwrap();
    let repo = repository(temp.path());
    let mirrors = Mirrors::open(&temp.path().join("mirrors")).unwrap();
    let repo_id = RepoId::new();
    // A bound remote must be https/ssh: a file path never validates, so
    // this is refused before any Git runs — no fallback, no fetch.
    let access = Access {
        binding: Binding {
            remote: "https://git.example:8443/team/repo.git".into(),
            allowed_refs: vec!["refs/heads/main".into()],
            pipeline_path: ".sentinel.yml".into(),
            trust: String::new(),
        },
        version: 1,
        expires_ms: sentinel_core::UnixMillis::now().0 + 60_000,
        credential: sentinel_protocol::source::Credential::Public,
    };
    let error = mirrors
        .checkout_authorized(
            &work(temp.path(), "denied"),
            &repo_id,
            &source(&repo, &repo.first, Some("refs/heads/main")),
            &access,
            "att_denied",
            Duration::from_secs(5),
        )
        .unwrap_err();
    assert!(matches!(error, Error::Preparation(_)));
}

/// P07-17: a mirror serves only the remote that filled it — the same
/// repository id checked out from another remote gets a rebuilt, empty
/// store, never the first remote's objects.
#[test]
fn a_mirror_serves_only_the_remote_that_filled_it() {
    let temp = tempfile::tempdir().unwrap();
    let victim = repository(temp.path());
    let other = repository(temp.path());
    // A commit only the first remote has.
    fs::write(victim.path.join("secret.txt"), "victim only\n").unwrap();
    git(&victim.path, &["add", "."]);
    git(&victim.path, &["commit", "-qm", "victim"]);
    let private = git(&victim.path, &["rev-parse", "HEAD"]);
    let mirrors = Mirrors::open(&temp.path().join("mirrors")).unwrap();
    let repo_id = RepoId::new();
    let timeout = Duration::from_secs(60);
    mirrors
        .checkout(
            &work(temp.path(), "victim"),
            &repo_id,
            &source(&victim, &private, None),
            None,
            "att_victim",
            timeout,
        )
        .unwrap();
    let mirror = mirrors.path(&repo_id);
    assert!(git_ok(&mirror, &["cat-file", "-e", &private]));
    mirrors
        .checkout(
            &work(temp.path(), "other"),
            &repo_id,
            &source(&other, &other.first, None),
            None,
            "att_other",
            timeout,
        )
        .unwrap();
    assert!(
        !git_ok(&mirror, &["cat-file", "-e", &private]),
        "the first remote's objects are gone with its store"
    );
}

/// P07-19: store damage a bare-repository check cannot see — the pinned
/// commit's object gone from under a ref — is rebuilt and served, not a
/// permanent preparation failure.
#[test]
fn damage_under_a_ref_tip_is_rebuilt_not_a_permanent_failure() {
    let temp = tempfile::tempdir().unwrap();
    let repo = repository(temp.path());
    let mirrors = Mirrors::open(&temp.path().join("mirrors")).unwrap();
    let repo_id = RepoId::new();
    let timeout = Duration::from_secs(60);
    let src = source(&repo, &repo.first, None);
    mirrors
        .checkout(
            &work(temp.path(), "a"),
            &repo_id,
            &src,
            None,
            "att_a",
            timeout,
        )
        .unwrap();
    let mirror = mirrors.path(&repo_id);
    // Every object file of the store goes: the pin ref now names nothing.
    let objects = mirror.join("objects");
    for entry in fs::read_dir(&objects).unwrap().flatten() {
        let name = entry.file_name();
        let name = name.to_str().unwrap();
        if name.len() == 2 || name == "pack" {
            fs::remove_dir_all(entry.path()).unwrap();
        }
    }
    fs::create_dir(objects.join("pack")).unwrap();
    let out = mirrors
        .checkout(
            &work(temp.path(), "b"),
            &repo_id,
            &src,
            None,
            "att_b",
            timeout,
        )
        .unwrap();
    assert_eq!(out.sha, repo.first);
}

/// P07-23: a crashed attempt's leftover lease temp file does not block the
/// same attempt id's next lease.
#[test]
fn a_leftover_lease_temp_file_does_not_block_a_retry() {
    let temp = tempfile::tempdir().unwrap();
    let repo = repository(temp.path());
    let mirrors = Mirrors::open(&temp.path().join("mirrors")).unwrap();
    let repo_id = RepoId::new();
    let leases = temp.path().join(format!("mirrors/{repo_id}.leases"));
    fs::create_dir_all(&leases).unwrap();
    fs::write(leases.join(".att_retry.tmp"), b"torn").unwrap();
    mirrors
        .checkout(
            &work(temp.path(), "retry"),
            &repo_id,
            &source(&repo, &repo.first, None),
            None,
            "att_retry",
            Duration::from_secs(60),
        )
        .unwrap();
}

/// P07-20: a store too large to copy is materialized by a depth-1 fetch of
/// the pinned commit alone. The job gets exactly that commit — here one the
/// branch has moved past, so not an advertised tip — in its own pack: no
/// history behind it, no `alternates`, sound with the mirror gone, and its
/// writes never reach the mirror.
#[test]
fn a_large_store_is_materialized_by_fetching_the_pinned_commit_alone() {
    let temp = tempfile::tempdir().unwrap();
    let repo = repository(temp.path());
    let mirrors = Mirrors::open(&temp.path().join("mirrors"))
        .unwrap()
        .fetch_materialization();
    let repo_id = RepoId::new();
    // Fill the mirror with both commits first, so the store holds history.
    mirrors
        .checkout(
            &work(temp.path(), "fill"),
            &repo_id,
            &source(&repo, &repo.second, Some("refs/heads/main")),
            None,
            "att_fill",
            Duration::from_secs(60),
        )
        .unwrap();
    let mirror = mirrors.path(&repo_id);
    let before = manifest(&mirror.join("objects"));
    let ws = work(temp.path(), "old");
    let out = mirrors
        .checkout(
            &ws,
            &repo_id,
            &source(&repo, &repo.first, None),
            None,
            "att_old",
            Duration::from_secs(60),
        )
        .unwrap();
    assert_eq!(out.sha, repo.first);
    assert_eq!(git(&ws, &["rev-parse", "HEAD"]), repo.first);
    assert_eq!(fs::read_to_string(ws.join("file.txt")).unwrap(), "one\n");
    // One commit, shallow, and none of the mirror's other history.
    assert_eq!(git(&ws, &["rev-list", "--count", "HEAD"]), "1");
    assert!(ws.join(".git/shallow").is_file());
    assert!(!git_ok(&ws, &["cat-file", "-e", &repo.second]));
    assert!(!ws.join(".git/objects/info/alternates").exists());
    // Private: sound without the mirror, and scribbling over the job's
    // objects leaves the mirror's bytes and verdict unchanged.
    fs::rename(&mirror, temp.path().join("mirror-away")).unwrap();
    assert!(git_ok(&ws, &["fsck", "--strict"]));
    fs::rename(temp.path().join("mirror-away"), &mirror).unwrap();
    let mut stack = vec![ws.join(".git/objects")];
    while let Some(d) = stack.pop() {
        for entry in fs::read_dir(&d).unwrap() {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_dir() {
                stack.push(entry.path());
            } else {
                let _ = fs::set_permissions(entry.path(), fs::Permissions::from_mode(0o644));
                let _ = fs::write(entry.path(), b"corrupted by the job");
            }
        }
    }
    let after = manifest(&mirror.join("objects"));
    for (path, hash) in &before {
        assert_eq!(after.get(path), Some(hash), "{} moved", path.display());
    }
    assert!(git_ok(&mirror, &["fsck", "--strict"]));
}
