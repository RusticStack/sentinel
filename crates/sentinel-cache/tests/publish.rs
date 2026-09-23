//! Publication behavior (K03): sealed generations, the atomic `current`
//! swap, the single-writer bound, cancellation and the trust boundary —
//! exercised through `commit` with synthetic `Attached` carriers, the
//! same shape K02's restore fills.

use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU32, Ordering},
    time::{Duration, Instant},
};

use sentinel_cache::{
    attach::{Attached, Stats, Target},
    lease::WriteLock,
    manifest::{Compat, FileEntry, FilesBlob, Manifest, read_files},
    outcome::{Miss, Outcome},
    publish::{PublishError, Published, SkipReason},
    scope::{self, Os, Platform, Scope},
};
use sentinel_core::{RepoId, TenantId, UnixMillis};
use sentinel_protocol::{cache::Class, cache::Trust, negotiate::Arch};

fn test_scope(trust: Trust) -> Scope {
    Scope::new(
        TenantId::new(),
        RepoId::new(),
        Class::Dependencies,
        trust,
        Platform {
            os: Os::Linux,
            arch: Arch::X86_64,
        },
        Scope::toolchain_digest(b"rust linux test"),
        "deps",
    )
    .unwrap()
}

fn compat() -> Compat {
    Compat::Dependencies {
        lock: *blake3::hash(b"Cargo.lock").as_bytes(),
        installer: "cargo".to_owned(),
        flags: "--locked".to_owned(),
        abi: "test".to_owned(),
    }
}

fn target(dir: PathBuf) -> Target {
    Target {
        declared: dir.to_string_lossy().into_owned(),
        root: dir.parent().unwrap().to_path_buf(),
        dir,
        container: "/workspace/cache".to_owned(),
        mount: false,
    }
}

fn attached(scope: Scope, targets: Vec<Target>) -> Attached {
    Attached {
        name: scope.name.clone(),
        scope,
        key: "deps-deadbeef".to_owned(),
        compat: compat(),
        generation: None,
        outcome: Outcome::Miss(Miss::Absent),
        targets,
        lease: None,
        stats: Stats::default(),
    }
}

fn never() -> impl Fn() -> bool {
    || false
}

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(60)
}

fn commit(root: &Path, a: &Attached, ms: i64) -> Result<Published, PublishError> {
    commit_inner(root, a, a.scope.trust, ms)
}

fn commit_inner(
    root: &Path,
    a: &Attached,
    trust: Trust,
    ms: i64,
) -> Result<Published, PublishError> {
    sentinel_cache::publish::commit(root, a, trust, UnixMillis(ms), deadline(), &never())
}

/// The entry dir `commit` writes under — the same derivation restore uses.
fn entry_of(root: &Path, a: &Attached) -> PathBuf {
    a.scope.entry_dir(
        root,
        sentinel_cache::attach::entry_key(a.scope.class, &a.key),
    )
}

/// Read `current` and resolve the generation it names.
fn current_gen(entry: &Path) -> Option<String> {
    fs::read_to_string(entry.join(scope::CURRENT_NAME))
        .ok()
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
}

/// A generation is sealed when its manifest decodes and its `files` blob
/// matches the manifest's digest and counts.
fn sealed(entry: &Path, generation: &str) -> (Manifest, FilesBlob) {
    let dir = entry.join(generation);
    let outcome = sentinel_cache::manifest::read(&dir);
    let Outcome::Hit(hit) = outcome else {
        panic!("{generation} is not a sealed generation: {outcome:?}")
    };
    let blob = read_files(&dir).unwrap();
    assert_eq!(
        blob.digest(),
        hit.manifest.files_digest,
        "the files blob must match the manifest's pin"
    );
    assert_eq!(hit.manifest.files as usize, blob.entries.len());
    (hit.manifest, blob)
}

fn put(dir: &Path, rel: &str, bytes: &[u8]) {
    let path = dir.join(rel);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, bytes).unwrap();
}

#[test]
fn a_commit_seals_a_generation_and_swaps_current() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("cache");
    let view = tmp.path().join("view");
    put(&view, "a/lib.rlib", b"lib-bytes");
    put(&view, "b/tool", b"tool-bytes");

    let scope = test_scope(Trust::Protected);
    let a = attached(scope, vec![target(view)]);
    let out = commit(&root, &a, 1_000).unwrap();
    let Published::Sealed {
        generation,
        files,
        bytes,
        ..
    } = out
    else {
        panic!("expected a sealed generation, got {out:?}")
    };
    assert_eq!(files, 2);
    assert_eq!(bytes, 9 + 10);

    let entry = entry_of(&root, &a);
    // `current` names exactly the sealed generation.
    assert_eq!(current_gen(&entry).as_deref(), Some(generation.as_str()));
    let (manifest, blob) = sealed(&entry, &generation);
    assert_eq!(manifest.key, "deps-deadbeef");
    // The payload layout is `payload/<target-index>/<rel>`.
    let paths: Vec<&str> = blob.entries.iter().map(|e| e.path.as_str()).collect();
    assert_eq!(paths, ["payload/0/a/lib.rlib", "payload/0/b/tool"]);
    // Digests verify the staged bytes.
    for e in &blob.entries {
        let staged = fs::read(entry.join(&generation).join(&e.path)).unwrap();
        assert_eq!(*blake3::hash(&staged).as_bytes(), e.digest);
        assert_eq!(staged.len() as u64, e.size);
    }
    // Staging is empty after a successful publish.
    let writing = entry.join(scope::WRITING_NAME);
    assert!(!writing.exists() || fs::read_dir(&writing).unwrap().next().is_none());
}

#[test]
fn a_second_publish_makes_a_distinct_generation_and_swaps() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("cache");
    let view = tmp.path().join("view");
    put(&view, "f", b"v1");

    let scope = test_scope(Trust::Protected);
    let a = attached(scope, vec![target(view.clone())]);
    let first = commit(&root, &a, 1_000).unwrap();
    let Published::Sealed {
        generation: gen_a, ..
    } = first
    else {
        panic!()
    };

    // Changed content, and the attempt knew the generation it cloned from.
    put(&view, "f", b"v2-longer");
    let mut b = attached(a.scope.clone(), vec![target(view)]);
    b.generation = Some(gen_a.clone());
    let second = commit(&root, &b, 2_000).unwrap();
    let Published::Sealed {
        generation: gen_b, ..
    } = second
    else {
        panic!()
    };

    assert_ne!(gen_a, gen_b);
    let entry = entry_of(&root, &b);
    assert_eq!(current_gen(&entry).as_deref(), Some(gen_b.as_str()));
    // Both generations remain sealed on disk; the pointer only moved.
    sealed(&entry, &gen_a);
    let (_, blob) = sealed(&entry, &gen_b);
    assert_eq!(
        fs::read(entry.join(&gen_b).join(&blob.entries[0].path)).unwrap(),
        b"v2-longer"
    );
}

#[test]
fn a_reader_never_sees_a_torn_current() {
    // While commits land, every read of `current` is either empty or names
    // a directory that already exists and already seals — the swap is
    // atomic against concurrent observation.
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("cache");
    let view = tmp.path().join("view");
    // Enough files that promotion takes a measurable window.
    for i in 0..64 {
        put(&view, &format!("d{i}/f"), &[i as u8; 256]);
    }
    let scope = test_scope(Trust::Protected);
    let entry = entry_of(&root, &attached(scope.clone(), vec![]));
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let reader = std::thread::spawn({
        let entry = entry.clone();
        let stop = std::sync::Arc::clone(&stop);
        move || {
            while !stop.load(Ordering::Acquire) {
                if let Some(name) = current_gen(&entry) {
                    let dir = entry.join(&name);
                    assert!(dir.is_dir(), "current named {name} but it is absent");
                    // If it is named by current, its manifest must already
                    // read as sealed — promotion happens after sealing.
                    assert!(
                        matches!(sentinel_cache::manifest::read(&dir), Outcome::Hit(_)),
                        "current named {name} before its manifest was sealed"
                    );
                }
            }
        }
    });
    for round in 0..3 {
        let mut a = attached(scope.clone(), vec![target(view.clone())]);
        a.generation = current_gen(&entry);
        // Rotate content so every round seals a new generation.
        put(&view, "d0/f", &[round as u8 + 100; 256]);
        commit(&root, &a, 1_000 + round).unwrap();
    }
    stop.store(true, Ordering::Release);
    reader.join().unwrap();
}

#[test]
fn a_live_writer_lock_makes_a_commit_busy() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("cache");
    let view = tmp.path().join("view");
    put(&view, "f", b"bytes");
    let scope = test_scope(Trust::Protected);
    let a = attached(scope, vec![target(view)]);
    let entry = entry_of(&root, &a);

    // A competing writer holds the staging lock.
    let held = WriteLock::acquire(&entry, "other-writer").unwrap().unwrap();
    let out = commit(&root, &a, 1_000).unwrap();
    assert_eq!(out, Published::Skipped(SkipReason::Busy));
    assert!(current_gen(&entry).is_none());
    drop(held);

    // Once it releases, the same commit goes through.
    let out = commit(&root, &a, 1_000).unwrap();
    assert!(matches!(out, Published::Sealed { .. }));
}

#[test]
fn a_stale_writer_lock_is_reaped_in_place() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("cache");
    let view = tmp.path().join("view");
    put(&view, "f", b"bytes");
    let scope = test_scope(Trust::Protected);
    let a = attached(scope, vec![target(view)]);
    let entry = entry_of(&root, &a);

    // A dead writer's marker: declared expiry long past.
    let writing = entry.join(scope::WRITING_NAME);
    fs::create_dir_all(&writing).unwrap();
    fs::write(
        writing.join(sentinel_cache::lease::WRITE_LOCK_NAME),
        b"1 dead",
    )
    .unwrap();
    let out = commit(&root, &a, 1_000).unwrap();
    assert!(matches!(out, Published::Sealed { .. }));
}

#[test]
fn cancellation_mid_walk_leaves_current_untouched_and_no_staging() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("cache");
    let view = tmp.path().join("view");
    for i in 0..600 {
        put(&view, &format!("f{i:04}"), b"x");
    }
    let scope = test_scope(Trust::Protected);
    let a = attached(scope, vec![target(view)]);
    let entry = entry_of(&root, &a);

    // Pre-existing current, so the test sees it survive the cancel.
    let first = sentinel_cache::publish::commit(
        &root,
        &a,
        Trust::Protected,
        UnixMillis(500),
        deadline(),
        &never(),
    )
    .unwrap();
    let Published::Sealed {
        generation: gen_a, ..
    } = first
    else {
        panic!()
    };
    assert_eq!(current_gen(&entry).as_deref(), Some(gen_a.as_str()));

    // Cancel trips after the first poll — inside the walk.
    let calls = AtomicU32::new(0);
    let canceled = || calls.fetch_add(1, Ordering::Relaxed) >= 1;
    let mut b = attached(a.scope.clone(), vec![target(a.targets[0].dir.clone())]);
    b.generation = Some(gen_a.clone());
    put(&b.targets[0].dir, "extra", b"new");
    let out = sentinel_cache::publish::commit(
        &root,
        &b,
        Trust::Protected,
        UnixMillis(600),
        deadline(),
        &canceled,
    )
    .unwrap();
    assert_eq!(out, Published::Skipped(SkipReason::Canceled));
    // `current` still names the first generation; no staged tree remains.
    assert_eq!(current_gen(&entry).as_deref(), Some(gen_a.as_str()));
    let writing = entry.join(scope::WRITING_NAME);
    let staged: Vec<_> = if writing.exists() {
        fs::read_dir(&writing)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.file_name()
                    .to_str()
                    .is_some_and(|n| n.starts_with("gen-"))
            })
            .collect()
    } else {
        Vec::new()
    };
    assert!(staged.is_empty(), "staging left behind: {staged:?}");
}

#[test]
fn zero_files_across_targets_is_empty() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("cache");
    let empty = tmp.path().join("empty");
    fs::create_dir_all(&empty).unwrap();
    let missing = tmp.path().join("never-made");
    let scope = test_scope(Trust::Protected);
    let a = attached(scope, vec![target(empty), target(missing)]);
    let out = commit(&root, &a, 1_000).unwrap();
    assert_eq!(out, Published::Skipped(SkipReason::Empty));
    // Nothing was published: no generation, no pointer.
    let entry = entry_of(&root, &a);
    assert!(current_gen(&entry).is_none());
}

#[test]
fn unchanged_content_is_skipped_unchanged() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("cache");
    let view = tmp.path().join("view");
    put(&view, "a", b"same-a");
    put(&view, "b", b"same-b");

    let scope = test_scope(Trust::Protected);
    let a = attached(scope.clone(), vec![target(view.clone())]);
    let Published::Sealed {
        generation: gen_a, ..
    } = commit(&root, &a, 1_000).unwrap()
    else {
        panic!()
    };

    // The next attempt cloned from gen_a and changed nothing.
    let mut b = attached(scope, vec![target(view)]);
    b.generation = Some(gen_a.clone());
    let out = commit(&root, &b, 2_000).unwrap();
    assert_eq!(out, Published::Skipped(SkipReason::Unchanged));
    assert_eq!(
        current_gen(&entry_of(&root, &b)).as_deref(),
        Some(gen_a.as_str())
    );
}

#[test]
fn incremental_publish_reuses_unchanged_files() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("cache");
    let view = tmp.path().join("view");
    put(&view, "keep/a", b"keep-a-bytes");
    put(&view, "keep/b", b"keep-b-bytes");
    put(&view, "change", b"old");

    let scope = test_scope(Trust::Protected);
    let a = attached(scope.clone(), vec![target(view.clone())]);
    let Published::Sealed {
        generation: gen_a, ..
    } = commit(&root, &a, 1_000).unwrap()
    else {
        panic!()
    };
    let entry = entry_of(&root, &a);
    let (_, blob_a) = sealed(&entry, &gen_a);

    put(&view, "change", b"new-and-longer");
    let mut b = attached(scope, vec![target(view)]);
    b.generation = Some(gen_a.clone());
    let Published::Sealed {
        generation: gen_b,
        files,
        bytes,
        reused_bytes,
        ..
    } = commit(&root, &b, 2_000).unwrap()
    else {
        panic!()
    };
    let (_, blob_b) = sealed(&entry, &gen_b);
    assert_eq!(files, 3);
    assert_eq!(bytes, 12 + 12 + 14);

    // Unchanged files keep their digests; the changed file got a new one.
    fn by_path<'a>(blob: &'a FilesBlob, p: &str) -> &'a FileEntry {
        blob.entries.iter().find(|e| e.path == p).unwrap()
    }
    for p in ["payload/0/keep/a", "payload/0/keep/b"] {
        assert_eq!(by_path(&blob_a, p).digest, by_path(&blob_b, p).digest);
    }
    let changed = by_path(&blob_b, "payload/0/change");
    assert_eq!(*blake3::hash(b"new-and-longer").as_bytes(), changed.digest);
    assert_ne!(by_path(&blob_a, "payload/0/change").digest, changed.digest);

    // Where hardlinks work, the unchanged payload shares storage with the
    // source generation — `reused_bytes` counts exactly that.
    let probe = tmp.path().join("probe-src");
    fs::write(&probe, b"p").unwrap();
    if fs::hard_link(&probe, tmp.path().join("probe-dst")).is_ok() {
        assert_eq!(reused_bytes, 24, "unchanged files should be reused");
    }
}

#[test]
fn a_pull_request_scope_stays_in_pull_request() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("cache");
    let view = tmp.path().join("view");
    put(&view, "f", b"bytes");
    let scope = test_scope(Trust::PullRequest);
    let a = attached(scope, vec![target(view)]);

    let out = commit_inner(&root, &a, Trust::PullRequest, 1_000).unwrap();
    assert!(matches!(out, Published::Sealed { .. }));
    let entry = entry_of(&root, &a);
    // The path carries the pull_request component — and nothing was
    // written anywhere near protected scope.
    assert!(entry.to_string_lossy().contains("pull_request"));
    assert!(
        !root
            .join(a.scope.repo.to_string())
            .join("dependencies")
            .join("protected")
            .exists()
    );
}

#[test]
fn a_trust_mismatch_is_a_typed_refusal() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("cache");
    let view = tmp.path().join("view");
    put(&view, "f", b"bytes");
    // A pull_request-scoped attachment handed to a protected job.
    let scope = test_scope(Trust::PullRequest);
    let a = attached(scope, vec![target(view)]);
    let err = commit_inner(&root, &a, Trust::Protected, 1_000).unwrap_err();
    assert!(matches!(err, PublishError::TrustMismatch));
    // Nothing was created — refusal happens before any directory exists.
    assert!(!entry_of(&root, &a).exists());
}

#[test]
fn unsupported_entries_are_skipped_not_followed() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("cache");
    let view = tmp.path().join("view");
    let outside = tmp.path().join("outside");
    put(&view, "real", b"real-bytes");
    put(&outside, "secret", b"do-not-publish");
    // A symlink inside the tree must not leak `outside` into the payload.
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(outside.join("secret"), view.join("linked")).unwrap();
        std::os::unix::fs::symlink(&outside, view.join("linked-dir")).unwrap();
    }
    #[cfg(windows)]
    {
        // Directory symlink needs an elevated right on Windows; skip the
        // link when it cannot be made, the file link still exercises the
        // no-follow rule.
        let _ = std::os::windows::fs::symlink_file(outside.join("secret"), view.join("linked"));
        let _ = std::os::windows::fs::symlink_dir(&outside, view.join("linked-dir"));
    }
    let scope = test_scope(Trust::Protected);
    let a = attached(scope, vec![target(view)]);
    let out = commit(&root, &a, 1_000).unwrap();
    let Published::Sealed { files, .. } = out else {
        panic!("expected sealed, got {out:?}")
    };
    assert_eq!(files, 1, "only the regular file may be staged");
}

/// K07: an executable staged into the payload must keep its exec bit —
/// restore re-applies the payload file's own mode, so a 0666&umask
/// staging would degrade every cached tool binary to Permission denied.
#[test]
#[cfg(unix)]
fn sealed_payload_files_carry_the_recorded_mode() {
    use std::os::unix::fs::PermissionsExt;

    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("cache");
    let view = tmp.path().join("view");
    put(&view, "bin/tool", b"#!/bin/sh\n");
    fs::set_permissions(view.join("bin/tool"), fs::Permissions::from_mode(0o755)).unwrap();
    put(&view, "data.txt", b"bytes");

    let scope = test_scope(Trust::Protected);
    let a = attached(scope, vec![target(view)]);
    let out = commit(&root, &a, 1_000).unwrap();
    let Published::Sealed { generation, .. } = out else {
        panic!("expected sealed, got {out:?}")
    };
    let entry = entry_of(&root, &a);
    let (manifest, blob) = sealed(&entry, &generation);
    assert_eq!(manifest.files, 2);
    let tool = blob
        .entries
        .iter()
        .find(|e| e.path.ends_with("tool"))
        .unwrap();
    assert_eq!(tool.mode & 0o777, 0o755, "manifest records the exec bit");
    let payload = entry.join(&generation).join("payload").join("0");
    assert_eq!(
        fs::metadata(payload.join("bin/tool"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o755,
        "the staged payload file itself carries the recorded mode"
    );
}

// ——— P07-1 / P07-5 / P07-9: confined, bounded, refusal-aware publish ———

/// A restore-shaped carrier over a real workspace: the targets are what
/// `restore` resolved (anchored at the workspace), so publish sees exactly
/// what finalization hands it.
#[cfg(unix)]
fn restored(root: &Path, ws: &Path, paths: &[&str], key: &str) -> Attached {
    let decl = sentinel_pipeline::schema::Cache {
        name: "deps".into(),
        class: Class::Dependencies,
        key: sentinel_pipeline::expr::Template::parse(key).unwrap(),
        paths: paths.iter().map(|p| (*p).to_owned()).collect(),
    };
    let env = sentinel_cache::restore::Context {
        cache_root: root,
        workspace: ws,
        workspace_mount: "/workspace",
        backend: sentinel_cache::clone::Backend::Copy,
    };
    sentinel_cache::restore::restore(
        &env,
        &decl,
        Some(key.to_owned()),
        test_scope(Trust::PullRequest),
        "attempt-1",
    )
}

/// Every payload path a sealed generation lists, in listing order.
#[cfg(unix)]
fn listed(root: &Path, a: &Attached, generation: &str) -> Vec<String> {
    let (_, blob) = sealed(&entry_of(root, a), generation);
    blob.entries.into_iter().map(|e| e.path).collect()
}

/// P07-1: a job that swaps an intermediate component of a declared path
/// for a symlink to a host directory must not seal that directory — for a
/// relative declaration and for an absolute one (whose private view lives
/// under `.sentinel-cache/` inside the workspace).
#[cfg(unix)]
#[test]
fn publish_refuses_a_symlinked_intermediate_component() {
    use std::os::unix::fs::symlink;
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("cache");
    let ws = tmp.path().join("ws");
    fs::create_dir_all(&ws).unwrap();
    // Host files the job must never read: the worker's key, another
    // tenant's cache — anything the worker account can open.
    let host = tmp.path().join("host");
    put(&host, "b/worker.key", b"PRIVATE KEY MATERIAL");
    put(&host, "1/stolen", b"PRIVATE KEY MATERIAL");

    let a = restored(&root, &ws, &["a/b", "/opt/tool"], "deps-p071");
    assert_eq!(a.outcome, Outcome::Miss(Miss::Absent));
    put(&ws, "a/b/honest", b"job output");
    // The job replaces `a` (above the declared `a/b`) and the private
    // `.sentinel-cache/deps` (above `/opt/tool`'s view) with links out.
    fs::remove_dir_all(ws.join("a")).unwrap();
    symlink(&host, ws.join("a")).unwrap();
    let private = ws.join(sentinel_cache::attach::PRIVATE_DIR).join("deps");
    fs::remove_dir_all(&private).unwrap();
    symlink(&host, &private).unwrap();

    let out = commit(&root, &a, 1_000).unwrap();
    assert_eq!(
        out,
        Published::Skipped(SkipReason::Empty),
        "nothing beneath a planted link may be walked"
    );
    // And no generation holding host bytes exists anywhere.
    assert!(current_gen(&entry_of(&root, &a)).is_none());
}

/// P07-1/P07-9: a symlink the checkout itself carries above a declared
/// path makes restore refuse the entry (`invalid`); publication of a
/// refused entry is a `refused` skip — the path is never walked.
#[cfg(unix)]
#[test]
fn publish_skips_an_entry_restore_refused() {
    use std::os::unix::fs::symlink;
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("cache");
    let ws = tmp.path().join("ws");
    fs::create_dir_all(&ws).unwrap();
    let host = tmp.path().join("host");
    put(&host, "sub/secret", b"host bytes");
    symlink(&host, ws.join("link")).unwrap();
    let a = restored(&root, &ws, &["link/sub"], "deps-p079");
    assert_eq!(a.outcome, Outcome::Miss(Miss::Invalid));
    assert_eq!(
        commit(&root, &a, 1_000).unwrap(),
        Published::Skipped(SkipReason::Refused)
    );
    assert!(!entry_of(&root, &a).exists(), "nothing was created");
}

/// P07-9: an entry whose key never rendered (`""`) could never serve — it
/// publishes nothing instead of a permanent unservable `current`; neither
/// does an entry restore answered `invalid`.
#[test]
fn an_unrendered_key_publishes_nothing() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("cache");
    let view = tmp.path().join("view");
    put(&view, "f", b"bytes");
    let mut a = attached(test_scope(Trust::Protected), vec![target(view)]);
    a.key = String::new();
    assert_eq!(
        commit(&root, &a, 1_000).unwrap(),
        Published::Skipped(SkipReason::Refused)
    );
    a.key = "deps-deadbeef".into();
    a.outcome = Outcome::Miss(Miss::Invalid);
    assert_eq!(
        commit(&root, &a, 1_000).unwrap(),
        Published::Skipped(SkipReason::Refused)
    );
    assert_eq!(SkipReason::Refused.as_str(), "refused");
}

/// P07-1: a file swapped for a symlink between the plan and the copy is
/// never opened — the stage reopens every file beneath its confined base
/// with `O_NOFOLLOW`, so the swap stages nothing of the link's target.
#[cfg(unix)]
#[test]
fn publish_opens_files_nofollow() {
    use std::os::unix::fs::symlink;
    use std::sync::atomic::AtomicBool;
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("cache");
    let view = tmp.path().join("view");
    put(&view, "keep", b"kept bytes");
    put(&view, "swap", b"planned bytes");
    let secret = tmp.path().join("secret");
    fs::write(&secret, b"PRIVATE KEY MATERIAL").unwrap();
    let a = attached(test_scope(Trust::Protected), vec![target(view.clone())]);
    // The commit polls `cancel` once before planning and once between the
    // plan and the stage: the second poll is where the job's swap lands.
    let calls = AtomicU32::new(0);
    let swapped = AtomicBool::new(false);
    let cancel = || {
        if calls.fetch_add(1, Ordering::SeqCst) == 1 {
            fs::remove_file(view.join("swap")).unwrap();
            symlink(&secret, view.join("swap")).unwrap();
            swapped.store(true, Ordering::SeqCst);
        }
        false
    };
    let out = sentinel_cache::publish::commit(
        &root,
        &a,
        Trust::Protected,
        UnixMillis(1_000),
        deadline(),
        &cancel,
    )
    .unwrap();
    assert!(swapped.load(Ordering::SeqCst), "the swap ran mid-commit");
    let Published::Sealed {
        generation,
        skipped,
        ..
    } = out
    else {
        panic!("expected sealed, got {out:?}")
    };
    assert_eq!(skipped, 1, "the swapped entry is counted, not staged");
    assert_eq!(listed(&root, &a, &generation), ["payload/0/keep"]);
}

/// P07-5: a generation whose logical payload exceeds the per-generation
/// cap is refused before a byte is staged — a sparse file claiming
/// terabytes costs a stat, not a copy.
#[cfg(target_os = "linux")]
#[test]
fn publish_refuses_a_generation_over_the_byte_cap() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("cache");
    let view = tmp.path().join("view");
    put(&view, "small", b"ok");
    let huge = fs::File::create(view.join("huge")).unwrap();
    huge.set_len(sentinel_cache::publish::MAX_GENERATION_BYTES + 1)
        .unwrap();
    let a = attached(test_scope(Trust::Protected), vec![target(view)]);
    let started = Instant::now();
    let out = commit(&root, &a, 1_000);
    assert!(
        matches!(out, Err(PublishError::TooLarge)),
        "over the cap must be refused, got {out:?}"
    );
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "refused at plan time, never after reading the file"
    );
    let entry = entry_of(&root, &a);
    assert!(current_gen(&entry).is_none());
    assert!(
        fs::read_dir(entry.join(scope::WRITING_NAME))
            .map(|d| d.count() == 0)
            .unwrap_or(true),
        "no staging survives"
    );
}

/// P07-5: a sparse file within the cap is staged hole-for-hole: the sealed
/// copy allocates about what the source allocates, not its logical size,
/// and its recorded digest is still of the full logical content.
#[cfg(target_os = "linux")]
#[test]
fn sparse_file_does_not_amplify() {
    use std::io::{Seek, SeekFrom, Write};
    use std::os::unix::fs::MetadataExt;
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("cache");
    let view = tmp.path().join("view");
    fs::create_dir_all(&view).unwrap();
    const LOGICAL: u64 = 256 << 20;
    let mut file = fs::File::create(view.join("sparse")).unwrap();
    file.write_all(b"head").unwrap();
    file.seek(SeekFrom::Start(LOGICAL - 4)).unwrap();
    file.write_all(b"tail").unwrap();
    drop(file);
    let source = fs::metadata(view.join("sparse")).unwrap();
    if source.blocks() * 512 * 2 >= LOGICAL {
        eprintln!("skipped: this filesystem does not keep holes");
        return;
    }
    let a = attached(test_scope(Trust::Protected), vec![target(view.clone())]);
    let Published::Sealed { generation, .. } = commit(&root, &a, 1_000).unwrap() else {
        panic!("expected sealed")
    };
    let staged = entry_of(&root, &a)
        .join(&generation)
        .join("payload/0/sparse");
    let meta = fs::metadata(&staged).unwrap();
    assert_eq!(meta.len(), LOGICAL);
    assert!(
        meta.blocks() * 512 < 16 << 20,
        "the staged copy allocated {} bytes for a 256 MiB mostly-hole file",
        meta.blocks() * 512
    );
    let (_, blob) = sealed(&entry_of(&root, &a), &generation);
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"head");
    let zeros = vec![0u8; 1 << 20];
    let mut left = LOGICAL - 8;
    while left > 0 {
        let n = left.min(zeros.len() as u64) as usize;
        hasher.update(&zeros[..n]);
        left -= n as u64;
    }
    hasher.update(b"tail");
    assert_eq!(blob.entries[0].digest, *hasher.finalize().as_bytes());
}
