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
