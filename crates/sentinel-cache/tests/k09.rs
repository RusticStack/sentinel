use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    sync::{
        Arc, Barrier, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use sentinel_cache::{
    attach::{self, Attached, Stats, Target, entry_key},
    clone, gc,
    lease::{self, WriteLock},
    manifest::{FilesBlob, Manifest, read_files},
    outcome::{Miss, Outcome},
    publish::{self, PublishError, Published, SkipReason},
    restore::{self, Context},
    scope::{self, Os, Platform, Scope},
};
use sentinel_core::{RepoId, TenantId, UnixMillis};
use sentinel_pipeline::{expr::Template, schema::Cache};
use sentinel_protocol::{
    cache::{Class, Trust},
    negotiate::Arch,
};

const KEY: &str = "k09-deps-fixed";

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
        Scope::toolchain_digest(b"k09 linux test"),
        "deps",
    )
    .unwrap()
}

fn named_scope(scope: &Scope, name: &str) -> Scope {
    let mut other = scope.clone();
    other.name = name.to_owned();
    other
}

fn decl(paths: &[&str]) -> Cache {
    Cache {
        name: "deps".into(),
        class: Class::Dependencies,
        key: Template::parse(KEY).unwrap(),
        paths: paths.iter().map(|s| (*s).to_owned()).collect(),
    }
}

fn target(dir: PathBuf) -> Target {
    Target {
        declared: dir.to_string_lossy().into_owned(),
        root: dir.parent().unwrap().to_path_buf(),
        dir,
        container: "/workspace/view".to_owned(),
        mount: false,
    }
}

fn attached(scope: Scope, d: &Cache, targets: Vec<Target>) -> Attached {
    Attached {
        name: scope.name.clone(),
        compat: attach::declared_compat(d, KEY, scope.platform),
        scope,
        key: KEY.to_owned(),
        generation: None,
        outcome: Outcome::Miss(Miss::Absent),
        targets,
        lease: None,
        stats: Stats::default(),
    }
}

fn env<'a>(root: &'a Path, ws: &'a Path) -> Context<'a> {
    Context {
        cache_root: root,
        workspace: ws,
        workspace_mount: "/workspace",
        backend: clone::detect(root),
    }
}

fn entry_of(root: &Path, scope: &Scope, key: &str) -> PathBuf {
    scope.entry_dir(root, entry_key(scope.class, key))
}

fn commit(root: &Path, a: &Attached, ms: i64) -> Result<Published, PublishError> {
    publish::commit(
        root,
        a,
        a.scope.trust,
        UnixMillis(ms),
        Instant::now() + Duration::from_secs(60),
        &|| false,
    )
}

fn current_gen(entry: &Path) -> Option<String> {
    fs::read_to_string(entry.join(scope::CURRENT_NAME))
        .ok()
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
}

fn gens(entry: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(entry)
        .map(|rd| {
            rd.filter_map(|e| e.ok())
                .filter_map(|e| e.file_name().to_str().map(str::to_owned))
                .filter(|n| n.starts_with("gen-"))
                .collect()
        })
        .unwrap_or_default();
    names.sort();
    names
}

fn put(dir: &Path, rel: &str, bytes: &[u8]) {
    let path = dir.join(rel);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, bytes).unwrap();
}

fn verify_generation(entry: &Path, name: &str) -> (Manifest, FilesBlob) {
    let dir = entry.join(name);
    let outcome = sentinel_cache::manifest::read(&dir);
    let Outcome::Hit(hit) = outcome else {
        panic!("{name} does not read as a sealed generation: {outcome:?}")
    };
    let blob = read_files(&dir).unwrap();
    assert_eq!(
        blob.digest(),
        hit.manifest.files_digest,
        "{name}: the files blob drifted from the manifest's pin"
    );
    assert_eq!(hit.manifest.files as usize, blob.entries.len());
    for e in &blob.entries {
        let staged = fs::read(dir.join(&e.path))
            .unwrap_or_else(|err| panic!("{name}: listed {} unreadable: {err}", e.path));
        assert_eq!(
            staged.len() as u64,
            e.size,
            "{name}: {} size drifted",
            e.path
        );
        assert_eq!(
            *blake3::hash(&staged).as_bytes(),
            e.digest,
            "{name}: {} content drifted",
            e.path
        );
    }
    (hit.manifest, blob)
}

fn staged_gens(entry: &Path) -> Vec<String> {
    let writing = entry.join(scope::WRITING_NAME);
    fs::read_dir(&writing)
        .map(|rd| {
            rd.filter_map(|e| e.ok())
                .filter_map(|e| e.file_name().to_str().map(str::to_owned))
                .filter(|n| n.starts_with("gen-"))
                .collect()
        })
        .unwrap_or_default()
}

fn now_ms() -> i64 {
    UnixMillis::now().0
}

fn far_future() -> i64 {
    now_ms() + (2 * lease::MAX_TTL.as_millis() as i64)
}

#[test]
fn concurrent_clones_during_republishing_are_never_torn() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("cache");
    let scope = test_scope(Trust::Protected);
    let d = decl(&["view"]);
    let entry = entry_of(&root, &scope, KEY);

    let names: Vec<String> = (0..12).map(|i| format!("sub{}/f{i:02}", i % 3)).collect();
    let view = temp.path().join("writer-view");
    let write_view = |marker: &str| {
        for rel in &names {
            put(&view, rel, marker.as_bytes());
        }
    };

    write_view("w0");
    let seed = attached(scope.clone(), &d, vec![target(view.clone())]);
    let Published::Sealed {
        generation: gen0, ..
    } = commit(&root, &seed, 1_000).unwrap()
    else {
        panic!("the seed generation must seal")
    };
    let markers: Arc<Mutex<BTreeMap<String, String>>> =
        Arc::new(Mutex::new(BTreeMap::from([(gen0, "w0".to_owned())])));
    let stop = Arc::new(AtomicBool::new(false));
    let tmp = temp.path().to_path_buf();

    let readers: Vec<_> = (0..8)
        .map(|r| {
            let (root, scope, markers, tmp, names) = (
                root.clone(),
                scope.clone(),
                Arc::clone(&markers),
                tmp.clone(),
                names.clone(),
            );
            thread::spawn(move || {
                let ws = tmp.join(format!("ws-{r}"));
                fs::create_dir_all(&ws).unwrap();
                let d = decl(&["view"]);
                for _round in 0..24 {
                    let a = restore::restore(
                        &env(&root, &ws),
                        &d,
                        Some(KEY.to_owned()),
                        scope.clone(),
                        &format!("reader-{r}"),
                    );
                    match &a.outcome {
                        Outcome::Hit(_) => {
                            let name = a.generation.as_ref().unwrap();
                            let waited = std::time::Instant::now();
                            let want = loop {
                                if let Some(m) = markers.lock().unwrap().get(name) {
                                    break m.clone();
                                }
                                assert!(
                                    waited.elapsed() < Duration::from_secs(10),
                                    "reader-{r} cloned {name}, never sealed by the writer"
                                );
                                thread::sleep(Duration::from_millis(1));
                            };
                            for rel in &names {
                                assert_eq!(
                                    fs::read(ws.join("view").join(rel)).unwrap(),
                                    want.as_bytes(),
                                    "reader-{r} holds a torn view of {name} at {rel}"
                                );
                            }
                        }
                        Outcome::Miss(miss) => assert!(
                            matches!(miss, Miss::Absent | Miss::Corrupt | Miss::Unavailable),
                            "reader-{r} saw an unexpected miss: {miss:?}"
                        ),
                    }
                }
            })
        })
        .collect();

    let sweeper = thread::spawn({
        let (root, stop) = (root.clone(), Arc::clone(&stop));
        move || {
            while !stop.load(Ordering::Acquire) {
                gc::sweep(&root, 1, gc::DEFAULT_PASS_WORK);
                thread::yield_now();
            }
        }
    });

    for round in 1..=6 {
        write_view(&format!("w{round}"));
        let mut a = attached(scope.clone(), &d, vec![target(view.clone())]);
        a.generation = current_gen(&entry);
        let Published::Sealed { generation, .. } = commit(&root, &a, 1_000 + round as i64)
            .unwrap_or_else(|e| panic!("writer round {round}: {e}"))
        else {
            panic!("writer round {round} must seal")
        };
        markers
            .lock()
            .unwrap()
            .insert(generation, format!("w{round}"));
    }

    stop.store(true, Ordering::Release);
    for (r, reader) in readers.into_iter().enumerate() {
        reader
            .join()
            .unwrap_or_else(|_| panic!("reader-{r} panicked"));
    }
    sweeper.join().unwrap();

    let held = markers.lock().unwrap();
    for name in gens(&entry) {
        let (_, blob) = verify_generation(&entry, &name);
        let want = held[&name].as_bytes();
        for e in &blob.entries {
            assert_eq!(
                fs::read(entry.join(&name).join(&e.path)).unwrap(),
                want,
                "{name} survived the storm but its bytes changed"
            );
        }
    }
}

#[test]
fn a_writer_canceled_mid_stage_promotes_nothing_and_the_store_recovers() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("cache");
    let view = temp.path().join("view");
    for i in 0..800 {
        put(&view, &format!("f{i:04}"), b"x");
    }
    let scope = test_scope(Trust::Protected);
    let d = decl(&["view"]);
    let a = attached(scope.clone(), &d, vec![target(view.clone())]);
    let entry = entry_of(&root, &a.scope, &a.key);

    let Published::Sealed {
        generation: gen_a, ..
    } = commit(&root, &a, 500).unwrap()
    else {
        panic!("the first publish must seal")
    };
    assert_eq!(current_gen(&entry).as_deref(), Some(gen_a.as_str()));

    put(&view, "extra", b"new");
    let mut b = attached(scope.clone(), &d, vec![target(view.clone())]);
    b.generation = Some(gen_a.clone());
    let writing = entry.join(scope::WRITING_NAME);
    let canceled = || {
        fs::read_dir(&writing).is_ok_and(|rd| {
            rd.filter_map(|e| e.ok()).any(|e| {
                e.file_name()
                    .to_str()
                    .is_some_and(|n| n.starts_with("gen-"))
            })
        })
    };
    let out = publish::commit(
        &root,
        &b,
        Trust::Protected,
        UnixMillis(600),
        Instant::now() + Duration::from_secs(60),
        &canceled,
    )
    .unwrap();
    assert_eq!(out, Published::Skipped(SkipReason::Canceled));
    assert_eq!(current_gen(&entry).as_deref(), Some(gen_a.as_str()));
    assert!(staged_gens(&entry).is_empty(), "staging left behind");
    let after = gens(&entry);
    assert_eq!(after, [gen_a.as_str()]);

    let staged = writing.join("gen-1-00000000");
    fs::create_dir_all(staged.join("payload/0")).unwrap();
    fs::write(staged.join("payload/0/partial"), b"half-written").unwrap();
    fs::write(writing.join(lease::WRITE_LOCK_NAME), b"1 dead-writer").unwrap();
    let stats = gc::sweep(&root, gc::DEFAULT_BUDGET_BYTES, gc::DEFAULT_PASS_WORK);
    assert_eq!(stats.writing_removed, 0);
    assert!(writing.exists());
    let stats = gc::sweep_at(
        &root,
        gc::DEFAULT_BUDGET_BYTES,
        gc::DEFAULT_PASS_WORK,
        far_future(),
    );
    assert_eq!(stats.writing_removed, 1);
    assert!(!writing.exists());

    let Published::Sealed {
        generation: gen_b, ..
    } = commit(&root, &b, 700).unwrap()
    else {
        panic!("the recovery publish must seal")
    };
    assert_eq!(current_gen(&entry).as_deref(), Some(gen_b.as_str()));
    verify_generation(&entry, &gen_b);
}

#[test]
fn eviction_during_active_use_never_undercuts_a_lease() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("cache");
    let view = temp.path().join("view");
    let scope = test_scope(Trust::Protected);
    let other = named_scope(&scope, "vendor");
    let d = decl(&["view"]);
    let d2 = Cache {
        name: "vendor".into(),
        ..decl(&["view"])
    };
    let entry1 = entry_of(&root, &scope, KEY);
    let entry2 = entry_of(&root, &other, KEY);

    for (s, dd) in [(&scope, &d), (&other, &d2)] {
        put(&view, "blob", &[7u8; 500]);
        let a = attached(s.clone(), dd, vec![target(view.clone())]);
        let first = commit(&root, &a, 1_000).unwrap();
        assert!(matches!(first, Published::Sealed { .. }));
        put(&view, "blob", &[9u8; 600]);
        let second = commit(&root, &a, 2_000).unwrap();
        assert!(matches!(second, Published::Sealed { .. }));
    }
    assert_eq!(gens(&entry1).len(), 2);
    assert_eq!(gens(&entry2).len(), 2);

    let ws = temp.path().join("ws");
    fs::create_dir(&ws).unwrap();
    let held = restore::restore(
        &env(&root, &ws),
        &d,
        Some(KEY.to_owned()),
        scope.clone(),
        "reader-1",
    );
    assert!(held.outcome.is_hit());
    assert!(held.lease.is_some(), "a hit pins the entry for the attempt");

    let stats = gc::sweep(&root, 1_700, gc::DEFAULT_PASS_WORK);
    assert_eq!(stats.leases_active, 1);
    assert_eq!(
        gens(&entry1).len(),
        2,
        "the leased entry must not be touched"
    );
    assert_eq!(
        gens(&entry2).len(),
        1,
        "the unleashed spare is evicted oldest-first"
    );
    assert_eq!(stats.generations_removed, 1);
    assert_eq!(stats.bytes_freed, 500);
    let ws2 = temp.path().join("ws2");
    fs::create_dir(&ws2).unwrap();
    let again = restore::restore(
        &env(&root, &ws2),
        &d,
        Some(KEY.to_owned()),
        scope.clone(),
        "reader-2",
    );
    assert!(again.outcome.is_hit());

    drop(held);
    drop(again);
    let stats = gc::sweep(&root, 1_200, gc::DEFAULT_PASS_WORK);
    assert_eq!(gens(&entry1).len(), 1, "unpinned, the spare goes");
    assert_eq!(stats.generations_removed, 1);
    assert!(entry1.join(current_gen(&entry1).unwrap()).is_dir());
    assert!(entry2.join(current_gen(&entry2).unwrap()).is_dir());
}

#[test]
fn tampered_state_is_a_typed_miss_and_republish_heals() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("cache");
    let ws = temp.path().join("ws");
    fs::create_dir(&ws).unwrap();
    let view = temp.path().join("view");
    put(&view, "a", b"alpha-bytes");
    put(&view, "b/c", b"nested-bytes");
    let scope = test_scope(Trust::Protected);
    let d = decl(&["view"]);
    let a = attached(scope.clone(), &d, vec![target(view.clone())]);
    let entry = entry_of(&root, &a.scope, &a.key);
    let Published::Sealed {
        generation: gen_a, ..
    } = commit(&root, &a, 1_000).unwrap()
    else {
        panic!("seed publish must seal")
    };
    let gdir = entry.join(&gen_a);
    let payload = |rel: &str| gdir.join("payload/0").join(rel);

    let restore = |ws: &Path| {
        restore::restore(
            &env(&root, ws),
            &d,
            Some(KEY.to_owned()),
            scope.clone(),
            "attempt-t",
        )
    };
    let miss = |a: &Attached| match a.outcome {
        Outcome::Miss(m) => m,
        _ => panic!("expected a miss, got {:?}", a.outcome),
    };

    let hit = restore(&ws);
    assert!(hit.outcome.is_hit());
    assert_eq!(fs::read(ws.join("view/a")).unwrap(), b"alpha-bytes");
    drop(hit);

    let good_files = fs::read(gdir.join(scope::FILES_NAME)).unwrap();
    fs::write(gdir.join(scope::FILES_NAME), FilesBlob::default().encode()).unwrap();
    assert_eq!(miss(&restore(&ws)), Miss::Corrupt);
    fs::write(gdir.join(scope::FILES_NAME), &good_files).unwrap();

    let good_manifest = fs::read(gdir.join(scope::MANIFEST_NAME)).unwrap();
    let mut flipped = good_manifest.clone();
    let last = flipped.len() - 1;
    flipped[last] ^= 0xFF;
    fs::write(gdir.join(scope::MANIFEST_NAME), &flipped).unwrap();
    let outcome = miss(&restore(&ws));
    assert!(
        matches!(outcome, Miss::Corrupt | Miss::Invalid | Miss::Unsealed),
        "a flipped manifest byte must be a typed miss, got {outcome:?}"
    );
    fs::write(gdir.join(scope::MANIFEST_NAME), &good_manifest).unwrap();

    let good_current = fs::read(entry.join(scope::CURRENT_NAME)).unwrap();
    fs::write(entry.join(scope::CURRENT_NAME), b"\xff\xfe not a name").unwrap();
    assert_eq!(miss(&restore(&ws)), Miss::Corrupt);
    fs::write(entry.join(scope::CURRENT_NAME), &good_current).unwrap();

    fs::write(payload("planted"), b"unlisted-bytes").unwrap();
    let tampered = restore(&ws);
    assert_eq!(miss(&tampered), Miss::Corrupt);
    assert!(
        !ws.join("view/planted").exists(),
        "planted bytes must never be served"
    );
    fs::remove_file(payload("planted")).unwrap();

    fs::remove_file(payload("b/c")).unwrap();
    assert_eq!(miss(&restore(&ws)), Miss::Corrupt);
    put(&gdir, "payload/0/b/c", b"nested-bytes");

    #[cfg(unix)]
    {
        fs::remove_file(payload("a")).unwrap();
        std::os::unix::fs::symlink("/etc/hostname", payload("a")).unwrap();
        assert_eq!(miss(&restore(&ws)), Miss::Corrupt);
        fs::remove_file(payload("a")).unwrap();
        put(&gdir, "payload/0/a", b"alpha-bytes");
    }

    assert!(restore(&ws).outcome.is_hit());
    put(&view, "healed", b"after-republish");
    let Published::Sealed {
        generation: gen_b, ..
    } = commit(&root, &a, 2_000).unwrap()
    else {
        panic!("the healing publish must seal")
    };
    assert_eq!(current_gen(&entry).as_deref(), Some(gen_b.as_str()));
    let healed = restore(&ws);
    assert!(healed.outcome.is_hit());
    assert_eq!(
        fs::read(ws.join("view/healed")).unwrap(),
        b"after-republish"
    );
    verify_generation(&entry, &gen_b);
}

#[test]
fn protected_state_never_serves_or_writes_pull_request() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("cache");
    let ws = temp.path().join("ws");
    fs::create_dir(&ws).unwrap();
    let view = temp.path().join("view");
    put(&view, "lib", b"protected-bytes");
    let protected = test_scope(Trust::Protected);
    let mut pr = protected.clone();
    pr.trust = Trust::PullRequest;
    let d = decl(&["view"]);
    let protected_entry = entry_of(&root, &protected, KEY);
    let pr_entry = entry_of(&root, &pr, KEY);
    assert_ne!(protected_entry, pr_entry, "the trust is a path boundary");

    let a = attached(protected.clone(), &d, vec![target(view.clone())]);
    let Published::Sealed {
        generation: gen_p, ..
    } = commit(&root, &a, 1_000).unwrap()
    else {
        panic!("protected publish must seal")
    };

    let pr_restore = |ws: &Path| {
        restore::restore(
            &env(&root, ws),
            &d,
            Some(KEY.to_owned()),
            pr.clone(),
            "pr-attempt",
        )
    };
    let r = pr_restore(&ws);
    assert_eq!(r.outcome, Outcome::Miss(Miss::Absent));

    fs::create_dir_all(&pr_entry).unwrap();
    copy_tree(&gdir(&protected_entry, &gen_p), &pr_entry.join(&gen_p));
    fs::write(pr_entry.join(scope::CURRENT_NAME), &gen_p).unwrap();
    let r = pr_restore(&ws);
    assert_eq!(r.outcome, Outcome::Miss(Miss::WrongTrust));
    assert!(!ws.join("view/lib").exists());

    put(&view, "lib", b"pr-bytes");
    let pa = attached(pr.clone(), &d, vec![target(view.clone())]);
    let Published::Sealed {
        generation: gen_pr, ..
    } = publish::commit(
        &root,
        &pa,
        Trust::PullRequest,
        UnixMillis(2_000),
        Instant::now() + Duration::from_secs(60),
        &|| false,
    )
    .unwrap()
    else {
        panic!("pr publish must seal")
    };

    assert!(pr_entry.join(&gen_pr).is_dir());
    assert_eq!(current_gen(&pr_entry).as_deref(), Some(gen_pr.as_str()));
    assert_eq!(gens(&protected_entry), [gen_p.as_str()]);
    assert_eq!(
        current_gen(&protected_entry).as_deref(),
        Some(gen_p.as_str())
    );
    let protected_scope = protected.dir(&root);
    let entries: Vec<_> = fs::read_dir(&protected_scope)
        .unwrap()
        .filter_map(|e| e.ok())
        .collect();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].path(), protected_entry);

    let err = publish::commit(
        &root,
        &pa,
        Trust::Protected,
        UnixMillis(3_000),
        Instant::now() + Duration::from_secs(60),
        &|| false,
    )
    .unwrap_err();
    assert!(matches!(err, PublishError::TrustMismatch));

    fs::remove_dir_all(pr_entry.join(&gen_p)).unwrap();
    fs::write(pr_entry.join(scope::CURRENT_NAME), &gen_pr).unwrap();
    let r = pr_restore(&ws);
    assert!(r.outcome.is_hit());
    assert_eq!(fs::read(ws.join("view/lib")).unwrap(), b"pr-bytes");
}

fn gdir(entry: &Path, name: &str) -> PathBuf {
    entry.join(name)
}

fn copy_tree(src: &Path, dst: &Path) {
    fs::create_dir_all(dst).unwrap();
    for e in fs::read_dir(src).unwrap() {
        let e = e.unwrap();
        let to = dst.join(e.file_name());
        if e.file_type().unwrap().is_dir() {
            copy_tree(&e.path(), &to);
        } else {
            fs::copy(e.path(), &to).unwrap();
        }
    }
}

#[test]
fn parallel_writers_are_serialized_and_never_double_promote() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("cache");
    let view = temp.path().join("view");
    put(&view, "f", b"bytes");
    let scope = test_scope(Trust::Protected);
    let d = decl(&["view"]);
    let entry = entry_of(&root, &scope, KEY);

    let held = WriteLock::acquire(&entry, "held-writer").unwrap().unwrap();
    for _ in 0..2 {
        let a = attached(scope.clone(), &d, vec![target(view.clone())]);
        assert_eq!(
            commit(&root, &a, 1_000).unwrap(),
            Published::Skipped(SkipReason::Busy)
        );
    }
    assert!(current_gen(&entry).is_none());
    drop(held);

    let slow_view = temp.path().join("slow-view");
    for i in 0..1_500 {
        put(&slow_view, &format!("f{i:04}"), b"s");
    }
    let fast_view = temp.path().join("fast-view");
    let mut busy_seen = false;
    for round in 0..8i64 {
        put(&fast_view, "round", format!("{round}").as_bytes());
        put(&slow_view, "round", format!("{round}").as_bytes());
        let barrier = Arc::new(Barrier::new(2));
        let spawn = |dir: PathBuf, ms: i64| {
            let (root, scope, barrier) = (root.clone(), scope.clone(), Arc::clone(&barrier));
            thread::spawn(move || {
                let d = decl(&["view"]);
                let mut a = attached(scope, &d, vec![target(dir)]);
                a.generation = current_gen(
                    &a.scope
                        .entry_dir(&root, entry_key(Class::Dependencies, KEY)),
                );
                barrier.wait();
                publish::commit(
                    &root,
                    &a,
                    Trust::Protected,
                    UnixMillis(ms),
                    Instant::now() + Duration::from_secs(60),
                    &|| false,
                )
            })
        };
        let slow = spawn(slow_view.clone(), 10_000 + round * 10);
        let fast = spawn(fast_view.clone(), 10_000 + round * 10 + 1);
        let slow_out = slow.join().unwrap().unwrap();
        let fast_out = fast.join().unwrap().unwrap();
        for out in [&slow_out, &fast_out] {
            assert!(
                matches!(
                    out,
                    Published::Sealed { .. } | Published::Skipped(SkipReason::Busy)
                ),
                "a raced writer must seal or skip busy, got {out:?}"
            );
        }
        busy_seen |= matches!(slow_out, Published::Skipped(SkipReason::Busy))
            || matches!(fast_out, Published::Skipped(SkipReason::Busy));
        assert!(staged_gens(&entry).is_empty());
        let cur = current_gen(&entry).expect("a sealed generation must be current");
        verify_generation(&entry, &cur);
        if busy_seen {
            break;
        }
    }
    assert!(
        busy_seen,
        "eight raced rounds never produced a `busy`: the lock does not exclude"
    );
    for name in gens(&entry) {
        verify_generation(&entry, &name);
    }
}

#[test]
fn only_a_jobs_own_trust_promotes_or_is_served_across_every_pairing() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("cache");
    let d = decl(&["view"]);
    let base = test_scope(Trust::Protected);
    let scope_for = |trust: Trust| {
        let mut s = base.clone();
        s.trust = trust;
        s
    };

    // A mismatched pairing is refused before a directory exists; the matching one seals its own bytes.
    for scope_trust in Trust::ALL {
        for job_trust in Trust::ALL {
            let view = temp
                .path()
                .join(format!("view-{scope_trust:?}-{job_trust:?}"));
            put(&view, "lib", format!("{scope_trust:?}").as_bytes());
            let scope = scope_for(scope_trust);
            let a = attached(scope.clone(), &d, vec![target(view)]);
            let entry = entry_of(&root, &scope, KEY);
            let had_current = current_gen(&entry);
            let out = publish::commit(
                &root,
                &a,
                job_trust,
                UnixMillis(1_000),
                Instant::now() + Duration::from_secs(60),
                &|| false,
            );
            if scope_trust == job_trust {
                assert!(matches!(out, Ok(Published::Sealed { .. })), "{out:?}");
            } else {
                assert!(
                    matches!(out, Err(PublishError::TrustMismatch)),
                    "{scope_trust:?} scope under a {job_trust:?} job: {out:?}"
                );
                assert_eq!(
                    current_gen(&entry),
                    had_current,
                    "a refused commit must not move {scope_trust:?} state"
                );
            }
        }
    }

    // Each trust class holds exactly the one generation its own matching job sealed.
    for trust in Trust::ALL {
        let scope = scope_for(trust);
        let entry = entry_of(&root, &scope, KEY);
        assert_eq!(gens(&entry).len(), 1, "{trust:?} sealed once");
        let ws = temp.path().join(format!("ws-{trust:?}"));
        fs::create_dir(&ws).unwrap();
        let r = restore::restore(&env(&root, &ws), &d, Some(KEY.to_owned()), scope, "own");
        assert!(r.outcome.is_hit(), "{trust:?}: {:?}", r.outcome);
        assert_eq!(
            fs::read(ws.join("view/lib")).unwrap(),
            format!("{trust:?}").as_bytes()
        );
    }

    // A generation moved under another trust's entry directory is a typed miss, in every direction.
    for from in Trust::ALL {
        for to in Trust::ALL.into_iter().filter(|t| *t != from) {
            let source = entry_of(&root, &scope_for(from), KEY);
            let name = current_gen(&source).unwrap();
            let dest = entry_of(&root, &scope_for(to), KEY);
            let backup = temp.path().join(format!("held-{from:?}-{to:?}"));
            fs::rename(&dest, &backup).unwrap();
            fs::create_dir_all(&dest).unwrap();
            copy_tree(&gdir(&source, &name), &dest.join(&name));
            fs::write(dest.join(scope::CURRENT_NAME), &name).unwrap();
            let ws = temp.path().join(format!("mws-{from:?}-{to:?}"));
            fs::create_dir(&ws).unwrap();
            let r = restore::restore(
                &env(&root, &ws),
                &d,
                Some(KEY.to_owned()),
                scope_for(to),
                "moved",
            );
            assert_eq!(
                r.outcome,
                Outcome::Miss(Miss::WrongTrust),
                "{from:?} state under {to:?}"
            );
            assert!(
                !ws.join("view/lib").exists(),
                "wrong-trust bytes reached a view"
            );
            drop(r);
            fs::remove_dir_all(&dest).unwrap();
            fs::rename(&backup, &dest).unwrap();
        }
    }
}

#[test]
fn a_sweep_running_inside_a_publish_cannot_take_the_entry_being_written() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("cache");
    let view = temp.path().join("view");
    let scope = test_scope(Trust::Protected);
    let sibling = named_scope(&scope, "vendor");
    let d = decl(&["view"]);
    let d2 = Cache {
        name: "vendor".into(),
        ..decl(&["view"])
    };
    let entry = entry_of(&root, &scope, KEY);
    let sibling_entry = entry_of(&root, &sibling, KEY);
    put(&view, "blob", &[1u8; 400]);
    let mut first = None;
    for (s, dd) in [(&scope, &d), (&sibling, &d2)] {
        let a = attached(s.clone(), dd, vec![target(view.clone())]);
        let Published::Sealed { generation, .. } = commit(&root, &a, 1_000).unwrap() else {
            panic!("setup publish must seal")
        };
        first.get_or_insert(generation);
    }
    let gen_a = first.unwrap();

    // A one-byte budget forces whole-entry eviction of every entry the pass may take. The sweep runs from
    // inside the commit (the cancel poll), while the commit's pin and writer marker are held.
    put(&view, "blob", &[2u8; 500]);
    let mut b = attached(scope.clone(), &d, vec![target(view.clone())]);
    b.generation = Some(gen_a.clone());
    // The first poll precedes the pin; the second is the plan check, with the pin and the marker held.
    let polls = std::sync::atomic::AtomicUsize::new(0);
    let during = Mutex::new(None);
    let cancel = || {
        if polls.fetch_add(1, Ordering::SeqCst) == 1 {
            *during.lock().unwrap() = Some(gc::sweep(&root, 1, gc::DEFAULT_PASS_WORK));
        }
        false
    };
    let out = publish::commit(
        &root,
        &b,
        Trust::Protected,
        UnixMillis(2_000),
        Instant::now() + Duration::from_secs(60),
        &cancel,
    )
    .unwrap();
    let stats = during.lock().unwrap().take().expect("the cancel poll ran");
    assert!(
        stats.leases_active >= 1,
        "the commit's pin was visible: {stats:?}"
    );
    assert!(
        !sibling_entry.exists(),
        "control: the same sweep did evict the unwritten entry: {stats:?}"
    );
    let Published::Sealed {
        generation: gen_b, ..
    } = out
    else {
        panic!("the publish must survive the sweep, got {out:?}")
    };
    assert_eq!(current_gen(&entry).as_deref(), Some(gen_b.as_str()));
    verify_generation(&entry, &gen_b);
    assert!(
        entry.join(&gen_a).is_dir(),
        "the source generation was kept"
    );
    assert!(staged_gens(&entry).is_empty());
}

#[test]
fn a_live_writer_keeps_its_entry_through_eviction_and_a_busy_loser_leaves_it_alone() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("cache");
    let view = temp.path().join("view");
    put(&view, "f", &[3u8; 300]);
    let scope = test_scope(Trust::Protected);
    let d = decl(&["view"]);
    let a = attached(scope.clone(), &d, vec![target(view)]);
    let entry = entry_of(&root, &scope, KEY);
    let Published::Sealed { generation, .. } = commit(&root, &a, 1_000).unwrap() else {
        panic!("setup publish must seal")
    };

    let writer = WriteLock::acquire(&entry, "other-process")
        .unwrap()
        .unwrap();
    assert_eq!(
        commit(&root, &a, 2_000).unwrap(),
        Published::Skipped(SkipReason::Busy)
    );
    assert!(
        lease::writing_lock_live(&entry, now_ms()),
        "the loser must not have removed the holder's marker"
    );
    let stats = gc::sweep(&root, 1, gc::DEFAULT_PASS_WORK);
    assert_eq!(stats.entries_removed, 0, "{stats:?}");
    assert_eq!(current_gen(&entry).as_deref(), Some(generation.as_str()));
    verify_generation(&entry, &generation);

    drop(writer);
    let stats = gc::sweep(&root, 1, gc::DEFAULT_PASS_WORK);
    assert_eq!(
        stats.entries_removed, 1,
        "released, the entry is evictable: {stats:?}"
    );
    assert!(!entry.exists());
}

#[cfg(target_os = "linux")]
#[test]
fn a_full_filesystem_fails_the_publish_cleanly() {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    if std::env::var_os("SENTINEL_MOUNT_TESTS").is_none() {
        eprintln!("skipped: set SENTINEL_MOUNT_TESTS=1 as a mount-capable account to run");
        return;
    }
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("cache");
    fs::create_dir(&root).unwrap();
    let target_c = CString::new(root.as_os_str().as_bytes()).unwrap();
    // SAFETY: mount(2) takes NUL-terminated strings held by `target_c`
    // and the literals; the mount point exists and outlives the call.
    let rc = unsafe {
        libc::mount(
            c"tmpfs".as_ptr(),
            target_c.as_ptr(),
            c"tmpfs".as_ptr(),
            0,
            c"size=8m".as_ptr() as *const _,
        )
    };
    if rc != 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EPERM) {
            eprintln!("skipped: mount(2) not permitted in this environment");
            return;
        }
        panic!("tmpfs mount failed: {err}");
    }
    struct Guard(PathBuf);
    impl Drop for Guard {
        fn drop(&mut self) {
            // SAFETY: detaches the mount the test made; the path bytes
            // live in the CString rebuilt here.
            let c = CString::new(self.0.as_os_str().as_bytes()).unwrap();
            unsafe {
                libc::umount2(c.as_ptr(), libc::MNT_DETACH);
            }
        }
    }
    let _guard = Guard(root.clone());

    let scope = test_scope(Trust::Protected);
    let d = decl(&["view"]);
    let small = temp.path().join("small-view");
    put(&small, "seed", b"seed-bytes");
    let a = attached(scope.clone(), &d, vec![target(small)]);
    let Published::Sealed {
        generation: gen_a, ..
    } = commit(&root, &a, 1_000).unwrap()
    else {
        panic!("the seed publish must seal")
    };
    let entry = entry_of(&root, &a.scope, &a.key);
    assert_eq!(current_gen(&entry).as_deref(), Some(gen_a.as_str()));

    let filler = root.join("filler");
    let mut written = 0u64;
    let chunk = [0u8; 64 << 10];
    loop {
        match fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(&filler)
        {
            Ok(mut f) => {
                use std::io::Write;
                match f.write_all(&chunk) {
                    Ok(()) => written += chunk.len() as u64,
                    Err(_) => break,
                }
            }
            Err(_) => break,
        }
        if written > 8 << 20 {
            panic!("tmpfs never filled — the mount did not take")
        }
    }
    let freed = 256 << 10;
    fs::OpenOptions::new()
        .write(true)
        .open(&filler)
        .unwrap()
        .set_len(written.saturating_sub(freed))
        .unwrap();

    let big = temp.path().join("big-view");
    for i in 0..64 {
        put(&big, &format!("blob{i:02}"), &[5u8; 64 << 10]);
    }
    let mut b = attached(scope, &d, vec![target(big)]);
    b.generation = Some(gen_a.clone());
    let out = commit(&root, &b, 2_000);
    assert!(
        matches!(out, Err(PublishError::NoSpace | PublishError::Io(_))),
        "a full filesystem must fail the publish, got {out:?}"
    );
    assert_eq!(current_gen(&entry).as_deref(), Some(gen_a.as_str()));
    assert_eq!(gens(&entry), [gen_a.as_str()]);
    assert!(staged_gens(&entry).is_empty());

    fs::remove_file(&filler).unwrap();
    let out = commit(&root, &b, 3_000).unwrap();
    let Published::Sealed {
        generation: gen_b, ..
    } = out
    else {
        panic!("with space back the publish must seal, got {out:?}")
    };
    assert_eq!(current_gen(&entry).as_deref(), Some(gen_b.as_str()));
}
