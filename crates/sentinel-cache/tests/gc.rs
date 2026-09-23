//! Reclamation behavior (K03): leases pin entries, stale staging is
//! collected, retention keeps `current` plus one spare, and the byte
//! budget evicts oldest-first — all through `gc::sweep_at` so the clock
//! can be moved without waiting out `MAX_TTL`.

use std::{
    fs,
    path::{Path, PathBuf},
    time::Duration,
};

use sentinel_cache::{
    attach::entry_key,
    gc::{self, sweep_at},
    lease::{self, Lease},
    manifest::{Compat, FilesBlob, Manifest},
    scope::{self, Os, Platform, Scope},
};
use sentinel_core::{RepoId, TenantId, UnixMillis};
use sentinel_protocol::{
    cache::{Class, Trust},
    negotiate::Arch,
};

fn test_scope(name: &str) -> Scope {
    Scope::new(
        TenantId::new(),
        RepoId::new(),
        Class::Dependencies,
        Trust::Protected,
        Platform {
            os: Os::Linux,
            arch: Arch::X86_64,
        },
        Scope::toolchain_digest(b"rust linux test"),
        name,
    )
    .unwrap()
}

fn entry(root: &Path, scope: &Scope, key: &str) -> PathBuf {
    scope.entry_dir(root, entry_key(scope.class, key))
}

fn now_ms() -> i64 {
    UnixMillis::now().0
}

/// A sealed generation directory carrying a manifest that claims `bytes`
/// of payload — enough for the sweep to account it — plus one real file
/// so the tree is not empty.
fn make_gen(entry: &Path, scope: &Scope, key: &str, name: &str, bytes: u64) -> PathBuf {
    let dir = entry.join(name);
    fs::create_dir_all(dir.join("payload/0")).unwrap();
    fs::write(
        dir.join("payload/0/blob"),
        vec![0u8; bytes.min(4096) as usize],
    )
    .unwrap();
    let blob = FilesBlob::default();
    fs::write(dir.join(scope::FILES_NAME), blob.encode()).unwrap();
    let mut manifest = Manifest::writing(
        scope,
        key,
        Compat::Dependencies {
            lock: [3; 32],
            installer: "cargo".to_owned(),
            flags: String::new(),
            abi: "test".to_owned(),
        },
    );
    manifest.bytes = bytes;
    manifest.files = 0;
    manifest.files_digest = blob.digest();
    manifest.seal(UnixMillis(now_ms()));
    fs::write(dir.join(scope::MANIFEST_NAME), manifest.encode()).unwrap();
    dir
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

fn set_current(entry: &Path, name: &str) {
    fs::write(entry.join(scope::CURRENT_NAME), name).unwrap();
}

/// `sweep_at` with the clock pushed past `MAX_TTL`, so anything mtime-bound
/// reads stale.
fn far_future() -> i64 {
    now_ms() + (2 * lease::MAX_TTL.as_millis() as i64)
}

#[test]
fn an_active_lease_keeps_every_generation() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("cache");
    let scope = test_scope("deps");
    let entry = entry(&root, &scope, "deps-aa");
    make_gen(&entry, &scope, "deps-aa", "gen-100-00000001", 100);
    make_gen(&entry, &scope, "deps-aa", "gen-200-00000002", 100);
    make_gen(&entry, &scope, "deps-aa", "gen-300-00000003", 100);
    set_current(&entry, "gen-300-00000003");

    // A reader mid-clone pins the whole entry: not even the oldest
    // non-current generation may go.
    let pin = Lease::acquire(&entry, "reader-1", lease::DEFAULT_TTL).unwrap();
    let stats = sweep_at(
        &root,
        gc::DEFAULT_BUDGET_BYTES,
        gc::DEFAULT_PASS_WORK,
        now_ms(),
    );
    assert_eq!(stats.entries_seen, 1);
    assert_eq!(stats.leases_active, 1);
    assert_eq!(stats.generations_removed, 0);
    assert_eq!(gens(&entry).len(), 3);
    // K08: a pinned entry still reports its occupancy — the availability
    // snapshot sees the whole store, removals or not.
    assert_eq!(stats.generations_seen, 3);
    assert_eq!(stats.payload_bytes, 300);
    pin.release().unwrap();
}

#[test]
fn an_expired_lease_lets_old_generations_go() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("cache");
    let scope = test_scope("deps");
    let entry = entry(&root, &scope, "deps-aa");
    make_gen(&entry, &scope, "deps-aa", "gen-100-00000001", 100);
    make_gen(&entry, &scope, "deps-aa", "gen-200-00000002", 100);
    make_gen(&entry, &scope, "deps-aa", "gen-300-00000003", 100);
    set_current(&entry, "gen-300-00000003");

    // A marker that expired long ago — the body declares it, so its fresh
    // mtime cannot keep it alive.
    let lease_dir = entry.join(scope::LEASE_NAME);
    fs::create_dir_all(&lease_dir).unwrap();
    fs::write(lease_dir.join("l-dead"), b"1 dead-reader").unwrap();

    let stats = sweep_at(
        &root,
        gc::DEFAULT_BUDGET_BYTES,
        gc::DEFAULT_PASS_WORK,
        now_ms(),
    );
    assert_eq!(stats.leases_expired, 1);
    // current + the one spare stay; the oldest goes.
    assert_eq!(
        gens(&entry),
        ["gen-200-00000002".to_owned(), "gen-300-00000003".to_owned()]
    );
    assert_eq!(stats.generations_removed, 1);
    assert_eq!(stats.bytes_freed, 100);
    assert!(!lease_dir.join("l-dead").exists());
}

#[test]
fn retention_keeps_current_plus_one_spare_oldest_first() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("cache");
    let scope = test_scope("deps");
    let entry = entry(&root, &scope, "deps-aa");
    for (i, name) in [
        "gen-1-00000001",
        "gen-2-00000002",
        "gen-3-00000003",
        "gen-4-00000004",
    ]
    .iter()
    .enumerate()
    {
        make_gen(&entry, &scope, "deps-aa", name, 10 + i as u64);
    }
    // `current` names the second-oldest: the newest still stays as the
    // spare — retention never removes the two newest slots' worth.
    set_current(&entry, "gen-2-00000002");
    let stats = sweep_at(
        &root,
        gc::DEFAULT_BUDGET_BYTES,
        gc::DEFAULT_PASS_WORK,
        now_ms(),
    );
    assert_eq!(stats.generations_removed, 2);
    assert_eq!(
        gens(&entry),
        ["gen-2-00000002".to_owned(), "gen-4-00000004".to_owned()]
    );
    assert_eq!(stats.bytes_freed, 10 + 12);
    // Occupancy counts what the pass saw, before its own removals.
    assert_eq!(stats.generations_seen, 4);
    assert_eq!(stats.payload_bytes, 10 + 11 + 12 + 13);
}

#[test]
fn over_budget_evicts_oldest_first_across_entries() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("cache");
    let s1 = test_scope("deps");
    let s2 = test_scope("vendor");
    let e1 = entry(&root, &s1, "deps-aa");
    let e2 = entry(&root, &s2, "vendor-bb");

    // e1: current 600 + spare 600.  e2: current 600 + spare 600.
    make_gen(&e1, &s1, "deps-aa", "gen-100-00000001", 600);
    make_gen(&e1, &s1, "deps-aa", "gen-300-00000003", 600);
    set_current(&e1, "gen-300-00000003");
    make_gen(&e2, &s2, "vendor-bb", "gen-200-00000002", 600);
    make_gen(&e2, &s2, "vendor-bb", "gen-400-00000004", 600);
    set_current(&e2, "gen-400-00000004");

    // Total 2400; budget 1200 → both spares evicted, oldest first, and
    // the two currents fit.
    let stats = sweep_at(&root, 1200, gc::DEFAULT_PASS_WORK, now_ms());
    assert_eq!(gens(&e1), ["gen-300-00000003".to_owned()]);
    assert_eq!(gens(&e2), ["gen-400-00000004".to_owned()]);
    assert_eq!(stats.generations_removed, 2);
    assert_eq!(stats.bytes_freed, 1200);

    // With a tighter budget the spares go first, then whole entries least
    // recently used first (P07-3): e2 was last used before e1, so it goes
    // and e1's current — enough to fit 700 bytes — stays.
    make_gen(&e1, &s1, "deps-aa", "gen-500-00000005", 600);
    set_current(&e1, "gen-500-00000005");
    age_current(&e2, 3_600_000);
    let stats = sweep_at(&root, 700, gc::DEFAULT_PASS_WORK, now_ms());
    assert_eq!(gens(&e1), ["gen-500-00000005".to_owned()]);
    assert!(!e2.exists(), "the least recently used entry went whole");
    assert_eq!(stats.entries_removed, 1);
    assert_eq!(stats.generations_removed, 2);
    assert_eq!(stats.estimated_bytes, 600);
}

/// Move `current`'s mtime `ms` into the past: its last use.
fn age_current(entry: &Path, ms: u64) {
    let file = fs::OpenOptions::new()
        .write(true)
        .open(entry.join(scope::CURRENT_NAME))
        .unwrap();
    file.set_modified(std::time::SystemTime::now() - Duration::from_millis(ms))
        .unwrap();
}

/// P07-3: the currents of stale keys are reclaimable — twenty entries
/// over a tiny budget all go, and an entry idle past `IDLE_TTL` goes
/// whole even under budget; a pinned one never does.
#[test]
fn budget_evicts_idle_currents_lru_and_ttl_removes_idle_entries() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("cache");
    let scope = test_scope("deps");
    let mut entries = Vec::new();
    for i in 0..20 {
        let key = format!("deps-{i:04}");
        let e = entry(&root, &scope, &key);
        make_gen(&e, &scope, &key, "gen-100-00000001", 64 << 10);
        set_current(&e, "gen-100-00000001");
        age_current(&e, (20 - i) * 1000);
        entries.push(e);
    }
    let pin = Lease::acquire(&entries[0], "reader-1", lease::DEFAULT_TTL).unwrap();
    let stats = sweep_at(&root, 1, gc::DEFAULT_PASS_WORK, now_ms());
    assert_eq!(stats.entries_removed, 19, "every unpinned current went");
    assert_eq!(stats.bytes_freed, 19 * (64 << 10));
    assert!(entries[0].exists(), "a leased current survives the budget");
    drop(pin);

    // Idle past the TTL: removed although the store is under budget, and
    // the empty scope directories go with it.
    age_current(&entries[0], gc::IDLE_TTL.as_millis() as u64 + 1000);
    let stats = sweep_at(
        &root,
        gc::DEFAULT_BUDGET_BYTES,
        gc::DEFAULT_PASS_WORK,
        now_ms(),
    );
    assert_eq!(stats.entries_removed, 1);
    assert!(!entries[0].exists());
    assert_eq!(
        fs::read_dir(&root).unwrap().count(),
        0,
        "no empty scope directories linger"
    );
}

/// P07-4: with a cursor, passes truncated by the work bound resume where
/// the previous one stopped — together they visit every entry — and each
/// truncated pass still enforces the budget.
#[test]
fn truncated_passes_cover_every_entry_and_still_enforce_the_budget() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("cache");
    let scope = test_scope("deps");
    for i in 0..20 {
        let key = format!("deps-{i:04}");
        let e = entry(&root, &scope, &key);
        make_gen(&e, &scope, &key, "gen-100-00000001", 10);
        set_current(&e, "gen-100-00000001");
    }
    let mut cursor = gc::Cursor::default();
    let mut seen = 0;
    let mut passes = 0;
    loop {
        let stats = gc::resume_at(&root, gc::DEFAULT_BUDGET_BYTES, 40, now_ms(), &mut cursor);
        seen += stats.entries_seen;
        passes += 1;
        assert!(passes < 50, "the passes never finished a cycle");
        if !stats.truncated {
            break;
        }
    }
    assert!(passes > 1, "the bound must have truncated at least once");
    assert!(seen >= 20, "successive passes covered every entry: {seen}");
    // The full cycle measured 200 bytes; a truncated pass over budget
    // evicts from what it saw even though it saw only part of the tree.
    let stats = gc::resume_at(&root, 150, 40, now_ms(), &mut cursor);
    assert!(stats.truncated);
    assert!(
        stats.entries_removed > 0,
        "budget enforced despite truncation"
    );
}

#[test]
fn stale_staging_is_removed_but_a_fresh_one_stays() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("cache");
    let scope = test_scope("deps");
    let entry = entry(&root, &scope, "deps-aa");
    make_gen(&entry, &scope, "deps-aa", "gen-100-00000001", 100);
    set_current(&entry, "gen-100-00000001");

    // A crashed writer's remains: staging dir and a dead lock marker.
    let writing = entry.join(scope::WRITING_NAME);
    fs::create_dir_all(writing.join("gen-999-00000009")).unwrap();
    fs::write(writing.join(lease::WRITE_LOCK_NAME), b"1 dead-writer").unwrap();

    // At the real clock the directory is too fresh to reap — a writer
    // between `create_dir_all` and its marker must never lose its staging.
    let stats = sweep_at(
        &root,
        gc::DEFAULT_BUDGET_BYTES,
        gc::DEFAULT_PASS_WORK,
        now_ms(),
    );
    assert_eq!(stats.writing_removed, 0);
    assert!(writing.exists());

    // Past the lease bound, the dead writer's tree collects.
    let stats = sweep_at(
        &root,
        gc::DEFAULT_BUDGET_BYTES,
        gc::DEFAULT_PASS_WORK,
        far_future(),
    );
    assert_eq!(stats.writing_removed, 1);
    assert!(!writing.exists());
}

#[test]
fn a_corrupt_current_is_noted_never_panics_and_never_served() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("cache");
    let scope = test_scope("deps");
    let entry = entry(&root, &scope, "deps-aa");
    make_gen(&entry, &scope, "deps-aa", "gen-100-00000001", 100);
    make_gen(&entry, &scope, "deps-aa", "gen-200-00000002", 100);
    // The pointer names a generation that does not exist.
    set_current(&entry, "gen-9-00000009");

    let stats = sweep_at(
        &root,
        gc::DEFAULT_BUDGET_BYTES,
        gc::DEFAULT_PASS_WORK,
        now_ms(),
    );
    assert_eq!(stats.stale_current, 1);
    // With nothing current to keep, retention still leaves the newest.
    assert_eq!(gens(&entry), ["gen-200-00000002".to_owned()]);

    // Garbage bytes in the pointer read the same way — no panic.
    fs::write(entry.join(scope::CURRENT_NAME), b"\xff\xfe not a name").unwrap();
    let stats = sweep_at(
        &root,
        gc::DEFAULT_BUDGET_BYTES,
        gc::DEFAULT_PASS_WORK,
        now_ms(),
    );
    assert_eq!(stats.stale_current, 1);
    assert_eq!(stats.errors, 0);
}

#[test]
fn the_work_bound_stops_a_pass_cleanly() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("cache");
    // More scope directories than the bound visits.
    for i in 0..20 {
        let scope = test_scope(&format!("cache{i:02}"));
        let entry = entry(&root, &scope, "k");
        make_gen(&entry, &scope, "k", "gen-100-00000001", 1);
        set_current(&entry, "gen-100-00000001");
    }
    let stats = sweep_at(&root, gc::DEFAULT_BUDGET_BYTES, 5, now_ms());
    assert!(stats.truncated);
    // A later full pass still completes the work.
    let full = sweep_at(
        &root,
        gc::DEFAULT_BUDGET_BYTES,
        gc::DEFAULT_PASS_WORK,
        now_ms(),
    );
    assert!(!full.truncated);
    assert_eq!(full.entries_seen, 20);
}

#[test]
fn a_missing_root_is_an_empty_pass() {
    let tmp = tempfile::tempdir().unwrap();
    let stats = gc::sweep(
        &tmp.path().join("no-cache"),
        gc::DEFAULT_BUDGET_BYTES,
        gc::DEFAULT_PASS_WORK,
    );
    assert_eq!(stats, gc::GcStats::default());
}

#[test]
fn a_reader_mid_clone_keeps_its_generation_through_budget_eviction() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("cache");
    let scope = test_scope("deps");
    let entry = entry(&root, &scope, "deps-aa");
    make_gen(&entry, &scope, "deps-aa", "gen-100-00000001", 600);
    make_gen(&entry, &scope, "deps-aa", "gen-200-00000002", 600);
    set_current(&entry, "gen-200-00000002");

    // The reader's pin protects even the non-current spare it cloned.
    let pin = Lease::acquire(&entry, "reader-2", Duration::from_secs(60)).unwrap();
    let stats = sweep_at(&root, 10, gc::DEFAULT_PASS_WORK, now_ms());
    assert_eq!(stats.generations_removed, 0);
    assert_eq!(gens(&entry).len(), 2);
    pin.release().unwrap();

    // After release, the same pass may evict it — and, still over the
    // budget, the whole entry with its current.
    let stats = sweep_at(&root, 10, gc::DEFAULT_PASS_WORK, now_ms());
    assert_eq!(stats.generations_removed, 2);
    assert_eq!(stats.entries_removed, 1);
    assert!(!entry.exists());
}
