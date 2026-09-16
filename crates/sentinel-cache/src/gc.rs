//! K03 — reclamation: a bounded pass over the cache tree that sweeps
//! expired lease markers, removes staging a dead writer left in
//! `writing/`, keeps at most `current` plus one spare generation per
//! entry, and evicts non-current generations oldest-first while the store
//! is over budget.
//!
//! A lease pins its whole entry: while any marker under `<entry>/lease/`
//! is live, nothing inside that entry is collected — a reader mid-clone
//! or a writer mid-publish is never undercut. A generation that was never
//! `current` is removed oldest-first; the generation a `current` names is
//! never deleted, so a pinned or current generation can always serve.
//!
//! The pass is bounded by a work counter (`DEFAULT_PASS_WORK`): every
//! directory entry enumerated and every tree removed counts, and hitting
//! the bound stops the pass cleanly — `truncated` is set and the next
//! pass continues. Removal failures are counted in `errors`, never
//! panic, never abort the pass.

use std::{
    fs,
    io::ErrorKind,
    path::{Path, PathBuf},
};

use crate::{lease, manifest, scope};

/// The byte budget a `cache/` root holds before a pass evicts non-current
/// generations (docs/cache.md). A fixed ceiling, not a config key: the
/// worker's data dir has no size knob today, and 50 GiB keeps a warm
/// worker under any plausible checkout-plus-cache pressure.
pub const DEFAULT_BUDGET_BYTES: u64 = 50 << 30;

/// Directory entries one pass visits at most — the same order as the
/// `hash_files` traversal bound. A pass runs at every worker start and
/// after every attempt, so a truncated pass simply resumes next time.
pub const DEFAULT_PASS_WORK: u64 = 100_000;

/// `current` names a `gen-*` directory; anything longer is corrupt and
/// the pointer is ignored rather than trusted.
const MAX_CURRENT_BYTES: u64 = 256;

/// Scope depth below the cache root: `<repo>/<class>/<trust>/<os-arch>/
/// <toolchain16>/<name>` — entries are the directories at depth 7.
const ENTRY_DEPTH: u32 = 7;

/// What one pass did — and what it saw, for the worker's diagnostics and
/// the availability snapshot (K08).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GcStats {
    /// Entry directories visited.
    pub entries_seen: u64,
    /// Generation directories seen across those entries — partial when
    /// `truncated`.
    pub generations_seen: u64,
    /// Payload bytes across those generations, per their sealed
    /// manifests — what the store held when the pass walked it, before
    /// any eviction the pass itself performed (`bytes_freed` covers
    /// that). Partial when `truncated`.
    pub payload_bytes: u64,
    /// Lease markers still live.
    pub leases_active: u64,
    /// Expired lease markers removed.
    pub leases_expired: u64,
    /// `writing/` staging trees removed (dead writers' remains).
    pub writing_removed: u64,
    /// Generation directories removed, retention plus eviction.
    pub generations_removed: u64,
    /// Payload bytes those removals freed, per the sealed manifests.
    pub bytes_freed: u64,
    /// `current` pointers naming a generation that is not there — noted,
    /// never repaired: publication owns `current`.
    pub stale_current: u64,
    /// Removals and reads that failed; counted, never fatal.
    pub errors: u64,
    /// The work bound stopped the pass; the rest is for next time.
    pub truncated: bool,
}

impl GcStats {
    /// Anything worth a diagnostic line: removals, reaped leases, a stale
    /// pointer, errors or an unfinished pass.
    pub fn did_work(&self) -> bool {
        self.truncated
            || self.errors > 0
            || self.leases_expired > 0
            || self.writing_removed > 0
            || self.generations_removed > 0
            || self.stale_current > 0
    }
}

/// A non-current generation that may be evicted under the byte budget.
struct Candidate {
    path: PathBuf,
    /// Its entry directory — a lease can arrive between the walk and the
    /// eviction, so the entry is re-swept before removal.
    entry: PathBuf,
    /// `gen-<unix_ms>-<rand>` sorts by creation order as a string.
    name: String,
    bytes: u64,
}

/// One bounded pass over `cache_root`: leases, stale staging, retention
/// and budget eviction, in that order per entry. Missing root is an empty
/// pass. The wall clock is taken once.
pub fn sweep(cache_root: &Path, budget_bytes: u64, max_work: u64) -> GcStats {
    sweep_at(cache_root, budget_bytes, max_work, unix_ms())
}

/// `sweep` with the clock supplied, so tests can age markers and files
/// without waiting out `lease::MAX_TTL`.
#[doc(hidden)]
pub fn sweep_at(cache_root: &Path, budget_bytes: u64, max_work: u64, now_ms: i64) -> GcStats {
    let mut gc = Gc {
        stats: GcStats::default(),
        work: 0,
        max_work,
        now_ms,
        total_bytes: 0,
        evictable: Vec::new(),
    };
    gc.visit(cache_root, 0);
    if !gc.stats.truncated && gc.total_bytes > budget_bytes {
        gc.enforce_budget(budget_bytes);
    }
    gc.stats
}

struct Gc {
    stats: GcStats,
    work: u64,
    max_work: u64,
    now_ms: i64,
    /// Payload bytes across every generation seen, per sealed manifests.
    total_bytes: u64,
    /// Non-current generations in unpinned entries kept past retention —
    /// the budget's eviction pool.
    evictable: Vec<Candidate>,
}

impl Gc {
    /// One unit of bounded work; past the bound the pass unwinds.
    fn tick(&mut self) -> bool {
        self.work += 1;
        if self.work > self.max_work {
            self.stats.truncated = true;
            return false;
        }
        true
    }

    /// Descend the fixed-depth scope tree; at `ENTRY_DEPTH` the directory
    /// is an entry. Anything that is not a directory is passed over.
    fn visit(&mut self, dir: &Path, depth: u32) {
        if self.stats.truncated {
            return;
        }
        if depth == ENTRY_DEPTH {
            self.entry(dir);
            return;
        }
        let entries = match fs::read_dir(dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == ErrorKind::NotFound => return,
            Err(_) => {
                self.stats.errors += 1;
                return;
            }
        };
        for child in entries {
            if self.stats.truncated {
                return;
            }
            if !self.tick() {
                return;
            }
            match child {
                Ok(child) if child.file_type().is_ok_and(|t| t.is_dir()) => {
                    self.visit(&child.path(), depth + 1);
                }
                Ok(_) => {}
                Err(_) => self.stats.errors += 1,
            }
        }
    }

    /// One entry: leases first — a live marker pins the whole entry —
    /// then stale staging, then generation retention.
    fn entry(&mut self, entry: &Path) {
        self.stats.entries_seen += 1;
        if !self.tick() {
            return;
        }
        let pinned = match lease::sweep(entry) {
            Ok(found) => {
                self.stats.leases_active += found.active as u64;
                self.stats.leases_expired += found.expired as u64;
                found.active > 0
            }
            // A lease directory that cannot be read is treated as pinned:
            // sweeping blind under an unknown pin is how a live reader
            // loses its generation.
            Err(_) => {
                self.stats.errors += 1;
                true
            }
        };
        if !pinned {
            self.writing(entry);
        }
        let (current, mut gens) = self.generations(entry);
        // Pinned entries still account their bytes — the budget and the
        // availability snapshot both see the whole store — but nothing
        // inside them is ever removed.
        self.stats.generations_seen += gens.len() as u64;
        let seen: u64 = gens.iter().map(|g| g.bytes).sum();
        self.total_bytes += seen;
        self.stats.payload_bytes += seen;
        if pinned {
            return;
        }
        // Oldest first: `gen-<unix_ms>-…` sorts by creation order.
        gens.sort_by(|a, b| a.name.cmp(&b.name));
        let keep = |g: &Candidate| Some(&g.name) == current.as_ref();
        // The spare is the newest non-current generation; everything
        // older is a delete candidate. Candidates are popped oldest-first
        // until only the spare remains.
        let spare = gens.iter().rev().find(|g| !keep(g)).map(|g| g.name.clone());
        for cand in gens {
            if self.stats.truncated {
                return;
            }
            if keep(&cand) {
                continue;
            }
            if Some(&cand.name) == spare.as_ref() {
                // The retained spare still joins the eviction pool: under
                // budget pressure a non-current generation goes too.
                self.evictable.push(cand);
                continue;
            }
            self.remove_gen(cand);
        }
    }

    /// Remove a stale `writing/` tree: no live lock marker and the
    /// directory itself older than the lease bound — fresh enough to
    /// belong to a writer between `create_dir_all` and its marker, it is
    /// left alone.
    fn writing(&mut self, entry: &Path) {
        let dir = entry.join(scope::WRITING_NAME);
        let Ok(meta) = fs::symlink_metadata(&dir) else {
            return;
        };
        if !meta.is_dir() || !self.tick() {
            return;
        }
        if lease::writing_lock_live(entry, self.now_ms) {
            return;
        }
        let stale = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .is_some_and(|d| {
                d.as_millis() as i64 + lease::MAX_TTL.as_millis() as i64 <= self.now_ms
            });
        if !stale {
            return;
        }
        if !self.tick() {
            return;
        }
        match fs::remove_dir_all(&dir) {
            Ok(()) => self.stats.writing_removed += 1,
            Err(e) if e.kind() == ErrorKind::NotFound => {}
            Err(_) => self.stats.errors += 1,
        }
    }

    /// The entry's `current` target and its generation directories with
    /// their sealed payload sizes (0 when the manifest cannot be read —
    /// a corrupt generation still costs nothing to count, and it is a
    /// delete candidate like any other non-current).
    fn generations(&mut self, entry: &Path) -> (Option<String>, Vec<Candidate>) {
        let mut gens = Vec::new();
        let entries = match fs::read_dir(entry) {
            Ok(entries) => entries,
            Err(e) if e.kind() == ErrorKind::NotFound => return (None, gens),
            Err(_) => {
                self.stats.errors += 1;
                return (None, gens);
            }
        };
        for child in entries {
            if self.stats.truncated {
                return (None, Vec::new());
            }
            if !self.tick() {
                return (None, Vec::new());
            }
            let Ok(child) = child else {
                self.stats.errors += 1;
                continue;
            };
            let name = child.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            if !name.starts_with("gen-") || !child.file_type().is_ok_and(|t| t.is_dir()) {
                continue;
            }
            let bytes = match manifest::read(&child.path()) {
                crate::outcome::Outcome::Hit(hit) => hit.bytes,
                _ => 0,
            };
            gens.push(Candidate {
                path: child.path(),
                entry: entry.to_path_buf(),
                name: name.to_owned(),
                bytes,
            });
        }
        let current = read_current(entry);
        let pointer_present =
            fs::symlink_metadata(entry.join(scope::CURRENT_NAME)).is_ok_and(|m| m.is_file());
        let usable = current
            .as_ref()
            .is_some_and(|name| gens.iter().any(|g| &g.name == name));
        if pointer_present && !usable {
            // A pointer naming a generation that is gone — or carrying
            // bytes that are not a name at all: noted, left in place — a
            // miss rebuilds it and publication owns the file.
            self.stats.stale_current += 1;
        }
        (current, gens)
    }

    /// Delete one generation; failures are counted and the pass moves on.
    fn remove_gen(&mut self, cand: Candidate) {
        if !self.tick() {
            return;
        }
        match fs::remove_dir_all(&cand.path) {
            Ok(()) => {
                self.stats.generations_removed += 1;
                self.stats.bytes_freed += cand.bytes;
            }
            Err(e) if e.kind() == ErrorKind::NotFound => {}
            Err(_) => self.stats.errors += 1,
        }
    }

    /// Over budget: evict non-current generations oldest-first across
    /// entries, re-checking each entry's leases before the removal — a
    /// reader that pinned between the walk and here keeps its generation.
    fn enforce_budget(&mut self, budget_bytes: u64) {
        self.evictable.sort_by(|a, b| a.name.cmp(&b.name));
        let evictable = std::mem::take(&mut self.evictable);
        for cand in evictable {
            if self.total_bytes <= budget_bytes {
                break;
            }
            if self.stats.truncated {
                return;
            }
            if !self.tick() {
                return;
            }
            let pinned = match lease::sweep(&cand.entry) {
                Ok(found) => {
                    self.stats.leases_active += found.active as u64;
                    self.stats.leases_expired += found.expired as u64;
                    found.active > 0
                }
                Err(_) => true,
            };
            if pinned {
                continue;
            }
            self.total_bytes = self.total_bytes.saturating_sub(cand.bytes);
            self.remove_gen(cand);
        }
    }
}

/// The name `current` carries, or `None` — absent, oversize or unreadable
/// pointers all mean "no live generation named".
fn read_current(entry: &Path) -> Option<String> {
    let path = entry.join(scope::CURRENT_NAME);
    let meta = fs::symlink_metadata(&path).ok()?;
    if !meta.is_file() || meta.len() > MAX_CURRENT_BYTES {
        return None;
    }
    let text = fs::read_to_string(&path).ok()?;
    let name = text.trim();
    if name.starts_with("gen-") && !name.contains(['/', '\\']) && !name.contains("..") {
        Some(name.to_owned())
    } else {
        None
    }
}

fn unix_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}
