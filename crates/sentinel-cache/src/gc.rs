//! K03 — reclamation: a bounded pass over the cache tree that sweeps
//! expired lease markers, removes staging a dead writer left in
//! `writing/`, keeps at most `current` plus one spare generation per
//! entry, removes entries nobody has used for [`IDLE_TTL`], and — while
//! the store is over budget — evicts spares oldest-first and then whole
//! entries (their `current` included) least-recently-used first.
//!
//! A lease pins its whole entry: while any marker under `<entry>/lease/`
//! is live, nothing inside that entry is collected — a reader mid-clone
//! or a writer mid-publish is never undercut, and an entry with a live
//! staging writer is never removed whole. Otherwise nothing is exempt
//! (P07-3): a `current` nobody reads is disk, not state, so the budget is
//! a real bound. Last use is `current`'s mtime — publication writes it,
//! and every restore hit touches it.
//!
//! The pass is bounded by a work counter (`DEFAULT_PASS_WORK`): every
//! directory entry enumerated and every tree removed counts, and hitting
//! the bound stops the pass cleanly — `truncated` is set. A [`Cursor`]
//! kept by the caller makes successive bounded passes cover the whole
//! tree (P07-4): each resumes after the last entry the previous one
//! finished, in name order, and wraps at the end. The budget is enforced
//! on every pass, truncated or not, against the larger of what this cycle
//! has seen and what the last complete cycle measured. Removal failures
//! are counted in `errors`, never panic, never abort the pass.

use std::{
    ffi::OsString,
    fs,
    io::ErrorKind,
    path::{Path, PathBuf},
    time::Duration,
};

use crate::{lease, manifest, scope};

/// The byte budget a `cache/` root holds before a pass evicts
/// (docs/cache.md). A fixed ceiling, not a config key: the worker's data
/// dir has no size knob today, and 50 GiB keeps a warm worker under any
/// plausible checkout-plus-cache pressure.
pub const DEFAULT_BUDGET_BYTES: u64 = 50 << 30;

/// Directory entries one pass visits at most — the same order as the
/// `hash_files` traversal bound. A pass runs at every worker start and
/// after every attempt; with a [`Cursor`] a truncated pass resumes next
/// time where it stopped.
pub const DEFAULT_PASS_WORK: u64 = 100_000;

/// An entry whose `current` nobody has written or read for this long is
/// removed whole, whatever the budget: a stale key's generation is never
/// going to serve again.
pub const IDLE_TTL: Duration = Duration::from_secs(14 * 24 * 60 * 60);

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
    /// Generation directories removed, retention plus eviction (a whole
    /// entry removed counts each of its generations).
    pub generations_removed: u64,
    /// Whole entries removed — idle past [`IDLE_TTL`] or least recently
    /// used under the budget.
    pub entries_removed: u64,
    /// Payload bytes those removals freed, per the sealed manifests.
    pub bytes_freed: u64,
    /// `current` pointers naming a generation that is not there — noted,
    /// never repaired: publication owns `current`.
    pub stale_current: u64,
    /// Removals and reads that failed; counted, never fatal.
    pub errors: u64,
    /// The work bound stopped the pass; a [`Cursor`] resumes after it.
    pub truncated: bool,
    /// The store's estimated total payload after this pass — the complete
    /// cycle's measure when this pass saw only part of the tree.
    pub estimated_bytes: u64,
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

/// Where successive bounded passes resume, and what the last complete
/// cycle measured. Kept by the caller between passes; the default starts
/// at the beginning with nothing measured.
#[derive(Clone, Debug, Default)]
pub struct Cursor {
    /// The last entry a pass finished, as its path components below the
    /// root; empty means start at the beginning.
    after: Vec<OsString>,
    /// Payload bytes seen so far in the cycle in progress.
    cycle_bytes: u64,
    /// Payload bytes of the last complete cycle, less what was freed
    /// since; `None` until a cycle completed.
    last_total: Option<u64>,
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

/// A whole entry that may be removed under the budget.
struct Stale {
    entry: PathBuf,
    /// `current`'s mtime in unix ms — last publication or restore hit.
    used_ms: i64,
    bytes: u64,
    generations: u64,
}

/// One bounded pass over `cache_root` from the beginning: leases, stale
/// staging, retention, idle entries and budget eviction. Missing root is
/// an empty pass. The wall clock is taken once.
pub fn sweep(cache_root: &Path, budget_bytes: u64, max_work: u64) -> GcStats {
    sweep_at(cache_root, budget_bytes, max_work, unix_ms())
}

/// `sweep` with the clock supplied, so tests can age markers and files
/// without waiting out `lease::MAX_TTL`.
#[doc(hidden)]
pub fn sweep_at(cache_root: &Path, budget_bytes: u64, max_work: u64, now_ms: i64) -> GcStats {
    resume_at(
        cache_root,
        budget_bytes,
        max_work,
        now_ms,
        &mut Cursor::default(),
    )
}

/// One bounded pass that resumes where `cursor` says and leaves it where
/// this pass stopped — the executor's form: successive passes cover the
/// whole tree however large it is.
pub fn resume(cache_root: &Path, budget_bytes: u64, max_work: u64, cursor: &mut Cursor) -> GcStats {
    resume_at(cache_root, budget_bytes, max_work, unix_ms(), cursor)
}

/// `resume` with the clock supplied.
#[doc(hidden)]
pub fn resume_at(
    cache_root: &Path,
    budget_bytes: u64,
    max_work: u64,
    now_ms: i64,
    cursor: &mut Cursor,
) -> GcStats {
    let mut gc = Gc {
        root: cache_root.to_path_buf(),
        stats: GcStats::default(),
        work: 0,
        max_work,
        now_ms,
        evictable: Vec::new(),
        stale: Vec::new(),
        resume: std::mem::take(&mut cursor.after),
        last: Vec::new(),
        path: Vec::new(),
    };
    gc.visit(cache_root, 0);
    cursor.cycle_bytes = cursor.cycle_bytes.saturating_add(gc.stats.payload_bytes);
    if gc.stats.truncated {
        cursor.after = std::mem::take(&mut gc.last);
    } else {
        // The walk reached the end of the tree: the cycle is complete and
        // its measure is the store's; the next pass starts over.
        cursor.last_total = Some(cursor.cycle_bytes);
        cursor.cycle_bytes = 0;
    }
    let estimate = cursor
        .last_total
        .unwrap_or(0)
        .max(cursor.cycle_bytes)
        .max(gc.stats.payload_bytes);
    let freed_before = gc.stats.bytes_freed;
    let mut total = estimate.saturating_sub(freed_before);
    if total > budget_bytes {
        total = gc.enforce_budget(budget_bytes, total);
    }
    let freed = gc.stats.bytes_freed;
    if let Some(last) = &mut cursor.last_total {
        *last = last.saturating_sub(freed);
    }
    cursor.cycle_bytes = cursor.cycle_bytes.saturating_sub(freed);
    gc.stats.estimated_bytes = total;
    gc.stats
}

struct Gc {
    root: PathBuf,
    stats: GcStats,
    work: u64,
    max_work: u64,
    now_ms: i64,
    /// Non-current generations in unpinned entries kept past retention —
    /// the budget's first eviction pool.
    evictable: Vec<Candidate>,
    /// Unpinned entries with a `current` — the budget's second pool, taken
    /// least recently used first.
    stale: Vec<Stale>,
    /// The entry to resume after, as components; consumed as the walk
    /// passes it.
    resume: Vec<OsString>,
    /// The last entry this pass finished — the next cursor.
    last: Vec<OsString>,
    /// Components of the directory being visited.
    path: Vec<OsString>,
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

    /// Descend the fixed-depth scope tree in name order; at `ENTRY_DEPTH`
    /// the directory is an entry. Anything that is not a directory is
    /// passed over. Children at or before the resume point are skipped.
    fn visit(&mut self, dir: &Path, depth: u32) {
        if self.stats.truncated {
            return;
        }
        if depth == ENTRY_DEPTH {
            self.entry(dir);
            if !self.stats.truncated {
                self.last = self.path.clone();
            }
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
        let mut children: Vec<OsString> = Vec::new();
        for child in entries {
            if !self.tick() {
                return;
            }
            match child {
                Ok(child) if child.file_type().is_ok_and(|t| t.is_dir()) => {
                    children.push(child.file_name());
                }
                Ok(_) => {}
                Err(_) => self.stats.errors += 1,
            }
        }
        children.sort_unstable();
        let level = depth as usize;
        for name in children {
            if self.stats.truncated {
                return;
            }
            // While on the resume path, skip what the previous pass did:
            // earlier names, and the finished entry itself.
            if let Some(mark) = self.resume.get(level) {
                match name.cmp(mark) {
                    std::cmp::Ordering::Less => continue,
                    std::cmp::Ordering::Equal if level + 1 == self.resume.len() => {
                        self.resume.clear();
                        continue;
                    }
                    std::cmp::Ordering::Equal => {}
                    std::cmp::Ordering::Greater => self.resume.clear(),
                }
            }
            self.path.push(name.clone());
            self.visit(&dir.join(&name), depth + 1);
            self.path.pop();
            if self.resume.len() > level {
                // The resume subtree is done (or vanished): everything after
                // it at this level is new work.
                self.resume.clear();
            }
        }
    }

    /// One entry: leases first — a live marker pins the whole entry —
    /// then stale staging, then generation retention, then idleness.
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
        let (current, used_ms, mut gens) = self.generations(entry);
        // Pinned entries still account their bytes — the budget and the
        // availability snapshot both see the whole store — but nothing
        // inside them is ever removed.
        self.stats.generations_seen += gens.len() as u64;
        let seen: u64 = gens.iter().map(|g| g.bytes).sum();
        self.stats.payload_bytes += seen;
        if pinned {
            return;
        }
        // Nothing left to serve and no pointer: an empty shell (a writer
        // that never sealed, a hydration that failed) goes whole.
        // A shell younger than the lease bound is left alone, like a young
        // `writing/`: it can be a pin or a writer between making the entry
        // directory and landing its marker — removing it there answers that
        // holder `NotFound` and, under a busy sweeper, again on every retry.
        if used_ms.is_none() && gens.is_empty() {
            if self.young(entry) {
                return;
            }
            self.remove_entry(Stale {
                entry: entry.to_path_buf(),
                used_ms: 0,
                bytes: 0,
                generations: 0,
            });
            return;
        }
        // Idle past the TTL: the whole entry goes, current and all.
        if let Some(used_ms) = used_ms
            && used_ms.saturating_add(IDLE_TTL.as_millis() as i64) <= self.now_ms
        {
            let generations = gens.len() as u64;
            self.remove_entry(Stale {
                entry: entry.to_path_buf(),
                used_ms,
                bytes: seen,
                generations,
            });
            return;
        }
        // Oldest first: `gen-<unix_ms>-…` sorts by creation order.
        gens.sort_by(|a, b| a.name.cmp(&b.name));
        let keep = |g: &Candidate| Some(&g.name) == current.as_ref();
        // The spare is the newest non-current generation; everything
        // older is a delete candidate.
        let spare = gens.iter().rev().find(|g| !keep(g)).map(|g| g.name.clone());
        let mut kept_bytes = 0u64;
        let mut kept = 0u64;
        for cand in gens {
            if self.stats.truncated {
                return;
            }
            if keep(&cand) {
                kept_bytes += cand.bytes;
                kept += 1;
                continue;
            }
            if Some(&cand.name) == spare.as_ref() {
                // The retained spare joins the eviction pool first.
                kept_bytes += cand.bytes;
                kept += 1;
                self.evictable.push(cand);
                continue;
            }
            self.remove_gen(cand);
        }
        if let Some(used_ms) = used_ms {
            // What remains of a live entry is the budget's last resort.
            self.stale.push(Stale {
                entry: entry.to_path_buf(),
                used_ms,
                bytes: kept_bytes,
                generations: kept,
            });
        }
    }

    /// Whether a directory was modified within the lease bound — or its
    /// age cannot be read, which counts as young: never removed blind.
    fn fresh(&self, meta: &fs::Metadata) -> bool {
        !meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .is_some_and(|d| {
                d.as_millis() as i64 + lease::MAX_TTL.as_millis() as i64 <= self.now_ms
            })
    }

    /// [`Gc::fresh`] for `dir` by path; a directory already gone is not.
    fn young(&self, dir: &Path) -> bool {
        fs::symlink_metadata(dir).is_ok_and(|meta| self.fresh(&meta))
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
        if self.fresh(&meta) {
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

    /// The entry's `current` target, `current`'s mtime (last use) and its
    /// generation directories with their sealed payload sizes (0 when the
    /// manifest cannot be read — a corrupt generation still costs nothing
    /// to count, and it is a delete candidate like any other non-current).
    fn generations(&mut self, entry: &Path) -> (Option<String>, Option<i64>, Vec<Candidate>) {
        let mut gens = Vec::new();
        let entries = match fs::read_dir(entry) {
            Ok(entries) => entries,
            Err(e) if e.kind() == ErrorKind::NotFound => return (None, None, gens),
            Err(_) => {
                self.stats.errors += 1;
                return (None, None, gens);
            }
        };
        for child in entries {
            if self.stats.truncated {
                return (None, None, Vec::new());
            }
            if !self.tick() {
                return (None, None, Vec::new());
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
        let pointer = fs::symlink_metadata(entry.join(scope::CURRENT_NAME))
            .ok()
            .filter(|m| m.is_file());
        let used_ms = pointer.as_ref().and_then(|m| {
            m.modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_millis() as i64)
        });
        let current = read_current(entry);
        let usable = current
            .as_ref()
            .is_some_and(|name| gens.iter().any(|g| &g.name == name));
        if pointer.is_some() && !usable {
            // A pointer naming a generation that is gone — or carrying
            // bytes that are not a name at all: noted, left in place — a
            // miss rebuilds it and publication owns the file.
            self.stats.stale_current += 1;
        }
        (current, used_ms, gens)
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

    /// Whether `entry` may be removed right now: no live lease (re-swept —
    /// a reader that pinned since the walk keeps it) and no live writer.
    fn removable(&mut self, entry: &Path) -> bool {
        let pinned = match lease::sweep(entry) {
            Ok(found) => {
                self.stats.leases_expired += found.expired as u64;
                found.active > 0
            }
            Err(_) => true,
        };
        !pinned && !lease::writing_lock_live(entry, self.now_ms)
    }

    /// Remove a whole entry, then any scope directories it leaves empty.
    /// Returns whether it went.
    fn remove_entry(&mut self, stale: Stale) -> bool {
        if !self.tick() || !self.removable(&stale.entry) {
            return false;
        }
        // Take the entry out of the tree first, then judge it again: a pin
        // (a reader's lease, a publisher's lease or its staging lock) taken
        // before the rename is inside the moved directory and is seen here,
        // and the entry goes back; one taken after it lands in a fresh entry
        // directory the removal never touches. Readers pin before they trust
        // `current`, so neither case can serve from a directory being removed.
        let Some(name) = stale.entry.file_name().and_then(|n| n.to_str()) else {
            return false;
        };
        let aside = stale
            .entry
            .with_file_name(format!("{name}.gc-{:08x}", lease::rand_u32()));
        match fs::rename(&stale.entry, &aside) {
            Ok(()) => {}
            Err(e) if e.kind() == ErrorKind::NotFound => return false,
            Err(_) => {
                self.stats.errors += 1;
                return false;
            }
        }
        if !self.removable(&aside) {
            // Put it back; if the name was taken meanwhile the moved entry
            // stays pinned where it is and a later pass collects it.
            let _ = fs::rename(&aside, &stale.entry);
            return false;
        }
        match fs::remove_dir_all(&aside) {
            Ok(()) => {
                self.stats.entries_removed += 1;
                self.stats.generations_removed += stale.generations;
                self.stats.bytes_freed += stale.bytes;
                // Empty scope directories go too; the first that still has
                // children (or the root) stops the climb.
                let mut dir = stale.entry.parent();
                while let Some(d) = dir {
                    if d == self.root || fs::remove_dir(d).is_err() {
                        break;
                    }
                    dir = d.parent();
                }
                true
            }
            Err(e) if e.kind() == ErrorKind::NotFound => false,
            Err(_) => {
                self.stats.errors += 1;
                false
            }
        }
    }

    /// Over budget: evict spares oldest-first across entries, then whole
    /// entries least recently used first, re-checking each entry's pins
    /// before the removal — a reader that pinned between the walk and here
    /// keeps its generation. Returns the estimated total after eviction.
    fn enforce_budget(&mut self, budget_bytes: u64, mut total: u64) -> u64 {
        // Eviction has its own allowance, the size of a walk's: a pass the
        // walk bound truncated still enforces the budget (P07-4), and the
        // eviction itself stays bounded.
        let walked_out = std::mem::replace(&mut self.stats.truncated, false);
        self.max_work = self.work.saturating_add(self.max_work);
        self.evictable.sort_by(|a, b| a.name.cmp(&b.name));
        let evictable = std::mem::take(&mut self.evictable);
        for cand in evictable {
            if total <= budget_bytes || self.stats.truncated {
                break;
            }
            let entry = cand.entry.clone();
            if !self.removable(&entry) {
                continue;
            }
            let bytes = cand.bytes;
            let before = self.stats.generations_removed;
            self.remove_gen(cand);
            if self.stats.generations_removed > before {
                total = total.saturating_sub(bytes);
                // The entry's remaining bytes shrank with it.
                if let Some(s) = self.stale.iter_mut().find(|s| s.entry == entry) {
                    s.bytes = s.bytes.saturating_sub(bytes);
                    s.generations = s.generations.saturating_sub(1);
                }
            }
        }
        self.stale.sort_by_key(|s| s.used_ms);
        let stale = std::mem::take(&mut self.stale);
        for entry in stale {
            if total <= budget_bytes || self.stats.truncated {
                break;
            }
            let bytes = entry.bytes;
            if self.remove_entry(entry) {
                total = total.saturating_sub(bytes);
            }
        }
        self.stats.truncated |= walked_out;
        total
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

/// Record a use of `entry` — a restore hit — by moving `current`'s mtime
/// to now: the least-recently-used order the budget evicts by. Best
/// effort: a pointer that cannot be touched only ages a little early.
pub(crate) fn touch(entry: &Path) {
    if let Ok(file) = fs::OpenOptions::new()
        .write(true)
        .open(entry.join(scope::CURRENT_NAME))
    {
        let _ = file.set_modified(std::time::SystemTime::now());
    }
}

fn unix_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}
