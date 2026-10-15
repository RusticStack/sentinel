use std::{
    ffi::OsString,
    fs,
    io::ErrorKind,
    path::{Path, PathBuf},
    time::Duration,
};

use crate::{lease, manifest, scope};

pub const DEFAULT_BUDGET_BYTES: u64 = 50 << 30;

pub const DEFAULT_PASS_WORK: u64 = 100_000;

pub const IDLE_TTL: Duration = Duration::from_secs(14 * 24 * 60 * 60);

const MAX_CURRENT_BYTES: u64 = 256;

const ENTRY_DEPTH: u32 = 7;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GcStats {
    pub entries_seen: u64,
    pub generations_seen: u64,
    pub payload_bytes: u64,
    pub leases_active: u64,
    pub leases_expired: u64,
    pub writing_removed: u64,
    pub generations_removed: u64,
    pub entries_removed: u64,
    pub bytes_freed: u64,
    pub stale_current: u64,
    pub errors: u64,
    pub truncated: bool,
    pub estimated_bytes: u64,
}

impl GcStats {
    pub fn did_work(&self) -> bool {
        self.truncated
            || self.errors > 0
            || self.leases_expired > 0
            || self.writing_removed > 0
            || self.generations_removed > 0
            || self.stale_current > 0
    }
}

#[derive(Clone, Debug, Default)]
pub struct Cursor {
    after: Vec<OsString>,
    cycle_bytes: u64,
    last_total: Option<u64>,
}

struct Candidate {
    path: PathBuf,
    entry: PathBuf,
    name: String,
    bytes: u64,
}

struct Stale {
    entry: PathBuf,
    used_ms: i64,
    bytes: u64,
    generations: u64,
}

pub fn sweep(cache_root: &Path, budget_bytes: u64, max_work: u64) -> GcStats {
    sweep_at(cache_root, budget_bytes, max_work, unix_ms())
}

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

pub fn resume(cache_root: &Path, budget_bytes: u64, max_work: u64, cursor: &mut Cursor) -> GcStats {
    resume_at(cache_root, budget_bytes, max_work, unix_ms(), cursor)
}

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
    evictable: Vec<Candidate>,
    stale: Vec<Stale>,
    resume: Vec<OsString>,
    last: Vec<OsString>,
    path: Vec<OsString>,
}

impl Gc {
    fn tick(&mut self) -> bool {
        self.work += 1;
        if self.work > self.max_work {
            self.stats.truncated = true;
            return false;
        }
        true
    }

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
                self.resume.clear();
            }
        }
    }

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
            Err(_) => {
                self.stats.errors += 1;
                true
            }
        };
        if !pinned {
            self.writing(entry);
        }
        let (current, used_ms, mut gens) = self.generations(entry);
        self.stats.generations_seen += gens.len() as u64;
        let seen: u64 = gens.iter().map(|g| g.bytes).sum();
        self.stats.payload_bytes += seen;
        if pinned {
            return;
        }
        // A young empty shell may be a pin or a writer between making the entry directory and its marker;
        // removing it would answer that holder NotFound.
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
        gens.sort_by(|a, b| a.name.cmp(&b.name));
        let keep = |g: &Candidate| Some(&g.name) == current.as_ref();
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
                kept_bytes += cand.bytes;
                kept += 1;
                self.evictable.push(cand);
                continue;
            }
            self.remove_gen(cand);
        }
        if let Some(used_ms) = used_ms {
            self.stale.push(Stale {
                entry: entry.to_path_buf(),
                used_ms,
                bytes: kept_bytes,
                generations: kept,
            });
        }
    }

    fn fresh(&self, meta: &fs::Metadata) -> bool {
        !meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .is_some_and(|d| {
                d.as_millis() as i64 + lease::MAX_TTL.as_millis() as i64 <= self.now_ms
            })
    }

    fn young(&self, dir: &Path) -> bool {
        fs::symlink_metadata(dir).is_ok_and(|meta| self.fresh(&meta))
    }

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
            self.stats.stale_current += 1;
        }
        (current, used_ms, gens)
    }

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

    fn remove_entry(&mut self, stale: Stale) -> bool {
        if !self.tick() || !self.removable(&stale.entry) {
            return false;
        }
        // Rename aside, then judge again: a pin taken before the rename is seen and the entry goes back;
        // one taken after lands in a fresh entry directory that this removal never touches.
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
            let _ = fs::rename(&aside, &stale.entry);
            return false;
        }
        match fs::remove_dir_all(&aside) {
            Ok(()) => {
                self.stats.entries_removed += 1;
                self.stats.generations_removed += stale.generations;
                self.stats.bytes_freed += stale.bytes;
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

    fn enforce_budget(&mut self, budget_bytes: u64, mut total: u64) -> u64 {
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
