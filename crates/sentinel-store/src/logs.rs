//! The controller's durable log store (W05 + D04): one directory per
//! attempt under `<logs>/<run>/<job>/<attempt>/` holding an append stream
//! split into segments.
//!
//! **Layout.** `seg-NNNNNN` files hold `sentinel-protocol::logs` records;
//! the last one is the active segment, sealed at `SEGMENT_BYTES` and
//! compressed on a background thread to `seg-NNNNNN.z` (`SNLZ` | format
//! u16 | codec u8 | zlib stream). `index` (`SNLI` | format u16) holds
//! sparse 41-byte entries — checkpoints by sequence, step, line count,
//! wall time and cumulative bytes, written on a segment's first frame, on
//! every step change and every `INDEX_EVERY` frames, plus a seal record
//! per closed segment. `end` (`SNLE` | format u16 | last_seq u64 | gaps)
//! is the completeness boundary, renamed into place and fsynced only
//! after the end record is durable in the stream.
//!
//! **Acknowledgement boundary.** A frame is acknowledged to the worker
//! only after it has been written *and* `fdatasync`ed; the worker may
//! then drop it from its spool. A repeat of a stored sequence (a resend
//! after a lost session) is accepted and not written twice. A sequence
//! jump records a hole rather than refusing the stream, and a resent
//! frame landing inside a hole is stored as a fill; holes merge into the
//! end marker's gap list, so a gap can never be silent. A `last_seq`
//! beyond what was stored is a truncation — the unwritten tail joins the
//! gaps. Readers report incomplete logs and declared gaps.
//!
//! **Recovery.** Index entries past the last fsynced seal record are
//! provisional; on open they are discarded and regenerated while the
//! uncovered segments are decoded. A torn record tail on the active
//! segment is cut, a torn index tail is cut at the last complete entry,
//! and a missing index is rebuilt by decoding every segment. The `end`
//! marker is written atomically, so it is complete or absent — an end
//! record in the stream without the marker is repaired on open.

use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::{
        Arc, Condvar, Mutex, OnceLock,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use flate2::{Compression, read::ZlibDecoder, write::ZlibEncoder};
use sentinel_core::{AttemptId, JobId, RunId, UnixMillis};
use sentinel_protocol::logs::{FRAME_HEADER_BYTES, Frame, Record, RecordError};

use crate::{Error, Result, objects::sync_dir, space::Admission};

pub const LOGS_DIR: &str = "logs";
/// Bytes an attempt's log may hold; past it frames are refused as
/// `Publication` failures rather than filling the disk.
pub const MAX_LOG_BYTES: u64 = 256 << 20;
/// Segment size target: the active segment seals once the next record
/// would pass this, then compresses in the background.
const SEGMENT_BYTES: u64 = 4 << 20;
/// Frames between index checkpoints inside a segment.
const INDEX_EVERY: u32 = 64;
/// Gap ranges a stored end marker may carry; wider hole sets coalesce.
const MAX_MARKER_GAPS: usize = 1024;

const INDEX_MAGIC: &[u8; 4] = b"SNLI";
const INDEX_FORMAT: u16 = 1;
/// `kind u8 | seq u64 | seg u32 | step u32 | line u64 | bytes u64 | ms i64`.
const INDEX_ENTRY_BYTES: usize = 41;
const KIND_CHECKPOINT: u8 = 1;
const KIND_SEAL: u8 = 2;

const COMPRESSED_MAGIC: &[u8; 4] = b"SNLZ";
const COMPRESSED_FORMAT: u16 = 1;
const CODEC_ZLIB: u8 = 1;

const END_MAGIC: &[u8; 4] = b"SNLE";
const END_FORMAT: u16 = 1;

/// The persisted hole list of a live log: `SNLH` | format u16 | count u32 |
/// `(from u64, to u64)` per hole, replaced atomically on every change.
const HOLES_MAGIC: &[u8; 4] = b"SNLH";
const HOLES_FORMAT: u16 = 1;
/// Distinct holes one live log may track; a stream fragmenting past this is
/// refused rather than growing the list (and its sidecar) without bound.
pub const MAX_HOLES: usize = 4096;

/// Writers held at once before the least recently used idle one closes.
pub const MAX_OPEN_WRITERS: usize = 1024;
/// A writer unused this long is closed by the maintenance pass
/// ([`LogStore::close_idle`]); the next frame reopens it from disk.
pub const WRITER_IDLE: Duration = Duration::from_secs(600);
/// Attempt directories one retention pass examines at most.
const SWEEP_BUDGET: u32 = 4096;

/// One sparse index entry. A checkpoint describes the frame that caused
/// it (`line`/`bytes` are cumulative *including* that frame); a seal
/// records a closed segment's totals.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Entry {
    kind: u8,
    seq: u64,
    seg: u32,
    step: u32,
    line: u64,
    bytes: u64,
    ms: i64,
}

impl Entry {
    fn bytes(&self) -> [u8; INDEX_ENTRY_BYTES] {
        let mut out = [0u8; INDEX_ENTRY_BYTES];
        out[0] = self.kind;
        out[1..9].copy_from_slice(&self.seq.to_le_bytes());
        out[9..13].copy_from_slice(&self.seg.to_le_bytes());
        out[13..17].copy_from_slice(&self.step.to_le_bytes());
        out[17..25].copy_from_slice(&self.line.to_le_bytes());
        out[25..33].copy_from_slice(&self.bytes.to_le_bytes());
        out[33..41].copy_from_slice(&self.ms.to_le_bytes());
        out
    }

    fn decode(bytes: &[u8]) -> Option<Entry> {
        if bytes.len() < INDEX_ENTRY_BYTES {
            return None;
        }
        let kind = bytes[0];
        if kind != KIND_CHECKPOINT && kind != KIND_SEAL {
            return None;
        }
        Some(Entry {
            kind,
            seq: u64::from_le_bytes(bytes[1..9].try_into().ok()?),
            seg: u32::from_le_bytes(bytes[9..13].try_into().ok()?),
            step: u32::from_le_bytes(bytes[13..17].try_into().ok()?),
            line: u64::from_le_bytes(bytes[17..25].try_into().ok()?),
            bytes: u64::from_le_bytes(bytes[25..33].try_into().ok()?),
            ms: i64::from_le_bytes(bytes[33..41].try_into().ok()?),
        })
    }
}

/// An attempt's open writer: the active segment, its index and the
/// running totals the size cap and checkpoints need.
struct Open {
    dir: PathBuf,
    /// The segment being appended to.
    seg: u32,
    /// The active segment's writer; `None` until its first frame.
    file: Option<File>,
    /// Bytes in the active segment.
    seg_len: u64,
    /// The index file, appended provisionally and fsynced at seals.
    index: File,
    /// Bytes of the index that decode cleanly — the valid tail. A failed
    /// append is truncated back here so later entries never sit behind a
    /// torn one; `u64::MAX` means the index is abandoned until reopen
    /// rebuilds it.
    index_len: u64,
    /// Highest stored sequence.
    last_seq: u64,
    /// Ranges below `last_seq` that were never stored, sorted and
    /// disjoint; fills shrink it. Mirrored in the `holes` sidecar.
    holes: Vec<(u64, u64)>,
    /// `holes` changed and the sidecar does not have it yet.
    holes_dirty: bool,
    /// Stored record bytes across all segments: the size cap.
    len: u64,
    /// Stored newline count across all segments.
    lines: u64,
    /// The last stored frame's step.
    step: u32,
    /// Frames advancing the frontier since the last checkpoint.
    since_index: u32,
    /// The active segment has its first checkpoint.
    seg_checkpointed: bool,
    /// The end marker's `last_seq` once the log is finished.
    ended: Option<u64>,
    /// Encode scratch, reused across frames.
    scratch: Vec<u8>,
}

/// Sealed segments waiting to be compressed, drained by one thread.
struct Compressor {
    queue: Mutex<VecDeque<PathBuf>>,
    wake: Condvar,
    stop: AtomicBool,
}

impl Compressor {
    fn enqueue(&self, path: PathBuf) {
        self.queue
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push_back(path);
        self.wake.notify_one();
    }

    fn run(&self) {
        loop {
            let path = {
                let mut queue = self.queue.lock().unwrap_or_else(|p| p.into_inner());
                loop {
                    if let Some(path) = queue.pop_front() {
                        break path;
                    }
                    if self.stop.load(Ordering::Acquire) {
                        return;
                    }
                    queue = self.wake.wait(queue).unwrap_or_else(|p| p.into_inner());
                }
            };
            // A failure leaves the plain segment readable; it is retried
            // on the next process start, never in a loop here.
            let _ = compress(&path);
        }
    }
}

/// One attempt's writer slot. The map lock only finds the slot; the frame's
/// write and `fdatasync` happen under the slot's own lock, so attempts never
/// wait on each other's flushes. `None` until first use (and after a failed
/// open), so opening an attempt — a bounded decode — also runs outside the
/// map lock.
struct Slot {
    open: Mutex<Option<Open>>,
    /// Store-clock milliseconds of the last use; the idle sweep reads it
    /// without taking `open`.
    touched: AtomicU64,
}

/// Append and read attempt logs. Cheap to share: a short map lock to find
/// an attempt's writer, a lock per writer for its I/O, one directory per
/// attempt, one compressor thread.
pub struct LogStore {
    dir: PathBuf,
    open: Mutex<HashMap<AttemptId, Arc<Slot>>>,
    /// The store clock `Slot::touched` counts from.
    epoch: Instant,
    /// Writers held at once; past it the least recently used idle one
    /// closes. Two descriptors and one frame of scratch each.
    max_open: usize,
    /// Bumped after every stored frame and finish; `wait=1` log polls park
    /// on it instead of re-reading on a timer.
    changes: Arc<LogChanges>,
    compressor: Arc<Compressor>,
    worker: Mutex<Option<JoinHandle<()>>>,
    /// Disk admission (D06); unset admits every append as before.
    admission: OnceLock<Arc<Admission>>,
    /// Stored bytes one attempt's log may occupy — `MAX_LOG_BYTES`
    /// normally, lower under `open_with_limit`.
    max_bytes: u64,
    /// Where the bounded retention sweep resumes: the last run directory
    /// it finished.
    sweep_cursor: Mutex<Option<String>>,
}

/// The log-append notifier: a generation bumped after every durable append
/// or finish, and a parking place for long polls. Same no-lost-wakeup
/// discipline as the store's commit notifier: a waiter registers before it
/// reads the generation under the lock; the bumper reads `waiters` after
/// bumping and notifies under the lock. The append path pays one atomic
/// add and one load; the lock only while someone is parked.
#[derive(Debug, Default)]
pub struct LogChanges {
    generation: AtomicU64,
    waiters: AtomicUsize,
    lock: Mutex<()>,
    cv: Condvar,
}

impl LogChanges {
    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::SeqCst)
    }

    /// Park until the generation differs from `seen` or `deadline` passes;
    /// returns the generation then.
    pub fn wait_past(&self, seen: u64, deadline: Instant) -> u64 {
        self.waiters.fetch_add(1, Ordering::SeqCst);
        let mut guard = self.lock.lock().unwrap_or_else(|p| p.into_inner());
        let generation = loop {
            let now = self.generation.load(Ordering::SeqCst);
            if now != seen {
                break now;
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break now;
            }
            guard = self
                .cv
                .wait_timeout(guard, remaining)
                .unwrap_or_else(|p| p.into_inner())
                .0;
        };
        drop(guard);
        self.waiters.fetch_sub(1, Ordering::SeqCst);
        generation
    }

    #[inline]
    fn bump(&self) {
        self.generation.fetch_add(1, Ordering::SeqCst);
        if self.waiters.load(Ordering::SeqCst) != 0 {
            let _guard = self.lock.lock().unwrap_or_else(|p| p.into_inner());
            self.cv.notify_all();
        }
    }
}

/// What appending a frame did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Appended {
    /// Written and synced; acknowledge through this sequence.
    Stored { through: u64 },
    /// Already stored (a resend); acknowledge through the stored sequence.
    Duplicate { through: u64 },
}

impl LogStore {
    pub fn open(dir: impl Into<PathBuf>) -> Result<LogStore> {
        Self::open_with_limit(dir, MAX_LOG_BYTES)
    }

    /// `open` under a caller-set per-attempt byte cap — the same contract
    /// where the default is too generous (and for tests).
    pub fn open_with_limit(dir: impl Into<PathBuf>, max_bytes: u64) -> Result<LogStore> {
        let dir = dir.into();
        if !dir.is_dir() {
            fs::create_dir_all(&dir)?;
            // Every acknowledgement below promises a path through this
            // directory: its own entry must be durable first.
            if let Some(parent) = dir.parent() {
                sync_dir(parent)?;
            }
        }
        let compressor = Arc::new(Compressor {
            queue: Mutex::new(VecDeque::new()),
            wake: Condvar::new(),
            stop: AtomicBool::new(false),
        });
        let worker = {
            let compressor = Arc::clone(&compressor);
            thread::Builder::new()
                .name("sentinel-logzip".into())
                .spawn(move || compressor.run())?
        };
        let store = LogStore {
            dir,
            open: Mutex::new(HashMap::new()),
            epoch: Instant::now(),
            max_open: MAX_OPEN_WRITERS,
            changes: Arc::new(LogChanges::default()),
            compressor,
            worker: Mutex::new(Some(worker)),
            admission: OnceLock::new(),
            max_bytes,
            sweep_cursor: Mutex::new(None),
        };
        store.sweep();
        Ok(store)
    }

    /// Hold at most `max` writers open at once (at least one); the default
    /// is [`MAX_OPEN_WRITERS`].
    #[must_use]
    pub fn with_max_open(mut self, max: usize) -> LogStore {
        self.max_open = max.max(1);
        self
    }

    /// Install the disk admission gate; appends refuse once free space
    /// falls below the log floor. Set once at startup.
    pub fn set_admission(&self, admission: Arc<Admission>) {
        let _ = self.admission.set(admission);
    }

    /// The append notifier long polls park on.
    pub fn changes(&self) -> &LogChanges {
        &self.changes
    }

    fn now_ms(&self) -> u64 {
        self.epoch.elapsed().as_millis() as u64
    }

    /// Writers held open right now.
    pub fn open_writers(&self) -> usize {
        self.open.lock().unwrap_or_else(|p| p.into_inner()).len()
    }

    /// Close writers unused for `idle`: attempts whose worker was lost,
    /// whose lease lapsed or whose flush timed out never send `LogEnd`, and
    /// their writers must not hold descriptors and scratch for the life of
    /// the process — or keep their logs out of retention. A later frame or
    /// end reopens the log from disk, which folds its state back exactly.
    /// A writer some request is using right now is never closed. Returns how
    /// many closed.
    pub fn close_idle(&self, idle: Duration) -> usize {
        let cutoff = self.now_ms().saturating_sub(idle.as_millis() as u64);
        let mut map = self.open.lock().unwrap_or_else(|p| p.into_inner());
        let before = map.len();
        // Only the map holds an idle slot's Arc: nobody can be inside it,
        // and nobody can clone it without this lock.
        map.retain(|_, slot| {
            Arc::strong_count(slot) > 1 || slot.touched.load(Ordering::Relaxed) > cutoff
        });
        before - map.len()
    }

    /// The attempt's slot, created on first use. At the cap, the least
    /// recently used slot nobody is using closes first — so descriptors and
    /// memory stay bounded however many attempts never finish.
    fn slot(&self, attempt: AttemptId) -> Arc<Slot> {
        let now = self.now_ms();
        let mut map = self.open.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(slot) = map.get(&attempt) {
            slot.touched.store(now, Ordering::Relaxed);
            return Arc::clone(slot);
        }
        if map.len() >= self.max_open {
            let lru = map
                .iter()
                .filter(|(_, s)| Arc::strong_count(s) == 1)
                .min_by_key(|(_, s)| s.touched.load(Ordering::Relaxed))
                .map(|(id, _)| *id);
            if let Some(id) = lru {
                map.remove(&id);
            }
        }
        let slot = Arc::new(Slot {
            open: Mutex::new(None),
            touched: AtomicU64::new(now),
        });
        map.insert(attempt, Arc::clone(&slot));
        slot
    }

    /// Run `f` on the attempt's writer, opening (or reopening after a
    /// restart or an idle close) it from disk first. Only this attempt's
    /// lock is held while `f` does its I/O.
    fn with_writer<T>(
        &self,
        run: RunId,
        job: JobId,
        attempt: AttemptId,
        f: impl FnOnce(&mut Open) -> Result<T>,
    ) -> Result<T> {
        let slot = self.slot(attempt);
        let mut guard = slot.open.lock().unwrap_or_else(|p| p.into_inner());
        if guard.is_none() {
            *guard = Some(self.open_attempt(run, job, attempt)?);
        }
        let result = f(guard.as_mut().expect("opened above"));
        if matches!(result, Err(Error::Io(_))) {
            // A write or sync that failed may have left part of a record in
            // the segment, and the writer's offsets no longer match the
            // file. Drop it: the next call reopens from disk, which cuts the
            // torn record — a later frame is never written behind one.
            *guard = None;
        }
        result
    }

    /// Remove attempt directories and legacy flat logs whose newest byte is
    /// older than `now - retention_ms`. Open writers are never touched; the
    /// deletion is of durable evidence only. One pass removes at most
    /// `limit` and looks at run directories in name order until it has
    /// examined [`SWEEP_BUDGET`] attempt directories, then the next pass
    /// resumes after the last run it finished — so a pass is bounded
    /// however many logs are retained. An attempt's age costs one directory
    /// listing and at most three `stat`s (`end`, `index`, newest segment).
    pub fn sweep_expired(&self, now: UnixMillis, retention_ms: i64, limit: u32) -> Result<u32> {
        if retention_ms <= 0 || limit == 0 {
            return Ok(0);
        }
        let cutoff = now.0 - retention_ms;
        let held: std::collections::HashSet<AttemptId> = self
            .open
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .keys()
            .copied()
            .collect();
        let resume = self
            .sweep_cursor
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        let mut runs: Vec<(String, PathBuf)> = match fs::read_dir(&self.dir) {
            Ok(read) => read
                .flatten()
                .filter_map(|e| Some((e.file_name().into_string().ok()?, e.path())))
                .filter(|(name, _)| resume.as_ref().is_none_or(|r| name > r))
                .collect(),
            Err(_) => return Ok(0),
        };
        runs.sort_unstable_by(|a, b| a.0.cmp(&b.0));
        let mut swept = 0u32;
        let mut seen = 0u32;
        let mut stopped = None;
        for (name, run_path) in runs {
            if run_path.is_file() {
                // Legacy flat log: `logs/<attempt>.log` from before D04.
                seen += 1;
                if run_path.extension().is_some_and(|e| e == "log")
                    && mtime_ms(&run_path).is_some_and(|ms| ms < cutoff)
                    && fs::remove_file(&run_path).is_ok()
                {
                    swept += 1;
                }
            } else if let Ok(jobs) = fs::read_dir(&run_path) {
                for job in jobs.flatten() {
                    let Ok(attempts) = fs::read_dir(job.path()) else {
                        continue;
                    };
                    for attempt in attempts.flatten() {
                        let dir = attempt.path();
                        if !dir.is_dir() {
                            continue;
                        }
                        seen += 1;
                        if let Ok(id) = attempt.file_name().to_string_lossy().parse::<AttemptId>()
                            && held.contains(&id)
                        {
                            continue;
                        }
                        if newest_ms(&dir) < cutoff && fs::remove_dir_all(&dir).is_ok() {
                            swept += 1;
                        }
                    }
                    // Prune an emptied job directory; a live one refuses.
                    let _ = fs::remove_dir(job.path());
                }
                let _ = fs::remove_dir(&run_path);
            }
            if swept >= limit || seen >= SWEEP_BUDGET {
                stopped = Some(name);
                break;
            }
        }
        *self.sweep_cursor.lock().unwrap_or_else(|p| p.into_inner()) = stopped;
        Ok(swept)
    }

    /// The attempt's segment directory.
    pub fn attempt_dir(&self, run: RunId, job: JobId, attempt: AttemptId) -> PathBuf {
        self.dir
            .join(run.to_string())
            .join(job.to_string())
            .join(attempt.to_string())
    }

    /// Whether the attempt's `end` marker is durable — the in-memory writer
    /// knows once `finish` has synced it; a writer this process never opened
    /// is answered by the marker file itself. A rename the writer has not yet
    /// synced still answers `false`: the marker is not yet the durable truth.
    pub fn has_end(&self, run: RunId, job: JobId, attempt: AttemptId) -> bool {
        let slot = self
            .open
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&attempt)
            .cloned();
        if let Some(slot) = slot
            && let Some(w) = slot.open.lock().unwrap_or_else(|p| p.into_inner()).as_ref()
        {
            return w.ended.is_some();
        }
        end_marker(&self.attempt_dir(run, job, attempt)).is_some()
    }

    /// Close the writer of an attempt that was released without its log
    /// ending (lease expiry, abandonment, a lost worker): its file handles
    /// and scratch go now instead of at process exit, and the log becomes
    /// eligible for retention. A later retransmission simply reopens it
    /// from disk. Returns whether a writer was open.
    pub fn forget(&self, attempt: AttemptId) -> bool {
        self.open
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&attempt)
            .is_some()
    }

    /// Recover interrupted compressions: plain segments whose successor
    /// or `.z` twin exists, or whose log ended, are sealed — queue them
    /// and drop stale compressor temporaries.
    fn sweep(&self) {
        let Ok(runs) = fs::read_dir(&self.dir) else {
            return;
        };
        for run in runs.flatten() {
            let Ok(jobs) = fs::read_dir(run.path()) else {
                continue;
            };
            for job in jobs.flatten() {
                let Ok(attempts) = fs::read_dir(job.path()) else {
                    continue;
                };
                for attempt in attempts.flatten() {
                    let dir = attempt.path();
                    if !dir.is_dir() {
                        continue;
                    }
                    sweep_tmp(&dir);
                    let Ok(segs) = segs(&dir) else {
                        continue;
                    };
                    let ended = end_marker(&dir).is_some();
                    let top = segs.keys().next_back().copied();
                    for (n, compressed) in &segs {
                        if *compressed {
                            // Compression finished; the plain twin is a
                            // crash leftover of the rename/delete pair.
                            let plain = seg_path(&dir, *n, false);
                            if plain.exists() {
                                let _ = fs::remove_file(plain);
                            }
                        } else if ended || top != Some(*n) {
                            self.compressor.enqueue(seg_path(&dir, *n, false));
                        }
                    }
                }
            }
        }
    }

    /// Open (or reopen after a restart or an idle close) the attempt's
    /// writer, folding the segments the index does not cover back into
    /// memory and the persisted holes of the ones it does.
    fn open_attempt(&self, run: RunId, job: JobId, attempt: AttemptId) -> Result<Open> {
        let dir = self.attempt_dir(run, job, attempt);
        // The attempt directory and its job and run parents: make each
        // entry durable before any frame in it is acknowledged. Also when
        // the directories already exist — a process that crashed between
        // creating and syncing them left entries a power cut can still take.
        // Once per writer open; syncing an unchanged directory is cheap.
        fs::create_dir_all(&dir)?;
        let mut at = dir.as_path();
        while let Some(parent) = at.parent() {
            sync_dir(parent)?;
            if parent == self.dir {
                break;
            }
            at = parent;
        }
        sweep_tmp(&dir);
        let segs = segs(&dir)?;
        for (n, compressed) in &segs {
            if *compressed {
                let plain = seg_path(&dir, *n, false);
                if plain.exists() {
                    let _ = fs::remove_file(plain);
                }
            }
        }
        let index_path = dir.join("index");
        let ended = end_marker(&dir).map(|m| m.0);
        let mut w = Open {
            dir,
            seg: 0,
            file: None,
            seg_len: 0,
            index: OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(false)
                .open(&index_path)?,
            index_len: 0,
            last_seq: 0,
            holes: Vec::new(),
            holes_dirty: false,
            len: 0,
            lines: 0,
            step: 0,
            since_index: 0,
            seg_checkpointed: false,
            ended,
            scratch: Vec::new(),
        };
        if w.ended.is_some() {
            // Complete on disk: nothing to fold. Leftover plain segments
            // from an interrupted finish still get compressed.
            for (n, compressed) in &segs {
                if !compressed {
                    self.compressor.enqueue(seg_path(&w.dir, *n, false));
                }
            }
            return Ok(w);
        }
        // Holes are known only from jumps; those inside sealed segments are
        // not re-decoded, so the persisted list is their record. Holes of
        // the uncovered segments are re-derived below either way.
        let persisted = read_holes(&w.dir);
        w.holes.clone_from(&persisted);
        // Durable base: totals through the last seal record. Entries past
        // it are provisional and regenerated from the segments they name.
        let index_bytes = fs::read(&index_path).unwrap_or_default();
        let valid = index_bytes.len() >= 6
            && index_bytes[..4] == *INDEX_MAGIC
            && u16::from_le_bytes(index_bytes[4..6].try_into().expect("2")) == INDEX_FORMAT;
        let entries = if valid {
            read_index(&index_bytes)?
        } else {
            Vec::new()
        };
        let mut covered = None;
        let mut keep = 6usize;
        for (at, entry) in entries.iter().enumerate() {
            if entry.kind == KIND_SEAL {
                covered = Some(entry.seg);
                keep = 6 + (at + 1) * INDEX_ENTRY_BYTES;
                w.last_seq = entry.seq;
                w.len = entry.bytes;
                w.lines = entry.line;
                w.step = entry.step;
            }
        }
        if valid {
            w.index.set_len(keep as u64)?;
        } else {
            // Missing or undecodable header: rebuild from the stream.
            w.index.set_len(0)?;
            w.index.write_all(INDEX_MAGIC)?;
            w.index.write_all(&INDEX_FORMAT.to_le_bytes())?;
            keep = 6;
        }
        w.index_len = keep as u64;
        w.index.seek(SeekFrom::End(0))?;
        let top = segs.keys().next_back().copied();
        let mut pending = Vec::new();
        let mut queue = Vec::new();
        for (n, compressed) in &segs {
            let (n, compressed) = (*n, *compressed);
            if covered.is_some_and(|c| n <= c) {
                if !compressed {
                    queue.push(seg_path(&w.dir, n, false));
                }
                continue;
            }
            // Decode the segments the index does not cover, folding state
            // and re-emitting their checkpoints.
            let mut decoder = seg_decoder(&w.dir, n, compressed)?;
            let mut advanced = false;
            let mut ended = false;
            while let Some(record) = decoder.next()? {
                match record {
                    Record::Frame(frame) => {
                        advanced |= fold_frame(&mut w, n, &frame, !advanced, &mut pending);
                    }
                    Record::End { last_seq, gaps } => {
                        w.ended = Some(last_seq);
                        merge_holes(&mut w.holes, &gaps);
                        ended = true;
                    }
                }
            }
            if compressed {
                continue;
            }
            let complete_len = decoder.complete;
            let path = seg_path(&w.dir, n, false);
            if ended || top != Some(n) {
                // A sealed segment: emit its seal record, cut a possible
                // torn tail, and queue it for compression.
                seal_entry(&w, n, &mut pending);
                OpenOptions::new()
                    .write(true)
                    .open(&path)?
                    .set_len(complete_len)?;
                queue.push(path);
            } else {
                // The active segment: cut the torn tail and keep writing.
                let mut file = OpenOptions::new()
                    .write(true)
                    .read(true)
                    .truncate(false)
                    .open(&path)?;
                file.set_len(complete_len)?;
                file.seek(SeekFrom::End(0))?;
                w.seg = n;
                w.seg_len = complete_len;
                w.seg_checkpointed = advanced;
                w.file = Some(file);
            }
        }
        // A finished log whose marker was lost: `finish` sealed the end
        // record into what is then the last segment, and a covered top
        // means nothing followed that seal. Decode it once — bounded by
        // SEGMENT_BYTES — so a lost marker cannot silently reopen the log.
        if w.ended.is_none()
            && let Some(n) = top
            && covered == Some(n)
        {
            let mut decoder = seg_decoder(&w.dir, n, segs[&n])?;
            while let Some(record) = decoder.next()? {
                if let Record::End { last_seq, gaps } = record {
                    w.ended = Some(last_seq);
                    merge_holes(&mut w.holes, &gaps);
                }
            }
        }
        // Holes re-derived from uncovered segments reach the sidecar at the
        // latest with the seal that covers them.
        w.holes.retain(|(from, _)| *from <= w.last_seq);
        w.holes_dirty = w.holes != persisted;
        if let Some(last) = w.ended {
            // The stream carries the end record but the marker never
            // landed: repair it so completeness is one file read.
            write_end_marker(&w.dir, last, &merged_gaps(&w, last, &[]))?;
            w.file = None;
        } else if w.file.is_none() {
            // Everything on disk is sealed (or nothing exists): appends
            // continue in a fresh segment after the last one seen.
            w.seg = top.map_or(0, |n| n + 1);
        }
        if !pending.is_empty() {
            index_write(&mut w, &pending)?;
            w.index.sync_data()?;
        }
        for path in queue {
            self.compressor.enqueue(path);
        }
        Ok(w)
    }

    /// Append one frame: synced, then acknowledged. A jump records a hole;
    /// a frame landing in a hole is stored as a fill. Either change to the
    /// hole list is persisted (the `holes` sidecar) before the frame is
    /// acknowledged, so a restart cannot forget a hole whose frames sit in
    /// a sealed segment.
    pub fn append(
        &self,
        run: RunId,
        job: JobId,
        attempt: AttemptId,
        frame: &Frame,
    ) -> Result<Appended> {
        let appended = self.with_writer(run, job, attempt, |w| self.append_to(w, frame))?;
        if matches!(appended, Appended::Stored { .. }) {
            self.changes.bump();
        }
        Ok(appended)
    }

    fn append_to(&self, w: &mut Open, frame: &Frame) -> Result<Appended> {
        if w.ended.is_some() {
            return Err(Error::Conflict);
        }
        // A hole change whose sidecar write failed is persisted before
        // anything is acknowledged again — a resend of that very frame
        // would otherwise be acked as a duplicate over a forgettable hole.
        persist_holes(w)?;
        if frame.seq <= w.last_seq && !in_hole(&w.holes, frame.seq) {
            return Ok(Appended::Duplicate {
                through: w.last_seq,
            });
        }
        // Evidence keeps its reserve: a frame refused for space is reported
        // as refused, never silently dropped — and never recorded as a hole,
        // since nothing was stored.
        if let Some(a) = self.admission.get()
            && !a.headroom()
        {
            return Err(Error::StorageFull);
        }
        if frame.seq > w.last_seq + 1 && w.holes.len() >= MAX_HOLES {
            return Err(Error::InvalidInput("log holes"));
        }
        w.scratch.clear();
        sentinel_protocol::logs::encode_frame(
            frame.seq,
            frame.step,
            frame.stream,
            &frame.bytes,
            &mut w.scratch,
        )
        .map_err(|_| Error::InvalidInput("log frame"))?;
        let record_len = w.scratch.len() as u64;
        if w.len + record_len > self.max_bytes {
            return Err(Error::InvalidInput("log size"));
        }
        if w.seg_len > 0 && w.seg_len + record_len > SEGMENT_BYTES {
            self.seal(w)?;
        }
        let first_of_seg = w.file.is_none();
        if first_of_seg {
            w.file = Some(
                OpenOptions::new()
                    .create(true)
                    .write(true)
                    .truncate(false)
                    .open(seg_path(&w.dir, w.seg, false))?,
            );
            // The acknowledgement below promises the frame survives a power
            // loss; a segment file whose directory entry is not durable yet
            // could vanish with it. Once per segment.
            sync_dir(&w.dir)?;
        }
        let file = w.file.as_mut().expect("opened above");
        if let Err(e) = file.write_all(&w.scratch).and_then(|()| file.sync_data()) {
            // Never acknowledged, so never kept: a short write (ENOSPC, a
            // file size limit) or a failed sync must not leave a record for
            // the next frame to land behind. `with_writer` reopens from
            // disk, which cuts whatever this could not.
            let _ = file.set_len(w.seg_len);
            return Err(e.into());
        }
        let step_changed = frame.step != w.step;
        w.seg_len += record_len;
        w.len += record_len;
        w.lines += frame.bytes.iter().filter(|b| **b == b'\n').count() as u64;
        if frame.seq <= w.last_seq {
            // A fill: stored but never indexed — index entries must stay
            // in sequence order for the tail seek.
            fill_hole(&mut w.holes, frame.seq);
            w.holes_dirty = true;
        } else {
            // The hole opens only once the frame past it is durable: a
            // failed write leaves neither.
            if frame.seq > w.last_seq + 1 {
                add_hole(&mut w.holes, w.last_seq + 1, frame.seq - 1);
                w.holes_dirty = true;
            }
            w.last_seq = frame.seq;
            w.step = frame.step;
            w.since_index += 1;
            if !w.seg_checkpointed || step_changed || w.since_index >= INDEX_EVERY {
                checkpoint(w);
                w.since_index = 0;
                w.seg_checkpointed = true;
            }
        }
        persist_holes(w)?;
        Ok(Appended::Stored {
            through: w.last_seq,
        })
    }

    /// Close the active segment: seal record into the index, fsync, and
    /// queue the segment for compression.
    fn seal(&self, w: &mut Open) -> Result<()> {
        // The seal record makes the segment "covered": its holes must be in
        // the sidecar before reopen stops re-deriving them.
        persist_holes(w)?;
        let mut entry = Vec::with_capacity(INDEX_ENTRY_BYTES);
        seal_entry(w, w.seg, &mut entry);
        index_write(w, &entry)?;
        w.index.sync_data()?;
        if let Some(file) = w.file.take() {
            file.sync_data()?;
        }
        self.compressor.enqueue(seg_path(&w.dir, w.seg, false));
        w.seg += 1;
        w.seg_len = 0;
        w.since_index = 0;
        w.seg_checkpointed = false;
        Ok(())
    }

    /// The worker will send nothing more: write the end record, seal the
    /// segment, and land the marker. `last_seq` may pass what was stored —
    /// the unwritten tail is declared as a gap, never refused.
    pub fn finish(
        &self,
        run: RunId,
        job: JobId,
        attempt: AttemptId,
        last_seq: u64,
        gaps: &[(u64, u64)],
    ) -> Result<()> {
        let fresh = self.with_writer(run, job, attempt, |w| {
            if let Some(ended) = w.ended {
                return if ended == last_seq {
                    Ok(false)
                } else {
                    Err(Error::Conflict)
                };
            }
            if last_seq < w.last_seq {
                return Err(Error::Conflict);
            }
            let merged = merged_gaps(w, last_seq, gaps);
            w.scratch.clear();
            Record::End {
                last_seq,
                gaps: gaps.to_vec(),
            }
            .encode(&mut w.scratch)
            .map_err(|_| Error::InvalidInput("log end"))?;
            if w.file.is_none() {
                w.file = Some(
                    OpenOptions::new()
                        .create(true)
                        .write(true)
                        .truncate(false)
                        .open(seg_path(&w.dir, w.seg, false))?,
                );
            }
            w.file
                .as_mut()
                .expect("opened above")
                .write_all(&w.scratch)?;
            w.file.as_mut().expect("opened above").sync_data()?;
            self.seal(w)?;
            write_end_marker(&w.dir, last_seq, &merged)?;
            w.ended = Some(last_seq);
            Ok(true)
        })?;
        // A finished log needs no writer: its descriptors and scratch go
        // now. Anyone still holding the slot sees `ended`; a later open
        // reads the marker.
        self.open
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&attempt);
        if fresh {
            self.changes.bump();
        }
        Ok(())
    }

    /// Read records with sequence greater than `after`, at most `limit`
    /// frames, filtered to `step` when given. The sparse index seeks the
    /// segment holding `after`, so a tail never re-reads the head.
    pub fn tail(
        &self,
        run: RunId,
        job: JobId,
        attempt: AttemptId,
        after: u64,
        limit: usize,
        step: Option<u32>,
    ) -> Result<Tail> {
        read_dir(&self.attempt_dir(run, job, attempt), after, limit, step)
    }

    /// [`LogStore::tail`] under a [`Page`] ([`read_page`]).
    pub fn tail_page(
        &self,
        run: RunId,
        job: JobId,
        attempt: AttemptId,
        after: u64,
        page: Page,
        step: Option<u32>,
    ) -> Result<Tail> {
        read_page(&self.attempt_dir(run, job, attempt), after, page, step)
    }

    /// The attempt's stored frontier as its live writer knows it — no
    /// I/O: `None` when this process holds no writer for it. A long poll
    /// compares it across wakes so appends to *other* attempts cost it
    /// nothing.
    pub fn frontier(&self, attempt: AttemptId) -> Option<(u64, bool)> {
        let slot = self
            .open
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&attempt)
            .cloned()?;
        let guard = slot.open.lock().unwrap_or_else(|p| p.into_inner());
        guard.as_ref().map(|w| (w.last_seq, w.ended.is_some()))
    }

    /// The newest sequence known for an attempt without decoding log
    /// frames. Open writers answer from memory, completed writers from the
    /// durable end marker, and recovered incomplete logs from their final
    /// sparse-index entry.
    pub fn last_seq(&self, run: RunId, job: JobId, attempt: AttemptId) -> Result<Option<u64>> {
        if let Some((seq, _)) = self.frontier(attempt) {
            return Ok(Some(seq));
        }
        let dir = self.attempt_dir(run, job, attempt);
        if let Some((seq, _)) = end_marker(&dir) {
            return Ok(Some(seq));
        }
        let path = dir.join("index");
        let mut file = match File::open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let len = file.metadata()?.len();
        if len < 6 {
            return Ok(None);
        }
        let mut header = [0u8; 6];
        file.seek(SeekFrom::Start(0))?;
        file.read_exact(&mut header)?;
        if header[..4] != *INDEX_MAGIC
            || u16::from_le_bytes(header[4..6].try_into().expect("2")) != INDEX_FORMAT
        {
            return Err(Error::Corrupt("log index"));
        }
        let valid_len = len - 6;
        if valid_len < INDEX_ENTRY_BYTES as u64 {
            return Ok(None);
        }
        let end = len - (valid_len % INDEX_ENTRY_BYTES as u64);
        if end < INDEX_ENTRY_BYTES as u64 + 6 {
            return Ok(None);
        }
        file.seek(SeekFrom::Start(end - INDEX_ENTRY_BYTES as u64))?;
        let mut encoded = [0u8; INDEX_ENTRY_BYTES];
        file.read_exact(&mut encoded)?;
        Entry::decode(&encoded)
            .map(|entry| Some(entry.seq))
            .ok_or(Error::Corrupt("log index"))
    }

    /// Pre-D04 flat logs (`<logs>/<attempt>.log`), kept readable. The read
    /// streams in bounded chunks like a segmented log; the step filter
    /// applies during the scan so foreign frames never eat the limit.
    pub fn tail_legacy(
        &self,
        attempt: AttemptId,
        after: u64,
        limit: usize,
        step: Option<u32>,
    ) -> Result<Tail> {
        read_tail(&self.dir.join(format!("{attempt}.log")), after, limit, step)
    }

    /// [`LogStore::tail_legacy`] with a returned-bytes bound: frames stop
    /// collecting at `page.bytes` (with `next_after`) while the scan still
    /// streams to the end marker for completeness.
    pub fn tail_legacy_page(
        &self,
        attempt: AttemptId,
        after: u64,
        page: Page,
        step: Option<u32>,
    ) -> Result<Tail> {
        read_tail_page(&self.dir.join(format!("{attempt}.log")), after, page, step)
    }

    /// Find a literal byte string in an attempt's log (O05): frames with
    /// sequence greater than `after`, scanned in stored order with one
    /// precompiled `memmem` finder and no per-frame allocation beyond the
    /// decode, until `limit` matching lines or `budget` payload bytes.
    ///
    /// A literal split across consecutive frames of the same step and
    /// stream is found exactly once, reported with the frame it ends in,
    /// whatever separates the pieces: a frame boundary, a sealed segment,
    /// other frames, or the cut between two requests. The scanner keeps
    /// each stream's open line as its last `needle.len() - 1` bytes; a
    /// request that stops early returns that state as [`Search::carry`],
    /// and the next request resumes from it ([`SearchQuery::carry`]).
    pub fn search(
        &self,
        run: RunId,
        job: JobId,
        attempt: AttemptId,
        query: SearchQuery<'_>,
    ) -> Result<Search> {
        let mut scanner = Scanner::new(query)?;
        search_dir(&self.attempt_dir(run, job, attempt), &mut scanner)
    }

    /// [`LogStore::search`] over a pre-D04 flat log.
    pub fn search_legacy(&self, attempt: AttemptId, query: SearchQuery<'_>) -> Result<Search> {
        let mut scanner = Scanner::new(query)?;
        let file = match File::open(self.dir.join(format!("{attempt}.log"))) {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(Error::NotFound),
            Err(e) => return Err(e.into()),
        };
        let mut decoder = Decoder {
            reader: Box::new(file),
            buf: Vec::new(),
            complete: 0,
            plain: true,
        };
        let mut ended = false;
        while let Some(record) = decoder.next()? {
            match record {
                Record::Frame(frame) => {
                    if !scanner.frame(&frame) {
                        return Ok(scanner.finish(false));
                    }
                }
                Record::End { .. } => {
                    ended = true;
                    break;
                }
            }
        }
        Ok(scanner.finish(ended))
    }
}

/// Bytes of frame payload one search request scans at most; a bigger log
/// takes several requests, each resuming at the previous `next_after`.
pub const SEARCH_SCAN_BYTES: u64 = 4 << 20;
/// A match's reported text: its line, cut to this many bytes around it.
pub const MATCH_TEXT_BYTES: usize = 512;
/// Longest needle whose split across two frames is still found; the API
/// accepts no longer one. A longer needle matches within one frame only.
pub const MAX_NEEDLE: usize = 256;
/// Context kept before a match inside one frame.
const LEAD: usize = MATCH_TEXT_BYTES / 4;
/// Look-behind one stream keeps: the most of a split needle that can
/// precede the frame it ends in.
const LOOK_BEHIND: usize = MAX_NEEDLE - 1;

/// The resume state's layout (hex on the wire): `format u8 | after u64 |
/// needle length u16`, then per stream `flags u8 | step u32 | len u8 |
/// len bytes`. Fixed upper size, so parsing never allocates.
const CARRY_FORMAT: u8 = 1;
const CARRY_OPEN: u8 = 1;
const CARRY_REPORTED: u8 = 2;
const CARRY_STREAM_BYTES: usize = 1 + 4 + 1;
const CARRY_MAX_BYTES: usize = 1 + 8 + 2 + 2 * (CARRY_STREAM_BYTES + LOOK_BEHIND);
/// Longest [`Search::carry`] text.
pub const MAX_CARRY_TEXT: usize = 2 * CARRY_MAX_BYTES;

/// A bounded literal search: frames past `after`, at most `limit` matching
/// lines and `budget` scanned payload bytes (normally [`SEARCH_SCAN_BYTES`]).
#[derive(Clone, Copy, Debug)]
pub struct SearchQuery<'a> {
    pub needle: &'a [u8],
    pub after: u64,
    pub limit: usize,
    pub budget: u64,
    /// The [`Search::carry`] returned with `after` as `next_after`, for the
    /// same needle. Without it the state is rebuilt from the frames before
    /// `after` in the segment that holds it (the sealed one when `after`
    /// ends it), which misses a line begun earlier than that.
    pub carry: Option<&'a str>,
}

/// One matching line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Match {
    pub seq: u64,
    pub step: u32,
    pub stream: sentinel_protocol::logs::Stream,
    /// The line holding the match (without its newline), at most
    /// [`MATCH_TEXT_BYTES`] around the first match on it. A match that
    /// began in an earlier frame starts at the match.
    pub text: Vec<u8>,
}

/// What one bounded search found. `next_after` is set when the scan
/// stopped at the match limit or the byte budget before the end of what is
/// stored: pass it as the next request's `after`, with `carry`. `complete`
/// means the log is finished and the scan reached its end, so nothing more
/// can match. Neither set: the scan reached the end of a log still being
/// written.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Search {
    pub matches: Vec<Match>,
    pub next_after: Option<u64>,
    /// Set with `next_after`: each stream's open line (at most
    /// `needle.len() - 1` bytes) and whether it was already reported, as
    /// at most [`MAX_CARRY_TEXT`] hex characters.
    pub carry: Option<String>,
    pub complete: bool,
}

/// One stream's open line: the latest frame of the stream ended inside a
/// line of `step`. Only its last `needle.len() - 1` bytes are kept — all a
/// needle split across the next frame boundary can need. Fixed-size: no
/// allocation per frame.
#[derive(Clone, Copy)]
struct Carry {
    open: bool,
    /// The open line already produced a match (one report per line).
    reported: bool,
    step: u32,
    len: usize,
    buf: [u8; LOOK_BEHIND],
}

impl Carry {
    const CLOSED: Carry = Carry {
        open: false,
        reported: false,
        step: 0,
        len: 0,
        buf: [0; LOOK_BEHIND],
    };

    /// Whether `frame` continues this open line.
    const fn continues(&self, frame: &Frame) -> bool {
        self.open && self.step == frame.step
    }

    /// Start a new line (or none) from `bytes`, which hold no newline.
    fn restart(&mut self, bytes: &[u8], reported: bool, keep: usize) {
        self.open = !bytes.is_empty();
        self.reported = reported;
        self.len = 0;
        self.extend(bytes, keep);
    }

    /// Continue the open line with `bytes` (no newline), keeping its last
    /// `keep` bytes.
    fn extend(&mut self, bytes: &[u8], keep: usize) {
        if bytes.len() >= keep {
            self.buf[..keep].copy_from_slice(&bytes[bytes.len() - keep..]);
            self.len = keep;
            return;
        }
        let kept = self.len.min(keep - bytes.len());
        self.buf.copy_within(self.len - kept..self.len, 0);
        self.buf[kept..kept + bytes.len()].copy_from_slice(bytes);
        self.len = kept + bytes.len();
    }
}

/// The per-request scan state: the finder is built once per request.
struct Scanner<'n> {
    finder: memchr::memmem::Finder<'n>,
    needle: usize,
    /// Look-behind kept per stream: `needle - 1`, at most [`LOOK_BEHIND`].
    keep: usize,
    /// Frames at or below this were scanned by earlier requests; it moves
    /// with the scan and becomes `next_after`.
    after: u64,
    limit: usize,
    budget: u64,
    scanned: u64,
    /// The carry came with the query: frames at or below `after` are
    /// skipped outright instead of replayed.
    seeded: bool,
    /// A frame past the query's `after` was scanned; earlier frames at or
    /// below the moving `after` are late fills, not replay.
    started: bool,
    out: Search,
    /// Indexed by stream (stdout, stderr).
    carry: [Carry; 2],
}

impl<'n> Scanner<'n> {
    fn new(query: SearchQuery<'n>) -> Result<Scanner<'n>> {
        let mut scanner = Scanner {
            finder: memchr::memmem::Finder::new(query.needle),
            needle: query.needle.len(),
            keep: query.needle.len().saturating_sub(1).min(LOOK_BEHIND),
            after: query.after,
            limit: query.limit,
            budget: query.budget,
            scanned: 0,
            seeded: false,
            started: false,
            out: Search::default(),
            carry: [Carry::CLOSED, Carry::CLOSED],
        };
        if let Some(text) = query.carry {
            scanner
                .seed(text.as_bytes())
                .ok_or(Error::InvalidInput("search carry"))?;
            scanner.seeded = true;
        }
        Ok(scanner)
    }

    /// Scan one decoded frame; `false` once the request's bound is reached
    /// (with `next_after` and `carry` set). Both bounds are checked between
    /// frames, so one frame's matching lines are never split across
    /// responses, and a frame that would take the scan past `budget` waits
    /// for the next request (the first frame always scans, so every request
    /// progresses).
    fn frame(&mut self, frame: &Frame) -> bool {
        if frame.seq <= self.after {
            if !self.seeded && !self.started {
                self.replay(frame);
            }
            return true;
        }
        let len = frame.bytes.len() as u64;
        if self.out.matches.len() >= self.limit
            || (self.started && self.scanned.saturating_add(len) > self.budget)
        {
            self.out.next_after = Some(self.after);
            self.out.carry = Some(self.carry_text());
            return false;
        }
        self.started = true;
        let bytes = &frame.bytes[..];
        let mut from = self.across(frame);
        // Whether the frame's last (unfinished) line has been reported.
        let mut tail_reported = from > bytes.len();
        while from < bytes.len()
            && let Some(at) = self.finder.find(&bytes[from..])
        {
            let at = from + at;
            let line_start = memchr::memrchr(b'\n', &bytes[..at]).map_or(0, |i| i + 1);
            let line_end = memchr::memchr(b'\n', &bytes[at..]).map_or(bytes.len(), |i| at + i);
            let start = line_start.max(at.saturating_sub(LEAD));
            let end = trim_cr(bytes, start, line_end.min(start + MATCH_TEXT_BYTES));
            self.out.matches.push(Match {
                seq: frame.seq,
                step: frame.step,
                stream: frame.stream,
                text: bytes[start..end].to_vec(),
            });
            tail_reported = line_end == bytes.len();
            // One report per line; the next match starts past it.
            from = line_end + 1;
        }
        self.remember(frame, tail_reported);
        self.scanned += len;
        self.after = frame.seq;
        true
    }

    /// The scan ended without a bound stopping it.
    fn finish(&mut self, complete: bool) -> Search {
        let mut out = std::mem::take(&mut self.out);
        out.complete = complete && out.next_after.is_none();
        out
    }

    /// Where the in-frame scan starts, after handling the stream's open
    /// line: past the frame's first line when that line continues one
    /// already reported, or when a match starting in the carried bytes ends
    /// in it (reported here); 0 otherwise. Past the frame's end means its
    /// last line is reported.
    fn across(&mut self, frame: &Frame) -> usize {
        let carry = &self.carry[frame.stream as usize - 1];
        if !carry.continues(frame) {
            return 0;
        }
        let bytes = &frame.bytes[..];
        let first_line = memchr::memchr(b'\n', bytes).unwrap_or(bytes.len());
        if carry.reported {
            return first_line + 1;
        }
        let Some(at) = self.cross(carry, &bytes[..first_line]) else {
            return 0;
        };
        let lead = &carry.buf[at..carry.len];
        let end = trim_cr(bytes, 0, first_line.min(MATCH_TEXT_BYTES - lead.len()));
        let mut text = Vec::with_capacity(lead.len() + end);
        text.extend_from_slice(lead);
        text.extend_from_slice(&bytes[..end]);
        self.out.matches.push(Match {
            seq: frame.seq,
            step: frame.step,
            stream: frame.stream,
            text,
        });
        first_line + 1
    }

    /// Where a match that starts in `carry`'s bytes and ends in `line` (the
    /// next frame's first line) starts, if there is one. Each side is
    /// shorter than the needle, so any match in their join crosses.
    fn cross(&self, carry: &Carry, line: &[u8]) -> Option<usize> {
        let n = self.needle;
        if !(2..=MAX_NEEDLE).contains(&n) || carry.len == 0 || line.is_empty() {
            return None;
        }
        let head = line.len().min(n - 1);
        let mut window = [0u8; 2 * LOOK_BEHIND];
        window[..carry.len].copy_from_slice(&carry.buf[..carry.len]);
        window[carry.len..carry.len + head].copy_from_slice(&line[..head]);
        self.finder.find(&window[..carry.len + head])
    }

    /// Rebuild the carry from a frame an earlier request scanned: only
    /// whether its last line holds a match matters, so only that line is
    /// searched. Equivalent to [`Scanner::frame`]'s state change.
    fn replay(&mut self, frame: &Frame) {
        let bytes = &frame.bytes[..];
        let carry = &self.carry[frame.stream as usize - 1];
        let tail_reported = match memchr::memrchr(b'\n', bytes) {
            Some(nl) => self.finder.find(&bytes[nl + 1..]).is_some(),
            None if carry.continues(frame) => {
                carry.reported
                    || self.cross(carry, bytes).is_some()
                    || self.finder.find(bytes).is_some()
            }
            None => self.finder.find(bytes).is_some(),
        };
        self.remember(frame, tail_reported);
    }

    /// Keep the frame's unfinished last line as its stream's carry.
    fn remember(&mut self, frame: &Frame, tail_reported: bool) {
        let keep = self.keep;
        let carry = &mut self.carry[frame.stream as usize - 1];
        let bytes = &frame.bytes[..];
        match memchr::memrchr(b'\n', bytes) {
            Some(nl) => carry.restart(&bytes[nl + 1..], tail_reported, keep),
            None if carry.continues(frame) => {
                carry.reported |= tail_reported;
                carry.extend(bytes, keep);
            }
            None => carry.restart(bytes, tail_reported, keep),
        }
        carry.step = frame.step;
    }

    /// The resume state after the last scanned frame, as hex.
    fn carry_text(&self) -> String {
        let mut raw = [0u8; CARRY_MAX_BYTES];
        raw[0] = CARRY_FORMAT;
        raw[1..9].copy_from_slice(&self.after.to_le_bytes());
        raw[9..11].copy_from_slice(&(self.needle.min(usize::from(u16::MAX)) as u16).to_le_bytes());
        let mut at = 11;
        for carry in &self.carry {
            raw[at] = if carry.open { CARRY_OPEN } else { 0 }
                | if carry.reported { CARRY_REPORTED } else { 0 };
            raw[at + 1..at + 5].copy_from_slice(&carry.step.to_le_bytes());
            raw[at + 5] = carry.len as u8;
            at += CARRY_STREAM_BYTES;
            raw[at..at + carry.len].copy_from_slice(&carry.buf[..carry.len]);
            at += carry.len;
        }
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut text = String::with_capacity(2 * at);
        for byte in &raw[..at] {
            text.push(char::from(HEX[usize::from(byte >> 4)]));
            text.push(char::from(HEX[usize::from(byte & 15)]));
        }
        text
    }

    /// Load the resume state [`Scanner::carry_text`] wrote; `None` when it
    /// is malformed or belongs to another `after` or needle length.
    fn seed(&mut self, text: &[u8]) -> Option<()> {
        if !text.len().is_multiple_of(2) || text.len() > MAX_CARRY_TEXT {
            return None;
        }
        let mut raw = [0u8; CARRY_MAX_BYTES];
        let raw = &mut raw[..text.len() / 2];
        for (byte, pair) in raw.iter_mut().zip(text.chunks_exact(2)) {
            *byte = (hex_digit(pair[0])? << 4) | hex_digit(pair[1])?;
        }
        let (&format, rest) = raw.split_first()?;
        let (after, rest) = rest.split_first_chunk::<8>()?;
        let (needle, mut rest) = rest.split_first_chunk::<2>()?;
        if format != CARRY_FORMAT
            || u64::from_le_bytes(*after) != self.after
            || usize::from(u16::from_le_bytes(*needle)) != self.needle.min(usize::from(u16::MAX))
        {
            return None;
        }
        for carry in &mut self.carry {
            let (&flags, r) = rest.split_first()?;
            let (step, r) = r.split_first_chunk::<4>()?;
            let (&len, r) = r.split_first()?;
            let len = usize::from(len);
            let open = flags & CARRY_OPEN != 0;
            if flags & !(CARRY_OPEN | CARRY_REPORTED) != 0
                || len > self.keep
                || r.len() < len
                || (!open && (flags != 0 || len != 0))
            {
                return None;
            }
            carry.open = open;
            carry.reported = flags & CARRY_REPORTED != 0;
            carry.step = u32::from_le_bytes(*step);
            carry.len = len;
            carry.buf[..len].copy_from_slice(&r[..len]);
            rest = &r[len..];
        }
        rest.is_empty().then_some(())
    }
}

const fn hex_digit(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    }
}

/// `end`, moved back over a `\r` that ends the line.
fn trim_cr(bytes: &[u8], start: usize, end: usize) -> usize {
    if end > start && bytes[end - 1] == b'\r' {
        end - 1
    } else {
        end
    }
}

/// Where a scan for frames past `after` starts: the last checkpoint at or
/// before `after` names the segment (a seal entry's coverage ends with its
/// segment, so the next frames sit in the one after). With `replay`, a
/// seal names its own segment instead, so the frames that end at `after`
/// are decoded too.
fn seek_start(entries: &[Entry], after: u64, replay: bool) -> u32 {
    let mut start = 0u32;
    for entry in entries {
        if entry.seq <= after {
            start = if entry.kind == KIND_SEAL && !replay {
                entry.seg.saturating_add(1)
            } else {
                entry.seg
            };
        }
    }
    start
}

fn search_dir(dir: &Path, scanner: &mut Scanner<'_>) -> Result<Search> {
    let segs = segs(dir)?;
    let marker = end_marker(dir).is_some();
    if segs.is_empty() && !marker {
        return Err(Error::NotFound);
    }
    let index_bytes = fs::read(dir.join("index")).unwrap_or_default();
    let entries = read_index(&index_bytes).unwrap_or_default();
    let start = seek_start(&entries, scanner.after, !scanner.seeded);
    let mut ended = marker;
    'decode: for (n, compressed) in segs.range(start..) {
        let Some(mut decoder) = listed_seg_decoder(dir, *n, *compressed)? else {
            break;
        };
        while let Some(record) = decoder.next()? {
            match record {
                Record::Frame(frame) => {
                    if !scanner.frame(&frame) {
                        return Ok(scanner.finish(false));
                    }
                }
                Record::End { .. } => {
                    ended = true;
                    break 'decode;
                }
            }
        }
    }
    Ok(scanner.finish(ended))
}

impl Drop for LogStore {
    fn drop(&mut self) {
        self.compressor.stop.store(true, Ordering::Release);
        self.compressor.wake.notify_one();
        if let Some(worker) = self.worker.lock().unwrap_or_else(|p| p.into_inner()).take() {
            let _ = worker.join();
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tail {
    pub frames: Vec<Frame>,
    pub complete: bool,
    pub gaps: Vec<(u64, u64)>,
    /// Set when a [`Page`] bound cut the read before the end of what is
    /// stored: the next read's `after`. `None` means the read reached the
    /// end (of the log, or of what is stored so far).
    pub next_after: Option<u64>,
    /// With a step filter: the log has moved on to a later step, so no new
    /// frame of this step will arrive — a long poll has nothing to wait for.
    pub step_done: bool,
}

/// The bounds of one tail read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Page {
    /// Frames returned at most.
    pub limit: usize,
    /// Payload bytes returned at most (the first frame always fits).
    pub bytes: u64,
    /// Payload bytes decoded past `after` at most, filtered-out frames
    /// included.
    pub scan: u64,
}

impl Page {
    /// Only a frame count: the unbounded reader's shape.
    #[must_use]
    pub const fn frames(limit: usize) -> Page {
        Page {
            limit,
            bytes: u64::MAX,
            scan: u64::MAX,
        }
    }
}

/// Payload bytes one API log page returns at most. JSON escaping can grow
/// a byte to six (``), so a page stays under ~6 MiB on the wire —
/// inside common client body limits (the CLI's is 10 MiB).
pub const PAGE_BYTES: u64 = 1 << 20;
/// Payload bytes one API log page decodes past `after` at most: a step
/// filter over a long log answers with `next_after` instead of decoding to
/// the end in one request.
pub const PAGE_SCAN_BYTES: u64 = 16 << 20;

fn seg_path(dir: &Path, seg: u32, compressed: bool) -> PathBuf {
    if compressed {
        dir.join(format!("seg-{seg:06}.z"))
    } else {
        dir.join(format!("seg-{seg:06}"))
    }
}

/// Segment number → compressed, in order. A `.z` twin wins over the
/// plain name: the rename was durable, the plain file is a leftover.
fn segs(dir: &Path) -> Result<BTreeMap<u32, bool>> {
    let mut out = BTreeMap::new();
    let read = match fs::read_dir(dir) {
        Ok(read) => read,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(Error::NotFound),
        Err(e) => return Err(e.into()),
    };
    for entry in read.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let Some(rest) = name.strip_prefix("seg-") else {
            continue;
        };
        let (num, compressed) = match rest.strip_suffix(".z") {
            Some(num) => (num, true),
            None => (rest, false),
        };
        if let Ok(n) = num.parse::<u32>() {
            *out.entry(n).or_insert(false) |= compressed;
        }
    }
    Ok(out)
}

/// A file's mtime in Unix milliseconds.
fn mtime_ms(path: &Path) -> Option<i64> {
    fs::metadata(path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_millis() as i64)
}

/// When an attempt directory last changed: the newest of its `end` marker,
/// its `index` and its highest segment — every write lands in one of those
/// (older segments are sealed and only ever renamed to their `.z` twin).
fn newest_ms(dir: &Path) -> i64 {
    let top = segs(dir)
        .ok()
        .and_then(|segs| segs.iter().next_back().map(|(n, z)| seg_path(dir, *n, *z)));
    [Some(dir.join("end")), Some(dir.join("index")), top]
        .into_iter()
        .flatten()
        .filter_map(|p| mtime_ms(&p))
        .max()
        .unwrap_or(0)
}

fn sweep_tmp(dir: &Path) {
    if let Ok(read) = fs::read_dir(dir) {
        for entry in read.flatten() {
            if entry
                .file_name()
                .to_str()
                .is_some_and(|n| n.ends_with(".tmp"))
            {
                let _ = fs::remove_file(entry.path());
            }
        }
    }
}

/// The durable completeness marker, decoded: `(last_seq, gaps)`.
fn end_marker(dir: &Path) -> Option<(u64, Vec<(u64, u64)>)> {
    let bytes = fs::read(dir.join("end")).ok()?;
    if bytes.len() < 18
        || bytes[..4] != *END_MAGIC
        || u16::from_le_bytes(bytes[4..6].try_into().ok()?) != END_FORMAT
    {
        return None;
    }
    let last_seq = u64::from_le_bytes(bytes[6..14].try_into().ok()?);
    let count = u32::from_le_bytes(bytes[14..18].try_into().ok()?) as usize;
    if bytes.len() < 18 + count * 16 {
        return None;
    }
    let gaps = (0..count)
        .map(|i| {
            let at = 18 + i * 16;
            (
                u64::from_le_bytes(bytes[at..at + 8].try_into().expect("8")),
                u64::from_le_bytes(bytes[at + 8..at + 16].try_into().expect("8")),
            )
        })
        .collect();
    Some((last_seq, gaps))
}

/// The marker lands atomically: tmp, fsync, rename, fsync the directory.
/// Either complete or absent — never torn.
fn write_end_marker(dir: &Path, last_seq: u64, gaps: &[(u64, u64)]) -> Result<()> {
    let mut bytes = Vec::with_capacity(18 + gaps.len() * 16);
    bytes.extend_from_slice(END_MAGIC);
    bytes.extend_from_slice(&END_FORMAT.to_le_bytes());
    bytes.extend_from_slice(&last_seq.to_le_bytes());
    bytes.extend_from_slice(&(gaps.len() as u32).to_le_bytes());
    for (from, to) in gaps {
        bytes.extend_from_slice(&from.to_le_bytes());
        bytes.extend_from_slice(&to.to_le_bytes());
    }
    let tmp = dir.join("end.tmp");
    {
        let mut file = File::create(&tmp)?;
        file.write_all(&bytes)?;
        file.sync_data()?;
    }
    fs::rename(&tmp, dir.join("end"))?;
    sync_dir(dir)
}

/// Land the hole list if it changed: tmp, fsync, rename, directory
/// fsync — complete or absent, like the end marker. Rare: only jumps and
/// fills change it.
fn persist_holes(w: &mut Open) -> Result<()> {
    if !w.holes_dirty {
        return Ok(());
    }
    let mut bytes = Vec::with_capacity(10 + w.holes.len() * 16);
    bytes.extend_from_slice(HOLES_MAGIC);
    bytes.extend_from_slice(&HOLES_FORMAT.to_le_bytes());
    bytes.extend_from_slice(&(w.holes.len() as u32).to_le_bytes());
    for (from, to) in &w.holes {
        bytes.extend_from_slice(&from.to_le_bytes());
        bytes.extend_from_slice(&to.to_le_bytes());
    }
    let tmp = w.dir.join("holes.tmp");
    {
        let mut file = File::create(&tmp)?;
        file.write_all(&bytes)?;
        file.sync_data()?;
    }
    fs::rename(&tmp, w.dir.join("holes"))?;
    sync_dir(&w.dir)?;
    w.holes_dirty = false;
    Ok(())
}

/// The persisted hole list; absent or undecodable reads as none (a log
/// written before the sidecar existed re-derives what it can).
fn read_holes(dir: &Path) -> Vec<(u64, u64)> {
    let Ok(bytes) = fs::read(dir.join("holes")) else {
        return Vec::new();
    };
    if bytes.len() < 10
        || bytes[..4] != *HOLES_MAGIC
        || u16::from_le_bytes([bytes[4], bytes[5]]) != HOLES_FORMAT
    {
        return Vec::new();
    }
    let count = u32::from_le_bytes(bytes[6..10].try_into().expect("4")) as usize;
    if count > MAX_HOLES || bytes.len() != 10 + count * 16 {
        return Vec::new();
    }
    let mut holes = Vec::with_capacity(count);
    for pair in bytes[10..].chunks_exact(16) {
        let from = u64::from_le_bytes(pair[..8].try_into().expect("8"));
        let to = u64::from_le_bytes(pair[8..].try_into().expect("8"));
        add_hole(&mut holes, from, to);
    }
    holes
}

/// Index file → entries, validated against magic and format. A torn tail
/// entry is ignored; a bad header reports corrupt so the caller rebuilds.
fn read_index(bytes: &[u8]) -> Result<Vec<Entry>> {
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    if bytes.len() < 6
        || bytes[..4] != *INDEX_MAGIC
        || u16::from_le_bytes(bytes[4..6].try_into().expect("2")) != INDEX_FORMAT
    {
        return Err(Error::Corrupt("log index"));
    }
    let mut out = Vec::new();
    let mut at = 6;
    while let Some(entry) = Entry::decode(&bytes[at..]) {
        out.push(entry);
        at += INDEX_ENTRY_BYTES;
    }
    Ok(out)
}

/// Append `bytes` at the index's valid tail. A failed write is truncated
/// back to `index_len` so a torn entry never hides what follows it; if the
/// repair itself fails the index is abandoned — readers decode less, never
/// more, and reopen rebuilds from the segments.
fn index_write(w: &mut Open, bytes: &[u8]) -> Result<()> {
    if w.index_len == u64::MAX {
        return Err(Error::Corrupt("log index"));
    }
    match w.index.write_all(bytes) {
        Ok(()) => {
            w.index_len += bytes.len() as u64;
            Ok(())
        }
        Err(e) => {
            if w.index.set_len(w.index_len).is_err()
                || w.index.seek(SeekFrom::Start(w.index_len)).is_err()
            {
                w.index_len = u64::MAX;
            }
            Err(e.into())
        }
    }
}

/// A checkpoint for the frame just stored (`line`/`bytes` include it).
/// Provisional: no fsync here — the seal fsyncs; a crash loses these and
/// the reopen regenerates them from the segment itself. A failed write
/// leaves no torn entry (`index_write` repairs), so ignoring it is safe.
fn checkpoint(w: &mut Open) {
    let entry = Entry {
        kind: KIND_CHECKPOINT,
        seq: w.last_seq,
        seg: w.seg,
        step: w.step,
        line: w.lines,
        bytes: w.len,
        ms: UnixMillis::now().0,
    };
    let _ = index_write(w, &entry.bytes());
}

/// A seal record for segment `seg` carrying the running totals.
fn seal_entry(w: &Open, seg: u32, out: &mut Vec<u8>) {
    let entry = Entry {
        kind: KIND_SEAL,
        seq: w.last_seq,
        seg,
        step: w.step,
        line: w.lines,
        bytes: w.len,
        ms: UnixMillis::now().0,
    };
    out.extend_from_slice(&entry.bytes());
}

/// Fold one decoded frame into reopen state: hole bookkeeping, counters,
/// and the same checkpoint triggers a live append would hit (`first` is
/// true until this segment's first frontier-advancing frame). Returns
/// whether the frame advanced the frontier; fills are folded into the
/// counters but never indexed, keeping entries in sequence order.
fn fold_frame(w: &mut Open, seg: u32, frame: &Frame, first: bool, pending: &mut Vec<u8>) -> bool {
    if frame.seq > w.last_seq + 1 {
        add_hole(&mut w.holes, w.last_seq + 1, frame.seq - 1);
    }
    let step_changed = frame.step != w.step;
    w.len += (FRAME_HEADER_BYTES + frame.bytes.len()) as u64;
    w.lines += frame.bytes.iter().filter(|b| **b == b'\n').count() as u64;
    if frame.seq <= w.last_seq {
        fill_hole(&mut w.holes, frame.seq);
        return false;
    }
    w.last_seq = frame.seq;
    w.step = frame.step;
    w.since_index += 1;
    if first || step_changed || w.since_index >= INDEX_EVERY {
        let entry = Entry {
            kind: KIND_CHECKPOINT,
            seq: frame.seq,
            seg,
            step: w.step,
            line: w.lines,
            bytes: w.len,
            ms: UnixMillis::now().0,
        };
        pending.extend_from_slice(&entry.bytes());
        w.since_index = 0;
    }
    true
}

fn in_hole(holes: &[(u64, u64)], seq: u64) -> bool {
    holes
        .binary_search_by(|(from, to)| {
            if seq < *from {
                std::cmp::Ordering::Greater
            } else if seq > *to {
                std::cmp::Ordering::Less
            } else {
                std::cmp::Ordering::Equal
            }
        })
        .is_ok()
}

/// Insert `(from..=to)` into the sorted disjoint hole list, merging
/// overlaps and neighbours.
fn add_hole(holes: &mut Vec<(u64, u64)>, from: u64, to: u64) {
    if from > to {
        return;
    }
    let (mut from, mut to) = (from, to);
    let start = holes.partition_point(|(_, t)| t.saturating_add(1) < from);
    let end = holes.partition_point(|(f, _)| *f <= to.saturating_add(1));
    for hole in &holes[start..end] {
        from = from.min(hole.0);
        to = to.max(hole.1);
    }
    holes.splice(start..end, [(from, to)]);
}

/// A stored frame arrived for a declared hole: narrow or drop it.
fn fill_hole(holes: &mut Vec<(u64, u64)>, seq: u64) {
    let Ok(at) = holes.binary_search_by(|(from, to)| {
        if seq < *from {
            std::cmp::Ordering::Greater
        } else if seq > *to {
            std::cmp::Ordering::Less
        } else {
            std::cmp::Ordering::Equal
        }
    }) else {
        return;
    };
    let (from, to) = holes[at];
    if from == to {
        holes.remove(at);
    } else if seq == from {
        holes[at].0 = from + 1;
    } else if seq == to {
        holes[at].1 = to - 1;
    } else {
        holes[at].1 = seq - 1;
        holes.insert(at + 1, (seq + 1, to));
    }
}

fn merge_holes(holes: &mut Vec<(u64, u64)>, gaps: &[(u64, u64)]) {
    for (from, to) in gaps {
        add_hole(holes, *from, *to);
    }
}

/// The marker's gap list: observed holes, the worker's declaration, and
/// the never-stored tail when `last_seq` passes what was written. A
/// pathological stream producing more than `MAX_MARKER_GAPS` ranges
/// coalesces the closest pair repeatedly; the widened range may span
/// delivered sequences, but the frames themselves stay readable.
fn merged_gaps(w: &Open, last_seq: u64, declared: &[(u64, u64)]) -> Vec<(u64, u64)> {
    let mut gaps = w.holes.clone();
    merge_holes(&mut gaps, declared);
    if last_seq > w.last_seq {
        add_hole(&mut gaps, w.last_seq + 1, last_seq);
    }
    while gaps.len() > MAX_MARKER_GAPS {
        let mut best = 0;
        for i in 1..gaps.len() - 1 {
            if gaps[i + 1].0 - gaps[i].1 < gaps[best + 1].0 - gaps[best].1 {
                best = i;
            }
        }
        gaps[best].1 = gaps[best + 1].1;
        gaps.remove(best + 1);
    }
    gaps
}

/// Incremental `Record` decode over a reader: the buffer refills until a
/// record completes or the stream ends mid-record — a torn tail.
struct Decoder {
    reader: Box<dyn Read>,
    buf: Vec<u8>,
    /// Bytes consumed so far: where the complete prefix ends.
    complete: u64,
    /// An uncompressed segment, whose tail a power cut can leave zeroed.
    plain: bool,
}

impl Decoder {
    fn next(&mut self) -> Result<Option<Record>> {
        loop {
            match Record::decode(&self.buf) {
                Ok((record, used)) => {
                    self.buf.drain(..used);
                    self.complete += used as u64;
                    return Ok(Some(record));
                }
                // A power cut can persist a file's new size before the data
                // written into it (a journal commit for another file carries
                // the size): the unsynced tail then reads back as zeros. It
                // was never acknowledged — an fsync would have written it —
                // so it ends the stream like a torn record. Anything else
                // that does not decode is corruption.
                Err(RecordError::Invalid) => {
                    return if self.plain && self.rest_is_zero()? {
                        Ok(None)
                    } else {
                        Err(Error::Corrupt("log record"))
                    };
                }
                Err(RecordError::Incomplete) => {
                    let mut chunk = [0u8; 64 << 10];
                    let read = self.reader.read(&mut chunk)?;
                    if read == 0 {
                        return Ok(None);
                    }
                    self.buf.extend_from_slice(&chunk[..read]);
                }
            }
        }
    }

    /// Whether everything from the current position to the end is zero.
    /// Only a stream that failed to decode pays for it.
    fn rest_is_zero(&mut self) -> Result<bool> {
        if self.buf.iter().any(|b| *b != 0) {
            return Ok(false);
        }
        let mut chunk = [0u8; 64 << 10];
        loop {
            let read = self.reader.read(&mut chunk)?;
            if read == 0 {
                return Ok(true);
            }
            if chunk[..read].iter().any(|b| *b != 0) {
                return Ok(false);
            }
        }
    }
}

fn seg_decoder(dir: &Path, seg: u32, compressed: bool) -> Result<Decoder> {
    let mut file = File::open(seg_path(dir, seg, compressed))?;
    if !compressed {
        return Ok(Decoder {
            reader: Box::new(file),
            buf: Vec::new(),
            complete: 0,
            plain: true,
        });
    }
    let mut header = [0u8; 7];
    file.read_exact(&mut header)?;
    if header[..4] != *COMPRESSED_MAGIC
        || u16::from_le_bytes(header[4..6].try_into().expect("2")) != COMPRESSED_FORMAT
        || header[6] != CODEC_ZLIB
    {
        return Err(Error::Corrupt("compressed log segment"));
    }
    Ok(Decoder {
        reader: Box::new(ZlibDecoder::new(file)),
        buf: Vec::new(),
        complete: 0,
        plain: false,
    })
}

/// Open a segment [`segs`] listed, or `None` when it is gone — the reader
/// stops there. A plain segment the compressor replaced between the
/// listing and the open is read from its `.z` twin: the rename lands
/// before the plain file goes. On Windows a plain file whose delete is
/// still pending (another handle — a concurrent reader, a scanner — held
/// it open when the compressor removed it) refuses the open with
/// `PermissionDenied` (or, from some paths, `ERROR_DELETE_PENDING`), not
/// `NotFound`; the twin is already there, so it is read the same way.
fn listed_seg_decoder(dir: &Path, seg: u32, compressed: bool) -> Result<Option<Decoder>> {
    use std::io::ErrorKind;
    /// `ERROR_DELETE_PENDING`, which `std` files as `Uncategorized`.
    const DELETE_PENDING: i32 = 303;
    let replaced = |e: &std::io::Error| {
        e.kind() == ErrorKind::NotFound
            || (cfg!(windows)
                && (e.kind() == ErrorKind::PermissionDenied
                    || e.raw_os_error() == Some(DELETE_PENDING)))
    };
    match seg_decoder(dir, seg, compressed) {
        Ok(decoder) => Ok(Some(decoder)),
        Err(Error::Io(e)) if !compressed && replaced(&e) => match seg_decoder(dir, seg, true) {
            Ok(decoder) => Ok(Some(decoder)),
            Err(Error::Io(z)) if z.kind() == ErrorKind::NotFound => {
                if e.kind() == ErrorKind::NotFound {
                    Ok(None)
                } else {
                    Err(Error::Io(e))
                }
            }
            Err(z) => Err(z),
        },
        Err(Error::Io(e)) if e.kind() == ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// Compress a sealed segment in place: `seg-N` → `seg-N.z` through a
/// temporary, fsync, rename, directory fsync, then the plain file goes.
fn compress(path: &Path) -> Result<()> {
    let tmp = path.with_extension("z.tmp");
    let done = path.with_extension("z");
    {
        let mut input = File::open(path)?;
        let mut out = File::create(&tmp)?;
        out.write_all(COMPRESSED_MAGIC)?;
        out.write_all(&COMPRESSED_FORMAT.to_le_bytes())?;
        out.write_all(&[CODEC_ZLIB])?;
        let mut encoder = ZlibEncoder::new(out, Compression::fast());
        let mut chunk = [0u8; 64 << 10];
        loop {
            let read = input.read(&mut chunk)?;
            if read == 0 {
                break;
            }
            encoder.write_all(&chunk[..read])?;
        }
        encoder.finish()?.sync_data()?;
    }
    fs::rename(&tmp, &done)?;
    if let Some(dir) = path.parent() {
        sync_dir(dir)?;
    }
    fs::remove_file(path)?;
    Ok(())
}

/// Read an attempt directory: frames with `seq > after` (filtered to
/// `step` when given), completeness, and the gap list. Unbounded but for
/// `limit`; the API reads through [`read_page`].
pub fn read_dir(dir: &Path, after: u64, limit: usize, step: Option<u32>) -> Result<Tail> {
    read_page(dir, after, Page::frames(limit), step)
}

/// [`read_dir`] under a [`Page`]: at most `limit` frames and `bytes` of
/// their payload (the first frame always fits, so every page progresses),
/// and at most `scan` bytes of payload decoded past `after` — a step filter
/// over a long log stops there too instead of decoding to the end. A page
/// cut by any bound carries [`Tail::next_after`].
pub fn read_page(dir: &Path, after: u64, page: Page, step: Option<u32>) -> Result<Tail> {
    let segs = segs(dir)?;
    let marker = end_marker(dir);
    if segs.is_empty() && marker.is_none() {
        return Err(Error::NotFound);
    }
    let index_bytes = fs::read(dir.join("index")).unwrap_or_default();
    let entries = read_index(&index_bytes).unwrap_or_default();
    // Seek ([`seek_start`]). Fills always carry a sequence below every
    // later checkpoint and land in a segment at or after the one holding
    // the frontier they fill under, so no earlier segment can hold a frame
    // past `after` — a step filter needs no earlier start either.
    let start = seek_start(&entries, after, false);
    let mut tail = Tail {
        frames: Vec::new(),
        complete: marker.is_some(),
        gaps: Vec::new(),
        next_after: None,
        step_done: step.is_some_and(|want| step_moved_on(&entries, want)),
    };
    // Decode-observed holes are only reliable when every earlier segment
    // was decoded: a fill arriving before a mid-stream start makes a jump
    // whose "missing" frames sit in the segments the seek skipped.
    let from_start = start == segs.keys().next().copied().unwrap_or(0);
    let mut prev_seq = 0u64;
    // The highest sequence past `after` this page consumed (returned or
    // passed over by the filter): where a cut page resumes.
    let mut consumed = after;
    let (mut taken, mut scanned) = (0u64, 0u64);
    'decode: for (n, compressed) in segs.range(start..) {
        let Some(mut decoder) = listed_seg_decoder(dir, *n, *compressed)? else {
            break;
        };
        while let Some(record) = decoder.next()? {
            match record {
                Record::Frame(frame) => {
                    if from_start {
                        if prev_seq > 0 && frame.seq > prev_seq + 1 {
                            add_hole(&mut tail.gaps, prev_seq + 1, frame.seq - 1);
                        } else if frame.seq <= prev_seq {
                            // An out-of-order fill narrows the hole it landed in.
                            fill_hole(&mut tail.gaps, frame.seq);
                        }
                    }
                    prev_seq = prev_seq.max(frame.seq);
                    if frame.seq <= after {
                        continue;
                    }
                    let len = frame.bytes.len() as u64;
                    let wanted = step.is_none_or(|s| frame.step == s);
                    // Every bound is checked between frames and needs some
                    // progress first, so a page is never empty for a bound.
                    let full = wanted
                        && (tail.frames.len() >= page.limit
                            || (!tail.frames.is_empty() && taken.saturating_add(len) > page.bytes));
                    if full || (consumed > after && scanned.saturating_add(len) > page.scan) {
                        tail.next_after = Some(consumed);
                        break 'decode;
                    }
                    scanned += len;
                    consumed = consumed.max(frame.seq);
                    if wanted {
                        taken += len;
                        tail.frames.push(frame);
                    }
                }
                Record::End { last_seq, gaps } => {
                    tail.complete = true;
                    merge_holes(&mut tail.gaps, &gaps);
                    if last_seq > prev_seq {
                        add_hole(&mut tail.gaps, prev_seq + 1, last_seq);
                    }
                    break 'decode;
                }
            }
        }
    }
    match marker {
        Some((_, gaps)) => merge_holes(&mut tail.gaps, &gaps),
        // A live log: the holes its writer has persisted so far, including
        // those inside segments this page did not decode.
        None => merge_holes(&mut tail.gaps, &read_holes(dir)),
    }
    Ok(tail)
}

/// Whether the log has moved past step `want`: some checkpoint names a
/// later step after the last checkpoint of `want` (none at all when the step
/// never ran). Steps run in order and every step change is checkpointed, so
/// a finished step gets no new frames — only a resent fill could still land.
fn step_moved_on(entries: &[Entry], want: u32) -> bool {
    let last_want = entries
        .iter()
        .filter(|e| e.step == want)
        .map(|e| e.seq)
        .max()
        .unwrap_or(0);
    entries.iter().any(|e| e.step > want && e.seq > last_want)
}

/// The W05 flat-file reader, kept for logs written before D04 and for
/// spool-shaped fixtures. Bounded however long the file: frames collect to
/// `limit` while the scan keeps streaming to the end marker.
pub fn read_tail(path: &Path, after: u64, limit: usize, step: Option<u32>) -> Result<Tail> {
    read_tail_page(path, after, Page::frames(limit), step)
}

/// [`read_tail`] under a page's frame and byte bounds (a flat file is read
/// from its start either way, so `scan` does not apply).
pub fn read_tail_page(path: &Path, after: u64, page: Page, step: Option<u32>) -> Result<Tail> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(Error::NotFound),
        Err(e) => return Err(e.into()),
    };
    let mut tail = Tail {
        frames: Vec::new(),
        complete: false,
        gaps: Vec::new(),
        next_after: None,
        step_done: false,
    };
    let mut decoder = Decoder {
        reader: Box::new(file),
        buf: Vec::new(),
        complete: 0,
        plain: true,
    };
    let mut taken = 0u64;
    while let Some(record) = decoder.next()? {
        match record {
            Record::Frame(f) => {
                if f.seq <= after || !step.is_none_or(|s| f.step == s) {
                    continue;
                }
                if tail.next_after.is_some() {
                    continue;
                }
                let len = f.bytes.len() as u64;
                if tail.frames.len() >= page.limit
                    || (!tail.frames.is_empty() && taken.saturating_add(len) > page.bytes)
                {
                    tail.next_after = Some(tail.frames.last().map_or(after, |l| l.seq));
                    continue;
                }
                taken += len;
                tail.frames.push(f);
            }
            Record::End { gaps, .. } => {
                tail.complete = true;
                tail.gaps = gaps;
                break;
            }
        }
    }
    Ok(tail)
}

#[cfg(all(test, windows))]
mod windows_tests {
    use std::{
        os::windows::{fs::OpenOptionsExt, io::AsRawHandle},
        time::{Duration, Instant},
    };

    use sentinel_protocol::logs::Stream;
    use windows_sys::Win32::Storage::FileSystem::{
        DELETE, FILE_DISPOSITION_INFO, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        FileDispositionInfo, SetFileInformationByHandle,
    };

    use super::*;

    /// Create `path` and leave it delete-pending: marked for deletion by a
    /// handle that stays open, so the name is still listed and every open
    /// is refused until the returned handle closes. `std`'s `remove_file`
    /// and `DeleteFileW` cannot build this state: both use POSIX delete
    /// semantics, which unlink the name at once. The classic disposition
    /// (`FileDispositionInfo`) is what a removal falls back to when POSIX
    /// semantics are unavailable, and what leaves the name behind.
    fn delete_pending(path: &Path) -> File {
        const GENERIC_WRITE: u32 = 0x4000_0000;
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .access_mode(GENERIC_WRITE | DELETE)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .open(path)
            .unwrap();
        let info = FILE_DISPOSITION_INFO { DeleteFile: true };
        // SAFETY: `file` is an open handle with `DELETE` access that outlives
        // the call; `info` is a live `FILE_DISPOSITION_INFO` and the size
        // passed is its own, as the `FileDispositionInfo` class requires.
        let marked = unsafe {
            SetFileInformationByHandle(
                file.as_raw_handle(),
                FileDispositionInfo,
                (&raw const info).cast(),
                size_of::<FILE_DISPOSITION_INFO>() as u32,
            )
        };
        assert_ne!(marked, 0, "{}", std::io::Error::last_os_error());
        file
    }

    /// The compressor renames `seg-N.z` into place and then removes the
    /// plain `seg-N`. A reader that listed the directory before the rename
    /// opens the plain file; when another handle held it at the removal,
    /// Windows keeps it listed but delete-pending and refuses the open with
    /// access denied. The reader must read the twin, not fail the read —
    /// and with no twin, the refusal is an error, never an early end.
    #[test]
    fn a_plain_segment_pending_delete_is_read_from_its_compressed_twin() {
        let temp = tempfile::tempdir().unwrap();
        let logs = LogStore::open(temp.path().join("logs")).unwrap();
        let (run, job, attempt) = (RunId::new(), JobId::new(), AttemptId::new());
        for seq in 1..=3u64 {
            let frame = Frame {
                seq,
                step: 0,
                stream: Stream::Stdout,
                bytes: format!("line {seq}\n").into_bytes(),
            };
            logs.append(run, job, attempt, &frame).unwrap();
        }
        logs.finish(run, job, attempt, 3, &[]).unwrap();
        let dir = logs.attempt_dir(run, job, attempt);
        let (plain, twin) = (seg_path(&dir, 0, false), seg_path(&dir, 0, true));
        let deadline = Instant::now() + Duration::from_secs(30);
        while !twin.exists() || plain.exists() {
            assert!(Instant::now() < deadline, "seg-000000 never compressed");
            std::thread::sleep(Duration::from_millis(25));
        }

        let pending = delete_pending(&plain);
        assert!(
            fs::read_dir(&dir)
                .unwrap()
                .flatten()
                .any(|e| e.path() == plain),
            "a delete-pending file stays listed"
        );
        let refused = File::open(&plain).unwrap_err();
        assert_eq!(refused.kind(), std::io::ErrorKind::PermissionDenied);

        // What a reader that listed only the plain segment does next.
        let mut decoder = listed_seg_decoder(&dir, 0, false)
            .unwrap()
            .expect("the twin is read");
        let mut read = Vec::new();
        while let Some(record) = decoder.next().unwrap() {
            if let Record::Frame(frame) = record {
                read.push((frame.seq, String::from_utf8(frame.bytes).unwrap()));
            }
        }
        assert_eq!(
            read,
            (1..=3u64)
                .map(|seq| (seq, format!("line {seq}\n")))
                .collect::<Vec<_>>()
        );

        fs::remove_file(&twin).unwrap();
        match listed_seg_decoder(&dir, 0, false) {
            Err(Error::Io(e)) => assert_eq!(e.kind(), std::io::ErrorKind::PermissionDenied),
            Ok(found) => panic!(
                "a refused segment without a twin read as {:?}",
                found.is_some()
            ),
            Err(e) => panic!("unexpected {e:?}"),
        }
        drop(pending);
        assert!(!plain.exists());
    }
}
