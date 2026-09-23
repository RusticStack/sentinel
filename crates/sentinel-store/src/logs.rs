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
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
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
    /// disjoint; fills shrink it.
    holes: Vec<(u64, u64)>,
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

/// Append and read attempt logs. Cheap to share: one mutex over the open
/// writers, one directory per attempt, one compressor thread.
pub struct LogStore {
    dir: PathBuf,
    open: Mutex<HashMap<AttemptId, Open>>,
    compressor: Arc<Compressor>,
    worker: Mutex<Option<JoinHandle<()>>>,
    /// Disk admission (D06); unset admits every append as before.
    admission: OnceLock<Arc<Admission>>,
    /// Stored bytes one attempt's log may occupy — `MAX_LOG_BYTES`
    /// normally, lower under `open_with_limit`.
    max_bytes: u64,
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
        fs::create_dir_all(&dir)?;
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
            compressor,
            worker: Mutex::new(Some(worker)),
            admission: OnceLock::new(),
            max_bytes,
        };
        store.sweep();
        Ok(store)
    }

    /// Install the disk admission gate; appends refuse once free space
    /// falls below the log floor. Set once at startup.
    pub fn set_admission(&self, admission: Arc<Admission>) {
        let _ = self.admission.set(admission);
    }

    /// Remove attempt directories and legacy flat logs whose newest byte is
    /// older than `now - retention_ms`. Open writers are never touched; the
    /// deletion is of durable evidence only. Returns directories/files
    /// removed, at most `limit`.
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
        let newest_ms = |dir: &Path| -> i64 {
            fs::read_dir(dir).map_or(0, |entries| {
                entries
                    .flatten()
                    .filter_map(|e| {
                        e.metadata()
                            .ok()
                            .and_then(|m| m.modified().ok())
                            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                            .map(|d| d.as_millis() as i64)
                    })
                    .max()
                    .unwrap_or(0)
            })
        };
        let mut swept = 0u32;
        let Ok(runs) = fs::read_dir(&self.dir) else {
            return Ok(0);
        };
        'runs: for run in runs.flatten() {
            let run_path = run.path();
            if run_path.is_file() {
                // Legacy flat log: `logs/<attempt>.log` from before D04.
                if run_path.extension().is_some_and(|e| e == "log")
                    && fs::metadata(&run_path)
                        .and_then(|m| m.modified())
                        .ok()
                        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                        .is_some_and(|age| (age.as_millis() as i64) < cutoff)
                    && fs::remove_file(&run_path).is_ok()
                {
                    swept += 1;
                    if swept >= limit {
                        break;
                    }
                }
                continue;
            }
            let Ok(jobs) = fs::read_dir(&run_path) else {
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
                    if let Ok(id) = attempt.file_name().to_string_lossy().parse::<AttemptId>()
                        && held.contains(&id)
                    {
                        continue;
                    }
                    if newest_ms(&dir) < cutoff && fs::remove_dir_all(&dir).is_ok() {
                        swept += 1;
                        // Prune the emptied job/run parents.
                        let _ = fs::remove_dir(job.path());
                        if swept >= limit {
                            break 'runs;
                        }
                    }
                }
                let _ = fs::remove_dir(job.path());
            }
            let _ = fs::remove_dir(&run_path);
        }
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
        {
            let open = self.open.lock().unwrap_or_else(|p| p.into_inner());
            if let Some(w) = open.get(&attempt) {
                return w.ended.is_some();
            }
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

    /// Open (or reopen after a restart) the attempt's writer, folding the
    /// segments the index does not cover back into memory.
    fn writer<'a>(
        &self,
        open: &'a mut HashMap<AttemptId, Open>,
        run: RunId,
        job: JobId,
        attempt: AttemptId,
    ) -> Result<&'a mut Open> {
        match open.entry(attempt) {
            std::collections::hash_map::Entry::Occupied(e) => Ok(e.into_mut()),
            std::collections::hash_map::Entry::Vacant(v) => {
                Ok(v.insert(self.open_attempt(run, job, attempt)?))
            }
        }
    }

    fn open_attempt(&self, run: RunId, job: JobId, attempt: AttemptId) -> Result<Open> {
        let dir = self.attempt_dir(run, job, attempt);
        if !dir.is_dir() {
            // A new attempt directory (and possibly its job and run
            // parents): make each new entry durable before any frame in it
            // is acknowledged.
            fs::create_dir_all(&dir)?;
            let mut at = dir.as_path();
            while let Some(parent) = at.parent() {
                sync_dir(parent)?;
                if parent == self.dir {
                    break;
                }
                at = parent;
            }
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
    /// a frame landing in a hole is stored as a fill.
    pub fn append(
        &self,
        run: RunId,
        job: JobId,
        attempt: AttemptId,
        frame: &Frame,
    ) -> Result<Appended> {
        let mut open = self.open.lock().unwrap_or_else(|p| p.into_inner());
        let w = self.writer(&mut open, run, job, attempt)?;
        if w.ended.is_some() {
            return Err(Error::Conflict);
        }
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
        if frame.seq > w.last_seq + 1 {
            add_hole(&mut w.holes, w.last_seq + 1, frame.seq - 1);
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
        w.file
            .as_mut()
            .expect("opened above")
            .write_all(&w.scratch)?;
        w.file.as_mut().expect("opened above").sync_data()?;
        let step_changed = frame.step != w.step;
        w.seg_len += record_len;
        w.len += record_len;
        w.lines += frame.bytes.iter().filter(|b| **b == b'\n').count() as u64;
        if frame.seq <= w.last_seq {
            // A fill: stored but never indexed — index entries must stay
            // in sequence order for the tail seek.
            fill_hole(&mut w.holes, frame.seq);
        } else {
            w.last_seq = frame.seq;
            w.step = frame.step;
            w.since_index += 1;
            if !w.seg_checkpointed || step_changed || w.since_index >= INDEX_EVERY {
                checkpoint(w);
                w.since_index = 0;
                w.seg_checkpointed = true;
            }
        }
        Ok(Appended::Stored {
            through: w.last_seq,
        })
    }

    /// Close the active segment: seal record into the index, fsync, and
    /// queue the segment for compression.
    fn seal(&self, w: &mut Open) -> Result<()> {
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
        let mut open = self.open.lock().unwrap_or_else(|p| p.into_inner());
        let w = self.writer(&mut open, run, job, attempt)?;
        if let Some(ended) = w.ended {
            return if ended == last_seq {
                Ok(())
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
        open.remove(&attempt);
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
        let mut decoder = match seg_decoder(dir, *n, *compressed) {
            Ok(decoder) => decoder,
            // The compressor renamed it between listing and open.
            Err(Error::Io(e)) if e.kind() == std::io::ErrorKind::NotFound && !compressed => {
                match seg_decoder(dir, *n, true) {
                    Ok(decoder) => decoder,
                    Err(Error::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => break,
                    Err(e) => return Err(e),
                }
            }
            Err(Error::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => break,
            Err(e) => return Err(e),
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
}

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
                Err(RecordError::Invalid) => return Err(Error::Corrupt("log record")),
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
}

fn seg_decoder(dir: &Path, seg: u32, compressed: bool) -> Result<Decoder> {
    let mut file = File::open(seg_path(dir, seg, compressed))?;
    if !compressed {
        return Ok(Decoder {
            reader: Box::new(file),
            buf: Vec::new(),
            complete: 0,
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
    })
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
/// `step` when given), completeness, and the gap list.
pub fn read_dir(dir: &Path, after: u64, limit: usize, step: Option<u32>) -> Result<Tail> {
    let segs = segs(dir)?;
    let marker = end_marker(dir);
    if segs.is_empty() && marker.is_none() {
        return Err(Error::NotFound);
    }
    let index_bytes = fs::read(dir.join("index")).unwrap_or_default();
    let entries = read_index(&index_bytes).unwrap_or_default();
    // Seek ([`seek_start`]). Fills always carry a sequence below every
    // later checkpoint, so no earlier segment can hold a frame past `after`.
    let mut start = seek_start(&entries, after, false);
    if let Some(want) = step {
        // A step's first frame is always checkpointed: the wanted frames
        // continue the step run spanning `after`, or start at the next
        // checkpoint of that step. Take the earlier candidate so neither
        // is missed.
        for entry in entries.iter().rev() {
            if entry.step == want && entry.seq <= after {
                start = start.min(entry.seg);
                break;
            }
        }
        for entry in &entries {
            if entry.step == want && entry.seq > after {
                start = start.min(entry.seg);
                break;
            }
        }
    }
    let mut tail = Tail {
        frames: Vec::new(),
        complete: marker.is_some(),
        gaps: Vec::new(),
    };
    // Decode-observed holes are only reliable when every earlier segment
    // was decoded: a fill arriving before a mid-stream start makes a jump
    // whose "missing" frames sit in the segments the seek skipped.
    let from_start = start == segs.keys().next().copied().unwrap_or(0);
    let mut prev_seq = 0u64;
    'decode: for (n, compressed) in segs.range(start..) {
        let mut decoder = match seg_decoder(dir, *n, *compressed) {
            Ok(decoder) => decoder,
            // The compressor renamed it between listing and open.
            Err(Error::Io(e)) if e.kind() == std::io::ErrorKind::NotFound && !compressed => {
                match seg_decoder(dir, *n, true) {
                    Ok(decoder) => decoder,
                    Err(Error::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => break,
                    Err(e) => return Err(e),
                }
            }
            Err(Error::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => break,
            Err(e) => return Err(e),
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
                    if frame.seq > after
                        && step.is_none_or(|s| frame.step == s)
                        && tail.frames.len() < limit
                    {
                        tail.frames.push(frame);
                    }
                    if tail.frames.len() >= limit {
                        break 'decode;
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
    if let Some((_, gaps)) = marker {
        merge_holes(&mut tail.gaps, &gaps);
    }
    Ok(tail)
}

/// The W05 flat-file reader, kept for logs written before D04 and for
/// spool-shaped fixtures. Bounded however long the file: frames collect to
/// `limit` while the scan keeps streaming to the end marker.
pub fn read_tail(path: &Path, after: u64, limit: usize, step: Option<u32>) -> Result<Tail> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(Error::NotFound),
        Err(e) => return Err(e.into()),
    };
    let mut tail = Tail {
        frames: Vec::new(),
        complete: false,
        gaps: Vec::new(),
    };
    let mut decoder = Decoder {
        reader: Box::new(file),
        buf: Vec::new(),
        complete: 0,
    };
    while let Some(record) = decoder.next()? {
        match record {
            Record::Frame(f) => {
                if f.seq > after && step.is_none_or(|s| f.step == s) && tail.frames.len() < limit {
                    tail.frames.push(f);
                }
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
