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
        Arc, Condvar, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
};

use flate2::{Compression, read::ZlibDecoder, write::ZlibEncoder};
use sentinel_core::{AttemptId, JobId, RunId, UnixMillis};
use sentinel_protocol::logs::{FRAME_HEADER_BYTES, Frame, Record, RecordError};

use crate::{Error, Result, objects::sync_dir};

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
        };
        store.sweep();
        Ok(store)
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
        fs::create_dir_all(&dir)?;
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
        }
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
            w.index.write_all(&pending)?;
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
        if frame.seq > w.last_seq + 1 {
            add_hole(&mut w.holes, w.last_seq + 1, frame.seq - 1);
        }
        w.scratch.clear();
        Record::Frame(frame.clone())
            .encode(&mut w.scratch)
            .map_err(|_| Error::InvalidInput("log frame"))?;
        let record_len = w.scratch.len() as u64;
        if w.len + record_len > MAX_LOG_BYTES {
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
        w.index.write_all(&entry)?;
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

    /// Pre-D04 flat logs (`<logs>/<attempt>.log`), kept readable. The
    /// whole file is already loaded by the legacy reader, so the step
    /// filter applies after.
    pub fn tail_legacy(
        &self,
        attempt: AttemptId,
        after: u64,
        limit: usize,
        step: Option<u32>,
    ) -> Result<Tail> {
        let mut tail = read_tail(&self.dir.join(format!("{attempt}.log")), after, usize::MAX)?;
        if let Some(step) = step {
            tail.frames.retain(|f| f.step == step);
        }
        tail.frames.truncate(limit);
        Ok(tail)
    }
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

/// A checkpoint for the frame just stored (`line`/`bytes` include it).
/// Provisional: no fsync here — the seal fsyncs; a crash loses these and
/// the reopen regenerates them from the segment itself.
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
    let _ = w.index.write_all(&entry.bytes());
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
    // Seek: the last checkpoint at or before `after` names the segment to
    // start at (a seal entry's coverage ends with its segment, so the
    // next frames sit in the one after). Fills always carry a sequence
    // below every later checkpoint, so no earlier segment can hold a
    // frame past `after`.
    let mut start = 0u32;
    for entry in &entries {
        if entry.seq <= after {
            start = if entry.kind == KIND_SEAL {
                entry.seg.saturating_add(1)
            } else {
                entry.seg
            };
        }
    }
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
/// spool-shaped fixtures.
pub fn read_tail(path: &Path, after: u64, limit: usize) -> Result<Tail> {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(Error::NotFound),
        Err(e) => return Err(e.into()),
    };
    let mut tail = Tail {
        frames: Vec::new(),
        complete: false,
        gaps: Vec::new(),
    };
    let mut at = 0;
    while at < bytes.len() {
        match Record::decode(&bytes[at..]) {
            Ok((Record::Frame(f), used)) => {
                at += used;
                if f.seq > after && tail.frames.len() < limit {
                    tail.frames.push(f);
                }
            }
            Ok((Record::End { gaps, .. }, _)) => {
                tail.complete = true;
                tail.gaps = gaps;
                break;
            }
            Err(RecordError::Incomplete) => break,
            Err(RecordError::Invalid) => return Err(Error::Corrupt("log record")),
        }
    }
    Ok(tail)
}
