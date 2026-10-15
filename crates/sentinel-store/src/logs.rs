//! A frame is acknowledged only after it is written and fdatasynced; the worker may then drop it from its spool.

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
pub const MAX_LOG_BYTES: u64 = 256 << 20;
const SEGMENT_BYTES: u64 = 4 << 20;
const INDEX_EVERY: u32 = 64;
const MAX_MARKER_GAPS: usize = 1024;

const INDEX_MAGIC: &[u8; 4] = b"SNLI";
const INDEX_FORMAT: u16 = 1;
const INDEX_ENTRY_BYTES: usize = 41;
const KIND_CHECKPOINT: u8 = 1;
const KIND_SEAL: u8 = 2;

const COMPRESSED_MAGIC: &[u8; 4] = b"SNLZ";
const COMPRESSED_FORMAT: u16 = 1;
const CODEC_ZLIB: u8 = 1;

const END_MAGIC: &[u8; 4] = b"SNLE";
const END_FORMAT: u16 = 1;

const HOLES_MAGIC: &[u8; 4] = b"SNLH";
const HOLES_FORMAT: u16 = 1;
pub const MAX_HOLES: usize = 4096;

pub const MAX_OPEN_WRITERS: usize = 1024;
pub const WRITER_IDLE: Duration = Duration::from_secs(600);
const SWEEP_BUDGET: u32 = 4096;

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

struct Open {
    dir: PathBuf,
    seg: u32,
    file: Option<File>,
    seg_len: u64,
    index: File,
    index_len: u64,
    last_seq: u64,
    holes: Vec<(u64, u64)>,
    holes_dirty: bool,
    len: u64,
    lines: u64,
    step: u32,
    since_index: u32,
    seg_checkpointed: bool,
    ended: Option<u64>,
    scratch: Vec<u8>,
    dirty: bool,
}

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
            let _ = compress(&path);
        }
    }
}

struct Slot {
    open: Mutex<Option<Open>>,
    touched: AtomicU64,
}

pub struct LogStore {
    dir: PathBuf,
    open: Mutex<HashMap<AttemptId, Arc<Slot>>>,
    epoch: Instant,
    max_open: usize,
    changes: Arc<LogChanges>,
    compressor: Arc<Compressor>,
    worker: Mutex<Option<JoinHandle<()>>>,
    admission: OnceLock<Arc<Admission>>,
    max_bytes: u64,
    sweep_cursor: Mutex<Option<String>>,
}

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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Appended {
    Stored { through: u64 },
    Duplicate { through: u64 },
}

impl LogStore {
    pub fn open(dir: impl Into<PathBuf>) -> Result<LogStore> {
        Self::open_with_limit(dir, MAX_LOG_BYTES)
    }

    pub fn open_with_limit(dir: impl Into<PathBuf>, max_bytes: u64) -> Result<LogStore> {
        let dir = dir.into();
        if !dir.is_dir() {
            fs::create_dir_all(&dir)?;
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

    #[must_use]
    pub fn with_max_open(mut self, max: usize) -> LogStore {
        self.max_open = max.max(1);
        self
    }

    pub fn set_admission(&self, admission: Arc<Admission>) {
        let _ = self.admission.set(admission);
    }

    pub fn changes(&self) -> &LogChanges {
        &self.changes
    }

    fn now_ms(&self) -> u64 {
        self.epoch.elapsed().as_millis() as u64
    }

    pub fn open_writers(&self) -> usize {
        self.open.lock().unwrap_or_else(|p| p.into_inner()).len()
    }

    pub fn close_idle(&self, idle: Duration) -> usize {
        let cutoff = self.now_ms().saturating_sub(idle.as_millis() as u64);
        let mut map = self.open.lock().unwrap_or_else(|p| p.into_inner());
        let before = map.len();
        // Only the map holds an idle slot's Arc, so nobody can be inside it or clone it without the map lock.
        map.retain(|_, slot| {
            Arc::strong_count(slot) > 1 || slot.touched.load(Ordering::Relaxed) > cutoff
        });
        before - map.len()
    }

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
            *guard = None;
        }
        result
    }

    pub fn sweep_dirs(&self, limit: u32, mut gone: impl FnMut(AttemptId) -> bool) -> Result<u32> {
        if limit == 0 {
            return Ok(0);
        }
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
                seen += 1;
                if let Some(id) = name
                    .strip_suffix(".log")
                    .and_then(|stem| stem.parse::<AttemptId>().ok())
                    && !held.contains(&id)
                    && gone(id)
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
                        let Ok(id) = attempt.file_name().to_string_lossy().parse::<AttemptId>()
                        else {
                            continue;
                        };
                        if !held.contains(&id) && gone(id) && fs::remove_dir_all(&dir).is_ok() {
                            swept += 1;
                        }
                    }
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

    pub fn stored_bytes(&self, run: RunId, job: JobId, attempt: AttemptId) -> u64 {
        let dir = self.attempt_dir(run, job, attempt);
        match fs::read_dir(&dir) {
            Ok(read) => read
                .flatten()
                .filter_map(|e| e.metadata().ok())
                .filter(|m| m.is_file())
                .map(|m| m.len())
                .sum(),
            Err(_) => fs::metadata(self.dir.join(format!("{attempt}.log"))).map_or(0, |m| m.len()),
        }
    }

    pub fn remove(&self, run: RunId, job: JobId, attempt: AttemptId) -> Result<()> {
        self.forget(attempt);
        let dir = self.attempt_dir(run, job, attempt);
        match fs::remove_dir_all(&dir) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        if let Some(parent) = dir.parent() {
            let _ = fs::remove_dir(parent);
            if let Some(run_dir) = parent.parent() {
                let _ = fs::remove_dir(run_dir);
            }
        }
        match fs::remove_file(self.dir.join(format!("{attempt}.log"))) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    pub fn attempt_dir(&self, run: RunId, job: JobId, attempt: AttemptId) -> PathBuf {
        self.dir
            .join(run.to_string())
            .join(job.to_string())
            .join(attempt.to_string())
    }

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

    pub fn forget(&self, attempt: AttemptId) -> bool {
        self.open
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&attempt)
            .is_some()
    }

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

    fn open_attempt(&self, run: RunId, job: JobId, attempt: AttemptId) -> Result<Open> {
        let dir = self.attempt_dir(run, job, attempt);
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
            dirty: false,
        };
        if w.ended.is_some() {
            for (n, compressed) in &segs {
                if !compressed {
                    self.compressor.enqueue(seg_path(&w.dir, *n, false));
                }
            }
            return Ok(w);
        }
        let persisted = read_holes(&w.dir);
        w.holes.clone_from(&persisted);
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
                seal_entry(&w, n, &mut pending);
                OpenOptions::new()
                    .write(true)
                    .open(&path)?
                    .set_len(complete_len)?;
                queue.push(path);
            } else {
                let mut file = OpenOptions::new()
                    .write(true)
                    .read(true)
                    .truncate(false)
                    .open(&path)?;
                file.set_len(complete_len)?;
                // Unsynced frames from a dropped writer are acked as duplicates on resend; sync survivors before serving.
                file.sync_data()?;
                file.seek(SeekFrom::End(0))?;
                w.seg = n;
                w.seg_len = complete_len;
                w.seg_checkpointed = advanced;
                w.file = Some(file);
            }
        }
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
        w.holes.retain(|(from, _)| *from <= w.last_seq);
        w.holes_dirty = w.holes != persisted;
        if let Some(last) = w.ended {
            write_end_marker(&w.dir, last, &merged_gaps(&w, last, &[]))?;
            w.file = None;
        } else if w.file.is_none() {
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

    pub fn append(
        &self,
        run: RunId,
        job: JobId,
        attempt: AttemptId,
        frame: &Frame,
    ) -> Result<Appended> {
        let appended = self.with_writer(run, job, attempt, |w| self.append_to(w, frame, true))?;
        if matches!(appended, Appended::Stored { .. }) {
            self.changes.bump();
        }
        Ok(appended)
    }

    pub fn append_deferred(
        &self,
        run: RunId,
        job: JobId,
        attempt: AttemptId,
        frame: &Frame,
    ) -> Result<Appended> {
        let appended = self.with_writer(run, job, attempt, |w| self.append_to(w, frame, false))?;
        if matches!(appended, Appended::Stored { .. }) {
            self.changes.bump();
        }
        Ok(appended)
    }

    pub fn sync(&self, attempt: AttemptId) -> Result<()> {
        let slot = self
            .open
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&attempt)
            .map(Arc::clone)
            .ok_or(Error::Conflict)?;
        let mut guard = slot.open.lock().unwrap_or_else(|p| p.into_inner());
        let Some(w) = guard.as_mut() else {
            return Err(Error::Conflict);
        };
        let result = sync_dirty(w);
        if result.is_err() {
            *guard = None;
        }
        result
    }

    fn append_to(&self, w: &mut Open, frame: &Frame, durable: bool) -> Result<Appended> {
        if w.ended.is_some() {
            return Err(Error::Conflict);
        }
        persist_holes(w)?;
        if frame.seq <= w.last_seq && !in_hole(&w.holes, frame.seq) {
            sync_dirty(w)?;
            return Ok(Appended::Duplicate {
                through: w.last_seq,
            });
        }
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
            // A segment's directory entry must be durable before a frame in it is acknowledged.
            sync_dir(&w.dir)?;
        }
        let file = w.file.as_mut().expect("opened above");
        let written = file.write_all(&w.scratch).and_then(|()| {
            if durable {
                // Covers every deferred frame written before this one too.
                file.sync_data()
            } else {
                Ok(())
            }
        });
        if let Err(e) = written {
            // Never acknowledged: truncate back so a later frame never lands behind a torn record.
            let _ = file.set_len(w.seg_len);
            return Err(e.into());
        }
        w.dirty = !durable;
        let step_changed = frame.step != w.step;
        w.seg_len += record_len;
        w.len += record_len;
        w.lines += frame.bytes.iter().filter(|b| **b == b'\n').count() as u64;
        if frame.seq <= w.last_seq {
            fill_hole(&mut w.holes, frame.seq);
            w.holes_dirty = true;
        } else {
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

    fn seal(&self, w: &mut Open) -> Result<()> {
        persist_holes(w)?;
        let mut entry = Vec::with_capacity(INDEX_ENTRY_BYTES);
        seal_entry(w, w.seg, &mut entry);
        index_write(w, &entry)?;
        w.index.sync_data()?;
        if let Some(file) = w.file.take() {
            file.sync_data()?;
        }
        w.dirty = false;
        self.compressor.enqueue(seg_path(&w.dir, w.seg, false));
        w.seg += 1;
        w.seg_len = 0;
        w.since_index = 0;
        w.seg_checkpointed = false;
        Ok(())
    }

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
        self.open
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&attempt);
        if fresh {
            self.changes.bump();
        }
        Ok(())
    }

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

    pub fn newest_page(
        &self,
        run: RunId,
        job: JobId,
        attempt: AttemptId,
        page: Page,
        step: Option<u32>,
    ) -> Result<Tail> {
        read_newest(&self.attempt_dir(run, job, attempt), page, step)
    }

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
        let entry = Entry::decode(&encoded).ok_or(Error::Corrupt("log index"))?;
        let mut last = entry.seq;
        let start = seek_start(std::slice::from_ref(&entry), entry.seq, false);
        'decode: for (n, compressed) in segs(&dir)?.range(start..) {
            let Some(mut decoder) = listed_seg_decoder(&dir, *n, *compressed)? else {
                break;
            };
            while let Some(record) = decoder.next()? {
                match record {
                    Record::Frame(frame) => last = last.max(frame.seq),
                    Record::End { last_seq, .. } => {
                        last = last.max(last_seq);
                        break 'decode;
                    }
                }
            }
        }
        Ok(Some(last))
    }

    pub fn tail_legacy(
        &self,
        attempt: AttemptId,
        after: u64,
        limit: usize,
        step: Option<u32>,
    ) -> Result<Tail> {
        read_tail(&self.dir.join(format!("{attempt}.log")), after, limit, step)
    }

    pub fn tail_legacy_page(
        &self,
        attempt: AttemptId,
        after: u64,
        page: Page,
        step: Option<u32>,
    ) -> Result<Tail> {
        read_tail_page(&self.dir.join(format!("{attempt}.log")), after, page, step)
    }

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

pub const SEARCH_SCAN_BYTES: u64 = 4 << 20;
pub const MATCH_TEXT_BYTES: usize = 512;
pub const MAX_NEEDLE: usize = 256;
const LEAD: usize = MATCH_TEXT_BYTES / 4;
const LOOK_BEHIND: usize = MAX_NEEDLE - 1;

const CARRY_FORMAT: u8 = 1;
const CARRY_OPEN: u8 = 1;
const CARRY_REPORTED: u8 = 2;
const CARRY_STREAM_BYTES: usize = 1 + 4 + 1;
const CARRY_MAX_BYTES: usize = 1 + 8 + 2 + 2 * (CARRY_STREAM_BYTES + LOOK_BEHIND);
pub const MAX_CARRY_TEXT: usize = 2 * CARRY_MAX_BYTES;

#[derive(Clone, Copy, Debug)]
pub struct SearchQuery<'a> {
    pub needle: &'a [u8],
    pub after: u64,
    pub limit: usize,
    pub budget: u64,
    pub carry: Option<&'a str>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Match {
    pub seq: u64,
    pub step: u32,
    pub stream: sentinel_protocol::logs::Stream,
    pub text: Vec<u8>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Search {
    pub matches: Vec<Match>,
    pub next_after: Option<u64>,
    pub carry: Option<String>,
    pub complete: bool,
}

#[derive(Clone, Copy)]
struct Carry {
    open: bool,
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

    const fn continues(&self, frame: &Frame) -> bool {
        self.open && self.step == frame.step
    }

    fn restart(&mut self, bytes: &[u8], reported: bool, keep: usize) {
        self.open = !bytes.is_empty();
        self.reported = reported;
        self.len = 0;
        self.extend(bytes, keep);
    }

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

struct Scanner<'n> {
    finder: memchr::memmem::Finder<'n>,
    needle: usize,
    keep: usize,
    after: u64,
    limit: usize,
    budget: u64,
    scanned: u64,
    seeded: bool,
    started: bool,
    out: Search,
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
            from = line_end + 1;
        }
        self.remember(frame, tail_reported);
        self.scanned += len;
        self.after = frame.seq;
        true
    }

    fn finish(&mut self, complete: bool) -> Search {
        let mut out = std::mem::take(&mut self.out);
        out.complete = complete && out.next_after.is_none();
        out
    }

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

fn trim_cr(bytes: &[u8], start: usize, end: usize) -> usize {
    if end > start && bytes[end - 1] == b'\r' {
        end - 1
    } else {
        end
    }
}

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
    pub next_after: Option<u64>,
    pub step_done: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Page {
    pub limit: usize,
    pub bytes: u64,
    pub scan: u64,
}

impl Page {
    #[must_use]
    pub const fn frames(limit: usize) -> Page {
        Page {
            limit,
            bytes: u64::MAX,
            scan: u64::MAX,
        }
    }
}

pub const PAGE_BYTES: u64 = 1 << 20;
pub const PAGE_SCAN_BYTES: u64 = 16 << 20;

fn seg_path(dir: &Path, seg: u32, compressed: bool) -> PathBuf {
    if compressed {
        dir.join(format!("seg-{seg:06}.z"))
    } else {
        dir.join(format!("seg-{seg:06}"))
    }
}

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

fn sync_dirty(w: &mut Open) -> Result<()> {
    if w.dirty {
        if let Some(file) = w.file.as_ref() {
            file.sync_data()?;
        }
        w.dirty = false;
    }
    Ok(())
}

fn persist_holes(w: &mut Open) -> Result<()> {
    if !w.holes_dirty {
        return Ok(());
    }
    sync_dirty(w)?;
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

struct Decoder {
    reader: Box<dyn Read>,
    buf: Vec<u8>,
    complete: u64,
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

/// Windows: a delete-pending plain segment fails open with PermissionDenied; read its .z twin instead.
fn listed_seg_decoder(dir: &Path, seg: u32, compressed: bool) -> Result<Option<Decoder>> {
    use std::io::ErrorKind;
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

pub fn read_dir(dir: &Path, after: u64, limit: usize, step: Option<u32>) -> Result<Tail> {
    read_page(dir, after, Page::frames(limit), step)
}

pub fn read_page(dir: &Path, after: u64, page: Page, step: Option<u32>) -> Result<Tail> {
    let segs = segs(dir)?;
    let marker = end_marker(dir);
    if segs.is_empty() && marker.is_none() {
        return Err(Error::NotFound);
    }
    let index_bytes = fs::read(dir.join("index")).unwrap_or_default();
    let entries = read_index(&index_bytes).unwrap_or_default();
    let start = seek_start(&entries, after, false);
    let mut tail = Tail {
        frames: Vec::new(),
        complete: marker.is_some(),
        gaps: Vec::new(),
        next_after: None,
        step_done: step.is_some_and(|want| step_moved_on(&entries, want)),
    };
    let from_start = start == segs.keys().next().copied().unwrap_or(0);
    let mut prev_seq = 0u64;
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
                            fill_hole(&mut tail.gaps, frame.seq);
                        }
                    }
                    prev_seq = prev_seq.max(frame.seq);
                    if frame.seq <= after {
                        continue;
                    }
                    let len = frame.bytes.len() as u64;
                    let wanted = step.is_none_or(|s| frame.step == s);
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
        None => merge_holes(&mut tail.gaps, &read_holes(dir)),
    }
    Ok(tail)
}

pub fn read_newest(dir: &Path, page: Page, step: Option<u32>) -> Result<Tail> {
    let segs = segs(dir)?;
    let marker = end_marker(dir);
    if segs.is_empty() && marker.is_none() {
        return Err(Error::NotFound);
    }
    let index_bytes = fs::read(dir.join("index")).unwrap_or_default();
    let entries = read_index(&index_bytes).unwrap_or_default();
    let mut tail = Tail {
        frames: Vec::new(),
        complete: marker.is_some(),
        gaps: Vec::new(),
        next_after: None,
        step_done: step.is_some_and(|want| step_moved_on(&entries, want)),
    };
    let mut until = u64::MAX;
    let mut end: Option<&Entry> = entries.last();
    if let Some(want) = step {
        match entries
            .iter()
            .rposition(|e| e.kind == KIND_CHECKPOINT && e.step == want)
        {
            Some(last) => {
                if let Some(next) = entries[last + 1..]
                    .iter()
                    .find(|e| e.kind == KIND_CHECKPOINT && e.step != want)
                {
                    until = next.seq.saturating_sub(1);
                    end = Some(next);
                }
            }
            None if !entries.is_empty() => {
                merge_newest_gaps(dir, marker, &mut tail);
                return Ok(tail);
            }
            None => {}
        }
    }
    let after = match end {
        Some(end) => entries
            .iter()
            .filter(|e| e.seq <= until && e.seq < end.seq)
            .filter(|e| {
                end.seq.saturating_sub(e.seq) >= page.limit as u64
                    || end.bytes.saturating_sub(e.bytes) >= page.bytes
            })
            .map(|e| e.seq)
            .next_back()
            .unwrap_or(0),
        None => 0,
    };
    let start = seek_start(&entries, after, false);
    let mut window: VecDeque<Frame> = VecDeque::new();
    let (mut held, mut scanned, mut consumed) = (0u64, 0u64, after);
    'decode: for (n, compressed) in segs.range(start..) {
        let Some(mut decoder) = listed_seg_decoder(dir, *n, *compressed)? else {
            break;
        };
        while let Some(record) = decoder.next()? {
            match record {
                Record::Frame(frame) => {
                    if frame.seq <= after {
                        continue;
                    }
                    if frame.seq > until {
                        break 'decode;
                    }
                    let len = frame.bytes.len() as u64;
                    if scanned > 0 && scanned.saturating_add(len) > page.scan {
                        tail.next_after = Some(consumed);
                        break 'decode;
                    }
                    scanned += len;
                    consumed = consumed.max(frame.seq);
                    if step.is_some_and(|want| frame.step != want) {
                        continue;
                    }
                    held += len;
                    window.push_back(frame);
                    while window.len() > page.limit.max(1)
                        || (window.len() > 1 && held > page.bytes)
                    {
                        if let Some(old) = window.pop_front() {
                            held -= old.bytes.len() as u64;
                        }
                    }
                }
                Record::End { gaps, .. } => {
                    tail.complete = true;
                    merge_holes(&mut tail.gaps, &gaps);
                    break 'decode;
                }
            }
        }
    }
    tail.frames = window.into();
    merge_newest_gaps(dir, marker, &mut tail);
    Ok(tail)
}

fn merge_newest_gaps(dir: &Path, marker: Option<(u64, Vec<(u64, u64)>)>, tail: &mut Tail) {
    match marker {
        Some((_, gaps)) => merge_holes(&mut tail.gaps, &gaps),
        None => merge_holes(&mut tail.gaps, &read_holes(dir)),
    }
}

fn step_moved_on(entries: &[Entry], want: u32) -> bool {
    let last_want = entries
        .iter()
        .filter(|e| e.step == want)
        .map(|e| e.seq)
        .max()
        .unwrap_or(0);
    entries.iter().any(|e| e.step > want && e.seq > last_want)
}

pub fn read_tail(path: &Path, after: u64, limit: usize, step: Option<u32>) -> Result<Tail> {
    read_tail_page(path, after, Page::frames(limit), step)
}

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
