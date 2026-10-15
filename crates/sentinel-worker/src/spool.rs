//! Frames reach disk before they reach the link, so a worker restart resumes from the cursor.

use std::{
    collections::VecDeque,
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use sentinel_core::AttemptId;
use sentinel_protocol::{
    limits::{MAX_LOG_FRAME_BYTES, MAX_UNACKED_LOG_FRAMES},
    logs::{FRAME_HEADER_BYTES, Frame, MAX_GAPS, Record, RecordError, Stream, encode_frame},
};

use crate::{Error, Result, sync_dir};

pub const SPOOL_DIR: &str = "spool";
pub const MAX_SPOOL_BYTES: u64 = 256 << 20;
pub const DEFAULT_SPOOL_RESERVE: u64 = 1 << 30;
pub const DEFAULT_SPOOL_QUOTA: u64 = 16 * MAX_SPOOL_BYTES;
const GRANT_BYTES: u64 = 16 << 20;
const PROBE_BACKOFF: Duration = Duration::from_secs(1);
const SCAN_CHUNK: usize = 64 << 10;
const MAX_RECORD: u64 = (FRAME_HEADER_BYTES + MAX_LOG_FRAME_BYTES) as u64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    Cap,
    Quota,
    LowSpace,
    WriteFailed,
    GapLimit,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Refused {
    pub cap: u64,
    pub quota: u64,
    pub low_space: u64,
    pub failed: u64,
    pub gap_limit: u64,
}

impl Refused {
    pub fn count(&mut self, why: Refusal) {
        let slot = match why {
            Refusal::Cap => &mut self.cap,
            Refusal::Quota => &mut self.quota,
            Refusal::LowSpace => &mut self.low_space,
            Refusal::WriteFailed => &mut self.failed,
            Refusal::GapLimit => &mut self.gap_limit,
        };
        *slot += 1;
    }

    pub fn total(&self) -> u64 {
        self.cap + self.quota + self.low_space + self.failed + self.gap_limit
    }
}

type Probe = Box<dyn Fn(&Path) -> Option<u64> + Send + Sync>;

pub struct SpoolSpace {
    root: PathBuf,
    reserve: AtomicU64,
    quota: AtomicU64,
    used: AtomicU64,
    grant: AtomicU64,
    refused_at: Mutex<Option<Instant>>,
    probe: Probe,
    rooted: AtomicBool,
}

impl SpoolSpace {
    pub fn new(root: impl Into<PathBuf>, reserve: u64, quota: u64) -> Arc<SpoolSpace> {
        Self::with_probe(root, reserve, quota, free_bytes)
    }

    pub fn unbounded(root: impl Into<PathBuf>) -> Arc<SpoolSpace> {
        Self::with_probe(root, 0, u64::MAX, |_| None)
    }

    pub fn with_probe(
        root: impl Into<PathBuf>,
        reserve: u64,
        quota: u64,
        probe: impl Fn(&Path) -> Option<u64> + Send + Sync + 'static,
    ) -> Arc<SpoolSpace> {
        Arc::new(SpoolSpace {
            root: root.into(),
            reserve: AtomicU64::new(reserve),
            quota: AtomicU64::new(quota),
            used: AtomicU64::new(0),
            grant: AtomicU64::new(0),
            refused_at: Mutex::new(None),
            probe: Box::new(probe),
            rooted: AtomicBool::new(false),
        })
    }

    pub fn set_limits(&self, reserve: u64, quota: u64) {
        self.reserve.store(reserve, Ordering::Relaxed);
        self.quota.store(quota, Ordering::Relaxed);
        self.grant.store(0, Ordering::Release);
        *self.refused_at.lock().unwrap_or_else(|p| p.into_inner()) = None;
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn used(&self) -> u64 {
        self.used.load(Ordering::Relaxed)
    }

    fn admit(&self, n: u64) -> std::result::Result<(), Refusal> {
        let quota = self.quota.load(Ordering::Relaxed);
        if self
            .used
            .fetch_update(Ordering::AcqRel, Ordering::Relaxed, |used| {
                used.checked_add(n).filter(|total| *total <= quota)
            })
            .is_err()
        {
            return Err(Refusal::Quota);
        }
        if self.take(n) || self.refill(n) {
            return Ok(());
        }
        self.used.fetch_sub(n, Ordering::AcqRel);
        Err(Refusal::LowSpace)
    }

    fn take(&self, n: u64) -> bool {
        self.grant
            .fetch_update(Ordering::AcqRel, Ordering::Relaxed, |left| {
                left.checked_sub(n)
            })
            .is_ok()
    }

    fn refill(&self, n: u64) -> bool {
        let mut refused_at = self.refused_at.lock().unwrap_or_else(|p| p.into_inner());
        if self.take(n) {
            return true;
        }
        if refused_at.is_some_and(|at| at.elapsed() < PROBE_BACKOFF) {
            return false;
        }
        let above = (self.probe)(&self.root).map_or(GRANT_BYTES, |free| {
            free.saturating_sub(self.reserve.load(Ordering::Relaxed))
                .min(GRANT_BYTES)
        });
        if above >= n {
            self.grant.store(above - n, Ordering::Release);
            *refused_at = None;
            true
        } else {
            self.grant.store(0, Ordering::Release);
            *refused_at = Some(Instant::now());
            false
        }
    }

    fn charge(&self, n: u64) {
        self.used.fetch_add(n, Ordering::AcqRel);
    }

    fn release(&self, n: u64) {
        let _ = self
            .used
            .fetch_update(Ordering::AcqRel, Ordering::Relaxed, |used| {
                Some(used.saturating_sub(n))
            });
    }

    fn sync_root(&self) -> Result<()> {
        if !self.rooted.load(Ordering::Acquire) {
            sync_dir(&self.root)?;
            self.rooted.store(true, Ordering::Release);
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn free_bytes(path: &Path) -> Option<u64> {
    use std::os::unix::ffi::OsStrExt;
    let cpath = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
    let mut stat = std::mem::MaybeUninit::<libc::statvfs>::zeroed();
    // SAFETY: `cpath` is NUL-terminated and `stat` is a writable statvfs.
    if unsafe { libc::statvfs(cpath.as_ptr(), stat.as_mut_ptr()) } != 0 {
        return None;
    }
    // SAFETY: statvfs returned 0, so it filled the whole structure.
    let stat = unsafe { stat.assume_init() };
    let block = if stat.f_frsize != 0 {
        stat.f_frsize
    } else {
        stat.f_bsize
    };
    Some(stat.f_bavail.saturating_mul(block))
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn free_bytes(_path: &Path) -> Option<u64> {
    None
}

#[cfg(target_os = "linux")]
pub fn filesystem_bytes(path: &Path) -> Option<u64> {
    use std::os::unix::ffi::OsStrExt;
    let cpath = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
    let mut stat = std::mem::MaybeUninit::<libc::statvfs>::zeroed();
    // SAFETY: `cpath` is NUL-terminated and `stat` is a writable statvfs.
    if unsafe { libc::statvfs(cpath.as_ptr(), stat.as_mut_ptr()) } != 0 {
        return None;
    }
    // SAFETY: statvfs returned 0, so it filled the whole structure.
    let stat = unsafe { stat.assume_init() };
    let block = if stat.f_frsize != 0 {
        stat.f_frsize
    } else {
        stat.f_bsize
    };
    Some(stat.f_blocks.saturating_mul(block))
}

#[cfg(not(target_os = "linux"))]
pub fn filesystem_bytes(_path: &Path) -> Option<u64> {
    None
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ScanEnd {
    Clean,
    Torn,
    Invalid,
}

fn scan(file: &mut File, mut each: impl FnMut(Record, u64) -> bool) -> Result<(u64, ScanEnd)> {
    let mut buf = Vec::with_capacity(SCAN_CHUNK + MAX_RECORD as usize);
    let mut at = 0u64;
    loop {
        match Record::decode(&buf) {
            Ok((record, used)) => {
                let keep = each(record, at);
                buf.drain(..used);
                at += used as u64;
                if !keep {
                    return Ok((at, ScanEnd::Clean));
                }
            }
            Err(RecordError::Incomplete) => {
                let mut chunk = [0u8; SCAN_CHUNK];
                let got = file.read(&mut chunk)?;
                if got == 0 {
                    return Ok((at, ScanEnd::Torn));
                }
                buf.extend_from_slice(&chunk[..got]);
            }
            // A power cut can leave an unsynced tail reading as zeros: that is a torn tail, not corruption.
            Err(RecordError::Invalid) => {
                let torn = !buf.iter().any(|b| *b != 0) && rest_is_zero(file)?;
                return Ok((
                    at,
                    if torn {
                        ScanEnd::Torn
                    } else {
                        ScanEnd::Invalid
                    },
                ));
            }
        }
    }
}

fn rest_is_zero(file: &mut File) -> Result<bool> {
    let mut chunk = [0u8; SCAN_CHUNK];
    loop {
        let got = file.read(&mut chunk)?;
        if got == 0 {
            return Ok(true);
        }
        if chunk[..got].iter().any(|b| *b != 0) {
            return Ok(false);
        }
    }
}

pub struct Spool {
    dir: PathBuf,
    frames: File,
    space: Arc<SpoolSpace>,
    len: u64,
    max: u64,
    next_seq: u64,
    last_stored: u64,
    acked: u64,
    send_offset: u64,
    gaps: Vec<(u64, u64)>,
    sealed: bool,
    refusal: Option<Refusal>,
    marks: VecDeque<(u64, u64)>,
    acked_offset: Option<u64>,
    declared_synced: u64,
    dirs_synced: bool,
    end: Option<(u64, Vec<(u64, u64)>)>,
    scratch: Vec<u8>,
}

impl Spool {
    pub fn open(root: &Path, attempt: AttemptId) -> Result<Spool> {
        Self::open_with_limit(root, attempt, MAX_SPOOL_BYTES)
    }

    pub fn open_with_limit(root: &Path, attempt: AttemptId, max: u64) -> Result<Spool> {
        Self::open_in(&SpoolSpace::unbounded(root), attempt, max)
    }

    pub fn open_in(space: &Arc<SpoolSpace>, attempt: AttemptId, max: u64) -> Result<Spool> {
        let dir = space.root.join(SPOOL_DIR).join(attempt.to_string());
        crate::private_dir_all(&dir)?;
        // Read/write rather than append: a torn tail is truncated on open, which append-only handles refuse on some platforms.
        let mut frames = OpenOptions::new()
            .create(true)
            .write(true)
            .read(true)
            .truncate(false)
            .open(dir.join("frames"))?;
        frames.seek(SeekFrom::Start(0))?;
        let mut last = 0u64;
        let mut gaps: Vec<(u64, u64)> = Vec::new();
        let mut end = None;
        let (at, scanned) = scan(&mut frames, |record, _| {
            match record {
                Record::Frame(f) => {
                    if f.seq > last + 1 {
                        gaps.push((last + 1, f.seq - 1));
                    }
                    last = last.max(f.seq);
                }
                Record::End { last_seq, gaps } => end = Some((last_seq, gaps)),
            }
            true
        })?;
        if matches!(scanned, ScanEnd::Invalid) {
            return Err(Error::Workspace("spool corrupt".into()));
        }
        frames.set_len(at)?;
        frames.seek(SeekFrom::End(0))?;
        let read_seq = |name: &str| -> u64 {
            fs::read_to_string(dir.join(name))
                .ok()
                .and_then(|t| t.trim().parse().ok())
                .unwrap_or(0)
        };
        let acked = read_seq("cursor");
        let declared = read_seq("declared");
        let _ = fs::remove_file(dir.join("declared.tmp"));
        let delivered = last.max(acked);
        let next_seq = match &end {
            Some((last_seq, declared_gaps)) => {
                gaps.clone_from(declared_gaps);
                *last_seq + 1
            }
            None => {
                if declared > delivered {
                    gaps.push((delivered + 1, declared));
                }
                delivered.max(declared) + 1
            }
        };
        space.charge(at);
        let mut spool = Spool {
            dir,
            frames,
            space: Arc::clone(space),
            len: at,
            max,
            next_seq,
            last_stored: last,
            acked,
            send_offset: 0,
            sealed: gaps.len() >= MAX_GAPS - 1,
            gaps,
            refusal: None,
            marks: VecDeque::new(),
            acked_offset: None,
            declared_synced: declared,
            dirs_synced: false,
            end,
            scratch: Vec::new(),
        };
        spool.rewind(acked)?;
        Ok(spool)
    }

    pub fn rewind(&mut self, after: u64) -> Result<()> {
        self.marks.clear();
        if after == self.acked
            && let Some(offset) = self.acked_offset
        {
            self.send_offset = offset;
            return Ok(());
        }
        self.frames.seek(SeekFrom::Start(0))?;
        let mut at = self.len;
        scan(&mut self.frames, |record, offset| {
            if let Record::Frame(f) = record
                && f.seq > after
            {
                at = offset;
                return false;
            }
            true
        })?;
        self.send_offset = at;
        if after == self.acked {
            self.acked_offset = Some(at);
        }
        self.frames.seek(SeekFrom::End(0))?;
        Ok(())
    }

    pub fn caught_up(&self) -> bool {
        self.send_offset == self.len
    }

    pub fn sent_tail(&mut self, seq: u64) {
        self.send_offset = self.len;
        self.mark(seq, self.len);
    }

    fn mark(&mut self, seq: u64, end: u64) {
        if self.marks.len() >= 4 * MAX_UNACKED_LOG_FRAMES {
            self.marks.clear();
            self.acked_offset = None;
        }
        self.marks.push_back((seq, end));
    }

    pub fn send_next(&mut self, limit: usize) -> Result<Vec<Frame>> {
        if limit == 0 || self.send_offset >= self.len {
            return Ok(Vec::new());
        }
        let want = (self.len - self.send_offset).min(limit as u64 * MAX_RECORD) as usize;
        let mut bytes = vec![0u8; want];
        self.frames.seek(SeekFrom::Start(self.send_offset))?;
        self.frames.read_exact(&mut bytes)?;
        self.frames.seek(SeekFrom::End(0))?;
        let mut out = Vec::new();
        let mut at = 0;
        while at < bytes.len() && out.len() < limit {
            match Record::decode(&bytes[at..]) {
                Ok((Record::Frame(f), used)) => {
                    at += used;
                    let end = self.send_offset + at as u64;
                    self.mark(f.seq, end);
                    out.push(f);
                }
                Ok((_, used)) => at += used,
                Err(_) => break,
            }
        }
        self.send_offset += at as u64;
        Ok(out)
    }

    pub fn append(&mut self, step: u32, stream: Stream, bytes: &[u8]) -> Result<Option<u64>> {
        debug_assert!(bytes.len() <= MAX_LOG_FRAME_BYTES);
        let seq = self.next_seq;
        self.scratch.clear();
        encode_frame(seq, step, stream, bytes, &mut self.scratch)
            .map_err(|_| Error::Workspace("log frame".into()))?;
        self.next_seq += 1;
        let encoded = self.scratch.len() as u64;
        let refused = if self.sealed {
            Some(Refusal::GapLimit)
        } else if self.len + encoded > self.max {
            Some(Refusal::Cap)
        } else {
            self.space.admit(encoded).err()
        };
        if let Some(why) = refused {
            self.refusal = Some(why);
            self.declared_gap(seq)?;
            return Ok(None);
        }
        self.frames.seek(SeekFrom::End(0))?;
        if let Err(e) = self.frames.write_all(&self.scratch) {
            self.space.release(encoded);
            let _ = self.frames.set_len(self.len);
            self.refusal = Some(Refusal::WriteFailed);
            let _ = self.declared_gap(seq);
            return Err(e.into());
        }
        self.len += encoded;
        self.last_stored = seq;
        self.refusal = None;
        Ok(Some(seq))
    }

    pub fn last_refusal(&self) -> Option<Refusal> {
        self.refusal
    }

    fn declared_gap(&mut self, seq: u64) -> Result<()> {
        match self.gaps.last_mut() {
            Some((_, to)) if *to + 1 == seq => *to = seq,
            _ => {
                self.gaps.push((seq, seq));
                if self.gaps.len() >= MAX_GAPS - 1 {
                    self.sealed = true;
                }
                self.persist_declared()?;
            }
        }
        Ok(())
    }

    pub fn declare_cut(&mut self) -> Result<()> {
        let seq = self.next_seq;
        self.next_seq += 1;
        self.declared_gap(seq)
    }

    pub fn persist_end(&mut self) -> Result<()> {
        let last_seq = self.last_seq();
        if self
            .end
            .as_ref()
            .is_some_and(|(last, gaps)| *last == last_seq && *gaps == self.gaps)
        {
            return Ok(());
        }
        self.persist_declared()?;
        self.scratch.clear();
        Record::End {
            last_seq,
            gaps: self.gaps.clone(),
        }
        .encode(&mut self.scratch)
        .map_err(|_| Error::Workspace("log end".into()))?;
        self.frames.seek(SeekFrom::End(0))?;
        if let Err(e) = self.frames.write_all(&self.scratch) {
            let _ = self.frames.set_len(self.len);
            return Err(e.into());
        }
        let written = self.scratch.len() as u64;
        self.space.charge(written);
        self.len += written;
        self.sync()?;
        self.end = Some((last_seq, self.gaps.clone()));
        Ok(())
    }

    pub fn ended(&self) -> bool {
        self.end.is_some()
    }

    /// Written atomically and durably: an unsynced file would read back as nothing declared, and a restart would re-number.
    fn persist_declared(&mut self) -> Result<()> {
        let through = self.gaps.last().map_or(0, |g| g.1);
        if through > self.declared_synced {
            let tmp = self.dir.join("declared.tmp");
            {
                let mut file = File::create(&tmp)?;
                file.write_all(format!("{through}\n").as_bytes())?;
                file.sync_data()?;
            }
            fs::rename(&tmp, self.dir.join("declared"))?;
            sync_dir(&self.dir)?;
            self.sync_parents()?;
            self.declared_synced = through;
        }
        Ok(())
    }

    fn sync_parents(&mut self) -> Result<()> {
        if !self.dirs_synced {
            if let Some(parent) = self.dir.parent() {
                sync_dir(parent)?;
            }
            self.space.sync_root()?;
            self.dirs_synced = true;
        }
        Ok(())
    }

    pub fn sync(&mut self) -> Result<()> {
        self.persist_declared()?;
        self.frames.sync_data()?;
        if !self.dirs_synced {
            sync_dir(&self.dir)?;
            self.sync_parents()?;
        }
        Ok(())
    }

    pub fn acknowledged(&mut self, seq: u64) -> Result<()> {
        if seq <= self.acked {
            return Ok(());
        }
        let mut end = None;
        while let Some(&(sent, after)) = self.marks.front() {
            if sent > seq {
                break;
            }
            end = Some(after);
            self.marks.pop_front();
        }
        self.acked_offset = end;
        self.acked = seq;
        if seq >= self.next_seq && self.end.is_none() {
            self.next_seq = seq + 1;
        }
        fs::write(self.dir.join("cursor"), format!("{seq}\n"))?;
        Ok(())
    }

    pub fn acked(&self) -> u64 {
        self.acked
    }

    pub fn last_seq(&self) -> u64 {
        self.next_seq - 1
    }

    pub fn last_stored(&self) -> u64 {
        self.last_stored
    }

    pub fn gaps(&self) -> &[(u64, u64)] {
        &self.gaps
    }

    pub fn unacked(&mut self, after: u64, limit: usize) -> Result<Vec<Frame>> {
        self.frames.seek(SeekFrom::Start(0))?;
        let mut out = Vec::new();
        scan(&mut self.frames, |record, _| {
            if let Record::Frame(f) = record
                && f.seq > after
            {
                out.push(f);
            }
            out.len() < limit
        })?;
        self.frames.seek(SeekFrom::End(0))?;
        Ok(out)
    }

    pub fn remove(self) -> Result<()> {
        let dir = self.dir.clone();
        drop(self);
        match fs::remove_dir_all(&dir) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    pub fn leftovers(root: &Path) -> Result<Vec<AttemptId>> {
        let parent = root.join(SPOOL_DIR);
        let mut found = Vec::new();
        let entries = match fs::read_dir(&parent) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(found),
            Err(e) => return Err(e.into()),
        };
        for entry in entries.flatten() {
            if let Some(id) = entry
                .file_name()
                .to_str()
                .and_then(|n| n.parse::<AttemptId>().ok())
            {
                found.push(id);
            }
        }
        Ok(found)
    }
}

impl Drop for Spool {
    fn drop(&mut self) {
        self.space.release(self.len);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_spool_survives_reopening_and_resends_only_what_is_unacknowledged() {
        let temp = tempfile::tempdir().unwrap();
        let attempt = AttemptId::new();
        let mut spool = Spool::open(temp.path(), attempt).unwrap();
        for i in 0..5u8 {
            let seq = spool.append(0, Stream::Stdout, &[i]).unwrap().unwrap();
            assert_eq!(seq, u64::from(i) + 1);
        }
        spool.sync().unwrap();
        spool.acknowledged(2).unwrap();
        spool.acknowledged(1).unwrap();
        assert_eq!(spool.acked(), 2);
        drop(spool);
        {
            let mut f = OpenOptions::new()
                .append(true)
                .open(
                    temp.path()
                        .join(SPOOL_DIR)
                        .join(attempt.to_string())
                        .join("frames"),
                )
                .unwrap();
            f.write_all(&[1, 9, 0]).unwrap();
        }
        let mut spool = Spool::open(temp.path(), attempt).unwrap();
        assert_eq!((spool.acked(), spool.last_seq()), (2, 5));
        let pending = spool.unacked(spool.acked(), 10).unwrap();
        assert_eq!(
            pending.iter().map(|f| f.seq).collect::<Vec<_>>(),
            vec![3, 4, 5]
        );
        assert_eq!(pending[0].bytes, vec![2]);
        let batch = spool.send_next(2).unwrap();
        assert_eq!(batch.iter().map(|f| f.seq).collect::<Vec<_>>(), vec![3, 4]);
        assert_eq!(spool.append(1, Stream::Stderr, b"x").unwrap().unwrap(), 6);
        let rest = spool.send_next(10).unwrap();
        assert_eq!(rest.iter().map(|f| f.seq).collect::<Vec<_>>(), vec![5, 6]);
        assert!(spool.send_next(10).unwrap().is_empty());
        spool.rewind(4).unwrap();
        assert_eq!(spool.send_next(10).unwrap().len(), 2);
        assert_eq!(Spool::leftovers(temp.path()).unwrap(), vec![attempt]);
        spool.remove().unwrap();
        assert!(Spool::leftovers(temp.path()).unwrap().is_empty());
    }

    #[test]
    fn a_full_spool_declares_gaps_and_the_sequences_stay_spent() {
        let temp = tempfile::tempdir().unwrap();
        let attempt = AttemptId::new();
        let mut spool = Spool::open_with_limit(temp.path(), attempt, 59).unwrap();
        assert!(spool.append(0, Stream::Stdout, b"aa").unwrap().is_some());
        assert!(spool.append(0, Stream::Stdout, b"bb").unwrap().is_some());
        assert!(spool.append(0, Stream::Stdout, b"cc").unwrap().is_none());
        assert!(spool.append(1, Stream::Stderr, b"dd").unwrap().is_none());
        assert_eq!(spool.gaps(), &[(3, 4)]);
        assert_eq!(spool.last_seq(), 4);
        assert_eq!(spool.unacked(0, 10).unwrap().len(), 2);
        spool.sync().unwrap();
        drop(spool);
        let mut reopened = Spool::open_with_limit(temp.path(), attempt, 59).unwrap();
        assert_eq!(reopened.gaps(), &[(3, 4)]);
        assert_eq!(reopened.last_seq(), 4);
        assert_eq!(
            reopened
                .send_next(10)
                .unwrap()
                .iter()
                .map(|f| f.seq)
                .collect::<Vec<_>>(),
            vec![1, 2]
        );
        drop(reopened);
        let mut spool = Spool::open_with_limit(temp.path(), attempt, 59).unwrap();
        assert!(spool.append(0, Stream::Stdout, b"ee").unwrap().is_none());
        spool.sync().unwrap();
        drop(spool);
        let mut spool = Spool::open_with_limit(temp.path(), attempt, 60).unwrap();
        assert_eq!(spool.append(0, Stream::Stdout, b"ee").unwrap(), Some(6));
        spool.sync().unwrap();
        drop(spool);
        let reopened = Spool::open_with_limit(temp.path(), attempt, 60).unwrap();
        assert_eq!(reopened.gaps(), &[(3, 5)]);
        assert_eq!(reopened.last_seq(), 6);
    }

    #[test]
    fn a_reopened_spool_never_reuses_an_acknowledged_sequence() {
        let temp = tempfile::tempdir().unwrap();
        let attempt = AttemptId::new();
        let mut spool = Spool::open(temp.path(), attempt).unwrap();
        spool.append(0, Stream::Stdout, b"one").unwrap();
        spool.acknowledged(3).unwrap();
        drop(spool);
        let mut spool = Spool::open(temp.path(), attempt).unwrap();
        assert_eq!(spool.append(0, Stream::Stdout, b"next").unwrap(), Some(4));
    }

    fn probed(
        root: &Path,
        reserve: u64,
    ) -> (
        Arc<SpoolSpace>,
        Arc<AtomicU64>,
        Arc<std::sync::atomic::AtomicUsize>,
    ) {
        let free = Arc::new(AtomicU64::new(u64::MAX));
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let (f, c) = (Arc::clone(&free), Arc::clone(&calls));
        let space = SpoolSpace::with_probe(root, reserve, u64::MAX, move |_| {
            c.fetch_add(1, Ordering::SeqCst);
            Some(f.load(Ordering::SeqCst))
        });
        (space, free, calls)
    }

    #[test]
    fn a_disk_at_its_reserve_refuses_into_declared_gaps_and_recovers() {
        let temp = tempfile::tempdir().unwrap();
        let (space, free, calls) = probed(temp.path(), 1 << 20);
        let attempt = AttemptId::new();
        let mut spool = Spool::open_in(&space, attempt, MAX_SPOOL_BYTES).unwrap();
        for _ in 0..1_000 {
            assert!(spool.append(0, Stream::Stdout, b"fits").unwrap().is_some());
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1, "one probe per grant");
        assert_eq!(space.used(), 1_000 * 22);

        free.store((1 << 20) + 10, Ordering::SeqCst);
        space.set_limits(1 << 20, u64::MAX);
        let before = calls.load(Ordering::SeqCst);
        for _ in 0..500 {
            assert!(spool.append(0, Stream::Stdout, b"lost").unwrap().is_none());
            assert_eq!(spool.last_refusal(), Some(Refusal::LowSpace));
        }
        assert_eq!(
            calls.load(Ordering::SeqCst),
            before + 1,
            "one probe per back-off"
        );
        assert_eq!(spool.gaps(), &[(1_001, 1_500)]);

        free.store(1 << 30, Ordering::SeqCst);
        std::thread::sleep(PROBE_BACKOFF);
        assert_eq!(
            spool.append(0, Stream::Stdout, b"back").unwrap(),
            Some(1_501)
        );
        assert_eq!(spool.last_refusal(), None);
        spool.sync().unwrap();
        drop(spool);
        assert_eq!(space.used(), 0, "a closed spool leaves the quota");
        let reopened = Spool::open_in(&space, attempt, MAX_SPOOL_BYTES).unwrap();
        assert_eq!(reopened.gaps(), &[(1_001, 1_500)]);
        assert_eq!(space.used(), 1_001 * 22);
    }

    #[test]
    fn spools_share_the_quota_and_return_it_when_they_close() {
        let temp = tempfile::tempdir().unwrap();
        let space = SpoolSpace::with_probe(temp.path(), 0, 3 * 22, |_| None);
        let mut a = Spool::open_in(&space, AttemptId::new(), MAX_SPOOL_BYTES).unwrap();
        let mut b = Spool::open_in(&space, AttemptId::new(), MAX_SPOOL_BYTES).unwrap();
        assert!(a.append(0, Stream::Stdout, b"aaaa").unwrap().is_some());
        assert!(a.append(0, Stream::Stdout, b"aaaa").unwrap().is_some());
        assert!(b.append(0, Stream::Stdout, b"bbbb").unwrap().is_some());
        assert!(b.append(0, Stream::Stdout, b"bbbb").unwrap().is_none());
        assert_eq!(b.last_refusal(), Some(Refusal::Quota));
        assert_eq!(b.gaps(), &[(2, 2)]);
        a.remove().unwrap();
        assert_eq!(b.append(0, Stream::Stdout, b"bbbb").unwrap(), Some(3));
    }

    #[test]
    fn the_gap_list_is_bounded_by_what_the_end_can_carry() {
        let temp = tempfile::tempdir().unwrap();
        let space = SpoolSpace::with_probe(temp.path(), 0, u64::MAX, |_| None);
        let mut spool = Spool::open_in(&space, AttemptId::new(), MAX_SPOOL_BYTES).unwrap();
        for _ in 0..2 * MAX_GAPS {
            space.set_limits(0, 0);
            assert!(spool.append(0, Stream::Stdout, b"x").unwrap().is_none());
            space.set_limits(0, u64::MAX);
            let _ = spool.append(0, Stream::Stdout, b"y").unwrap();
        }
        assert_eq!(spool.gaps().len(), MAX_GAPS - 1);
        assert_eq!(spool.last_refusal(), Some(Refusal::GapLimit));
        assert_eq!(spool.gaps().last().unwrap().1, spool.last_seq());
        spool.declare_cut().unwrap();
        assert!(spool.gaps().len() <= MAX_GAPS);
        spool.persist_end().unwrap();
    }

    #[test]
    fn an_end_record_is_kept_and_a_crash_cut_declares_its_tail() {
        let temp = tempfile::tempdir().unwrap();
        let (ended, cut) = (AttemptId::new(), AttemptId::new());
        let mut spool = Spool::open_with_limit(temp.path(), ended, 59).unwrap();
        for _ in 0..3 {
            let _ = spool.append(0, Stream::Stdout, b"aa").unwrap();
        }
        spool.persist_end().unwrap();
        spool.persist_end().unwrap();
        drop(spool);
        let mut reopened = Spool::open_with_limit(temp.path(), ended, 59).unwrap();
        assert!(reopened.ended());
        assert_eq!((reopened.last_seq(), reopened.gaps()), (3, &[(3, 3)][..]));
        assert_eq!(reopened.send_next(10).unwrap().len(), 2);

        let mut spool = Spool::open(temp.path(), cut).unwrap();
        spool.append(0, Stream::Stdout, b"printed").unwrap();
        spool.sync().unwrap();
        drop(spool);
        let mut reopened = Spool::open(temp.path(), cut).unwrap();
        assert!(!reopened.ended());
        reopened.declare_cut().unwrap();
        assert_eq!((reopened.last_seq(), reopened.gaps()), (2, &[(2, 2)][..]));
    }

    #[test]
    fn an_acknowledgement_past_the_spool_moves_its_end() {
        let temp = tempfile::tempdir().unwrap();
        let mut spool = Spool::open(temp.path(), AttemptId::new()).unwrap();
        spool.append(0, Stream::Stdout, b"one").unwrap();
        spool.acknowledged(5).unwrap();
        assert_eq!((spool.last_seq(), spool.last_stored()), (5, 1));
        spool.persist_end().unwrap();
        assert_eq!(spool.last_seq(), 5);
    }

    #[test]
    fn a_zeroed_tail_is_cut_but_garbage_is_corrupt() {
        let temp = tempfile::tempdir().unwrap();
        let (zeroed, garbled) = (AttemptId::new(), AttemptId::new());
        for (attempt, tail) in [(zeroed, [0u8; 300]), (garbled, [5u8; 300])] {
            let mut spool = Spool::open(temp.path(), attempt).unwrap();
            spool.append(0, Stream::Stdout, b"kept").unwrap();
            spool.sync().unwrap();
            drop(spool);
            OpenOptions::new()
                .append(true)
                .open(
                    temp.path()
                        .join(SPOOL_DIR)
                        .join(attempt.to_string())
                        .join("frames"),
                )
                .unwrap()
                .write_all(&tail)
                .unwrap();
        }
        let mut spool = Spool::open(temp.path(), zeroed).unwrap();
        assert_eq!(spool.unacked(0, 10).unwrap().len(), 1);
        assert_eq!(spool.append(0, Stream::Stdout, b"next").unwrap(), Some(2));
        assert!(Spool::open(temp.path(), garbled).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn the_free_space_probe_reads_the_file_system() {
        let temp = tempfile::tempdir().unwrap();
        assert!(free_bytes(temp.path()).is_some_and(|free| free > 0));
        assert!(free_bytes(&temp.path().join("missing")).is_none());
    }

    #[test]
    fn rewinds_to_the_acknowledgement_resume_at_the_recorded_offset() {
        let temp = tempfile::tempdir().unwrap();
        let attempt = AttemptId::new();
        let mut spool = Spool::open(temp.path(), attempt).unwrap();
        for i in 0..4u8 {
            assert!(spool.caught_up());
            let seq = spool.append(0, Stream::Stdout, &[i]).unwrap().unwrap();
            spool.sent_tail(seq);
        }
        spool.acknowledged(2).unwrap();
        spool.rewind(2).unwrap();
        assert_eq!(
            spool
                .send_next(10)
                .unwrap()
                .iter()
                .map(|f| f.seq)
                .collect::<Vec<_>>(),
            vec![3, 4]
        );
        spool.acknowledged(4).unwrap();
        spool.rewind(4).unwrap();
        assert!(spool.send_next(10).unwrap().is_empty());
        assert!(spool.caught_up());
    }

    #[test]
    fn a_crash_after_a_refused_tail_still_declares_it() {
        let temp = tempfile::tempdir().unwrap();
        let attempt = AttemptId::new();
        let mut spool = Spool::open_with_limit(temp.path(), attempt, 59).unwrap();
        assert!(spool.append(0, Stream::Stdout, b"aa").unwrap().is_some());
        assert!(spool.append(0, Stream::Stdout, b"bb").unwrap().is_some());
        assert!(spool.append(0, Stream::Stdout, b"cc").unwrap().is_none());
        assert!(spool.append(0, Stream::Stdout, b"dd").unwrap().is_none());
        spool.sync().unwrap();
        drop(spool);
        let spool = Spool::open_with_limit(temp.path(), attempt, 59).unwrap();
        assert!(spool.last_seq() >= 3, "the refused tail vanished");
        assert_eq!(spool.gaps().first().map(|g| g.0), Some(3));
        assert_eq!(spool.gaps().last().map(|g| g.1), Some(spool.last_seq()));
    }

    #[test]
    fn scans_over_a_large_spool_stay_bounded_and_in_order() {
        let temp = tempfile::tempdir().unwrap();
        let attempt = AttemptId::new();
        let kilobyte = vec![b'x'; 1_000];
        let mut spool = Spool::open(temp.path(), attempt).unwrap();
        for _ in 0..200 {
            spool.append(0, Stream::Stdout, &kilobyte).unwrap();
        }
        spool.sync().unwrap();
        drop(spool);

        let mut spool = Spool::open(temp.path(), attempt).unwrap();
        assert_eq!(spool.last_seq(), 200);
        let mut seen = Vec::new();
        loop {
            let batch = spool.send_next(7).unwrap();
            if batch.is_empty() {
                break;
            }
            seen.extend(batch.iter().map(|f| f.seq));
        }
        assert_eq!(seen, (1..=200).collect::<Vec<_>>());
        spool.rewind(150).unwrap();
        let rest = spool.send_next(100).unwrap();
        assert_eq!(
            rest.iter().map(|f| f.seq).collect::<Vec<_>>(),
            (151..=200).collect::<Vec<_>>()
        );
        assert_eq!(spool.unacked(199, 10).unwrap()[0].seq, 200);
    }
}
