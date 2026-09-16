//! The worker's durable log spool (W05): `<data_dir>/spool/<attempt>/frames`
//! holds every frame until the controller has acknowledged it; `cursor`
//! holds the highest acknowledged sequence.
//!
//! Output goes to disk first and to the link second, so a slow or absent
//! controller costs disk, never memory, and a worker restart resumes from
//! the cursor (W07). The spool is bounded: past `MAX_SPOOL_BYTES` the step
//! fails as `Publication` rather than filling the disk, and what could not
//! be written is declared as a gap in the end marker, never dropped in
//! silence. Reading it back is bounded too — scans stream in `SCAN_CHUNK`
//! windows and sends read only what `limit` frames can occupy, so a
//! `MAX_SPOOL_BYTES` spool never becomes `MAX_SPOOL_BYTES` of RAM.

use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

use sentinel_core::AttemptId;
use sentinel_protocol::{
    limits::MAX_LOG_FRAME_BYTES,
    logs::{FRAME_HEADER_BYTES, Frame, Record, RecordError, Stream},
};

use crate::{Error, Result};

pub const SPOOL_DIR: &str = "spool";
/// Bytes one attempt may spool; an attempt producing more has a log
/// problem that must surface, not a disk to consume.
pub const MAX_SPOOL_BYTES: u64 = 256 << 20;
/// One read of a spool scan: bounded memory however long the file.
const SCAN_CHUNK: usize = 64 << 10;
/// The largest record that can appear: a frame header plus a full frame.
const MAX_RECORD: u64 = (FRAME_HEADER_BYTES + MAX_LOG_FRAME_BYTES) as u64;

/// How a spool scan ended.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ScanEnd {
    /// Every byte decoded, or the caller's predicate stopped early.
    Clean,
    /// The file ends inside a record — a torn tail from a crash.
    Torn,
    /// A record that does not decode at all.
    Invalid,
}

/// Feed `each` every complete record with its byte offset until it returns
/// false or the file ends. Returns the consumed length and how the scan
/// ended; reads never exceed `SCAN_CHUNK` plus one record.
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
            Err(RecordError::Invalid) => return Ok((at, ScanEnd::Invalid)),
        }
    }
}

pub struct Spool {
    dir: PathBuf,
    frames: File,
    len: u64,
    /// The spool cap — `MAX_SPOOL_BYTES` normally, lower under
    /// `open_with_limit`.
    max: u64,
    next_seq: u64,
    acked: u64,
    /// Byte offset of the next frame to send, so sending is one sequential
    /// read of the file however large the log grows.
    send_offset: u64,
    /// Ranges refused for size, declared at the end.
    gaps: Vec<(u64, u64)>,
}

impl Spool {
    /// Create the attempt's spool, or reopen it after a restart with the
    /// cursor and every complete record intact.
    pub fn open(root: &Path, attempt: AttemptId) -> Result<Spool> {
        Self::open_with_limit(root, attempt, MAX_SPOOL_BYTES)
    }

    /// `open` under a caller-set cap — the same durability contract where
    /// the default is too generous (and for tests).
    pub fn open_with_limit(root: &Path, attempt: AttemptId, max: u64) -> Result<Spool> {
        let dir = root.join(SPOOL_DIR).join(attempt.to_string());
        fs::create_dir_all(&dir)?;
        // Read/write rather than append: a torn tail is truncated on open,
        // which an append-only handle refuses on some platforms; every
        // write seeks to the end first.
        let mut frames = OpenOptions::new()
            .create(true)
            .write(true)
            .read(true)
            .truncate(false)
            .open(dir.join("frames"))?;
        frames.seek(SeekFrom::Start(0))?;
        let mut last = 0u64;
        let (at, end) = scan(&mut frames, |record, _| {
            if let Record::Frame(f) = record {
                last = f.seq;
            }
            true
        })?;
        if matches!(end, ScanEnd::Invalid) {
            return Err(Error::Workspace("spool corrupt".into()));
        }
        frames.set_len(at)?;
        frames.seek(SeekFrom::End(0))?;
        let acked = fs::read_to_string(dir.join("cursor"))
            .ok()
            .and_then(|t| t.trim().parse().ok())
            .unwrap_or(0);
        let mut spool = Spool {
            dir,
            frames,
            len: at,
            max,
            next_seq: last + 1,
            acked,
            send_offset: 0,
            gaps: Vec::new(),
        };
        spool.rewind(acked)?;
        Ok(spool)
    }

    /// Position the send cursor just after `after`: a resend after a lost
    /// session starts from the last acknowledgement.
    pub fn rewind(&mut self, after: u64) -> Result<()> {
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
        self.frames.seek(SeekFrom::End(0))?;
        Ok(())
    }

    /// The next `limit` frames from the send cursor, advancing it. The
    /// read is bounded by what `limit` records can occupy, not by how much
    /// of the spool is still unsent.
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
                    out.push(f);
                }
                Ok((_, used)) => at += used,
                Err(_) => break,
            }
        }
        self.send_offset += at as u64;
        Ok(out)
    }

    /// Append one chunk of one stream as the next frame. Returns the frame
    /// as written, or `None` when the spool is full (recorded as a gap).
    /// A write that fails also declares the sequence — it is spent either
    /// way — and cuts the torn tail so later appends stay decodable.
    pub fn append(&mut self, step: u32, stream: Stream, bytes: &[u8]) -> Result<Option<Frame>> {
        debug_assert!(bytes.len() <= MAX_LOG_FRAME_BYTES);
        let frame = Frame {
            seq: self.next_seq,
            step,
            stream,
            bytes: bytes.to_vec(),
        };
        let mut encoded = Vec::with_capacity(bytes.len() + 32);
        Record::Frame(frame.clone())
            .encode(&mut encoded)
            .map_err(|_| Error::Workspace("log frame".into()))?;
        self.next_seq += 1;
        if self.len + encoded.len() as u64 > self.max {
            self.declared_gap(frame.seq);
            return Ok(None);
        }
        self.frames.seek(SeekFrom::End(0))?;
        if let Err(e) = self.frames.write_all(&encoded) {
            let _ = self.frames.set_len(self.len);
            self.declared_gap(frame.seq);
            return Err(e.into());
        }
        self.len += encoded.len() as u64;
        Ok(Some(frame))
    }

    /// One sequence the spool could not hold, merged into the range list.
    fn declared_gap(&mut self, seq: u64) {
        match self.gaps.last_mut() {
            Some((_, to)) if *to + 1 == seq => *to = seq,
            _ => self.gaps.push((seq, seq)),
        }
    }

    /// Make everything appended so far durable.
    pub fn sync(&mut self) -> Result<()> {
        Ok(self.frames.sync_data()?)
    }

    /// The controller acknowledged through `seq`; persisted so a restart
    /// resends only what is still unacknowledged.
    pub fn acknowledged(&mut self, seq: u64) -> Result<()> {
        if seq <= self.acked {
            return Ok(());
        }
        self.acked = seq;
        fs::write(self.dir.join("cursor"), format!("{seq}\n"))?;
        Ok(())
    }

    pub fn acked(&self) -> u64 {
        self.acked
    }

    /// The last sequence written or declared.
    pub fn last_seq(&self) -> u64 {
        self.next_seq - 1
    }

    pub fn gaps(&self) -> &[(u64, u64)] {
        &self.gaps
    }

    /// Frames with sequence in `(after, after + limit]`, from disk.
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

    /// Everything acknowledged and the end delivered: nothing to keep.
    pub fn remove(self) -> Result<()> {
        let dir = self.dir.clone();
        drop(self);
        match fs::remove_dir_all(&dir) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    /// Attempts with a spool on disk, for W07.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_spool_survives_reopening_and_resends_only_what_is_unacknowledged() {
        let temp = tempfile::tempdir().unwrap();
        let attempt = AttemptId::new();
        let mut spool = Spool::open(temp.path(), attempt).unwrap();
        for i in 0..5u8 {
            let frame = spool.append(0, Stream::Stdout, &[i]).unwrap().unwrap();
            assert_eq!(frame.seq, u64::from(i) + 1);
        }
        spool.sync().unwrap();
        spool.acknowledged(2).unwrap();
        spool.acknowledged(1).unwrap(); // never backwards
        assert_eq!(spool.acked(), 2);
        drop(spool);
        // A torn tail: half a record after the last complete one.
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
        // The send cursor resumes after the acknowledgement, in bounded reads.
        let batch = spool.send_next(2).unwrap();
        assert_eq!(batch.iter().map(|f| f.seq).collect::<Vec<_>>(), vec![3, 4]);
        // Continues the sequence after the reopen; the cursor sees it too.
        assert_eq!(
            spool.append(1, Stream::Stderr, b"x").unwrap().unwrap().seq,
            6
        );
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
        // Two 20-byte records fit under the cap; every later append is a
        // declared gap, and its sequence is spent either way.
        let mut spool = Spool::open_with_limit(temp.path(), attempt, 59).unwrap();
        assert!(spool.append(0, Stream::Stdout, b"aa").unwrap().is_some());
        assert!(spool.append(0, Stream::Stdout, b"bb").unwrap().is_some());
        assert!(spool.append(0, Stream::Stdout, b"cc").unwrap().is_none());
        assert!(spool.append(1, Stream::Stderr, b"dd").unwrap().is_none());
        assert_eq!(spool.gaps(), &[(3, 4)]);
        // The refused sequences are gone for good — resends and the end
        // marker both tell the truth about what the spool holds.
        assert_eq!(spool.last_seq(), 4);
        assert_eq!(spool.unacked(0, 10).unwrap().len(), 2);
        let mut reopened = Spool::open_with_limit(temp.path(), attempt, 59).unwrap();
        assert_eq!(
            reopened
                .send_next(10)
                .unwrap()
                .iter()
                .map(|f| f.seq)
                .collect::<Vec<_>>(),
            vec![1, 2]
        );
        // And a refused tail still cannot wedge later small writes once
        // space frees: the cap is on stored bytes, not on the sequence.
        let mut spool = Spool::open_with_limit(temp.path(), attempt, 59).unwrap();
        assert!(spool.append(0, Stream::Stdout, b"ee").unwrap().is_none());
        let mut spool = Spool::open_with_limit(temp.path(), attempt, 60).unwrap();
        assert!(spool.append(0, Stream::Stdout, b"ee").unwrap().is_some());
    }

    #[test]
    fn scans_over_a_large_spool_stay_bounded_and_in_order() {
        let temp = tempfile::tempdir().unwrap();
        let attempt = AttemptId::new();
        let kilobyte = vec![b'x'; 1_000];
        let mut spool = Spool::open(temp.path(), attempt).unwrap();
        // ~205 KiB of frames: every scan crosses the 64 KiB read window.
        for _ in 0..200 {
            spool.append(0, Stream::Stdout, &kilobyte).unwrap();
        }
        spool.sync().unwrap();
        drop(spool);

        let mut spool = Spool::open(temp.path(), attempt).unwrap();
        assert_eq!(spool.last_seq(), 200);
        // `send_next` pages by its limit, never by what is left in the file.
        let mut seen = Vec::new();
        loop {
            let batch = spool.send_next(7).unwrap();
            if batch.is_empty() {
                break;
            }
            seen.extend(batch.iter().map(|f| f.seq));
        }
        assert_eq!(seen, (1..=200).collect::<Vec<_>>());
        // `rewind` lands mid-file and `unacked` walks the same records.
        spool.rewind(150).unwrap();
        let rest = spool.send_next(100).unwrap();
        assert_eq!(
            rest.iter().map(|f| f.seq).collect::<Vec<_>>(),
            (151..=200).collect::<Vec<_>>()
        );
        assert_eq!(spool.unacked(199, 10).unwrap()[0].seq, 200);
    }
}
