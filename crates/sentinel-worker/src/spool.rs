//! The worker's durable log spool (W05): `<data_dir>/spool/<attempt>/frames`
//! holds every frame until the controller has acknowledged it; `cursor`
//! holds the highest acknowledged sequence.
//!
//! Output goes to disk first and to the link second, so a slow or absent
//! controller costs disk, never memory, and a worker restart resumes from
//! the cursor (W07). The spool is bounded: past `MAX_SPOOL_BYTES` further
//! output is not written, and what could not be written is declared as a
//! gap in the end marker, never dropped in silence — the highest declared
//! sequence is kept in a small `declared` file so the gaps survive a
//! restart. Reading it back is bounded too — scans stream in `SCAN_CHUNK`
//! windows and sends read only what `limit` frames can occupy, so a
//! `MAX_SPOOL_BYTES` spool never becomes `MAX_SPOOL_BYTES` of RAM — and a
//! frame sent the moment it is written is sent from memory, never read back.

use std::{
    collections::VecDeque,
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

use sentinel_core::AttemptId;
use sentinel_protocol::{
    limits::{MAX_LOG_FRAME_BYTES, MAX_UNACKED_LOG_FRAMES},
    logs::{FRAME_HEADER_BYTES, Frame, Record, RecordError, Stream, encode_frame},
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
    /// Ranges never stored (the size cap, a failed write), declared at the
    /// end.
    gaps: Vec<(u64, u64)>,
    /// `(seq, byte offset just after it)` of frames sent since the last
    /// rewind, oldest first: an acknowledgement turns into the offset a
    /// rewind resumes from without scanning the file. Bounded by the send
    /// window.
    marks: VecDeque<(u64, u64)>,
    /// Byte offset just after the acknowledged frame, when known.
    acked_offset: Option<u64>,
    /// The highest declared-gap sequence already on disk in `declared`.
    declared_synced: u64,
    /// Encode scratch, reused by every append.
    scratch: Vec<u8>,
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
        // Sequences skipped between stored frames were declared gaps (the
        // cap, a failed write): recover them from the jumps themselves.
        let mut gaps: Vec<(u64, u64)> = Vec::new();
        let (at, end) = scan(&mut frames, |record, _| {
            if let Record::Frame(f) = record {
                if f.seq > last + 1 {
                    gaps.push((last + 1, f.seq - 1));
                }
                last = f.seq;
            }
            true
        })?;
        if matches!(end, ScanEnd::Invalid) {
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
        // Declared past the last stored frame: a refused tail that must
        // still be declared at the end, however the process ended.
        let declared = read_seq("declared");
        if declared > last {
            gaps.push((last + 1, declared));
        }
        let mut spool = Spool {
            dir,
            frames,
            len: at,
            max,
            // Never reuse a sequence the controller may already hold: one it
            // acknowledged (the frame can be gone from an unsynced tail) or
            // one declared missing.
            next_seq: last.max(acked).max(declared) + 1,
            acked,
            send_offset: 0,
            gaps,
            marks: VecDeque::new(),
            acked_offset: None,
            declared_synced: declared,
            scratch: Vec::new(),
        };
        spool.rewind(acked)?;
        Ok(spool)
    }

    /// Position the send cursor just after `after`: a resend after a lost
    /// session starts from the last acknowledgement.
    ///
    /// Rewinding to the acknowledgement — every reattach, every lost bulk
    /// connection — uses the offset the acknowledgement already named, so
    /// the pipe lock is not held across a scan of a large spool; only an
    /// offset nothing recorded (a reopen, an arbitrary point) is scanned.
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

    /// Whether everything written has been handed to the link: the next
    /// frame appended may then be sent straight from memory.
    pub fn caught_up(&self) -> bool {
        self.send_offset == self.len
    }

    /// The frame just appended (`seq`) was sent from memory: the send
    /// cursor moves past it without reading it back.
    pub fn sent_tail(&mut self, seq: u64) {
        self.send_offset = self.len;
        self.mark(seq, self.len);
    }

    fn mark(&mut self, seq: u64, end: u64) {
        if self.marks.len() >= 4 * MAX_UNACKED_LOG_FRAMES {
            // Far more than the window can have in flight: acks stopped
            // matching sends. Forget the hints; a rewind scans instead.
            self.marks.clear();
            self.acked_offset = None;
        }
        self.marks.push_back((seq, end));
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

    /// Append one chunk of one stream as the next frame, encoded straight
    /// from the borrowed bytes into a reused buffer. Returns its sequence,
    /// or `None` when the spool is full (recorded as a gap). A write that
    /// fails also declares the sequence — it is spent either way — and cuts
    /// the torn tail so later appends stay decodable.
    pub fn append(&mut self, step: u32, stream: Stream, bytes: &[u8]) -> Result<Option<u64>> {
        debug_assert!(bytes.len() <= MAX_LOG_FRAME_BYTES);
        let seq = self.next_seq;
        self.scratch.clear();
        encode_frame(seq, step, stream, bytes, &mut self.scratch)
            .map_err(|_| Error::Workspace("log frame".into()))?;
        self.next_seq += 1;
        let encoded = self.scratch.len() as u64;
        if self.len + encoded > self.max {
            self.declared_gap(seq)?;
            return Ok(None);
        }
        self.frames.seek(SeekFrom::End(0))?;
        if let Err(e) = self.frames.write_all(&self.scratch) {
            let _ = self.frames.set_len(self.len);
            let _ = self.declared_gap(seq);
            return Err(e.into());
        }
        self.len += encoded;
        Ok(Some(seq))
    }

    /// One sequence the spool could not hold, merged into the range list.
    /// A new range is recorded on disk at once (the next sync covers its
    /// growth), so a restart still declares what was never stored.
    fn declared_gap(&mut self, seq: u64) -> Result<()> {
        match self.gaps.last_mut() {
            Some((_, to)) if *to + 1 == seq => *to = seq,
            _ => {
                self.gaps.push((seq, seq));
                self.persist_declared()?;
            }
        }
        Ok(())
    }

    fn persist_declared(&mut self) -> Result<()> {
        let through = self.gaps.last().map_or(0, |g| g.1);
        if through > self.declared_synced {
            fs::write(self.dir.join("declared"), format!("{through}\n"))?;
            self.declared_synced = through;
        }
        Ok(())
    }

    /// Make everything appended (and every gap declared) so far durable.
    pub fn sync(&mut self) -> Result<()> {
        self.persist_declared()?;
        Ok(self.frames.sync_data()?)
    }

    /// The controller acknowledged through `seq`; persisted so a restart
    /// resends only what is still unacknowledged.
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
        // Sequences up to `seq` with no frame of their own (declared gaps)
        // sit at no offset: the last marked frame's end is where the next
        // unacknowledged frame begins. No mark at all: unknown, and the
        // next rewind scans.
        self.acked_offset = end;
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
            let seq = spool.append(0, Stream::Stdout, &[i]).unwrap().unwrap();
            assert_eq!(seq, u64::from(i) + 1);
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
        // A range's growth is durable with the next sync, like the frames.
        spool.sync().unwrap();
        drop(spool);
        // P04-22: a restart keeps the declared tail — a truncated log is
        // never delivered as complete — and never reuses its sequences.
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
        // And a refused tail still cannot wedge later small writes once
        // space frees: the cap is on stored bytes, not on the sequence;
        // the gap stays declared between the stored frames.
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

    /// A frame the controller acknowledged may be gone from an unsynced
    /// tail after a crash; its sequence is never handed out again (the
    /// controller would take the new frame for a duplicate and drop it).
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

    /// Rewinding to the acknowledgement uses the offset the ack named; the
    /// direct-send path moves the cursor without a read.
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
