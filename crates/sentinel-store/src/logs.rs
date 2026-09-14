//! The controller's durable log store (W05): one append-only file per
//! attempt under `<logs>/<attempt>.log`, records as `sentinel-protocol::logs`
//! encodes them.
//!
//! **Acknowledgement boundary.** A frame is acknowledged to the worker only
//! after it has been written *and* `fdatasync`ed here; the worker may then
//! drop it from its spool. Frames arrive in sequence per attempt; a repeat
//! of a stored sequence (a resend after a lost session) is accepted and
//! not written twice, a jump is refused so a gap can never be silent. The
//! end marker makes the log complete; readers report `Incomplete` until it
//! is there and `Gaps` when the worker declared any.

use std::{
    collections::HashMap,
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::Mutex,
};

use sentinel_core::AttemptId;
use sentinel_protocol::logs::{Frame, Record, RecordError};

use crate::{Error, Result};

pub const LOGS_DIR: &str = "logs";
/// Bytes an attempt's log may hold; past it frames are refused as
/// `Publication` failures rather than filling the disk.
pub const MAX_LOG_BYTES: u64 = 256 << 20;

struct Open {
    file: File,
    last_seq: u64,
    len: u64,
    ended: bool,
}

/// Append and read attempt logs. Cheap to share: one mutex over the open
/// writers, one file per attempt.
pub struct LogStore {
    dir: PathBuf,
    open: Mutex<HashMap<AttemptId, Open>>,
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
        Ok(LogStore {
            dir,
            open: Mutex::new(HashMap::new()),
        })
    }

    pub fn path(&self, attempt: AttemptId) -> PathBuf {
        self.dir.join(format!("{attempt}.log"))
    }

    /// Open (or reopen after a restart, scanning to the last complete
    /// record) the attempt's file.
    fn writer<'a>(
        &self,
        open: &'a mut HashMap<AttemptId, Open>,
        attempt: AttemptId,
    ) -> Result<&'a mut Open> {
        match open.entry(attempt) {
            std::collections::hash_map::Entry::Occupied(e) => Ok(e.into_mut()),
            std::collections::hash_map::Entry::Vacant(v) => {
                let path = self.dir.join(format!("{attempt}.log"));
                // Read/write rather than append: the torn tail of a crash is cut
                // on open, which an append-only handle refuses on some
                // platforms; every write seeks to the end first.
                let mut file = OpenOptions::new()
                    .create(true)
                    .write(true)
                    .read(true)
                    .truncate(false)
                    .open(&path)?;
                let (last_seq, len, ended) = scan(&mut file)?;
                file.set_len(len)?;
                file.seek(SeekFrom::End(0))?;
                Ok(v.insert(Open {
                    file,
                    last_seq,
                    len,
                    ended,
                }))
            }
        }
    }

    /// Append one frame: in sequence, synced, then acknowledged.
    pub fn append(&self, attempt: AttemptId, frame: &Frame) -> Result<Appended> {
        let mut open = self.open.lock().unwrap_or_else(|p| p.into_inner());
        let w = self.writer(&mut open, attempt)?;
        if w.ended {
            return Err(Error::Conflict);
        }
        if frame.seq <= w.last_seq {
            return Ok(Appended::Duplicate {
                through: w.last_seq,
            });
        }
        if frame.seq != w.last_seq + 1 {
            return Err(Error::InvalidInput("log sequence"));
        }
        let mut bytes = Vec::new();
        Record::Frame(frame.clone())
            .encode(&mut bytes)
            .map_err(|_| Error::InvalidInput("log frame"))?;
        if w.len + bytes.len() as u64 > MAX_LOG_BYTES {
            return Err(Error::InvalidInput("log size"));
        }
        w.file.seek(SeekFrom::End(0))?;
        w.file.write_all(&bytes)?;
        w.file.sync_data()?;
        w.len += bytes.len() as u64;
        w.last_seq = frame.seq;
        Ok(Appended::Stored { through: frame.seq })
    }

    /// The worker will send nothing more: write the end marker and close.
    /// `last_seq` must be what was stored, or the worker's claim is refused.
    pub fn finish(&self, attempt: AttemptId, last_seq: u64, gaps: &[(u64, u64)]) -> Result<()> {
        let mut open = self.open.lock().unwrap_or_else(|p| p.into_inner());
        let w = self.writer(&mut open, attempt)?;
        if w.ended {
            return Ok(());
        }
        if last_seq != w.last_seq {
            return Err(Error::Conflict);
        }
        let mut bytes = Vec::new();
        Record::End {
            last_seq,
            gaps: gaps.to_vec(),
        }
        .encode(&mut bytes)
        .map_err(|_| Error::InvalidInput("log end"))?;
        w.file.seek(SeekFrom::End(0))?;
        w.file.write_all(&bytes)?;
        w.file.sync_data()?;
        w.ended = true;
        open.remove(&attempt);
        Ok(())
    }

    /// Read records with sequence greater than `after`, at most `limit`
    /// frames, and whether the log is complete. Reads the file as it is
    /// on disk, so a follower sees exactly what was acknowledged.
    pub fn tail(&self, attempt: AttemptId, after: u64, limit: usize) -> Result<Tail> {
        read_tail(&self.path(attempt), after, limit)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tail {
    pub frames: Vec<Frame>,
    pub complete: bool,
    pub gaps: Vec<(u64, u64)>,
}

/// Scan a log file: last frame sequence, length of the complete prefix,
/// and whether the end marker is present. A torn tail (a crash mid-write)
/// is cut off, never read as data.
fn scan(file: &mut File) -> Result<(u64, u64, bool)> {
    let mut bytes = Vec::new();
    file.seek(SeekFrom::Start(0))?;
    file.read_to_end(&mut bytes)?;
    let (mut at, mut last_seq, mut ended) = (0usize, 0u64, false);
    while at < bytes.len() {
        match Record::decode(&bytes[at..]) {
            Ok((Record::Frame(f), used)) => {
                last_seq = f.seq;
                at += used;
            }
            Ok((Record::End { .. }, used)) => {
                ended = true;
                at += used;
                break;
            }
            Err(RecordError::Incomplete) => break,
            Err(RecordError::Invalid) => return Err(Error::Corrupt("log record")),
        }
    }
    Ok((last_seq, at as u64, ended))
}

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
