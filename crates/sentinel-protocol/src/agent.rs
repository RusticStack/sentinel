//! The worker ↔ guest agent protocol for microVM jobs (plan 16.8, TODO M04).
//!
//! The agent serves several connections at once: the attempt's, and a canceler's that only signals. Every
//! frame is a little-endian `u32` body length followed by a postcard body;
//! bodies are bounded by [`MAX_FRAME`]. The worker sends [`Request`]s, the agent answers with [`Reply`]s.
//! While a command runs the agent keeps reading requests, so [`Request::Signal`] reaches it mid-step, and
//! output frames for that command interleave with the replies to other requests.

use serde::{Deserialize, Serialize};

/// Bumped on any change to these types; the agent states its own in [`Reply::Ready`].
pub const VERSION: u16 = 2;

/// The vsock port the agent listens on.
pub const PORT: u32 = 1024;

/// Upper bound of one frame body; `Data` and `Output` chunks stay well below it.
pub const MAX_FRAME: usize = 1 << 20;

/// Bytes of a data or output chunk.
pub const CHUNK: usize = 256 << 10;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Request {
    /// First frame on a connection.
    Hello {
        version: u16,
    },
    /// A tar stream follows as `Data` frames ended by `End`; the agent unpacks it under `root`, an absolute
    /// guest path it creates, and answers `Done` or `Failed`.
    Put {
        root: String,
    },
    Data(Vec<u8>),
    End,
    /// Packs `paths` (relative to `root`; missing ones are skipped) into a tar stream sent back as `Data`
    /// frames ended by `End`, or `Failed`.
    Get {
        root: String,
        paths: Vec<String>,
    },
    /// Starts a command in its own process group; its output comes as `Output` and its end as `Exited`.
    Exec(Exec),
    /// Signals a running command's process group.
    Signal {
        id: u32,
        signal: i32,
    },
    /// Signals every process except the agent: a cancel's polite stop, then its forced one. Answers `Done`.
    SignalAll {
        signal: i32,
    },
    /// Kills every process except the agent: what earlier steps left running. Answers `Done`.
    KillStrays,
    /// Answers `OomKills` with the guest kernel's OOM-kill count.
    OomKills,
    /// Syncs file systems and powers the guest off; the stream ends.
    Shutdown,
    /// First request to a guest restored from a snapshot (M06): the restored guest knows neither the time that
    /// passed nor that it is not the only copy of the snapshot. The agent credits `entropy` to the kernel's
    /// random pool (bytes the worker drew fresh for this attempt, so no two restores share a random stream),
    /// sets the wall clock to `realtime_ns` nanoseconds since the Unix epoch and answers `Done`.
    Resume {
        entropy: Vec<u8>,
        realtime_ns: u64,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Exec {
    pub id: u32,
    pub argv: Vec<String>,
    /// The whole environment: the agent passes nothing of its own.
    pub env: Vec<(String, String)>,
    /// Absolute guest path.
    pub workdir: String,
    /// The command's root: the job image's file system, entered with `chroot`.
    pub root: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Stream {
    Stdout,
    Stderr,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Reply {
    Ready {
        version: u16,
        kernel: String,
    },
    Done,
    Failed {
        message: String,
    },
    Data(Vec<u8>),
    End,
    Output {
        id: u32,
        stream: Stream,
        bytes: Vec<u8>,
    },
    /// `code` for a normal exit, `signal` when a signal ended it.
    Exited {
        id: u32,
        code: Option<i32>,
        signal: Option<i32>,
    },
    OomKills(u64),
}

#[derive(Debug, PartialEq, Eq)]
pub enum FrameError {
    TooLarge(usize),
    Decode,
    Encode,
}

/// The frame bytes for `message`: length prefix and body.
pub fn encode<T: Serialize>(message: &T) -> Result<Vec<u8>, FrameError> {
    let body = postcard::to_allocvec(message).map_err(|_| FrameError::Encode)?;
    if body.len() > MAX_FRAME {
        return Err(FrameError::TooLarge(body.len()));
    }
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&(body.len() as u32).to_le_bytes());
    out.extend_from_slice(&body);
    Ok(out)
}

/// The body length a prefix announces, refused above [`MAX_FRAME`] before any body is read.
pub fn body_len(prefix: [u8; 4]) -> Result<usize, FrameError> {
    let len = u32::from_le_bytes(prefix) as usize;
    if len > MAX_FRAME {
        return Err(FrameError::TooLarge(len));
    }
    Ok(len)
}

pub fn decode<'a, T: Deserialize<'a>>(body: &'a [u8]) -> Result<T, FrameError> {
    match postcard::take_from_bytes(body) {
        Ok((value, [])) => Ok(value),
        _ => Err(FrameError::Decode),
    }
}

/// Reads one frame from a blocking reader; `Ok(None)` at a clean end of stream.
pub fn read<T: for<'de> Deserialize<'de>>(
    reader: &mut impl std::io::Read,
) -> std::io::Result<Option<T>> {
    let mut prefix = [0u8; 4];
    match reader.read_exact(&mut prefix) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = body_len(prefix).map_err(|e| std::io::Error::other(format!("{e:?}")))?;
    let mut body = vec![0u8; len];
    reader.read_exact(&mut body)?;
    decode(&body)
        .map(Some)
        .map_err(|e| std::io::Error::other(format!("{e:?}")))
}

pub fn write<T: Serialize>(writer: &mut impl std::io::Write, message: &T) -> std::io::Result<()> {
    let frame = encode(message).map_err(|e| std::io::Error::other(format!("{e:?}")))?;
    writer.write_all(&frame)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_round_trip_and_oversized_bodies_are_refused() {
        let exec = Request::Exec(Exec {
            id: 7,
            argv: vec!["/bin/sh".into(), "-c".into(), "echo hi".into()],
            env: vec![("HOME".into(), "/root".into())],
            workdir: "/workspace".into(),
            root: "/job".into(),
        });
        let frame = encode(&exec).unwrap();
        let len = body_len(frame[..4].try_into().unwrap()).unwrap();
        assert_eq!(len, frame.len() - 4);
        assert_eq!(decode::<Request>(&frame[4..]).unwrap(), exec);
        assert_eq!(
            decode::<Request>(&frame[4..frame.len() - 1]),
            Err(FrameError::Decode)
        );
        let too_big = ((MAX_FRAME + 1) as u32).to_le_bytes();
        assert_eq!(body_len(too_big), Err(FrameError::TooLarge(MAX_FRAME + 1)));
        assert!(matches!(
            encode(&Reply::Data(vec![0; MAX_FRAME])),
            Err(FrameError::TooLarge(_))
        ));
        let chunk = encode(&Reply::Data(vec![0; CHUNK])).unwrap();
        assert!(chunk.len() <= MAX_FRAME + 4);
    }

    #[test]
    fn a_resume_request_carries_its_entropy_and_clock() {
        let resume = Request::Resume {
            entropy: vec![7; 64],
            realtime_ns: 1_790_000_000_123_456_789,
        };
        let frame = encode(&resume).unwrap();
        assert_eq!(decode::<Request>(&frame[4..]).unwrap(), resume);
    }

    #[test]
    fn a_stream_of_frames_reads_back_and_ends_cleanly() {
        let mut buf = Vec::new();
        for r in [Reply::Done, Reply::OomKills(3), Reply::End] {
            write(&mut buf, &r).unwrap();
        }
        let mut cursor = std::io::Cursor::new(buf);
        assert_eq!(read::<Reply>(&mut cursor).unwrap(), Some(Reply::Done));
        assert_eq!(
            read::<Reply>(&mut cursor).unwrap(),
            Some(Reply::OomKills(3))
        );
        assert_eq!(read::<Reply>(&mut cursor).unwrap(), Some(Reply::End));
        assert_eq!(read::<Reply>(&mut cursor).unwrap(), None);
    }
}
