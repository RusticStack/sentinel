//! Log frames and the on-disk record they are spooled and stored as (W05).
//!
//! A frame is at most `MAX_LOG_FRAME_BYTES` of one stream of one step,
//! numbered by a per-attempt sequence that starts at 1 and never skips.
//! The same record encoding is used by the worker's spool and the
//! controller's log file, so what was acknowledged is byte-for-byte what
//! was written: `kind u8 | seq u64 | step u32 | stream u8 | len u32 | bytes`
//! for a frame, and `kind u8 | last_seq u64 | gaps u32 | (from u64, to u64)*`
//! for the end marker that makes an attempt's log complete.

use crate::limits::MAX_LOG_FRAME_BYTES;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Stream {
    Stdout = 1,
    Stderr = 2,
}

impl Stream {
    pub const fn from_code(code: u8) -> Option<Stream> {
        match code {
            1 => Some(Stream::Stdout),
            2 => Some(Stream::Stderr),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame {
    pub seq: u64,
    pub step: u32,
    pub stream: Stream,
    pub bytes: Vec<u8>,
}

/// A record in a spool or log file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Record {
    Frame(Frame),
    /// The attempt produced nothing after `last_seq`; `gaps` are ranges the
    /// worker could not deliver (spool loss), reported rather than hidden.
    End {
        last_seq: u64,
        gaps: Vec<(u64, u64)>,
    },
}

const KIND_FRAME: u8 = 1;
const KIND_END: u8 = 2;
pub const FRAME_HEADER_BYTES: usize = 1 + 8 + 4 + 1 + 4;
/// Gap ranges an end record may carry.
pub const MAX_GAPS: usize = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecordError {
    /// The buffer ends inside a record: wait for more, or a torn tail.
    Incomplete,
    /// Not a record: wrong kind, oversized frame, unknown stream.
    Invalid,
}

impl Record {
    /// Append the record's bytes to `out`.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<(), RecordError> {
        match self {
            Record::Frame(frame) => {
                if frame.bytes.len() > MAX_LOG_FRAME_BYTES {
                    return Err(RecordError::Invalid);
                }
                out.reserve(FRAME_HEADER_BYTES + frame.bytes.len());
                out.push(KIND_FRAME);
                out.extend_from_slice(&frame.seq.to_le_bytes());
                out.extend_from_slice(&frame.step.to_le_bytes());
                out.push(frame.stream as u8);
                out.extend_from_slice(&(frame.bytes.len() as u32).to_le_bytes());
                out.extend_from_slice(&frame.bytes);
            }
            Record::End { last_seq, gaps } => {
                if gaps.len() > MAX_GAPS {
                    return Err(RecordError::Invalid);
                }
                out.push(KIND_END);
                out.extend_from_slice(&last_seq.to_le_bytes());
                out.extend_from_slice(&(gaps.len() as u32).to_le_bytes());
                for (from, to) in gaps {
                    out.extend_from_slice(&from.to_le_bytes());
                    out.extend_from_slice(&to.to_le_bytes());
                }
            }
        }
        Ok(())
    }

    /// Decode one record from the front of `bytes`; returns it with the
    /// number of bytes consumed.
    pub fn decode(bytes: &[u8]) -> Result<(Record, usize), RecordError> {
        let kind = *bytes.first().ok_or(RecordError::Incomplete)?;
        match kind {
            KIND_FRAME => {
                if bytes.len() < FRAME_HEADER_BYTES {
                    return Err(RecordError::Incomplete);
                }
                let seq = u64::from_le_bytes(bytes[1..9].try_into().expect("8"));
                let step = u32::from_le_bytes(bytes[9..13].try_into().expect("4"));
                let stream = Stream::from_code(bytes[13]).ok_or(RecordError::Invalid)?;
                let len = u32::from_le_bytes(bytes[14..18].try_into().expect("4")) as usize;
                if len > MAX_LOG_FRAME_BYTES {
                    return Err(RecordError::Invalid);
                }
                let end = FRAME_HEADER_BYTES + len;
                if bytes.len() < end {
                    return Err(RecordError::Incomplete);
                }
                Ok((
                    Record::Frame(Frame {
                        seq,
                        step,
                        stream,
                        bytes: bytes[FRAME_HEADER_BYTES..end].to_vec(),
                    }),
                    end,
                ))
            }
            KIND_END => {
                if bytes.len() < 13 {
                    return Err(RecordError::Incomplete);
                }
                let last_seq = u64::from_le_bytes(bytes[1..9].try_into().expect("8"));
                let count = u32::from_le_bytes(bytes[9..13].try_into().expect("4")) as usize;
                if count > MAX_GAPS {
                    return Err(RecordError::Invalid);
                }
                let end = 13 + count * 16;
                if bytes.len() < end {
                    return Err(RecordError::Incomplete);
                }
                let gaps = (0..count)
                    .map(|i| {
                        let at = 13 + i * 16;
                        (
                            u64::from_le_bytes(bytes[at..at + 8].try_into().expect("8")),
                            u64::from_le_bytes(bytes[at + 8..at + 16].try_into().expect("8")),
                        )
                    })
                    .collect();
                Ok((Record::End { last_seq, gaps }, end))
            }
            _ => Err(RecordError::Invalid),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_round_trip_and_torn_tails_are_incomplete() {
        let frame = Record::Frame(Frame {
            seq: 7,
            step: 2,
            stream: Stream::Stderr,
            bytes: b"hello\n".to_vec(),
        });
        let end = Record::End {
            last_seq: 7,
            gaps: vec![(3, 4)],
        };
        let mut buf = Vec::new();
        frame.encode(&mut buf).unwrap();
        end.encode(&mut buf).unwrap();
        let (a, n) = Record::decode(&buf).unwrap();
        assert_eq!(a, frame);
        let (b, m) = Record::decode(&buf[n..]).unwrap();
        assert_eq!(b, end);
        assert_eq!(n + m, buf.len());
        for cut in 1..buf.len() {
            let head = &buf[..cut];
            match Record::decode(head) {
                Ok((r, used)) => assert!(r == frame && used == n && cut >= n),
                Err(RecordError::Incomplete) => {}
                Err(RecordError::Invalid) => panic!("valid prefix reported invalid at {cut}"),
            }
        }
        assert_eq!(Record::decode(&[9]), Err(RecordError::Invalid));
        let oversized = Record::Frame(Frame {
            seq: 1,
            step: 0,
            stream: Stream::Stdout,
            bytes: vec![0; MAX_LOG_FRAME_BYTES + 1],
        });
        assert_eq!(oversized.encode(&mut Vec::new()), Err(RecordError::Invalid));
    }
}
