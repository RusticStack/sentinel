//! W05 log store behavior: frames are acknowledged only once written and
//! synced, in sequence; a resend is accepted without a second copy; a jump
//! is refused; the end marker completes the log with its gaps; a torn tail
//! from a crash is cut on reopen; the size cap holds.

use sentinel_core::AttemptId;
use sentinel_protocol::logs::{Frame, Stream};
use sentinel_store::{
    Error,
    logs::{Appended, LogStore, read_tail},
};

fn frame(seq: u64, text: &str) -> Frame {
    Frame {
        seq,
        step: 0,
        stream: Stream::Stdout,
        bytes: text.as_bytes().to_vec(),
    }
}

#[test]
fn frames_are_stored_in_sequence_acknowledged_once_durable_and_completed_with_gaps() {
    let temp = tempfile::tempdir().unwrap();
    let logs = LogStore::open(temp.path().join("logs")).unwrap();
    let attempt = AttemptId::new();
    assert!(matches!(logs.tail(attempt, 0, 10), Err(Error::NotFound)));
    assert_eq!(
        logs.append(attempt, &frame(1, "one\n")).unwrap(),
        Appended::Stored { through: 1 }
    );
    // A jump leaves a hole the reader could never explain: refused.
    assert!(matches!(
        logs.append(attempt, &frame(3, "three\n")),
        Err(Error::InvalidInput("log sequence"))
    ));
    assert_eq!(
        logs.append(attempt, &frame(2, "two\n")).unwrap(),
        Appended::Stored { through: 2 }
    );
    // A resend after a lost session is acknowledged and not written twice.
    assert_eq!(
        logs.append(attempt, &frame(1, "one\n")).unwrap(),
        Appended::Duplicate { through: 2 }
    );
    let tail = logs.tail(attempt, 0, 10).unwrap();
    assert_eq!(tail.frames.len(), 2);
    assert!(!tail.complete);
    assert_eq!(logs.tail(attempt, 1, 10).unwrap().frames[0].seq, 2);
    assert_eq!(logs.tail(attempt, 0, 1).unwrap().frames.len(), 1);
    // The end must agree with what was stored.
    assert!(matches!(logs.finish(attempt, 5, &[]), Err(Error::Conflict)));
    logs.finish(attempt, 2, &[(9, 9)]).unwrap();
    let tail = logs.tail(attempt, 0, 10).unwrap();
    assert!(tail.complete);
    assert_eq!(tail.gaps, vec![(9, 9)]);
    // Nothing after the end.
    assert!(matches!(
        logs.append(attempt, &frame(3, "late\n")),
        Err(Error::Conflict)
    ));
    // A second finish is idempotent.
    logs.finish(attempt, 2, &[]).unwrap();

    // Crash mid-write: the torn tail is cut on reopen, the sequence resumes.
    let other = AttemptId::new();
    logs.append(other, &frame(1, "a")).unwrap();
    let path = logs.path(other);
    drop(logs);
    {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        f.write_all(&[1, 2, 0, 0]).unwrap();
    }
    let reopened = LogStore::open(temp.path().join("logs")).unwrap();
    assert_eq!(
        reopened.append(other, &frame(2, "b")).unwrap(),
        Appended::Stored { through: 2 }
    );
    let tail = read_tail(&path, 0, 10).unwrap();
    assert_eq!(
        tail.frames.iter().map(|f| f.seq).collect::<Vec<_>>(),
        vec![1, 2]
    );
}

#[test]
fn an_attempt_log_is_capped() {
    let temp = tempfile::tempdir().unwrap();
    let logs = LogStore::open(temp.path().join("logs")).unwrap();
    let attempt = AttemptId::new();
    let big = Frame {
        seq: 0,
        step: 0,
        stream: Stream::Stderr,
        bytes: vec![b'x'; sentinel_protocol::limits::MAX_LOG_FRAME_BYTES],
    };
    let per_frame = big.bytes.len() as u64 + sentinel_protocol::logs::FRAME_HEADER_BYTES as u64;
    let fits = sentinel_store::logs::MAX_LOG_BYTES / per_frame;
    for seq in 1..=fits {
        let mut f = big.clone();
        f.seq = seq;
        logs.append(attempt, &f).unwrap();
    }
    let mut f = big.clone();
    f.seq = fits + 1;
    assert!(matches!(
        logs.append(attempt, &f),
        Err(Error::InvalidInput("log size"))
    ));
}
