//! D04 log store behavior: frames are acknowledged only once written and
//! synced, in sequence; a resend is accepted without a second copy; a
//! sequence jump records a hole and a resend inside a hole fills it; the
//! end marker completes the log with merged gaps — declared, observed and
//! the never-stored tail; a torn tail is cut on reopen; sealed segments
//! compress in the background; the sparse index seeks tails without
//! re-reading the head; the size cap holds.

use std::time::{Duration, Instant};

use sentinel_core::{AttemptId, JobId, RunId};
use sentinel_protocol::logs::{Frame, Record, Stream};
use sentinel_store::{
    Error,
    logs::{Appended, LogStore, read_dir},
};

fn run() -> RunId {
    RunId::from_bytes([1, 2, 3, 4, 5, 6, 0x40, 7, 0x80, 9, 10, 11, 12, 13, 14, 15]).unwrap()
}
fn job() -> JobId {
    JobId::from_bytes([2, 3, 4, 5, 6, 7, 0x40, 8, 0x80, 10, 11, 12, 13, 14, 15, 16]).unwrap()
}

fn frame(seq: u64, text: &str) -> Frame {
    Frame {
        seq,
        step: 0,
        stream: Stream::Stdout,
        bytes: text.as_bytes().to_vec(),
    }
}

fn at_step(seq: u64, step: u32, text: &str) -> Frame {
    Frame {
        step,
        ..frame(seq, text)
    }
}

fn wait_compressed(dir: &std::path::Path, seg: u32) {
    let done = dir.join(format!("seg-{seg:06}.z"));
    let deadline = Instant::now() + Duration::from_secs(30);
    while !done.exists() {
        assert!(Instant::now() < deadline, "seg-{seg:06} never compressed");
        std::thread::sleep(Duration::from_millis(25));
    }
}

#[test]
fn frames_are_stored_in_sequence_acknowledged_once_durable_and_completed_with_gaps() {
    let temp = tempfile::tempdir().unwrap();
    let logs = LogStore::open(temp.path().join("logs")).unwrap();
    let attempt = AttemptId::new();
    assert!(matches!(
        logs.tail(run(), job(), attempt, 0, 10, None),
        Err(Error::NotFound)
    ));
    assert_eq!(
        logs.append(run(), job(), attempt, &frame(1, "one\n"))
            .unwrap(),
        Appended::Stored { through: 1 }
    );
    // A jump is recorded as a hole, not refused: the frame still lands and
    // the gap shows up for readers and in the end marker.
    assert_eq!(
        logs.append(run(), job(), attempt, &frame(3, "three\n"))
            .unwrap(),
        Appended::Stored { through: 3 }
    );
    assert_eq!(
        logs.append(run(), job(), attempt, &frame(4, "four\n"))
            .unwrap(),
        Appended::Stored { through: 4 }
    );
    // A resend of a stored sequence is acknowledged, not written twice.
    assert_eq!(
        logs.append(run(), job(), attempt, &frame(1, "one\n"))
            .unwrap(),
        Appended::Duplicate { through: 4 }
    );
    // A resend landing inside the hole fills it.
    assert_eq!(
        logs.append(run(), job(), attempt, &frame(2, "two\n"))
            .unwrap(),
        Appended::Stored { through: 4 }
    );
    let tail = logs.tail(run(), job(), attempt, 0, 10, None).unwrap();
    assert_eq!(
        tail.frames.iter().map(|f| f.seq).collect::<Vec<_>>(),
        vec![1, 3, 4, 2]
    );
    assert!(!tail.complete);
    assert!(tail.gaps.is_empty());
    assert_eq!(
        logs.tail(run(), job(), attempt, 1, 10, None)
            .unwrap()
            .frames[0]
            .seq,
        3
    );
    assert_eq!(
        logs.tail(run(), job(), attempt, 0, 1, None)
            .unwrap()
            .frames
            .len(),
        1
    );
    // A last_seq below what was stored is refused; past it is truncation.
    assert!(matches!(
        logs.finish(run(), job(), attempt, 1, &[]),
        Err(Error::Conflict)
    ));
    logs.finish(run(), job(), attempt, 6, &[(9, 9)]).unwrap();
    let tail = logs.tail(run(), job(), attempt, 0, 10, None).unwrap();
    assert!(tail.complete);
    // Declared (9,9) plus the truncated tail 5-6.
    assert_eq!(tail.gaps, vec![(5, 6), (9, 9)]);
    // Nothing after the end.
    assert!(matches!(
        logs.append(run(), job(), attempt, &frame(3, "late\n")),
        Err(Error::Conflict)
    ));
    // A second finish with the same last_seq is idempotent, a different
    // one is refused.
    logs.finish(run(), job(), attempt, 6, &[]).unwrap();
    assert!(matches!(
        logs.finish(run(), job(), attempt, 7, &[]),
        Err(Error::Conflict)
    ));
}

#[test]
fn a_hole_between_stored_frames_is_reported_not_silent() {
    let temp = tempfile::tempdir().unwrap();
    let logs = LogStore::open(temp.path().join("logs")).unwrap();
    let attempt = AttemptId::new();
    logs.append(run(), job(), attempt, &frame(1, "one\n"))
        .unwrap();
    logs.append(run(), job(), attempt, &frame(4, "four\n"))
        .unwrap();
    logs.finish(run(), job(), attempt, 4, &[]).unwrap();
    let tail = logs.tail(run(), job(), attempt, 0, 10, None).unwrap();
    assert!(tail.complete);
    assert_eq!(tail.gaps, vec![(2, 3)]);
}

#[test]
fn torn_tails_are_cut_on_reopen() {
    let temp = tempfile::tempdir().unwrap();
    let logs = LogStore::open(temp.path().join("logs")).unwrap();
    let attempt = AttemptId::new();
    logs.append(run(), job(), attempt, &frame(1, "a")).unwrap();
    logs.append(run(), job(), attempt, &frame(2, "b")).unwrap();
    let dir = logs.attempt_dir(run(), job(), attempt);
    drop(logs);
    {
        // A crash mid-write: a partial record on the segment, a partial
        // entry on the index.
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(dir.join("seg-000000"))
            .unwrap();
        f.write_all(&[1, 2, 0, 0]).unwrap();
        let mut i = std::fs::OpenOptions::new()
            .append(true)
            .open(dir.join("index"))
            .unwrap();
        i.write_all(&[9, 9, 9]).unwrap();
    }
    let reopened = LogStore::open(temp.path().join("logs")).unwrap();
    assert_eq!(
        reopened
            .append(run(), job(), attempt, &frame(3, "c"))
            .unwrap(),
        Appended::Stored { through: 3 }
    );
    let tail = read_dir(&dir, 0, 10, None).unwrap();
    assert_eq!(
        tail.frames.iter().map(|f| f.seq).collect::<Vec<_>>(),
        vec![1, 2, 3]
    );
}

#[test]
fn sealed_segments_compress_and_still_read() {
    let temp = tempfile::tempdir().unwrap();
    let logs = LogStore::open(temp.path().join("logs")).unwrap();
    let attempt = AttemptId::new();
    // 4 MiB of ~32 KiB frames crosses SEGMENT_BYTES: seg 0 seals.
    let text = "x".repeat(32 * 1024 - 18);
    for seq in 1..=140u64 {
        logs.append(run(), job(), attempt, &frame(seq, &text))
            .unwrap();
    }
    let dir = logs.attempt_dir(run(), job(), attempt);
    assert!(dir.join("seg-000001").exists());
    wait_compressed(&dir, 0);
    assert!(!dir.join("seg-000000").exists());
    logs.finish(run(), job(), attempt, 140, &[]).unwrap();
    wait_compressed(&dir, 1);
    // The compressed stream reads identically, seeks included.
    let tail = read_dir(&dir, 0, 300, None).unwrap();
    assert!(tail.complete);
    assert_eq!(tail.frames.len(), 140);
    let tail = read_dir(&dir, 100, 300, None).unwrap();
    assert_eq!(tail.frames[0].seq, 101);
    assert_eq!(tail.frames.len(), 40);
}

#[test]
fn the_sparse_index_carries_step_line_and_time_checkpoints() {
    let temp = tempfile::tempdir().unwrap();
    let logs = LogStore::open(temp.path().join("logs")).unwrap();
    let attempt = AttemptId::new();
    for seq in 1..=10u64 {
        logs.append(run(), job(), attempt, &at_step(seq, 0, "a\nb\n"))
            .unwrap();
    }
    for seq in 11..=20u64 {
        logs.append(run(), job(), attempt, &at_step(seq, 3, "c\n"))
            .unwrap();
    }
    let dir = logs.attempt_dir(run(), job(), attempt);
    let index = std::fs::read(dir.join("index")).unwrap();
    assert_eq!(index[..4], *b"SNLI");
    // Step-0 first frame, the 0→3 step change, line/byte totals grow.
    assert!(index.len() >= 6 + 41 * 2);
    // The step filter serves frames of one step only.
    let tail = read_dir(&dir, 0, 50, Some(3)).unwrap();
    assert_eq!(tail.frames.len(), 10);
    assert!(tail.frames.iter().all(|f| f.step == 3));
    let tail = read_dir(&dir, 5, 50, Some(0)).unwrap();
    assert_eq!(
        tail.frames.iter().map(|f| f.seq).collect::<Vec<_>>(),
        vec![6, 7, 8, 9, 10]
    );
}

#[test]
fn reopen_resumes_the_sequence_and_the_cap() {
    let temp = tempfile::tempdir().unwrap();
    let attempt = AttemptId::new();
    {
        let logs = LogStore::open(temp.path().join("logs")).unwrap();
        logs.append(run(), job(), attempt, &frame(1, "a")).unwrap();
        logs.append(run(), job(), attempt, &frame(4, "d")).unwrap();
    }
    let logs = LogStore::open(temp.path().join("logs")).unwrap();
    // The hole survives reopen; the fill still lands.
    assert_eq!(
        logs.append(run(), job(), attempt, &frame(2, "b")).unwrap(),
        Appended::Stored { through: 4 }
    );
    assert_eq!(
        logs.append(run(), job(), attempt, &frame(5, "e")).unwrap(),
        Appended::Stored { through: 5 }
    );
    logs.finish(run(), job(), attempt, 5, &[]).unwrap();
    let dir = logs.attempt_dir(run(), job(), attempt);
    let tail = read_dir(&dir, 0, 10, None).unwrap();
    assert_eq!(tail.gaps, vec![(3, 3)]);
}

#[test]
fn pre_d04_flat_logs_still_read() {
    let temp = tempfile::tempdir().unwrap();
    let logs = LogStore::open(temp.path().join("logs")).unwrap();
    let attempt = AttemptId::new();
    // A W05-era flat log: frames then the end record, whole-file.
    let mut bytes = Vec::new();
    Record::Frame(frame(1, "old\n")).encode(&mut bytes).unwrap();
    Record::End {
        last_seq: 3,
        gaps: vec![(2, 2)],
    }
    .encode(&mut bytes)
    .unwrap();
    std::fs::write(
        temp.path().join("logs").join(format!("{attempt}.log")),
        &bytes,
    )
    .unwrap();
    let tail = logs.tail_legacy(attempt, 0, 10, None).unwrap();
    assert!(tail.complete);
    assert_eq!(tail.gaps, vec![(2, 2)]);
    assert_eq!(tail.frames.len(), 1);
    assert!(
        logs.tail_legacy(attempt, 0, 10, Some(7))
            .unwrap()
            .frames
            .is_empty()
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
        logs.append(run(), job(), attempt, &f).unwrap();
    }
    let mut f = big.clone();
    f.seq = fits + 1;
    assert!(matches!(
        logs.append(run(), job(), attempt, &f),
        Err(Error::InvalidInput("log size"))
    ));
    // The refused tail still completes: last_seq passes what was stored
    // and lands in the gaps.
    logs.finish(run(), job(), attempt, fits + 1, &[]).unwrap();
    let dir = logs.attempt_dir(run(), job(), attempt);
    let tail = read_dir(&dir, 0, 1, None).unwrap();
    assert!(tail.complete);
    assert_eq!(tail.gaps, vec![(fits + 1, fits + 1)]);
}
