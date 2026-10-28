use std::time::{Duration, Instant};

use sentinel_core::{AttemptId, JobId, RunId, UnixMillis};
use sentinel_protocol::logs::{Frame, Record, Stream};
use sentinel_store::{
    Error,
    logs::{Appended, LineSeek, LogStore, TimeSeek, read_dir, seek_line, seek_time},
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
    let plain = dir.join(format!("seg-{seg:06}"));
    let deadline = Instant::now() + Duration::from_secs(30);
    // Waiting for `.z` alone races the unlink of the plain segment.
    while !done.exists() || plain.exists() {
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
    assert_eq!(
        logs.append(run(), job(), attempt, &frame(1, "one\n"))
            .unwrap(),
        Appended::Duplicate { through: 4 }
    );
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
    assert!(matches!(
        logs.finish(run(), job(), attempt, 1, &[]),
        Err(Error::Conflict)
    ));
    logs.finish(run(), job(), attempt, 6, &[(9, 9)]).unwrap();
    let tail = logs.tail(run(), job(), attempt, 0, 10, None).unwrap();
    assert!(tail.complete);
    assert_eq!(tail.gaps, vec![(5, 6), (9, 9)]);
    assert!(matches!(
        logs.append(run(), job(), attempt, &frame(3, "late\n")),
        Err(Error::Conflict)
    ));
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

/// A zeroed tail from a power cut is cut like a torn record; other garbage is corrupt.
#[test]
fn a_zeroed_tail_from_a_power_cut_is_cut_but_garbage_is_corrupt() {
    let temp = tempfile::tempdir().unwrap();
    let logs = LogStore::open(temp.path().join("logs")).unwrap();
    let (zeroed, garbled) = (AttemptId::new(), AttemptId::new());
    for attempt in [zeroed, garbled] {
        logs.append(run(), job(), attempt, &frame(1, "a")).unwrap();
        logs.append(run(), job(), attempt, &frame(2, "b")).unwrap();
    }
    drop(logs);
    let append = |attempt: AttemptId, bytes: &[u8]| {
        use std::io::Write;
        std::fs::OpenOptions::new()
            .append(true)
            .open(
                temp.path()
                    .join("logs")
                    .join(run().to_string())
                    .join(job().to_string())
                    .join(attempt.to_string())
                    .join("seg-000000"),
            )
            .unwrap()
            .write_all(bytes)
            .unwrap();
    };
    append(zeroed, &[0; 4096]);
    append(garbled, &[7; 64]);
    let reopened = LogStore::open(temp.path().join("logs")).unwrap();
    let dir = reopened.attempt_dir(run(), job(), zeroed);
    assert_eq!(read_dir(&dir, 0, 10, None).unwrap().frames.len(), 2);
    assert_eq!(
        reopened
            .append(run(), job(), zeroed, &frame(3, "c"))
            .unwrap(),
        Appended::Stored { through: 3 }
    );
    assert_eq!(
        read_dir(&dir, 0, 10, None)
            .unwrap()
            .frames
            .iter()
            .map(|f| f.seq)
            .collect::<Vec<_>>(),
        vec![1, 2, 3]
    );
    assert!(matches!(
        reopened.append(run(), job(), garbled, &frame(3, "c")),
        Err(Error::Corrupt(_))
    ));
}

#[test]
fn sealed_segments_compress_and_still_read() {
    let temp = tempfile::tempdir().unwrap();
    let logs = LogStore::open(temp.path().join("logs")).unwrap();
    let attempt = AttemptId::new();
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
    assert!(index.len() >= 6 + 41 * 2);
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
    logs.finish(run(), job(), attempt, fits + 1, &[]).unwrap();
    let dir = logs.attempt_dir(run(), job(), attempt);
    let tail = read_dir(&dir, 0, 1, None).unwrap();
    assert!(tail.complete);
    assert_eq!(tail.gaps, vec![(fits + 1, fits + 1)]);
}

#[test]
fn a_hole_in_a_sealed_segment_survives_a_reopen() {
    let full = "x".repeat(32 * 1024 - 18);
    for fill in [true, false] {
        let temp = tempfile::tempdir().unwrap();
        let attempt = AttemptId::new();
        {
            let logs = LogStore::open(temp.path().join("logs")).unwrap();
            logs.append(run(), job(), attempt, &frame(1, "one"))
                .unwrap();
            for seq in 3..=140u64 {
                logs.append(run(), job(), attempt, &frame(seq, &full))
                    .unwrap();
            }
        }
        let logs = LogStore::open(temp.path().join("logs")).unwrap();
        let dir = logs.attempt_dir(run(), job(), attempt);
        assert_eq!(read_dir(&dir, 139, 10, None).unwrap().gaps, vec![(2, 2)]);
        if fill {
            assert_eq!(
                logs.append(run(), job(), attempt, &frame(2, "two"))
                    .unwrap(),
                Appended::Stored { through: 140 }
            );
        }
        logs.finish(run(), job(), attempt, 140, &[]).unwrap();
        let tail = read_dir(&dir, 139, 10, None).unwrap();
        let whole = read_dir(&dir, 0, 1000, None).unwrap();
        if fill {
            assert!(tail.gaps.is_empty(), "{:?}", tail.gaps);
            assert!(whole.frames.iter().any(|f| f.seq == 2));
        } else {
            assert_eq!(tail.gaps, vec![(2, 2)], "the marker lost the hole");
        }
    }
}

#[test]
fn idle_writers_close_are_capped_and_their_logs_expire() {
    let temp = tempfile::tempdir().unwrap();
    let logs = LogStore::open(temp.path().join("logs"))
        .unwrap()
        .with_max_open(4);
    let attempts: Vec<AttemptId> = (0..10).map(|_| AttemptId::new()).collect();
    for attempt in &attempts {
        logs.append(run(), job(), *attempt, &frame(1, "a")).unwrap();
    }
    assert_eq!(logs.open_writers(), 4, "the writer cap did not hold");
    assert_eq!(logs.close_idle(Duration::ZERO), 4);
    assert_eq!(logs.open_writers(), 0);
    assert_eq!(
        logs.append(run(), job(), attempts[0], &frame(2, "b"))
            .unwrap(),
        Appended::Stored { through: 2 }
    );
    logs.close_idle(Duration::ZERO);
    assert_eq!(logs.sweep_dirs(256, |_| true).unwrap(), 10);
}

#[test]
fn pages_are_bounded_and_a_finished_step_is_reported() {
    use sentinel_store::logs::{Page, read_page};
    let temp = tempfile::tempdir().unwrap();
    let logs = LogStore::open(temp.path().join("logs")).unwrap();
    let attempt = AttemptId::new();
    let full = "y".repeat(32 * 1024);
    for seq in 1..=40u64 {
        logs.append(run(), job(), attempt, &at_step(seq, 0, &full))
            .unwrap();
    }
    for seq in 41..=80u64 {
        logs.append(run(), job(), attempt, &at_step(seq, 1, "later\n"))
            .unwrap();
    }
    let dir = logs.attempt_dir(run(), job(), attempt);
    let page = Page {
        limit: 500,
        bytes: 1 << 20,
        scan: 16 << 20,
    };
    let mut after = 0;
    let mut seen = Vec::new();
    loop {
        let tail = read_page(&dir, after, page, None).unwrap();
        let bytes: usize = tail.frames.iter().map(|f| f.bytes.len()).sum();
        assert!(bytes <= 1 << 20, "a page carried {bytes} bytes");
        seen.extend(tail.frames.iter().map(|f| f.seq));
        match tail.next_after {
            Some(next) => after = next,
            None => break,
        }
    }
    assert_eq!(seen, (1..=80).collect::<Vec<_>>());
    let step0 = read_page(&dir, 40, page, Some(0)).unwrap();
    assert!(step0.frames.is_empty() && step0.step_done);
    assert!(!read_page(&dir, 79, page, Some(1)).unwrap().step_done);
    let small = Page {
        scan: 64 * 1024,
        ..page
    };
    let cut = read_page(&dir, 0, small, Some(7)).unwrap();
    assert!(cut.frames.is_empty());
    assert!(
        cut.next_after.is_some_and(|n| n < 80),
        "{:?}",
        cut.next_after
    );
}

#[test]
fn the_newest_page_of_a_step_ignores_later_steps_and_reaches_the_real_end() {
    use sentinel_store::logs::Page;
    let temp = tempfile::tempdir().unwrap();
    let attempt = AttemptId::new();
    let page = Page {
        limit: 128,
        bytes: 4 << 20,
        scan: 16 << 20,
    };
    {
        let logs = LogStore::open(temp.path().join("logs")).unwrap();
        for seq in 1..=200u64 {
            let text = format!("fail {seq}\n");
            logs.append(run(), job(), attempt, &at_step(seq, 0, &text))
                .unwrap();
        }
        for seq in 201..=400u64 {
            logs.append(run(), job(), attempt, &at_step(seq, 1, "cleanup\n"))
                .unwrap();
        }
        let failed = logs
            .newest_page(run(), job(), attempt, page, Some(0))
            .unwrap();
        assert_eq!(
            failed.frames.iter().map(|f| f.seq).collect::<Vec<_>>(),
            (73..=200).collect::<Vec<_>>()
        );
        assert!(failed.step_done && failed.next_after.is_none());
        for seq in 401..=430u64 {
            logs.append(run(), job(), attempt, &at_step(seq, 1, "late\n"))
                .unwrap();
        }
    }
    let logs = LogStore::open(temp.path().join("logs")).unwrap();
    assert_eq!(logs.last_seq(run(), job(), attempt).unwrap(), Some(430));
    let newest = logs
        .newest_page(run(), job(), attempt, Page { limit: 5, ..page }, None)
        .unwrap();
    assert_eq!(
        newest.frames.iter().map(|f| f.seq).collect::<Vec<_>>(),
        (426..=430).collect::<Vec<_>>()
    );
    assert!(!newest.complete);
    let never = logs
        .newest_page(run(), job(), attempt, page, Some(7))
        .unwrap();
    assert!(never.frames.is_empty());
}

#[test]
fn the_newest_page_holds_at_most_its_byte_bound_of_the_newest_frames() {
    use sentinel_store::logs::Page;
    let temp = tempfile::tempdir().unwrap();
    let logs = LogStore::open(temp.path().join("logs")).unwrap();
    let attempt = AttemptId::new();
    let full = "z".repeat(32 * 1024);
    for seq in 1..=400u64 {
        logs.append(run(), job(), attempt, &frame(seq, &full))
            .unwrap();
    }
    logs.finish(run(), job(), attempt, 400, &[]).unwrap();
    let tail = logs
        .newest_page(
            run(),
            job(),
            attempt,
            Page {
                limit: 1_024,
                bytes: 1 << 20,
                scan: 16 << 20,
            },
            Some(0),
        )
        .unwrap();
    assert_eq!(
        tail.frames.iter().map(|f| f.seq).collect::<Vec<_>>(),
        (369..=400).collect::<Vec<_>>()
    );
    assert!(tail.complete && tail.next_after.is_none());
}

#[test]
fn deferred_frames_are_readable_and_a_window_syncs_once_before_it_is_acknowledged() {
    let temp = tempfile::tempdir().unwrap();
    let logs = LogStore::open(temp.path().join("logs")).unwrap();
    let attempt = AttemptId::new();
    assert!(matches!(logs.sync(attempt), Err(Error::Conflict)));
    for seq in 1..=5 {
        assert_eq!(
            logs.append_deferred(
                run(),
                job(),
                attempt,
                &frame(
                    seq, "x
"
                )
            )
            .unwrap(),
            Appended::Stored { through: seq }
        );
    }
    let tail = logs.tail(run(), job(), attempt, 0, 10, None).unwrap();
    assert_eq!(tail.frames.len(), 5);
    logs.sync(attempt).unwrap();
    logs.sync(attempt).unwrap();
    logs.finish(run(), job(), attempt, 5, &[]).unwrap();
    let dir = logs.attempt_dir(run(), job(), attempt);
    assert_eq!(read_dir(&dir, 0, 10, None).unwrap().frames.len(), 5);
}

#[test]
fn a_deferred_hole_fill_is_on_disk_before_the_hole_is_recorded_closed() {
    let temp = tempfile::tempdir().unwrap();
    let attempt = AttemptId::new();
    {
        let logs = LogStore::open(temp.path().join("logs")).unwrap();
        for (seq, text, through) in [(1, "a\n", 1), (3, "c\n", 3), (2, "b\n", 3)] {
            assert_eq!(
                logs.append_deferred(run(), job(), attempt, &frame(seq, text))
                    .unwrap(),
                Appended::Stored { through }
            );
        }
    }
    let logs = LogStore::open(temp.path().join("logs")).unwrap();
    let tail = logs.tail(run(), job(), attempt, 0, 10, None).unwrap();
    let mut seqs = tail.frames.iter().map(|f| f.seq).collect::<Vec<_>>();
    seqs.sort_unstable();
    assert_eq!(seqs, vec![1, 2, 3]);
    assert_eq!(
        logs.append_deferred(run(), job(), attempt, &frame(2, "b\n"))
            .unwrap(),
        Appended::Duplicate { through: 3 }
    );
}

#[test]
fn a_resent_deferred_frame_is_a_duplicate_and_a_reopen_keeps_what_was_written() {
    let temp = tempfile::tempdir().unwrap();
    let attempt = AttemptId::new();
    {
        let logs = LogStore::open(temp.path().join("logs")).unwrap();
        logs.append_deferred(
            run(),
            job(),
            attempt,
            &frame(
                1, "a
",
            ),
        )
        .unwrap();
        logs.append_deferred(
            run(),
            job(),
            attempt,
            &frame(
                2, "b
",
            ),
        )
        .unwrap();
        assert_eq!(
            logs.append_deferred(
                run(),
                job(),
                attempt,
                &frame(
                    1, "a
"
                )
            )
            .unwrap(),
            Appended::Duplicate { through: 2 }
        );
    }
    let logs = LogStore::open(temp.path().join("logs")).unwrap();
    assert_eq!(
        logs.append(
            run(),
            job(),
            attempt,
            &frame(
                2, "b
"
            )
        )
        .unwrap(),
        Appended::Duplicate { through: 2 }
    );
    assert_eq!(
        logs.append_deferred(
            run(),
            job(),
            attempt,
            &frame(
                3, "c
"
            )
        )
        .unwrap(),
        Appended::Stored { through: 3 }
    );
}

/// The index entry layout: a 6-byte header, then 41-byte entries (`kind`, `seq`, `seg`, `step`, `line`, `bytes`, `ms`).
fn index_entries(dir: &std::path::Path) -> Vec<Vec<u8>> {
    std::fs::read(dir.join("index")).unwrap()[6..]
        .chunks_exact(41)
        .map(<[u8]>::to_vec)
        .collect()
}

fn write_index(dir: &std::path::Path, entries: &[Vec<u8>]) {
    let mut bytes = std::fs::read(dir.join("index")).unwrap()[..6].to_vec();
    entries.iter().for_each(|e| bytes.extend_from_slice(e));
    std::fs::write(dir.join("index"), bytes).unwrap();
}

fn found(after: u64) -> impl Fn(LineSeek) -> bool {
    move |seek| seek.found && seek.after == after
}

#[test]
fn a_line_is_found_in_the_frame_holding_its_first_byte() {
    let temp = tempfile::tempdir().unwrap();
    let logs = LogStore::open(temp.path().join("logs")).unwrap();
    let attempt = AttemptId::new();
    // "abc\ndef\ng\nh": a line split across frames, newlines ending a frame, a last line without one.
    for (seq, text) in [(1, "ab"), (2, "c\nde"), (3, "f\n"), (4, "g\n"), (5, "h")] {
        logs.append(run(), job(), attempt, &frame(seq, text))
            .unwrap();
    }
    let at = |line| logs.seek_line(run(), job(), attempt, line).unwrap();
    assert!(found(0)(at(1)));
    assert!(found(1)(at(2)));
    // Line 3 ("g") starts after the newline that closes frame 3, so in frame 4.
    assert!(found(3)(at(3)));
    assert!(found(4)(at(4)));
    let beyond = at(5);
    assert!(!beyond.found);
    assert_eq!(beyond.after, 5);
    assert!(beyond.exact);
    assert!(!beyond.complete);
    assert!(matches!(
        logs.seek_line(run(), job(), attempt, 0),
        Err(Error::InvalidInput(_))
    ));
    logs.finish(run(), job(), attempt, 5, &[]).unwrap();
    let ended = at(5);
    assert!(!ended.found && ended.complete);
    // The cursor is the ordinary sequence cursor: reading after it starts at the line.
    let dir = logs.attempt_dir(run(), job(), attempt);
    let tail = read_dir(&dir, at(3).after, 10, None).unwrap();
    assert_eq!(tail.frames.first().map(|f| f.seq), Some(4));
    assert!(matches!(
        seek_line(&temp.path().join("absent"), 1),
        Err(Error::NotFound)
    ));
}

/// Every line of a log whose frames cut lines anywhere resolves to the frame a byte-by-byte model names, across
/// the index's checkpoints (a line checkpoint every 64 frames and at each step change).
#[test]
fn every_line_resolves_like_a_byte_model_across_checkpoints() {
    let temp = tempfile::tempdir().unwrap();
    let logs = LogStore::open(temp.path().join("logs")).unwrap();
    let attempt = AttemptId::new();
    let mut frames = Vec::new();
    for seq in 1..=300u64 {
        let text = format!(
            "{}{}",
            "p".repeat(1 + (seq % 7) as usize),
            "\n".repeat((seq % 4) as usize)
        );
        logs.append(
            run(),
            job(),
            attempt,
            &at_step(seq, (seq / 100) as u32, &text),
        )
        .unwrap();
        frames.push((seq, text));
    }
    let stream: String = frames.iter().map(|(_, t)| t.as_str()).collect();
    let newlines = stream.matches('\n').count() as u64;
    let dir = logs.attempt_dir(run(), job(), attempt);
    for line in 1..=newlines + 2 {
        let start = if line == 1 {
            Some(0)
        } else {
            stream
                .match_indices('\n')
                .nth((line - 2) as usize)
                .map(|(i, _)| i + 1)
                .filter(|pos| *pos < stream.len())
        };
        let expected = start.map(|pos| {
            let mut end = 0;
            frames
                .iter()
                .find(|(_, t)| {
                    end += t.len();
                    pos < end
                })
                .map(|(seq, _)| *seq)
                .unwrap()
        });
        let seek = seek_line(&dir, line).unwrap();
        match expected {
            Some(seq) => {
                assert!(seek.found, "line {line}");
                let after = if line == 1 { 0 } else { seq - 1 };
                assert_eq!(seek.after, after, "line {line}");
            }
            None => {
                assert!(!seek.found, "line {line}");
                assert_eq!(seek.after, 300, "line {line}");
            }
        }
        assert!(seek.exact);
    }
}

/// A lookup decodes from the nearest line checkpoint: a corrupted early segment is never opened for a line past it.
#[test]
fn a_line_lookup_seeks_by_checkpoint_and_skips_sealed_segments_before_it() {
    let temp = tempfile::tempdir().unwrap();
    let logs = LogStore::open(temp.path().join("logs")).unwrap();
    let attempt = AttemptId::new();
    let text = format!("{}\n", "x".repeat(32 * 1024 - 19));
    for seq in 1..=140u64 {
        logs.append(run(), job(), attempt, &frame(seq, &text))
            .unwrap();
    }
    let dir = logs.attempt_dir(run(), job(), attempt);
    wait_compressed(&dir, 0);
    std::fs::write(dir.join("seg-000000.z"), b"not a segment").unwrap();
    let seek = logs.seek_line(run(), job(), attempt, 135).unwrap();
    assert!(found(134)(seek) && seek.exact);
    assert!(
        logs.seek_line(run(), job(), attempt, 100).is_err(),
        "a line inside the damaged segment needs it"
    );
}

#[test]
fn a_missing_stale_or_reordered_index_falls_back_to_the_segments() {
    let temp = tempfile::tempdir().unwrap();
    let logs = LogStore::open(temp.path().join("logs")).unwrap();
    let attempt = AttemptId::new();
    for seq in 1..=200u64 {
        logs.append(run(), job(), attempt, &frame(seq, "x\n"))
            .unwrap();
    }
    let dir = logs.attempt_dir(run(), job(), attempt);
    let honest = index_entries(&dir);
    assert!(honest.len() >= 3);
    let check = || {
        for line in [1, 2, 64, 65, 66, 150, 200] {
            let seek = seek_line(&dir, line).unwrap();
            assert!(found(line - 1)(seek) && seek.exact, "line {line}");
        }
        let seek = seek_line(&dir, 201).unwrap();
        assert!(!seek.found && seek.after == 200);
    };
    check();
    // Checkpoints that name frames the segment does not hold.
    let stale: Vec<Vec<u8>> = honest
        .iter()
        .map(|e| {
            let mut e = e.clone();
            e[1..9].copy_from_slice(&777_777u64.to_le_bytes());
            e
        })
        .collect();
    write_index(&dir, &stale);
    check();
    // Line counts that decrease cannot be searched.
    let reordered: Vec<Vec<u8>> = honest.iter().rev().cloned().collect();
    write_index(&dir, &reordered);
    check();
    std::fs::remove_file(dir.join("index")).unwrap();
    check();
}

#[test]
fn gaps_and_late_fills_make_a_line_inexact_but_not_the_lines_before_them() {
    let temp = tempfile::tempdir().unwrap();
    let logs = LogStore::open(temp.path().join("logs")).unwrap();
    let attempt = AttemptId::new();
    // Stored order 1, 2, 5, then the fill 3: seq 4 stays a hole.
    for (seq, text) in [(1, "a\n"), (2, "b\n"), (5, "e\n"), (3, "c\n")] {
        logs.append(run(), job(), attempt, &frame(seq, text))
            .unwrap();
    }
    let at = |line| logs.seek_line(run(), job(), attempt, line).unwrap();
    assert!(found(0)(at(1)) && at(1).exact);
    assert!(found(1)(at(2)) && at(2).exact);
    // Line 3 is "e" (seq 5) behind the hole; line 4 is the late fill, found by stored order.
    assert!(found(4)(at(3)) && !at(3).exact);
    assert!(found(2)(at(4)) && !at(4).exact);
    logs.finish(run(), job(), attempt, 6, &[]).unwrap();
    // The finished log keeps the same answer, now complete, and a line past the end is not found.
    assert!(found(1)(at(2)) && at(2).exact && at(2).complete);
    assert!(!at(3).exact);
    let beyond = at(9);
    assert!(!beyond.found && beyond.complete);
    assert!(
        !beyond.exact,
        "the hole at 4 lies behind the last stored frame"
    );
}

#[test]
fn torn_and_zeroed_tails_end_the_lookup_at_the_last_whole_frame() {
    use std::io::Write;
    let temp = tempfile::tempdir().unwrap();
    let logs = LogStore::open(temp.path().join("logs")).unwrap();
    let tails: [&[u8]; 2] = [&[1, 2, 0, 0], &[0; 4096]];
    let mut dirs = Vec::new();
    for _ in tails {
        let attempt = AttemptId::new();
        for (seq, text) in [
            (
                1, "a
",
            ),
            (
                2, "b
",
            ),
            (
                3, "c
",
            ),
        ] {
            logs.append(run(), job(), attempt, &frame(seq, text))
                .unwrap();
        }
        dirs.push(logs.attempt_dir(run(), job(), attempt));
    }
    drop(logs);
    for (dir, tail) in dirs.iter().zip(tails) {
        let mut segment = std::fs::OpenOptions::new()
            .append(true)
            .open(dir.join("seg-000000"))
            .unwrap();
        segment.write_all(tail).unwrap();
        let mut index = std::fs::OpenOptions::new()
            .append(true)
            .open(dir.join("index"))
            .unwrap();
        index.write_all(&[9, 9, 9]).unwrap();
        assert!(found(2)(seek_line(dir, 3).unwrap()));
        let beyond = seek_line(dir, 5).unwrap();
        assert!(!beyond.found && beyond.after == 3);
        let time = seek_time(dir, UnixMillis(i64::MAX)).unwrap();
        assert!(time.until.is_none() && time.after == 1);
    }
}

#[test]
fn a_wall_time_lookup_brackets_the_frames_between_two_checkpoints() {
    let temp = tempfile::tempdir().unwrap();
    let logs = LogStore::open(temp.path().join("logs")).unwrap();
    let attempt = AttemptId::new();
    let nap = || std::thread::sleep(Duration::from_millis(40));
    // Every frame opens a checkpoint: the first of a segment, then each step change.
    logs.append(run(), job(), attempt, &at_step(1, 0, "a\n"))
        .unwrap();
    nap();
    let early = UnixMillis::now();
    nap();
    logs.append(run(), job(), attempt, &at_step(2, 1, "b\n"))
        .unwrap();
    nap();
    let middle = UnixMillis::now();
    nap();
    logs.append(run(), job(), attempt, &at_step(3, 2, "c\n"))
        .unwrap();
    nap();
    let late = UnixMillis::now();
    let at = |ms| logs.seek_time(run(), job(), attempt, ms).unwrap();
    let seek = |after, until| TimeSeek {
        after,
        until,
        complete: false,
    };
    assert_eq!(at(UnixMillis(0)), seek(0, Some(1)));
    assert_eq!(at(early), seek(1, Some(2)));
    assert_eq!(at(middle), seek(2, Some(3)));
    assert_eq!(at(late), seek(3, None));
    logs.finish(run(), job(), attempt, 3, &[]).unwrap();
    assert!(at(late).complete);
    assert!(matches!(
        seek_time(&temp.path().join("absent"), early),
        Err(Error::NotFound)
    ));
}

/// A seal record is a wall-time checkpoint too, and a segment before the instant need not be read to place it.
#[test]
fn a_wall_time_lookup_uses_seal_records_across_segments() {
    let temp = tempfile::tempdir().unwrap();
    let logs = LogStore::open(temp.path().join("logs")).unwrap();
    let attempt = AttemptId::new();
    let text = "x".repeat(32 * 1024 - 18);
    for seq in 1..=100u64 {
        logs.append(run(), job(), attempt, &frame(seq, &text))
            .unwrap();
    }
    std::thread::sleep(Duration::from_millis(60));
    let mark = UnixMillis::now();
    std::thread::sleep(Duration::from_millis(60));
    for seq in 101..=140u64 {
        logs.append(run(), job(), attempt, &frame(seq, &text))
            .unwrap();
    }
    let dir = logs.attempt_dir(run(), job(), attempt);
    wait_compressed(&dir, 0);
    std::fs::write(dir.join("seg-000000.z"), b"not a segment").unwrap();
    let seek = logs.seek_time(run(), job(), attempt, mark).unwrap();
    assert!(seek.after <= 100, "{seek:?}");
    assert!(
        seek.until
            .is_some_and(|until| until > 100 && until >= seek.after),
        "{seek:?}"
    );
}
