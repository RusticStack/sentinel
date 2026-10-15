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
