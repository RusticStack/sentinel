//! A write the kernel cuts short, on both ends of the log path: the
//! controller's log store and the worker's spool. `RLIMIT_FSIZE` makes the
//! kernel accept part of a write and refuse the rest (`EFBIG`), which is
//! what a file system filling up mid-record does — without root and without
//! filling a disk. The limit is process-wide, so this binary holds exactly
//! one test.

#![cfg(target_os = "linux")]

use sentinel_core::{AttemptId, JobId, RunId};
use sentinel_protocol::logs::{Frame, Stream};
use sentinel_store::logs::{Appended, LogStore};
use sentinel_worker::spool::{Refusal, Spool};

/// Cap the size of any file this process writes; restored on drop.
struct FileSizeLimit(libc::rlimit);

impl FileSizeLimit {
    fn set(bytes: u64) -> FileSizeLimit {
        let mut old = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: plain getrlimit/setrlimit on this process with valid
        // pointers; SIGXFSZ is ignored so the refused write returns EFBIG
        // instead of killing the process.
        unsafe {
            libc::signal(libc::SIGXFSZ, libc::SIG_IGN);
            assert_eq!(libc::getrlimit(libc::RLIMIT_FSIZE, &mut old), 0);
            let new = libc::rlimit {
                rlim_cur: bytes,
                rlim_max: old.rlim_max,
            };
            assert_eq!(libc::setrlimit(libc::RLIMIT_FSIZE, &new), 0);
        }
        FileSizeLimit(old)
    }
}

impl Drop for FileSizeLimit {
    fn drop(&mut self) {
        // SAFETY: restores the limit read in `set`.
        unsafe {
            libc::setrlimit(libc::RLIMIT_FSIZE, &self.0);
        }
    }
}

fn frame(seq: u64, len: usize) -> Frame {
    Frame {
        seq,
        step: 0,
        stream: Stream::Stdout,
        bytes: vec![b'a' + (seq % 26) as u8; len],
    }
}

fn segment_len(dir: &std::path::Path) -> u64 {
    let mut len = 0;
    for entry in walk(dir) {
        if entry
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.starts_with("seg-"))
        {
            len += std::fs::metadata(&entry).unwrap().len();
        }
    }
    len
}

fn walk(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir).unwrap().flatten() {
        let path = entry.path();
        if path.is_dir() {
            out.extend(walk(&path));
        } else {
            out.push(path);
        }
    }
    out
}

/// A frame whose write was cut short is never acknowledged, and the frames
/// after it are never written behind its remains: the resend of it and
/// everything after read back exactly. Before the fix the store kept the
/// partial record and appended behind it, and a reopen read the rest of
/// the segment as garbage — acknowledged frames lost.
#[test]
fn a_short_write_never_strands_a_record_in_the_log_or_the_spool() {
    let temp = tempfile::tempdir().unwrap();
    let (run, job, attempt) = (RunId::new(), JobId::new(), AttemptId::new());
    let logs = temp.path().join("logs");
    let store = LogStore::open(&logs).unwrap();
    for seq in 1..=3 {
        assert!(matches!(
            store.append(run, job, attempt, &frame(seq, 100)).unwrap(),
            Appended::Stored { through } if through == seq
        ));
    }
    let written = segment_len(&logs);
    {
        // Room for half of the next record.
        let _limit = FileSizeLimit::set(written + 60);
        assert!(store.append(run, job, attempt, &frame(4, 100)).is_err());
    }
    // The worker never saw an acknowledgement for 4: it resends it.
    for seq in 4..=5 {
        assert!(matches!(
            store.append(run, job, attempt, &frame(seq, 100)).unwrap(),
            Appended::Stored { through } if through == seq
        ));
    }
    drop(store);
    let store = LogStore::open(&logs).unwrap();
    let tail = store.tail(run, job, attempt, 0, 100, None).unwrap();
    assert_eq!(
        tail.frames,
        (1..=5).map(|s| frame(s, 100)).collect::<Vec<_>>()
    );
    assert!(tail.gaps.is_empty());

    // The spool: the cut frame's sequence is declared, never reused, and
    // later frames stay decodable across a reopen.
    let worker = temp.path().join("worker");
    let spooled = AttemptId::new();
    let mut spool = Spool::open(&worker, spooled).unwrap();
    for _ in 0..3 {
        spool
            .append(0, Stream::Stdout, &[b'x'; 100])
            .unwrap()
            .unwrap();
    }
    spool.sync().unwrap();
    let frames = worker
        .join(sentinel_worker::spool::SPOOL_DIR)
        .join(spooled.to_string())
        .join("frames");
    let written = std::fs::metadata(&frames).unwrap().len();
    {
        let _limit = FileSizeLimit::set(written + 60);
        assert!(spool.append(0, Stream::Stdout, &[b'y'; 100]).is_err());
        assert_eq!(spool.last_refusal(), Some(Refusal::WriteFailed));
    }
    assert_eq!(
        spool.append(0, Stream::Stdout, &[b'z'; 100]).unwrap(),
        Some(5)
    );
    spool.sync().unwrap();
    drop(spool);
    let mut spool = Spool::open(&worker, spooled).unwrap();
    let seqs: Vec<u64> = spool
        .unacked(0, 10)
        .unwrap()
        .iter()
        .map(|f| f.seq)
        .collect();
    assert_eq!(seqs, vec![1, 2, 3, 5]);
    assert_eq!(spool.gaps(), &[(4, 4)]);
}
