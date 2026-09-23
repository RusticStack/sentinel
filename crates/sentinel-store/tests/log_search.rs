//! Log search across every boundary a literal can straddle (O05
//! follow-up): frames, a sealed segment, the byte-budget cut between two
//! requests and an arbitrary `after`. Paged requests that pass the returned
//! carry find exactly what one unbounded request finds — once each.

use sentinel_core::{AttemptId, JobId, RunId};
use sentinel_protocol::logs::{FRAME_HEADER_BYTES, Frame, Stream};
use sentinel_store::logs::{
    LogStore, MAX_CARRY_TEXT, Match, SEARCH_SCAN_BYTES, Search, SearchQuery,
};

struct Log {
    _dir: tempfile::TempDir,
    logs: LogStore,
    run: RunId,
    job: JobId,
    attempt: AttemptId,
    seq: u64,
}

impl Log {
    fn new() -> Log {
        let dir = tempfile::tempdir().unwrap();
        let logs = LogStore::open(dir.path().join("logs")).unwrap();
        Log {
            _dir: dir,
            logs,
            run: RunId::new(),
            job: JobId::new(),
            attempt: AttemptId::new(),
            seq: 0,
        }
    }

    fn push(&mut self, step: u32, stream: Stream, bytes: Vec<u8>) -> u64 {
        self.seq += 1;
        self.logs
            .append(
                self.run,
                self.job,
                self.attempt,
                &Frame {
                    seq: self.seq,
                    step,
                    stream,
                    bytes,
                },
            )
            .unwrap();
        self.seq
    }

    fn search(
        &self,
        needle: &[u8],
        after: u64,
        budget: u64,
        carry: Option<&str>,
    ) -> sentinel_store::Result<Search> {
        self.logs.search(
            self.run,
            self.job,
            self.attempt,
            SearchQuery {
                needle,
                after,
                limit: 500,
                budget,
                carry,
            },
        )
    }

    /// Page through the whole log under `budget`, passing each carry back
    /// (or not), and return every match with the number of requests.
    fn paged(&self, needle: &[u8], budget: u64, with_carry: bool) -> (Vec<Match>, usize) {
        let (mut found, mut after, mut carry, mut requests) = (Vec::new(), 0, None, 0);
        loop {
            let page = self
                .search(needle, after, budget, carry.as_deref())
                .unwrap();
            requests += 1;
            found.extend(page.matches);
            let Some(next) = page.next_after else {
                return (found, requests);
            };
            assert!(next > after, "every request makes progress");
            let text = page.carry.expect("a carry comes with next_after");
            assert!(text.len() <= MAX_CARRY_TEXT);
            after = next;
            carry = with_carry.then_some(text);
        }
    }
}

fn summary(found: &[Match]) -> Vec<(u64, Stream, String)> {
    found
        .iter()
        .map(|m| (m.seq, m.stream, String::from_utf8(m.text.clone()).unwrap()))
        .collect()
}

/// A payload whose record is exactly 32 KiB, so a 4 MiB segment holds
/// exactly 128 frames and the 4 MiB search budget covers exactly as many.
const PAYLOAD: usize = (32 << 10) - FRAME_HEADER_BYTES;

/// `PAYLOAD` bytes of filler lines, then `tail` (whose last line may stay open).
fn frame_ending(head: &str, tail: &str) -> Vec<u8> {
    let mut out = head.as_bytes().to_vec();
    while out.len() + tail.len() < PAYLOAD {
        let line = (PAYLOAD - tail.len() - out.len()).min(100);
        out.extend(std::iter::repeat_n(b'x', line - 1));
        out.push(b'\n');
    }
    out.extend_from_slice(tail.as_bytes());
    assert_eq!(out.len(), PAYLOAD);
    out
}

#[test]
fn a_literal_split_across_a_sealed_segment_is_found_once_single_or_paged() {
    let mut log = Log::new();
    // stderr opens a line early and finishes it three segments later.
    log.push(0, Stream::Stderr, frame_ending("", "warn: nee"));
    // Frames 2..=128 fill segment 0 (128 records of 32 KiB); frame 128 ends
    // with an open line holding the needle's first half.
    for _ in 2..128 {
        log.push(0, Stream::Stdout, frame_ending("", ""));
    }
    let last_of_seg0 = log.push(0, Stream::Stdout, frame_ending("", "error: nee"));
    assert_eq!(last_of_seg0, 128);
    // Frame 129 opens segment 1 and finishes the line.
    log.push(0, Stream::Stdout, frame_ending("dle across the seal\n", ""));
    for _ in 130..=400 {
        log.push(0, Stream::Stdout, frame_ending("", ""));
    }
    let far = log.push(0, Stream::Stderr, b"dle from far back\n".to_vec());
    log.logs
        .finish(log.run, log.job, log.attempt, log.seq, &[])
        .unwrap();
    let segs = std::fs::read_dir(log.logs.attempt_dir(log.run, log.job, log.attempt))
        .unwrap()
        .filter(|e| {
            e.as_ref()
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with("seg-")
        })
        .count();
    assert!(segs >= 4, "the log spans several segments: {segs}");

    let expected = vec![
        (129, Stream::Stdout, "needle across the seal".to_owned()),
        (far, Stream::Stderr, "needle from far back".to_owned()),
    ];
    // One unbounded request.
    let whole = log.search(b"needle", 0, u64::MAX, None).unwrap();
    assert_eq!(summary(&whole.matches), expected);
    assert!(whole.complete && whole.next_after.is_none() && whole.carry.is_none());

    // The real 4 MiB budget stops the first request exactly at the seal.
    let first = log.search(b"needle", 0, SEARCH_SCAN_BYTES, None).unwrap();
    assert!(first.matches.is_empty());
    assert_eq!(first.next_after, Some(last_of_seg0));
    // The next request resumes at the boundary and finds the split, once.
    let carry = first.carry.unwrap();
    let second = log
        .search(b"needle", last_of_seg0, SEARCH_SCAN_BYTES, Some(&carry))
        .unwrap();
    assert_eq!(summary(&second.matches), expected[..1]);
    // Without the carry (an older client), the sealed segment is replayed
    // and the stdout split is still found.
    let legacy = log
        .search(b"needle", last_of_seg0, SEARCH_SCAN_BYTES, None)
        .unwrap();
    assert_eq!(summary(&legacy.matches), expected[..1]);

    // Paging under several budgets, carry passed back: identical to the
    // single request — nothing missed, nothing twice.
    for frames in [128u64, 37] {
        let budget = frames * PAYLOAD as u64;
        let (found, requests) = log.paged(b"needle", budget, true);
        assert_eq!(summary(&found), expected, "{frames} frames per request");
        assert_eq!(requests as u64, far.div_ceil(frames));
    }
}

#[test]
fn the_budget_cut_landing_mid_needle_finds_it_once() {
    let mut log = Log::new();
    let frames: [(u32, Stream, &[u8]); 9] = [
        (0, Stream::Stdout, b"one nee"),
        (0, Stream::Stdout, b"dle split\n"),
        // Three pieces, with a stderr frame between two of them.
        (0, Stream::Stdout, b"two n"),
        (0, Stream::Stderr, b"unrelated ne"),
        (0, Stream::Stdout, b"eed"),
        (0, Stream::Stdout, b"le three\n"),
        // A line already reported must not be reported again when a second
        // occurrence straddles the cut after it.
        (0, Stream::Stdout, b"needle then nee"),
        (0, Stream::Stdout, b"dle again, and needle\n"),
        // A step change is not a continuation.
        (1, Stream::Stderr, b"edle is not a match\n"),
    ];
    for (step, stream, bytes) in frames {
        log.push(step, stream, bytes.to_vec());
    }
    let expected = vec![
        (2, Stream::Stdout, "needle split".to_owned()),
        (6, Stream::Stdout, "needle three".to_owned()),
        (7, Stream::Stdout, "needle then nee".to_owned()),
    ];
    let whole = log.search(b"needle", 0, u64::MAX, None).unwrap();
    assert_eq!(summary(&whole.matches), expected);
    // A one-byte budget scans exactly one frame per request: every gap
    // between frames is a cut between requests.
    let (found, requests) = log.paged(b"needle", 1, true);
    assert_eq!(summary(&found), expected);
    assert_eq!(requests, frames.len());
    // A budget that fits only the first frame cuts mid-needle.
    let first = log.search(b"needle", 0, 7, None).unwrap();
    assert_eq!((first.matches.len(), first.next_after), (0, Some(1)));
    let rest = log
        .search(b"needle", 1, u64::MAX, first.carry.as_deref())
        .unwrap();
    assert_eq!(summary(&rest.matches), expected);
    // Resuming at any `after` without a carry rebuilds the same state from
    // the segment (everything here is in one): no miss, no repeat.
    for after in 0..frames.len() as u64 {
        let page = log.search(b"needle", after, u64::MAX, None).unwrap();
        let want: Vec<_> = expected
            .iter()
            .filter(|(seq, ..)| *seq > after)
            .cloned()
            .collect();
        assert_eq!(summary(&page.matches), want, "after {after}");
    }
}

#[test]
fn the_scan_budget_is_a_hard_bound_and_a_carry_is_checked() {
    let mut log = Log::new();
    for _ in 0..300 {
        log.push(0, Stream::Stdout, frame_ending("", ""));
    }
    let bytes_through = |from: u64, to: u64| (to - from) * PAYLOAD as u64;
    let mut after = 0;
    let mut carry: Option<String> = None;
    loop {
        let page = log
            .search(b"absent", after, SEARCH_SCAN_BYTES, carry.as_deref())
            .unwrap();
        let Some(next) = page.next_after else {
            assert!(bytes_through(after, log.seq) <= SEARCH_SCAN_BYTES);
            break;
        };
        // At most 4 MiB scanned, and the next frame would not have fit.
        assert!(bytes_through(after, next) <= SEARCH_SCAN_BYTES);
        assert!(bytes_through(after, next + 1) > SEARCH_SCAN_BYTES);
        after = next;
        carry = page.carry;
    }
    // A frame larger than the budget still scans: every request progresses.
    let tiny = log.search(b"absent", 0, 1, None).unwrap();
    assert_eq!(tiny.next_after, Some(1));

    // A carry belongs to its `after` and needle; anything else is refused.
    let carry = tiny.carry.unwrap();
    let refused: [(&[u8], u64, String); 6] = [
        (b"absent", 2, carry.clone()),
        (b"absent!", 1, carry.clone()),
        (b"absent", 1, "zz".to_owned()),
        (b"absent", 1, String::new()),
        (b"absent", 1, carry[..carry.len() - 2].to_owned()),
        (b"absent", 1, format!("{carry}00")),
    ];
    for (needle, after, text) in refused {
        assert!(
            matches!(
                log.search(needle, after, 1, Some(&text)),
                Err(sentinel_store::Error::InvalidInput(_))
            ),
            "{after} {text}"
        );
    }
    assert!(log.search(b"absent", 1, 1, Some(&carry)).is_ok());
}
