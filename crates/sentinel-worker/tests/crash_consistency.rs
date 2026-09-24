//! Crash consistency of the worker's log spool and the controller's log
//! store (P04-28): what an acknowledgement, a sync or a declared end
//! promises must survive a power loss at any point, and whatever a crash
//! leaves must reopen and converge to the log an uninterrupted run
//! produces.
//!
//! One deterministic workload drives the real code — `recovery::mark`, a
//! capped `Spool` (appends, syncs, acknowledgements, refused frames and the
//! persisted end) and a `LogStore` (appends, a jump and its fill, a
//! finished log with declared gaps, a log large enough to seal and compress
//! a segment, a store reopen and a live log that never ends). After every
//! operation returns, the workload records it as done; the promises a
//! prefix of done operations makes are then checked against the state a
//! crash left, with the same real code reopening it.
//!
//! Two ways to crash it, both opt-in because they need tools a plain
//! `cargo test` host does not have:
//!
//! - `posix_crash_states` (`SENTINEL_CRASH_TESTS=1`, needs `strace`) runs
//!   the workload once under `strace`, replays every recorded file-system
//!   call into a model with POSIX-strict persistence — file data is durable
//!   only after an `fsync`/`fdatasync` of that file, a directory entry only
//!   after an `fsync` of its directory — and after every call checks five
//!   crash states: nothing unsynced survived; every namespace change
//!   survived but only synced data; unsynced appends survived half-torn;
//!   unsynced growth survived as zeros (the size reached the disk, the data
//!   did not); everything survived (a process crash). Journaling file
//!   systems persist more than this model, so it catches ordering mistakes
//!   they hide.
//! - `power_cut_on_dm_flakey` (`SENTINEL_POWER_LOSS_TESTS=1`, as root, with
//!   `dm-flakey`, `losetup`, `mkfs.ext4` and `mkfs.xfs`) runs the workload on
//!   a real ext4 and a real XFS over a `dm-flakey` device and cuts power
//!   after chosen operations by switching the device to `drop_writes`
//!   (suspended without freezing the file system, so nothing is flushed):
//!   every write the kernel had not completed to the device is lost, as in
//!   a power cut. The file system is then unmounted, restored and mounted
//!   again, and the same checks run on what the disk kept.

#![cfg(target_os = "linux")]

use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    fs,
    hash::{DefaultHasher, Hash, Hasher},
    io::Write,
    path::{Path, PathBuf},
    process::Command,
    sync::{Mutex, atomic::AtomicUsize},
};

use sentinel_core::{AttemptId, Fence, JobId, RunId};
use sentinel_protocol::logs::{Frame, Stream};
use sentinel_store::logs::{LogStore, Tail};
use sentinel_worker::{recovery, spool::Spool};

// ---------------------------------------------------------------- workload

/// A fixed, valid (version 4) identifier from one byte.
fn id(n: u8) -> [u8; 16] {
    let mut bytes = [n; 16];
    bytes[6] = 0x40 | (n & 0x0f);
    bytes[8] = 0x80 | (n & 0x3f);
    bytes
}

fn worker_attempt() -> AttemptId {
    AttemptId::from_bytes(id(1)).unwrap()
}

const WORKER_FENCE: Fence = Fence(7);
/// Twelve 14-byte spool frames (32 bytes encoded) fit, the thirteenth does not.
const SPOOL_CAP: u64 = 12 * 32 + 10;
/// Frames of the log that seals a segment: 130 × 32 KiB passes 4 MiB.
const BIG_FRAMES: u64 = 130;
const BIG_FRAME: usize = 32 << 10;

/// The controller logs the workload writes: `(run, job, attempt)`.
fn logs() -> [(RunId, JobId, AttemptId); 3] {
    [
        (
            RunId::from_bytes(id(10)).unwrap(),
            JobId::from_bytes(id(11)).unwrap(),
            AttemptId::from_bytes(id(12)).unwrap(),
        ),
        (
            RunId::from_bytes(id(10)).unwrap(),
            JobId::from_bytes(id(21)).unwrap(),
            AttemptId::from_bytes(id(22)).unwrap(),
        ),
        (
            RunId::from_bytes(id(30)).unwrap(),
            JobId::from_bytes(id(31)).unwrap(),
            AttemptId::from_bytes(id(32)).unwrap(),
        ),
    ]
}

#[derive(Clone, Debug)]
enum Op {
    /// `recovery::mark` of the worker attempt.
    Mark,
    SpoolOpen,
    SpoolAppend(Vec<u8>),
    SpoolSync,
    SpoolAck(u64),
    /// `persist_end`: the end a `LogEnd` would declare.
    SpoolEnd,
    StoreOpen,
    /// Drop the store and open it again, as a controller restart would.
    StoreReopen,
    StoreAppend {
        log: usize,
        seq: u64,
        bytes: Vec<u8>,
    },
    StoreFinish {
        log: usize,
        last_seq: u64,
        gaps: Vec<(u64, u64)>,
    },
}

fn big_frame(seq: u64) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(BIG_FRAME);
    let mut x = seq.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    while bytes.len() < BIG_FRAME {
        // Mostly text, a little noise: compresses, but not to nothing.
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        let line = format!("frame {seq} line {} {:x}\n", bytes.len(), x & 0xffff);
        bytes.extend_from_slice(line.as_bytes());
    }
    bytes.truncate(BIG_FRAME);
    bytes
}

fn plan() -> Vec<Op> {
    let mut ops = vec![Op::Mark, Op::SpoolOpen];
    let line = |n: u64| format!("spool line {n:02}").into_bytes();
    for n in 1..=5 {
        ops.push(Op::SpoolAppend(line(n)));
    }
    ops.push(Op::SpoolSync);
    ops.push(Op::SpoolAck(3));
    for n in 6..=10 {
        ops.push(Op::SpoolAppend(line(n)));
    }
    ops.push(Op::SpoolSync);
    ops.push(Op::SpoolAck(8));
    // 11 and 12 fit; 13 opens a refused range, 14 extends it.
    for n in 11..=14 {
        ops.push(Op::SpoolAppend(line(n)));
    }
    ops.push(Op::SpoolSync);
    ops.push(Op::SpoolEnd);

    ops.push(Op::StoreOpen);
    let small = |seq: u64| format!("log line {seq}\n").into_bytes();
    // A jump (hole 4..=5), its partial fill, and an end declaring a gap
    // and an unstored tail.
    for seq in [1, 2, 3, 6, 4, 7] {
        ops.push(Op::StoreAppend {
            log: 0,
            seq,
            bytes: small(seq),
        });
    }
    ops.push(Op::StoreFinish {
        log: 0,
        last_seq: 9,
        gaps: vec![(8, 8)],
    });
    for seq in 1..=BIG_FRAMES {
        ops.push(Op::StoreAppend {
            log: 1,
            seq,
            bytes: big_frame(seq),
        });
    }
    ops.push(Op::StoreFinish {
        log: 1,
        last_seq: BIG_FRAMES,
        gaps: Vec::new(),
    });
    ops.push(Op::StoreReopen);
    for seq in [1, 2, 4] {
        ops.push(Op::StoreAppend {
            log: 2,
            seq,
            bytes: small(seq),
        });
    }
    ops
}

/// What an operation returned, as far as its promises go.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Outcome {
    None,
    /// The sequence the append spent, and whether it was stored.
    Appended {
        seq: u64,
        stored: bool,
    },
    /// The spool's last sequence and gaps when a sync or end returned.
    Synced {
        last_seq: u64,
        gaps: Vec<(u64, u64)>,
    },
    Stored,
    Ended,
}

struct Live {
    spool: Option<Spool>,
    store: Option<LogStore>,
}

fn apply(root: &Path, live: &mut Live, op: &Op) -> Outcome {
    let worker = root.join("worker");
    let logs_dir = root.join("logs");
    match op {
        Op::Mark => {
            recovery::mark(&worker, worker_attempt(), WORKER_FENCE).unwrap();
            Outcome::None
        }
        Op::SpoolOpen => {
            live.spool =
                Some(Spool::open_with_limit(&worker, worker_attempt(), SPOOL_CAP).unwrap());
            Outcome::None
        }
        Op::SpoolAppend(bytes) => {
            let spool = live.spool.as_mut().unwrap();
            let stored = spool.append(0, Stream::Stdout, bytes).unwrap().is_some();
            Outcome::Appended {
                seq: spool.last_seq(),
                stored,
            }
        }
        Op::SpoolSync | Op::SpoolEnd => {
            let spool = live.spool.as_mut().unwrap();
            if matches!(op, Op::SpoolSync) {
                spool.sync().unwrap();
            } else {
                spool.persist_end().unwrap();
            }
            Outcome::Synced {
                last_seq: spool.last_seq(),
                gaps: spool.gaps().to_vec(),
            }
        }
        Op::SpoolAck(seq) => {
            live.spool.as_mut().unwrap().acknowledged(*seq).unwrap();
            Outcome::None
        }
        Op::StoreOpen => {
            live.store = Some(LogStore::open(&logs_dir).unwrap());
            Outcome::None
        }
        Op::StoreReopen => {
            live.store = None;
            live.store = Some(LogStore::open(&logs_dir).unwrap());
            Outcome::None
        }
        Op::StoreAppend { log, seq, bytes } => {
            let (run, job, attempt) = logs()[*log];
            let frame = Frame {
                seq: *seq,
                step: 0,
                stream: Stream::Stdout,
                bytes: bytes.clone(),
            };
            match live
                .store
                .as_ref()
                .unwrap()
                .append(run, job, attempt, &frame)
                .unwrap()
            {
                sentinel_store::logs::Appended::Stored { .. } => Outcome::Stored,
                other => panic!("append {seq} of log {log}: {other:?}"),
            }
        }
        Op::StoreFinish {
            log,
            last_seq,
            gaps,
        } => {
            let (run, job, attempt) = logs()[*log];
            live.store
                .as_ref()
                .unwrap()
                .finish(run, job, attempt, *last_seq, gaps)
                .unwrap();
            Outcome::Ended
        }
    }
}

/// The directories an operator (or the service's start-up) creates before
/// either role writes anything: the controller's and the worker's data
/// directories. Their own entries are not the log path's to make durable.
fn prepare(root: &Path) {
    fs::create_dir_all(root.join("worker")).unwrap();
}

/// Run the plan under `root` (already [`prepare`]d), calling `done(i,
/// outcome)` once operation `i` has returned; stop early when it answers
/// false. Everything the workload holds is dropped before this returns.
fn run_workload(root: &Path, ops: &[Op], mut done: impl FnMut(usize, &Outcome) -> bool) {
    let mut live = Live {
        spool: None,
        store: None,
    };
    for (i, op) in ops.iter().enumerate() {
        let outcome = apply(root, &mut live, op);
        if !done(i, &outcome) {
            return;
        }
    }
}

// ------------------------------------------------------------ expectations

/// The uninterrupted run: every outcome, and the final logs a reopen shows.
struct Golden {
    ops: Vec<Op>,
    outcomes: Vec<Outcome>,
    tails: Vec<Tail>,
    /// Every stored spool frame by sequence.
    spool_frames: BTreeMap<u64, Vec<u8>>,
}

fn full_tail(store: &LogStore, log: usize) -> sentinel_store::Result<Tail> {
    let (run, job, attempt) = logs()[log];
    store.tail(run, job, attempt, 0, 100_000, None)
}

fn golden() -> Golden {
    let temp = tempfile::tempdir().unwrap();
    let ops = plan();
    let mut outcomes = Vec::new();
    prepare(temp.path());
    run_workload(temp.path(), &ops, |_, outcome| {
        outcomes.push(outcome.clone());
        true
    });
    let store = LogStore::open(temp.path().join("logs")).unwrap();
    let tails = (0..logs().len())
        .map(|log| full_tail(&store, log).unwrap())
        .collect::<Vec<_>>();
    let mut spool_frames = BTreeMap::new();
    for (op, outcome) in ops.iter().zip(&outcomes) {
        if let (Op::SpoolAppend(bytes), Outcome::Appended { seq, stored: true }) = (op, outcome) {
            spool_frames.insert(*seq, bytes.clone());
        }
    }
    // The uninterrupted run itself must be what the plan intends.
    assert!(tails[0].complete && tails[1].complete && !tails[2].complete);
    assert_eq!(tails[0].gaps, vec![(5, 5), (8, 9)]);
    assert_eq!(tails[1].frames.len() as u64, BIG_FRAMES);
    assert_eq!(spool_frames.len(), 12);
    Golden {
        ops,
        outcomes,
        tails,
        spool_frames,
    }
}

/// What the first `done` operations promised.
#[derive(Default, Debug)]
struct Promises {
    marker: bool,
    /// Stored spool frames at or below this are durable.
    spool_synced: u64,
    /// Spent (refused) spool sequences that must read back as gaps.
    spool_declared: BTreeSet<u64>,
    /// The end declared: exact last sequence and gaps.
    spool_end: Option<(u64, Vec<(u64, u64)>)>,
    /// The highest acknowledgement handed to the spool, counting an
    /// operation in flight at the crash.
    spool_acked_at_most: u64,
    store_open: bool,
    /// Per log: sequences acknowledged as stored.
    stored: Vec<BTreeSet<u64>>,
    ended: Vec<bool>,
}

fn promises(golden: &Golden, done: usize) -> Promises {
    let mut p = Promises {
        stored: vec![BTreeSet::new(); logs().len()],
        ended: vec![false; logs().len()],
        ..Promises::default()
    };
    let mut refused_since_sync: Vec<u64> = Vec::new();
    let mut last_refused: Option<u64> = None;
    for (i, (op, outcome)) in golden.ops.iter().zip(&golden.outcomes).enumerate() {
        if i == done {
            // The operation in flight may have moved the cursor already.
            if let Op::SpoolAck(seq) = op {
                p.spool_acked_at_most = p.spool_acked_at_most.max(*seq);
            }
            break;
        }
        match (op, outcome) {
            (Op::Mark, _) => p.marker = true,
            (Op::SpoolAppend(_), Outcome::Appended { seq, stored }) => {
                if !stored {
                    // A new refused range is persisted when it opens; its
                    // growth with the next sync.
                    if last_refused != Some(seq - 1) {
                        p.spool_declared.insert(*seq);
                    } else {
                        refused_since_sync.push(*seq);
                    }
                    last_refused = Some(*seq);
                }
            }
            (Op::SpoolSync, Outcome::Synced { last_seq, .. }) => {
                p.spool_synced = *last_seq;
                p.spool_declared.extend(refused_since_sync.drain(..));
            }
            (Op::SpoolEnd, Outcome::Synced { last_seq, gaps }) => {
                p.spool_end = Some((*last_seq, gaps.clone()));
            }
            (Op::SpoolAck(seq), _) => p.spool_acked_at_most = p.spool_acked_at_most.max(*seq),
            (Op::StoreOpen, _) => p.store_open = true,
            (Op::StoreAppend { log, seq, .. }, Outcome::Stored) => {
                p.stored[*log].insert(*seq);
            }
            (Op::StoreFinish { log, .. }, Outcome::Ended) => p.ended[*log] = true,
            _ => {}
        }
    }
    p
}

fn in_gaps(gaps: &[(u64, u64)], seq: u64) -> bool {
    gaps.iter().any(|(from, to)| (*from..=*to).contains(&seq))
}

/// Check the state a crash left under `root` against what the first
/// `done` operations promised; then drive every log to its end and check
/// it converges to the uninterrupted run. Returns every violation.
fn verify(root: &Path, done: usize, golden: &Golden) -> Vec<String> {
    let p = promises(golden, done);
    let mut bad = Vec::new();
    verify_worker(root, &p, golden, &mut bad);
    verify_store(root, &p, golden, &mut bad);
    bad
}

fn verify_worker(root: &Path, p: &Promises, golden: &Golden, bad: &mut Vec<String>) {
    let worker = root.join("worker");
    let markers = recovery::leftovers(&worker).unwrap_or_default();
    let marked = markers
        .iter()
        .any(|m| m.attempt == worker_attempt() && m.fence == WORKER_FENCE);
    if p.marker && !marked {
        bad.push("the attempt marker was lost".into());
    }
    let dir = worker
        .join(sentinel_worker::spool::SPOOL_DIR)
        .join(worker_attempt().to_string());
    let promised = p.spool_synced > 0 || !p.spool_declared.is_empty() || p.spool_end.is_some();
    if !dir.join("frames").exists() {
        if promised {
            bad.push("the spool was lost after it synced".into());
        }
        return;
    }
    if promised && !marked {
        bad.push("synced spool output without its marker: recovery discards it".into());
    }
    let mut spool = match Spool::open_with_limit(&worker, worker_attempt(), SPOOL_CAP) {
        Ok(spool) => spool,
        Err(e) => {
            bad.push(format!("the spool does not reopen: {e}"));
            return;
        }
    };
    let frames = spool.unacked(0, 10_000).unwrap_or_default();
    let present: BTreeSet<u64> = frames.iter().map(|f| f.seq).collect();
    for frame in &frames {
        if golden.spool_frames.get(&frame.seq) != Some(&frame.bytes) {
            bad.push(format!("spool frame {} has the wrong content", frame.seq));
        }
    }
    for (seq, _) in golden.spool_frames.range(..=p.spool_synced) {
        if !present.contains(seq) {
            bad.push(format!("synced spool frame {seq} was lost"));
        }
    }
    let gaps = spool.gaps().to_vec();
    for seq in &p.spool_declared {
        if !in_gaps(&gaps, *seq) {
            bad.push(format!("declared spool gap {seq} was forgotten"));
        }
        if spool.last_seq() < *seq {
            bad.push(format!("declared spool sequence {seq} would be reused"));
        }
    }
    if spool.last_seq() < p.spool_synced {
        bad.push("a synced spool sequence would be reused".into());
    }
    for seq in &present {
        if in_gaps(&gaps, *seq) {
            bad.push(format!("stored spool frame {seq} is declared a gap"));
        }
    }
    if spool.acked() > p.spool_acked_at_most {
        bad.push(format!(
            "the spool cursor claims {} acknowledged, only {} was",
            spool.acked(),
            p.spool_acked_at_most
        ));
    }
    if let Some((last_seq, end_gaps)) = &p.spool_end
        && (spool.last_seq() != *last_seq || gaps != *end_gaps)
    {
        bad.push(format!(
            "the declared end changed: {last_seq} {end_gaps:?} became {} {gaps:?}",
            spool.last_seq()
        ));
    }
}

fn verify_store(root: &Path, p: &Promises, golden: &Golden, bad: &mut Vec<String>) {
    let dir = root.join("logs");
    let any_stored = p.stored.iter().any(|s| !s.is_empty());
    if !dir.is_dir() {
        if any_stored {
            bad.push("the logs directory was lost".into());
        }
        return;
    }
    let store = match LogStore::open(&dir) {
        Ok(store) => store,
        Err(e) => {
            bad.push(format!("the log store does not open: {e}"));
            return;
        }
    };
    for (log, &(run, job, attempt)) in logs().iter().enumerate() {
        let want = &golden.tails[log];
        let content: HashMap<u64, &Vec<u8>> =
            want.frames.iter().map(|f| (f.seq, &f.bytes)).collect();
        match full_tail(&store, log) {
            Ok(tail) => {
                let seen: HashSet<u64> = tail.frames.iter().map(|f| f.seq).collect();
                for frame in &tail.frames {
                    if content.get(&frame.seq) != Some(&&frame.bytes) {
                        bad.push(format!(
                            "log {log} frame {} has the wrong content",
                            frame.seq
                        ));
                    }
                }
                for seq in &p.stored[log] {
                    if !seen.contains(seq) {
                        bad.push(format!("log {log}: acknowledged frame {seq} was lost"));
                    }
                }
                if p.ended[log] && (!tail.complete || tail.gaps != want.gaps) {
                    bad.push(format!(
                        "log {log}: the durable end was lost ({} {:?})",
                        tail.complete, tail.gaps
                    ));
                }
                if tail.complete && !p.ended[log] && want.complete {
                    // An end durable before its call returned is allowed; a
                    // different one is not.
                    if tail.gaps != want.gaps {
                        bad.push(format!("log {log}: an end with other gaps appeared"));
                    }
                } else if tail.complete && !want.complete {
                    bad.push(format!("log {log}: a live log reads as ended"));
                }
            }
            Err(e) => {
                if !p.stored[log].is_empty() {
                    bad.push(format!("log {log} does not read: {e}"));
                }
            }
        }
        // Convergence: the worker resends everything it holds and ends the
        // log again; the result must be the uninterrupted run's.
        for (op, _) in golden.ops.iter().zip(&golden.outcomes) {
            match op {
                Op::StoreAppend { log: l, seq, bytes } if *l == log => {
                    let frame = Frame {
                        seq: *seq,
                        step: 0,
                        stream: Stream::Stdout,
                        bytes: bytes.clone(),
                    };
                    match store.append(run, job, attempt, &frame) {
                        Ok(_) | Err(sentinel_store::Error::Conflict) => {}
                        Err(e) => bad.push(format!("log {log}: resend of {seq} failed: {e}")),
                    }
                }
                Op::StoreFinish {
                    log: l,
                    last_seq,
                    gaps,
                } if *l == log => {
                    if let Err(e) = store.finish(run, job, attempt, *last_seq, gaps) {
                        bad.push(format!("log {log}: the end does not land again: {e}"));
                    }
                }
                _ => {}
            }
        }
        match full_tail(&store, log) {
            Ok(tail) if tail == *want => {}
            Ok(tail) => bad.push(format!(
                "log {log} did not converge: {} frames complete={} gaps={:?}, want {} complete={} gaps={:?}",
                tail.frames.len(),
                tail.complete,
                tail.gaps,
                want.frames.len(),
                want.complete,
                want.gaps
            )),
            Err(e) => bad.push(format!("log {log} does not read after resending: {e}")),
        }
    }
}

// ------------------------------------------------------ POSIX-strict model

/// The traced workload: runs the plan under `$CRASH_ROOT`, writing each
/// done operation's index to `$CRASH_JOURNAL` — the trace orders those
/// writes against the file-system calls.
#[test]
#[ignore = "run by posix_crash_states under strace"]
fn record_crash_workload() {
    let (Some(root), Some(journal)) = (
        std::env::var_os("CRASH_ROOT"),
        std::env::var_os("CRASH_JOURNAL"),
    ) else {
        return;
    };
    let mut journal = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(journal)
        .unwrap();
    run_workload(Path::new(&root), &plan(), |i, _| {
        journal.write_all(format!("{i}\n").as_bytes()).unwrap();
        true
    });
}

enum Node {
    File {
        data: Vec<u8>,
        durable: Vec<u8>,
        /// Bumped on every change of `data` / `durable`: a crash state is
        /// keyed by these, never by hashing contents.
        version: u64,
        durable_version: u64,
    },
    Dir {
        entries: BTreeMap<String, usize>,
        durable: BTreeMap<String, usize>,
    },
}

#[derive(Clone, Copy)]
struct Handle {
    node: usize,
    offset: u64,
    append: bool,
}

/// A file system that persists only what POSIX promises.
struct Model {
    root: PathBuf,
    nodes: Vec<Node>,
    fds: HashMap<i64, Handle>,
    versions: u64,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
enum Crash {
    /// Only what was synced: data by file fsyncs, entries by directory fsyncs.
    Synced,
    /// Every namespace change, only synced data.
    Namespace,
    /// Every namespace change; unsynced appends half there (a torn tail).
    Torn,
    /// Every namespace change; unsynced growth there as zeros — the size
    /// reached the disk (another file's journal commit), the data did not.
    Zeroed,
    /// Everything issued: a process crash.
    Issued,
}

const CRASHES: [Crash; 5] = [
    Crash::Synced,
    Crash::Namespace,
    Crash::Torn,
    Crash::Zeroed,
    Crash::Issued,
];

impl Model {
    fn new(root: PathBuf) -> Model {
        Model {
            root,
            nodes: vec![Node::Dir {
                entries: BTreeMap::new(),
                durable: BTreeMap::new(),
            }],
            fds: HashMap::new(),
            versions: 0,
        }
    }

    /// Take in the directories that exist before the trace starts, as
    /// durable: they were there before anything was promised.
    fn seed(&mut self) {
        let mut pending = vec![(self.root.clone(), 0usize)];
        while let Some((path, node)) = pending.pop() {
            for entry in fs::read_dir(&path).unwrap().flatten() {
                assert!(
                    entry.file_type().unwrap().is_dir(),
                    "only directories are seeded"
                );
                let child = self.nodes.len();
                self.nodes.push(Node::Dir {
                    entries: BTreeMap::new(),
                    durable: BTreeMap::new(),
                });
                let name = entry.file_name().to_string_lossy().into_owned();
                if let Node::Dir { entries, durable } = &mut self.nodes[node] {
                    entries.insert(name.clone(), child);
                    durable.insert(name, child);
                }
                pending.push((entry.path(), child));
            }
        }
    }

    /// The path relative to the model root, or `None` outside it.
    fn rel(&self, path: &str) -> Option<Vec<String>> {
        let rest = Path::new(path).strip_prefix(&self.root).ok()?;
        Some(
            rest.components()
                .map(|c| c.as_os_str().to_string_lossy().into_owned())
                .collect(),
        )
    }

    fn lookup(&self, parts: &[String]) -> Option<usize> {
        let mut at = 0;
        for part in parts {
            match &self.nodes[at] {
                Node::Dir { entries, .. } => at = *entries.get(part)?,
                Node::File { .. } => return None,
            }
        }
        Some(at)
    }

    fn parent(&self, parts: &[String]) -> (usize, String) {
        let (name, dir) = parts.split_last().expect("not the root");
        let at = self
            .lookup(dir)
            .unwrap_or_else(|| panic!("no parent for {parts:?}"));
        (at, name.clone())
    }

    fn bump(&mut self) -> u64 {
        self.versions += 1;
        self.versions
    }

    fn link(&mut self, dir: usize, name: String, node: usize) {
        match &mut self.nodes[dir] {
            Node::Dir { entries, .. } => {
                entries.insert(name, node);
            }
            Node::File { .. } => panic!("link into a file"),
        }
    }

    fn unlink(&mut self, dir: usize, name: &str) -> Option<usize> {
        match &mut self.nodes[dir] {
            Node::Dir { entries, .. } => entries.remove(name),
            Node::File { .. } => panic!("unlink in a file"),
        }
    }

    fn open(&mut self, path: &str, flags: &str, fd: i64) {
        let Some(parts) = self.rel(path) else {
            return;
        };
        let node = match self.lookup(&parts) {
            Some(node) => node,
            None => {
                assert!(flags.contains("O_CREAT"), "open of a missing {path}");
                let (dir, name) = self.parent(&parts);
                let node = self.nodes.len();
                let version = self.bump();
                self.nodes.push(Node::File {
                    data: Vec::new(),
                    durable: Vec::new(),
                    version,
                    durable_version: 0,
                });
                self.link(dir, name, node);
                node
            }
        };
        if flags.contains("O_TRUNC") {
            let version = self.bump();
            if let Node::File {
                data, version: v, ..
            } = &mut self.nodes[node]
            {
                data.clear();
                *v = version;
            }
        }
        self.fds.insert(
            fd,
            Handle {
                node,
                offset: 0,
                append: flags.contains("O_APPEND"),
            },
        );
    }

    fn write(&mut self, fd: i64, bytes: &[u8], at: Option<u64>) {
        let Some(handle) = self.fds.get(&fd).copied() else {
            return;
        };
        let version = self.bump();
        let Node::File {
            data, version: v, ..
        } = &mut self.nodes[handle.node]
        else {
            panic!("write to a directory");
        };
        let start = match at {
            Some(offset) => offset as usize,
            None if handle.append => data.len(),
            None => handle.offset as usize,
        };
        if data.len() < start + bytes.len() {
            data.resize(start + bytes.len(), 0);
        }
        data[start..start + bytes.len()].copy_from_slice(bytes);
        *v = version;
        if at.is_none() {
            self.fds.get_mut(&fd).expect("present").offset = (start + bytes.len()) as u64;
        }
    }

    fn truncate(&mut self, fd: i64, len: u64) {
        let Some(handle) = self.fds.get(&fd).copied() else {
            return;
        };
        let version = self.bump();
        if let Node::File {
            data, version: v, ..
        } = &mut self.nodes[handle.node]
        {
            data.resize(len as usize, 0);
            *v = version;
        }
    }

    fn sync(&mut self, fd: i64) {
        let Some(handle) = self.fds.get(&fd).copied() else {
            return;
        };
        match &mut self.nodes[handle.node] {
            Node::File {
                data,
                durable,
                version,
                durable_version,
            } => {
                durable.clone_from(data);
                *durable_version = *version;
            }
            Node::Dir { entries, durable } => durable.clone_from(entries),
        }
    }

    fn mkdir(&mut self, path: &str) {
        let Some(parts) = self.rel(path) else {
            return;
        };
        let (dir, name) = self.parent(&parts);
        let node = self.nodes.len();
        self.nodes.push(Node::Dir {
            entries: BTreeMap::new(),
            durable: BTreeMap::new(),
        });
        self.link(dir, name, node);
    }

    fn rename(&mut self, from: &str, to: &str) {
        let (Some(from), Some(to)) = (self.rel(from), self.rel(to)) else {
            return;
        };
        let (from_dir, from_name) = self.parent(&from);
        let (to_dir, to_name) = self.parent(&to);
        let node = self
            .unlink(from_dir, &from_name)
            .unwrap_or_else(|| panic!("rename of {from:?}, which the model does not hold"));
        self.link(to_dir, to_name, node);
    }

    fn remove(&mut self, path: &str) {
        let Some(parts) = self.rel(path) else {
            return;
        };
        let (dir, name) = self.parent(&parts);
        self.unlink(dir, &name);
    }

    /// The files and directories a crash of this kind leaves, keyed by
    /// relative path: `None` for a directory, otherwise the file's content
    /// as `(node, version, torn length)` — cheap to hash, resolved when
    /// materialized.
    fn state(&self, crash: Crash) -> BTreeMap<String, Option<(usize, u64, usize)>> {
        let mut out = BTreeMap::new();
        let mut pending = vec![(String::new(), 0usize)];
        while let Some((prefix, dir)) = pending.pop() {
            let Node::Dir { entries, durable } = &self.nodes[dir] else {
                continue;
            };
            let entries = if crash == Crash::Synced {
                durable
            } else {
                entries
            };
            for (name, node) in entries {
                let path = if prefix.is_empty() {
                    name.clone()
                } else {
                    format!("{prefix}/{name}")
                };
                match &self.nodes[*node] {
                    Node::Dir { .. } => {
                        out.insert(path.clone(), None);
                        pending.push((path, *node));
                    }
                    Node::File {
                        data,
                        durable,
                        version,
                        durable_version,
                    } => {
                        let content = match crash {
                            Crash::Issued => (*node, *version, data.len()),
                            Crash::Torn
                                if data.len() > durable.len() && data.starts_with(durable) =>
                            {
                                let extra = data.len() - durable.len();
                                (*node, *version, durable.len() + extra.div_ceil(2))
                            }
                            Crash::Zeroed if data.len() > durable.len() => {
                                (*node, *durable_version, data.len())
                            }
                            _ => (*node, *durable_version, durable.len()),
                        };
                        out.insert(path, Some(content));
                    }
                }
            }
        }
        out
    }

    /// Write a crash state out as a real directory tree under `into`.
    fn materialize(
        &self,
        crash: Crash,
        state: &BTreeMap<String, Option<(usize, u64, usize)>>,
        into: &Path,
    ) {
        fs::create_dir_all(into).unwrap();
        for (path, content) in state {
            let target = into.join(path);
            match content {
                None => fs::create_dir_all(&target).unwrap(),
                Some((node, _, len)) => {
                    let Node::File { data, durable, .. } = &self.nodes[*node] else {
                        unreachable!()
                    };
                    let bytes = match crash {
                        Crash::Issued | Crash::Torn if *len > durable.len() => {
                            data[..*len].to_vec()
                        }
                        Crash::Zeroed if *len > durable.len() => {
                            let mut bytes = durable.clone();
                            bytes.resize(*len, 0);
                            bytes
                        }
                        _ => durable[..*len].to_vec(),
                    };
                    fs::write(&target, bytes).unwrap();
                }
            }
        }
    }
}

/// One traced call, as `strace -y -xx` prints it.
struct Call {
    name: String,
    args: Vec<String>,
    ret: String,
}

/// Split `a, "b, c", [d, e], f` at top-level commas.
fn split_args(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let (mut depth, mut quoted, mut start) = (0i32, false, 0usize);
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'"' => quoted = !quoted,
            b'\\' if quoted => i += 1,
            b'[' | b'{' | b'<' | b'(' if !quoted => depth += 1,
            b']' | b'}' | b'>' | b')' if !quoted => depth -= 1,
            b',' if !quoted && depth == 0 => {
                out.push(text[start..i].trim().to_owned());
                start = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    if start < text.len() {
        out.push(text[start..].trim().to_owned());
    }
    out
}

fn parse_call(line: &str) -> Option<Call> {
    let open = line.find('(')?;
    let name = line[..open].trim().to_owned();
    if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return None;
    }
    // A resumed call pads before its result: `)            = 6<…>`.
    let eq = line.rfind(" = ")?;
    let head = line[..eq].trim_end().strip_suffix(')')?;
    Some(Call {
        name,
        args: split_args(&head[open + 1..]),
        ret: line[eq + 3..].trim().to_owned(),
    })
}

/// `\x2f\x74` → bytes: `-xx` escapes every byte of strings and of the
/// paths `-y` prints.
fn unescape(inner: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(inner.len() / 4);
    let bytes = inner.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        assert_eq!(&bytes[i..i + 2], b"\\x", "unexpected escape in {inner}");
        out.push(u8::from_str_radix(&inner[i + 2..i + 4], 16).unwrap());
        i += 4;
    }
    out
}

/// The `-xx` form of a path, to find it in a raw line.
fn escaped(path: &str) -> String {
    path.bytes().map(|b| format!("\\x{b:02x}")).collect()
}

/// `"\x2f\x74"` → bytes; a truncated string (`"…"...`) is a harness error.
fn unhex(arg: &str) -> Vec<u8> {
    assert!(!arg.ends_with("..."), "strace truncated a buffer: raise -s");
    let inner = arg
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .unwrap_or_else(|| panic!("not a string: {arg}"));
    unescape(inner)
}

/// `5<\x2f\x61>` → (5, "/a"); `AT_FDCWD<…>` → (-100, …).
fn fd_path(arg: &str) -> (i64, String) {
    let (fd, rest) = arg.split_once('<').unwrap_or((arg, ""));
    let fd = if fd == "AT_FDCWD" {
        -100
    } else {
        fd.parse().unwrap_or(-1)
    };
    let path = rest.strip_suffix('>').unwrap_or(rest);
    (fd, String::from_utf8(unescape(path)).unwrap())
}

/// A path argument relative to a directory descriptor's path.
fn resolve(dir: &str, path: &[u8]) -> String {
    let path = String::from_utf8(path.to_vec()).unwrap();
    if path.starts_with('/') {
        path
    } else {
        format!("{dir}/{path}")
    }
}

fn ok(ret: &str) -> bool {
    !ret.starts_with('-')
}

/// Every call of the trace, in completion order, with the journal's done
/// counts interleaved.
enum Event {
    Call(Call),
    Done(usize),
}

fn read_trace(trace: &Path, journal: &Path) -> Vec<Event> {
    let text = fs::read_to_string(trace).unwrap();
    let journal = escaped(journal.to_str().unwrap());
    let mut pending: HashMap<String, String> = HashMap::new();
    let mut events = Vec::new();
    for raw in text.lines() {
        let (pid, rest) = raw.split_once(' ').unwrap_or(("", raw));
        let rest = rest.trim_start();
        let line = if let Some(head) = rest.strip_suffix(" <unfinished ...>") {
            pending.insert(pid.to_owned(), head.to_owned());
            continue;
        } else if let Some(at) = rest.find(" resumed>") {
            let head = pending.remove(pid).unwrap_or_default();
            format!("{head}{}", &rest[at + " resumed>".len()..])
        } else {
            rest.to_owned()
        };
        let Some(call) = parse_call(&line) else {
            continue;
        };
        if call.name == "write" && call.args.first().is_some_and(|a| a.contains(&journal)) {
            if ok(&call.ret) {
                for n in String::from_utf8(unhex(&call.args[1])).unwrap().lines() {
                    events.push(Event::Done(n.parse::<usize>().unwrap() + 1));
                }
            }
            continue;
        }
        events.push(Event::Call(call));
    }
    events
}

/// Apply one call to the model; calls outside the root change nothing.
fn replay(model: &mut Model, call: &Call) {
    if !ok(&call.ret) {
        return;
    }
    let root = model.root.to_str().unwrap().to_owned();
    let marker = escaped(&root);
    let touches = call.args.iter().any(|a| a.contains(&marker))
        || call.ret.contains(&marker)
        || matches!(
            call.name.as_str(),
            "close" | "lseek" | "dup" | "dup2" | "dup3"
        );
    if !touches {
        return;
    }
    let arg = |i: usize| call.args[i].as_str();
    match call.name.as_str() {
        "openat" => {
            let (fd, path) = fd_path(&call.ret);
            let flags = arg(2);
            model.open(&path, flags, fd);
        }
        "open" | "creat" => {
            let (fd, path) = fd_path(&call.ret);
            let flags = if call.name == "creat" {
                "O_CREAT|O_TRUNC"
            } else {
                arg(1)
            };
            model.open(&path, flags, fd);
        }
        "write" => model.write(fd_path(arg(0)).0, &unhex(arg(1)), None),
        "pwrite64" => model.write(
            fd_path(arg(0)).0,
            &unhex(arg(1)),
            Some(arg(3).parse().unwrap()),
        ),
        "writev" => {
            let fd = fd_path(arg(0)).0;
            for part in call.args[1].split("iov_base=").skip(1) {
                let end = part.find(", iov_len").unwrap();
                model.write(fd, &unhex(&part[..end]), None);
            }
        }
        "lseek" => {
            let fd = fd_path(arg(0)).0;
            if let Some(handle) = model.fds.get_mut(&fd) {
                handle.offset = call.ret.parse().unwrap();
            }
        }
        "ftruncate" => model.truncate(fd_path(arg(0)).0, arg(1).parse().unwrap()),
        "fsync" | "fdatasync" => model.sync(fd_path(arg(0)).0),
        "close" => {
            model.fds.remove(&fd_path(arg(0)).0);
        }
        "dup" | "fcntl" | "dup2" | "dup3" => {
            if call.name == "fcntl" && !arg(1).starts_with("F_DUPFD") {
                return;
            }
            let (new, _) = fd_path(&call.ret);
            if let Some(handle) = model.fds.get(&fd_path(arg(0)).0).copied() {
                model.fds.insert(new, handle);
            }
        }
        "mkdir" => model.mkdir(&resolve(&root, &unhex(arg(0)))),
        "mkdirat" => {
            let (_, dir) = fd_path(arg(0));
            model.mkdir(&resolve(&dir, &unhex(arg(1))));
        }
        "rename" => model.rename(
            &resolve(&root, &unhex(arg(0))),
            &resolve(&root, &unhex(arg(1))),
        ),
        "renameat" | "renameat2" => {
            let (_, from_dir) = fd_path(arg(0));
            let (_, to_dir) = fd_path(arg(2));
            model.rename(
                &resolve(&from_dir, &unhex(arg(1))),
                &resolve(&to_dir, &unhex(arg(3))),
            );
        }
        "unlink" | "rmdir" => model.remove(&resolve(&root, &unhex(arg(0)))),
        "unlinkat" => {
            let (_, dir) = fd_path(arg(0));
            model.remove(&resolve(&dir, &unhex(arg(1))));
        }
        other => panic!(
            "the model does not handle {other} under the root: {:?}",
            call.args
        ),
    }
}

fn traced_syscalls() -> &'static str {
    "openat,open,creat,write,pwrite64,writev,pwritev,pwritev2,lseek,ftruncate,truncate,\
     fsync,fdatasync,sync,syncfs,sync_file_range,rename,renameat,renameat2,mkdir,mkdirat,\
     unlink,unlinkat,rmdir,close,dup,dup2,dup3,fcntl,link,linkat,symlink,symlinkat,\
     fallocate,copy_file_range,sendfile"
}

fn enabled(var: &str) -> bool {
    if std::env::var_os(var).is_some() {
        return true;
    }
    eprintln!("skipped: set {var}=1 to run");
    false
}

#[test]
fn posix_crash_states() {
    if !enabled("SENTINEL_CRASH_TESTS") {
        return;
    }
    let temp = tempfile::tempdir().unwrap();
    let base = fs::canonicalize(temp.path()).unwrap();
    let root = base.join("root");
    let journal = base.join("journal");
    let trace = base.join("trace");
    prepare(&root);
    let mut model = Model::new(root.clone());
    model.seed();
    let status = Command::new("strace")
        .args(["-f", "-qq", "-y", "-xx", "-s", "1048576", "-e"])
        .arg(format!("trace={}", traced_syscalls()))
        .args(["-e", "signal=none", "-o"])
        .arg(&trace)
        .arg(std::env::current_exe().unwrap())
        .args([
            "record_crash_workload",
            "--exact",
            "--ignored",
            "--test-threads=1",
        ])
        .env("CRASH_ROOT", &root)
        .env("CRASH_JOURNAL", &journal)
        .status()
        .expect("strace runs");
    assert!(status.success(), "the traced workload failed");
    let events = read_trace(&trace, &journal);
    let golden = golden();
    let calls = events
        .iter()
        .filter(|e| matches!(e, Event::Call(_)))
        .count();
    assert!(
        events
            .iter()
            .any(|e| matches!(e, Event::Done(n) if *n == golden.ops.len())),
        "the journal did not record the whole run"
    );

    // Replay; after every call, write out each distinct crash state (its
    // contents are the model's at that moment) and hand it to a checker.
    // Scratch lives in RAM when it can: the checks resend a 4 MiB log with
    // an fsync per frame, which tmpfs makes free.
    let scratch = tempfile::Builder::new()
        .prefix("sentinel-crash")
        .tempdir_in(if Path::new("/dev/shm").is_dir() {
            Path::new("/dev/shm")
        } else {
            temp.path()
        })
        .unwrap();
    let failures: Mutex<Vec<String>> = Mutex::new(Vec::new());
    let checked = AtomicUsize::new(0);
    let threads = std::thread::available_parallelism().map_or(2, |n| n.get().min(8));
    let (send, receive) = std::sync::mpsc::sync_channel::<(Crash, usize, PathBuf)>(threads * 2);
    let receive = Mutex::new(receive);
    let mut points = 0usize;
    std::thread::scope(|scope| {
        for _ in 0..threads {
            let (receive, golden, failures, checked) = (&receive, &golden, &failures, &checked);
            scope.spawn(move || {
                loop {
                    let next = receive.lock().unwrap().recv();
                    let Ok((crash, done, dir)) = next else {
                        break;
                    };
                    for problem in verify(&dir, done, golden) {
                        failures.lock().unwrap().push(format!(
                            "{crash:?} crash after {done} done operations: {problem}"
                        ));
                    }
                    let _ = fs::remove_dir_all(&dir);
                    checked.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
            });
        }
        let mut done = 0usize;
        let mut seen = HashSet::new();
        for event in &events {
            match event {
                Event::Done(n) => done = *n,
                Event::Call(call) => replay(&mut model, call),
            }
            points += 1;
            for crash in CRASHES {
                let state = model.state(crash);
                let mut hasher = DefaultHasher::new();
                (crash, done, &state).hash(&mut hasher);
                if seen.insert(hasher.finish()) {
                    let dir = scratch.path().join(format!("s{}", seen.len()));
                    model.materialize(crash, &state, &dir);
                    send.send((crash, done, dir)).unwrap();
                }
            }
        }
        drop(send);
    });
    let checked = checked.into_inner();
    eprintln!(
        "{calls} traced calls, {points} crash points, {checked} distinct crash states checked"
    );
    let failures = failures.into_inner().unwrap();
    let distinct: BTreeSet<&str> = failures
        .iter()
        .map(|f| f.split_once(": ").map_or(f.as_str(), |(_, p)| p))
        .collect();
    assert!(
        failures.is_empty(),
        "{} of {checked} crash states break a promise; distinct problems:\n{}\nfirst: {}",
        failures.len(),
        distinct.into_iter().collect::<Vec<_>>().join("\n"),
        failures[0]
    );
}

// ------------------------------------------------------------- dm-flakey

struct Flakey {
    name: String,
    loopdev: String,
    image: PathBuf,
    sectors: u64,
}

fn sh(program: &str, args: &[&str]) {
    let output = Command::new(program).args(args).output().unwrap();
    assert!(
        output.status.success(),
        "{program} {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn sh_out(program: &str, args: &[&str]) -> String {
    let output = Command::new(program).args(args).output().unwrap();
    assert!(
        output.status.success(),
        "{program} {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}

impl Flakey {
    fn new(dir: &Path, name: &str) -> Flakey {
        let image = dir.join(format!("{name}.img"));
        fs::File::create(&image)
            .unwrap()
            .set_len(400 << 20)
            .unwrap();
        let loopdev = sh_out("losetup", &["--find", "--show", image.to_str().unwrap()]);
        let sectors: u64 = sh_out("blockdev", &["--getsz", &loopdev]).parse().unwrap();
        let flakey = Flakey {
            name: format!("sentinel-{name}-{}", std::process::id()),
            loopdev,
            image,
            sectors,
        };
        sh(
            "dmsetup",
            &["create", &flakey.name, "--table", &flakey.table(false)],
        );
        flakey
    }

    fn device(&self) -> String {
        format!("/dev/mapper/{}", self.name)
    }

    fn table(&self, drop: bool) -> String {
        if drop {
            format!(
                "0 {} flakey {} 0 0 180 1 drop_writes",
                self.sectors, self.loopdev
            )
        } else {
            format!("0 {} flakey {} 0 180 0", self.sectors, self.loopdev)
        }
    }

    /// Swap the table. `--nolockfs`: the mounted file system is not frozen,
    /// so nothing it holds in memory is flushed first.
    fn load(&self, drop: bool) {
        sh("dmsetup", &["suspend", "--nolockfs", &self.name]);
        sh(
            "dmsetup",
            &["load", &self.name, "--table", &self.table(drop)],
        );
        sh("dmsetup", &["resume", &self.name]);
    }
}

impl Drop for Flakey {
    fn drop(&mut self) {
        let _ = Command::new("dmsetup")
            .args(["remove", "--retry", &self.name])
            .status();
        let _ = Command::new("losetup").args(["-d", &self.loopdev]).status();
        let _ = fs::remove_file(&self.image);
    }
}

#[test]
fn power_cut_on_dm_flakey() {
    if !enabled("SENTINEL_POWER_LOSS_TESTS") {
        return;
    }
    let golden = golden();
    let total = golden.ops.len();
    // Every operation of the spool and the small logs, then every eighth
    // of the large one and everything after it.
    let big_start = golden
        .ops
        .iter()
        .position(|op| matches!(op, Op::StoreAppend { log: 1, .. }))
        .unwrap();
    let big_end = big_start + BIG_FRAMES as usize;
    let points: Vec<usize> = (0..total)
        .filter(|&i| i < big_start || i >= big_end || (i - big_start) % 8 == 0)
        .collect();
    let temp = tempfile::tempdir().unwrap();
    let mnt = temp.path().join("mnt");
    fs::create_dir(&mnt).unwrap();
    let mnt_s = mnt.to_str().unwrap().to_owned();
    let mut failures = Vec::new();
    for (fs_name, mkfs, options) in [
        ("ext4", vec!["mkfs.ext4", "-q", "-F"], "commit=600"),
        ("xfs", vec!["mkfs.xfs", "-q", "-f"], "defaults"),
    ] {
        for &cut in &points {
            let flakey = Flakey::new(temp.path(), fs_name);
            let device = flakey.device();
            let mut args: Vec<&str> = mkfs[1..].to_vec();
            args.push(&device);
            sh(mkfs[0], &args);
            sh("mount", &["-o", options, &device, &mnt_s]);
            let root = mnt.join("root");
            prepare(&root);
            sh("sync", &["-f", &mnt_s]);
            run_workload(&root, &golden.ops, |i, _| {
                if i == cut {
                    flakey.load(true);
                    return false;
                }
                true
            });
            sh("umount", &[&mnt_s]);
            flakey.load(false);
            sh("blockdev", &["--flushbufs", &device]);
            sh("mount", &[&device, &mnt_s]);
            for problem in verify(&root, cut + 1, &golden) {
                failures.push(format!(
                    "{fs_name}, power cut after operation {cut}: {problem}"
                ));
            }
            sh("umount", &[&mnt_s]);
        }
        eprintln!("{fs_name}: {} power cuts checked", points.len());
    }
    assert!(
        failures.is_empty(),
        "{} problems:\n{}",
        failures.len(),
        failures.join("\n")
    );
}
