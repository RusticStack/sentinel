//! Power loss mid-fsync (C08, Part 02 gate). The store runs through a recording VFS ([`crash_vfs`]); for every point at
//! which a power cut could land (just before each sync of the database or its log returns, just after each one, and just
//! after each acknowledged write) the files that cut would leave are rebuilt, with the bytes written since each file's
//! last sync surviving in no, every or a random torn subset, and the real store is reopened on them.
//!
//! Under `Durability::Full` every acknowledged write must be visible afterwards and the one in flight must be all or
//! nothing. Under `Durability::Normal` (replayable data and tests only) the log is not synced per commit, so the same
//! cuts may lose acknowledged writes; they must still leave an intact database holding a prefix of the writes, and the
//! harness must be seen to lose some, or it proves nothing about Full.
//!
//! Scope: a cut after the database and its first migration were created (`Ack(0)`). A cut while SQLite is still creating
//! the file for the first time can leave a file that is not a database; the controller creates it once, before it
//! serves anything. A cut inside the migration of an existing database is not swept here.

mod crash_vfs;

use crash_vfs::{CrashVfs, Event, Image, Persist, image_at};
use sentinel_store::{Durability, Store};

const TXNS: u64 = 12;
const ROWS: u64 = 4;
const PAYLOAD: usize = 2_600;
/// Deterministic seeds for the random persist policy.
const SEEDS: std::ops::RangeInclusive<u64> = 1..=6;

fn payload(txn: u64, row: u64) -> Vec<u8> {
    (0..PAYLOAD)
        .map(|i| (txn * 31 + row * 7 + i as u64) as u8)
        .collect()
}

struct Run {
    events: Vec<Event>,
    /// The first write that returned an error, if any.
    failed: Option<u64>,
    /// Syncs of the database or its log after setup.
    syncs: u64,
}

fn workload(durability: Durability, fail_sync: Option<u64>) -> Run {
    let dir = tempfile::tempdir().unwrap();
    let vfs = CrashVfs::register();
    let store =
        Store::open_on_vfs(dir.path().join("metadata.sqlite"), durability, vfs.name()).unwrap();
    store
        .writer()
        .write(|tx| {
            tx.execute_batch(
                "CREATE TABLE crash_probe(id INTEGER PRIMARY KEY, txn INTEGER NOT NULL, payload BLOB NOT NULL);
                 CREATE TABLE crash_counter(id INTEGER PRIMARY KEY CHECK(id = 1), last INTEGER NOT NULL);
                 INSERT INTO crash_counter VALUES(1, 0);",
            )?;
            Ok(())
        })
        .unwrap();
    vfs.ack(0);
    // Counting restarts here; 0 only resets the count.
    vfs.fail_sync_number(fail_sync.unwrap_or(0));
    let mut failed = None;
    for txn in 1..=TXNS {
        let outcome = store.writer().write(move |tx| {
            let mut insert = tx.prepare("INSERT INTO crash_probe(txn, payload) VALUES (?1, ?2)")?;
            for row in 0..ROWS {
                insert.execute(rusqlite::params![txn as i64, payload(txn, row)])?;
            }
            drop(insert);
            tx.execute("UPDATE crash_counter SET last = ?1", [txn as i64])?;
            Ok(())
        });
        match outcome {
            Ok(()) => vfs.ack(txn),
            Err(_) => {
                failed = Some(txn);
                break;
            }
        }
        // Checkpoints move frames into the database file and reset the log: the other half of the sync traffic.
        if (txn == 6 || txn == 10) && store.checkpoint().is_err() {
            break;
        }
    }
    let syncs = vfs.syncs_seen();
    let events = vfs.events();
    // The store must close before its directory goes; the events are already copied out.
    drop(store);
    Run {
        events,
        failed,
        syncs,
    }
}

struct Recovered {
    tables: bool,
    /// The highest visible write.
    last: u64,
}

/// Reopens the real store on the rebuilt files and checks everything that holds whatever was lost.
fn recover(image: &Image) -> Result<Recovered, String> {
    if image.main.is_empty() {
        return Err("the database file did not survive".into());
    }
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("metadata.sqlite");
    std::fs::write(&path, &image.main).unwrap();
    if !image.wal.is_empty() {
        std::fs::write(dir.path().join("metadata.sqlite-wal"), &image.wal).unwrap();
    }
    let store = Store::open(&path, Durability::Full).map_err(|e| format!("reopen failed: {e}"))?;
    store
        .read(|conn| {
            let integrity: String = conn.query_row("PRAGMA integrity_check", [], |r| r.get(0))?;
            if integrity != "ok" {
                return Ok(Err(format!("integrity_check: {integrity}")));
            }
            let tables: i64 = conn.query_row(
                "SELECT count(*) FROM sqlite_master WHERE name IN ('crash_probe', 'crash_counter')",
                [],
                |r| r.get(0),
            )?;
            if tables == 0 {
                return Ok(Ok(Recovered {
                    tables: false,
                    last: 0,
                }));
            }
            if tables != 2 {
                return Ok(Err("setup is half applied".into()));
            }
            let mut rows = conn.prepare("SELECT txn, payload FROM crash_probe ORDER BY id")?;
            let found: Vec<(i64, Vec<u8>)> = rows
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
                .collect::<Result<_, _>>()?;
            let counter: i64 =
                conn.query_row("SELECT last FROM crash_counter WHERE id = 1", [], |r| {
                    r.get(0)
                })?;
            Ok(check_rows(&found, counter))
        })
        .map_err(|e| format!("read failed: {e}"))?
}

fn check_rows(found: &[(i64, Vec<u8>)], counter: i64) -> Result<Recovered, String> {
    let last = found.last().map_or(0, |(txn, _)| *txn as u64);
    if found.len() as u64 != last * ROWS {
        return Err(format!(
            "{} rows for writes up to {last}: a write is torn",
            found.len()
        ));
    }
    for (index, (txn, bytes)) in found.iter().enumerate() {
        let (expected_txn, row) = (index as u64 / ROWS + 1, index as u64 % ROWS);
        if *txn as u64 != expected_txn {
            return Err(format!(
                "write {txn} where {expected_txn} belongs: not a prefix"
            ));
        }
        if *bytes != payload(expected_txn, row) {
            return Err(format!("write {txn} row {row} holds foreign bytes"));
        }
    }
    if counter as u64 != last {
        return Err(format!(
            "counter {counter} disagrees with the rows up to {last}: a commit is torn across pages"
        ));
    }
    Ok(Recovered { tables: true, last })
}

/// Every cut worth trying after setup: either side of each sync and just after each acknowledgement.
fn cuts(events: &[Event]) -> Vec<usize> {
    let setup = events
        .iter()
        .position(|e| matches!(e, Event::Ack(0)))
        .expect("setup acknowledged");
    let mut cuts = Vec::new();
    for (index, event) in events.iter().enumerate().skip(setup) {
        match event {
            Event::Sync { .. } => cuts.extend([index, index + 1]),
            Event::Ack(_) => cuts.push(index + 1),
            _ => {}
        }
    }
    cuts.retain(|cut| *cut > setup);
    cuts.dedup();
    cuts
}

fn policies() -> Vec<Persist> {
    [Persist::Nothing, Persist::Everything]
        .into_iter()
        .chain(SEEDS.map(Persist::Chance))
        .collect()
}

fn acked_before(events: &[Event], cut: usize) -> u64 {
    events[..cut]
        .iter()
        .filter_map(|e| match e {
            Event::Ack(id) => Some(*id),
            _ => None,
        })
        .max()
        .unwrap_or(0)
}

#[derive(Default)]
struct Verdict {
    cases: usize,
    violations: Vec<String>,
    /// Cases that lost an acknowledged write (allowed only when durability is not required).
    lost: usize,
}

fn judge(events: &[Event], cut: usize, persist: Persist, require_acked: bool, v: &mut Verdict) {
    let acked = acked_before(events, cut);
    let image = image_at(events, cut, persist);
    v.cases += 1;
    match recover(&image) {
        Err(e) => v.violations.push(format!("cut {cut} {persist:?}: {e}")),
        Ok(found) => {
            let lost = !found.tables || found.last < acked;
            if lost {
                v.lost += 1;
                if require_acked {
                    v.violations.push(format!(
                        "cut {cut} {persist:?}: write {acked} was acknowledged but recovery holds {}",
                        if found.tables {
                            found.last.to_string()
                        } else {
                            "no tables".into()
                        }
                    ));
                }
            }
            // The write in flight at the cut may have landed whole; never more than one beyond the acknowledged.
            if found.last > acked + 1 {
                v.violations.push(format!(
                    "cut {cut} {persist:?}: writes up to {} exist but only {acked} were acknowledged",
                    found.last
                ));
            }
        }
    }
}

fn sweep(events: &[Event], require_acked: bool) -> Verdict {
    let mut verdict = Verdict::default();
    for cut in cuts(events) {
        for persist in policies() {
            judge(events, cut, persist, require_acked, &mut verdict);
        }
    }
    verdict
}

fn report(v: &Verdict) -> String {
    format!(
        "{} of {} cases failed:\n{}",
        v.violations.len(),
        v.cases,
        v.violations
            .iter()
            .take(12)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    )
}

#[test]
fn full_durability_keeps_every_acknowledged_write_and_makes_the_one_in_flight_atomic() {
    let run = workload(Durability::Full, None);
    assert_eq!(run.failed, None);
    let syncs = run
        .events
        .iter()
        .filter(|e| matches!(e, Event::Sync { .. }))
        .count();
    assert!(
        syncs as u64 >= TXNS,
        "every commit must sync before it is acknowledged: {syncs} syncs for {TXNS} writes"
    );
    let verdict = sweep(&run.events, true);
    assert!(
        verdict.cases >= 100,
        "a vacuous sweep: {} cases",
        verdict.cases
    );
    assert!(verdict.violations.is_empty(), "{}", report(&verdict));
}

#[test]
fn normal_durability_stays_intact_and_prefix_consistent_and_the_harness_sees_it_lose_writes() {
    let run = workload(Durability::Normal, None);
    assert_eq!(run.failed, None);
    let verdict = sweep(&run.events, false);
    assert!(verdict.violations.is_empty(), "{}", report(&verdict));
    // Control: without a sync per commit the same cuts do lose acknowledged writes. If this ever reads zero, the
    // recording VFS is not discarding unsynced bytes and the Full result above says nothing.
    assert!(
        verdict.lost > 0,
        "no cut lost an acknowledged write under Normal; the harness does not discard unsynced bytes"
    );
}

#[test]
fn a_failed_fsync_is_never_acknowledged_and_leaves_an_atomic_state() {
    let clean = workload(Durability::Full, None);
    assert!(clean.syncs >= TXNS, "{} syncs", clean.syncs);
    let mut failures = 0;
    for nth in 1..=clean.syncs {
        let run = workload(Durability::Full, Some(nth));
        let acked = acked_before(&run.events, run.events.len());
        // A write that failed was not acknowledged: the acknowledgement count stops short of it.
        if let Some(txn) = run.failed {
            failures += 1;
            assert_eq!(
                acked,
                txn - 1,
                "sync {nth} failed write {txn} yet it was acknowledged"
            );
        }
        let mut verdict = Verdict::default();
        let cut = run.events.len();
        for persist in policies() {
            judge(&run.events, cut, persist, true, &mut verdict);
        }
        assert!(
            verdict.violations.is_empty(),
            "sync {nth} failed: {}",
            report(&verdict)
        );
    }
    assert!(
        failures > 0,
        "no injected sync failure reached a write; the injection does nothing"
    );
}

mod model {
    use super::crash_vfs::{Event, File, Persist, image_at};

    fn write(offset: u64, byte: u8, len: usize) -> Event {
        Event::Write {
            file: File::Wal,
            offset,
            data: vec![byte; len],
        }
    }

    #[test]
    fn unsynced_bytes_survive_only_when_the_policy_says_so() {
        let events = [
            write(0, 1, 1024),
            Event::Sync { file: File::Wal },
            write(1024, 2, 1024),
        ];
        let lost = image_at(&events, 3, Persist::Nothing);
        assert_eq!(lost.wal, vec![1; 1024]);
        let kept = image_at(&events, 3, Persist::Everything);
        assert_eq!(kept.wal.len(), 2048);
        assert!(kept.wal[1024..].iter().all(|b| *b == 2));
        // The cut just before the sync returns: nothing of the first write is promised either.
        let mid_sync = image_at(&events, 1, Persist::Nothing);
        assert!(mid_sync.wal.is_empty());
        let after_sync = image_at(&events, 2, Persist::Nothing);
        assert_eq!(after_sync.wal, vec![1; 1024]);
    }

    #[test]
    fn a_sync_of_one_file_promises_nothing_about_the_other() {
        let events = [
            write(0, 7, 512),
            Event::Write {
                file: File::Main,
                offset: 0,
                data: vec![9; 512],
            },
            Event::Sync { file: File::Wal },
        ];
        let image = image_at(&events, 3, Persist::Nothing);
        assert_eq!(image.wal, vec![7; 512]);
        assert!(image.main.is_empty());
    }

    #[test]
    fn a_chance_cut_tears_writes_at_whole_sectors() {
        let events = [write(0, 5, 4096)];
        let mut torn = false;
        for seed in 0..64 {
            let image = image_at(&events, 1, Persist::Chance(seed));
            assert_eq!(image.wal.len() % 512, 0, "seed {seed}");
            torn |= !image.wal.is_empty() && image.wal.len() < 4096;
        }
        assert!(torn, "no seed produced a partial write");
    }
}
