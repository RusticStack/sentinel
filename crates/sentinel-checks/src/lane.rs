use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use sentinel_core::{CheckId, UnixMillis};
use sentinel_store::{Error as StoreError, Store, checks};

const QUARANTINE_AFTER: u32 = 3;
const QUARANTINE_MS: i64 = checks::MAX_DEFER_MS;
const MAX_TRACKED: usize = 1024;
/// Rows that could not even be parked durably are left out of the batch in memory for a while, and the lane
/// remembers at most this many. The due read asks for that many extra rows, so they cannot crowd out the
/// healthy ones behind them.
const SKIP_FOR: Duration = Duration::from_secs(60);
const MAX_SKIPPED: usize = 64;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Publish {
    Published {
        check_run_id: i64,
        check_suite_id: Option<i64>,
    },
    /// Transient: try again, no earlier than `after_ms` from now.
    Retry { after_ms: i64, detail: String },
    /// Permanent for this generation: recorded with a reason and not retried.
    Refused { reason: String },
    /// The publication's scope is rate-limited until `until_ms`; other scopes continue.
    Throttled { until_ms: i64, scope: u64 },
}

pub trait Publisher: Send {
    fn publish(&mut self, publication: &checks::Publication) -> Publish;

    fn scope(&self, _publication: &checks::Publication) -> u64 {
        0
    }
}

#[derive(Clone, Debug)]
pub struct Notice {
    pub id: CheckId,
    pub name: String,
    pub outcome: String,
}

#[derive(Clone, Debug, Default)]
pub struct Batch {
    pub delivered: usize,
    pub retried: usize,
    pub refused: usize,
    pub paused_until_ms: Option<i64>,
    /// Rows whose store writes kept failing and that were set aside (parked for an hour, or skipped in memory
    /// when even parking failed).
    pub quarantined: usize,
    /// Rows that could not be decoded and were parked by their raw key.
    pub corrupt_parked: usize,
    /// The store began failing: reported once, not on every back-off round.
    pub store_unavailable: bool,
    /// The store answered again after a failure.
    pub store_recovered: bool,
    pub entries: Vec<Notice>,
}

const COMMIT_GAP: Duration = Duration::from_millis(50);

#[derive(Clone, Copy, Debug)]
pub struct Config {
    pub batch: u16,
    pub idle: Duration,
    pub min_backoff: Duration,
    pub max_backoff: Duration,
    pub rearm_interval: Duration,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            batch: 32,
            idle: Duration::from_secs(2),
            min_backoff: Duration::from_secs(1),
            max_backoff: Duration::from_secs(30),
            rearm_interval: Duration::from_secs(60 * 60),
        }
    }
}

pub struct Lane {
    store: Arc<Store>,
    stop: Arc<AtomicBool>,
    settled: Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>,
    thread: Option<thread::JoinHandle<()>>,
}

impl Lane {
    pub fn start(
        store: Arc<Store>,
        publisher: Box<dyn Publisher>,
        config: Config,
        notice: impl Fn(&Batch) + Send + Sync + 'static,
    ) -> Lane {
        let stop = Arc::new(AtomicBool::new(false));
        let settled = Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
        let notice: Arc<dyn Fn(&Batch) + Send + Sync> = Arc::new(notice);
        let thread = {
            let (stop, settled) = (Arc::clone(&stop), Arc::clone(&settled));
            let notice = Arc::clone(&notice);
            let store = Arc::clone(&store);
            thread::Builder::new()
                .name("sentinel-checks".into())
                .spawn(move || run(&store, publisher, &config, &stop, &settled, &*notice))
                .expect("spawn checks lane")
        };
        Lane {
            store,
            stop,
            settled,
            thread: Some(thread),
        }
    }
}

impl Drop for Lane {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        let (lock, cv) = &*self.settled;
        *lock.lock().unwrap_or_else(|p| p.into_inner()) = true;
        cv.notify_all();
        self.store.changes().nudge();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

enum Fault {
    Moved,
    Down,
    Quarantined,
    /// Parking the row failed too; it is left out of the batch in memory instead.
    Skipped,
}

#[derive(Default)]
struct Poison {
    strikes: HashMap<CheckId, u32>,
    skipped: HashMap<CheckId, Instant>,
}

fn store_fault(
    store: &Store,
    poison: &mut Poison,
    id: CheckId,
    seq: i64,
    error: &StoreError,
) -> Fault {
    if error.is_transient() {
        return Fault::Down;
    }
    match error {
        StoreError::Conflict => return Fault::Moved,
        StoreError::Sqlite(_)
        | StoreError::Corrupt(_)
        | StoreError::InvalidInput(_)
        | StoreError::NotFound
        | StoreError::WriterPanicked => {}
        _ => return Fault::Down,
    }
    if poison.strikes.len() >= MAX_TRACKED && !poison.strikes.contains_key(&id) {
        poison.strikes.clear();
    }
    let count = poison.strikes.entry(id).or_insert(0);
    *count += 1;
    if *count < QUARANTINE_AFTER {
        return Fault::Down;
    }
    poison.strikes.remove(&id);
    let now = UnixMillis::now();
    match store
        .writer()
        .write(move |tx| checks::defer(tx, id, seq, now, now.0.saturating_add(QUARANTINE_MS)))
    {
        Ok(_) => Fault::Quarantined,
        // The store is busy or gone, which says nothing about this row.
        Err(error) if error.is_transient() => Fault::Down,
        // A row that rejects even the write that parks it would stay at the head of the queue and be
        // retried before every healthy row. Leave it out of the batch in memory instead.
        Err(_) if poison.skipped.len() < MAX_SKIPPED || poison.skipped.contains_key(&id) => {
            poison.skipped.insert(id, Instant::now() + SKIP_FOR);
            Fault::Skipped
        }
        Err(_) => Fault::Down,
    }
}

/// The store began failing: say so once, however many back-off rounds follow.
fn store_failed(failures: &mut u32, notice: &(dyn Fn(&Batch) + Send + Sync)) {
    *failures = failures.saturating_add(1);
    if *failures == 1 {
        notice(&Batch {
            store_unavailable: true,
            ..Batch::default()
        });
    }
}

fn store_recovered(failures: &mut u32, notice: &(dyn Fn(&Batch) + Send + Sync)) {
    if std::mem::take(failures) > 0 {
        notice(&Batch {
            store_recovered: true,
            ..Batch::default()
        });
    }
}

fn rearm(store: &Store) {
    let now = UnixMillis::now();
    let _ = store
        .writer()
        .write(move |tx| checks::rearm_exhausted(tx, now, checks::REARM_LIMIT));
}

fn run(
    store: &Store,
    mut publisher: Box<dyn Publisher>,
    config: &Config,
    stop: &AtomicBool,
    settled: &(std::sync::Mutex<bool>, std::sync::Condvar),
    notice: &(dyn Fn(&Batch) + Send + Sync),
) {
    rearm(store);
    let mut next_rearm = Instant::now() + config.rearm_interval;
    let mut failures: u32 = 0;
    let mut parked: HashMap<u64, i64> = HashMap::new();
    let mut poison = Poison::default();
    loop {
        let seen = store.changes().generation();
        if stop.load(Ordering::Acquire) {
            break;
        }
        let polled = Instant::now();
        if polled >= next_rearm {
            // Whether the batch succeeds or fails, the next pass is one interval away.
            rearm(store);
            next_rearm = Instant::now() + config.rearm_interval;
        }
        poison.skipped.retain(|_, until| *until > polled);
        let limit = config
            .batch
            .saturating_add(u16::try_from(poison.skipped.len()).unwrap_or(u16::MAX));
        let due = match store.read(|c| checks::due(c, UnixMillis::now(), limit)) {
            Ok(due) => due,
            Err(_) => {
                store_failed(&mut failures, notice);
                wait(settled, backoff(config, failures));
                continue;
            }
        };
        let checks::Due {
            publications: mut due,
            corrupt,
        } = due;
        let fetched = due.len();
        if !poison.skipped.is_empty() {
            due.retain(|publication| !poison.skipped.contains_key(&publication.id));
        }
        let hidden = due.len() != fetched;
        let mut corrupt_parked = 0;
        if !corrupt.is_empty() {
            let now = UnixMillis::now();
            let until = now.0.saturating_add(QUARANTINE_MS);
            let count = corrupt.len();
            if store
                .writer()
                .write(move |tx| {
                    for id in &corrupt {
                        checks::defer_raw(tx, id, now, until)?;
                    }
                    Ok(())
                })
                .is_err()
            {
                store_failed(&mut failures, notice);
                wait(settled, backoff(config, failures));
                continue;
            }
            corrupt_parked = count;
        }
        if due.is_empty() {
            store_recovered(&mut failures, notice);
            if corrupt_parked > 0 {
                notice(&Batch {
                    corrupt_parked,
                    ..Batch::default()
                });
            }
            // Rows held back in memory are still due in the store, so they must not shorten the sleep.
            let deadline = if hidden {
                (polled + config.idle).min(next_rearm)
            } else {
                wake_at(store, config, polled, next_rearm)
            };
            store.changes().wait_past(seen, deadline);
            if let Some(rest) = COMMIT_GAP.min(config.idle).checked_sub(polled.elapsed()) {
                wait(settled, rest);
            }
            continue;
        }
        let pass_start = UnixMillis::now();
        parked.retain(|_, until| *until > pass_start.0);
        let mut batch = Batch {
            corrupt_parked,
            ..Batch::default()
        };
        let mut pause_until: Option<i64> = None;
        let mut write_failed = false;
        let mut skipped: Vec<(CheckId, i64, i64)> = Vec::new();
        for publication in due {
            if stop.load(Ordering::Acquire) {
                break;
            }
            let (id, seq, name) = (publication.id, publication.seq, publication.name.clone());
            if let Some(&until) = parked.get(&publisher.scope(&publication)) {
                skipped.push((id, seq, until));
                continue;
            }
            let outcome: Result<String, StoreError> = match publisher.publish(&publication) {
                Publish::Published {
                    check_run_id,
                    check_suite_id,
                } => {
                    let now = UnixMillis::now();
                    store
                        .writer()
                        .write(move |tx| {
                            checks::published(tx, id, seq, check_run_id, check_suite_id, now)
                        })
                        .map(|current| {
                            batch.delivered += 1;
                            if current {
                                "published".to_owned()
                            } else {
                                "published (superseded)".to_owned()
                            }
                        })
                }
                Publish::Retry { after_ms, detail } => {
                    let now = UnixMillis::now();
                    store
                        .writer()
                        .write(move |tx| checks::retry(tx, id, seq, now, after_ms))
                        .map(|retry| match retry {
                            checks::Retry::Scheduled { .. } => {
                                batch.retried += 1;
                                format!("retried: {}", brief(&detail))
                            }
                            checks::Retry::Exhausted => {
                                batch.refused += 1;
                                format!("refused: retry budget spent ({})", brief(&detail))
                            }
                        })
                }
                Publish::Refused { reason } => {
                    let now = UnixMillis::now();
                    let reason_text = reason.clone();
                    store
                        .writer()
                        .write(move |tx| checks::refused(tx, id, seq, &reason_text, now))
                        .map(|()| {
                            batch.refused += 1;
                            format!("refused: {}", brief(&reason))
                        })
                }
                Publish::Throttled { until_ms, scope } => {
                    let now = UnixMillis::now();
                    let until = until_ms.min(now.0.saturating_add(checks::MAX_DEFER_MS));
                    let reset = parked.entry(scope).or_insert(until);
                    *reset = (*reset).max(until);
                    pause_until = Some(pause_until.map_or(until, |p| p.max(until)));
                    store
                        .writer()
                        .write(move |tx| checks::defer(tx, id, seq, now, until))
                        .map(|_| "throttled".to_owned())
                }
            };
            match outcome {
                Ok(outcome) => {
                    poison.strikes.remove(&id);
                    batch.entries.push(Notice { id, name, outcome });
                }
                Err(error) => match store_fault(store, &mut poison, id, seq, &error) {
                    Fault::Moved => {}
                    Fault::Quarantined => {
                        batch.quarantined += 1;
                        batch.entries.push(Notice {
                            id,
                            name,
                            outcome: "quarantined: store writes kept failing".into(),
                        });
                    }
                    Fault::Skipped => {
                        batch.quarantined += 1;
                        batch.entries.push(Notice {
                            id,
                            name,
                            outcome: "quarantined: row cannot be written, skipped for now".into(),
                        });
                    }
                    Fault::Down => {
                        write_failed = true;
                        break;
                    }
                },
            }
        }
        if !skipped.is_empty() && !write_failed {
            let now = UnixMillis::now();
            if store
                .writer()
                .write(move |tx| {
                    for (id, seq, until) in &skipped {
                        checks::defer(tx, *id, *seq, now, *until)?;
                    }
                    Ok(())
                })
                .is_err()
            {
                write_failed = true;
            }
        }
        if write_failed {
            store_failed(&mut failures, notice);
            wait(settled, backoff(config, failures));
            continue;
        }
        store_recovered(&mut failures, notice);
        batch.paused_until_ms = pause_until;
        if !batch.entries.is_empty() || pause_until.is_some() || batch.corrupt_parked > 0 {
            notice(&batch);
        }
    }
}

fn wake_at(store: &Store, config: &Config, from: Instant, next_rearm: Instant) -> Instant {
    let ceiling = (from + config.idle).min(next_rearm);
    match store.read(checks::next_due_ms) {
        Ok(Some(due_ms)) => {
            let wait_ms = due_ms.saturating_sub(UnixMillis::now().0).max(0) as u64;
            (from + Duration::from_millis(wait_ms)).min(ceiling)
        }
        _ => ceiling,
    }
}

fn backoff(config: &Config, failures: u32) -> Duration {
    config
        .min_backoff
        .saturating_mul(1u32 << failures.min(5))
        .min(config.max_backoff)
}

fn brief(detail: &str) -> String {
    detail
        .chars()
        .filter(|c| !c.is_control())
        .take(120)
        .collect()
}

fn wait(settled: &(std::sync::Mutex<bool>, std::sync::Condvar), timeout: Duration) {
    let (lock, cv) = settled;
    let settled = lock.lock().unwrap_or_else(|p| p.into_inner());
    if *settled {
        return;
    }
    let (mut settled, _) = cv
        .wait_timeout(settled, timeout)
        .unwrap_or_else(|p| p.into_inner());
    *settled = false;
}

#[cfg(test)]
mod tests {
    use sentinel_store::Durability;

    use super::*;

    #[test]
    fn transient_database_faults_do_not_count_toward_quarantine() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("metadata.sqlite"), Durability::Normal).unwrap();
        let error = StoreError::Sqlite(rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_BUSY),
            None,
        ));
        let mut poison = Poison::default();
        let id = CheckId::new();
        for _ in 0..=QUARANTINE_AFTER {
            assert!(matches!(
                store_fault(&store, &mut poison, id, 1, &error),
                Fault::Down
            ));
        }
        assert!(poison.strikes.is_empty());
        assert!(poison.skipped.is_empty());
    }
}
