//! The outbox lane: one bounded thread draining due publications.
//!
//! It reads a batch of due rows, hands each to the publisher, and writes the
//! outcome back in a short transaction. The lane never holds the writer while
//! a publisher is on the network. A rate limit parks one *scope* (for GitHub,
//! one installation: the limit is per installation) until it resets: rows of
//! that scope are deferred without spending an attempt, while every other
//! scope keeps flowing. Store failures back off doubling to a ceiling, and a
//! row whose store write keeps failing is quarantined for an hour so one
//! poison row can never hold the head of the queue.

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

/// Consecutive failed store writes for one row before it is quarantined.
const QUARANTINE_AFTER: u32 = 3;
/// How long a quarantined row waits before the lane tries it again.
const QUARANTINE_MS: i64 = checks::MAX_DEFER_MS;
/// Rows the failure counter tracks at once; beyond it the oldest entries go.
const MAX_TRACKED: usize = 1024;

/// What one publication attempt did. The publisher decides what is retryable;
/// the store decides what is durable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Publish {
    /// Delivered: the forge's own check-run handle, and the suite it landed
    /// in when the forge named one.
    Published {
        check_run_id: i64,
        check_suite_id: Option<i64>,
    },
    /// Transient: try again, no earlier than `after_ms` from now.
    Retry { after_ms: i64, detail: String },
    /// Permanent for this generation: recorded with a reason and not retried.
    Refused { reason: String },
    /// The publication's [`Publisher::scope`] is rate-limited until
    /// `until_ms`: its rows are parked until then, other scopes continue.
    Throttled { until_ms: i64, scope: u64 },
}

/// Turns one stored publication into a forge's request.
pub trait Publisher: Send {
    fn publish(&mut self, publication: &checks::Publication) -> Publish;

    /// The rate-limit domain a publication belongs to. Rows that share a
    /// scope share a limit: when one is [`Publish::Throttled`] the lane skips
    /// the rest of that scope until the limit resets. The default is one
    /// scope for everything.
    fn scope(&self, _publication: &checks::Publication) -> u64 {
        0
    }
}

/// One publication the lane settled, for the caller's diagnostics.
#[derive(Clone, Debug)]
pub struct Notice {
    pub id: CheckId,
    pub name: String,
    pub outcome: String,
}

/// One pass's settlements.
#[derive(Clone, Debug, Default)]
pub struct Batch {
    pub delivered: usize,
    pub retried: usize,
    pub refused: usize,
    /// Set when a rate limit parked a scope during the pass: the latest
    /// reset among the scopes it parked.
    pub paused_until_ms: Option<i64>,
    pub entries: Vec<Notice>,
}

/// The least time between two reads of the outbox that commits (not the
/// clock) asked for: a storm of unrelated writes costs the lane at most one
/// indexed read per interval. The first commit after a quiet spell is read at
/// once, since the interval is measured from the previous read.
const COMMIT_GAP: Duration = Duration::from_millis(50);

/// How the lane paces itself. Defaults: 32 publications per batch, a 2 s
/// safety re-read, and store-failure back-off from one second to thirty.
///
/// The lane does not poll. It sleeps on the store's commit notifier and a
/// deadline at the earliest pending row's retry time, so a new publication is
/// read when its transaction commits and a backed-off one exactly when it is
/// due. `idle` is only the longest it sleeps without reading: the net for a
/// write the notifier cannot see (another process on the same database).
#[derive(Clone, Copy, Debug)]
pub struct Config {
    pub batch: u16,
    pub idle: Duration,
    pub min_backoff: Duration,
    pub max_backoff: Duration,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            batch: 32,
            idle: Duration::from_secs(2),
            min_backoff: Duration::from_secs(1),
            max_backoff: Duration::from_secs(30),
        }
    }
}

/// A running lane; dropping it stops and joins the thread.
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
        // The lane may be parked on the commit notifier rather than the
        // condvar above.
        self.store.changes().nudge();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// What a failed store write means for the lane.
enum Fault {
    /// The row moved on while the publisher held it: nothing to record.
    Moved,
    /// The writer or database is unavailable: stop the pass and back off.
    Down,
    /// This row's writes kept failing, so it was parked; carry on.
    Quarantined,
}

/// Classify one failed write for row `id` at `seq`. A failure that can belong
/// to the row itself (a constraint, a corrupt value) is counted: after
/// [`QUARANTINE_AFTER`] in a row the row is parked for [`QUARANTINE_MS`], so
/// it cannot sit at the head of the queue and block every other check.
/// Anything that says the writer or database is down backs the lane off.
fn store_fault(
    store: &Store,
    poison: &mut HashMap<CheckId, u32>,
    id: CheckId,
    seq: i64,
    error: &StoreError,
) -> Fault {
    match error {
        StoreError::Conflict => return Fault::Moved,
        StoreError::Sqlite(_)
        | StoreError::Corrupt(_)
        | StoreError::InvalidInput(_)
        | StoreError::NotFound
        | StoreError::WriterPanicked => {}
        _ => return Fault::Down,
    }
    if poison.len() >= MAX_TRACKED && !poison.contains_key(&id) {
        poison.clear();
    }
    let count = poison.entry(id).or_insert(0);
    *count += 1;
    if *count < QUARANTINE_AFTER {
        return Fault::Down;
    }
    poison.remove(&id);
    let now = UnixMillis::now();
    match store
        .writer()
        .write(move |tx| checks::defer(tx, id, seq, now, now.0.saturating_add(QUARANTINE_MS)))
    {
        Ok(_) => Fault::Quarantined,
        Err(_) => Fault::Down,
    }
}

/// A final status that spent its budget in an earlier outage is owed again:
/// once per start the lane puts such rows back in the queue (bounded by the
/// store's window and limit). A failed write leaves them refused, and the
/// next start tries again.
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
    let mut failures: u32 = 0;
    // Rate-limit scopes and when each resets; rows of a parked scope are
    // deferred instead of being sent into a limit that is known to be spent.
    let mut parked: HashMap<u64, i64> = HashMap::new();
    let mut poison: HashMap<CheckId, u32> = HashMap::new();
    loop {
        // The generation is read before the stop flag and before the read of
        // the outbox: a commit or a shutdown after this point moves it, so
        // the sleep below returns at once instead of missing it.
        let seen = store.changes().generation();
        if stop.load(Ordering::Acquire) {
            break;
        }
        let polled = Instant::now();
        let due = match store.read(|c| checks::due(c, UnixMillis::now(), config.batch)) {
            Ok(due) => due,
            Err(_) => {
                failures = failures.saturating_add(1);
                wait(settled, backoff(config, failures));
                continue;
            }
        };
        if due.is_empty() {
            failures = 0;
            let deadline = wake_at(store, config, polled);
            store.changes().wait_past(seen, deadline);
            // Unrelated commits wake the lane too: coalesce them.
            if let Some(rest) = COMMIT_GAP.min(config.idle).checked_sub(polled.elapsed()) {
                wait(settled, rest);
            }
            continue;
        }
        let pass_start = UnixMillis::now();
        parked.retain(|_, until| *until > pass_start.0);
        let mut batch = Batch::default();
        let mut pause_until: Option<i64> = None;
        let mut store_failed = false;
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
                                // The handle is recorded; the newer generation
                                // is still due.
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
                            // The budget is spent: the row is refused with an
                            // explicit reason rather than retried forever.
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
                    // Park the scope, and this row with it, without spending
                    // an attempt: a rate limit says nothing about the row.
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
                    poison.remove(&id);
                    batch.entries.push(Notice { id, name, outcome });
                }
                Err(error) => match store_fault(store, &mut poison, id, seq, &error) {
                    Fault::Moved => {}
                    Fault::Quarantined => {
                        batch.entries.push(Notice {
                            id,
                            name,
                            outcome: "quarantined: store writes kept failing".into(),
                        });
                    }
                    // The batch is dropped below; this entry never ships.
                    Fault::Down => {
                        store_failed = true;
                        break;
                    }
                },
            }
        }
        if !skipped.is_empty() && !store_failed {
            // One transaction parks every row the limit skipped, so they
            // leave the head of the queue and others get their turn.
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
                store_failed = true;
            }
        }
        if store_failed {
            failures = failures.saturating_add(1);
            wait(settled, backoff(config, failures));
            continue;
        }
        failures = 0;
        batch.paused_until_ms = pause_until;
        if !batch.entries.is_empty() || pause_until.is_some() {
            notice(&batch);
        }
    }
}

/// When an idle lane must read the outbox again without a commit: at the
/// earliest pending row's retry time, and never later than `idle` from
/// `from`.
fn wake_at(store: &Store, config: &Config, from: Instant) -> Instant {
    let ceiling = from + config.idle;
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

/// One bounded, control-free diagnostic line.
fn brief(detail: &str) -> String {
    detail
        .chars()
        .filter(|c| !c.is_control())
        .take(120)
        .collect()
}

/// Wait until the timeout, or until the lane is asked to stop.
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
