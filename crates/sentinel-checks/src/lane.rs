//! The outbox lane: one bounded thread draining due publications.
//!
//! It reads a batch of due rows, hands each to the publisher, and writes the
//! outcome back in a short transaction. The lane never holds the writer while
//! a publisher is on the network. A rate limit pauses the whole lane (the
//! limit is account-wide, so continuing would only spend the next refusal);
//! store failures back off doubling to a ceiling.

use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};

use sentinel_core::{CheckId, UnixMillis};
use sentinel_store::{Store, checks};

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
    /// The whole forge is rate-limited until `until_ms`: stop this pass.
    Throttled { until_ms: i64 },
}

/// Turns one stored publication into a forge's request.
pub trait Publisher: Send {
    fn publish(&mut self, publication: &checks::Publication) -> Publish;
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
    /// Set when a rate limit stopped the pass.
    pub paused_until_ms: Option<i64>,
    pub entries: Vec<Notice>,
}

/// How the lane paces itself. Defaults: 32 publications per batch, a 250 ms
/// idle tick, and store-failure back-off from one second to thirty.
#[derive(Clone, Copy, Debug)]
pub struct Config {
    pub batch: u16,
    pub idle: Duration,
    pub min_backoff: Duration,
    pub max_backoff: Duration,
    /// Longest single sleep, so shutdown stays prompt even after a long
    /// rate-limit reset.
    pub max_pause: Duration,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            batch: 32,
            idle: Duration::from_millis(250),
            min_backoff: Duration::from_secs(1),
            max_backoff: Duration::from_secs(30),
            max_pause: Duration::from_secs(30),
        }
    }
}

/// A running lane; dropping it stops and joins the thread.
pub struct Lane {
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
            thread::Builder::new()
                .name("sentinel-checks".into())
                .spawn(move || run(&store, publisher, &config, &stop, &settled, &*notice))
                .expect("spawn checks lane")
        };
        Lane {
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
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn run(
    store: &Store,
    mut publisher: Box<dyn Publisher>,
    config: &Config,
    stop: &AtomicBool,
    settled: &(std::sync::Mutex<bool>, std::sync::Condvar),
    notice: &(dyn Fn(&Batch) + Send + Sync),
) {
    let mut failures: u32 = 0;
    while !stop.load(Ordering::Acquire) {
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
            wait(settled, config.idle);
            continue;
        }
        let mut batch = Batch::default();
        let mut pause_until: Option<i64> = None;
        let mut store_failed = false;
        for publication in due {
            if stop.load(Ordering::Acquire) {
                break;
            }
            let (id, seq, name) = (publication.id, publication.seq, publication.name.clone());
            match publisher.publish(&publication) {
                Publish::Published {
                    check_run_id,
                    check_suite_id,
                } => {
                    let now = UnixMillis::now();
                    let current = match store.writer().write(move |tx| {
                        checks::published(tx, id, seq, check_run_id, check_suite_id, now)
                    }) {
                        Ok(current) => current,
                        Err(_) => {
                            store_failed = true;
                            break;
                        }
                    };
                    batch.delivered += 1;
                    batch.entries.push(Notice {
                        id,
                        name,
                        outcome: if current {
                            "published".into()
                        } else {
                            // The handle is recorded; the newer generation is
                            // still due.
                            "published (superseded)".into()
                        },
                    });
                }
                Publish::Retry { after_ms, detail } => {
                    let now = UnixMillis::now();
                    let outcome = store
                        .writer()
                        .write(move |tx| checks::retry(tx, id, seq, now, after_ms));
                    let outcome = match outcome {
                        Ok(checks::Retry::Scheduled { .. }) => {
                            batch.retried += 1;
                            format!("retried: {}", brief(&detail))
                        }
                        // The budget is spent: the row is refused with an
                        // explicit reason rather than retried forever.
                        Ok(checks::Retry::Exhausted) => {
                            batch.refused += 1;
                            format!("refused: retry budget spent ({})", brief(&detail))
                        }
                        // The batch is dropped below; this entry never ships.
                        Err(_) => {
                            store_failed = true;
                            break;
                        }
                    };
                    batch.entries.push(Notice { id, name, outcome });
                }
                Publish::Refused { reason } => {
                    let now = UnixMillis::now();
                    let reason_text = reason.clone();
                    match store
                        .writer()
                        .write(move |tx| checks::refused(tx, id, seq, &reason_text, now))
                    {
                        Ok(_) => batch.refused += 1,
                        Err(_) => {
                            store_failed = true;
                            break;
                        }
                    }
                    batch.entries.push(Notice {
                        id,
                        name,
                        outcome: format!("refused: {}", brief(&reason)),
                    });
                }
                Publish::Throttled { until_ms } => {
                    // Park this generation too: the limit is account-wide, so
                    // the row must not be first in line when the pass resumes.
                    let now = UnixMillis::now();
                    let wait_ms = until_ms.saturating_sub(now.0);
                    let outcome = match store
                        .writer()
                        .write(move |tx| checks::retry(tx, id, seq, now, wait_ms))
                    {
                        Ok(checks::Retry::Scheduled { .. }) => "throttled",
                        // The park spent the last attempt: the row is durably
                        // refused, not parked — say what happened.
                        Ok(checks::Retry::Exhausted) => {
                            batch.refused += 1;
                            "throttled: retry budget spent, refused"
                        }
                        // The batch is dropped below; this entry never ships.
                        Err(_) => {
                            store_failed = true;
                            "store"
                        }
                    };
                    pause_until = Some(until_ms);
                    batch.entries.push(Notice {
                        id,
                        name,
                        outcome: outcome.into(),
                    });
                    break;
                }
            }
        }
        if store_failed {
            failures = failures.saturating_add(1);
            wait(settled, backoff(config, failures));
            continue;
        }
        failures = 0;
        batch.paused_until_ms = pause_until;
        notice(&batch);
        if let Some(until) = pause_until {
            // Sleep in bounded pieces so shutdown stays prompt.
            let mut remaining = until.saturating_sub(UnixMillis::now().0);
            while remaining > 0 && !stop.load(Ordering::Acquire) {
                let slice = u64::try_from(remaining)
                    .unwrap_or(u64::MAX)
                    .min(config.max_pause.as_millis() as u64)
                    .max(1);
                wait(settled, Duration::from_millis(slice));
                remaining = until.saturating_sub(UnixMillis::now().0);
            }
        }
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
