//! The mail lane: one bounded thread draining the outbox.
//!
//! It reads a batch of due messages, opens each (the body is sealed with the
//! master key), hands it to the transport, and writes the outcome back in a
//! short transaction. It never holds the writer while a relay is on the
//! network, and it never sends from a request handler: a handler only writes
//! the row.
//!
//! The lane does not poll. It sleeps on the store's commit notifier and a
//! deadline at the earliest pending message's retry time. A transient failure
//! (relay down, slow, or misconfigured) schedules the message again with
//! doubling backoff under the row's attempt budget and pauses the pass, so a
//! dead relay costs one connection attempt per pause rather than one per
//! queued message. A refusal of the message itself is recorded and not
//! retried. A message the lane cannot open (its key was retired) is given up.
//! Maintenance (expiring undelivered rows, deleting week-old settled rows and
//! tokens) runs from here, on its own cadence.

use std::{
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use sentinel_auth::{sealed::Key, secret::wipe_string};
use sentinel_core::{MailId, UnixMillis};
use sentinel_store::{
    Error as StoreError, Store,
    email::{self, Retry},
};

use crate::smtp::{Failure, Mail, Transport};

/// How the lane paces itself: 16 messages per pass, a 10 s safety re-read
/// (the net for a write the notifier cannot see), failure backoff from one
/// second to a minute, maintenance every ten minutes.
#[derive(Clone, Copy, Debug)]
pub struct Config {
    pub batch: u16,
    pub idle: Duration,
    pub min_backoff: Duration,
    pub max_backoff: Duration,
    pub maintenance: Duration,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            batch: 16,
            idle: Duration::from_secs(10),
            min_backoff: Duration::from_secs(1),
            max_backoff: Duration::from_secs(60),
            maintenance: Duration::from_secs(600),
        }
    }
}

/// One message the lane settled or rescheduled, for the caller's
/// diagnostics. It never names the recipient.
#[derive(Clone, Debug)]
pub struct Notice {
    pub id: MailId,
    pub kind: &'static str,
    pub outcome: String,
}

/// One pass's results.
#[derive(Clone, Debug, Default)]
pub struct Batch {
    pub delivered: usize,
    pub retried: usize,
    pub abandoned: usize,
    pub entries: Vec<Notice>,
}

/// The least time between two reads of the outbox that commits (not the
/// clock) asked for.
const COMMIT_GAP: Duration = Duration::from_millis(50);

type Settled = (Mutex<bool>, Condvar);

/// A running lane; dropping it stops and joins the thread.
pub struct Lane {
    store: Arc<Store>,
    stop: Arc<AtomicBool>,
    settled: Arc<Settled>,
    thread: Option<thread::JoinHandle<()>>,
}

impl Lane {
    pub fn start(
        store: Arc<Store>,
        key: Arc<Key>,
        transport: Box<dyn Transport>,
        config: Config,
        notice: impl Fn(&Batch) + Send + Sync + 'static,
    ) -> Lane {
        let stop = Arc::new(AtomicBool::new(false));
        let settled: Arc<Settled> = Arc::new((Mutex::new(false), Condvar::new()));
        let thread = {
            let (stop, settled) = (Arc::clone(&stop), Arc::clone(&settled));
            let store = Arc::clone(&store);
            thread::Builder::new()
                .name("sentinel-mail".into())
                .spawn(move || run(&store, &key, transport, &config, &stop, &settled, &notice))
                .expect("spawn mail lane")
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

/// What the write-back of one message's outcome meant.
enum Written {
    Done(String),
    /// The row moved on (settled by another path): nothing to record.
    Moved,
}

fn run(
    store: &Store,
    key: &Key,
    mut transport: Box<dyn Transport>,
    config: &Config,
    stop: &AtomicBool,
    settled: &Settled,
    notice: &(dyn Fn(&Batch) + Send + Sync),
) {
    let mut failures: u32 = 0;
    let mut maintained: Option<Instant> = None;
    loop {
        if stop.load(Ordering::Acquire) {
            break;
        }
        if maintained.is_none_or(|at| at.elapsed() >= config.maintenance) {
            let _ = email::purge(store, UnixMillis::now(), 256);
            maintained = Some(Instant::now());
        }
        // Read before the stop flag and the outbox: a commit or a shutdown
        // after this point moves it, so the sleep below returns at once.
        let seen = store.changes().generation();
        if stop.load(Ordering::Acquire) {
            break;
        }
        let polled = Instant::now();
        let due = match store.read(|c| email::due(c, UnixMillis::now(), config.batch)) {
            Ok(due) => due,
            Err(_) => {
                failures = failures.saturating_add(1);
                wait(settled, backoff(config, failures));
                continue;
            }
        };
        if due.is_empty() {
            failures = 0;
            let deadline = wake_at(store, config, polled, maintained);
            store.changes().wait_past(seen, deadline);
            // Unrelated commits wake the lane too: coalesce them, so a storm
            // of other writes costs at most one indexed read per interval.
            if let Some(rest) = COMMIT_GAP.min(config.idle).checked_sub(polled.elapsed()) {
                wait(settled, rest);
            }
            continue;
        }
        let mut batch = Batch::default();
        let mut pause = false;
        let mut store_failed = false;
        for pending in due {
            if stop.load(Ordering::Acquire) {
                break;
            }
            let (id, kind) = (pending.id, pending.kind.name());
            let now = UnixMillis::now();
            let written: Result<Written, StoreError> = if now.0 >= pending.expires_ms {
                settle_refused(store, id, "not delivered before it expired", now)
                    .inspect(|w| count(&mut batch, w))
            } else if let Some(mut message) = pending.open(key) {
                let mail = Mail {
                    id,
                    to: &pending.recipient,
                    subject: &message.subject,
                    body: &message.body,
                    now,
                };
                let sent = transport.send(&mail);
                // The body carries a one-time link.
                wipe_string(&mut message.body);
                let at = UnixMillis::now();
                match sent {
                    Ok(()) => store
                        .writer()
                        .write(move |tx| email::delivered(tx, id, at))
                        .map(|()| {
                            batch.delivered += 1;
                            Written::Done("delivered".into())
                        }),
                    Err(Failure::Transient(why)) => {
                        pause = true;
                        let reason = why.clone();
                        store
                            .writer()
                            .write(move |tx| email::retry(tx, id, at, &reason))
                            .map(|retry| match retry {
                                Retry::Scheduled { attempts, .. } => {
                                    batch.retried += 1;
                                    Written::Done(format!("retry {attempts}: {why}"))
                                }
                                Retry::GaveUp => {
                                    batch.abandoned += 1;
                                    Written::Done(format!("abandoned after retries: {why}"))
                                }
                            })
                    }
                    Err(Failure::Permanent(why)) => {
                        settle_refused(store, id, &why, at).inspect(|w| count(&mut batch, w))
                    }
                }
            } else {
                settle_refused(store, id, "the sealed body cannot be opened", now)
                    .inspect(|w| count(&mut batch, w))
            };
            match written {
                Ok(Written::Done(outcome)) => batch.entries.push(Notice { id, kind, outcome }),
                Ok(Written::Moved) => {}
                Err(StoreError::Conflict) => {}
                Err(_) => {
                    store_failed = true;
                    break;
                }
            }
            if pause {
                break;
            }
        }
        if store_failed || pause {
            failures = failures.saturating_add(1);
        } else {
            failures = 0;
        }
        if !batch.entries.is_empty() {
            notice(&batch);
        }
        if store_failed || pause {
            wait(settled, backoff(config, failures));
        }
    }
}

fn count(batch: &mut Batch, written: &Written) {
    if matches!(written, Written::Done(_)) {
        batch.abandoned += 1;
    }
}

fn settle_refused(
    store: &Store,
    id: MailId,
    why: &str,
    at: UnixMillis,
) -> Result<Written, StoreError> {
    let reason = why.to_owned();
    match store
        .writer()
        .write(move |tx| email::give_up(tx, id, &reason, at))
    {
        Ok(()) => Ok(Written::Done(format!("refused: {why}"))),
        Err(StoreError::Conflict) => Ok(Written::Moved),
        Err(error) => Err(error),
    }
}

/// When an idle lane must read the outbox again without a commit: at the
/// earliest pending message's retry time, at its next maintenance, and never
/// later than `idle` from `from`.
fn wake_at(store: &Store, config: &Config, from: Instant, maintained: Option<Instant>) -> Instant {
    let mut ceiling = from + config.idle;
    if let Some(at) = maintained {
        ceiling = ceiling.min(at + config.maintenance);
    }
    match store.read(email::next_due_ms) {
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
        .saturating_mul(1u32 << failures.min(6))
        .min(config.max_backoff)
}

/// Wait until the timeout, or until the lane is asked to stop.
fn wait(settled: &Settled, timeout: Duration) {
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
