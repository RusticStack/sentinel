//! Drains the outbox. A transient failure pauses the pass, so a dead service costs one connection attempt per pause, not one per message.

use std::{
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use sentinel_auth::sealed::Key;
use sentinel_core::{MailId, UnixMillis};
use sentinel_store::{
    Error as StoreError, Store,
    email::{self, Retry},
};

use crate::{Failure, Mail, Transport};

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

#[derive(Clone, Debug)]
pub struct Notice {
    pub id: MailId,
    pub kind: &'static str,
    pub outcome: String,
}

#[derive(Clone, Debug, Default)]
pub struct Batch {
    pub delivered: usize,
    pub retried: usize,
    pub abandoned: usize,
    pub entries: Vec<Notice>,
    /// Set on the pass where the lane enters or leaves a fault, never on the passes in between.
    pub health: Option<Health>,
}

const COMMIT_GAP: Duration = Duration::from_millis(50);

type Settled = (Mutex<bool>, Condvar);

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
        self.store.changes().nudge();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

enum Written {
    Done(String),
    Moved,
}

/// Why the lane cannot do its job right now. The row contents never appear: only the class.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cause {
    /// The outbox cannot be read.
    StoreRead,
    /// A settled message cannot be written back.
    StoreWrite,
    /// Expired and delivered rows cannot be purged.
    Maintenance,
    /// The mail service refuses every message the same way: the key or the sender needs the operator.
    Service,
}

impl Cause {
    pub const fn name(self) -> &'static str {
        match self {
            Cause::StoreRead => "store_read",
            Cause::StoreWrite => "store_write",
            Cause::Maintenance => "maintenance",
            Cause::Service => "service",
        }
    }
}

/// A change of state, reported once when it happens and not on every pass.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Health {
    Degraded(Cause),
    Recovered,
}

/// Tells the owner of the lane when its state changes.
fn report(
    notice: &(dyn Fn(&Batch) + Send + Sync),
    state: &mut Option<Cause>,
    now: Option<Cause>,
    batch: Option<&mut Batch>,
) {
    if *state == now {
        return;
    }
    *state = now;
    let health = Some(now.map_or(Health::Recovered, Health::Degraded));
    match batch {
        Some(batch) => batch.health = health,
        None => notice(&Batch {
            health,
            ..Batch::default()
        }),
    }
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
    let mut maintenance_failed = false;
    let mut degraded: Option<Cause> = None;
    loop {
        if stop.load(Ordering::Acquire) {
            break;
        }
        if maintained.is_none_or(|at| at.elapsed() >= config.maintenance) {
            maintenance_failed = email::purge(store, UnixMillis::now(), 256).is_err();
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
                report(notice, &mut degraded, Some(Cause::StoreRead), None);
                wait(settled, backoff(config, failures));
                continue;
            }
        };
        if due.is_empty() {
            failures = 0;
            report(
                notice,
                &mut degraded,
                maintenance_failed.then_some(Cause::Maintenance),
                None,
            );
            let deadline = wake_at(store, config, polled, maintained);
            store.changes().wait_past(seen, deadline);
            if let Some(rest) = COMMIT_GAP.min(config.idle).checked_sub(polled.elapsed()) {
                wait(settled, rest);
            }
            continue;
        }
        let mut batch = Batch::default();
        let mut pause = false;
        let mut store_failed = false;
        let mut refused_by_service = false;
        for pending in due {
            if stop.load(Ordering::Acquire) {
                break;
            }
            let (id, kind) = (pending.id, pending.kind.name());
            let now = UnixMillis::now();
            let written: Result<Written, StoreError> = if now.0 >= pending.expires_ms {
                settle_refused(store, id, "not delivered before it expired", now)
                    .inspect(|w| count(&mut batch, w))
            } else if let Some(message) = pending.open(key) {
                let mail = Mail {
                    id,
                    to: &pending.recipient,
                    subject: message.subject(),
                    body: message.body(),
                    now,
                };
                let sent = transport.send(&mail);
                // The readable copy is wiped as it drops, on every outcome.
                drop(message);
                let at = UnixMillis::now();
                match sent {
                    Ok(()) => store
                        .writer()
                        .write(move |tx| email::delivered(tx, id, at))
                        .map(|()| {
                            batch.delivered += 1;
                            Written::Done("delivered".into())
                        }),
                    Err(Failure::Transient { why, retry_after }) => {
                        pause = true;
                        let reason = why.clone();
                        let not_before_ms = retry_after
                            .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX));
                        store
                            .writer()
                            .write(move |tx| email::retry(tx, id, at, &reason, not_before_ms))
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
                    // Every message would get the same answer: leave this one as it is, send nothing else this
                    // pass, and try again after the pause. A fixed key delivers what is still queued; nothing
                    // is given up on account of a mistake that is not the message's.
                    Err(Failure::Service(_)) => {
                        pause = true;
                        refused_by_service = true;
                        Ok(Written::Moved)
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
        let cause = if store_failed {
            Some(Cause::StoreWrite)
        } else if refused_by_service {
            Some(Cause::Service)
        } else if maintenance_failed {
            Some(Cause::Maintenance)
        } else {
            None
        };
        // A pause for a provider outage is not a fault of this deployment: the rows retry on their own clock.
        if cause.is_some() || !pause {
            report(notice, &mut degraded, cause, Some(&mut batch));
        }
        if !batch.entries.is_empty() || batch.health.is_some() {
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
