//! The bounded resolution lane (G02/G03).
//!
//! One thread drains work in two phases. **Validation** settles pending
//! deliveries against the source binding inside one writer transaction.
//! **Dispatch** then takes ready deliveries, one at a time, through the
//! resolver — which does its Git and HTTP work outside any transaction and
//! ends in a short write — and wakes the dispatcher for every run it creates.
//!
//! A wake from an accepted delivery shortens the wait and the idle tick is the
//! safety net for a missed wake; store failures back off doubling to a
//! ceiling rather than spinning, and shutdown joins the thread.

use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};

use sentinel_core::{DeliveryId, UnixMillis};
use sentinel_store::{Store, intake};

use crate::resolve::{Outcome, Resolver};

/// How the lane paces itself. Defaults: 64 deliveries per batch, a 250 ms
/// idle tick, and failure back-off from one second to thirty.
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
            batch: 64,
            idle: Duration::from_millis(250),
            min_backoff: Duration::from_secs(1),
            max_backoff: Duration::from_secs(30),
        }
    }
}

/// One delivery the lane settled, with its readable outcome.
#[derive(Clone, Debug)]
pub struct Settled {
    pub id: DeliveryId,
    pub outcome: String,
}

/// One pass's settlements, for the caller's diagnostics.
#[derive(Clone, Debug, Default)]
pub struct Batch {
    pub settled: Vec<Settled>,
    /// Permanent failures: the delivery is terminal with an explicit reason.
    pub failed: usize,
    /// Transient faults: the delivery stays open with a scheduled attempt.
    pub retried: usize,
}

/// Wake the lane from another thread. Cheap to clone; the intake route holds
/// one so an accepted delivery is resolved without waiting for the tick.
#[derive(Clone)]
pub struct Waker {
    state: Arc<(Mutex<bool>, std::sync::Condvar)>,
}

impl Waker {
    fn new() -> Waker {
        Waker {
            state: Arc::new((Mutex::new(false), std::sync::Condvar::new())),
        }
    }

    pub fn wake(&self) {
        let (flag, cv) = &*self.state;
        *flag.lock().unwrap_or_else(|p| p.into_inner()) = true;
        cv.notify_one();
    }

    /// Block until woken or `timeout` passes. A wake that arrived before the
    /// wait is not lost.
    fn wait(&self, timeout: Duration) {
        let (flag, cv) = &*self.state;
        let mut flag = flag.lock().unwrap_or_else(|p| p.into_inner());
        if *flag {
            *flag = false;
            return;
        }
        let (mut flag, _) = cv
            .wait_timeout(flag, timeout)
            .unwrap_or_else(|p| p.into_inner());
        *flag = false;
    }
}

/// A running lane; dropping it stops and joins the thread.
pub struct Lane {
    stop: Arc<AtomicBool>,
    waker: Waker,
    thread: Option<thread::JoinHandle<()>>,
}

impl Lane {
    /// Start the lane. Without a resolver it only validates (G02's behavior);
    /// `wake` is called after every dispatched run so the dispatcher places it
    /// immediately.
    pub fn start(
        store: Arc<Store>,
        resolver: Option<Arc<Resolver>>,
        wake: Option<Arc<dyn Fn() + Send + Sync>>,
        config: Config,
        notice: impl Fn(&Batch) + Send + Sync + 'static,
    ) -> Lane {
        let stop = Arc::new(AtomicBool::new(false));
        let waker = Waker::new();
        let notice: Arc<dyn Fn(&Batch) + Send + Sync> = Arc::new(notice);
        let thread = {
            let (stop, waker) = (Arc::clone(&stop), waker.clone());
            let notice = Arc::clone(&notice);
            thread::Builder::new()
                .name("sentinel-intake".into())
                .spawn(move || {
                    let mut failures: u32 = 0;
                    while !stop.load(Ordering::Acquire) {
                        match validate(&store, &config) {
                            Ok(Some(batch)) => {
                                failures = 0;
                                notice(&batch);
                                continue;
                            }
                            Ok(None) => {}
                            Err(()) => {
                                failures = failures.saturating_add(1);
                                waker.wait(backoff(&config, failures));
                                continue;
                            }
                        }
                        let Some(resolver) = &resolver else {
                            failures = 0;
                            waker.wait(config.idle);
                            continue;
                        };
                        match dispatch(&store, resolver, wake.as_deref(), &config) {
                            Ok(Some(batch)) => {
                                failures = 0;
                                notice(&batch);
                                continue;
                            }
                            Ok(None) => {
                                failures = 0;
                                waker.wait(config.idle);
                            }
                            Err(()) => {
                                failures = failures.saturating_add(1);
                                waker.wait(backoff(&config, failures));
                            }
                        }
                    }
                })
                .expect("spawn intake lane")
        };
        Lane {
            stop,
            waker,
            thread: Some(thread),
        }
    }

    /// A cheap handle for the intake route to call on acceptance.
    pub fn waker(&self) -> Waker {
        self.waker.clone()
    }
}

impl Drop for Lane {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        self.waker.wake();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn backoff(config: &Config, failures: u32) -> Duration {
    config
        .min_backoff
        .saturating_mul(1u32 << failures.min(5))
        .min(config.max_backoff)
}

/// Phase one: revalidate due pending deliveries in one writer transaction.
/// `Ok(Some(batch))` means at least one delivery settled.
fn validate(store: &Store, config: &Config) -> Result<Option<Batch>, ()> {
    let batch_size = config.batch;
    let settled = match store
        .writer()
        .write(move |tx| intake::resolve_due(tx, UnixMillis::now(), batch_size))
    {
        Ok(settled) => settled,
        Err(_) => return Err(()),
    };
    if settled.is_empty() {
        return Ok(None);
    }
    let mut batch = Batch::default();
    for (id, resolution) in settled {
        batch.failed += usize::from(matches!(resolution, intake::Resolution::Failed(_)));
        batch.settled.push(Settled {
            id,
            outcome: resolution.describe(),
        });
    }
    Ok(Some(batch))
}

/// Phase two: resolve ready deliveries, one bounded unit of remote work at a
/// time. Store faults leave the delivery open for the next pass.
fn dispatch(
    store: &Store,
    resolver: &Resolver,
    wake: Option<&(dyn Fn() + Send + Sync)>,
    config: &Config,
) -> Result<Option<Batch>, ()> {
    let ready = match store
        .read(|c| intake::due(c, intake::State::Ready, UnixMillis::now(), config.batch))
    {
        Ok(ready) => ready,
        Err(_) => return Err(()),
    };
    if ready.is_empty() {
        return Ok(None);
    }
    let mut batch = Batch::default();
    for delivery in ready {
        let outcome = match resolver.resolve(&delivery, UnixMillis::now()) {
            Ok(outcome) => outcome,
            // A store fault while resolving: leave the delivery ready and let
            // the next pass (after a backoff) try again.
            Err(_) => return Err(()),
        };
        if matches!(outcome, Outcome::Dispatched { .. })
            && let Some(wake) = wake
        {
            wake();
        }
        batch.failed += usize::from(matches!(outcome, Outcome::Failed { .. }));
        batch.retried += usize::from(matches!(outcome, Outcome::Retried { .. }));
        batch.settled.push(Settled {
            id: delivery.id,
            outcome: outcome.describe(),
        });
    }
    Ok(Some(batch))
}
