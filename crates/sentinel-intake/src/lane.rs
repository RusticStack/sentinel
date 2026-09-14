//! The bounded resolution lane (G02).
//!
//! One thread drains due deliveries in fixed-size batches inside the store's
//! writer; a wake from the intake route shortens the wait, and the idle tick
//! is the safety net for a missed wake. Failures back off doubling to a
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

/// How the lane paces itself. Defaults: 64 deliveries per transaction, a
/// 250 ms idle tick, and failure back-off from one second to thirty.
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
    pub failed: usize,
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
    pub fn start(
        store: Arc<Store>,
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
                        let outcome = store.writer().write(move |tx| {
                            intake::resolve_due(tx, UnixMillis::now(), config.batch)
                        });
                        match outcome {
                            Ok(settled) if !settled.is_empty() => {
                                failures = 0;
                                let mut batch = Batch::default();
                                for (id, resolution) in settled {
                                    let outcome = resolution.describe();
                                    batch.failed += usize::from(matches!(
                                        resolution,
                                        intake::Resolution::Failed(_)
                                    ));
                                    batch.settled.push(Settled { id, outcome });
                                }
                                notice(&batch);
                                // Keep draining while there is work.
                                continue;
                            }
                            Ok(_) => {
                                failures = 0;
                                waker.wait(config.idle);
                            }
                            Err(_) => {
                                failures = failures.saturating_add(1);
                                let backoff = config
                                    .min_backoff
                                    .saturating_mul(1u32 << failures.min(5))
                                    .min(config.max_backoff);
                                waker.wait(backoff);
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
