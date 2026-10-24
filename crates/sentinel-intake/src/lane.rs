//! Resolution does Git and HTTP work outside any transaction, so the writer is never held across network I/O.

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

#[derive(Clone, Debug)]
pub struct Settled {
    pub id: DeliveryId,
    pub outcome: String,
}

#[derive(Clone, Debug, Default)]
pub struct Batch {
    pub settled: Vec<Settled>,
    pub failed: usize,
    pub retried: usize,
    pub error: Option<String>,
}

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

    /// A wake that arrives before the wait is not lost.
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

pub struct Lane {
    stop: Arc<AtomicBool>,
    waker: Waker,
    thread: Option<thread::JoinHandle<()>>,
}

impl Lane {
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
                            Err(e) => {
                                failures = failures.saturating_add(1);
                                notice(&Batch {
                                    error: Some(e.to_string()),
                                    ..Batch::default()
                                });
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
                            Err(e) => {
                                failures = failures.saturating_add(1);
                                notice(&Batch {
                                    error: Some(e.to_string()),
                                    ..Batch::default()
                                });
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

/// The writer, and the commit every change watcher wakes on, is taken only when a delivery is due.
fn validate(store: &Store, config: &Config) -> Result<Option<Batch>, sentinel_store::Error> {
    let now = UnixMillis::now();
    if !store.read(move |c| intake::any_due(c, intake::State::Pending, now))? {
        return Ok(None);
    }
    let batch_size = config.batch;
    let settled = store
        .writer()
        .write(move |tx| intake::resolve_due(tx, UnixMillis::now(), batch_size))?;
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

fn dispatch(
    store: &Store,
    resolver: &Resolver,
    wake: Option<&(dyn Fn() + Send + Sync)>,
    config: &Config,
) -> Result<Option<Batch>, sentinel_store::Error> {
    let ready =
        store.read(|c| intake::due(c, intake::State::Ready, UnixMillis::now(), config.batch))?;
    if ready.is_empty() {
        return Ok(None);
    }
    let mut batch = Batch::default();
    for delivery in ready {
        let outcome = match resolver.resolve(&delivery, UnixMillis::now()) {
            Ok(outcome) => outcome,
            Err(error) => park(store, &delivery, &error)?,
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

fn park(
    store: &Store,
    delivery: &intake::Delivery,
    error: &sentinel_store::Error,
) -> Result<Outcome, sentinel_store::Error> {
    let id = delivery.id;
    let detail = Some(error.to_string());
    match store.writer().write(move |tx| {
        intake::retry(
            tx,
            id,
            UnixMillis::now(),
            intake::Resolution::Failed("resolution_attempts"),
        )
    }) {
        Ok(intake::Retry::Scheduled { .. }) => Ok(Outcome::Retried {
            reason: "store_fault",
            detail,
        }),
        Ok(intake::Retry::Exhausted) => Ok(Outcome::Failed {
            reason: "resolution_attempts",
            detail,
        }),
        Err(sentinel_store::Error::Conflict) => Ok(Outcome::Skipped),
        Err(e) => Err(e),
    }
}
