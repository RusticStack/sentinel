//! The schedule lane: due occurrences become runs.
//!
//! The pass claims occurrences in one writer transaction — that is where dedup, overlap, the missed
//! bound and suspension are decided — and then resolves each claimed occurrence outside any
//! transaction, because reading a repository is network work. A claim the controller dies holding is
//! claimed again after `CLAIM_TTL_MS`, so a restart in the middle of an occurrence neither loses it
//! nor runs it twice.

use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};

use sentinel_core::{RepoId, UnixMillis};
use sentinel_store::{Store, schedule};

use crate::resolve::Resolver;

#[derive(Clone, Copy, Debug)]
pub struct Config {
    /// Schedules one pass claims.
    pub batch: u32,
    /// How long an idle pass waits before looking for due occurrences again.
    pub idle: Duration,
    pub min_backoff: Duration,
    pub max_backoff: Duration,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            batch: schedule::MAX_PER_PASS,
            idle: Duration::from_millis(500),
            min_backoff: Duration::from_secs(1),
            max_backoff: Duration::from_secs(30),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Notice {
    /// The schedule's repository, absent on a pass that could not read the store at all.
    pub repo: Option<RepoId>,
    /// The occurrence instant, UTC milliseconds: the identity a run was fired for.
    pub at_ms: i64,
    pub outcome: String,
    pub error: Option<String>,
}

pub struct Lane {
    stop: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}

impl Lane {
    pub fn start(
        store: Arc<Store>,
        resolver: Arc<Resolver>,
        config: Config,
        notice: impl Fn(&Notice) + Send + Sync + 'static,
    ) -> Lane {
        let stop = Arc::new(AtomicBool::new(false));
        let thread = {
            let stop = Arc::clone(&stop);
            let notice: Arc<dyn Fn(&Notice) + Send + Sync> = Arc::new(notice);
            thread::Builder::new()
                .name("sentinel-schedule".into())
                .spawn(move || {
                    let mut failures: u32 = 0;
                    while !stop.load(Ordering::Acquire) {
                        // A schedule is wall-clock work: its occurrences are UTC instants, not offsets
                        // from a process that started at an arbitrary moment.
                        let now = UnixMillis::now();
                        let batch = config.batch;
                        match store
                            .writer()
                            .write(move |tx| schedule::claim(tx, now, batch))
                        {
                            Ok(claims) if claims.is_empty() => {
                                failures = 0;
                                thread::sleep(config.idle);
                            }
                            Ok(claims) => {
                                failures = 0;
                                for claim in claims {
                                    match resolver.resolve_scheduled(&claim, UnixMillis::now()) {
                                        Ok(outcome) => notice(&Notice {
                                            repo: Some(claim.schedule.repo),
                                            at_ms: claim.at_ms,
                                            outcome: outcome.describe(),
                                            error: None,
                                        }),
                                        // A transport or capacity fault leaves the claim for the
                                        // reclaim to retry; anything else would fail the same way
                                        // every pass, so the occurrence records why instead.
                                        Err(e) if retryable(&e) => notice(&Notice {
                                            repo: Some(claim.schedule.repo),
                                            at_ms: claim.at_ms,
                                            outcome: "store_unavailable".into(),
                                            error: Some(e.to_string()),
                                        }),
                                        Err(e) => notice(&Notice {
                                            repo: Some(claim.schedule.repo),
                                            at_ms: claim.at_ms,
                                            outcome: refused(&store, &claim, UnixMillis::now()),
                                            error: Some(e.to_string()),
                                        }),
                                    }
                                }
                            }
                            Err(e) => {
                                failures = failures.saturating_add(1);
                                notice(&Notice {
                                    repo: None,
                                    at_ms: 0,
                                    outcome: "claim_failed".into(),
                                    error: Some(e.to_string()),
                                });
                                thread::sleep(backoff(&config, failures));
                            }
                        }
                    }
                })
                .expect("spawn schedule lane")
        };
        Lane {
            stop,
            thread: Some(thread),
        }
    }
}

impl Drop for Lane {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// Whether a store error is a fault worth another pass, or a refusal this occurrence would hit
/// again: only transport and capacity faults are worth the retry.
fn retryable(error: &sentinel_store::Error) -> bool {
    use sentinel_store::Error;
    matches!(
        error,
        Error::Sqlite(_)
            | Error::Overloaded
            | Error::WriterUnavailable
            | Error::WriteAmbiguous
            | Error::WriterPanicked
            | Error::Io(_)
    )
}

/// Record an occurrence whose dispatch the store refused outright, so the row says why it did not
/// run rather than staying claimed forever.
fn refused(store: &Store, claim: &sentinel_store::schedule::Claim, now: UnixMillis) -> String {
    let row = claim.clone();
    let settled = store.writer().write(move |tx| {
        schedule::settle(
            tx,
            row.schedule.repo,
            row.at_ms,
            schedule::State::Failed,
            Some("store_rejected"),
            now,
        )
    });
    if settled.is_err() {
        return "store_unavailable".into();
    }
    "failed:store_rejected".into()
}

fn backoff(config: &Config, failures: u32) -> Duration {
    config
        .min_backoff
        .saturating_mul(1u32 << failures.min(5))
        .min(config.max_backoff)
}
