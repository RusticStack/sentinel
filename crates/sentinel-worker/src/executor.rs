//! The link's `Executor`, backed by real attempts on threads.
//!
//! An offer is taken when the runtime is usable and the worker holds fewer
//! than its bound of attempts; the spec is then asked for over the link and
//! the attempt starts once it arrives. Reports go out on the live session
//! from the attempt's own thread, in order; when there is no session they
//! queue in memory and are replayed at the next attach (a durable spool is
//! W05). A `stop` from the controller flips the attempt's cancel flag and
//! ends its container; it is not reported, because the controller already
//! counts the attempt as gone.

use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use sentinel_core::{AttemptId, Event, Fence, UnixMillis};
use sentinel_link::session::{Executor as LinkExecutor, JobContext, Offer, Reporter};
use sentinel_pipeline::RunSpec;
use sentinel_protocol::limits::MAX_LIST_ITEMS;

use crate::{
    Result,
    attempt::{self, Cancel, Job, Report, Verdict},
    logpipe::LogPipe,
    podman,
    recovery::{self, Leftover, Recovered},
    redact::Redactor,
};

/// What happened, for the process's diagnostics.
#[derive(Debug)]
pub enum Notice {
    Started(AttemptId),
    Finished(AttemptId, Verdict),
    SpecRefused(AttemptId),
    Stopped(AttemptId),
    /// A cancel order was carried out; `forced` when the grace ran out.
    Canceled {
        attempt: AttemptId,
        forced: bool,
    },
    /// The lease deadline passed with no renewal: every attempt was ended
    /// without a report, because the controller has already expired them.
    LeaseLost(Vec<AttemptId>),
    /// A leftover of the previous process was handed to the controller:
    /// its spool delivered (or refused) and the attempt abandoned.
    Abandoned {
        attempt: AttemptId,
        log_delivered: bool,
    },
}

/// TERM-to-KILL grace for a cancel when the process sets none.
pub const DEFAULT_CANCEL_GRACE: Duration = Duration::from_secs(30);
/// Subtracted from the controller's lease deadline: the worker acts before
/// the controller could have expired it, never after.
pub const LEASE_GUARD: Duration = Duration::from_secs(5);
/// How often the lease watchdog looks.
const WATCHDOG_INTERVAL: Duration = Duration::from_secs(1);

struct Live {
    cancel: Cancel,
    logs: Arc<LogPipe>,
    /// A cancel order is already being carried out.
    canceling: bool,
}

struct State {
    reporter: Option<Reporter>,
    /// Offers taken and waiting for their spec.
    awaiting: HashMap<AttemptId, Offer>,
    live: HashMap<AttemptId, Live>,
    /// Reports that found no session, in order, with the summary of a
    /// terminal one.
    pending: Vec<(AttemptId, Fence, Event, Option<Vec<u8>>)>,
    /// Values every new attempt's redactor starts with (S05/S06 register
    /// per attempt; until then the operator's list applies to all).
    secrets: Vec<Vec<u8>>,
    /// Monotonic deadline derived from the last renewal, minus the guard.
    lease_deadline: Option<Instant>,
    cancel_grace: Duration,
    prepare_hold: Duration,
    /// Attempts of the previous process still to abandon, once a session is up.
    leftovers: Vec<Leftover>,
    /// Leftover spools being delivered, so their acknowledgements route.
    recovering: HashMap<AttemptId, Arc<LogPipe>>,
}

/// The executor handle the link holds; cheap to clone, one runtime behind it.
#[derive(Clone)]
pub struct Executor(Arc<Inner>);

impl std::ops::Deref for Executor {
    type Target = Inner;
    fn deref(&self) -> &Inner {
        &self.0
    }
}

pub struct Inner {
    root: PathBuf,
    worker: sentinel_core::WorkerId,
    runtime: podman::Runtime,
    state: Mutex<State>,
    notify: Box<dyn Fn(Notice) + Send + Sync>,
    recovered: Recovered,
}

impl Executor {
    /// Probe the runtime and prepare the data directory. Refuses to exist
    /// without rootless Podman: an executor that cannot isolate is not one.
    pub fn start(
        root: PathBuf,
        worker: sentinel_core::WorkerId,
        notify: impl Fn(Notice) + Send + Sync + 'static,
    ) -> Result<Executor> {
        let runtime = podman::probe()?;
        std::fs::create_dir_all(root.join(crate::workspace::WORKSPACES_DIR))?;
        // Before any offer: what the previous process left is settled on
        // disk and in the runtime; what it owed the controller waits for
        // the session.
        let (recovered, leftovers) = recovery::recover(&root, worker)?;
        let executor = Executor(Arc::new(Inner {
            root,
            worker,
            runtime,
            state: Mutex::new(State {
                reporter: None,
                awaiting: HashMap::new(),
                live: HashMap::new(),
                pending: Vec::new(),
                secrets: Vec::new(),
                lease_deadline: None,
                cancel_grace: DEFAULT_CANCEL_GRACE,
                prepare_hold: Duration::ZERO,
                leftovers,
                recovering: HashMap::new(),
            }),
            notify: Box::new(notify),
            recovered,
        }));
        let watched = Arc::downgrade(&executor.0);
        thread::Builder::new()
            .name("sentinel-lease-watchdog".into())
            .spawn(move || {
                while let Some(inner) = watched.upgrade() {
                    inner.watch_lease();
                    drop(inner);
                    thread::sleep(WATCHDOG_INTERVAL);
                }
            })?;
        Ok(executor)
    }

    /// How long a canceled step gets between `SIGTERM` and the forced stop.
    pub fn set_cancel_grace(&self, grace: Duration) {
        self.state().cancel_grace = grace;
    }

    /// Hold every attempt between checkout and image pull; a test aid for
    /// cancellation during preparation. Zero (the default) holds nothing.
    pub fn set_prepare_hold(&self, hold: Duration) {
        self.state().prepare_hold = hold;
    }

    /// Register a value to redact from every attempt started from now on.
    pub fn register_secret(&self, value: &[u8]) {
        self.state().secrets.push(value.to_vec());
    }

    fn spawn(&self, offer: Offer, spec: RunSpec, context: JobContext, job_index: usize) {
        let cancel: Cancel = Arc::new(AtomicBool::new(false));
        let logs = {
            let state = self.state();
            let mut redactor = Redactor::new();
            for secret in &state.secrets {
                redactor.register(secret);
            }
            match LogPipe::open(&self.root, offer.attempt, redactor, state.reporter.clone()) {
                Ok(pipe) => Arc::new(pipe),
                Err(_) => {
                    drop(state);
                    self.send(
                        offer.attempt,
                        offer.fence,
                        Event::Failed(sentinel_core::FailureClass::Publication),
                        None,
                    );
                    return;
                }
            }
        };
        self.state().live.insert(
            offer.attempt,
            Live {
                cancel: Arc::clone(&cancel),
                logs: Arc::clone(&logs),
                canceling: false,
            },
        );
        let executor = Arc::clone(&self.0);
        let job = Job {
            worker: self.worker,
            attempt: offer.attempt,
            fence: offer.fence,
            job_index,
            digest: offer.image_digest.clone(),
            spec,
            context,
            prepare_hold: self.state().prepare_hold,
        };
        // On disk before anything runs: a crash from here on leaves a
        // marker the next process reconciles.
        let _ = recovery::mark(&self.root, offer.attempt, offer.fence);
        let spawned = thread::Builder::new()
            .name(format!("sentinel-attempt-{}", offer.attempt))
            .spawn(move || {
                (executor.notify)(Notice::Started(job.attempt));
                let output: Arc<dyn attempt::Output> = logs;
                let (verdict, _) = attempt::run(&executor.root, &job, &*executor, output, &cancel);
                let delivered = {
                    let mut state = executor.state();
                    state.live.remove(&job.attempt);
                    // The marker outlives the report: if the terminal event
                    // is still waiting for a session, a crash now must be
                    // reconciled, not forgotten.
                    !state.pending.iter().any(|p| p.0 == job.attempt)
                };
                if delivered {
                    recovery::unmark(&executor.root, job.attempt);
                }
                (executor.notify)(Notice::Finished(job.attempt, verdict));
            });
        if spawned.is_err() {
            self.state().live.remove(&offer.attempt);
        }
    }
}

impl Inner {
    pub fn runtime(&self) -> &podman::Runtime {
        &self.runtime
    }

    /// What starting this executor found of the previous process.
    pub fn recovered(&self) -> &Recovered {
        &self.recovered
    }

    /// Attempts still to be abandoned to the controller.
    pub fn leftovers_pending(&self) -> usize {
        self.state().leftovers.len()
    }

    /// No attempt running or waiting for its spec.
    pub fn state_is_idle(&self) -> bool {
        let state = self.state();
        state.live.is_empty() && state.awaiting.is_empty()
    }

    /// Reports that found no session and wait for the next one.
    pub fn pending_reports(&self) -> usize {
        self.state().pending.len()
    }

    /// Hand the previous process's attempts to the controller: the spool's
    /// frames and end first (the attempt is still held, so they are
    /// accepted — or refused if its lease already expired), then the
    /// abandonment under the fence, then the marker goes.
    fn abandon_leftovers(&self, leftovers: Vec<Leftover>, reporter: Reporter) {
        for leftover in leftovers {
            let delivered = if leftover.spooled {
                match LogPipe::open(
                    &self.root,
                    leftover.attempt,
                    Redactor::new(),
                    Some(reporter.clone()),
                ) {
                    Ok(pipe) => {
                        let pipe = Arc::new(pipe);
                        self.state()
                            .recovering
                            .insert(leftover.attempt, Arc::clone(&pipe));
                        let ok = attempt::Output::complete(&*pipe);
                        self.state().recovering.remove(&leftover.attempt);
                        ok
                    }
                    Err(_) => false,
                }
            } else {
                true
            };
            if reporter.abandon(leftover.attempt, leftover.fence).is_err() {
                // Session gone: keep it for the next attach.
                self.state().leftovers.push(leftover);
                return;
            }
            recovery::unmark(&self.root, leftover.attempt);
            (self.notify)(Notice::Abandoned {
                attempt: leftover.attempt,
                log_delivered: delivered,
            });
        }
    }

    /// The lease watchdog: once the deadline the controller last granted
    /// (less the guard) has passed without a renewal, no attempt here is
    /// ours any more. End them all, forced, and report nothing — the
    /// controller has expired them and any report would be stale.
    fn watch_lease(&self) {
        let lost: Vec<(AttemptId, Cancel)> = {
            let mut state = self.state();
            let Some(deadline) = state.lease_deadline else {
                return;
            };
            if Instant::now() < deadline || state.live.is_empty() {
                return;
            }
            state.lease_deadline = None;
            state
                .live
                .iter_mut()
                .map(|(id, live)| {
                    live.canceling = true;
                    (*id, Arc::clone(&live.cancel))
                })
                .collect()
        };
        for (attempt, cancel) in &lost {
            cancel.store(true, Ordering::Release);
            let _ = podman::remove_named(&format!("sentinel-{attempt}"));
        }
        (self.notify)(Notice::LeaseLost(
            lost.into_iter().map(|(a, _)| a).collect(),
        ));
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// The log pipe of a live or recovering attempt.
    fn pipe(&self, attempt: AttemptId) -> Option<Arc<LogPipe>> {
        let state = self.state();
        state
            .live
            .get(&attempt)
            .map(|l| Arc::clone(&l.logs))
            .or_else(|| state.recovering.get(&attempt).cloned())
    }

    fn send(&self, attempt: AttemptId, fence: Fence, event: Event, summary: Option<Vec<u8>>) {
        let mut state = self.state();
        let sent = match (&state.reporter, &summary) {
            (Some(reporter), Some(summary)) => reporter
                .finish(attempt, fence, event, summary.clone())
                .is_ok(),
            (Some(reporter), None) => reporter.report(attempt, fence, event).is_ok(),
            (None, _) => false,
        };
        if !sent {
            state.pending.push((attempt, fence, event, summary));
        }
    }
}

impl Report for Inner {
    fn event(&self, attempt: AttemptId, fence: Fence, event: Event) {
        self.send(attempt, fence, event, None);
    }
    fn finish(&self, attempt: AttemptId, fence: Fence, event: Event, summary: Vec<u8>) {
        self.send(attempt, fence, event, Some(summary));
    }
}

impl LinkExecutor for Executor {
    fn offered(&self, offer: &Offer) -> bool {
        let mut state = self.state();
        if state.live.len() + state.awaiting.len() >= MAX_LIST_ITEMS || state.reporter.is_none() {
            return false;
        }
        state.awaiting.insert(offer.attempt, offer.clone());
        true
    }

    fn accepted(&self, attempt: AttemptId) {
        let reporter = {
            let state = self.state();
            if !state.awaiting.contains_key(&attempt) {
                return;
            }
            state.reporter.clone()
        };
        if let Some(reporter) = reporter {
            let _ = reporter.need_spec(attempt);
        }
    }

    fn stop(&self, attempt: AttemptId) {
        let live = {
            let mut state = self.state();
            state.awaiting.remove(&attempt);
            state.live.get(&attempt).map(|l| Arc::clone(&l.cancel))
        };
        if let Some(cancel) = live {
            cancel.store(true, Ordering::Release);
            // End the container now, outside the lock; the attempt thread
            // finalizes what is left and exits.
            let _ = podman::remove_named(&format!("sentinel-{attempt}"));
        }
        (self.notify)(Notice::Stopped(attempt));
    }

    fn cancel(&self, attempt: AttemptId) {
        let (cancel, grace) = {
            let mut state = self.state();
            let grace = state.cancel_grace;
            match state.live.get_mut(&attempt) {
                Some(live) if !live.canceling => {
                    live.canceling = true;
                    (Arc::clone(&live.cancel), grace)
                }
                _ => return,
            }
        };
        // Desired state first, so a step that ends by itself meanwhile is
        // still reported as canceled; then the signals, off this thread.
        cancel.store(true, Ordering::Release);
        let executor = Arc::clone(&self.0);
        let _ = thread::Builder::new()
            .name(format!("sentinel-cancel-{attempt}"))
            .spawn(move || {
                let outcome = podman::terminate_named(&format!("sentinel-{attempt}"), grace);
                let forced = matches!(outcome, Ok(podman::Terminated::Forced));
                (executor.notify)(Notice::Canceled { attempt, forced });
            });
    }

    fn held(&self) -> Vec<AttemptId> {
        let state = self.state();
        state
            .live
            .keys()
            .chain(state.awaiting.keys())
            .copied()
            .collect()
    }

    fn renewed(&self, until: UnixMillis) {
        // Monotonic from here on: the wall-clock deadline the controller
        // granted becomes an `Instant`, less the guard margin.
        let remaining = until.0.saturating_sub(UnixMillis::now().0).max(0) as u64;
        let deadline =
            Instant::now() + Duration::from_millis(remaining).saturating_sub(LEASE_GUARD);
        self.state().lease_deadline = Some(deadline);
    }

    fn attached(&self, reporter: Reporter) {
        let (pending, pipes) = {
            let mut state = self.state();
            state.reporter = Some(reporter.clone());
            (
                std::mem::take(&mut state.pending),
                state
                    .live
                    .values()
                    .map(|l| Arc::clone(&l.logs))
                    .collect::<Vec<_>>(),
            )
        };
        for pipe in pipes {
            pipe.attached(reporter.clone());
        }
        // Leftovers of the previous process: deliver what they printed,
        // close the log, then abandon them — off this thread, since the
        // delivery waits for acknowledgements.
        let leftovers = std::mem::take(&mut self.state().leftovers);
        if !leftovers.is_empty() {
            let executor = Arc::clone(&self.0);
            let reporter = reporter.clone();
            let _ = thread::Builder::new()
                .name("sentinel-recovery".into())
                .spawn(move || executor.abandon_leftovers(leftovers, reporter));
        }
        for (attempt, fence, event, summary) in pending {
            let sent = match &summary {
                Some(bytes) => reporter
                    .finish(attempt, fence, event, bytes.clone())
                    .is_ok(),
                None => reporter.report(attempt, fence, event).is_ok(),
            };
            if !sent {
                self.state().pending.push((attempt, fence, event, summary));
            } else if summary.is_some() || matches!(event, Event::Passed | Event::Failed(_)) {
                recovery::unmark(&self.root, attempt);
            }
        }
        // Specs asked for on a lost session: ask again.
        let awaiting: Vec<AttemptId> = self.state().awaiting.keys().copied().collect();
        for attempt in awaiting {
            let _ = reporter.need_spec(attempt);
        }
    }

    fn detached(&self) {
        let pipes: Vec<Arc<LogPipe>> = {
            let mut state = self.state();
            state.reporter = None;
            state.live.values().map(|l| Arc::clone(&l.logs)).collect()
        };
        for pipe in pipes {
            pipe.detached();
        }
    }

    fn log_acked(&self, attempt: AttemptId, through: u64) {
        if let Some(pipe) = self.pipe(attempt) {
            pipe.acked(through);
        }
    }

    fn log_refused(&self, attempt: AttemptId) {
        if let Some(pipe) = self.pipe(attempt) {
            pipe.refused();
        }
    }

    fn spec(&self, attempt: AttemptId, context: JobContext, bytes: Vec<u8>) {
        let Some(offer) = self.state().awaiting.remove(&attempt) else {
            return;
        };
        match RunSpec::decode(&bytes) {
            Ok(spec) => {
                let job_index = offer.job_index as usize;
                self.spawn(offer, spec, context, job_index);
            }
            Err(_) => {
                self.send(
                    attempt,
                    offer.fence,
                    Event::Failed(sentinel_core::FailureClass::Preparation),
                    None,
                );
            }
        }
    }

    fn no_spec(&self, attempt: AttemptId) {
        self.state().awaiting.remove(&attempt);
        (self.notify)(Notice::SpecRefused(attempt));
    }
}

impl Drop for Inner {
    fn drop(&mut self) {
        // Ask every live attempt to stop; their threads finalize on their own.
        for live in self.state().live.values() {
            live.cancel.store(true, Ordering::Release);
        }
    }
}
