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
    redact::Redactor,
};

/// What happened, for the process's diagnostics.
#[derive(Debug)]
pub enum Notice {
    Started(AttemptId),
    Finished(AttemptId, Verdict),
    SpecRefused(AttemptId),
    Stopped(AttemptId),
}

struct Live {
    cancel: Cancel,
    logs: Arc<LogPipe>,
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
        Ok(Executor(Arc::new(Inner {
            root,
            worker,
            runtime,
            state: Mutex::new(State {
                reporter: None,
                awaiting: HashMap::new(),
                live: HashMap::new(),
                pending: Vec::new(),
                secrets: Vec::new(),
            }),
            notify: Box::new(notify),
        })))
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
        };
        let spawned = thread::Builder::new()
            .name(format!("sentinel-attempt-{}", offer.attempt))
            .spawn(move || {
                (executor.notify)(Notice::Started(job.attempt));
                let output: Arc<dyn attempt::Output> = logs;
                let (verdict, _) = attempt::run(&executor.root, &job, &*executor, output, &cancel);
                executor.state().live.remove(&job.attempt);
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

    /// No attempt running or waiting for its spec.
    pub fn state_is_idle(&self) -> bool {
        let state = self.state();
        state.live.is_empty() && state.awaiting.is_empty()
    }

    /// Reports that found no session and wait for the next one.
    pub fn pending_reports(&self) -> usize {
        self.state().pending.len()
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
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
        let reporter = {
            let mut state = self.state();
            if state.live.len() + state.awaiting.len() >= MAX_LIST_ITEMS {
                return false;
            }
            let Some(reporter) = state.reporter.clone() else {
                return false;
            };
            state.awaiting.insert(offer.attempt, offer.clone());
            reporter
        };
        if reporter.need_spec(offer.attempt).is_err() {
            self.state().awaiting.remove(&offer.attempt);
            return false;
        }
        true
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

    fn held(&self) -> Vec<AttemptId> {
        let state = self.state();
        state
            .live
            .keys()
            .chain(state.awaiting.keys())
            .copied()
            .collect()
    }

    fn renewed(&self, _until: UnixMillis) {}

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
        for (attempt, fence, event, summary) in pending {
            let sent = match &summary {
                Some(bytes) => reporter
                    .finish(attempt, fence, event, bytes.clone())
                    .is_ok(),
                None => reporter.report(attempt, fence, event).is_ok(),
            };
            if !sent {
                self.state().pending.push((attempt, fence, event, summary));
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
        let pipe = self.state().live.get(&attempt).map(|l| Arc::clone(&l.logs));
        if let Some(pipe) = pipe {
            pipe.acked(through);
        }
    }

    fn log_refused(&self, attempt: AttemptId) {
        let pipe = self.state().live.get(&attempt).map(|l| Arc::clone(&l.logs));
        if let Some(pipe) = pipe {
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
