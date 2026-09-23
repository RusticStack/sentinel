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
use sentinel_link::session::{ArtifactCode, Executor as LinkExecutor, JobContext, Offer, Reporter};
use sentinel_pipeline::RunSpec;
use sentinel_protocol::limits::MAX_LIST_ITEMS;

use crate::{
    Result,
    artifacts::{self, REPLY_TIMEOUT},
    attempt::{self, CacheNote, Cancel, Job, Report, Verdict},
    images::Images,
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
    /// The mirrors root could not be opened at start; every checkout runs
    /// direct for the life of this process. The reason is bounded.
    MirrorsUnavailable(String),
    /// A declared cache's publication settled during finalization —
    /// sealed, skipped or failed; the attempt's verdict never depends on it.
    CachePublished {
        attempt: AttemptId,
        note: CacheNote,
    },
    /// A bounded reclamation pass over the cache root removed something —
    /// expired leases, dead staging or generations past retention/budget.
    CacheSwept(sentinel_cache::gc::GcStats),
    /// A nominal cache hit paid rebuild-scale restore cost — the K08
    /// costly-hit rule (docs/cache.md) tripped. Diagnostics only; the
    /// attempt's verdict never depends on it.
    CostlyCacheHit {
        attempt: AttemptId,
        /// The declared cache's name.
        name: String,
        /// Which clause tripped (`copied_all`/`slow`).
        costly: sentinel_cache::Costly,
        /// The restore's measured stats — the evidence.
        stats: sentinel_cache::Stats,
    },
    /// The worker's compact availability snapshot (K08), emitted after
    /// each bounded cache sweep — at start and after every attempt's
    /// finalization, never on a timer. Part 08's placement consumes it.
    Availability(Availability),
}

/// The snapshot [`Notice::Availability`] carries — bounded, learned from
/// pull outcomes and the sweep's own walk; never a store scan.
#[derive(Clone, Debug)]
pub struct Availability {
    /// Image digests the local store is known to hold — sorted, bounded
    /// by `images::MAX_HELD`.
    pub images_held: Vec<String>,
    /// Image pulls in flight right now.
    pub images_in_flight: usize,
    /// Cache entry directories the sweep saw.
    pub cache_entries: u64,
    /// Generation directories the sweep saw.
    pub cache_generations: u64,
    /// Payload bytes the store holds now — what the pass saw less what it
    /// freed (`bytes_freed`).
    pub cache_bytes: u64,
    /// The pass hit its work bound — the occupancy counts are partial.
    pub truncated: bool,
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
    /// Artifact reply waiters, one per attempt: the link admits one
    /// in-flight publication per attempt and the attempt thread captures
    /// its artifacts sequentially.
    artifact_waits: HashMap<AttemptId, Arc<Watch>>,
}

/// The controller's next artifact answer, shared with the attempt thread.
/// `gate` makes the check-and-send of each in-flight frame atomic against
/// a verdict resolving the watch: a frame can never be sent after the
/// controller has closed the artifact.
#[derive(Default)]
struct Watch {
    reply: Mutex<Option<Reply>>,
    cv: std::sync::Condvar,
    gate: Mutex<()>,
}

/// What a watch can carry: the grant that opens a stream, or the terminal
/// verdict that closes it.
#[derive(Clone, Copy)]
enum Reply {
    Granted,
    Done(ArtifactCode),
}

impl Watch {
    /// The latest answer wins; a verdict can always follow a grant.
    fn resolve(&self, reply: Reply) {
        *self.reply.lock().unwrap_or_else(|p| p.into_inner()) = Some(reply);
        self.cv.notify_all();
    }
    /// The current answer without consuming it.
    fn peek(&self) -> Option<Reply> {
        *self.reply.lock().unwrap_or_else(|p| p.into_inner())
    }
    /// Wait for the first answer — `Granted` or a verdict.
    fn wait_reply(&self, timeout: Duration) -> Option<Reply> {
        let slot = self.reply.lock().unwrap_or_else(|p| p.into_inner());
        let (slot, waited) = self
            .cv
            .wait_timeout_while(slot, timeout, |r| r.is_none())
            .unwrap_or_else(|p| p.into_inner());
        if waited.timed_out() {
            return None;
        }
        *slot
    }
    /// Wait for the terminal verdict only; a stale `Granted` is not it.
    fn wait_done(&self, timeout: Duration) -> Option<ArtifactCode> {
        let deadline = Instant::now() + timeout;
        let mut slot = self.reply.lock().unwrap_or_else(|p| p.into_inner());
        loop {
            if let Some(Reply::Done(code)) = *slot {
                return Some(code);
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return None;
            }
            let (s, _) = self
                .cv
                .wait_timeout(slot, remaining)
                .unwrap_or_else(|p| p.into_inner());
            slot = s;
        }
    }
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
    /// One in-flight pull per image reference across every attempt, and
    /// the record of what the local store holds.
    images: Images,
    /// The worker-local object mirrors, opened once here so the reflink
    /// probe and the root are settled for the process's life. `None` —
    /// configured off, or open failed — runs every checkout direct.
    mirrors: Option<crate::checkout::Mirrors>,
    state: Mutex<State>,
    /// One cache reclamation pass at a time; a second caller skips rather
    /// than waits, because the running pass already covers its work. The
    /// lock holds the resume cursor, so bounded passes cover the whole
    /// tree across attempts (P07-4).
    gc_lock: Mutex<sentinel_cache::gc::Cursor>,
    /// The cache store's payload bytes as the last pass estimated them —
    /// the availability the link reports to placement (K08).
    cache_bytes: std::sync::atomic::AtomicU64,
    /// Moves whenever `cache_bytes` changes.
    cache_version: std::sync::atomic::AtomicU64,
    notify: Box<dyn Fn(Notice) + Send + Sync>,
    recovered: Recovered,
}

impl Executor {
    /// Probe the runtime and prepare the data directory. Refuses to exist
    /// without rootless Podman: an executor that cannot isolate is not one.
    /// `git_mirrors` is the operator's escape hatch; when on, a mirror root
    /// that cannot be opened is reported once and checkouts run direct.
    pub fn start(
        root: PathBuf,
        worker: sentinel_core::WorkerId,
        notify: impl Fn(Notice) + Send + Sync + 'static,
        git_mirrors: bool,
    ) -> Result<Executor> {
        let runtime = podman::probe()?;
        std::fs::create_dir_all(root.join(crate::workspace::WORKSPACES_DIR))?;
        let mirrors = if git_mirrors {
            match crate::checkout::Mirrors::open(&root.join(crate::checkout::MIRRORS_DIR)) {
                Ok(mirrors) => Some(mirrors),
                Err(error) => {
                    notify(Notice::MirrorsUnavailable(error.to_string()));
                    None
                }
            }
        } else {
            None
        };
        // Before any offer: what the previous process left is settled on
        // disk and in the runtime; what it owed the controller waits for
        // the session.
        let (recovered, leftovers) = recovery::recover(&root, worker)?;
        let executor = Executor(Arc::new(Inner {
            root,
            worker,
            runtime,
            images: Images::new(),
            mirrors,
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
                artifact_waits: HashMap::new(),
            }),
            notify: Box::new(notify),
            gc_lock: Mutex::new(sentinel_cache::gc::Cursor::default()),
            cache_bytes: std::sync::atomic::AtomicU64::new(0),
            cache_version: std::sync::atomic::AtomicU64::new(0),
            recovered,
        }));
        // One bounded reclamation pass at start: what a dead process left —
        // expired leases, a torn staging dir, generations a crashed publish
        // abandoned — collects here rather than under a running job. Off
        // this thread, so a large store cannot hold executor start.
        let watched = Arc::downgrade(&executor.0);
        let _ = thread::Builder::new()
            .name("sentinel-cache-gc".into())
            .spawn(move || {
                if let Some(inner) = watched.upgrade() {
                    inner.sweep_caches();
                }
            });
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
        let mut job = Job {
            worker: self.worker,
            attempt: offer.attempt,
            fence: offer.fence,
            job_index,
            digest: offer.image_digest.clone(),
            spec,
            context,
            images: self.images.clone(),
            caches: Vec::new(),
            mirrors: self.mirrors.clone(),
            prepare_hold: self.state().prepare_hold,
        };
        // On disk before anything runs: a crash from here on leaves a
        // marker the next process reconciles. If the marker cannot be
        // written the attempt must not start — a crash would leave a
        // spool with no marker, which recovery discards as reported.
        if recovery::mark(&self.root, offer.attempt, offer.fence).is_err() {
            self.state().live.remove(&offer.attempt);
            self.send(
                offer.attempt,
                offer.fence,
                Event::Failed(sentinel_core::FailureClass::Publication),
                None,
            );
            return;
        }
        let spawned = thread::Builder::new()
            .name(format!("sentinel-attempt-{}", offer.attempt))
            .spawn(move || {
                (executor.notify)(Notice::Started(job.attempt));
                let output: Arc<dyn attempt::Output> = logs;
                let sink: &dyn artifacts::Sink = &*executor;
                let (verdict, _) =
                    attempt::run(&executor.root, &mut job, &*executor, output, sink, &cancel);
                let delivered = {
                    let mut state = executor.state();
                    state.live.remove(&job.attempt);
                    state.artifact_waits.remove(&job.attempt);
                    // The marker outlives the report: if the terminal event
                    // is still waiting for a session, a crash now must be
                    // reconciled, not forgotten.
                    !state.pending.iter().any(|p| p.0 == job.attempt)
                };
                if delivered {
                    recovery::unmark(&executor.root, job.attempt);
                }
                (executor.notify)(Notice::Finished(job.attempt, verdict));
                // Finalization is where the store grows: one bounded pass
                // now keeps publication's remains from accumulating.
                executor.sweep_caches();
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

    /// The worker's image pulls and what its store is known to hold —
    /// the locality record a later part advertises to placement.
    pub fn images(&self) -> &Images {
        &self.images
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
                        if ok {
                            // The spool is gone now; a crash before the
                            // abandon lands must still call this delivered.
                            recovery::mark_ended(&self.root, leftover.attempt);
                        }
                        ok
                    }
                    Err(_) => false,
                }
            } else {
                // No spool: either its end was already durable when it went
                // (`ended`), or the frames are genuinely gone — say which.
                leftover.ended
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

    /// One bounded reclamation pass over the cache root — skipped while
    /// another runs, because the running pass already covers its work.
    /// A pass that touched nothing stays quiet, but every pass ends by
    /// emitting the K08 availability snapshot: the sweep is the bounded
    /// cadence (start plus post-attempt) that Part 08's placement feed
    /// rides, so the occupancy it already computed costs a second walk
    /// never.
    fn sweep_caches(&self) {
        let mut cursor = match self.gc_lock.try_lock() {
            Ok(guard) => guard,
            Err(std::sync::TryLockError::Poisoned(p)) => p.into_inner(),
            Err(std::sync::TryLockError::WouldBlock) => return,
        };
        let stats = sentinel_cache::gc::resume(
            &self.root.join(sentinel_cache::CACHE_DIR),
            sentinel_cache::gc::DEFAULT_BUDGET_BYTES,
            sentinel_cache::gc::DEFAULT_PASS_WORK,
            &mut cursor,
        );
        drop(cursor);
        // The mirrors share the pass's cadence: bounded, and skipped for
        // any mirror a checkout holds (P07-22).
        if let Some(mirrors) = &self.mirrors {
            let _ = mirrors.sweep(crate::checkout::MIRRORS_BUDGET_BYTES);
        }
        if self
            .cache_bytes
            .swap(stats.estimated_bytes, std::sync::atomic::Ordering::Relaxed)
            != stats.estimated_bytes
        {
            self.cache_version
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        (self.notify)(Notice::Availability(Availability {
            images_held: self.images.held(),
            images_in_flight: self.images.in_flight(),
            cache_entries: stats.entries_seen,
            cache_generations: stats.generations_seen,
            cache_bytes: stats.estimated_bytes,
            truncated: stats.truncated,
        }));
        if stats.did_work() {
            (self.notify)(Notice::CacheSwept(stats));
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

    /// One in-flight artifact frame under the send gate: refuses once the
    /// stream is closed, and a dead wire resolves the watch `Store` so the
    /// capture settles without another wait.
    fn stream(
        &self,
        attempt: AttemptId,
        send: impl FnOnce(&Reporter) -> std::result::Result<(), sentinel_link::Error>,
    ) -> bool {
        let Some(watch) = self.state().artifact_waits.get(&attempt).cloned() else {
            return false;
        };
        let _gate = watch.gate.lock().unwrap_or_else(|p| p.into_inner());
        if matches!(watch.peek(), Some(Reply::Done(_))) {
            return false;
        }
        let Some(reporter) = self.state().reporter.clone() else {
            watch.resolve(Reply::Done(ArtifactCode::Store));
            return false;
        };
        if send(&reporter).is_err() {
            watch.resolve(Reply::Done(ArtifactCode::Store));
            return false;
        }
        true
    }
}

impl Report for Inner {
    fn event(&self, attempt: AttemptId, fence: Fence, event: Event) {
        self.send(attempt, fence, event, None);
    }
    fn finish(&self, attempt: AttemptId, fence: Fence, event: Event, summary: Vec<u8>) {
        self.send(attempt, fence, event, Some(summary));
    }
    /// Cache notes are process diagnostics, not wire traffic: the
    /// controller's summary format is not theirs to ride.
    fn cache_note(&self, attempt: AttemptId, note: CacheNote) {
        (self.notify)(Notice::CachePublished { attempt, note });
    }
    /// The costly-hit flag is the same kind of diagnostic — the summary's
    /// per-entry record carries the flag; the notice carries the numbers.
    fn costly_hit(
        &self,
        attempt: AttemptId,
        name: &str,
        costly: sentinel_cache::Costly,
        stats: &sentinel_cache::Stats,
    ) {
        (self.notify)(Notice::CostlyCacheHit {
            attempt,
            name: name.to_owned(),
            costly,
            stats: *stats,
        });
    }
    /// Q08: the session's remote-cache transport, when the link offers
    /// one. It is session state, not attempt state — a reconnect that
    /// replaces the reporter replaces this handle with it, and an
    /// attempt holding the old one simply drops its offers.
    fn remote(&self) -> Option<std::sync::Arc<dyn sentinel_cache::remote::Remote>> {
        self.state()
            .reporter
            .as_ref()
            .and_then(Reporter::remote_cache)
    }
}

impl artifacts::Sink for Inner {
    fn capable(&self) -> bool {
        self.state()
            .reporter
            .as_ref()
            .is_some_and(Reporter::artifacts)
    }

    fn begin(&self, attempt: AttemptId, name: &str) -> Option<ArtifactCode> {
        let watch = Arc::new(Watch::default());
        let reporter = {
            let mut state = self.state();
            let reporter = state.reporter.clone();
            match &reporter {
                Some(r) if r.artifacts() => {
                    state.artifact_waits.insert(attempt, Arc::clone(&watch));
                }
                _ => return Some(ArtifactCode::Stale),
            }
            reporter
        };
        if reporter
            .expect("capability checked")
            .artifact_begin(attempt, name)
            .is_err()
        {
            self.state().artifact_waits.remove(&attempt);
            return Some(ArtifactCode::Store);
        }
        match watch.wait_reply(REPLY_TIMEOUT) {
            Some(Reply::Granted) => None,
            answer => {
                self.state().artifact_waits.remove(&attempt);
                match answer {
                    Some(Reply::Done(code)) => Some(code),
                    _ => Some(ArtifactCode::Store),
                }
            }
        }
    }

    fn file(&self, attempt: AttemptId, path: &str, len: u64, mode: u32) -> bool {
        self.stream(attempt, |reporter| {
            reporter.artifact_file(attempt, path, len, mode)
        })
    }

    fn data(&self, attempt: AttemptId, seq: u32, bytes: &[u8]) -> bool {
        self.stream(attempt, |reporter| {
            reporter.artifact_data(attempt, seq, bytes)
        })
    }

    fn end(&self, attempt: AttemptId, name: &str) -> ArtifactCode {
        let Some(watch) = self.state().artifact_waits.get(&attempt).cloned() else {
            return ArtifactCode::Stale;
        };
        {
            let _gate = watch.gate.lock().unwrap_or_else(|p| p.into_inner());
            if let Some(Reply::Done(code)) = watch.peek() {
                self.state().artifact_waits.remove(&attempt);
                return code;
            }
            match self.state().reporter.clone() {
                Some(reporter) => {
                    if reporter.artifact_end(attempt, name).is_err() {
                        watch.resolve(Reply::Done(ArtifactCode::Store));
                    }
                }
                None => watch.resolve(Reply::Done(ArtifactCode::Store)),
            }
        }
        let code = watch
            .wait_done(REPLY_TIMEOUT)
            .unwrap_or(ArtifactCode::Store);
        self.state().artifact_waits.remove(&attempt);
        code
    }

    fn absent(&self, attempt: AttemptId, name: &str, reason: u8) -> ArtifactCode {
        let watch = {
            let mut state = self.state();
            match state.artifact_waits.get(&attempt) {
                Some(watch) => Arc::clone(watch),
                None => {
                    if state.reporter.is_none() {
                        return ArtifactCode::Stale;
                    }
                    let watch = Arc::new(Watch::default());
                    state.artifact_waits.insert(attempt, Arc::clone(&watch));
                    watch
                }
            }
        };
        {
            let _gate = watch.gate.lock().unwrap_or_else(|p| p.into_inner());
            if let Some(Reply::Done(code)) = watch.peek() {
                self.state().artifact_waits.remove(&attempt);
                return code;
            }
            match self.state().reporter.clone() {
                Some(reporter) => {
                    if reporter.artifact_absent(attempt, name, reason).is_err() {
                        watch.resolve(Reply::Done(ArtifactCode::Store));
                    }
                }
                None => watch.resolve(Reply::Done(ArtifactCode::Store)),
            }
        }
        let code = watch
            .wait_done(REPLY_TIMEOUT)
            .unwrap_or(ArtifactCode::Store);
        self.state().artifact_waits.remove(&attempt);
        code
    }

    fn settle(&self, attempt: AttemptId, _name: &str) -> ArtifactCode {
        let Some(watch) = self.state().artifact_waits.get(&attempt).cloned() else {
            return ArtifactCode::Store;
        };
        let code = watch
            .wait_done(REPLY_TIMEOUT)
            .unwrap_or(ArtifactCode::Store);
        self.state().artifact_waits.remove(&attempt);
        code
    }
}

impl LinkExecutor for Executor {
    /// P07-6: the image keys the local store is known to hold (newest
    /// first, bounded by the wire's list limit) and the cache store's bytes
    /// as the last sweep estimated them. Both come from state the worker
    /// already keeps — no store scan, no podman call; the version moves
    /// when either changes, so the link resends only then.
    fn availability(&self) -> Option<(u64, sentinel_protocol::negotiate::Availability)> {
        let version = self.images.version().wrapping_add(
            self.cache_version
                .load(std::sync::atomic::Ordering::Relaxed),
        );
        Some((
            version,
            sentinel_protocol::negotiate::Availability {
                images: self
                    .images
                    .held_keys(sentinel_protocol::limits::MAX_LIST_ITEMS),
                cache_bytes: self.cache_bytes.load(std::sync::atomic::Ordering::Relaxed),
                load_ns: 0,
            },
        ))
    }

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
            // Handed through a slot so a failed spawn re-queues them for
            // the next attach instead of waiting for a process restart.
            let slot = Arc::new(Mutex::new(Some(leftovers)));
            let hand = Arc::clone(&slot);
            let executor = Arc::clone(&self.0);
            let reporter = reporter.clone();
            let spawned = thread::Builder::new()
                .name("sentinel-recovery".into())
                .spawn(move || {
                    let leftovers = hand
                        .lock()
                        .unwrap_or_else(|p| p.into_inner())
                        .take()
                        .unwrap_or_default();
                    executor.abandon_leftovers(leftovers, reporter);
                });
            if spawned.is_err()
                && let Some(leftovers) = slot.lock().unwrap_or_else(|p| p.into_inner()).take()
            {
                self.state().leftovers = leftovers;
            }
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
        let (pipes, watches): (Vec<Arc<LogPipe>>, Vec<Arc<Watch>>) = {
            let mut state = self.state();
            state.reporter = None;
            (
                state.live.values().map(|l| Arc::clone(&l.logs)).collect(),
                state.artifact_waits.drain().map(|(_, w)| w).collect(),
            )
        };
        for pipe in pipes {
            pipe.detached();
        }
        // Any capture waiting on a controller reply is told the link is
        // gone; nothing was committed, so the artifact fails to publish.
        for watch in watches {
            watch.resolve(Reply::Done(ArtifactCode::Store));
        }
    }

    fn artifact_granted(&self, attempt: AttemptId, _name: &str) {
        let watch = self.state().artifact_waits.get(&attempt).cloned();
        if let Some(watch) = watch {
            // Resolve under the send gate: an `ArtifactFile` either ships
            // before this grant is seen or sees it first — never both.
            let _gate = watch.gate.lock().unwrap_or_else(|p| p.into_inner());
            watch.resolve(Reply::Granted);
        }
    }

    fn artifact_verdict(&self, attempt: AttemptId, _name: &str, code: ArtifactCode) {
        let watch = self.state().artifact_waits.get(&attempt).cloned();
        if let Some(watch) = watch {
            let _gate = watch.gate.lock().unwrap_or_else(|p| p.into_inner());
            watch.resolve(Reply::Done(code));
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

    fn log_ended(&self, attempt: AttemptId) {
        if let Some(pipe) = self.pipe(attempt) {
            pipe.end_acked();
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
