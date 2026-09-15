//! The controller's side of the link: listen, admit, keep the fleet, place
//! work and push offers (W02).
//!
//! Two threads own the loop. The acceptor takes connections and hands each
//! to a session thread that authenticates it against the store, registers
//! it in the fleet and serves it. The dispatcher sleeps on a condition
//! variable and is woken the moment anything changes the answer to "is
//! there work for a connected worker?": a worker arriving, an enqueue, a
//! completion, a decline. A short reconciliation interval is the safety
//! net for a missed wake, and the ack-timeout sweep rides on the same loop.
//! Heartbeats never drive dispatch; they only renew leases.
//!
//! Every decision is one writer transaction on the store: placement takes the
//! lease and reservation together, the ack marks the attempt, a lapse frees
//! it. Nothing here is state the database does not also hold, so a restart
//! reconstructs the queue and the reservations by reading them.

use std::{
    collections::HashMap,
    net::{SocketAddr, TcpListener, TcpStream},
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicBool, AtomicI64, AtomicU64, AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use sentinel_auth::secret::{Digest, Secret};
use sentinel_core::{
    AttemptId, Event, Fence, JobId, PoolId, RunId, TenantId, UnixMillis, WorkerId,
};
use sentinel_protocol::limits::{MAX_ARTIFACT_BYTES, MAX_ARTIFACT_ENTRIES, MAX_RUN_ARTIFACT_BYTES};
use sentinel_protocol::logs::Frame;
use sentinel_protocol::negotiate::Hello;
use sentinel_store::{
    Store, artifacts, dispatch,
    logs::LogStore,
    objects::{self, Objects},
    workers,
};

use crate::{
    Error, Result,
    identity::Identity,
    session::{
        self, Admission, Admitted, ArtifactCode, ArtifactReply, Beat, Capacity, JobContext,
        LogVerdict, Offer, Rejection, Sender, SessionHandler,
    },
    tls,
};

/// How long the dispatcher sleeps without a wake before re-checking the
/// queue and sweeping unacknowledged offers. A safety net, not the clock.
pub const RECONCILE_INTERVAL: Duration = Duration::from_secs(2);
/// Sessions accepted at once; beyond this a connection is closed unserved.
pub const MAX_SESSIONS: usize = 1024;

/// Counters for diagnostics and tests. Monotonic, never reset.
#[derive(Debug, Default)]
pub struct Stats {
    pub admitted: AtomicU64,
    pub rejected: AtomicU64,
    pub offers: AtomicU64,
    pub acknowledged: AtomicU64,
    pub lapsed: AtomicU64,
    pub sessions_ended: AtomicU64,
    pub reports: AtomicU64,
    pub stale_reports: AtomicU64,
    pub log_frames: AtomicU64,
    pub log_refused: AtomicU64,
    pub expired: AtomicU64,
    pub queue_timeouts: AtomicU64,
    pub abandoned: AtomicU64,
    /// Artifacts committed through the object store (protocol 4).
    pub artifacts: AtomicU64,
}

struct Peer {
    sender: Sender,
    pool: PoolId,
    generation: u64,
    /// When liveness was last written, so a beat costs a write once a minute.
    seen_recorded_ms: AtomicI64,
    /// Attempts verified as held by this worker for log frames, mapped to
    /// their (run, job) so the store path costs one read per attempt
    /// rather than one per frame.
    logging: Mutex<HashMap<AttemptId, (RunId, JobId)>>,
}

/// A file currently receiving `ArtifactData` chunks.
struct OpenFile {
    path: String,
    mode: u32,
    declared: u64,
    next_seq: u32,
    staging: objects::Staging,
}

/// An artifact publication in flight (protocol 4): granted by
/// `artifact_begin`, settled by `artifact_end`/`artifact_absent` or a
/// mid-flight failure. The session orders the messages; this owns the
/// staging and the run-budget accounting.
struct InFlight {
    tenant: TenantId,
    run: RunId,
    job: sentinel_core::JobId,
    name: String,
    retain_secs: u64,
    /// Sealed-but-uncommitted files in wire order; committed at `end`.
    done: Vec<(String, u32, objects::Staged)>,
    /// Bytes charged to the run budget: sealed files plus the open file's
    /// declared length. Equals the artifact's total when `end` lands.
    accounted: u64,
    /// The path most recently declared; wire order must be strictly
    /// increasing so the manifest lands sorted.
    last_path: String,
    file: Option<OpenFile>,
}

#[derive(Default)]
struct ArtifactState {
    in_flight: HashMap<AttemptId, InFlight>,
    /// Accounted in-flight bytes per run: the per-run budget stays exact
    /// while attempts on different workers publish concurrently.
    runs: HashMap<RunId, u64>,
}

struct Inner {
    source_destinations: Mutex<Arc<Vec<String>>>,
    source_app: Mutex<Option<Arc<sentinel_github::app::App>>>,
    source_active: Arc<AtomicUsize>,
    source_key: Mutex<Option<Arc<sentinel_auth::sealed::Key>>>,
    store: Arc<Store>,
    logs: Arc<LogStore>,
    objects: Arc<Objects>,
    artifacts: Mutex<ArtifactState>,
    config: Arc<rustls::ServerConfig>,
    fleet: Mutex<HashMap<WorkerId, Arc<Peer>>>,
    generation: AtomicU64,
    wake: (Mutex<bool>, Condvar),
    stop: AtomicBool,
    sessions: AtomicUsize,
    stats: Stats,
}

impl Inner {
    fn wake(&self) {
        let (flag, cv) = &self.wake;
        *flag.lock().unwrap_or_else(|p| p.into_inner()) = true;
        cv.notify_one();
    }

    fn write<T: Send + 'static>(
        &self,
        f: impl FnOnce(&sentinel_store::Transaction<'_>) -> sentinel_store::Result<T> + Send + 'static,
    ) -> Result<T> {
        self.store
            .writer()
            .write(f)
            .map_err(|_| Error::Internal("store write"))
    }

    fn register(&self, worker: WorkerId, peer: Arc<Peer>) {
        let old = self
            .fleet
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(worker, peer);
        // A reconnecting worker replaces its previous session; the old socket
        // is closed so its thread ends instead of lingering to its deadline.
        if let Some(old) = old {
            old.sender.close();
        }
    }

    fn unregister(&self, worker: WorkerId, generation: u64) {
        let mut fleet = self.fleet.lock().unwrap_or_else(|p| p.into_inner());
        if fleet
            .get(&worker)
            .is_some_and(|p| p.generation == generation)
        {
            fleet.remove(&worker);
        }
    }

    fn serve(self: &Arc<Self>, socket: TcpStream) {
        let outcome = session::accept(socket, Arc::clone(&self.config), &**self);
        let mut session = match outcome {
            Ok(session) => session,
            Err(_) => {
                self.stats.rejected.fetch_add(1, Ordering::Relaxed);
                return;
            }
        };
        self.stats.admitted.fetch_add(1, Ordering::Relaxed);
        let Admitted { worker, pool, .. } = session.admitted;
        let generation = self.generation.fetch_add(1, Ordering::Relaxed);
        let peer = Arc::new(Peer {
            sender: session.sender(),
            pool,
            generation,
            seen_recorded_ms: AtomicI64::new(0),
            logging: Mutex::new(HashMap::new()),
        });
        self.register(worker, peer);
        self.wake();
        let _ = session.serve(&**self);
        self.unregister(worker, generation);
        self.stats.sessions_ended.fetch_add(1, Ordering::Relaxed);
        // Its unacknowledged offers lapse in the sweep; acknowledged leases
        // run to expiry (W06), so a brief reconnect keeps its work.
    }

    /// One dispatch pass: sweep lapsed offers, then fill every connected
    /// worker until nothing fits. Each placement is its own transaction, so
    /// a failing one never holds up the rest.
    fn dispatch_pass(&self) {
        let now = UnixMillis::now();
        // Leases that ran out and attempts that outran their job's timeout
        // by the grace: infra-failed, capacity back, never replayed.
        if let Ok(due) = self.store.read(|c| dispatch::expired(c, now)) {
            for attempt in due {
                if self
                    .write(move |tx| dispatch::expire(tx, attempt, now))
                    .is_ok()
                {
                    self.stats.expired.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
        if let Ok(count) = self.write(move |tx| dispatch::sweep_queue_timeouts(tx, now)) {
            self.stats
                .queue_timeouts
                .fetch_add(count as u64, Ordering::Relaxed);
        }
        if let Ok(due) = self.store.read(|c| dispatch::unacknowledged(c, now)) {
            for attempt in due {
                if self
                    .write(move |tx| dispatch::lapse(tx, attempt, now))
                    .is_ok()
                {
                    self.stats.lapsed.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
        let peers: Vec<(WorkerId, Arc<Peer>)> = self
            .fleet
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .map(|(w, p)| (*w, Arc::clone(p)))
            .collect();
        for (worker, peer) in peers {
            let pool = peer.pool;
            for _ in 0..dispatch::MAX_HELD_ATTEMPTS {
                let placed = self.write(move |tx| {
                    dispatch::place(
                        tx,
                        worker,
                        pool,
                        dispatch::DEFAULT_LEASE_MS,
                        UnixMillis::now(),
                    )
                });
                let Ok(Some(placed)) = placed else { break };
                let offer = Offer {
                    attempt: placed.attempt,
                    tenant: placed.tenant,
                    run: placed.run,
                    job: placed.job,
                    fence: placed.fence,
                    lease_until: placed.lease_until,
                    cpu_millis: placed.cpu_millis as u64,
                    memory_bytes: placed.memory_bytes as u64,
                    image_digest: placed.image.digest,
                    image_platform: placed.image.platform,
                    job_index: placed.job_index,
                };
                if session::offer(&peer.sender, &offer).is_err() {
                    // The session is gone: give the job back at once rather
                    // than letting the ack timeout find it.
                    let attempt = offer.attempt;
                    let _ = self.write(move |tx| dispatch::lapse(tx, attempt, UnixMillis::now()));
                    peer.sender.close();
                    break;
                }
                self.stats.offers.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    fn dispatch_loop(&self) {
        let (flag, cv) = &self.wake;
        loop {
            {
                let mut woken = flag.lock().unwrap_or_else(|p| p.into_inner());
                if !*woken {
                    woken = cv
                        .wait_timeout(woken, RECONCILE_INTERVAL)
                        .unwrap_or_else(|p| p.into_inner())
                        .0;
                }
                *woken = false;
            }
            if self.stop.load(Ordering::Acquire) {
                return;
            }
            self.dispatch_pass();
        }
    }
}

impl Inner {
    fn peer(&self, worker: WorkerId) -> Option<Arc<Peer>> {
        self.fleet
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&worker)
            .cloned()
    }

    /// Whether `attempt` is held by `worker`, checked against the store
    /// once per attempt and remembered on the session.
    fn holds(&self, worker: WorkerId, attempt: AttemptId) -> bool {
        self.log_scope(worker, attempt).is_some()
    }

    /// The attempt's `(run, job)` when held by `worker`: resolved against
    /// the store once per attempt, then remembered on the session.
    fn log_scope(&self, worker: WorkerId, attempt: AttemptId) -> Option<(RunId, JobId)> {
        let peer = self.peer(worker)?;
        if let Some(scope) = peer
            .logging
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&attempt)
        {
            return Some(*scope);
        }
        let scope = self
            .store
            .read(|c| {
                let tx = c.unchecked_transaction()?;
                let (_, run, job, _) = dispatch::attempt_scope(&tx, worker, attempt)?;
                Ok((run, job))
            })
            .ok()?;
        peer.logging
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(attempt, scope);
        Some(scope)
    }

    /// Record the settled outcome of a declared artifact: `state`, the
    /// committed manifest version when captured, and the charged bytes.
    /// A store fault changes nothing the verdict reports.
    fn record_artifact(
        &self,
        f: &InFlight,
        attempt: AttemptId,
        state: artifacts::State,
        manifest_version: Option<u64>,
    ) {
        let (tenant, run, job) = (f.tenant, f.run, f.job);
        let name = f.name.clone();
        // Sealed files only: a file that never completed reports nothing.
        let entries = f.done.len() as u64;
        let bytes = f.done.iter().map(|(_, _, s)| s.len()).sum::<u64>();
        let retain_until = UnixMillis(
            UnixMillis::now()
                .0
                .saturating_add(f.retain_secs.saturating_mul(1000) as i64),
        );
        let _ = self.write(move |tx| {
            artifacts::record(
                tx,
                tenant,
                run,
                job,
                attempt,
                &name,
                state,
                manifest_version,
                entries,
                bytes,
                retain_until,
                UnixMillis::now(),
            )
        });
    }

    /// Drop an in-flight publication: release the run budget, discard the
    /// sealed-but-uncommitted files it created, and — for a declared
    /// artifact that failed after opening — record `failed` so the run's
    /// output stays explainable. `Stale` means nothing was granted.
    fn artifact_fail(
        &self,
        state: &mut ArtifactState,
        attempt: AttemptId,
        code: ArtifactCode,
    ) -> ArtifactCode {
        let Some(f) = state.in_flight.remove(&attempt) else {
            return ArtifactCode::Stale;
        };
        if let Some(r) = state.runs.get_mut(&f.run) {
            *r = r.saturating_sub(f.accounted);
        }
        if code != ArtifactCode::Stale {
            self.record_artifact(&f, attempt, artifacts::State::Failed, None);
        }
        for (_, _, staged) in f.done {
            staged.discard();
        }
        code
    }
}

impl Admission for Inner {
    fn admit(
        &self,
        fingerprint: &Digest,
        worker: WorkerId,
        name: &str,
        hello: &Hello,
        enrollment: Option<&Secret>,
        capacity: Capacity,
    ) -> std::result::Result<Admitted, Rejection> {
        let negotiated = sentinel_protocol::negotiate::negotiate(hello).map_err(Rejection::from)?;
        let capacity = dispatch::Capacity {
            cpu_millis: i64::try_from(capacity.cpu_millis).map_err(|_| Rejection::Capacity)?,
            memory_bytes: i64::try_from(capacity.memory_bytes).map_err(|_| Rejection::Capacity)?,
        };
        if let Ok(known) = self.store.read(|c| workers::authenticate(c, fingerprint)) {
            let id = known.id;
            self.write(move |tx| dispatch::report_capacity(tx, id, capacity))
                .map_err(|_| Rejection::Unavailable)?;
            return Ok(Admitted {
                worker: known.id,
                pool: known.pool,
                negotiated: known.negotiated,
            });
        }
        let Some(secret) = enrollment else {
            return Err(Rejection::NotEnrolled);
        };
        let (secret, fingerprint, name) = (
            Secret::parse(&{
                let mut t = String::new();
                secret.expose(&mut t);
                t
            })
            .ok_or(Rejection::Enrollment)?,
            *fingerprint,
            name.to_owned(),
        );
        self.store
            .writer()
            .write(move |tx| {
                let enrolled = workers::enroll(
                    tx,
                    &secret,
                    workers::Presentation {
                        worker,
                        fingerprint,
                        name: &name,
                        negotiated,
                    },
                    UnixMillis::now(),
                )?;
                dispatch::report_capacity(tx, enrolled.id, capacity)?;
                Ok(Admitted {
                    worker: enrolled.id,
                    pool: enrolled.pool,
                    negotiated: enrolled.negotiated,
                })
            })
            .map_err(|e| match e {
                sentinel_store::Error::Conflict | sentinel_store::Error::InvalidInput(_) => {
                    Rejection::Identity
                }
                sentinel_store::Error::NotFound => Rejection::Enrollment,
                _ => Rejection::Unavailable,
            })
    }
}

impl SessionHandler for Inner {
    fn spec_requested(
        &self,
        worker: WorkerId,
        attempt: AttemptId,
        sender: Sender,
        protocol: u16,
    ) -> bool {
        // No unbounded queue, and no GitHub round trip on heartbeat/dispatch.
        if self
            .source_active
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                (n < 8).then_some(n + 1)
            })
            .is_err()
        {
            let _ = sender.send(&session::ServerMessage::NoSpec {
                attempt: *attempt.as_bytes(),
            });
            return true;
        }
        let active = Arc::clone(&self.source_active);
        let store = Arc::clone(&self.store);
        let key = self
            .source_key
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        let app = self
            .source_app
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        let failed = sender.clone();
        let destinations = self
            .source_destinations
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        if thread::Builder::new()
            .name("sentinel-source".into())
            .spawn(move || {
                struct Permit(Arc<AtomicUsize>);
                impl Drop for Permit {
                    fn drop(&mut self) {
                        self.0.fetch_sub(1, Ordering::AcqRel);
                    }
                }
                let _permit = Permit(active);
                let spec = resolve_spec(
                    &store,
                    key.as_deref(),
                    app.as_ref(),
                    &destinations,
                    worker,
                    attempt,
                )
                .ok();
                let _ = send_resolved(&sender, attempt, protocol, spec);
            })
            .is_err()
        {
            self.source_active.fetch_sub(1, Ordering::AcqRel);
            let _ = failed.send(&session::ServerMessage::NoSpec {
                attempt: *attempt.as_bytes(),
            });
        }
        true
    }
    fn ping(&self, worker: WorkerId, held: &[AttemptId]) -> Result<Beat> {
        let now = UnixMillis::now();
        let peer = self
            .fleet
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&worker)
            .cloned();
        let record_seen = peer.as_ref().is_some_and(|p| {
            let last = p.seen_recorded_ms.load(Ordering::Relaxed);
            now.0.saturating_sub(last) >= workers::SEEN_RECORD_INTERVAL_MS
        });
        if held.is_empty() && !record_seen {
            // Nothing to renew and liveness recorded recently: no write.
            return Ok(Beat {
                lease_until: UnixMillis(now.0 + dispatch::DEFAULT_LEASE_MS),
                stop: Vec::new(),
                cancel: Vec::new(),
            });
        }
        let held = held.to_vec();
        let wanted = held.clone();
        let (lease_until, stop) = self.write(move |tx| {
            if record_seen {
                workers::seen(tx, worker, now)?;
            }
            dispatch::renew(tx, worker, &held, dispatch::DEFAULT_LEASE_MS, now)
        })?;
        if record_seen && let Some(peer) = peer {
            peer.seen_recorded_ms.store(now.0, Ordering::Relaxed);
        }
        // Cancellation desired for anything still held: delivered with every
        // beat until the worker reports, so a missed pong changes nothing.
        let cancel = if wanted.is_empty() {
            Vec::new()
        } else {
            self.store
                .read(|c| dispatch::cancel_requested(c, worker, &wanted))
                .map_err(|_| Error::Internal("store read"))?
        };
        Ok(Beat {
            lease_until,
            stop,
            cancel,
        })
    }

    fn acknowledged(&self, worker: WorkerId, attempt: AttemptId, fence: Fence) {
        let acked = self
            .write(move |tx| dispatch::acknowledge(tx, worker, attempt, fence, UnixMillis::now()));
        if acked.is_ok() {
            self.stats.acknowledged.fetch_add(1, Ordering::Relaxed);
        }
        // A stale acknowledgement changes nothing; the worker learns the
        // attempt is not its own from the stop list on its next beat.
    }

    fn reported(
        &self,
        worker: WorkerId,
        attempt: AttemptId,
        fence: Fence,
        event: Event,
        summary: Option<Vec<u8>>,
    ) {
        let finished = self.write(move |tx| {
            dispatch::report(
                tx,
                worker,
                attempt,
                fence,
                event,
                summary.as_deref(),
                UnixMillis::now(),
            )
        });
        match finished {
            Ok(state) => {
                self.stats.reports.fetch_add(1, Ordering::Relaxed);
                if state.is_terminal() {
                    // Capacity came back and dependents may be queued.
                    self.wake();
                }
            }
            // Stale fence, unknown attempt or a terminal duplicate: the
            // machine refused it and nothing changed.
            Err(_) => {
                self.stats.stale_reports.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    fn abandoned(&self, worker: WorkerId, attempt: AttemptId, fence: Fence) {
        let settled =
            self.write(move |tx| dispatch::abandon(tx, worker, attempt, fence, UnixMillis::now()));
        if settled.is_ok() {
            self.stats.abandoned.fetch_add(1, Ordering::Relaxed);
            self.wake();
        } else {
            self.stats.stale_reports.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// The synchronous fallback is never used by this controller: it resolves
    /// specs on its own thread ([`Inner::spec_requested`]) so that GitHub
    /// round trips and credential minting happen outside the session thread.
    fn spec(&self, _worker: WorkerId, _attempt: AttemptId) -> Option<(JobContext, Vec<u8>)> {
        None
    }

    fn log(&self, worker: WorkerId, attempt: AttemptId, frame: Frame) -> LogVerdict {
        let Some((run, job)) = self.log_scope(worker, attempt) else {
            self.stats.log_refused.fetch_add(1, Ordering::Relaxed);
            return LogVerdict::Refused;
        };
        match self.logs.append(run, job, attempt, &frame) {
            Ok(sentinel_store::logs::Appended::Stored { through })
            | Ok(sentinel_store::logs::Appended::Duplicate { through }) => {
                self.stats.log_frames.fetch_add(1, Ordering::Relaxed);
                LogVerdict::Acked(through)
            }
            Err(_) => {
                self.stats.log_refused.fetch_add(1, Ordering::Relaxed);
                LogVerdict::Refused
            }
        }
    }

    fn log_end(
        &self,
        worker: WorkerId,
        attempt: AttemptId,
        last_seq: u64,
        gaps: &[(u64, u64)],
    ) -> LogVerdict {
        let Some((run, job)) = self.log_scope(worker, attempt) else {
            self.stats.log_refused.fetch_add(1, Ordering::Relaxed);
            return LogVerdict::Refused;
        };
        match self.logs.finish(run, job, attempt, last_seq, gaps) {
            Ok(()) => {
                if let Some(peer) = self.peer(worker) {
                    peer.logging
                        .lock()
                        .unwrap_or_else(|p| p.into_inner())
                        .remove(&attempt);
                }
                LogVerdict::Acked(last_seq)
            }
            Err(_) => {
                self.stats.log_refused.fetch_add(1, Ordering::Relaxed);
                LogVerdict::Refused
            }
        }
    }

    fn declined(&self, _worker: WorkerId, attempt: AttemptId, _fence: Fence) {
        if self
            .write(move |tx| dispatch::lapse(tx, attempt, UnixMillis::now()))
            .is_ok()
        {
            self.stats.lapsed.fetch_add(1, Ordering::Relaxed);
            // Deliberately no wake: the job is queued again and the next
            // reconciliation places it, which bounds a worker that keeps
            // refusing to one offer per interval instead of a tight loop.
        }
    }

    fn artifact_begin(&self, worker: WorkerId, attempt: AttemptId, name: &str) -> ArtifactReply {
        use crate::session::ArtifactReply::Verdict;
        if !self.holds(worker, attempt) {
            return Verdict(ArtifactCode::Stale);
        }
        // One read snapshot: the attempt's ownership scope, its encoded spec,
        // whether the artifact already has a row, and the run's budget base.
        let scope = self.store.read(|c| {
            let tx = c.unchecked_transaction()?;
            let (tenant, run, job, index) = dispatch::attempt_scope(&tx, worker, attempt)?;
            let spec = dispatch::spec_bytes(&tx, worker, attempt)?;
            let duplicate = artifacts::exists(&tx, attempt, name)?;
            let committed = artifacts::run_bytes(&tx, tenant, run)?;
            Ok((tenant, run, job, index, spec, duplicate, committed))
        });
        let Ok((tenant, run, job, index, spec, duplicate, committed)) = scope else {
            return Verdict(ArtifactCode::Stale);
        };
        if duplicate {
            return Verdict(ArtifactCode::Duplicate);
        }
        let declared = sentinel_pipeline::RunSpec::decode(&spec)
            .ok()
            .and_then(|s| s.pipeline.jobs.get(index as usize).cloned())
            .and_then(|j| j.spec.artifacts.into_iter().find(|a| a.name == name));
        let Some(decl) = declared else {
            return Verdict(ArtifactCode::NotDeclared);
        };
        let mut state = self.artifacts.lock().unwrap_or_else(|p| p.into_inner());
        if state.in_flight.contains_key(&attempt) {
            // The session already orders one publication per attempt; a
            // second begin here means the worker raced its own stream.
            return Verdict(ArtifactCode::Invalid);
        }
        if committed.saturating_add(*state.runs.get(&run).unwrap_or(&0)) >= MAX_RUN_ARTIFACT_BYTES {
            return Verdict(ArtifactCode::TooLarge);
        }
        state.in_flight.insert(
            attempt,
            InFlight {
                tenant,
                run,
                job,
                name: name.to_string(),
                retain_secs: decl.retain_secs,
                done: Vec::new(),
                accounted: 0,
                last_path: String::new(),
                file: None,
            },
        );
        ArtifactReply::Grant
    }

    fn artifact_file(
        &self,
        _worker: WorkerId,
        attempt: AttemptId,
        path: &str,
        len: u64,
        mode: u32,
    ) -> Option<ArtifactCode> {
        let mut state = self.artifacts.lock().unwrap_or_else(|p| p.into_inner());
        enum Out {
            Ok,
            Fail(ArtifactCode),
        }
        let out = {
            let Some(f) = state.in_flight.get(&attempt) else {
                return Some(ArtifactCode::Stale);
            };
            let (tenant, run, accounted) = (f.tenant, f.run, f.accounted);
            if f.file.is_some()
                || !objects::valid_entry_path(path)
                || f.done.len() >= MAX_ARTIFACT_ENTRIES
                || (!f.last_path.is_empty() && path <= f.last_path.as_str())
            {
                Out::Fail(ArtifactCode::Invalid)
            } else {
                // The run budget is committed bytes plus what every
                // in-flight artifact of the run already charges.
                let committed = self
                    .store
                    .read(|c| artifacts::run_bytes(c, tenant, run))
                    .unwrap_or(u64::MAX);
                let charged = state.runs.get(&run).copied().unwrap_or(0);
                if committed.saturating_add(charged).saturating_add(len) > MAX_RUN_ARTIFACT_BYTES
                    || accounted.saturating_add(len) > MAX_ARTIFACT_BYTES
                {
                    Out::Fail(ArtifactCode::TooLarge)
                } else {
                    match self.objects.stage_begin(len) {
                        Ok(staging) => {
                            *state.runs.entry(run).or_default() += len;
                            let f = state.in_flight.get_mut(&attempt).expect("checked present");
                            f.last_path = path.to_string();
                            f.accounted += len;
                            f.file = Some(OpenFile {
                                path: path.to_string(),
                                mode: mode & crate::session::ARTIFACT_MODE_BITS,
                                declared: len,
                                next_seq: 0,
                                staging,
                            });
                            // An empty file sends no data frames: seal it at
                            // once, or `artifact_end` would find it still open.
                            if len == 0 {
                                let file = f.file.take().expect("just opened");
                                match self.objects.stage_seal(tenant, file.staging, 0) {
                                    Ok(staged) => {
                                        f.done.push((file.path, file.mode, staged));
                                        Out::Ok
                                    }
                                    Err(_) => Out::Fail(ArtifactCode::Store),
                                }
                            } else {
                                Out::Ok
                            }
                        }
                        Err(_) => Out::Fail(ArtifactCode::Store),
                    }
                }
            }
        };
        match out {
            Out::Ok => None,
            Out::Fail(code) => Some(self.artifact_fail(&mut state, attempt, code)),
        }
    }

    fn artifact_data(
        &self,
        _worker: WorkerId,
        attempt: AttemptId,
        seq: u32,
        bytes: &[u8],
    ) -> Option<ArtifactCode> {
        let mut state = self.artifacts.lock().unwrap_or_else(|p| p.into_inner());
        enum Out {
            Ok,
            Fail(ArtifactCode),
        }
        let out = {
            let Some(f) = state.in_flight.get_mut(&attempt) else {
                return Some(ArtifactCode::Stale);
            };
            let Some(file) = f.file.as_mut() else {
                return Some(self.artifact_fail(&mut state, attempt, ArtifactCode::Invalid));
            };
            if file.next_seq != seq
                || file.staging.written().saturating_add(bytes.len() as u64) > file.declared
            {
                Out::Fail(ArtifactCode::Invalid)
            } else if self.objects.stage_write(&mut file.staging, bytes).is_err() {
                Out::Fail(ArtifactCode::Store)
            } else {
                file.next_seq += 1;
                if file.staging.written() == file.declared {
                    let file = f.file.take().expect("open file checked");
                    match self
                        .objects
                        .stage_seal(f.tenant, file.staging, file.declared)
                    {
                        Ok(staged) => f.done.push((file.path, file.mode, staged)),
                        Err(_) => {
                            return Some(self.artifact_fail(
                                &mut state,
                                attempt,
                                ArtifactCode::Store,
                            ));
                        }
                    }
                }
                Out::Ok
            }
        };
        match out {
            Out::Ok => None,
            Out::Fail(code) => Some(self.artifact_fail(&mut state, attempt, code)),
        }
    }

    fn artifact_end(&self, _worker: WorkerId, attempt: AttemptId, name: &str) -> ArtifactCode {
        let mut state = self.artifacts.lock().unwrap_or_else(|p| p.into_inner());
        let Some(f) = state.in_flight.get(&attempt) else {
            return ArtifactCode::Stale;
        };
        if f.name != name || f.file.is_some() {
            let code = self.artifact_fail(&mut state, attempt, ArtifactCode::Invalid);
            return code;
        }
        let f = state.in_flight.remove(&attempt).expect("checked present");
        if let Some(r) = state.runs.get_mut(&f.run) {
            *r = r.saturating_sub(f.accounted);
        }
        drop(state);
        let entries: Vec<objects::Entry> = f
            .done
            .iter()
            .map(|(path, mode, staged)| objects::Entry {
                path: path.clone(),
                digest: staged.digest(),
                len: staged.len(),
                mode: *mode,
            })
            .collect();
        let manifest = artifacts::manifest_name(f.job, &f.name);
        let retain_until = UnixMillis(
            UnixMillis::now()
                .0
                .saturating_add(f.retain_secs.saturating_mul(1000) as i64),
        );
        let staged: Vec<objects::Staged> = f.done.into_iter().map(|(_, _, s)| s).collect();
        let objects = Arc::clone(&self.objects);
        let (tenant, run, job) = (f.tenant, f.run, f.job);
        let artifact_name = f.name;
        let bytes = entries.iter().map(|e| e.len).sum::<u64>();
        let count = entries.len() as u64;
        // One transaction: object references, the manifest row and file,
        // then the artifact row that names its version. A crash mid-commit
        // can only leave adoptable orphans under `objects/`.
        self.write(move |tx| {
            for s in &staged {
                objects.commit(tx, s)?;
            }
            let version = objects.commit_manifest(
                tx,
                tenant,
                objects::Kind::Artifact,
                &manifest,
                &entries,
            )?;
            artifacts::record(
                tx,
                tenant,
                run,
                job,
                attempt,
                &artifact_name,
                artifacts::State::Captured,
                Some(version),
                count,
                bytes,
                retain_until,
                UnixMillis::now(),
            )?;
            Ok(())
        })
        .map(|()| {
            self.stats.artifacts.fetch_add(1, Ordering::Relaxed);
            ArtifactCode::Stored
        })
        .unwrap_or(ArtifactCode::Store)
    }

    fn artifact_absent(
        &self,
        worker: WorkerId,
        attempt: AttemptId,
        name: &str,
        reason: u8,
    ) -> ArtifactCode {
        let outcome = if reason == 0 {
            artifacts::State::Absent
        } else {
            artifacts::State::Failed
        };
        // An in-flight publication of the same name is abandoned; its scope
        // comes with the state and needs no lookup.
        {
            let mut state = self.artifacts.lock().unwrap_or_else(|p| p.into_inner());
            if let Some(f) = state.in_flight.remove(&attempt) {
                if let Some(r) = state.runs.get_mut(&f.run) {
                    *r = r.saturating_sub(f.accounted);
                }
                drop(state);
                self.record_artifact(&f, attempt, outcome, None);
                for (_, _, staged) in f.done {
                    staged.discard();
                }
                return if reason == 0 {
                    ArtifactCode::Absent
                } else {
                    ArtifactCode::CaptureFailed
                };
            }
        }
        if !self.holds(worker, attempt) {
            return ArtifactCode::Stale;
        }
        let scope = self.store.read(|c| {
            let tx = c.unchecked_transaction()?;
            let (tenant, run, job, index) = dispatch::attempt_scope(&tx, worker, attempt)?;
            let spec = dispatch::spec_bytes(&tx, worker, attempt)?;
            let duplicate = artifacts::exists(&tx, attempt, name)?;
            Ok((tenant, run, job, index, spec, duplicate))
        });
        let Ok((tenant, run, job, index, spec, duplicate)) = scope else {
            return ArtifactCode::Stale;
        };
        if duplicate {
            return ArtifactCode::Duplicate;
        }
        let declared = sentinel_pipeline::RunSpec::decode(&spec)
            .ok()
            .and_then(|s| s.pipeline.jobs.get(index as usize).cloned())
            .and_then(|j| j.spec.artifacts.into_iter().find(|a| a.name == name));
        let Some(decl) = declared else {
            return ArtifactCode::NotDeclared;
        };
        let retain_until = UnixMillis(
            UnixMillis::now()
                .0
                .saturating_add(decl.retain_secs.saturating_mul(1000) as i64),
        );
        let artifact_name = name.to_string();
        let recorded = self.write(move |tx| {
            artifacts::record(
                tx,
                tenant,
                run,
                job,
                attempt,
                &artifact_name,
                outcome,
                None,
                0,
                0,
                retain_until,
                UnixMillis::now(),
            )
        });
        match recorded {
            Ok(_) => {
                if reason == 0 {
                    ArtifactCode::Absent
                } else {
                    ArtifactCode::CaptureFailed
                }
            }
            Err(_) => ArtifactCode::Store,
        }
    }
}

/// A running controller: listener, fleet and dispatcher.
fn resolve_spec(
    store: &Store,
    key: Option<&sentinel_auth::sealed::Key>,
    app: Option<&Arc<sentinel_github::app::App>>,
    destinations: &[String],
    worker: WorkerId,
    attempt: AttemptId,
) -> sentinel_store::Result<(JobContext, Vec<u8>)> {
    use sentinel_store::{Error as StoreError, sources};
    // One read snapshot: the attempt's context and spec, the binding that
    // authorizes it, and the destination policy.
    let (mut context, bytes, binding) = store.read(|conn| {
        let tx = conn.unchecked_transaction()?;
        let c = dispatch::job_context(&tx, worker, attempt)?;
        let bytes = dispatch::spec_bytes(&tx, worker, attempt)?;
        let context = JobContext {
            source: None,
            run: c.run,
            repo: c.repo,
            repo_name: c.repo_name,
            job: c.job,
            job_name: c.job_name,
            sha: c.sha,
            event: session::EventContext {
                name: c.event.name,
                ref_name: c.event.ref_name,
                base_ref: c.event.base_ref,
                pr_number: c.event.pr_number,
                key: c.event.key,
            },
            cancelled: c.cancelled,
            needs: c.needs,
        };
        let binding = match sentinel_intake::source::lookup_conn(&tx, context.repo)? {
            None => None,
            Some(binding) => {
                let authority = sentinel_protocol::source::remote(&binding.metadata.binding.remote)
                    .ok_or(StoreError::Forbidden)?;
                if !destinations.iter().any(|d| d == authority) {
                    return Err(StoreError::Forbidden);
                }
                let now = UnixMillis::now();
                let (tenant, repo) = sources::attempt_repo(&tx, worker, attempt, now)?;
                if (tenant, repo) != (binding.tenant, binding.repo) {
                    return Err(StoreError::Forbidden);
                }
                let spec = sentinel_pipeline::RunSpec::decode(&bytes)
                    .map_err(|_| StoreError::Corrupt("run spec"))?;
                sources::validate_source(&tx, repo, &spec.source)?;
                Some(binding)
            }
        };
        Ok((context, bytes, binding))
    })?;
    if let Some(binding) = binding {
        // The only network step; a revocation that lands while a token is
        // being minted wins the race (rechecked inside `issue`).
        let access = sentinel_intake::source::issue(store, key, app, &binding, UnixMillis::now())
            .map_err(|_| StoreError::Forbidden)?;
        // And the lease that authorized this delivery must still be live.
        let (tenant, repo) = (binding.tenant, binding.repo);
        store.read(move |conn| {
            if sources::attempt_repo(conn, worker, attempt, UnixMillis::now())? != (tenant, repo) {
                return Err(StoreError::Forbidden);
            }
            Ok(())
        })?;
        context.source = Some(access);
    }
    Ok((context, bytes))
}

fn send_resolved(
    sender: &Sender,
    attempt: AttemptId,
    protocol: u16,
    spec: Option<(JobContext, Vec<u8>)>,
) -> Result<()> {
    use session::ServerMessage;
    // Protocol 3 carries the event context and (from 2) the source access;
    // anything older is served `NoSpec` rather than a message it cannot decode.
    let Some((context, bytes)) =
        spec.filter(|(_, b)| protocol >= 3 && b.len() <= session::MAX_SPEC_BYTES)
    else {
        return sender.send(&ServerMessage::NoSpec {
            attempt: *attempt.as_bytes(),
        });
    };
    sender.send(&ServerMessage::Context(context.to_wire(attempt)))?;
    if let Some(access) = context.source {
        sender.send(&ServerMessage::Source {
            attempt: *attempt.as_bytes(),
            access,
        })?;
    }
    let chunks = bytes.chunks(session::SPEC_CHUNK_BYTES);
    let count = chunks.len();
    if count == 0 {
        return sender.send(&ServerMessage::Spec {
            attempt: *attempt.as_bytes(),
            seq: 0,
            last: true,
            bytes: Vec::new(),
        });
    }
    for (seq, chunk) in chunks.enumerate() {
        sender.send(&ServerMessage::Spec {
            attempt: *attempt.as_bytes(),
            seq: seq as u32,
            last: seq + 1 == count,
            bytes: chunk.to_vec(),
        })?;
    }
    Ok(())
}

/// A running controller: listener, fleet and dispatcher.
pub struct Controller {
    inner: Arc<Inner>,
    addr: SocketAddr,
    fingerprint: Digest,
    reconciled: dispatch::Reconciled,
    acceptor: Option<thread::JoinHandle<()>>,
    dispatcher: Option<thread::JoinHandle<()>>,
}

impl Controller {
    pub fn set_source_destinations(&self, destinations: Vec<String>) {
        *self
            .inner
            .source_destinations
            .lock()
            .unwrap_or_else(|p| p.into_inner()) = Arc::new(destinations);
    }
    pub fn set_source_app(&self, app: Arc<sentinel_github::app::App>) {
        *self
            .inner
            .source_app
            .lock()
            .unwrap_or_else(|p| p.into_inner()) = Some(app);
    }
    pub fn set_source_key(&self, key: Arc<sentinel_auth::sealed::Key>) {
        *self
            .inner
            .source_key
            .lock()
            .unwrap_or_else(|p| p.into_inner()) = Some(key);
    }
    /// Bind `listen`, present `identity`, and start serving workers of
    /// `store`. Returns once the socket is bound; workers may connect.
    pub fn start(
        store: Arc<Store>,
        logs: Arc<LogStore>,
        objects: Arc<Objects>,
        identity: Identity,
        listen: SocketAddr,
    ) -> Result<Controller> {
        let fingerprint = identity.fingerprint();
        let config = tls::server_config(identity)?;
        // What the last controller left mid-flight is settled from the rows
        // before any worker is admitted: expired leases, unanswered offers,
        // attempts of workers revoked meanwhile.
        let reconciled = store
            .writer()
            .write(|tx| dispatch::reconcile_startup(tx, UnixMillis::now()))
            .map_err(|_| Error::Internal("startup reconciliation"))?;
        let listener = TcpListener::bind(listen)?;
        let addr = listener.local_addr()?;
        let inner = Arc::new(Inner {
            source_destinations: Mutex::new(Arc::new(Vec::new())),
            source_app: Mutex::new(None),
            source_active: Arc::new(AtomicUsize::new(0)),
            source_key: Mutex::new(None),
            store,
            logs,
            objects,
            artifacts: Mutex::new(ArtifactState::default()),
            config,
            fleet: Mutex::new(HashMap::new()),
            generation: AtomicU64::new(1),
            wake: (Mutex::new(false), Condvar::new()),
            stop: AtomicBool::new(false),
            sessions: AtomicUsize::new(0),
            stats: Stats::default(),
        });
        let acceptor = {
            let inner = Arc::clone(&inner);
            thread::Builder::new()
                .name("sentinel-link-accept".into())
                .spawn(move || accept_loop(&inner, &listener))?
        };
        let dispatcher = {
            let inner = Arc::clone(&inner);
            thread::Builder::new()
                .name("sentinel-dispatch".into())
                .spawn(move || inner.dispatch_loop())?
        };
        Ok(Controller {
            inner,
            addr,
            fingerprint,
            reconciled,
            acceptor: Some(acceptor),
            dispatcher: Some(dispatcher),
        })
    }

    /// What starting this controller settled from the previous one's rows.
    pub fn reconciled(&self) -> dispatch::Reconciled {
        self.reconciled
    }

    /// A cheap handle for other subsystems (the API) to wake the dispatcher
    /// and ask who is connected, without owning the controller.
    pub fn handle(&self) -> Handle {
        Handle(Arc::clone(&self.inner))
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    /// What workers must pin.
    pub fn fingerprint(&self) -> Digest {
        self.fingerprint
    }

    /// Something changed the queue (an enqueue, a completion, a cancel):
    /// dispatch now rather than at the next reconciliation.
    pub fn wake(&self) {
        self.inner.wake();
    }

    /// Workers with a live session, for placement reasons and operators.
    pub fn connected(&self) -> Vec<WorkerId> {
        self.inner
            .fleet
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .keys()
            .copied()
            .collect()
    }

    pub fn stats(&self) -> &Stats {
        &self.inner.stats
    }

    /// Stop accepting, close every session and stop dispatching. Returns
    /// whether every session thread ended within `timeout`; the store is the
    /// caller's to shut down afterwards, and nothing durable is lost either
    /// way — leases and offers are rows, reconciled at the next start.
    pub fn shutdown(mut self, timeout: Duration) -> bool {
        self.inner.stop.store(true, Ordering::Release);
        self.inner.wake();
        // Unblock the acceptor with one connection to itself.
        let _ = TcpStream::connect_timeout(&self.addr, Duration::from_secs(1));
        if let Some(handle) = self.acceptor.take() {
            let _ = handle.join();
        }
        if let Some(handle) = self.dispatcher.take() {
            let _ = handle.join();
        }
        let peers: Vec<Arc<Peer>> = self
            .inner
            .fleet
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .values()
            .cloned()
            .collect();
        for peer in peers {
            peer.sender.close();
        }
        let deadline = Instant::now() + timeout;
        while self.inner.sessions.load(Ordering::Acquire) > 0 {
            if Instant::now() >= deadline {
                return false;
            }
            thread::sleep(Duration::from_millis(5));
        }
        true
    }
}

fn accept_loop(inner: &Arc<Inner>, listener: &TcpListener) {
    for socket in listener.incoming() {
        if inner.stop.load(Ordering::Acquire) {
            return;
        }
        let Ok(socket) = socket else { continue };
        if inner.sessions.load(Ordering::Acquire) >= MAX_SESSIONS {
            drop(socket);
            continue;
        }
        inner.sessions.fetch_add(1, Ordering::AcqRel);
        let session = Arc::clone(inner);
        let spawned = thread::Builder::new()
            .name("sentinel-link-session".into())
            .spawn(move || {
                session.serve(socket);
                session.sessions.fetch_sub(1, Ordering::AcqRel);
            });
        if spawned.is_err() {
            inner.sessions.fetch_sub(1, Ordering::AcqRel);
        }
    }
}

/// See [`Controller::handle`].
#[derive(Clone)]
pub struct Handle(Arc<Inner>);

impl Handle {
    pub fn wake(&self) {
        self.0.wake();
    }

    pub fn connected(&self) -> Vec<WorkerId> {
        self.0
            .fleet
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .keys()
            .copied()
            .collect()
    }

    /// Close a worker's session from the controller's side. Its leases stay
    /// until they expire and it may reconnect at once; an operator's way to
    /// force a fresh session, and the test's way to lose the network.
    pub fn disconnect(&self, worker: WorkerId) -> bool {
        let peer = self
            .0
            .fleet
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&worker)
            .cloned();
        match peer {
            Some(peer) => {
                peer.sender.close();
                true
            }
            None => false,
        }
    }
}

impl std::fmt::Debug for Controller {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Controller")
            .field("addr", &self.addr)
            .field("fingerprint", &self.fingerprint)
            .finish_non_exhaustive()
    }
}
