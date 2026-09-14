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
    collections::{HashMap, HashSet},
    net::{SocketAddr, TcpListener, TcpStream},
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicBool, AtomicI64, AtomicU64, AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use sentinel_auth::secret::{Digest, Secret};
use sentinel_core::{AttemptId, Event, Fence, PoolId, UnixMillis, WorkerId};
use sentinel_protocol::logs::Frame;
use sentinel_protocol::negotiate::Hello;
use sentinel_store::{Store, dispatch, logs::LogStore, workers};

use crate::{
    Error, Result,
    identity::Identity,
    session::{
        self, Admission, Admitted, Beat, Capacity, JobContext, LogVerdict, Offer, Rejection,
        Sender, SessionHandler,
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
}

struct Peer {
    sender: Sender,
    pool: PoolId,
    generation: u64,
    /// When liveness was last written, so a beat costs a write once a minute.
    seen_recorded_ms: AtomicI64,
    /// Attempts verified as held by this worker for log frames, so the
    /// check costs one read per attempt rather than one per frame.
    logging: Mutex<HashSet<AttemptId>>,
}

struct Inner {
    source_destinations: Mutex<Arc<Vec<String>>>,
    source_app: Mutex<Option<Arc<sentinel_github::app::App>>>,
    source_active: Arc<AtomicUsize>,
    source_key: Mutex<Option<Arc<sentinel_auth::sealed::Key>>>,
    store: Arc<Store>,
    logs: Arc<LogStore>,
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
            logging: Mutex::new(HashSet::new()),
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
        let Some(peer) = self.peer(worker) else {
            return false;
        };
        if peer
            .logging
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .contains(&attempt)
        {
            return true;
        }
        let held = self
            .store
            .read(|c| dispatch::is_held(c, worker, attempt))
            .unwrap_or(false);
        if held {
            peer.logging
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .insert(attempt);
        }
        held
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
                    app.as_deref(),
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

    fn spec(&self, worker: WorkerId, attempt: AttemptId) -> Option<(JobContext, Vec<u8>)> {
        self.store
            .read(|c| {
                let context = dispatch::job_context(c, worker, attempt)?;
                let bytes = dispatch::spec_bytes(c, worker, attempt)?;
                Ok((
                    JobContext {
                        source: {
                            let bound: bool = c.query_row(
                                "SELECT EXISTS(SELECT 1 FROM source_bindings WHERE repo_id=?1)",
                                [context.repo.as_bytes()],
                                |r| r.get(0),
                            )?;
                            if bound {
                                let now = UnixMillis::now();
                                let (tenant, repo) =
                                    sentinel_store::sources::attempt_repo(c, worker, attempt, now)?;
                                let key = self
                                    .source_key
                                    .lock()
                                    .unwrap_or_else(|p| p.into_inner())
                                    .clone()
                                    .ok_or(sentinel_store::Error::Forbidden)?;
                                Some(sentinel_store::sources::issue(c, tenant, repo, &key, now)?)
                            } else {
                                None
                            }
                        },
                        run: context.run,
                        repo: context.repo,
                        repo_name: context.repo_name,
                        job: context.job,
                        job_name: context.job_name,
                        sha: context.sha,
                        cancelled: context.cancelled,
                        needs: context.needs,
                    },
                    bytes,
                ))
            })
            .ok()
    }

    fn log(&self, worker: WorkerId, attempt: AttemptId, frame: Frame) -> LogVerdict {
        if !self.holds(worker, attempt) {
            self.stats.log_refused.fetch_add(1, Ordering::Relaxed);
            return LogVerdict::Refused;
        }
        match self.logs.append(attempt, &frame) {
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

    fn log_end(&self, worker: WorkerId, attempt: AttemptId, last_seq: u64, gaps: &[(u64, u64)]) {
        if !self.holds(worker, attempt) {
            return;
        }
        let _ = self.logs.finish(attempt, last_seq, gaps);
        if let Some(peer) = self.peer(worker) {
            peer.logging
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .remove(&attempt);
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
}

/// A running controller: listener, fleet and dispatcher.
fn resolve_spec(
    store: &Store,
    key: Option<&sentinel_auth::sealed::Key>,
    app: Option<&sentinel_github::app::App>,
    destinations: &[String],
    worker: WorkerId,
    attempt: AttemptId,
) -> sentinel_store::Result<(JobContext, Vec<u8>)> {
    use sentinel_store::{Error as StoreError, sources, sources_forge};
    let (mut context, bytes, forge) = store.read(|conn| {
        let tx = conn.unchecked_transaction()?;
        let c = dispatch::job_context(&tx, worker, attempt)?;
        let bytes = dispatch::spec_bytes(&tx, worker, attempt)?;
        let mut context = JobContext {
            source: None,
            run: c.run,
            repo: c.repo,
            repo_name: c.repo_name,
            job: c.job,
            job_name: c.job_name,
            sha: c.sha,
            cancelled: c.cancelled,
            needs: c.needs,
        };
        let forge = match sources::load_metadata(&tx, context.repo) {
            Err(StoreError::NotFound) => None,
            Err(e) => return Err(e),
            Ok(m) => {
                let authority = sentinel_protocol::source::remote(&m.binding.remote)
                    .ok_or(StoreError::Forbidden)?;
                if !destinations.iter().any(|d| d == authority) {
                    return Err(StoreError::Forbidden);
                }
                let now = UnixMillis::now();
                let (tenant, repo) = sources::attempt_repo(&tx, worker, attempt, now)?;
                let spec = sentinel_pipeline::RunSpec::decode(&bytes)
                    .map_err(|_| StoreError::Corrupt("run spec"))?;
                sources::validate_source(&tx, repo, &spec.source)?;
                if m.forge.is_some() {
                    Some((tenant, repo, m, sources_forge::grant(&tx, tenant, repo)?))
                } else {
                    context.source = Some(sources::issue(
                        &tx,
                        tenant,
                        repo,
                        key.ok_or(StoreError::Forbidden)?,
                        now,
                    )?);
                    None
                }
            }
        };
        Ok((context, bytes, forge))
    })?;
    if let Some((tenant, repo, metadata, grant)) = forge {
        let token = app
            .ok_or(StoreError::Forbidden)?
            .source_token(
                grant.installation,
                grant.account,
                grant.repo,
                &metadata.binding.remote,
                UnixMillis::now().0,
            )
            .map_err(|_| StoreError::Forbidden)?;
        // HTTP ran without any database connection or writer lock held. A
        // revoked lease, rotated binding or lifecycle update wins this race.
        store.read(|conn| {
            let tx = conn.unchecked_transaction()?;
            if sources::attempt_repo(&tx, worker, attempt, UnixMillis::now())? != (tenant, repo)
                || sources::load_metadata(&tx, repo)?.version != metadata.version
                || sources_forge::grant(&tx, tenant, repo)? != grant
            {
                return Err(StoreError::Forbidden);
            }
            Ok(())
        })?;
        context.source = Some(sentinel_protocol::source::Access {
            binding: metadata.binding,
            version: metadata.version,
            expires_ms: token.expires_ms.min(UnixMillis::now().0 + 60_000),
            credential: sentinel_protocol::source::Credential::Https {
                username: "x-access-token".into(),
                secret: token.secret,
            },
        });
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
    let Some((context, bytes)) = spec.filter(|(c, b)| {
        b.len() <= session::MAX_SPEC_BYTES && (c.source.is_none() || protocol >= 2)
    }) else {
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
