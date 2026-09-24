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
    collections::{HashMap, HashSet, VecDeque},
    net::{SocketAddr, TcpListener, TcpStream},
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicBool, AtomicI64, AtomicU64, AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use sentinel_auth::secret::{Digest, Secret};
use sentinel_cache::remote::{Need, Upload};
use sentinel_core::{
    AttemptId, Event, Fence, JobId, PoolId, RunId, TenantId, UnixMillis, WorkerId,
};
use sentinel_protocol::limits::{MAX_ARTIFACT_BYTES, MAX_ARTIFACT_ENTRIES, MAX_RUN_ARTIFACT_BYTES};
use sentinel_protocol::logs::Frame;
use sentinel_protocol::negotiate::{
    Capabilities, Hello, MAX_PREFETCH_IMAGES, PREFETCH_MIN, PROFILE_MIN, Profile,
};
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
        self, Accepted, Admission, Admitted, ArtifactCode, ArtifactReply, Beat, BulkSession,
        Capacity, JobContext, LogVerdict, Offer, Rejection, Sender, SessionHandler, TransportStats,
    },
    tailcat::{NodeKey, Server, canonical},
    tls,
};

/// How long the dispatcher sleeps without a wake before re-checking the
/// queue and sweeping unacknowledged offers. A safety net, not the clock.
pub const RECONCILE_INTERVAL: Duration = Duration::from_secs(2);
/// The prefetch pass (K05) reads the queue at most this often: a hint is
/// advisory, so a burst of wakes never becomes a burst of reads.
pub const PREFETCH_INTERVAL: Duration = Duration::from_millis(500);
const _: () = assert!(
    dispatch::MAX_PREFETCH_HINTS <= MAX_PREFETCH_IMAGES,
    "a hint must fit the wire bound"
);
/// Sessions accepted at once; beyond this a connection is closed unserved.
pub const MAX_SESSIONS: usize = 1024;
/// Connections that have not finished their handshake and hello yet. A
/// separate cap: peers that have proved nothing can hold at most this many
/// slots (each for at most the handshake deadline), so three quarters of
/// [`MAX_SESSIONS`] always stay for authenticated workers, while a fleet
/// reconnecting at once after a controller restart still gets through.
pub const MAX_PENDING: usize = 256;
/// Spec resolutions running at once. Each may make GitHub round trips to
/// mint a source token, so they run off the session threads, bounded.
const SPEC_RESOLVERS: usize = 8;
/// Spec requests waiting for a resolver, fleet-wide. Per worker the bound
/// is what it may hold ([`dispatch::MAX_HELD_ATTEMPTS`]); a request past
/// either bound is dropped unanswered and the worker asks again.
const MAX_SPEC_QUEUE: usize = 4096;
/// How long a resolver waits for an acknowledgement still in flight on the
/// control connection before leaving the request unanswered.
const SPEC_ACK_WAIT: Duration = Duration::from_millis(dispatch::OFFER_ACK_MS as u64);
/// Tries per request against a transient fault (reader overload, a GitHub
/// timeout) before the request is left for the worker to ask again.
const SPEC_TRIES: u32 = 3;

/// Rows one storage maintenance pass may touch.
const STORAGE_BATCH: i64 = 256;
/// Directory entries one orphan sweep pass examines at most.
const ORPHAN_SCAN_BUDGET: u32 = 4096;
/// How often the maintenance thread checks whether a pass is due.
const MAINTENANCE_TICK: Duration = Duration::from_millis(250);

/// How the controller runs storage maintenance (D06). Unset disables the
/// pass entirely — no deletions, no quota bookkeeping side effects.
#[derive(Clone, Copy, Debug)]
pub struct StoragePolicy {
    /// Finished attempt logs are kept this long; `<= 0` keeps them.
    pub log_retention_ms: i64,
    /// The pass runs at most this often, on the storage maintenance thread.
    pub interval_ms: i64,
}

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
    /// Protocol-7 bulk connections attached to a live control session.
    pub bulk_attached: AtomicU64,
    /// Protocol-7 bulk connections refused: no live control session with
    /// that certificate.
    pub bulk_refused: AtomicU64,
    /// Remote-cache needs and offers refused `denied`: no remote store, an
    /// attempt this worker does not own (or released too long ago), or a
    /// boundary that is not the job's.
    pub cache_denied: AtomicU64,
    /// Bytes the remote-cache store's reclamation removed, in total.
    pub remote_cache_freed: AtomicU64,
    /// The remote-cache store's kept bytes after its last sweep.
    pub remote_cache_bytes: AtomicU64,
    /// Connections closed unserved because the session or pre-admission
    /// cap was full.
    pub shed: AtomicU64,
    /// Spec requests handed back to the queue: offers declined and
    /// acknowledged attempts whose spec never reached their worker.
    pub handed_back: AtomicU64,
    /// Placement transactions (or the reads that precede them) the store
    /// failed. Each failure is also logged, by error kind only, at most once
    /// a minute (P08-15): a fleet that stops placing leaves evidence.
    pub placement_errors: AtomicU64,
    /// Expiry, queue-timeout, offer-lapse and revocation sweeps the store
    /// failed, counted and logged the same way. A sweep that found its row
    /// already moved (renewed, acknowledged, released) is not a failure.
    pub sweep_errors: AtomicU64,
    /// Prefetch hints sent (protocol 9, K05): one per session whose wanted
    /// set changed.
    pub prefetch_hints: AtomicU64,
    /// Live sessions closed because their worker was revoked (P08-7).
    pub revoked_sessions: AtomicU64,
}

struct Peer {
    sender: Sender,
    /// The connection's remote end as accepted (canonical): what a hand-off
    /// matches against the helper's connections, without a socket call.
    addr: SocketAddr,
    /// The worker advertised `HANDOFF_ANSWER`: its silence after a hand-off
    /// close means the close was not delivered.
    answers_handoff: bool,
    pool: PoolId,
    generation: u64,
    /// The CPU and memory the hello reported: the sweep's order and what the
    /// rest of the fleet can hold are read from here, never from the store.
    cpu_millis: i64,
    memory_bytes: i64,
    /// The scratch disk its protocol-7 profile reported; 0 until then (or
    /// for protocol 6), which is not a disk constraint.
    disk_bytes: AtomicI64,
    /// The measured load its protocol-7 profile reported: CPU busy
    /// nanoseconds over the worker's sampling window, across all cores; 0
    /// when unmeasured. Read by the dispatch sweep's ranking (Q03).
    load_ns: AtomicI64,
    /// Warm cache bytes its profile reported; 0 when unmeasured.
    cache_bytes: AtomicI64,
    /// When liveness was last written, so a beat costs a write once a minute.
    seen_recorded_ms: AtomicI64,
    /// The certificate this session presented; a bulk connection may only
    /// attach to it from the same fingerprint.
    fingerprint: Digest,
    /// The session's negotiated protocol: bulk traffic and the profile are
    /// gated on it.
    protocol: u16,
    /// The latest transport telemetry the worker reported (Q07).
    transport: Mutex<Option<TransportStats>>,
    /// Attempts verified as held by this worker for log frames, mapped to
    /// their (run, job) so the store path costs one read per attempt
    /// rather than one per frame.
    logging: Mutex<HashMap<AttemptId, (RunId, JobId)>>,
    /// The protocol-7 bulk connection attached to this session, closed with
    /// it: a bulk connection lives exactly as long as its control session.
    bulk: Mutex<Option<Sender>>,
    /// The prefetch hint (protocol 9) this session was last sent; `None`
    /// until the first, so a new session always learns the current set.
    prefetch_sent: Mutex<Option<Vec<String>>>,
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
    /// Settled (ended, failed or abandoned) and out of the map: a caller
    /// that found the entry before it left answers `Stale`.
    settled: bool,
}

/// One attempt's publication behind its own lock: file writes, fsyncs and
/// renames happen under it, never under the process-wide map lock.
type Publication = Arc<Mutex<InFlight>>;

#[derive(Default)]
struct ArtifactState {
    in_flight: HashMap<AttemptId, Publication>,
    /// Accounted in-flight bytes per run: the per-run budget stays exact
    /// while attempts on different workers publish concurrently.
    runs: HashMap<RunId, u64>,
}

/// One worker's request for an attempt's run spec, waiting for a resolver.
struct SpecRequest {
    worker: WorkerId,
    attempt: AttemptId,
    sender: Sender,
    protocol: u16,
}

/// The bounded spec queue (P04-4): at most [`SPEC_RESOLVERS`] resolutions
/// run at once, the rest wait here in arrival order instead of being
/// refused. A request already waiting or running for the same attempt is
/// not queued twice, and a worker can have no more waiting than it may
/// hold. Resolver threads drain the queue and exit when it is empty.
struct SpecDesk<T> {
    state: Mutex<DeskState<T>>,
}

struct DeskState<T> {
    running: usize,
    queue: VecDeque<((WorkerId, AttemptId), T)>,
    /// Queued or being resolved.
    pending: HashSet<(WorkerId, AttemptId)>,
    per_worker: HashMap<WorkerId, usize>,
}

/// What [`SpecDesk::submit`] did with a request.
#[derive(Debug, PartialEq, Eq)]
enum Submitted {
    /// Queued; the caller must start one more resolver thread.
    Start,
    /// Queued behind the running resolvers.
    Queued,
    /// The same attempt is already waiting or being resolved.
    Duplicate,
    /// Over the per-worker or fleet bound: dropped, the worker asks again.
    Full,
}

impl<T> SpecDesk<T> {
    fn new() -> Self {
        SpecDesk {
            state: Mutex::new(DeskState {
                running: 0,
                queue: VecDeque::new(),
                pending: HashSet::new(),
                per_worker: HashMap::new(),
            }),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, DeskState<T>> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn submit(&self, key: (WorkerId, AttemptId), request: T) -> Submitted {
        let mut state = self.lock();
        if state.pending.contains(&key) {
            return Submitted::Duplicate;
        }
        let queued = state.per_worker.get(&key.0).copied().unwrap_or(0);
        if state.queue.len() >= MAX_SPEC_QUEUE || queued >= dispatch::MAX_HELD_ATTEMPTS {
            return Submitted::Full;
        }
        state.pending.insert(key);
        *state.per_worker.entry(key.0).or_default() += 1;
        state.queue.push_back((key, request));
        if state.running < SPEC_RESOLVERS {
            state.running += 1;
            Submitted::Start
        } else {
            Submitted::Queued
        }
    }

    /// The next request for a resolver thread, after settling the one it
    /// finished (`done`). `None` means the queue is empty and the thread
    /// has been counted out — it must exit.
    fn next(&self, done: Option<(WorkerId, AttemptId)>) -> Option<((WorkerId, AttemptId), T)> {
        let mut state = self.lock();
        if let Some(key) = done {
            state.pending.remove(&key);
        }
        match state.queue.pop_front() {
            Some((key, request)) => {
                if let Some(n) = state.per_worker.get_mut(&key.0) {
                    *n -= 1;
                    if *n == 0 {
                        state.per_worker.remove(&key.0);
                    }
                }
                Some((key, request))
            }
            None => {
                state.running -= 1;
                None
            }
        }
    }

    /// A resolver thread could not be started: count it out. Its request
    /// stays queued for the next thread.
    fn not_started(&self) {
        self.lock().running -= 1;
    }
}

struct Inner {
    /// This controller, for the threads it starts from a `&self` handler.
    me: std::sync::OnceLock<std::sync::Weak<Inner>>,
    source_destinations: Mutex<Arc<Vec<String>>>,
    source_app: Mutex<Option<Arc<sentinel_github::app::App>>>,
    specs: SpecDesk<SpecRequest>,
    source_key: Mutex<Option<Arc<sentinel_auth::sealed::Key>>>,
    store: Arc<Store>,
    logs: Arc<LogStore>,
    objects: Arc<Objects>,
    artifacts: Mutex<ArtifactState>,
    /// Storage maintenance policy and when it last ran (D06).
    storage: Mutex<Option<StoragePolicy>>,
    last_storage: AtomicI64,
    /// Set (and notified) at shutdown so the maintenance thread stops
    /// without waiting out its tick.
    maintenance: (Mutex<bool>, Condvar),
    /// Where the controller keeps remote cache objects (Q08); `None` answers
    /// every cache need as a miss.
    remote_cache: Mutex<Option<std::path::PathBuf>>,
    config: Arc<rustls::ServerConfig>,
    fleet: Mutex<HashMap<WorkerId, Arc<Peer>>>,
    generation: AtomicU64,
    wake: (Mutex<bool>, Condvar),
    stop: AtomicBool,
    sessions: AtomicUsize,
    /// Connections still in their handshake or hello.
    pending: AtomicUsize,
    /// Those of them from loopback, by the peer's (canonical) address: the
    /// only ones a Tailcat helper can carry, so the only ones a hand-off may
    /// have to close before they are sessions. A remote peer costs nothing
    /// here.
    arrivals: Mutex<Vec<(SocketAddr, Arc<session::Arrival>)>>,
    /// Loopback arrivals so far: a hand-off in progress reads the helper's
    /// connections again when this moves.
    arrived: AtomicU64,
    max_pending: AtomicUsize,
    handshake_ms: AtomicU64,
    stats: Stats,
    /// The revocation fingerprint (`dispatch::revocations`) the dispatcher
    /// last acted on; `(-1, -1)` until the first pass, which always checks.
    revocations: Mutex<(i64, i64)>,
    /// When a placement or sweep failure was last logged, for the
    /// once-a-minute limit.
    warned: [AtomicI64; 2],
    /// When the prefetch pass last read the queue: it runs at most once
    /// per `PREFETCH_INTERVAL`, however often the dispatcher wakes.
    prefetch_at: Mutex<Option<Instant>>,
}

/// Placement and sweep failures are logged at most this often per kind.
const WARN_INTERVAL_MS: i64 = 60_000;

/// What the dispatch sweep ranks a connected worker by, lowest first: the
/// share of its reported CPU its held attempts already take (least committed
/// first, so a burst spreads instead of filling whichever worker comes
/// first), then its measured load per reported millicore (the host's own
/// busy time — work that is not ours counts too), then more warm cache
/// first, then the smaller worker (best fit: the large worker's room stays
/// for the jobs only it can run, Q10), then its id for a total order.
fn rank(size: Ranked, held_millis: i64) -> (i64, i64, i64, i64, i64) {
    let cpu = size.cpu_millis.max(1);
    (
        held_millis.saturating_mul(1_000) / cpu,
        size.load_ns / cpu,
        size.cache_bytes.saturating_neg(),
        size.cpu_millis,
        size.memory_bytes,
    )
}

/// What [`rank`] reads of a worker.
#[derive(Clone, Copy, Debug)]
struct Ranked {
    cpu_millis: i64,
    memory_bytes: i64,
    load_ns: i64,
    cache_bytes: i64,
}

impl Peer {
    fn ranked(&self) -> Ranked {
        Ranked {
            cpu_millis: self.cpu_millis,
            memory_bytes: self.memory_bytes,
            load_ns: self.load_ns.load(Ordering::Relaxed),
            cache_bytes: self.cache_bytes.load(Ordering::Relaxed),
        }
    }
}

/// Per pool, the largest and second-largest of each resource among the
/// connected workers of one sweep, so what "every other worker" can hold is
/// O(1) per worker instead of a scan per worker.
struct Reach {
    pools: Vec<PoolReach>,
}

struct PoolReach {
    pool: PoolId,
    workers: usize,
    /// `(largest, index of its holder, second largest)` per resource.
    cpu: (i64, usize, i64),
    memory: (i64, usize, i64),
    disk: (i64, usize, i64),
}

/// Fold one value into a `(largest, holder, second)` triple.
fn top_two(top: &mut (i64, usize, i64), value: i64, index: usize) {
    if value > top.0 {
        *top = (value, index, top.0);
    } else if value > top.2 {
        top.2 = value;
    }
}

/// The most any worker but `index` holds: the second largest when `index`
/// holds the largest, the largest otherwise.
fn other_than(top: (i64, usize, i64), index: usize) -> i64 {
    if top.1 == index { top.2 } else { top.0 }
}

impl Peer {
    /// What this worker holds, as the sweep compares it: a worker that never
    /// reported disk has no disk constraint.
    fn size(&self) -> dispatch::Capacity {
        dispatch::Capacity {
            cpu_millis: self.cpu_millis,
            memory_bytes: self.memory_bytes,
            disk_bytes: match self.disk_bytes.load(Ordering::Relaxed) {
                0 => i64::MAX,
                disk => disk,
            },
        }
    }
}

impl Reach {
    /// Fold the sweep's workers, in sweep order, as `(pool, size)`.
    fn of(sizes: impl IntoIterator<Item = (PoolId, dispatch::Capacity)>) -> Reach {
        let mut pools: Vec<PoolReach> = Vec::new();
        for (index, (pool, size)) in sizes.into_iter().enumerate() {
            let at = match pools.iter().position(|r| r.pool == pool) {
                Some(at) => at,
                None => {
                    pools.push(PoolReach {
                        pool,
                        workers: 0,
                        cpu: (i64::MIN, usize::MAX, i64::MIN),
                        memory: (i64::MIN, usize::MAX, i64::MIN),
                        disk: (i64::MIN, usize::MAX, i64::MIN),
                    });
                    pools.len() - 1
                }
            };
            let r = &mut pools[at];
            r.workers += 1;
            top_two(&mut r.cpu, size.cpu_millis, index);
            top_two(&mut r.memory, size.memory_bytes, index);
            top_two(&mut r.disk, size.disk_bytes, index);
        }
        Reach { pools }
    }

    /// What the rest of `pool` can hold beside the `index`th worker, per
    /// resource; `None` when it is the pool's only connected worker (nothing
    /// to prefer).
    fn elsewhere(&self, index: usize, pool: PoolId) -> Option<dispatch::Capacity> {
        let r = self.pools.iter().find(|r| r.pool == pool)?;
        (r.workers > 1).then(|| dispatch::Capacity {
            cpu_millis: other_than(r.cpu, index),
            memory_bytes: other_than(r.memory, index),
            disk_bytes: other_than(r.disk, index),
        })
    }
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

    /// Its thread is done with an arrival (a session now, closed, or
    /// failed): it leaves the list a hand-off reads.
    fn leave(&self, arrival: Option<&Arc<session::Arrival>>) {
        let Some(arrival) = arrival else {
            return;
        };
        arrival.leave();
        let mut arrivals = self.arrivals.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(index) = arrivals.iter().position(|(_, a)| Arc::ptr_eq(a, arrival)) {
            arrivals.swap_remove(index);
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

    fn serve(self: &Arc<Self>, socket: TcpStream, addr: SocketAddr) {
        let deadline = Duration::from_millis(self.handshake_ms.load(Ordering::Relaxed));
        let addr = canonical(addr);
        let arrival = addr.ip().is_loopback().then(|| {
            let arrival = Arc::new(session::Arrival::default());
            self.arrivals
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .push((addr, Arc::clone(&arrival)));
            self.arrived.fetch_add(1, Ordering::AcqRel);
            arrival
        });
        let outcome = match &arrival {
            Some(arrival) => session::accept_arriving(
                socket,
                Arc::clone(&self.config),
                &**self,
                deadline,
                arrival,
                HANDOFF_BOUND,
            ),
            None => session::accept_within(socket, Arc::clone(&self.config), &**self, deadline),
        };
        // Handshake and hello are over, one way or the other: the slot of
        // the pre-admission cap is free again.
        self.pending.fetch_sub(1, Ordering::AcqRel);
        let mut session = match outcome {
            Ok(Accepted::Control(session)) => session,
            Ok(Accepted::Bulk(bulk)) => {
                self.leave(arrival.as_ref());
                self.serve_bulk(bulk);
                return;
            }
            // Closed by a hand-off before it was a session.
            Err(Error::Closed) if arrival.as_ref().is_some_and(|a| a.answered().is_some()) => {
                self.leave(arrival.as_ref());
                return;
            }
            Err(_) => {
                self.leave(arrival.as_ref());
                self.stats.rejected.fetch_add(1, Ordering::Relaxed);
                return;
            }
        };
        self.stats.admitted.fetch_add(1, Ordering::Relaxed);
        let Admitted { worker, pool, .. } = session.admitted;
        let generation = self.generation.fetch_add(1, Ordering::Relaxed);
        let capacity = session.capacity();
        let peer = Arc::new(Peer {
            sender: session.sender(),
            addr,
            answers_handoff: session
                .admitted
                .negotiated
                .capabilities
                .contains(Capabilities::HANDOFF_ANSWER),
            pool,
            generation,
            // Admission already refused a capacity that is not an i64.
            cpu_millis: i64::try_from(capacity.cpu_millis).unwrap_or(i64::MAX),
            memory_bytes: i64::try_from(capacity.memory_bytes).unwrap_or(i64::MAX),
            disk_bytes: AtomicI64::new(0),
            load_ns: AtomicI64::new(0),
            cache_bytes: AtomicI64::new(0),
            seen_recorded_ms: AtomicI64::new(0),
            fingerprint: session.fingerprint,
            protocol: session.admitted.negotiated.protocol.0,
            transport: Mutex::new(None),
            logging: Mutex::new(HashMap::new()),
            bulk: Mutex::new(None),
            prefetch_sent: Mutex::new(None),
        });
        self.register(worker, Arc::clone(&peer));
        // Only now: a hand-off that found this connection being admitted
        // waits for it to leave, then finds the session registered.
        self.leave(arrival.as_ref());
        self.wake();
        let _ = session.serve(&**self);
        self.unregister(worker, generation);
        // The socket goes with the session, whatever ended it: a sender
        // still holding it (a spec resolver, the dispatcher) fails at once
        // instead of writing into a connection nobody reads.
        peer.sender.close();
        if let Some(bulk) = peer.bulk.lock().unwrap_or_else(|p| p.into_inner()).take() {
            bulk.close();
        }
        self.stats.sessions_ended.fetch_add(1, Ordering::Relaxed);
        // Its unacknowledged offers lapse in the sweep; acknowledged leases
        // run to expiry (W06), so a brief reconnect keeps its work.
    }

    /// Attach and serve a bulk connection: only the same certificate that
    /// holds the live control session may open one, and it carries no
    /// negotiation of its own — it serves the version that session agreed.
    fn serve_bulk(self: &Arc<Self>, mut bulk: BulkSession) {
        let Some(peer) = self.peer(bulk.worker) else {
            self.stats.bulk_refused.fetch_add(1, Ordering::Relaxed);
            return;
        };
        if !sentinel_auth::secret::digest_eq(&peer.fingerprint, &bulk.fingerprint) {
            self.stats.bulk_refused.fetch_add(1, Ordering::Relaxed);
            return;
        }
        self.stats.bulk_attached.fetch_add(1, Ordering::Relaxed);
        let sender = bulk.sender();
        if let Some(previous) = peer
            .bulk
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .replace(sender.clone())
        {
            previous.close();
        }
        // Idle is fine for as long as the control session this connection
        // belongs to is registered; its end closes this socket too.
        let worker = bulk.worker;
        let alive = || {
            self.peer(worker)
                .is_some_and(|live| Arc::ptr_eq(&live, &peer))
        };
        let _ = bulk.serve(&**self, peer.protocol, &alive);
        sender.close();
        self.stats.sessions_ended.fetch_add(1, Ordering::Relaxed);
    }

    /// A write whose store error the caller needs (to tell a benign "the row
    /// already moved" from a failure).
    fn write_store<T: Send + 'static>(
        &self,
        f: impl FnOnce(&sentinel_store::Transaction<'_>) -> sentinel_store::Result<T> + Send + 'static,
    ) -> sentinel_store::Result<T> {
        self.store.writer().write(f)
    }

    /// Count a failed placement or sweep and log its kind, at most once a
    /// minute per class. The error's kind is the variant name only: no SQL,
    /// path or row value reaches the log.
    fn failed(&self, placement: bool, what: &'static str, error: &sentinel_store::Error) {
        let (counter, slot) = if placement {
            (&self.stats.placement_errors, &self.warned[0])
        } else {
            (&self.stats.sweep_errors, &self.warned[1])
        };
        let total = counter.fetch_add(1, Ordering::Relaxed) + 1;
        let now = UnixMillis::now().0;
        let last = slot.load(Ordering::Relaxed);
        if now.saturating_sub(last) >= WARN_INTERVAL_MS
            && slot
                .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
        {
            tracing::warn!(
                event = if placement {
                    "dispatch_placement_failed"
                } else {
                    "dispatch_sweep_failed"
                },
                stage = what,
                kind = error.kind(),
                total,
                "the dispatcher's store work failed; counted, retried next pass"
            );
        }
    }

    /// Whether a sweep's error only says the row moved first (renewed,
    /// acknowledged, released): the sweep's work is already done or moot.
    fn benign(error: &sentinel_store::Error) -> bool {
        matches!(
            error,
            sentinel_store::Error::Conflict | sentinel_store::Error::NotFound
        )
    }

    /// One dispatch pass: sweep expired leases, queue timeouts and lapsed
    /// offers (one batched transaction each, every row re-checked inside it
    /// under its own savepoint), apply revocations, then place work in
    /// rounds ([`Inner::placement_pass`]). Storage maintenance runs on its
    /// own thread ([`Inner::maintenance_loop`]), never here. A sweep row
    /// that moved first (renewed, acknowledged, released) is skipped; any
    /// other store failure is counted and logged (P08-15).
    fn dispatch_pass(&self) {
        let now = UnixMillis::now();
        // Leases that ran out and attempts that outran their job's timeout
        // by the grace: infra-failed, capacity back, never replayed. One
        // write for the whole batch, each lease re-checked inside it; the
        // log-end answer is read here, so the writer never waits on log I/O.
        match self.store.read(|c| dispatch::expired_scoped(c, now)) {
            Ok(due) if !due.is_empty() => {
                let ends: Vec<(AttemptId, bool)> = due
                    .iter()
                    .map(|&(attempt, run, job)| (attempt, self.logs.has_end(run, job, attempt)))
                    .collect();
                match self.write_store(move |tx| dispatch::expire_batch(tx, &ends, now)) {
                    Ok(swept) => {
                        self.stats
                            .expired
                            .fetch_add(swept.done as u64, Ordering::Relaxed);
                        self.swept("expire", swept);
                        for (attempt, _, _) in due {
                            self.logs.forget(attempt);
                        }
                    }
                    Err(e) => self.failed(false, "expire", &e),
                }
            }
            Ok(_) => {}
            Err(e) => self.failed(false, "expire", &e),
        }
        match self.write_store(move |tx| dispatch::sweep_queue_timeouts(tx, now)) {
            Ok(count) => {
                self.stats
                    .queue_timeouts
                    .fetch_add(count as u64, Ordering::Relaxed);
            }
            Err(e) => self.failed(false, "queue_timeout", &e),
        }
        match self.write_store(move |tx| dispatch::lapse_due(tx, now)) {
            Ok(swept) => {
                self.stats
                    .lapsed
                    .fetch_add(swept.done as u64, Ordering::Relaxed);
                self.swept("lapse", swept);
            }
            Err(e) => self.failed(false, "lapse", &e),
        }
        self.revocation_pass(now);
        self.placement_pass();
        self.prefetch_pass();
    }

    /// K05: tell each idle or underused protocol-9 worker which images the
    /// work still queued after placement needs and it does not hold
    /// (`dispatch::prefetch_hints` decides eligibility, fan-out and
    /// bounds). A session is sent a hint only when its wanted set changed
    /// — an empty set included, which is how a stale prefetch is stopped.
    /// One store read per pass, at most once per [`PREFETCH_INTERVAL`];
    /// nothing is read when no connected session speaks protocol 9.
    fn prefetch_pass(&self) {
        let peers: Vec<(WorkerId, Arc<Peer>)> = self
            .fleet
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .filter(|(_, p)| p.protocol >= PREFETCH_MIN.0)
            .map(|(w, p)| (*w, Arc::clone(p)))
            .collect();
        if peers.is_empty() {
            return;
        }
        {
            let mut at = self.prefetch_at.lock().unwrap_or_else(|p| p.into_inner());
            if at.is_some_and(|at| at.elapsed() < PREFETCH_INTERVAL) {
                return;
            }
            *at = Some(Instant::now());
        }
        let workers: Vec<WorkerId> = peers.iter().map(|(w, _)| *w).collect();
        let hints = match self
            .store
            .read(move |c| dispatch::prefetch_hints(c, &workers))
        {
            Ok(hints) => hints,
            Err(e) => return self.failed(true, "prefetch", &e),
        };
        // `prefetch_hints` answers every worker, in the order asked.
        for ((_, images), (_, peer)) in hints.into_iter().zip(&peers) {
            let mut sent = peer.prefetch_sent.lock().unwrap_or_else(|p| p.into_inner());
            if sent.as_ref() == Some(&images) {
                continue;
            }
            if session::prefetch(&peer.sender, &images).is_ok() {
                self.stats.prefetch_hints.fetch_add(1, Ordering::Relaxed);
                *sent = Some(images);
            }
        }
    }

    /// Count a batched sweep's failed rows: each is a sweep error, logged
    /// (by its first error's kind) under the same once-a-minute limit.
    fn swept(&self, what: &'static str, swept: dispatch::Swept) {
        if let Some(error) = &swept.error {
            self.stats
                .sweep_errors
                .fetch_add(swept.failed as u64 - 1, Ordering::Relaxed);
            self.failed(false, what, error);
        }
    }

    /// A revocation is written by the host-local admin command, another
    /// process that cannot signal this one. Each pass compares one indexed
    /// fingerprint of the revoked set; when it moved, every connected
    /// session of a revoked worker is closed and everything a revoked worker
    /// holds is fenced — acknowledged attempts `Reconciled`, offers lapsed —
    /// within one reconciliation interval of the revocation (P08-7). The
    /// store already refuses such a worker's acknowledgements, renewals,
    /// reports, logs, publications and cache transfers from the moment the
    /// row says revoked.
    fn revocation_pass(&self, now: UnixMillis) {
        let stamp = match self.store.read(dispatch::revocations) {
            Ok(stamp) => stamp,
            Err(e) => return self.failed(false, "revocation", &e),
        };
        if *self.revocations.lock().unwrap_or_else(|p| p.into_inner()) == stamp {
            return;
        }
        let connected: Vec<WorkerId> = self
            .fleet
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .keys()
            .copied()
            .collect();
        match self
            .store
            .read(move |c| dispatch::revoked_among(c, &connected))
        {
            Ok(revoked) => {
                for worker in revoked {
                    if let Some(peer) = self.peer(worker) {
                        peer.sender.close();
                        self.stats.revoked_sessions.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
            Err(e) => return self.failed(false, "revocation", &e),
        }
        // One sweep batch per transaction until nothing is left; bounded,
        // and an unfinished sweep leaves the fingerprint unrecorded so the
        // next pass continues it.
        for _ in 0..16 {
            let logs = Arc::clone(&self.logs);
            match self.write_store(move |tx| dispatch::reconcile_revoked(tx, now, Some(&logs))) {
                Ok(0) => {
                    *self.revocations.lock().unwrap_or_else(|p| p.into_inner()) = stamp;
                    return;
                }
                Ok(settled) => {
                    self.stats
                        .abandoned
                        .fetch_add(settled as u64, Ordering::Relaxed);
                }
                Err(e) => return self.failed(false, "revocation", &e),
            }
        }
    }

    /// Place work in rounds. A round ranks the connected workers (see
    /// [`rank`]) and offers each one job, all in one writer transaction; a
    /// worker with nothing to take leaves the pass, and rounds repeat until
    /// none is left or each worker holds [`dispatch::MAX_HELD_ATTEMPTS`].
    /// A burst therefore spreads over the fleet by commitment and measured
    /// load instead of filling whichever worker comes first (Q03, P08-6),
    /// and the writer sees one round trip per round rather than one per
    /// worker. Nothing is read or written when no job is ready at all
    /// (P08-14).
    fn placement_pass(&self) {
        // Below the low watermark, no new work is placed: a job that cannot
        // store its output must not consume capacity discovering that.
        if !self.objects.admission().is_none_or(|a| a.is_open()) {
            return;
        }
        let mut peers: Vec<(WorkerId, Arc<Peer>)> = self
            .fleet
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .map(|(w, p)| (*w, Arc::clone(p)))
            .collect();
        if peers.is_empty() {
            return;
        }
        match self.store.read(dispatch::any_ready) {
            Ok(true) => {}
            Ok(false) => return,
            Err(e) => return self.failed(true, "ready", &e),
        }
        let mut held = match self.store.read(dispatch::held_by_worker) {
            Ok(held) => held,
            Err(e) => return self.failed(true, "held", &e),
        };
        // A stable index per worker for `Reach`; the order is the Q10 best
        // fit, which is also `rank`'s tie-break.
        peers.sort_unstable_by_key(|(worker, p)| (p.cpu_millis, p.memory_bytes, *worker));
        let reach = Reach::of(peers.iter().map(|(_, p)| (p.pool, p.size())));
        let mut active: Vec<usize> = (0..peers.len()).collect();
        for _ in 0..dispatch::MAX_HELD_ATTEMPTS {
            if active.is_empty() {
                return;
            }
            active.sort_by_cached_key(|&i| {
                let (worker, peer) = &peers[i];
                (
                    rank(peer.ranked(), held.get(worker).copied().unwrap_or(0)),
                    *worker,
                )
            });
            let round: Vec<(usize, WorkerId, PoolId, Option<dispatch::Capacity>)> = active
                .iter()
                .map(|&i| {
                    (
                        i,
                        peers[i].0,
                        peers[i].1.pool,
                        reach.elsewhere(i, peers[i].1.pool),
                    )
                })
                .collect();
            let now = UnixMillis::now();
            let placed: Vec<(usize, Option<dispatch::Offer>)> = {
                let batch = round.clone();
                match self.write_store(move |tx| {
                    let mut placed = Vec::with_capacity(batch.len());
                    for (i, worker, pool, elsewhere) in batch {
                        let offer = dispatch::place_in_fleet(
                            tx,
                            worker,
                            pool,
                            elsewhere,
                            dispatch::DEFAULT_LEASE_MS,
                            now,
                        )?;
                        placed.push((i, offer));
                    }
                    Ok(placed)
                }) {
                    Ok(placed) => placed,
                    Err(e) => {
                        // One worker's failure must not stall the fleet:
                        // retry the round a worker per transaction, and a
                        // worker that still fails leaves this pass.
                        self.failed(true, "round", &e);
                        round
                            .into_iter()
                            .map(|(i, worker, pool, elsewhere)| {
                                let offer = self
                                    .write_store(move |tx| {
                                        dispatch::place_in_fleet(
                                            tx,
                                            worker,
                                            pool,
                                            elsewhere,
                                            dispatch::DEFAULT_LEASE_MS,
                                            now,
                                        )
                                    })
                                    .unwrap_or_else(|e| {
                                        self.failed(true, "place", &e);
                                        None
                                    });
                                (i, offer)
                            })
                            .collect()
                    }
                }
            };
            let mut done: Vec<usize> = Vec::new();
            for (i, offer) in placed {
                let Some(placed) = offer else {
                    done.push(i);
                    continue;
                };
                let (worker, peer) = &peers[i];
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
                    // The session is gone: give the attempt back at once
                    // rather than letting the ack timeout find it.
                    let attempt = offer.attempt;
                    match self
                        .write_store(move |tx| dispatch::lapse(tx, attempt, UnixMillis::now()))
                    {
                        Ok(()) => {}
                        Err(e) if Self::benign(&e) => {}
                        Err(e) => self.failed(false, "lapse", &e),
                    }
                    peer.sender.close();
                    done.push(i);
                    continue;
                }
                self.stats.offers.fetch_add(1, Ordering::Relaxed);
                *held.entry(*worker).or_insert(0) += placed.cpu_millis;
            }
            active.retain(|i| !done.contains(i));
        }
    }

    /// Storage maintenance (D06): retire expired uploads and leases, expire
    /// artifact rows past their declared retention (their manifest versions
    /// retire with them, releasing object references), index un-indexed
    /// manifests, reclaim unreferenced objects, then sweep orphan files,
    /// idle log writers and out-of-retention logs. Every stage is bounded:
    /// the row stages take at most `STORAGE_BATCH` rows through indexes,
    /// the orphan and log sweeps look at a bounded number of directory
    /// entries and resume where they stopped, and none of the file walks
    /// runs on the writer. Every unlink runs on the writer through
    /// [`Objects::unlink`], which re-checks ownership first.
    fn storage_pass(&self, now: UnixMillis, policy: StoragePolicy) {
        let objects = Arc::clone(&self.objects);
        if let Ok(doomed) = self.write(move |tx| {
            objects.sweep_uploads(tx, now)?;
            objects.sweep_leases(tx, now)?;
            let mut doomed = artifacts::sweep_expired(tx, &objects, now, STORAGE_BATCH)?;
            objects.index_refs(tx, STORAGE_BATCH)?;
            doomed.extend(objects.reclaim(tx, now, STORAGE_BATCH)?.doomed);
            Ok(doomed)
        }) && !doomed.is_empty()
        {
            // The rows are committed gone; a failure leaves orphans the
            // file sweep collects.
            let objects = Arc::clone(&self.objects);
            let _ = self.write(move |tx| objects.unlink(tx, &doomed));
        }
        let objects = Arc::clone(&self.objects);
        if let Ok((doomed, _)) = self
            .store
            .read(move |c| objects.orphans(c, STORAGE_BATCH as u32, ORPHAN_SCAN_BUDGET))
            && !doomed.is_empty()
        {
            let objects = Arc::clone(&self.objects);
            let _ = self.write(move |tx| objects.unlink(tx, &doomed));
        }
        self.logs.close_idle(sentinel_store::logs::WRITER_IDLE);
        let _ = self
            .logs
            .sweep_expired(now, policy.log_retention_ms, STORAGE_BATCH as u32);
    }

    /// The storage maintenance thread: checks the policy every
    /// `MAINTENANCE_TICK` and runs [`Inner::storage_pass`] when its interval
    /// is due — off the dispatch thread, so placement never waits on a
    /// sweep.
    fn maintenance_loop(&self) {
        let (flag, cv) = &self.maintenance;
        loop {
            {
                let stopped = flag.lock().unwrap_or_else(|p| p.into_inner());
                let _ = cv
                    .wait_timeout_while(stopped, MAINTENANCE_TICK, |stopped| !*stopped)
                    .unwrap_or_else(|p| p.into_inner());
            }
            if self.stop.load(Ordering::Acquire) {
                return;
            }
            let Some(policy) = *self.storage.lock().unwrap_or_else(|p| p.into_inner()) else {
                continue;
            };
            let now = UnixMillis::now();
            if now.0 - self.last_storage.load(Ordering::Relaxed) >= policy.interval_ms {
                self.last_storage.store(now.0, Ordering::Relaxed);
                self.storage_pass(now, policy);
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

/// How often the controller's remote-cache store is reclaimed.
pub const REMOTE_SWEEP_INTERVAL: Duration = Duration::from_secs(10 * 60);

/// How long after its release an attempt may still offer what it sealed
/// (P07-7): the worker's offer budget plus slack for publication and the
/// terminal report's round trip.
pub const OFFER_WINDOW_MS: i64 = 10 * 60 * 1000;

impl Inner {
    /// Protocol 7 (Q08). The shared remote-cache gate: `attempt` is owned
    /// by `worker` (held, or released since `released_since` for an offer)
    /// and the transfer names exactly the job's tenant and repository and a
    /// trust class the job's admits. `Some(root)` to serve from; a refusal
    /// is counted in `cache_denied`.
    fn cache_authorize(
        &self,
        worker: WorkerId,
        attempt: [u8; 16],
        (tenant, repo, trust): ([u8; 16], [u8; 16], u8),
        released_since: Option<UnixMillis>,
    ) -> Option<std::path::PathBuf> {
        let root = self
            .remote_cache
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        let authorized = root.is_some()
            && AttemptId::from_bytes(attempt).is_ok_and(|attempt| {
                self.store
                    .read(|c| dispatch::cache_scope(c, worker, attempt, released_since))
                    .is_ok_and(|(job_tenant, job_repo, job_trust)| {
                        *job_tenant.as_bytes() == tenant
                            && *job_repo.as_bytes() == repo
                            && sentinel_protocol::cache::Trust::from_u8(trust)
                                .is_some_and(|t| job_trust.admits(t))
                    })
            });
        if !authorized {
            self.stats.cache_denied.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        root
    }

    fn peer(&self, worker: WorkerId) -> Option<Arc<Peer>> {
        self.fleet
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&worker)
            .cloned()
    }

    /// Whether `attempt` is still held by `worker`: the gate for artifact
    /// publication, where a released attempt is stale. Logs use the wider
    /// [`Self::log_scope`]: late retransmissions only complete the record.
    fn holds(&self, worker: WorkerId, attempt: AttemptId) -> bool {
        self.store
            .read(|c| dispatch::is_held(c, worker, attempt))
            .unwrap_or(false)
    }

    /// The attempt's `(run, job)` when owned by `worker` — held or released:
    /// resolved against the store once per attempt, then remembered on the
    /// session. A released attempt still accepts log frames and its end;
    /// the verdict is long decided and the bytes are evidence.
    ///
    /// `Ok(None)` is a definite "not this worker's" (or no live session);
    /// `Err` is a store fault, which must never be answered as a refusal.
    fn log_scope(
        &self,
        worker: WorkerId,
        attempt: AttemptId,
    ) -> std::result::Result<Option<(RunId, JobId)>, ()> {
        let Some(peer) = self.peer(worker) else {
            return Ok(None);
        };
        if let Some(scope) = peer
            .logging
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&attempt)
        {
            return Ok(Some(*scope));
        }
        let scope = match self.store.read(|c| {
            let tx = c.unchecked_transaction()?;
            dispatch::attempt_log_scope(&tx, worker, attempt)
        }) {
            Ok(scope) => scope,
            Err(sentinel_store::Error::NotFound) => return Ok(None),
            Err(_) => return Err(()),
        };
        peer.logging
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(attempt, scope);
        Ok(Some(scope))
    }

    /// Whether the attempt's log end is durable, asked before a terminal
    /// write so the writer thread never waits on the log store's I/O.
    /// Unknown (a store fault) answers `false`: the row then says
    /// `incomplete`, which a later `LogEnd` upgrades.
    fn log_has_end(&self, worker: WorkerId, attempt: AttemptId) -> bool {
        match self.log_scope(worker, attempt) {
            Ok(Some((run, job))) => self.logs.has_end(run, job, attempt),
            _ => false,
        }
    }

    /// The attempt was released: its open log writer and cached scope go
    /// with it, so neither grows with uptime (P04-23).
    fn released(&self, worker: WorkerId, attempt: AttemptId) {
        self.logs.forget(attempt);
        if let Some(peer) = self.peer(worker) {
            peer.logging
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .remove(&attempt);
        }
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

    /// The attempt's publication, if one is in flight. The map lock is held
    /// only for the lookup.
    fn publication(&self, attempt: AttemptId) -> Option<Publication> {
        self.artifacts
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .in_flight
            .get(&attempt)
            .cloned()
    }

    /// Take the publication out of the map and release its run budget; the
    /// caller holds its lock. Idempotent through `settled`.
    fn settle(&self, attempt: AttemptId, f: &mut InFlight) {
        if f.settled {
            return;
        }
        f.settled = true;
        let mut state = self.artifacts.lock().unwrap_or_else(|p| p.into_inner());
        state.in_flight.remove(&attempt);
        if let Some(r) = state.runs.get_mut(&f.run) {
            *r = r.saturating_sub(f.accounted);
        }
    }

    /// Drop an in-flight publication: release the run budget, discard the
    /// sealed-but-uncommitted files it created, and — for a declared
    /// artifact that failed after opening — record `failed` so the run's
    /// output stays explainable. `Stale` means nothing was granted. The
    /// caller holds the publication's lock.
    fn artifact_fail(
        &self,
        f: &mut InFlight,
        attempt: AttemptId,
        code: ArtifactCode,
    ) -> ArtifactCode {
        if f.settled {
            return ArtifactCode::Stale;
        }
        self.settle(attempt, f);
        if code != ArtifactCode::Stale {
            self.record_artifact(f, attempt, artifacts::State::Failed, None);
        }
        // The open file's temp copy goes with its `Staging`.
        f.file = None;
        self.discard(std::mem::take(&mut f.done));
        code
    }

    /// Discard sealed-but-uncommitted files on the writer: a file another
    /// stage or a committed row still owns stays ([`Objects::discard`]).
    /// Should the writer refuse, the stages drop unpinned and the orphan
    /// sweep decides later — never this thread.
    fn discard(&self, done: Vec<(String, u32, objects::Staged)>) {
        if done.is_empty() {
            return;
        }
        let objects = Arc::clone(&self.objects);
        let _ = self.write(move |tx| {
            for (_, _, staged) in done {
                objects.discard(tx, staged)?;
            }
            Ok(())
        });
    }
}

/// Back-off between tries against a transient fault: doubling from 100 ms,
/// with ±25 % jitter from the attempt id so concurrent resolutions do not
/// retry in step.
fn spec_backoff(try_no: u32, attempt: AttemptId) -> Duration {
    let base = 100u64 << try_no.min(4);
    let quarter = base / 4;
    let noise = u64::from(attempt.as_bytes()[15] ^ attempt.as_bytes()[7]);
    Duration::from_millis(base - quarter + noise % (2 * quarter + 1))
}

impl Inner {
    /// A resolver thread: drain the spec desk, then exit.
    fn resolve_specs(&self) {
        let mut done = None;
        while let Some((key, request)) = self.specs.next(done.take()) {
            self.serve_spec(&request);
            done = Some(key);
        }
    }

    fn no_spec(request: &SpecRequest) {
        let _ = request.sender.send(&session::ServerMessage::NoSpec {
            attempt: *request.attempt.as_bytes(),
        });
    }

    /// Where the attempt stands, with transient read faults retried. `None`
    /// means the question stays open: leave the request unanswered.
    fn spec_gate(&self, request: &SpecRequest) -> Option<dispatch::SpecGate> {
        let (worker, attempt) = (request.worker, request.attempt);
        let started = Instant::now();
        let mut pause = Duration::from_millis(2);
        let mut faults = 0;
        loop {
            match self.store.read(|c| dispatch::spec_gate(c, worker, attempt)) {
                // The acknowledgement is on its way on the control
                // connection (the request may have come on bulk): wait for
                // it, briefly. Nothing is served before it is durable.
                Ok(dispatch::SpecGate::Unacknowledged) => {
                    if started.elapsed() >= SPEC_ACK_WAIT {
                        return None;
                    }
                    thread::sleep(pause);
                    pause = (pause * 2).min(Duration::from_millis(100));
                }
                Ok(gate) => return Some(gate),
                Err(_) => {
                    faults += 1;
                    if faults >= SPEC_TRIES {
                        return None;
                    }
                    thread::sleep(spec_backoff(faults, attempt));
                }
            }
        }
    }

    /// Settle an acknowledged, unstarted attempt whose job has cancellation
    /// desired: `canceled` now, dependents decided, and `NoSpec` so the
    /// worker lets it go.
    fn settle_canceled(&self, request: &SpecRequest, fence: Fence) {
        let (worker, attempt) = (request.worker, request.attempt);
        if self
            .write(move |tx| dispatch::decline(tx, worker, attempt, fence, UnixMillis::now()))
            .is_ok()
        {
            self.stats.handed_back.fetch_add(1, Ordering::Relaxed);
            self.wake();
            Self::no_spec(request);
        }
    }

    /// Serve one spec request. A definitive answer is sent — the spec, or
    /// `NoSpec` for an attempt that is not this worker's, was settled
    /// canceled, or whose source or spec is refused for good. A transient
    /// fault is retried a few times and then left unanswered: the worker
    /// asks again, and hands the attempt back if it never gets it, so a
    /// fault never turns into an infrastructure failure of a job that did
    /// not run (P04-4).
    fn serve_spec(&self, request: &SpecRequest) {
        let (worker, attempt) = (request.worker, request.attempt);
        match self.spec_gate(request) {
            None => return,
            Some(dispatch::SpecGate::NotHeld) => return Self::no_spec(request),
            Some(dispatch::SpecGate::Canceled(fence)) => {
                return self.settle_canceled(request, fence);
            }
            Some(dispatch::SpecGate::Ready | dispatch::SpecGate::Unacknowledged) => {}
        }
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
        let destinations = self
            .source_destinations
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        for try_no in 0..SPEC_TRIES {
            match resolve_spec(
                &self.store,
                key.as_deref(),
                app.as_ref(),
                &destinations,
                worker,
                attempt,
            ) {
                Ok(spec) => {
                    let _ = send_resolved(&request.sender, attempt, request.protocol, Some(spec));
                    return;
                }
                Err(SpecFault::Refused) => {
                    // A cancel that landed after the gate refuses a bound
                    // source too: settle it as the cancel it is.
                    match self.spec_gate(request) {
                        Some(dispatch::SpecGate::Canceled(fence)) => {
                            self.settle_canceled(request, fence);
                        }
                        None => {}
                        Some(_) => Self::no_spec(request),
                    }
                    return;
                }
                Err(SpecFault::Transient) => {
                    if try_no + 1 < SPEC_TRIES {
                        thread::sleep(spec_backoff(try_no, attempt));
                    }
                }
            }
        }
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
        // The disk half of the capacity only arrives with the protocol-7
        // profile, after the welcome. Defer the capacity write entirely for
        // such a session so placement never sees a disk of zero for a worker
        // that is about to report one.
        let deferred = negotiated.protocol.0 >= PROFILE_MIN.0;
        let capacity = dispatch::Capacity {
            cpu_millis: i64::try_from(capacity.cpu_millis).map_err(|_| Rejection::Capacity)?,
            memory_bytes: i64::try_from(capacity.memory_bytes).map_err(|_| Rejection::Capacity)?,
            disk_bytes: 0,
        };
        match self.store.read(|c| workers::authenticate(c, fingerprint)) {
            Ok(known) => {
                // The architecture is part of what was enrolled; a machine
                // presenting the key on another one is not that worker.
                if known.negotiated.arch != negotiated.arch {
                    return Err(Rejection::Identity);
                }
                // Negotiated afresh on every hello and recorded: an upgraded
                // worker is welcomed at the newer protocol (and so sends
                // its profile), a rolled-back one at a version it speaks.
                let id = known.id;
                let renegotiated = (known.negotiated != negotiated).then_some(negotiated);
                let immediate = (!deferred).then_some(capacity);
                if renegotiated.is_some() || immediate.is_some() {
                    self.write(move |tx| {
                        if let Some(negotiated) = renegotiated {
                            workers::renegotiate(tx, id, negotiated)?;
                        }
                        if let Some(capacity) = immediate {
                            dispatch::report_capacity(tx, id, capacity)?;
                        }
                        Ok(())
                    })
                    .map_err(|_| Rejection::Unavailable)?;
                }
                return Ok(Admitted {
                    worker: known.id,
                    pool: known.pool,
                    negotiated,
                });
            }
            Err(sentinel_store::Error::NotFound) => {}
            // A store fault is not an unknown fingerprint: answering the
            // enrollment path would refuse a known worker with the wrong
            // error — say it is the store, retryably.
            Err(_) => return Err(Rejection::Unavailable),
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
        let immediate_capacity = (!deferred).then_some(capacity);
        self.store
            .writer()
            .write(move |tx| {
                // A refused secret commits its audit row: `Ok(None)`.
                let Some(enrolled) = workers::redeem(
                    tx,
                    &secret,
                    workers::Presentation {
                        worker,
                        fingerprint,
                        name: &name,
                        negotiated,
                    },
                    UnixMillis::now(),
                )?
                else {
                    return Ok(None);
                };
                if let Some(capacity) = immediate_capacity {
                    dispatch::report_capacity(tx, enrolled.id, capacity)?;
                }
                Ok(Some(Admitted {
                    worker: enrolled.id,
                    pool: enrolled.pool,
                    negotiated: enrolled.negotiated,
                }))
            })
            .map_err(|e| match e {
                sentinel_store::Error::Conflict | sentinel_store::Error::InvalidInput(_) => {
                    Rejection::Identity
                }
                sentinel_store::Error::NotFound => Rejection::Enrollment,
                _ => Rejection::Unavailable,
            })?
            .ok_or(Rejection::Enrollment)
    }
}

impl SessionHandler for Inner {
    /// Queue the request on the bounded spec desk: at most
    /// [`SPEC_RESOLVERS`] resolutions (each possibly a GitHub round trip)
    /// run off the session threads, and the rest wait their turn instead of
    /// being refused. A request over the bound is dropped unanswered — the
    /// worker asks again — never answered `NoSpec`, which would end the
    /// attempt.
    fn spec_requested(
        &self,
        worker: WorkerId,
        attempt: AttemptId,
        sender: Sender,
        protocol: u16,
    ) -> bool {
        let request = SpecRequest {
            worker,
            attempt,
            sender,
            protocol,
        };
        if self.specs.submit((worker, attempt), request) == Submitted::Start {
            let me = self.me.get().and_then(std::sync::Weak::upgrade);
            let spawned = me.is_some_and(|me| {
                thread::Builder::new()
                    .name("sentinel-source".into())
                    .spawn(move || me.resolve_specs())
                    .is_ok()
            });
            if !spawned {
                // The request stays queued for the next resolver.
                self.specs.not_started();
            }
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
        // Whether the log ended is asked here, before the writer is taken,
        // so a terminal report never waits behind another attempt's log
        // fsync on the single writer thread.
        let ended =
            matches!(event, Event::Passed | Event::Failed(_)) && self.log_has_end(worker, attempt);
        let finished = self.write(move |tx| {
            let state = dispatch::report(
                tx,
                worker,
                attempt,
                fence,
                event,
                summary.as_deref(),
                UnixMillis::now(),
                None,
            )?;
            if ended && state.is_terminal() {
                dispatch::log_ended(tx, attempt)?;
            }
            Ok(state)
        });
        match finished {
            Ok(state) => {
                self.stats.reports.fetch_add(1, Ordering::Relaxed);
                if state.is_terminal() {
                    self.released(worker, attempt);
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
        let ended = self.log_has_end(worker, attempt);
        let settled = self.write(move |tx| {
            let state = dispatch::abandon(tx, worker, attempt, fence, UnixMillis::now(), None)?;
            if ended && state.is_terminal() {
                dispatch::log_ended(tx, attempt)?;
            }
            Ok(state)
        });
        if settled.is_ok() {
            self.stats.abandoned.fetch_add(1, Ordering::Relaxed);
            self.released(worker, attempt);
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

    /// Protocol 7. Records the profile and, in the same transaction, the
    /// capacity with the disk the profile carries — the hello's own capacity
    /// write was deferred for exactly this one, so placement never sees a
    /// disk of zero for a worker that reports one. Values the worker did not
    /// measure (zero on the wire) are reported absent, so a column keeps its
    /// last known value instead of being overwritten with a zero claim.
    fn profiled(&self, worker: WorkerId, profile: &Profile, capacity: Capacity) -> Result<()> {
        let capacity = dispatch::Capacity {
            cpu_millis: i64::try_from(capacity.cpu_millis)
                .map_err(|_| Error::Protocol("capacity"))?,
            memory_bytes: i64::try_from(capacity.memory_bytes)
                .map_err(|_| Error::Protocol("capacity"))?,
            disk_bytes: i64::try_from(profile.disk_bytes)
                .map_err(|_| Error::Protocol("profile disk"))?,
        };
        let labels = profile.labels.clone();
        let images = profile.availability.images.clone();
        let host_id = (profile.host_id != [0u8; 16]).then_some(profile.host_id);
        let cache_bytes = (profile.availability.cache_bytes != 0)
            .then(|| i64::try_from(profile.availability.cache_bytes).unwrap_or(i64::MAX));
        let load_ns = (profile.availability.load_ns != 0)
            .then(|| i64::try_from(profile.availability.load_ns).unwrap_or(i64::MAX));
        if let Some(peer) = self.peer(worker) {
            peer.disk_bytes
                .store(capacity.disk_bytes, Ordering::Relaxed);
            peer.load_ns.store(load_ns.unwrap_or(0), Ordering::Relaxed);
            peer.cache_bytes
                .store(cache_bytes.unwrap_or(0), Ordering::Relaxed);
        }
        self.write(move |tx| {
            dispatch::report_capacity(tx, worker, capacity)?;
            dispatch::report_profile(
                tx,
                worker,
                &dispatch::ReportedProfile {
                    labels: &labels,
                    host_id,
                    avail_images: &images,
                    cache_bytes,
                    load_ns,
                },
            )
        })
        .map_err(|_| Error::Internal("profile write"))?;
        // A worker that just reported an image warm — often one it
        // prefetched — may now take work a locality hold kept from it, so
        // placement runs now rather than at the next reconciliation.
        self.wake();
        Ok(())
    }

    /// Protocol 7 (Q07). The worker's latest transport telemetry, kept on
    /// its session for operators and diagnostics.
    fn transport(&self, worker: WorkerId, stats: &TransportStats) {
        if let Some(peer) = self.peer(worker) {
            *peer.transport.lock().unwrap_or_else(|p| p.into_inner()) = Some(stats.clone());
        }
    }

    /// Protocol 7 (Q08). Authorizes a download: the fenced attempt must be
    /// held by the worker, and the need's tenant, repo and trust class must
    /// equal the attempt's — the worker never names a boundary it does not
    /// hold. The controller's remote-cache root is returned to serve from;
    /// without one, every need is a miss.
    fn cache_need(&self, worker: WorkerId, need: &Need) -> Option<std::path::PathBuf> {
        self.cache_authorize(
            worker,
            need.attempt,
            (need.tenant, need.repo, need.trust),
            None,
        )
    }

    /// Protocol 7 (Q08). Authorizes an upload under the same boundary rule
    /// as a download before any bytes are staged — except that the attempt
    /// may already be released: a worker offers what it sealed only after
    /// its terminal report (P07-7), so the same worker's attempt released
    /// within [`OFFER_WINDOW_MS`] still names its boundary.
    fn cache_offer(&self, worker: WorkerId, upload: &Upload) -> Option<std::path::PathBuf> {
        let since = UnixMillis(UnixMillis::now().0 - OFFER_WINDOW_MS);
        self.cache_authorize(
            worker,
            upload.attempt,
            (upload.tenant, upload.repo, upload.trust),
            Some(since),
        )
    }

    /// `Refused` only for a permanent cause — not this worker's attempt, a
    /// log that already ended, the size cap, no disk reserve left for
    /// evidence. A store read or log I/O fault is `Retry`: the connection
    /// closes and the worker resends from its last acknowledgement, so a
    /// passing job never loses its log (and its verdict) to a hiccup.
    fn log(&self, worker: WorkerId, attempt: AttemptId, frame: Frame) -> LogVerdict {
        let (run, job) = match self.log_scope(worker, attempt) {
            Ok(Some(scope)) => scope,
            Ok(None) => {
                self.stats.log_refused.fetch_add(1, Ordering::Relaxed);
                return LogVerdict::Refused;
            }
            Err(()) => return LogVerdict::Retry,
        };
        match self.logs.append(run, job, attempt, &frame) {
            Ok(sentinel_store::logs::Appended::Stored { through })
            | Ok(sentinel_store::logs::Appended::Duplicate { through }) => {
                self.stats.log_frames.fetch_add(1, Ordering::Relaxed);
                LogVerdict::Acked(through)
            }
            Err(
                sentinel_store::Error::Conflict
                | sentinel_store::Error::InvalidInput(_)
                | sentinel_store::Error::StorageFull,
            ) => {
                self.stats.log_refused.fetch_add(1, Ordering::Relaxed);
                LogVerdict::Refused
            }
            Err(_) => LogVerdict::Retry,
        }
    }

    fn log_end(
        &self,
        worker: WorkerId,
        attempt: AttemptId,
        last_seq: u64,
        gaps: &[(u64, u64)],
    ) -> LogVerdict {
        let (run, job) = match self.log_scope(worker, attempt) {
            Ok(Some(scope)) => scope,
            Ok(None) => {
                self.stats.log_refused.fetch_add(1, Ordering::Relaxed);
                return LogVerdict::Refused;
            }
            Err(()) => return LogVerdict::Retry,
        };
        match self.logs.finish(run, job, attempt, last_seq, gaps) {
            Ok(()) => {
                // The acknowledgement — and the spool it releases — waits for
                // the row that says the end marker is durable. If the write
                // fails the connection closes and the worker re-sends
                // `LogEnd` from its rewind; `finish` is idempotent.
                if self
                    .write(move |tx| dispatch::log_ended(tx, attempt))
                    .is_err()
                {
                    return LogVerdict::Retry;
                }
                if let Some(peer) = self.peer(worker) {
                    peer.logging
                        .lock()
                        .unwrap_or_else(|p| p.into_inner())
                        .remove(&attempt);
                }
                LogVerdict::Acked(last_seq)
            }
            // A different end than the one recorded, or an end before what
            // is stored: the worker's claim cannot be accepted, ever.
            Err(sentinel_store::Error::Conflict | sentinel_store::Error::InvalidInput(_)) => {
                self.stats.log_refused.fetch_add(1, Ordering::Relaxed);
                LogVerdict::Refused
            }
            Err(_) => LogVerdict::Retry,
        }
    }

    /// Fenced on the declining worker (P04-25): only the holder of the
    /// offer, under its fence, can give it back — an unacknowledged offer,
    /// or an acknowledged attempt it never started because the spec never
    /// arrived (P04-4). Either goes back to the queue, or ends `canceled`.
    fn declined(&self, worker: WorkerId, attempt: AttemptId, fence: Fence) {
        if let Ok(state) =
            self.write(move |tx| dispatch::decline(tx, worker, attempt, fence, UnixMillis::now()))
        {
            self.stats.lapsed.fetch_add(1, Ordering::Relaxed);
            self.stats.handed_back.fetch_add(1, Ordering::Relaxed);
            // Deliberately no wake for a requeue: the next reconciliation
            // places it, which bounds a worker that keeps refusing to one
            // offer per interval instead of a tight loop. A cancel that
            // ended the job did free capacity and decide dependents.
            if state.is_terminal() {
                self.wake();
            }
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
        if committed.saturating_add(*state.runs.get(&run).unwrap_or(&0)) >= MAX_RUN_ARTIFACT_BYTES
            || self.objects.admission().is_some_and(|a| !a.is_open())
        {
            return Verdict(ArtifactCode::TooLarge);
        }
        state.in_flight.insert(
            attempt,
            Arc::new(Mutex::new(InFlight {
                tenant,
                run,
                job,
                name: name.to_string(),
                retain_secs: decl.retain_secs,
                done: Vec::new(),
                accounted: 0,
                last_path: String::new(),
                file: None,
                settled: false,
            })),
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
        let Some(publication) = self.publication(attempt) else {
            return Some(ArtifactCode::Stale);
        };
        let mut guard = publication.lock().unwrap_or_else(|p| p.into_inner());
        let f = &mut *guard;
        if f.settled {
            return Some(ArtifactCode::Stale);
        }
        if f.file.is_some()
            || !objects::valid_entry_path(path)
            || f.done.len() >= MAX_ARTIFACT_ENTRIES
            || (!f.last_path.is_empty() && path <= f.last_path.as_str())
        {
            return Some(self.artifact_fail(f, attempt, ArtifactCode::Invalid));
        }
        // The run budget is committed bytes plus what every in-flight
        // artifact of the run already charges; the charge is taken under
        // the map lock so two publications cannot both fit the last byte.
        let committed = self
            .store
            .read(|c| artifacts::run_bytes(c, f.tenant, f.run))
            .unwrap_or(u64::MAX);
        let fits = f.accounted.saturating_add(len) <= MAX_ARTIFACT_BYTES
            // Disk admission closed: the stream would refuse its writes
            // anyway, so the file is never opened.
            && self.objects.admission().is_none_or(|a| a.check(len).is_ok())
            && {
                let mut state = self.artifacts.lock().unwrap_or_else(|p| p.into_inner());
                let charged = state.runs.entry(f.run).or_default();
                let fits = committed.saturating_add(*charged).saturating_add(len)
                    <= MAX_RUN_ARTIFACT_BYTES;
                if fits {
                    *charged += len;
                }
                fits
            };
        if !fits {
            return Some(self.artifact_fail(f, attempt, ArtifactCode::TooLarge));
        }
        f.accounted += len;
        f.last_path = path.to_string();
        let staging = match self.objects.stage_begin(f.tenant, len) {
            Ok(staging) => staging,
            Err(_) => return Some(self.artifact_fail(f, attempt, ArtifactCode::Store)),
        };
        let file = OpenFile {
            path: path.to_string(),
            mode: mode & crate::session::ARTIFACT_MODE_BITS,
            declared: len,
            next_seq: 0,
            staging,
        };
        // An empty file sends no data frames: seal it at once, or
        // `artifact_end` would find it still open.
        if len == 0 {
            match self.objects.stage_seal(f.tenant, file.staging, 0) {
                Ok(staged) => f.done.push((file.path, file.mode, staged)),
                Err(_) => return Some(self.artifact_fail(f, attempt, ArtifactCode::Store)),
            }
        } else {
            f.file = Some(file);
        }
        None
    }

    fn artifact_data(
        &self,
        _worker: WorkerId,
        attempt: AttemptId,
        seq: u32,
        bytes: &[u8],
    ) -> Option<ArtifactCode> {
        let Some(publication) = self.publication(attempt) else {
            return Some(ArtifactCode::Stale);
        };
        let mut guard = publication.lock().unwrap_or_else(|p| p.into_inner());
        let f = &mut *guard;
        if f.settled {
            return Some(ArtifactCode::Stale);
        }
        let Some(file) = f.file.as_mut() else {
            return Some(self.artifact_fail(f, attempt, ArtifactCode::Invalid));
        };
        if file.next_seq != seq
            || file.staging.written().saturating_add(bytes.len() as u64) > file.declared
        {
            return Some(self.artifact_fail(f, attempt, ArtifactCode::Invalid));
        }
        if self.objects.stage_write(&mut file.staging, bytes).is_err() {
            return Some(self.artifact_fail(f, attempt, ArtifactCode::Store));
        }
        file.next_seq += 1;
        if file.staging.written() == file.declared {
            let file = f.file.take().expect("open file checked");
            match self
                .objects
                .stage_seal(f.tenant, file.staging, file.declared)
            {
                Ok(staged) => f.done.push((file.path, file.mode, staged)),
                Err(_) => return Some(self.artifact_fail(f, attempt, ArtifactCode::Store)),
            }
        }
        None
    }

    fn artifact_end(&self, _worker: WorkerId, attempt: AttemptId, name: &str) -> ArtifactCode {
        let Some(publication) = self.publication(attempt) else {
            return ArtifactCode::Stale;
        };
        let mut guard = publication.lock().unwrap_or_else(|p| p.into_inner());
        let f = &mut *guard;
        if f.settled {
            return ArtifactCode::Stale;
        }
        if f.name != name || f.file.is_some() {
            return self.artifact_fail(f, attempt, ArtifactCode::Invalid);
        }
        self.settle(attempt, f);
        let done = std::mem::take(&mut f.done);
        let (tenant, run, job, retain_secs) = (f.tenant, f.run, f.job, f.retain_secs);
        let artifact_name = std::mem::take(&mut f.name);
        drop(guard);
        let entries: Vec<objects::Entry> = done
            .iter()
            .map(|(path, mode, staged)| objects::Entry {
                path: path.clone(),
                digest: staged.digest(),
                len: staged.len(),
                mode: *mode,
            })
            .collect();
        let manifest = artifacts::manifest_name(job, &artifact_name);
        let retain_until = UnixMillis(
            UnixMillis::now()
                .0
                .saturating_add(retain_secs.saturating_mul(1000) as i64),
        );
        let staged: Vec<objects::Staged> = done.into_iter().map(|(_, _, s)| s).collect();
        let objects = Arc::clone(&self.objects);
        let bytes = entries.iter().map(|e| e.len).sum::<u64>();
        let count = entries.len() as u64;
        // One transaction: object references, the manifest row and file,
        // then the artifact row that names its version. A crash mid-commit
        // can only leave adoptable orphans under `objects/`. The stages stay
        // pinned until this closure ends on the writer, after their rows.
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
        if let Some(publication) = self.publication(attempt) {
            let mut guard = publication.lock().unwrap_or_else(|p| p.into_inner());
            let f = &mut *guard;
            if !f.settled {
                self.settle(attempt, f);
                self.record_artifact(f, attempt, outcome, None);
                f.file = None;
                self.discard(std::mem::take(&mut f.done));
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

/// Why a spec could not be resolved.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SpecFault {
    /// For good: the attempt is gone, the source is not authorized or not
    /// allowed, the stored spec does not decode.
    Refused,
    /// Worth another try: reader overload, a busy writer, a GitHub timeout.
    Transient,
}

impl From<sentinel_store::Error> for SpecFault {
    fn from(error: sentinel_store::Error) -> Self {
        use sentinel_store::Error as E;
        match error {
            E::NotFound
            | E::Forbidden
            | E::Conflict
            | E::Corrupt(_)
            | E::InvalidInput(_)
            | E::Transition(_)
            | E::Spec(_)
            | E::Unresolved => SpecFault::Refused,
            _ => SpecFault::Transient,
        }
    }
}

fn resolve_spec(
    store: &Store,
    key: Option<&sentinel_auth::sealed::Key>,
    app: Option<&Arc<sentinel_github::app::App>>,
    destinations: &[String],
    worker: WorkerId,
    attempt: AttemptId,
) -> std::result::Result<(JobContext, Vec<u8>), SpecFault> {
    use sentinel_store::{Error as StoreError, sources};
    // One read snapshot: the attempt's context and spec, the binding that
    // authorizes it, and the destination policy.
    let (mut context, bytes, binding) = store.read(|conn| {
        let tx = conn.unchecked_transaction()?;
        let c = dispatch::job_context(&tx, worker, attempt)?;
        let bytes = dispatch::spec_bytes(&tx, worker, attempt)?;
        let context = JobContext {
            // Access is minted below, outside this snapshot.
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
            tenant: Some(c.tenant),
            trust: c.trust,
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
            .map_err(|e| match e {
            sentinel_intake::source::Error::Unavailable(_) => SpecFault::Transient,
            sentinel_intake::source::Error::Refused(_) => SpecFault::Refused,
        })?;
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
    // `Context2` carries the tenant and cache trust class from protocol 6;
    // earlier workers get the original shape and scope themselves to
    // pull-request state.
    sender.send(&session::context_message(protocol, &context, attempt))?;
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
    maintainer: Option<thread::JoinHandle<()>>,
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
    /// Pre-admission limits: how many connections may be in their handshake
    /// and hello at once, and how long each may take. Defaults are
    /// [`MAX_PENDING`] and [`session::HANDSHAKE_DEADLINE`].
    pub fn set_admission_limits(&self, pending: usize, handshake: Duration) {
        self.inner
            .max_pending
            .store(pending.max(1), Ordering::Relaxed);
        self.inner.handshake_ms.store(
            handshake.as_millis().clamp(1, u64::MAX as u128) as u64,
            Ordering::Relaxed,
        );
    }

    /// Enable storage maintenance (D06). Unset keeps every byte forever.
    pub fn set_storage_policy(&self, policy: StoragePolicy) {
        *self.inner.storage.lock().unwrap_or_else(|p| p.into_inner()) = Some(policy);
    }

    /// Where the controller keeps remote cache objects (Q08), normally
    /// `<data_dir>/remote-cache`. Unset answers every cache need `denied`;
    /// the directory itself is created lazily by the first upload. Setting
    /// it starts the store's reclamation (P08-C4): one bounded
    /// `remote::sweep_store` pass now and every [`REMOTE_SWEEP_INTERVAL`] —
    /// one bundle per entry, abandoned uploads removed, and the store held
    /// to `remote::STORE_BUDGET_BYTES`, least recently served first.
    pub fn set_remote_cache(&self, root: std::path::PathBuf) {
        let first = self
            .inner
            .remote_cache
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .replace(root)
            .is_none();
        if !first {
            return;
        }
        let watched = Arc::downgrade(&self.inner);
        let _ = thread::Builder::new()
            .name("sentinel-remote-cache-gc".into())
            .spawn(move || {
                loop {
                    let Some(inner) = watched.upgrade() else {
                        return;
                    };
                    let root = inner
                        .remote_cache
                        .lock()
                        .unwrap_or_else(|p| p.into_inner())
                        .clone();
                    if let Some(root) = root {
                        let swept = sentinel_cache::remote::sweep_store(
                            &root,
                            sentinel_cache::remote::STORE_BUDGET_BYTES,
                            sentinel_cache::gc::DEFAULT_PASS_WORK,
                            UnixMillis::now().0,
                        );
                        inner
                            .stats
                            .remote_cache_freed
                            .fetch_add(swept.bytes_freed, Ordering::Relaxed);
                        inner
                            .stats
                            .remote_cache_bytes
                            .store(swept.bytes, Ordering::Relaxed);
                    }
                    drop(inner);
                    thread::sleep(REMOTE_SWEEP_INTERVAL);
                }
            });
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
        let reconcile_logs = Arc::clone(&logs);
        let reconciled = store
            .writer()
            .write(move |tx| {
                dispatch::reconcile_startup(tx, UnixMillis::now(), Some(&reconcile_logs))
            })
            .map_err(|_| Error::Internal("startup reconciliation"))?;
        let listener = TcpListener::bind(listen)?;
        let addr = listener.local_addr()?;
        let inner = Arc::new(Inner {
            me: std::sync::OnceLock::new(),
            source_destinations: Mutex::new(Arc::new(Vec::new())),
            source_app: Mutex::new(None),
            specs: SpecDesk::new(),
            source_key: Mutex::new(None),
            store,
            logs,
            objects,
            artifacts: Mutex::new(ArtifactState::default()),
            storage: Mutex::new(None),
            last_storage: AtomicI64::new(0),
            maintenance: (Mutex::new(false), Condvar::new()),
            remote_cache: Mutex::new(None),
            config,
            fleet: Mutex::new(HashMap::new()),
            generation: AtomicU64::new(1),
            wake: (Mutex::new(false), Condvar::new()),
            stop: AtomicBool::new(false),
            sessions: AtomicUsize::new(0),
            pending: AtomicUsize::new(0),
            arrivals: Mutex::new(Vec::new()),
            arrived: AtomicU64::new(0),
            max_pending: AtomicUsize::new(MAX_PENDING),
            handshake_ms: AtomicU64::new(session::HANDSHAKE_DEADLINE.as_millis() as u64),
            stats: Stats::default(),
            revocations: Mutex::new((-1, -1)),
            warned: [AtomicI64::new(i64::MIN), AtomicI64::new(i64::MIN)],
            prefetch_at: Mutex::new(None),
        });
        let _ = inner.me.set(Arc::downgrade(&inner));
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
        let maintainer = {
            let inner = Arc::clone(&inner);
            thread::Builder::new()
                .name("sentinel-storage".into())
                .spawn(move || inner.maintenance_loop())?
        };
        Ok(Controller {
            inner,
            addr,
            fingerprint,
            reconciled,
            acceptor: Some(acceptor),
            dispatcher: Some(dispatcher),
            maintainer: Some(maintainer),
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
        {
            let (flag, cv) = &self.inner.maintenance;
            *flag.lock().unwrap_or_else(|p| p.into_inner()) = true;
            cv.notify_all();
        }
        if let Some(handle) = self.maintainer.take() {
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
    loop {
        let accepted = listener.accept();
        if inner.stop.load(Ordering::Acquire) {
            return;
        }
        let Ok((socket, addr)) = accepted else {
            continue;
        };
        // Two caps: every session, and — much smaller — connections that
        // have not authenticated yet, each also bounded by the handshake
        // deadline. Peers that prove nothing can never hold the slots the
        // enrolled fleet reconnects into.
        if inner.sessions.load(Ordering::Acquire) >= MAX_SESSIONS
            || inner.pending.load(Ordering::Acquire) >= inner.max_pending.load(Ordering::Relaxed)
        {
            inner.stats.shed.fetch_add(1, Ordering::Relaxed);
            drop(socket);
            continue;
        }
        inner.sessions.fetch_add(1, Ordering::AcqRel);
        inner.pending.fetch_add(1, Ordering::AcqRel);
        let session = Arc::clone(inner);
        let spawned = thread::Builder::new()
            .name("sentinel-link-session".into())
            .spawn(move || {
                session.serve(socket, addr);
                session.sessions.fetch_sub(1, Ordering::AcqRel);
            });
        if spawned.is_err() {
            inner.pending.fetch_sub(1, Ordering::AcqRel);
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

    /// The latest transport telemetry the worker reported (Q07): direct or
    /// relayed path, round-trip time, reconnects, helper version and byte
    /// counters. `None` until a protocol-7 worker reports one.
    pub fn transport(&self, worker: WorkerId) -> Option<TransportStats> {
        let peer = self
            .0
            .fleet
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&worker)
            .cloned()?;
        peer.transport
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
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

    /// Replace the allow list of the Tailcat helper that carries this link
    /// port, handing the tunnelled connections over instead of cutting them.
    ///
    /// Restarting the helper (its only way to take a new list) leaves every
    /// connection it carried open at the worker's end: a killed helper
    /// closes nothing through the tunnel, so the worker would notice only at
    /// a deadline, about 20 s later. So, while the old helper still runs,
    /// every connection that arrived through it — told apart from direct TLS
    /// by the helper owning the socket's other end — is closed cleanly (a
    /// TLS `close_notify` and a FIN), which the helper carries to the worker,
    /// and only then is the helper replaced. That covers sessions and also
    /// connections still in their TLS handshake or hello
    /// ([`session::Arrival`]). Direct-TLS sessions are never touched. `None`
    /// when the list is unchanged: no restart, no close.
    ///
    /// The helper is replaced as soon as every closed connection has ended
    /// at the worker's side too (the close was delivered), plus
    /// [`HANDOFF_SETTLE`], and after [`HANDOFF_BOUND`] at most. A close the
    /// tunnel lost is resent only by the helper that took it, so when every
    /// closed session's worker advertised `HANDOFF_ANSWER` (its silence then
    /// means the close was not delivered, and it cannot be stranded by a
    /// redial) the old helper is kept for up to [`HANDOFF_RESEND_BOUND`]
    /// while a close is unanswered. A worker that redials into it meanwhile
    /// is closed the same way: a new loopback arrival makes the helper's
    /// connections be read again.
    ///
    /// The worker reads the close as [`crate::Error::Closed`], replaces its
    /// own helper once its answer had time to leave, and redials on its
    /// shortest back-off. Live, a change then costs about the restarted
    /// helper's own start (3.2-4.3 s) where cutting cost 18.0-21.0 s.
    pub fn hand_off(&self, server: &Server, allow: &[NodeKey]) -> Option<Handoff> {
        let started = Instant::now();
        let mut handoff = Handoff::default();
        let changed = server.set_allow_draining(allow, |carried| {
            handoff = self.drain(carried, HANDOFF_BOUND, HANDOFF_RESEND_BOUND);
        });
        changed.then(|| {
            handoff.waited = started.elapsed();
            handoff
        })
    }

    /// Close cleanly every session (and its bulk connection) and every
    /// connection still in its handshake or hello that `carried` names, and
    /// wait until each has ended or `within` passed; `patiently`, when every
    /// closed connection is a session whose worker answers hand-offs.
    /// `carried` is read again whenever a loopback connection arrives
    /// meanwhile.
    fn drain(
        &self,
        carried: &dyn Fn() -> Vec<SocketAddr>,
        within: Duration,
        patiently: Duration,
    ) -> Handoff {
        let started = Instant::now();
        let (short, long) = (started + within, started + patiently.max(within));
        let mut seen = self.0.arrived.load(Ordering::Acquire);
        let mut from = carried();
        let mut handoff = Handoff {
            tunnelled: from.len(),
            ..Handoff::default()
        };
        if from.is_empty() {
            return handoff;
        }
        let mut claimed = Vec::new();
        let mut admitting = Vec::new();
        let mut closed: Vec<Closed> = Vec::new();
        let mut patient = None;
        self.claim(&from, &mut claimed, &mut admitting);
        self.close_carried(&from, &mut closed);
        loop {
            // A connection that arrived meanwhile may be a worker redialling
            // into the old helper: it would be cut with it.
            let arrived = self.0.arrived.load(Ordering::Acquire);
            if arrived != seen {
                seen = arrived;
                from = carried();
                self.claim(&from, &mut claimed, &mut admitting);
                self.close_carried(&from, &mut closed);
            }
            let admitted = admitting.len();
            admitting.retain(|arrival| arrival.admitting());
            if admitting.len() < admitted {
                self.close_carried(&from, &mut closed);
            }
            let open = {
                let fleet = self.0.fleet.lock().unwrap_or_else(|p| p.into_inner());
                closed
                    .iter()
                    .filter(|closed| {
                        fleet
                            .get(&closed.worker)
                            .is_some_and(|peer| peer.generation == closed.generation)
                    })
                    .count()
            };
            let (mut concluded, mut answered) = (0, 0);
            for arrival in &claimed {
                if let Some(yes) = arrival.answered() {
                    concluded += 1;
                    answered += usize::from(yes);
                }
            }
            handoff.closed = closed.len();
            handoff.arrivals = claimed.len();
            handoff.ended = closed.len() - open + answered;
            let now = Instant::now();
            if open == 0 && concluded == claimed.len() && admitting.is_empty() {
                if handoff.closed + handoff.arrivals > 0 {
                    let bound = if patient == Some(true) { long } else { short };
                    thread::sleep(HANDOFF_SETTLE.min(bound.saturating_duration_since(now)));
                }
                return handoff;
            }
            // Past the short bound only for workers that answer a delivered
            // close: one that does not could be redialling into this helper.
            // Decided once, at the short bound, so a redial closed later
            // still gets its close through.
            let deadline = if now < short {
                short
            } else if *patient.get_or_insert_with(|| {
                claimed.is_empty()
                    && admitting.is_empty()
                    && closed.iter().all(|closed| closed.answers)
            }) {
                long
            } else {
                short
            };
            if now >= deadline {
                return handoff;
            }
            thread::sleep(HANDOFF_POLL.min(deadline - now));
        }
    }

    /// Claim the connections still in their handshake or hello whose remote
    /// end is one of `from` (each then closes itself from its own thread),
    /// and note those whose hello is being admitted: they become sessions,
    /// closed once registered.
    fn claim(
        &self,
        from: &[SocketAddr],
        claimed: &mut Vec<Arc<session::Arrival>>,
        admitting: &mut Vec<Arc<session::Arrival>>,
    ) {
        for (addr, arrival) in self
            .0
            .arrivals
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
        {
            if from.binary_search(addr).is_err() {
                continue;
            }
            if arrival.hand_off() {
                claimed.push(Arc::clone(arrival));
            } else if arrival.admitting() && !admitting.iter().any(|a| Arc::ptr_eq(a, arrival)) {
                admitting.push(Arc::clone(arrival));
            }
        }
    }

    /// Close cleanly the registered sessions whose remote end is one of
    /// `from` and that are not in `closed` yet, adding them there.
    fn close_carried(&self, from: &[SocketAddr], closed: &mut Vec<Closed>) {
        // The fleet lock is not held across the socket calls below.
        let peers: Vec<(WorkerId, Arc<Peer>)> = self
            .0
            .fleet
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .filter(|(_, peer)| from.binary_search(&peer.addr).is_ok())
            .map(|(worker, peer)| (*worker, Arc::clone(peer)))
            .collect();
        for (worker, peer) in peers {
            if closed
                .iter()
                .any(|closed| closed.worker == worker && closed.generation == peer.generation)
            {
                continue;
            }
            if let Some(bulk) = peer.bulk.lock().unwrap_or_else(|p| p.into_inner()).as_ref() {
                bulk.close_notify();
            }
            peer.sender.close_notify();
            closed.push(Closed {
                worker,
                generation: peer.generation,
                answers: peer.answers_handoff,
            });
        }
    }
}

/// A session a hand-off closed.
struct Closed {
    worker: WorkerId,
    generation: u64,
    /// Its worker advertised `HANDOFF_ANSWER`.
    answers: bool,
}

/// Longest [`Handle::hand_off`] waits for closed connections before it
/// replaces the helper, whoever the workers are. Below the shortest
/// reconnect back-off (1 s less its 25 % jitter) of a worker that saw the
/// close, so it cannot redial into the old helper before it goes: a worker
/// older than `HANDOFF_ANSWER` keeps a forward younger than 10 s, and one
/// that redialled through it into the old helper was stuck for 21 s when
/// the wait was longer.
pub const HANDOFF_BOUND: Duration = Duration::from_millis(600);
/// Longest [`Handle::hand_off`] keeps the old helper for a close still
/// unanswered when every closed session's worker advertised
/// `HANDOFF_ANSWER`, so the silence means the close was not delivered. A
/// close the tunnel dropped is resent only by the helper that took it, on
/// its own retransmission clock: live, with 800 ms of loss at the worker,
/// closes arrived 1.4 s (direct) and up to 2.8 s (relayed) after they were
/// sent, and the direct ones were lost for good when the helper went at
/// 600 ms. Such a worker that redials into the old helper meanwhile is
/// closed as well, and replaces its forward on that close too.
pub const HANDOFF_RESEND_BOUND: Duration = Duration::from_millis(3_000);
/// After the last closed connection ended: time for the old helper to send
/// the close on through the tunnel before it is killed.
pub const HANDOFF_SETTLE: Duration = Duration::from_millis(100);
/// How often the hand-off looks for the closed connections' end.
const HANDOFF_POLL: Duration = Duration::from_millis(5);

/// What one [`Handle::hand_off`] did, for the operator's log.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Handoff {
    /// Connections the old helper carried into the link port.
    pub tunnelled: usize,
    /// Sessions among them that were closed cleanly.
    pub closed: usize,
    /// Connections among them still in their TLS handshake or hello, not
    /// yet sessions, that were closed cleanly.
    pub arrivals: usize,
    /// Of the closed sessions and connections, the ones whose worker closed
    /// its end before the helper was replaced: the close was delivered.
    pub ended: usize,
    /// From the call to the helper's replacement.
    pub waited: Duration,
}

impl std::fmt::Debug for Controller {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Controller")
            .field("addr", &self.addr)
            .field("fingerprint", &self.fingerprint)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn size(cpu_millis: i64, memory_bytes: i64, disk_bytes: i64) -> dispatch::Capacity {
        dispatch::Capacity {
            cpu_millis,
            memory_bytes,
            disk_bytes,
        }
    }

    #[test]
    fn reach_is_what_every_other_worker_of_the_pool_can_hold() {
        let (pool, other) = (PoolId::new(), PoolId::new());
        let reach = Reach::of([
            (pool, size(2_500, 2, 64)),
            (pool, size(5_000, 8, i64::MAX)),
            (other, size(64_000, 64, 64)),
            (pool, size(7_000, 16, 256)),
        ]);
        // The largest worker is compared with the next largest per resource,
        // across workers: memory and disk need not come from one machine.
        assert_eq!(reach.elsewhere(3, pool), Some(size(5_000, 8, i64::MAX)));
        assert_eq!(reach.elsewhere(0, pool), Some(size(7_000, 16, i64::MAX)));
        assert_eq!(reach.elsewhere(1, pool), Some(size(7_000, 16, 256)));
        // Another pool's worker is never "elsewhere", and a lone worker has
        // nothing to prefer.
        assert_eq!(reach.elsewhere(2, other), None);
    }

    fn ranked(cpu_millis: i64, load_ns: i64, cache_bytes: i64) -> Ranked {
        Ranked {
            cpu_millis,
            memory_bytes: 8 << 30,
            load_ns,
            cache_bytes,
        }
    }

    /// Q03's ranking, in its order of precedence: commitment, then measured
    /// load per core, then warm cache, then the smaller worker.
    #[test]
    fn the_sweep_ranks_workers_by_commitment_then_load_then_cache_then_size() {
        let idle = ranked(8_000, 0, 0);
        // A quarter committed ranks behind idle, whatever else it has.
        assert!(rank(idle, 0) < rank(ranked(8_000, 0, 1 << 40), 2_000));
        // Commitment is a share of the worker: 2 cores of 16 beat 2 of 8.
        assert!(rank(ranked(16_000, 0, 0), 2_000) < rank(ranked(8_000, 0, 0), 2_000));
        // Equal commitment: the host that measured less busy time per core.
        assert!(rank(ranked(8_000, 10_000_000, 0), 0) < rank(ranked(8_000, 400_000_000, 0), 0));
        // Load is per core: the same busy time on twice the cores is lighter.
        assert!(rank(ranked(16_000, 200_000_000, 0), 0) < rank(ranked(8_000, 200_000_000, 0), 0));
        // Equal load: more warm cache first.
        assert!(rank(ranked(8_000, 0, 1 << 30), 0) < rank(idle, 0));
        // Everything equal: the smaller worker (Q10's best fit).
        assert!(rank(ranked(2_500, 0, 0), 0) < rank(idle, 0));
    }

    /// P04-4: a burst of spec requests past the resolver bound is queued and
    /// every one is served, never refused; duplicates are not queued twice,
    /// and a worker cannot queue more than it may hold.
    #[test]
    fn the_spec_desk_serves_a_burst_past_its_resolver_bound_in_order() {
        let desk = std::sync::Arc::new(SpecDesk::<usize>::new());
        let worker = WorkerId::new();
        let keys: Vec<(WorkerId, AttemptId)> =
            (0..20).map(|_| (worker, AttemptId::new())).collect();
        let mut starts = 0;
        for (i, key) in keys.iter().enumerate() {
            match desk.submit(*key, i) {
                Submitted::Start => starts += 1,
                Submitted::Queued => {}
                other => panic!("request {i} was {other:?}"),
            }
        }
        assert_eq!(starts, SPEC_RESOLVERS);
        assert_eq!(desk.submit(keys[3], 99), Submitted::Duplicate);
        // Resolver threads drain the queue with at most SPEC_RESOLVERS
        // running; every request is served exactly once, in arrival order.
        let running = std::sync::Arc::new(AtomicUsize::new(0));
        let peak = std::sync::Arc::new(AtomicUsize::new(0));
        let served = std::sync::Arc::new(Mutex::new(Vec::new()));
        let threads: Vec<_> = (0..starts)
            .map(|_| {
                let (desk, running, peak, served) = (
                    std::sync::Arc::clone(&desk),
                    std::sync::Arc::clone(&running),
                    std::sync::Arc::clone(&peak),
                    std::sync::Arc::clone(&served),
                );
                thread::spawn(move || {
                    let mut done = None;
                    while let Some((key, i)) = desk.next(done.take()) {
                        let now = running.fetch_add(1, Ordering::SeqCst) + 1;
                        peak.fetch_max(now, Ordering::SeqCst);
                        thread::sleep(Duration::from_millis(5));
                        served.lock().unwrap().push(i);
                        running.fetch_sub(1, Ordering::SeqCst);
                        done = Some(key);
                    }
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }
        let mut served = served.lock().unwrap().clone();
        served.sort_unstable();
        assert_eq!(served, (0..20).collect::<Vec<_>>());
        assert!(peak.load(Ordering::SeqCst) <= SPEC_RESOLVERS);
        // Drained: the same attempt may ask again, and threads were counted out.
        assert_eq!(desk.submit(keys[3], 3), Submitted::Start);
        // Per-worker bound: no more waiting than it may hold.
        let desk = SpecDesk::<()>::new();
        for _ in 0..dispatch::MAX_HELD_ATTEMPTS {
            assert_ne!(desk.submit((worker, AttemptId::new()), ()), Submitted::Full);
        }
        assert_eq!(desk.submit((worker, AttemptId::new()), ()), Submitted::Full);
        assert_ne!(
            desk.submit((WorkerId::new(), AttemptId::new()), ()),
            Submitted::Full
        );
    }

    #[test]
    fn equal_largest_workers_hold_nothing_exclusive() {
        let pool = PoolId::new();
        let reach = Reach::of([(pool, size(7_000, 16, 256)), (pool, size(7_000, 16, 256))]);
        assert_eq!(reach.elsewhere(0, pool), Some(size(7_000, 16, 256)));
        assert_eq!(reach.elsewhere(1, pool), Some(size(7_000, 16, 256)));
    }
}
