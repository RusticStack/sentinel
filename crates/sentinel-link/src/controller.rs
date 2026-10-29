use std::{
    collections::{HashMap, HashSet, VecDeque},
    net::{IpAddr, SocketAddr, TcpListener, TcpStream},
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicBool, AtomicI64, AtomicU8, AtomicU64, AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use sentinel_auth::secret::{Digest, Secret};
use sentinel_cache::remote::{Need, Upload};
use sentinel_core::{
    AttemptId, Event, Fence, JobId, PoolId, RunId, TenantId, UnixMillis, WorkerId,
};
use sentinel_protocol::limits::{MAX_ARTIFACT_BYTES, MAX_ARTIFACT_ENTRIES};
use sentinel_protocol::logs::Frame;
use sentinel_protocol::negotiate::{
    CANCEL_PUSH_MIN, Capabilities, Hello, MAX_CANCEL_PUSH, MAX_PREFETCH_IMAGES, PREFETCH_MIN,
    PROFILE_MIN, Profile,
};
use sentinel_store::{
    Store, artifacts, dispatch,
    logs::LogStore,
    objects::{self, Objects},
    retention, workers,
};

use crate::{
    Error, Result, admission,
    identity::Identity,
    session::{
        self, Accepted, Admission, Admitted, ArtifactCode, ArtifactReply, Beat, BulkSession,
        Capacity, JobContext, LogVerdict, Offer, Rejection, Sender, SessionHandler, TransportStats,
    },
    tailcat::{NodeKey, Server, canonical},
    tls,
};

pub const RECONCILE_INTERVAL: Duration = Duration::from_secs(2);
pub const PREFETCH_INTERVAL: Duration = Duration::from_millis(500);
const _: () = assert!(
    dispatch::MAX_PREFETCH_HINTS <= MAX_PREFETCH_IMAGES,
    "a hint must fit the wire bound"
);
pub const MAX_SESSIONS: usize = 1024;
pub const MAX_PENDING: usize = 256;
const _: () = assert!(
    MAX_SESSIONS <= sentinel_store::logs::MAX_OPEN_WRITERS,
    "admission::LOG_FDS_PER_SESSION assumes one open log writer per session at most"
);

/// The open descriptors the controller needs to hold `sessions` worker sessions; the service raises its soft limit to this.
pub const fn descriptors_needed(sessions: usize) -> usize {
    admission::descriptors_for(sessions)
}
const SPEC_RESOLVERS: usize = 8;
const MAX_SPEC_QUEUE: usize = 4096;
const SPEC_ACK_WAIT: Duration = Duration::from_millis(dispatch::OFFER_ACK_MS as u64);
const SPEC_TRIES: u32 = 3;

const STORAGE_BATCH: i64 = 256;
const ORPHAN_SCAN_BUDGET: u32 = 4096;
const LOG_STAMP_ROUNDS: u32 = 16;
const MAINTENANCE_TICK: Duration = Duration::from_millis(250);

#[derive(Clone, Copy, Debug)]
pub struct StoragePolicy {
    pub interval_ms: i64,
}

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
    pub artifacts: AtomicU64,
    pub bulk_attached: AtomicU64,
    pub bulk_refused: AtomicU64,
    pub cache_denied: AtomicU64,
    pub remote_cache_freed: AtomicU64,
    pub remote_cache_bytes: AtomicU64,
    pub shed: AtomicU64,
    pub enrollment_limited: AtomicU64,
    pub handed_back: AtomicU64,
    pub placement_errors: AtomicU64,
    pub sweep_errors: AtomicU64,
    pub prefetch_hints: AtomicU64,
    pub cancels_pushed: AtomicU64,
    pub revoked_sessions: AtomicU64,
    /// Hellos refused because the certificate belongs to a revoked or uninstalled worker.
    pub revoked_refused: AtomicU64,
    pub deferred_worker_messages: AtomicU64,
    pub deferred_dropped: AtomicU64,
}

#[derive(Clone)]
enum Deferred {
    Ack,
    Report {
        event: Event,
        summary: Option<Arc<Vec<u8>>>,
    },
}

#[derive(Clone)]
struct DeferredMessage {
    id: u64,
    worker: WorkerId,
    attempt: AttemptId,
    fence: Fence,
    what: Deferred,
    since: Instant,
}

#[derive(Default)]
struct DeferredQueue {
    items: VecDeque<DeferredMessage>,
}

impl DeferredQueue {
    fn holds(&self, attempt: AttemptId) -> bool {
        self.items.iter().any(|m| m.attempt == attempt)
    }

    fn push(&mut self, message: DeferredMessage) -> bool {
        if self.items.len() >= MAX_DEFERRED {
            return false;
        }
        self.items.push_back(message);
        true
    }

    fn head(&self) -> Option<DeferredMessage> {
        self.items.front().cloned()
    }

    fn settle(&mut self, id: u64) {
        if self.items.front().is_some_and(|m| m.id == id) {
            self.items.pop_front();
        }
    }

    fn has_report(&self, attempt: AttemptId) -> bool {
        self.items
            .iter()
            .any(|m| m.attempt == attempt && matches!(m.what, Deferred::Report { .. }))
    }

    fn attempts(&self) -> HashSet<AttemptId> {
        self.items.iter().map(|m| m.attempt).collect()
    }
}

const MAX_DEFERRED: usize = 256;
const DEFERRED_MAX_AGE: Duration = Duration::from_secs(300);

enum Received {
    /// The store took it.
    Applied,
    /// A verdict already waiting for this attempt; a resend adds nothing.
    Copy,
    /// Waits behind an earlier message of the attempt; `kept` is `false` when the full queue refused it.
    Queued { kept: bool },
    Transient {
        error: sentinel_store::Error,
        kept: bool,
    },
    /// The store refused it as stale: nothing changed.
    Stale,
}

fn receive_with(
    queue: &Mutex<DeferredQueue>,
    message: &DeferredMessage,
    apply: impl FnOnce(&DeferredMessage) -> sentinel_store::Result<()>,
) -> Received {
    {
        let mut q = queue.lock().unwrap_or_else(|p| p.into_inner());
        if q.holds(message.attempt) {
            if matches!(message.what, Deferred::Report { .. }) && q.has_report(message.attempt) {
                return Received::Copy;
            }
            return Received::Queued {
                kept: q.push(message.clone()),
            };
        }
    }
    match apply(message) {
        Ok(()) => Received::Applied,
        Err(error) if error.is_transient() => {
            let kept = queue
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .push(message.clone());
            Received::Transient { error, kept }
        }
        Err(_) => Received::Stale,
    }
}

enum Retried {
    Applied,
    Aged,
    Stale,
    Transient(sentinel_store::Error),
}

fn retry_with(
    queue: &Mutex<DeferredQueue>,
    max_age: Duration,
    mut apply: impl FnMut(&DeferredMessage) -> sentinel_store::Result<()>,
    mut each: impl FnMut(&DeferredMessage, &Retried),
) {
    loop {
        let head = queue.lock().unwrap_or_else(|p| p.into_inner()).head();
        let Some(message) = head else {
            return;
        };
        let outcome = if message.since.elapsed() >= max_age {
            Retried::Aged
        } else {
            match apply(&message) {
                Ok(()) => Retried::Applied,
                Err(e) if e.is_transient() => Retried::Transient(e),
                Err(_) => Retried::Stale,
            }
        };
        each(&message, &outcome);
        if matches!(outcome, Retried::Transient(_)) {
            return;
        }
        queue
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .settle(message.id);
    }
}

fn shield(due: &mut Vec<(AttemptId, RunId, JobId)>, waiting: &HashSet<AttemptId>) {
    if !waiting.is_empty() {
        due.retain(|(attempt, _, _)| !waiting.contains(attempt));
    }
}

fn shield_stop(stop: &mut Vec<AttemptId>, waiting: &HashSet<AttemptId>) {
    if !waiting.is_empty() {
        stop.retain(|attempt| !waiting.contains(attempt));
    }
}

struct Peer {
    sender: Sender,
    addr: SocketAddr,
    answers_handoff: bool,
    pool: PoolId,
    generation: u64,
    cpu_millis: i64,
    memory_bytes: i64,
    disk_bytes: AtomicI64,
    load_ns: AtomicI64,
    cache_bytes: AtomicI64,
    /// The machine identity from the worker's profile; identities sharing one are one physical host.
    host: Mutex<Option<[u8; 16]>>,
    seen_recorded_ms: AtomicI64,
    fingerprint: Digest,
    protocol: u16,
    arch: sentinel_protocol::negotiate::Arch,
    transport: Mutex<Option<TransportStats>>,
    logging: Mutex<HashMap<AttemptId, (RunId, JobId)>>,
    bulk: Mutex<Option<Sender>>,
    prefetch_sent: Mutex<Option<Vec<String>>>,
}

struct OpenFile {
    path: String,
    mode: u32,
    declared: u64,
    next_seq: u32,
    staging: objects::Staging,
}

struct InFlight {
    tenant: TenantId,
    run: RunId,
    job: sentinel_core::JobId,
    name: String,
    retain_secs: u64,
    done: Vec<(String, u32, objects::Staged)>,
    accounted: u64,
    last_path: String,
    file: Option<OpenFile>,
    settled: bool,
}

type Publication = Arc<Mutex<InFlight>>;

#[derive(Default)]
struct ArtifactState {
    in_flight: HashMap<AttemptId, Publication>,
    runs: HashMap<RunId, u64>,
}

struct SpecRequest {
    worker: WorkerId,
    attempt: AttemptId,
    sender: Sender,
    protocol: u16,
}

struct SpecDesk<T> {
    state: Mutex<DeskState<T>>,
}

struct DeskState<T> {
    running: usize,
    queue: VecDeque<((WorkerId, AttemptId), T)>,
    pending: HashSet<(WorkerId, AttemptId)>,
    per_worker: HashMap<WorkerId, usize>,
}

#[derive(Debug, PartialEq, Eq)]
enum Submitted {
    Start,
    Queued,
    Duplicate,
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

    fn not_started(&self) {
        self.lock().running -= 1;
    }
}

struct Inner {
    me: std::sync::OnceLock<std::sync::Weak<Inner>>,
    source_destinations: Mutex<Arc<Vec<String>>>,
    source_app: Mutex<Option<Arc<sentinel_github::app::App>>>,
    specs: SpecDesk<SpecRequest>,
    source_key: Mutex<Option<Arc<sentinel_auth::sealed::Key>>>,
    store: Arc<Store>,
    logs: Arc<LogStore>,
    objects: Arc<Objects>,
    artifacts: Mutex<ArtifactState>,
    storage: Mutex<Option<StoragePolicy>>,
    remote_budget: AtomicU64,
    order: AtomicU8,
    last_storage: AtomicI64,
    maintenance: (Mutex<bool>, Condvar),
    remote_cache: Mutex<Option<std::path::PathBuf>>,
    config: Arc<rustls::ServerConfig>,
    fleet: Mutex<HashMap<WorkerId, Arc<Peer>>>,
    generation: AtomicU64,
    wake: (Mutex<bool>, Condvar),
    stop: AtomicBool,
    sessions: AtomicUsize,
    session_cap: usize,
    pending: admission::Pending,
    enrollments: admission::Enrollments,
    arrivals: Mutex<Vec<(SocketAddr, Arc<session::Arrival>)>>,
    arrived: AtomicU64,
    max_pending: AtomicUsize,
    handshake_ms: AtomicU64,
    stats: Stats,
    revocations: Mutex<(i64, i64)>,
    warned: [AtomicI64; 2],
    prefetch_at: Mutex<Option<Instant>>,
    cancel_hint: AtomicBool,
    deferred: Mutex<DeferredQueue>,
    next_deferred: AtomicU64,
}

const WARN_INTERVAL_MS: i64 = 60_000;

/// The busy CPU time `Availability::load_ns` counts is measured over this window (the worker samples
/// `/proc/stat` for 100 ms), so `load_ns / LOAD_WINDOW_NS` is the number of busy cores.
const LOAD_WINDOW_NS: i64 = 100_000_000;
/// Placement ranks workers by when a reference job would finish on them: [`REFERENCE_JOB_MILLIS`] of CPU
/// and [`REFERENCE_WORK_NS`] of service with no contention. Only the ratios matter; neither is a claim
/// about real jobs.
const REFERENCE_JOB_MILLIS: i64 = 1_000;
const REFERENCE_WORK_NS: i128 = 10_000_000_000;
/// A host already fully used runs the reference job `1 / INTERFERENCE_DIVISOR` slower even before the
/// job oversubscribes it (memory bandwidth, disk and cache are shared).
const INTERFERENCE_DIVISOR: i64 = 16;
/// A warm cache of `CACHE_CREDIT_FULL_BYTES` or more is worth at most a tenth of the reference service
/// time. The credit is bounded on purpose: locality can offset a mild slowdown but never an
/// oversubscribed host, so cache affinity cannot strand work behind a saturated machine.
const CACHE_CREDIT_FULL_BYTES: i64 = 4 << 30;
const CACHE_CREDIT_MAX_NS: i128 = REFERENCE_WORK_NS / 10;

/// What the controller knows of one worker when it ranks it. `committed_millis` is the **host's**
/// commitment, not the identity's: the larger of what every connected identity on the host has been
/// offered and what the host measured busy (the two overlap, running attempts are inside the
/// measurement, so they are not added).
#[derive(Clone, Copy, Debug)]
struct Standing {
    cpu_millis: i64,
    memory_bytes: i64,
    committed_millis: i64,
    cache_bytes: i64,
}

fn busy_millis(load_ns: i64) -> i64 {
    load_ns.max(0) / (LOAD_WINDOW_NS / 1_000)
}

/// Nanoseconds until the reference job would finish if it started on this worker now, less the bounded
/// credit for a warm cache. Processor sharing: once the host's commitment plus the job exceeds its
/// cores, every core's share falls with it. Lower is better.
fn expected_finish_ns(standing: Standing) -> i64 {
    let cpu = i128::from(standing.cpu_millis.max(1));
    let committed = i128::from(standing.committed_millis.max(0));
    let after = committed + i128::from(REFERENCE_JOB_MILLIS);
    let slowdown_ppm = (after * 1_000_000 / cpu).max(1_000_000);
    let busy_ppm = committed.min(cpu) * 1_000_000 / cpu;
    let factor_ppm = slowdown_ppm + busy_ppm / i128::from(INTERFERENCE_DIVISOR);
    let service = REFERENCE_WORK_NS * factor_ppm / 1_000_000;
    let warm = i128::from(standing.cache_bytes.clamp(0, CACHE_CREDIT_FULL_BYTES));
    let credit = CACHE_CREDIT_MAX_NS * warm / i128::from(CACHE_CREDIT_FULL_BYTES);
    i64::try_from(service - credit).unwrap_or(i64::MAX)
}

/// Earliest expected finish first; among equals the smaller worker (best fit keeps the larger one free
/// for work only it can hold), then the smaller memory.
fn rank(standing: Standing) -> (i64, i64, i64) {
    (
        expected_finish_ns(standing),
        standing.cpu_millis,
        standing.memory_bytes,
    )
}

/// How the sweep orders the free workers once hard admission has decided what each may take.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum PlacementOrder {
    /// Earliest expected finish first (the default): the fastest eligible worker.
    #[default]
    Fastest,
    /// Highest operator priority first, then earliest expected finish. The operator's priority
    /// overrides speed and nothing else: the order only decides which free worker is asked first, and
    /// a worker is asked to take only work that tenant, pool, architecture, OS, isolation, label,
    /// disk, CPU and memory admission already let it have ([`dispatch::place_in_fleet`]).
    Priority,
}

impl PlacementOrder {
    pub fn parse(text: &str) -> Option<PlacementOrder> {
        match text {
            "fastest" => Some(PlacementOrder::Fastest),
            "priority" => Some(PlacementOrder::Priority),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            PlacementOrder::Fastest => "fastest",
            PlacementOrder::Priority => "priority",
        }
    }
}

/// The first thing that puts one worker ahead of the next in the order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OrderFactor {
    /// A higher operator priority (only under [`PlacementOrder::Priority`]).
    Priority,
    /// An earlier expected finish.
    ExpectedFinish,
    /// Equal finish: the smaller worker, which keeps the larger one free.
    BestFit,
    /// Everything equal: the worker identifier, so the order is deterministic.
    Identity,
}

impl OrderFactor {
    pub fn as_str(self) -> &'static str {
        match self {
            OrderFactor::Priority => "priority",
            OrderFactor::ExpectedFinish => "expected_finish",
            OrderFactor::BestFit => "best_fit",
            OrderFactor::Identity => "identity",
        }
    }
}

/// One free worker as the next placement round orders it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ranked {
    pub worker: WorkerId,
    /// The priority the controller approved for the host (0 when it has none).
    pub priority: i32,
    pub expected_finish_ns: i64,
    /// Why this worker is ahead of the next one; `None` for the last.
    pub ahead_because: Option<OrderFactor>,
}

type OrderKey = (i32, (i64, i64, i64));

/// The sort key of one worker: the (negated) priority first under [`PlacementOrder::Priority`] and a
/// constant under [`PlacementOrder::Fastest`], then the speed rank. Lower sorts first.
fn order_key(order: PlacementOrder, priority: i32, standing: Standing) -> OrderKey {
    let lead = match order {
        PlacementOrder::Fastest => 0,
        PlacementOrder::Priority => priority.saturating_neg(),
    };
    (lead, rank(standing))
}

fn ahead_because(ahead: OrderKey, behind: OrderKey) -> OrderFactor {
    if ahead.0 != behind.0 {
        OrderFactor::Priority
    } else if (ahead.1).0 != (behind.1).0 {
        OrderFactor::ExpectedFinish
    } else if ((ahead.1).1, (ahead.1).2) != ((behind.1).1, (behind.1).2) {
        OrderFactor::BestFit
    } else {
        OrderFactor::Identity
    }
}

/// The order the next round uses, with the reason each worker is ahead of the next. The placement
/// pass sorts by the same [`order_key`], so this is the order, not a description of it.
fn ranking(order: PlacementOrder, entries: &[(WorkerId, i32, Standing)]) -> Vec<Ranked> {
    let mut keyed: Vec<(OrderKey, WorkerId, i32)> = entries
        .iter()
        .map(|(w, priority, standing)| (order_key(order, *priority, *standing), *w, *priority))
        .collect();
    keyed.sort_unstable_by_key(|(key, worker, _)| (*key, *worker));
    (0..keyed.len())
        .map(|i| Ranked {
            worker: keyed[i].1,
            priority: keyed[i].2,
            expected_finish_ns: (keyed[i].0.1).0,
            ahead_because: keyed
                .get(i + 1)
                .map(|next| ahead_because(keyed[i].0, next.0)),
        })
        .collect()
}

/// The size the controller offers a worker: the store's effective size (the report under the approved
/// ceilings), not the size its hello claimed. A worker the store has not listed yet keeps its hello.
fn effective_size(peer: &Peer, approved: Option<&dispatch::Approved>) -> dispatch::Capacity {
    match approved {
        Some(a) => dispatch::Capacity {
            cpu_millis: a.size.cpu_millis,
            memory_bytes: a.size.memory_bytes,
            disk_bytes: if peer.protocol >= PROFILE_MIN.0 {
                a.size.disk_bytes
            } else {
                i64::MAX
            },
        },
        None => peer.size(),
    }
}

/// Per machine: the CPU its identities hold and the busy cores the machine measured. Identities are
/// grouped by machine over the whole fleet, busy sessions included: their attempts and their
/// measurements are still the host's.
fn host_commitments(
    fleet: &[(WorkerId, Arc<Peer>)],
    hosts: &HashMap<WorkerId, [u8; 16]>,
    held: &HashMap<WorkerId, i64>,
) -> (HashMap<[u8; 16], i64>, HashMap<[u8; 16], i64>) {
    let mut host_held: HashMap<[u8; 16], i64> = HashMap::new();
    let mut host_busy: HashMap<[u8; 16], i64> = HashMap::new();
    for (worker, peer) in fleet {
        let host = hosts[worker];
        *host_held.entry(host).or_default() += held.get(worker).copied().unwrap_or(0);
        let busy = host_busy.entry(host).or_default();
        *busy = (*busy).max(busy_millis(peer.load_ns.load(Ordering::Relaxed)));
    }
    (host_held, host_busy)
}

/// The machine key placement groups identities by: the reported host, or the worker itself when it
/// reported none (each such identity is accounted alone, as the store does).
fn host_key(worker: WorkerId, host: Option<[u8; 16]>) -> [u8; 16] {
    host.unwrap_or(*worker.as_bytes())
}

impl Peer {
    fn host(&self) -> Option<[u8; 16]> {
        *self.host.lock().unwrap_or_else(|p| p.into_inner())
    }
}

struct Reach {
    pools: Vec<PoolReach>,
}

struct PoolReach {
    pool: PoolId,
    workers: usize,
    cpu: (i64, usize, i64),
    memory: (i64, usize, i64),
    disk: (i64, usize, i64),
}

fn top_two(top: &mut (i64, usize, i64), value: i64, index: usize) {
    if value > top.0 {
        *top = (value, index, top.0);
    } else if value > top.2 {
        top.2 = value;
    }
}

fn other_than(top: (i64, usize, i64), index: usize) -> i64 {
    if top.1 == index { top.2 } else { top.0 }
}

impl Peer {
    fn size(&self) -> dispatch::Capacity {
        dispatch::Capacity {
            cpu_millis: self.cpu_millis,
            memory_bytes: self.memory_bytes,
            disk_bytes: if self.protocol >= PROFILE_MIN.0 {
                self.disk_bytes.load(Ordering::Relaxed)
            } else {
                i64::MAX
            },
        }
    }
}

impl Reach {
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

    /// A worker authenticated from `ip`: remember the source, and tell the store when it has not heard of it lately.
    fn vouch(&self, ip: IpAddr) {
        let Some(source) = self.pending.vouch(ip, Instant::now()) else {
            return;
        };
        let _ = self.write_store(move |tx| {
            sentinel_store::known_sources::record(
                tx,
                source,
                UnixMillis::now().0,
                admission::KNOWN_TTL.as_millis() as i64,
            )
        });
    }

    fn register(&self, worker: WorkerId, peer: Arc<Peer>) {
        let old = self
            .fleet
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(worker, peer);
        if let Some(old) = old {
            old.sender.close();
        }
    }

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
        self.pending.leave(addr.ip());
        let mut session = match outcome {
            Ok(Accepted::Control(session)) => {
                self.vouch(addr.ip());
                session
            }
            Ok(Accepted::Bulk(bulk)) => {
                self.vouch(addr.ip());
                self.leave(arrival.as_ref());
                self.serve_bulk(bulk);
                return;
            }
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
            cpu_millis: i64::try_from(capacity.cpu_millis).unwrap_or(i64::MAX),
            memory_bytes: i64::try_from(capacity.memory_bytes).unwrap_or(i64::MAX),
            disk_bytes: AtomicI64::new(0),
            load_ns: AtomicI64::new(0),
            cache_bytes: AtomicI64::new(0),
            host: Mutex::new(None),
            seen_recorded_ms: AtomicI64::new(0),
            fingerprint: session.fingerprint,
            protocol: session.admitted.negotiated.protocol.0,
            arch: session.admitted.negotiated.arch,
            transport: Mutex::new(None),
            logging: Mutex::new(HashMap::new()),
            bulk: Mutex::new(None),
            prefetch_sent: Mutex::new(None),
        });
        self.register(worker, Arc::clone(&peer));
        self.leave(arrival.as_ref());
        self.wake();
        let _ = session.serve(&**self);
        self.unregister(worker, generation);
        peer.sender.close();
        if let Some(bulk) = peer.bulk.lock().unwrap_or_else(|p| p.into_inner()).take() {
            bulk.close();
        }
        self.stats.sessions_ended.fetch_add(1, Ordering::Relaxed);
    }

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
        let worker = bulk.worker;
        let alive = || {
            self.peer(worker)
                .is_some_and(|live| Arc::ptr_eq(&live, &peer))
        };
        let _ = bulk.serve(&**self, peer.protocol, &alive);
        sender.close();
        self.stats.sessions_ended.fetch_add(1, Ordering::Relaxed);
    }

    fn write_store<T: Send + 'static>(
        &self,
        f: impl FnOnce(&sentinel_store::Transaction<'_>) -> sentinel_store::Result<T> + Send + 'static,
    ) -> sentinel_store::Result<T> {
        self.store.writer().write(f)
    }

    fn failed(&self, placement: bool, what: &'static str, error: &sentinel_store::Error) {
        let (counter, slot) = if placement {
            (&self.stats.placement_errors, &self.warned[0])
        } else {
            (&self.stats.sweep_errors, &self.warned[1])
        };
        let total = counter.fetch_add(1, Ordering::Relaxed) + 1;
        let now = UnixMillis::steady().0;
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

    fn benign(error: &sentinel_store::Error) -> bool {
        matches!(
            error,
            sentinel_store::Error::Conflict | sentinel_store::Error::NotFound
        )
    }

    fn dispatch_pass(&self) {
        if self.cancel_hint.swap(false, Ordering::AcqRel) {
            self.cancel_push_pass();
        }
        self.retry_deferred();
        let now = UnixMillis::steady();
        match self
            .store
            .read(|c| dispatch::expired_scoped(c, now))
            .map(|mut due| {
                shield(&mut due, &self.deferred_attempts());
                due
            }) {
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
        let deferred = self.deferred_attempts();
        match self.write_store(move |tx| {
            dispatch::lapse_due(tx, now, |attempt| deferred.contains(&attempt))
        }) {
            Ok(swept) => {
                self.stats
                    .lapsed
                    .fetch_add(swept.done as u64, Ordering::Relaxed);
                self.swept("lapse", swept);
            }
            Err(e) => self.failed(false, "lapse", &e),
        }
        self.uninstall_pass();
        self.revocation_pass(now);
        self.placement_pass();
        self.prefetch_pass();
    }

    /// One read for every connected worker that speaks protocol 11; a failed read or send is left to the
    /// heartbeat, which repeats every pending cancel anyway.
    fn cancel_push_pass(&self) {
        let peers: Vec<(WorkerId, Arc<Peer>)> = self
            .fleet
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .filter(|(_, p)| p.protocol >= CANCEL_PUSH_MIN.0)
            .map(|(w, p)| (*w, Arc::clone(p)))
            .collect();
        if peers.is_empty() {
            return;
        }
        let workers: Vec<WorkerId> = peers.iter().map(|(w, _)| *w).collect();
        let pending = match self.store.read(move |c| {
            workers
                .iter()
                .map(|&w| dispatch::cancel_pending(c, w))
                .collect::<sentinel_store::Result<Vec<_>>>()
        }) {
            Ok(pending) => pending,
            Err(e) => return self.failed(false, "cancel_push", &e),
        };
        for (attempts, (_, peer)) in pending.iter().zip(&peers) {
            for chunk in attempts.chunks(MAX_CANCEL_PUSH) {
                if session::cancel(&peer.sender, chunk).is_ok() {
                    self.stats
                        .cancels_pushed
                        .fetch_add(chunk.len() as u64, Ordering::Relaxed);
                }
            }
        }
    }

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

    fn swept(&self, what: &'static str, swept: dispatch::Swept) {
        if let Some(error) = &swept.error {
            self.stats
                .sweep_errors
                .fetch_add(swept.failed as u64 - 1, Ordering::Relaxed);
            self.failed(false, what, error);
        }
    }

    /// An uninstall is a drain plus a revoke once the accepted work has settled; the revocation pass
    /// that follows closes the session and fences whatever is left.
    fn uninstall_pass(&self) {
        match self.store.read(workers::uninstalling) {
            Ok(false) => {}
            Ok(true) => {
                if let Err(e) =
                    self.write_store(|tx| workers::settle_uninstalls(tx, UnixMillis::now()))
                {
                    self.failed(false, "uninstall", &e);
                }
            }
            Err(e) => self.failed(false, "uninstall", &e),
        }
    }

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

    fn placement_order(&self) -> PlacementOrder {
        if self.order.load(Ordering::Relaxed) == PlacementOrder::Priority as u8 {
            PlacementOrder::Priority
        } else {
            PlacementOrder::Fastest
        }
    }

    /// The order the next placement round would use, from the same inputs and the same sort key as
    /// the pass, with the reason each free worker is ahead of the next. Read-only.
    fn placement_ranking(&self) -> Vec<Ranked> {
        let fleet: Vec<(WorkerId, Arc<Peer>)> = self
            .fleet
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .map(|(w, p)| (*w, Arc::clone(p)))
            .collect();
        let (held, approved) = match (
            self.store.read(dispatch::held_by_worker),
            self.store.read(dispatch::approved_by_worker),
        ) {
            (Ok(held), Ok(approved)) => (held, approved),
            _ => return Vec::new(),
        };
        let hosts: HashMap<WorkerId, [u8; 16]> = fleet
            .iter()
            .map(|(w, p)| (*w, host_key(*w, p.host())))
            .collect();
        let (host_held, host_busy) = host_commitments(&fleet, &hosts, &held);
        let entries: Vec<(WorkerId, i32, Standing)> = fleet
            .iter()
            .filter(|(_, p)| session::is_free(&p.sender))
            .map(|(w, p)| {
                let size = effective_size(p, approved.get(w));
                let host = hosts[w];
                (
                    *w,
                    approved.get(w).map_or(0, |a| a.priority),
                    Standing {
                        cpu_millis: size.cpu_millis,
                        memory_bytes: size.memory_bytes,
                        committed_millis: host_held
                            .get(&host)
                            .copied()
                            .unwrap_or(0)
                            .max(host_busy.get(&host).copied().unwrap_or(0)),
                        cache_bytes: p.cache_bytes.load(Ordering::Relaxed),
                    },
                )
            })
            .collect();
        ranking(self.placement_order(), &entries)
    }

    fn placement_pass(&self) {
        if !self.objects.admission().is_none_or(|a| a.is_open()) {
            return;
        }
        let fleet: Vec<(WorkerId, Arc<Peer>)> = self
            .fleet
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .map(|(w, p)| (*w, Arc::clone(p)))
            .collect();
        let mut peers: Vec<(WorkerId, Arc<Peer>)> = fleet
            .iter()
            .filter(|(_, p)| session::is_free(&p.sender))
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
        // The effective size and the approved priority come from the store on every pass, so a
        // ceiling lowered or a priority changed after a worker connected is used at once.
        let approved = match self.store.read(dispatch::approved_by_worker) {
            Ok(approved) => approved,
            Err(e) => return self.failed(true, "approved", &e),
        };
        peers.sort_unstable_by_key(|(worker, p)| {
            let size = effective_size(p, approved.get(worker));
            (size.cpu_millis, size.memory_bytes, *worker)
        });
        let sizes: Vec<dispatch::Capacity> = peers
            .iter()
            .map(|(w, p)| effective_size(p, approved.get(w)))
            .collect();
        let priorities: Vec<i32> = peers
            .iter()
            .map(|(w, _)| approved.get(w).map_or(0, |a| a.priority))
            .collect();
        let order = self.placement_order();
        let reach = Reach::of(
            peers
                .iter()
                .zip(&sizes)
                .map(|((_, p), size)| (p.pool, *size)),
        );
        let hosts: HashMap<WorkerId, [u8; 16]> = fleet
            .iter()
            .map(|(w, p)| (*w, host_key(*w, p.host())))
            .collect();
        let host_of: Vec<[u8; 16]> = peers.iter().map(|(w, _)| hosts[w]).collect();
        let mut active: Vec<usize> = (0..peers.len()).collect();
        for _ in 0..dispatch::MAX_HELD_ATTEMPTS {
            if active.is_empty() {
                return;
            }
            let (host_held, host_busy) = host_commitments(&fleet, &hosts, &held);
            active.sort_by_cached_key(|&i| {
                let (worker, peer) = &peers[i];
                let host = host_of[i];
                (
                    order_key(
                        order,
                        priorities[i],
                        Standing {
                            cpu_millis: sizes[i].cpu_millis,
                            memory_bytes: sizes[i].memory_bytes,
                            committed_millis: host_held
                                .get(&host)
                                .copied()
                                .unwrap_or(0)
                                .max(host_busy.get(&host).copied().unwrap_or(0)),
                            cache_bytes: peer.cache_bytes.load(Ordering::Relaxed),
                        },
                    ),
                    *worker,
                )
            });
            // One identity per machine per round: the next placement on a host is ranked again
            // against what this round just committed, so several identities on one host cannot
            // each take a job from the same stale view and oversubscribe it.
            let mut taken: HashSet<[u8; 16]> = HashSet::new();
            let round: Vec<(usize, WorkerId, PoolId, Option<dispatch::Capacity>)> = active
                .iter()
                .copied()
                .filter(|&i| taken.insert(host_of[i]))
                .map(|i| {
                    (
                        i,
                        peers[i].0,
                        peers[i].1.pool,
                        reach.elsewhere(i, peers[i].1.pool),
                    )
                })
                .collect();
            let now = UnixMillis::steady();
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
                if let Err(sent) = session::offer(&peer.sender, &offer) {
                    let busy = session::is_busy(&sent);
                    let attempt = offer.attempt;
                    match self
                        .write_store(move |tx| dispatch::lapse(tx, attempt, UnixMillis::steady()))
                    {
                        Ok(()) => {}
                        Err(e) if Self::benign(&e) => {}
                        Err(e) => self.failed(false, "lapse", &e),
                    }
                    if !busy {
                        peer.sender.close();
                    }
                    done.push(i);
                    continue;
                }
                self.stats.offers.fetch_add(1, Ordering::Relaxed);
                *held.entry(*worker).or_insert(0) += placed.cpu_millis;
            }
            active.retain(|i| !done.contains(i));
        }
    }

    fn storage_pass(&self, now: UnixMillis) {
        // A backup holds this for its whole run: nothing it snapshotted may be deleted before it is copied.
        let Some(_maintenance) = self.objects.try_maintenance() else {
            return;
        };
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
        self.log_retention(now);
    }

    fn log_retention(&self, now: UnixMillis) {
        let deployment = self.objects.deployment();
        if let Some(admission) = self.objects.admission() {
            admission.set_metadata_bytes(self.store.metadata_bytes());
        }
        for _ in 0..LOG_STAMP_ROUNDS {
            let Ok(rows) = self
                .store
                .read(|c| retention::unstamped(c, STORAGE_BATCH as u32))
            else {
                break;
            };
            let full = rows.len() as i64 == STORAGE_BATCH;
            if rows.is_empty() {
                break;
            }
            let sized: Vec<_> = rows
                .into_iter()
                .map(|r| {
                    let bytes = self.logs.stored_bytes(r.run, r.job, r.attempt);
                    (r, bytes)
                })
                .collect();
            if self
                .write(move |tx| retention::stamp(tx, &deployment, &sized))
                .is_err()
                || !full
            {
                break;
            }
        }
        if let Ok(due) = self
            .store
            .read(|c| retention::expiring(c, now, STORAGE_BATCH as u32))
            && !due.is_empty()
            && let Ok(expired) = self.write(move |tx| retention::expire(tx, &due, now))
        {
            for log in expired {
                let _ = self.logs.remove(log.run, log.job, log.attempt);
            }
        }
        let store = &self.store;
        let _ = self.logs.sweep_dirs(STORAGE_BATCH as u32, |attempt| {
            store
                .read(|c| retention::log_gone(c, attempt))
                .unwrap_or(false)
        });
        let _ =
            self.write(move |tx| retention::purge_aborted_uploads(tx, now, STORAGE_BATCH as u32));
    }

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
                self.storage_pass(now);
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

pub const REMOTE_SWEEP_INTERVAL: Duration = Duration::from_secs(10 * 60);

pub const OFFER_WINDOW_MS: i64 = 10 * 60 * 1000;

impl Inner {
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

    fn holds(&self, worker: WorkerId, attempt: AttemptId) -> bool {
        self.store
            .read(|c| dispatch::is_held(c, worker, attempt))
            .unwrap_or(false)
    }

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

    fn log_has_end(&self, worker: WorkerId, attempt: AttemptId) -> bool {
        match self.log_scope(worker, attempt) {
            Ok(Some((run, job))) => self.logs.has_end(run, job, attempt),
            _ => false,
        }
    }

    fn released(&self, worker: WorkerId, attempt: AttemptId) {
        self.logs.forget(attempt);
        if let Some(peer) = self.peer(worker) {
            peer.logging
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .remove(&attempt);
        }
    }

    /// Only a transient failure is kept: the worker sent its verdict once, so dropping it would lose the outcome.
    fn receive(&self, worker: WorkerId, attempt: AttemptId, fence: Fence, what: Deferred) {
        let message = DeferredMessage {
            id: self.next_deferred.fetch_add(1, Ordering::Relaxed),
            worker,
            attempt,
            fence,
            what,
            since: Instant::now(),
        };
        match receive_with(&self.deferred, &message, |m| self.apply(m)) {
            Received::Applied | Received::Copy => {}
            Received::Queued { kept } => self.counted(kept),
            Received::Transient { error, kept } => {
                self.failed(false, "worker_message", &error);
                self.counted(kept);
            }
            Received::Stale => self.stale(&message, false),
        }
    }

    fn apply(&self, m: &DeferredMessage) -> sentinel_store::Result<()> {
        let (worker, attempt, fence) = (m.worker, m.attempt, m.fence);
        match &m.what {
            Deferred::Ack => {
                self.write_store(move |tx| {
                    dispatch::acknowledge(tx, worker, attempt, fence, UnixMillis::steady())
                })?;
                self.stats.acknowledged.fetch_add(1, Ordering::Relaxed);
            }
            Deferred::Report { event, summary } => {
                let event = *event;
                let summary = summary.clone();
                let ended = matches!(event, Event::Passed | Event::Failed(_))
                    && self.log_has_end(worker, attempt);
                let state = self.write_store(move |tx| {
                    let state = dispatch::report(
                        tx,
                        worker,
                        attempt,
                        fence,
                        event,
                        summary.as_deref().map(Vec::as_slice),
                        UnixMillis::steady(),
                        None,
                    )?;
                    if ended && state.is_terminal() {
                        dispatch::log_ended(tx, attempt)?;
                    }
                    Ok(state)
                })?;
                self.stats.reports.fetch_add(1, Ordering::Relaxed);
                if state.is_terminal() {
                    self.released(worker, attempt);
                    self.wake();
                }
            }
        }
        Ok(())
    }

    fn stale(&self, m: &DeferredMessage, retried: bool) {
        if matches!(m.what, Deferred::Report { .. }) {
            self.stats.stale_reports.fetch_add(1, Ordering::Relaxed);
            if retried {
                self.released(m.worker, m.attempt);
                self.wake();
            }
        }
    }

    fn counted(&self, kept: bool) {
        let counter = if kept {
            &self.stats.deferred_worker_messages
        } else {
            &self.stats.deferred_dropped
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    fn retry_deferred(&self) {
        retry_with(
            &self.deferred,
            DEFERRED_MAX_AGE,
            |m| self.apply(m),
            |message, retried| match retried {
                Retried::Applied => {}
                Retried::Aged => {
                    self.stats.deferred_dropped.fetch_add(1, Ordering::Relaxed);
                }
                Retried::Stale => self.stale(message, true),
                Retried::Transient(e) => self.failed(false, "worker_message", e),
            },
        );
    }

    fn deferred_attempts(&self) -> HashSet<AttemptId> {
        self.deferred
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .attempts()
    }

    fn record_artifact(
        &self,
        f: &InFlight,
        attempt: AttemptId,
        state: artifacts::State,
        manifest_version: Option<u64>,
    ) {
        let (tenant, run, job) = (f.tenant, f.run, f.job);
        let name = f.name.clone();
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

    fn publication(&self, attempt: AttemptId) -> Option<Publication> {
        self.artifacts
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .in_flight
            .get(&attempt)
            .cloned()
    }

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
        f.file = None;
        self.discard(std::mem::take(&mut f.done));
        code
    }

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

fn spec_backoff(try_no: u32, attempt: AttemptId) -> Duration {
    let base = 100u64 << try_no.min(4);
    let quarter = base / 4;
    let noise = u64::from(attempt.as_bytes()[15] ^ attempt.as_bytes()[7]);
    Duration::from_millis(base - quarter + noise % (2 * quarter + 1))
}

impl Inner {
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

    fn spec_gate(&self, request: &SpecRequest) -> Option<dispatch::SpecGate> {
        let (worker, attempt) = (request.worker, request.attempt);
        let started = Instant::now();
        let mut pause = Duration::from_millis(2);
        let mut faults = 0;
        loop {
            match self.store.read(|c| dispatch::spec_gate(c, worker, attempt)) {
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

    fn settle_canceled(&self, request: &SpecRequest, fence: Fence) {
        let (worker, attempt) = (request.worker, request.attempt);
        if self
            .write(move |tx| dispatch::decline(tx, worker, attempt, fence, UnixMillis::steady()))
            .is_ok()
        {
            self.stats.handed_back.fetch_add(1, Ordering::Relaxed);
            self.wake();
            Self::no_spec(request);
        }
    }

    fn refuse_secrets(&self, request: &SpecRequest) {
        let (worker, attempt) = (request.worker, request.attempt);
        let settled = self.write(move |tx| {
            let now = UnixMillis::steady();
            let Some(refusal) = sentinel_store::secrets::refuse_delivery(tx, worker, attempt)?
            else {
                return Ok(None);
            };
            let summary = sentinel_protocol::summary::AttemptSummary {
                detail: refusal.detail,
                ..Default::default()
            };
            let bytes = summary
                .encode()
                .map_err(|_| sentinel_store::Error::InvalidInput("attempt summary"))?;
            dispatch::report(
                tx,
                worker,
                attempt,
                refusal.fence,
                Event::Failed(sentinel_core::FailureClass::Preparation),
                Some(&bytes),
                now,
                None,
            )
            .map(Some)
        });
        if let Ok(Some(state)) = settled {
            self.stats.reports.fetch_add(1, Ordering::Relaxed);
            if state.is_terminal() {
                self.released(worker, attempt);
                self.wake();
            }
        }
    }

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
                key.clone(),
                app.as_ref(),
                &destinations,
                worker,
                attempt,
                request.protocol,
            ) {
                Ok(spec) => {
                    let _ = send_resolved(&request.sender, attempt, request.protocol, Some(spec));
                    return;
                }
                Err(SpecFault::Refused) => {
                    match self.spec_gate(request) {
                        Some(dispatch::SpecGate::Canceled(fence)) => {
                            self.settle_canceled(request, fence);
                        }
                        None => {}
                        Some(_) => {
                            self.refuse_secrets(request);
                            Self::no_spec(request);
                        }
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
        self.admit_from(None, fingerprint, worker, name, hello, enrollment, capacity)
    }

    #[allow(clippy::too_many_arguments)]
    fn admit_from(
        &self,
        source: Option<IpAddr>,
        fingerprint: &Digest,
        worker: WorkerId,
        name: &str,
        hello: &Hello,
        enrollment: Option<&Secret>,
        capacity: Capacity,
    ) -> std::result::Result<Admitted, Rejection> {
        let negotiated = sentinel_protocol::negotiate::negotiate(hello).map_err(Rejection::from)?;
        let deferred = negotiated.protocol.0 >= PROFILE_MIN.0;
        let capacity = dispatch::Capacity {
            cpu_millis: i64::try_from(capacity.cpu_millis).map_err(|_| Rejection::Capacity)?,
            memory_bytes: i64::try_from(capacity.memory_bytes).map_err(|_| Rejection::Capacity)?,
            disk_bytes: 0,
        };
        match self.store.read(|c| workers::authenticate(c, fingerprint)) {
            Ok(known) => {
                // A certificate belongs to one worker. A hello that carries it under another worker
                // identifier is a copy of the identity (or a confused host), not a reconnect.
                if known.id != worker || known.negotiated.arch != negotiated.arch {
                    return Err(Rejection::Identity);
                }
                let id = known.id;
                let renegotiated = (known.negotiated != negotiated).then_some(negotiated);
                let immediate = (!deferred).then_some(capacity);
                let software = workers::software_label(&hello.software)
                    .filter(|s| known.software.as_deref() != Some(s.as_str()));
                if renegotiated.is_some() || immediate.is_some() || software.is_some() {
                    self.write(move |tx| {
                        if let Some(negotiated) = renegotiated {
                            workers::renegotiate(tx, id, negotiated)?;
                        }
                        if let Some(capacity) = immediate {
                            dispatch::report_capacity(tx, id, capacity)?;
                        }
                        if let Some(software) = &software {
                            workers::record_software(tx, id, software)?;
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
            Err(sentinel_store::Error::NotFound) => {
                // A revoked identity is told so, with or without a new enrollment: a fresh secret
                // never revives a certificate the controller has revoked.
                match self
                    .store
                    .read(|c| workers::revoked_fingerprint(c, fingerprint))
                {
                    Ok(false) => {}
                    Ok(true) => {
                        self.stats.revoked_refused.fetch_add(1, Ordering::Relaxed);
                        return Err(Rejection::Revoked);
                    }
                    Err(_) => return Err(Rejection::Unavailable),
                }
            }
            Err(_) => return Err(Rejection::Unavailable),
        }
        // Behind a Tailcat helper every peer is loopback, so the address cannot say who is asking; the
        // identity can, and an unknown one does not get the reserved part of the pool.
        if source.is_some_and(admission::is_loopback)
            && !self
                .pending
                .stranger_room(self.max_pending.load(Ordering::Relaxed))
        {
            self.stats.shed.fetch_add(1, Ordering::Relaxed);
            return Err(Rejection::Unavailable);
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
        // A secret that would redeem is never charged to the guessing budget, so a peer that burns the
        // budget (or the audit allowance) cannot keep the real machine from enrolling.
        let redeemable = self
            .store
            .read(|c| workers::redeemable(c, &secret, UnixMillis::now()))
            .map_err(|_| Rejection::Unavailable)?;
        if !redeemable
            && let Some(source) = source
            && !self.enrollments.allow(source, Instant::now())
        {
            self.stats
                .enrollment_limited
                .fetch_add(1, Ordering::Relaxed);
            return Err(Rejection::Unavailable);
        }
        let peer = source.map_or(workers::UNATTRIBUTED, admission::peer_key);
        let immediate_capacity = (!deferred).then_some(capacity);
        let enrolled_software = workers::software_label(&hello.software);
        self.store
            .writer()
            .write(move |tx| {
                let Some(enrolled) = workers::redeem_authorized_from(
                    tx,
                    &secret,
                    workers::Presentation {
                        worker,
                        fingerprint,
                        name: &name,
                        negotiated,
                    },
                    UnixMillis::now(),
                    peer,
                )?
                else {
                    return Ok(None);
                };
                if let Some(capacity) = immediate_capacity {
                    dispatch::report_capacity(tx, enrolled.id, capacity)?;
                }
                if let Some(software) = &enrolled_software {
                    workers::record_software(tx, enrolled.id, software)?;
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
                self.specs.not_started();
            }
        }
        true
    }
    fn ping(&self, worker: WorkerId, held: &[AttemptId]) -> Result<Beat> {
        let now = UnixMillis::steady();
        let wall = UnixMillis::now();
        let peer = self
            .fleet
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&worker)
            .cloned();
        let record_seen = peer.as_ref().is_some_and(|p| {
            let last = p.seen_recorded_ms.load(Ordering::Relaxed);
            wall.0.saturating_sub(last) >= workers::SEEN_RECORD_INTERVAL_MS
        });
        if held.is_empty() && !record_seen {
            return Ok(Beat {
                lease_until: UnixMillis(now.0 + dispatch::DEFAULT_LEASE_MS),
                stop: Vec::new(),
                cancel: Vec::new(),
            });
        }
        let held = held.to_vec();
        let wanted = held.clone();
        let (lease_until, mut stop) = self.write(move |tx| {
            if record_seen {
                workers::seen(tx, worker, wall)?;
            }
            dispatch::renew(tx, worker, &held, dispatch::DEFAULT_LEASE_MS, now)
        })?;
        let deferred = self.deferred_attempts();
        shield_stop(&mut stop, &deferred);
        if record_seen && let Some(peer) = peer {
            peer.seen_recorded_ms.store(wall.0, Ordering::Relaxed);
        }
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
        self.receive(worker, attempt, fence, Deferred::Ack);
    }

    fn reported(
        &self,
        worker: WorkerId,
        attempt: AttemptId,
        fence: Fence,
        event: Event,
        summary: Option<Vec<u8>>,
    ) {
        self.receive(
            worker,
            attempt,
            fence,
            Deferred::Report {
                event,
                summary: summary.map(Arc::new),
            },
        );
    }

    fn abandoned(&self, worker: WorkerId, attempt: AttemptId, fence: Fence) {
        let ended = self.log_has_end(worker, attempt);
        let settled = self.write(move |tx| {
            let state = dispatch::abandon(tx, worker, attempt, fence, UnixMillis::steady(), None)?;
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

    fn spec(&self, _worker: WorkerId, _attempt: AttemptId) -> Option<(JobContext, Vec<u8>)> {
        None
    }

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
            // The store scopes the stated machine by architecture when it records it; the placement key
            // must be the same value, so it is scoped here too.
            *peer.host.lock().unwrap_or_else(|p| p.into_inner()) =
                host_id.map(|h| dispatch::scope_host(&h, peer.arch.as_str()));
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
        self.wake();
        Ok(())
    }

    fn transport(&self, worker: WorkerId, stats: &TransportStats) {
        if let Some(peer) = self.peer(worker) {
            *peer.transport.lock().unwrap_or_else(|p| p.into_inner()) = Some(stats.clone());
        }
    }

    fn cache_need(&self, worker: WorkerId, need: &Need) -> Option<std::path::PathBuf> {
        self.cache_authorize(
            worker,
            need.attempt,
            (need.tenant, need.repo, need.trust),
            None,
        )
    }

    fn cache_offer(&self, worker: WorkerId, upload: &Upload) -> Option<std::path::PathBuf> {
        let since = UnixMillis(UnixMillis::steady().0 - OFFER_WINDOW_MS);
        self.cache_authorize(
            worker,
            upload.attempt,
            (upload.tenant, upload.repo, upload.trust),
            Some(since),
        )
    }

    fn log(&self, worker: WorkerId, attempt: AttemptId, frame: Frame) -> LogVerdict {
        let (run, job) = match self.log_scope(worker, attempt) {
            Ok(Some(scope)) => scope,
            Ok(None) => {
                self.stats.log_refused.fetch_add(1, Ordering::Relaxed);
                return LogVerdict::Refused;
            }
            Err(()) => return LogVerdict::Retry,
        };
        match self.logs.append_deferred(run, job, attempt, &frame) {
            Ok(sentinel_store::logs::Appended::Stored { through }) => {
                self.stats.log_frames.fetch_add(1, Ordering::Relaxed);
                LogVerdict::Stored(through)
            }
            Ok(sentinel_store::logs::Appended::Duplicate { through }) => {
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

    fn log_sync(&self, _worker: WorkerId, attempt: AttemptId) -> bool {
        self.logs.sync(attempt).is_ok()
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
            Err(sentinel_store::Error::Conflict | sentinel_store::Error::InvalidInput(_)) => {
                self.stats.log_refused.fetch_add(1, Ordering::Relaxed);
                LogVerdict::Refused
            }
            Err(_) => LogVerdict::Retry,
        }
    }

    fn declined(&self, worker: WorkerId, attempt: AttemptId, fence: Fence) {
        if let Ok(state) = self
            .write(move |tx| dispatch::decline(tx, worker, attempt, fence, UnixMillis::steady()))
        {
            self.stats.lapsed.fetch_add(1, Ordering::Relaxed);
            self.stats.handed_back.fetch_add(1, Ordering::Relaxed);
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
        let deployment = self.objects.deployment();
        let scope = self.store.read(|c| {
            let tx = c.unchecked_transaction()?;
            let (tenant, run, job, index) = dispatch::attempt_scope(&tx, worker, attempt)?;
            let spec = dispatch::spec_bytes(&tx, worker, attempt)?;
            let duplicate = artifacts::exists(&tx, attempt, name)?;
            let committed = artifacts::run_bytes(&tx, tenant, run)?;
            let repo_full = matches!(
                retention::check_run_repo(&tx, &deployment, tenant, run, 1),
                Err(sentinel_store::Error::QuotaExceeded)
            );
            Ok((
                tenant, run, job, index, spec, duplicate, committed, repo_full,
            ))
        });
        let Ok((tenant, run, job, index, spec, duplicate, committed, repo_full)) = scope else {
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
            return Verdict(ArtifactCode::Invalid);
        }
        if committed.saturating_add(*state.runs.get(&run).unwrap_or(&0))
            >= deployment.run_artifact_bytes
            || repo_full
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
        let committed = self
            .store
            .read(|c| artifacts::run_bytes(c, f.tenant, f.run))
            .unwrap_or(u64::MAX);
        let fits = f.accounted.saturating_add(len) <= MAX_ARTIFACT_BYTES
            && self
                .objects
                .admission()
                .is_none_or(|a| a.check(len).is_ok())
            && {
                let mut state = self.artifacts.lock().unwrap_or_else(|p| p.into_inner());
                let charged = state.runs.entry(f.run).or_default();
                let fits = committed.saturating_add(*charged).saturating_add(len)
                    <= self.objects.deployment().run_artifact_bytes;
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
        // One transaction: a crash mid-commit leaves only adoptable orphans; the stages stay pinned until it ends.
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SpecFault {
    Refused,
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
    key: Option<Arc<sentinel_auth::sealed::Key>>,
    app: Option<&Arc<sentinel_github::app::App>>,
    destinations: &[String],
    worker: WorkerId,
    attempt: AttemptId,
    protocol: u16,
) -> std::result::Result<
    (
        JobContext,
        Vec<u8>,
        Option<sentinel_store::secrets::PreparedDelivery>,
    ),
    SpecFault,
> {
    use sentinel_store::{Error as StoreError, secrets, sources};
    let (mut context, bytes, binding, requires_secret_delivery) = store.read(|conn| {
        let tx = conn.unchecked_transaction()?;
        let c = dispatch::job_context(&tx, worker, attempt)?;
        let bytes = dispatch::spec_bytes(&tx, worker, attempt)?;
        let context = JobContext {
            source: None,
            source_valid_until: None,
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
        let spec = sentinel_pipeline::RunSpec::decode(&bytes)
            .map_err(|_| StoreError::Corrupt("run spec"))?;
        let job_spec = spec
            .pipeline
            .jobs
            .iter()
            .find(|job| job.name == context.job_name)
            .ok_or(StoreError::Corrupt("job spec index"))?;
        let requires_secret_delivery = job_spec.spec.requires_secret_delivery();
        let binding = match sentinel_intake::source::lookup_conn(&tx, context.repo)? {
            None => None,
            Some(binding) => {
                let authority = sentinel_protocol::source::remote(&binding.metadata.binding.remote)
                    .ok_or(StoreError::Forbidden)?;
                if !destinations.iter().any(|d| d == authority) {
                    return Err(StoreError::Forbidden);
                }
                let now = UnixMillis::steady();
                let (tenant, repo) = sources::attempt_repo(&tx, worker, attempt, now)?;
                if (tenant, repo) != (binding.tenant, binding.repo) {
                    return Err(StoreError::Forbidden);
                }
                sources::validate_source(&tx, repo, &spec.source)?;
                Some(binding)
            }
        };
        Ok((context, bytes, binding, requires_secret_delivery))
    })?;
    if let Some(binding) = binding {
        let access =
            sentinel_intake::source::issue(store, key.as_deref(), app, &binding, UnixMillis::now())
                .map_err(|e| match e {
                    sentinel_intake::source::Error::Unavailable(_) => SpecFault::Transient,
                    sentinel_intake::source::Error::Refused(_) => SpecFault::Refused,
                })?;
        let (tenant, repo) = (binding.tenant, binding.repo);
        store.read(move |conn| {
            if sources::attempt_repo(conn, worker, attempt, UnixMillis::steady())? != (tenant, repo)
            {
                return Err(StoreError::Forbidden);
            }
            Ok(())
        })?;
        context.source = Some(access);
    }
    let prepared = if requires_secret_delivery {
        if protocol < 10 {
            return Err(SpecFault::Refused);
        }
        let Some(key) = key else {
            return Err(SpecFault::Refused);
        };
        Some(
            secrets::deliver(store, key, worker, attempt, UnixMillis::now())
                .map_err(SpecFault::from)?,
        )
    } else {
        None
    };
    Ok((context, bytes, prepared))
}

fn send_resolved(
    sender: &Sender,
    attempt: AttemptId,
    protocol: u16,
    spec: Option<(
        JobContext,
        Vec<u8>,
        Option<sentinel_store::secrets::PreparedDelivery>,
    )>,
) -> Result<()> {
    use session::ServerMessage;
    let Some((context, bytes, delivery)) = spec.filter(|(_, b, delivery)| {
        protocol >= 3
            && b.len() <= session::MAX_SPEC_BYTES
            && (delivery.is_none() || protocol >= 10)
    }) else {
        return sender.send(&ServerMessage::NoSpec {
            attempt: *attempt.as_bytes(),
        });
    };
    sender.send(&session::context_message(protocol, &context, attempt))?;
    if let Some(access) = context.source {
        sender.send(&ServerMessage::Source {
            attempt: *attempt.as_bytes(),
            access,
        })?;
    }
    if let Some(prepared) = delivery {
        use sentinel_protocol::secrets::{MAX_DELIVERY_BYTES, SecretBytes};
        let fence = prepared.fence;
        let payload = prepared.encoded;
        if payload.is_empty() || payload.len() > MAX_DELIVERY_BYTES {
            return sender.send(&ServerMessage::NoSpec {
                attempt: *attempt.as_bytes(),
            });
        }
        let length =
            u32::try_from(payload.len()).map_err(|_| Error::Protocol("secret bundle length"))?;
        sender.send(&ServerMessage::SecretBegin {
            attempt: *attempt.as_bytes(),
            fence: fence.0,
            length,
        })?;
        let chunks = payload.as_slice().chunks(session::SPEC_CHUNK_BYTES);
        let count = chunks.len();
        for (seq, chunk) in chunks.enumerate() {
            sender.send_sensitive(&ServerMessage::SecretChunk {
                attempt: *attempt.as_bytes(),
                fence: fence.0,
                seq: seq as u32,
                last: seq + 1 == count,
                bytes: SecretBytes::copy_from(chunk),
            })?;
        }
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
    pub fn set_admission_limits(&self, pending: usize, handshake: Duration) {
        self.inner
            .max_pending
            .store(pending.max(1), Ordering::Relaxed);
        self.inner.handshake_ms.store(
            handshake.as_millis().clamp(1, u64::MAX as u128) as u64,
            Ordering::Relaxed,
        );
    }

    pub fn set_storage_policy(&self, policy: StoragePolicy) {
        *self.inner.storage.lock().unwrap_or_else(|p| p.into_inner()) = Some(policy);
    }

    /// Choose how free workers are ordered (default [`PlacementOrder::Fastest`]). Takes effect on the
    /// next placement pass.
    pub fn set_placement_order(&self, order: PlacementOrder) {
        self.inner.order.store(order as u8, Ordering::Relaxed);
    }

    pub fn set_remote_cache_budget(&self, bytes: u64) {
        self.inner.remote_budget.store(bytes, Ordering::Relaxed);
    }

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
                            inner.remote_budget.load(Ordering::Relaxed),
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
    pub fn start(
        store: Arc<Store>,
        logs: Arc<LogStore>,
        objects: Arc<Objects>,
        identity: Identity,
        listen: SocketAddr,
    ) -> Result<Controller> {
        let session_cap = admission::session_cap(MAX_SESSIONS)?;
        if session_cap < MAX_SESSIONS {
            tracing::warn!(
                event = "session_cap_lowered",
                cap = session_cap,
                wanted = MAX_SESSIONS,
                needed = descriptors_needed(MAX_SESSIONS),
                "the open-files limit holds fewer worker sessions than the controller allows"
            );
        }
        let fingerprint = identity.fingerprint();
        let config = tls::server_config(identity)?;
        let reconcile_logs = Arc::clone(&logs);
        let reconciled = store
            .writer()
            .write(move |tx| {
                dispatch::reconcile_startup(tx, UnixMillis::steady(), Some(&reconcile_logs))
            })
            .map_err(|_| Error::Internal("startup reconciliation"))?;
        let listener = TcpListener::bind(listen)?;
        let addr = listener.local_addr()?;
        let pending = admission::Pending::default();
        let wall = UnixMillis::now().0;
        // A failed read leaves every source a stranger until it connects, as before a restart was survivable.
        if let Ok(known) = store.read(|c| {
            sentinel_store::known_sources::load(c, wall, admission::KNOWN_TTL.as_millis() as i64)
        }) {
            pending.restore(
                known.into_iter().map(|(source, seen_ms)| {
                    (
                        source,
                        Duration::from_millis(
                            u64::try_from(wall.saturating_sub(seen_ms)).unwrap_or(0),
                        ),
                    )
                }),
                Instant::now(),
            );
        }
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
            remote_budget: AtomicU64::new(sentinel_cache::remote::STORE_BUDGET_BYTES),
            order: AtomicU8::new(PlacementOrder::Fastest as u8),
            last_storage: AtomicI64::new(0),
            maintenance: (Mutex::new(false), Condvar::new()),
            remote_cache: Mutex::new(None),
            config,
            fleet: Mutex::new(HashMap::new()),
            generation: AtomicU64::new(1),
            wake: (Mutex::new(false), Condvar::new()),
            stop: AtomicBool::new(false),
            sessions: AtomicUsize::new(0),
            session_cap,
            pending,
            enrollments: admission::Enrollments::new(Instant::now()),
            arrivals: Mutex::new(Vec::new()),
            arrived: AtomicU64::new(0),
            max_pending: AtomicUsize::new(MAX_PENDING),
            handshake_ms: AtomicU64::new(session::HANDSHAKE_DEADLINE.as_millis() as u64),
            stats: Stats::default(),
            revocations: Mutex::new((-1, -1)),
            warned: [AtomicI64::new(i64::MIN), AtomicI64::new(i64::MIN)],
            prefetch_at: Mutex::new(None),
            cancel_hint: AtomicBool::new(false),
            deferred: Mutex::new(DeferredQueue::default()),
            next_deferred: AtomicU64::new(0),
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

    pub fn reconciled(&self) -> dispatch::Reconciled {
        self.reconciled
    }

    /// The most worker sessions admitted at once, as the open-files limit allows.
    pub fn session_cap(&self) -> usize {
        self.inner.session_cap
    }

    pub fn handle(&self) -> Handle {
        Handle(Arc::clone(&self.inner))
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    /// Network sources remembered as having authenticated a worker (restored from the store at start).
    pub fn known_sources(&self) -> usize {
        self.inner.pending.known()
    }

    pub fn fingerprint(&self) -> Digest {
        self.fingerprint
    }

    pub fn wake(&self) {
        self.inner.wake();
    }

    /// A cancel committed: push it to the workers holding its attempts on this wake, not their next beat.
    pub fn cancel_hint(&self) {
        self.inner.cancel_hint.store(true, Ordering::Release);
        self.inner.wake();
    }

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

    pub fn shutdown(mut self, timeout: Duration) -> bool {
        self.inner.stop.store(true, Ordering::Release);
        self.inner.wake();
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
    let mut failures = 0u32;
    loop {
        let accepted = listener.accept();
        if inner.stop.load(Ordering::Acquire) {
            return;
        }
        let (socket, addr) = match accepted {
            Ok(accepted) => {
                failures = 0;
                accepted
            }
            Err(error) => {
                if !admission::accept_error_is_peer_local(&error) {
                    thread::sleep(admission::accept_backoff(failures));
                    failures = failures.saturating_add(1);
                }
                continue;
            }
        };
        let ip = canonical(addr).ip();
        if inner.sessions.load(Ordering::Acquire) >= inner.session_cap
            || !inner.pending.enter(
                ip,
                inner.max_pending.load(Ordering::Relaxed),
                Instant::now(),
            )
        {
            inner.stats.shed.fetch_add(1, Ordering::Relaxed);
            drop(socket);
            continue;
        }
        inner.sessions.fetch_add(1, Ordering::AcqRel);
        let session = Arc::clone(inner);
        let spawned = thread::Builder::new()
            .name("sentinel-link-session".into())
            .spawn(move || {
                session.serve(socket, addr);
                session.sessions.fetch_sub(1, Ordering::AcqRel);
            });
        if spawned.is_err() {
            inner.pending.leave(ip);
            inner.sessions.fetch_sub(1, Ordering::AcqRel);
        }
    }
}

#[derive(Clone)]
pub struct Handle(Arc<Inner>);

impl Handle {
    pub fn wake(&self) {
        self.0.wake();
    }

    /// Puts a GitHub App in force for source resolution without a restart.
    pub fn set_source_app(&self, app: Arc<sentinel_github::app::App>) {
        *self.0.source_app.lock().unwrap_or_else(|p| p.into_inner()) = Some(app);
    }

    pub fn cancel_hint(&self) {
        self.0.cancel_hint.store(true, Ordering::Release);
        self.0.wake();
    }

    pub fn stats(&self) -> &Stats {
        &self.0.stats
    }

    /// The configured order of the free workers.
    pub fn placement_order(&self) -> PlacementOrder {
        self.0.placement_order()
    }

    /// The free workers in the order the next placement round uses, each with its approved priority,
    /// its expected finish and the first factor that puts it ahead of the next. It answers "why this
    /// host before that one"; whether a worker may take a given job is hard admission, explained per
    /// job by the queue's wait reasons.
    pub fn placement_ranking(&self) -> Vec<Ranked> {
        self.0.placement_ranking()
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

    /// Closes the carried sessions cleanly rather than cutting them: a killed helper leaves workers to notice after about 20 s.
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

    fn close_carried(&self, from: &[SocketAddr], closed: &mut Vec<Closed>) {
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

struct Closed {
    worker: WorkerId,
    generation: u64,
    answers: bool,
}

/// Kept below the shortest worker reconnect back-off, so no worker redials into the old helper first.
pub const HANDOFF_BOUND: Duration = Duration::from_millis(600);
pub const HANDOFF_RESEND_BOUND: Duration = Duration::from_millis(3_000);
pub const HANDOFF_SETTLE: Duration = Duration::from_millis(100);
const HANDOFF_POLL: Duration = Duration::from_millis(5);

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Handoff {
    pub tunnelled: usize,
    pub closed: usize,
    pub arrivals: usize,
    pub ended: usize,
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
        assert_eq!(reach.elsewhere(3, pool), Some(size(5_000, 8, i64::MAX)));
        assert_eq!(reach.elsewhere(0, pool), Some(size(7_000, 16, i64::MAX)));
        assert_eq!(reach.elsewhere(1, pool), Some(size(7_000, 16, 256)));
        assert_eq!(reach.elsewhere(2, other), None);
    }

    fn message(id: u64, attempt: AttemptId, what: Deferred) -> DeferredMessage {
        DeferredMessage {
            id,
            worker: WorkerId::new(),
            attempt,
            fence: Fence(1),
            what,
            since: Instant::now(),
        }
    }

    fn report() -> Deferred {
        Deferred::Report {
            event: Event::Passed,
            summary: None,
        }
    }

    #[test]
    fn deferred_messages_keep_their_order_protect_their_attempt_and_are_bounded() {
        let (a, b) = (AttemptId::new(), AttemptId::new());
        let mut queue = DeferredQueue::default();
        assert!(queue.push(message(1, a, Deferred::Ack)));
        assert!(queue.holds(a) && !queue.holds(b));
        assert_eq!(queue.attempts(), HashSet::from([a]));
        assert!(queue.push(message(2, a, report())));
        assert!(queue.push(message(3, b, report())));
        assert_eq!(queue.attempts(), HashSet::from([a, b]));
        assert_eq!(queue.head().map(|m| m.id), Some(1));
        queue.settle(2);
        assert_eq!(queue.head().map(|m| m.id), Some(1));
        queue.settle(1);
        assert_eq!(queue.head().map(|m| m.id), Some(2));
        queue.settle(2);
        queue.settle(3);
        assert!(queue.head().is_none() && !queue.holds(a));
        for id in 0..MAX_DEFERRED as u64 {
            assert!(queue.push(message(id, AttemptId::new(), report())));
        }
        assert!(!queue.push(message(u64::MAX, a, report())));
    }

    use sentinel_store::Error as StoreError;

    fn queue() -> Mutex<DeferredQueue> {
        Mutex::new(DeferredQueue::default())
    }

    fn ids(queue: &Mutex<DeferredQueue>) -> Vec<u64> {
        let q = queue.lock().unwrap();
        q.items.iter().map(|m| m.id).collect()
    }

    #[test]
    fn a_transient_store_error_keeps_the_message_and_a_stale_one_drops_it() {
        let errors: [fn() -> StoreError; 3] = [
            || StoreError::WriterUnavailable,
            || StoreError::WriteAmbiguous,
            || StoreError::Overloaded,
        ];
        for error in errors {
            let q = queue();
            let m = message(1, AttemptId::new(), report());
            let got = receive_with(&q, &m, |_| Err(error()));
            assert!(
                matches!(got, Received::Transient { kept: true, .. }),
                "{:?} is kept",
                error()
            );
            assert_eq!(ids(&q), vec![1]);
        }
        let q = queue();
        let got = receive_with(&q, &message(1, AttemptId::new(), report()), |_| {
            Err(StoreError::InvalidInput("stale"))
        });
        assert!(matches!(got, Received::Stale));
        assert!(ids(&q).is_empty(), "a stale message is not kept");
    }

    #[test]
    fn a_refused_report_is_retried_once_and_shields_its_attempt_until_then() {
        let q = queue();
        let (a, other) = (AttemptId::new(), AttemptId::new());
        let m = message(1, a, report());
        let got = receive_with(&q, &m, |_| Err(StoreError::WriterUnavailable));
        assert!(matches!(got, Received::Transient { kept: true, .. }));
        let due = |attempts: &[AttemptId]| -> Vec<(AttemptId, RunId, JobId)> {
            attempts
                .iter()
                .map(|&a| (a, RunId::new(), JobId::new()))
                .collect()
        };
        let mut sweep = due(&[a, other]);
        shield(&mut sweep, &q.lock().unwrap().attempts());
        assert_eq!(
            sweep.iter().map(|d| d.0).collect::<Vec<_>>(),
            vec![other],
            "only the attempt with a waiting verdict is shielded"
        );
        let got = receive_with(&q, &message(2, a, report()), |_| {
            panic!("a copy must not reach the store")
        });
        assert!(matches!(got, Received::Copy));
        assert_eq!(ids(&q), vec![1]);
        let applied = std::cell::RefCell::new(Vec::new());
        let seen = std::cell::RefCell::new(0);
        retry_with(
            &q,
            DEFERRED_MAX_AGE,
            |m| {
                applied.borrow_mut().push(m.id);
                Ok(())
            },
            |_, r| {
                assert!(matches!(r, Retried::Applied));
                *seen.borrow_mut() += 1;
            },
        );
        assert_eq!(*applied.borrow(), vec![1]);
        assert_eq!(*seen.borrow(), 1);
        assert!(ids(&q).is_empty());
        let mut sweep = due(&[a]);
        shield(&mut sweep, &q.lock().unwrap().attempts());
        assert_eq!(sweep.len(), 1, "settled: the lease owns it again");
    }

    #[test]
    fn retries_keep_arrival_order_and_stop_at_a_store_that_is_still_down() {
        let q = queue();
        let a = AttemptId::new();
        let got = receive_with(&q, &message(1, a, Deferred::Ack), |_| {
            Err(StoreError::WriteAmbiguous)
        });
        assert!(matches!(got, Received::Transient { kept: true, .. }));
        let got = receive_with(&q, &message(2, a, report()), |_| {
            panic!("a report must wait for the acknowledgement before it")
        });
        assert!(matches!(got, Received::Queued { kept: true }));
        assert_eq!(ids(&q), vec![1, 2]);
        let calls = std::cell::RefCell::new(Vec::new());
        let transient = std::cell::RefCell::new(0);
        retry_with(
            &q,
            DEFERRED_MAX_AGE,
            |m| {
                calls.borrow_mut().push(m.id);
                Err(StoreError::Overloaded)
            },
            |_, r| {
                if matches!(r, Retried::Transient(_)) {
                    *transient.borrow_mut() += 1;
                }
            },
        );
        assert_eq!(*calls.borrow(), vec![1]);
        assert_eq!(*transient.borrow(), 1);
        assert_eq!(ids(&q), vec![1, 2]);
        retry_with(
            &q,
            DEFERRED_MAX_AGE,
            |m| {
                calls.borrow_mut().push(m.id);
                Ok(())
            },
            |_, _| {},
        );
        assert_eq!(*calls.borrow(), vec![1, 1, 2]);
        assert!(ids(&q).is_empty());
    }

    #[test]
    fn a_deferred_ack_is_shielded_from_lapse_and_stop_confirmation() {
        let q = queue();
        let (a, other) = (AttemptId::new(), AttemptId::new());
        let got = receive_with(&q, &message(1, a, Deferred::Ack), |_| {
            Err(StoreError::WriterUnavailable)
        });
        assert!(matches!(got, Received::Transient { kept: true, .. }));
        let mut due = vec![
            (a, RunId::new(), JobId::new()),
            (other, RunId::new(), JobId::new()),
        ];
        shield(&mut due, &q.lock().unwrap().attempts());
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].0, other);
        let mut stop = vec![a, other];
        shield_stop(&mut stop, &q.lock().unwrap().attempts());
        assert_eq!(stop, vec![other]);
    }

    #[test]
    fn a_retried_message_that_turns_out_stale_is_settled_as_stale() {
        let q = queue();
        let a = AttemptId::new();
        let _ = receive_with(&q, &message(1, a, report()), |_| {
            Err(StoreError::WriteAmbiguous)
        });
        let outcomes = std::cell::RefCell::new(Vec::new());
        retry_with(
            &q,
            DEFERRED_MAX_AGE,
            |_| Err(StoreError::InvalidInput("stale")),
            |m, r| {
                outcomes
                    .borrow_mut()
                    .push((m.attempt == a, matches!(r, Retried::Stale)))
            },
        );
        assert_eq!(*outcomes.borrow(), vec![(true, true)]);
        assert!(ids(&q).is_empty());
    }

    #[test]
    fn a_message_past_its_retry_window_is_dropped_unapplied() {
        let q = queue();
        let _ = receive_with(&q, &message(1, AttemptId::new(), report()), |_| {
            Err(StoreError::WriterUnavailable)
        });
        let aged = std::cell::RefCell::new(0);
        retry_with(
            &q,
            Duration::ZERO,
            |_| panic!("an aged message must not be applied"),
            |_, r| {
                if matches!(r, Retried::Aged) {
                    *aged.borrow_mut() += 1;
                }
            },
        );
        assert_eq!(*aged.borrow(), 1);
        assert!(ids(&q).is_empty());
    }

    #[test]
    fn a_full_queue_refuses_the_next_transient_message() {
        let q = queue();
        for id in 0..MAX_DEFERRED as u64 {
            let got = receive_with(&q, &message(id, AttemptId::new(), report()), |_| {
                Err(StoreError::WriterUnavailable)
            });
            assert!(matches!(got, Received::Transient { kept: true, .. }));
        }
        let got = receive_with(&q, &message(u64::MAX, AttemptId::new(), report()), |_| {
            Err(StoreError::WriterUnavailable)
        });
        assert!(matches!(got, Received::Transient { kept: false, .. }));
        assert_eq!(ids(&q).len(), MAX_DEFERRED);
    }

    fn standing(cpu_millis: i64, committed_millis: i64, cache_bytes: i64) -> Standing {
        Standing {
            cpu_millis,
            memory_bytes: 8 << 30,
            committed_millis,
            cache_bytes,
        }
    }

    #[test]
    fn measured_load_is_busy_cores_over_the_sampling_window() {
        assert_eq!(busy_millis(0), 0);
        assert_eq!(busy_millis(100_000_000), 1_000);
        assert_eq!(busy_millis(800_000_000), 8_000);
        assert_eq!(busy_millis(-5), 0);
    }

    #[test]
    fn the_sweep_ranks_workers_by_expected_finish() {
        let idle = standing(8_000, 0, 0);
        // A host with spare cores is slowed only by sharing; the idle one finishes first.
        assert!(rank(idle) < rank(standing(8_000, 4_000, 0)));
        // The same absolute commitment hurts the smaller host more.
        assert!(rank(standing(16_000, 8_000, 0)) < rank(standing(8_000, 8_000, 0)));
        // At equal finish the smaller worker goes first, keeping the larger one free.
        assert!(rank(standing(2_500, 0, 0)) < rank(idle));
        let mut bigger_memory = idle;
        bigger_memory.memory_bytes += 1;
        assert!(rank(idle) < rank(bigger_memory));
    }

    #[test]
    fn a_warm_cache_offsets_sharing_but_never_an_oversubscribed_host() {
        let idle = standing(8_000, 0, 0);
        // Warm and half busy still finishes before cold and idle...
        assert!(rank(standing(8_000, 4_000, 4 << 30)) < rank(idle));
        // ...and so does warm and full to the last core, since the job still gets a core of its own...
        assert!(rank(standing(8_000, 7_000, 4 << 30)) < rank(idle));
        // ...but once the job would oversubscribe the host, no amount of cache wins.
        assert!(rank(idle) < rank(standing(8_000, 8_000, 1 << 50)));
        assert!(rank(idle) < rank(standing(8_000, 20_000, 1 << 50)));
        // The credit is bounded by the warm size and saturates.
        assert!(rank(standing(8_000, 0, 1 << 30)) < rank(idle));
        assert!(rank(standing(8_000, 0, 4 << 30)) < rank(standing(8_000, 0, 1 << 30)));
        assert_eq!(
            expected_finish_ns(standing(8_000, 0, 4 << 30)),
            expected_finish_ns(standing(8_000, 0, i64::MAX))
        );
    }

    /// A valid identifier whose order is `n`'s.
    fn wrk(n: u8) -> WorkerId {
        let mut bytes = [0u8; 16];
        bytes[0] = n;
        bytes[6] = 0x40;
        bytes[8] = 0x80;
        WorkerId::from_bytes(bytes).unwrap()
    }

    fn order_of(order: PlacementOrder, entries: &[(WorkerId, i32, Standing)]) -> Vec<WorkerId> {
        ranking(order, entries)
            .into_iter()
            .map(|r| r.worker)
            .collect()
    }

    #[test]
    fn the_default_order_ignores_priority() {
        let idle = standing(8_000, 0, 0);
        let busy = standing(8_000, 4_000, 0);
        let entries = [(wrk(1), 100, busy), (wrk(2), -100, idle)];
        assert_eq!(
            order_of(PlacementOrder::Fastest, &entries),
            vec![wrk(2), wrk(1)],
            "the fastest eligible host goes first however it is ranked by the operator"
        );
        let ranked = ranking(PlacementOrder::Fastest, &entries);
        assert_eq!(ranked[0].ahead_because, Some(OrderFactor::ExpectedFinish));
        assert_eq!(ranked[1].ahead_because, None);
    }

    #[test]
    fn priority_overrides_speed_and_falls_back_to_speed_within_a_priority() {
        let idle = standing(8_000, 0, 0);
        let busy = standing(8_000, 4_000, 0);
        let entries = [
            (wrk(1), 0, idle),
            (wrk(2), 10, busy),
            (wrk(3), 10, idle),
            (wrk(4), -5, idle),
        ];
        let ranked = ranking(PlacementOrder::Priority, &entries);
        assert_eq!(
            ranked.iter().map(|r| r.worker).collect::<Vec<_>>(),
            vec![wrk(3), wrk(2), wrk(1), wrk(4)]
        );
        assert_eq!(
            ranked.iter().map(|r| r.ahead_because).collect::<Vec<_>>(),
            vec![
                Some(OrderFactor::ExpectedFinish),
                Some(OrderFactor::Priority),
                Some(OrderFactor::Priority),
                None
            ],
            "the busy priority-10 host is ahead of the idle neutral one because of priority, not speed"
        );
        assert_eq!(ranked[1].priority, 10);
        assert!(ranked[1].expected_finish_ns > ranked[2].expected_finish_ns);
    }

    #[test]
    fn equal_priority_and_finish_go_to_the_smaller_worker_then_the_identifier() {
        let small = standing(2_500, 0, 0);
        let large = standing(8_000, 0, 0);
        let order = PlacementOrder::Priority;
        // The smaller worker is first among equals, whatever the input order.
        for entries in [
            [(wrk(1), 7, large), (wrk(2), 7, small)],
            [(wrk(2), 7, small), (wrk(1), 7, large)],
        ] {
            let ranked = ranking(order, &entries);
            assert_eq!(ranked[0].worker, wrk(2));
            assert_eq!(ranked[0].ahead_because, Some(OrderFactor::BestFit));
        }
        let twins = [(wrk(9), 7, small), (wrk(3), 7, small)];
        let ranked = ranking(order, &twins);
        assert_eq!(ranked[0].worker, wrk(3));
        assert_eq!(ranked[0].ahead_because, Some(OrderFactor::Identity));
    }

    #[test]
    fn the_priority_bounds_order_without_overflow() {
        let idle = standing(8_000, 0, 0);
        let entries = [
            (wrk(1), -100, idle),
            (wrk(2), 100, idle),
            (wrk(3), i32::MIN, idle),
        ];
        assert_eq!(
            order_of(PlacementOrder::Priority, &entries),
            vec![wrk(2), wrk(1), wrk(3)]
        );
    }

    #[test]
    fn extreme_inputs_rank_without_overflow() {
        let huge = standing(i64::MAX, i64::MAX, i64::MAX);
        let tiny = standing(0, i64::MAX, i64::MIN);
        assert!(expected_finish_ns(huge) > 0);
        assert_eq!(expected_finish_ns(tiny), i64::MAX);
        assert!(rank(huge) < rank(tiny));
    }

    /// The ordering step of one placement round (the sort key of every free worker, then the sort) at
    /// the fleet size of `tests/fleet_sessions.rs`. Ignored because it measures time:
    /// `cargo test --release -p sentinel-link --lib ranking_cost -- --ignored --nocapture`.
    #[test]
    #[ignore = "ordering cost: cargo test --release -p sentinel-link --lib ranking_cost -- --ignored --nocapture"]
    fn ranking_cost_stays_microseconds_for_a_hundred_and_a_thousand_workers() {
        for (workers, bound_us) in [(100usize, 2_000u128), (1_000, 20_000)] {
            let entries: Vec<(WorkerId, i32, Standing)> = (0..workers)
                .map(|i| {
                    let n = i as i64;
                    let key = u32::try_from(i).unwrap().to_be_bytes();
                    let mut bytes = [0u8; 16];
                    bytes[..4].copy_from_slice(&key);
                    bytes[6] = 0x40;
                    bytes[8] = 0x80;
                    (
                        WorkerId::from_bytes(bytes).unwrap(),
                        i32::try_from(i % 7).unwrap() - 3,
                        standing(2_000 + (n % 5) * 2_000, (n % 9) * 500, (n % 4) * (1 << 30)),
                    )
                })
                .collect();
            for order in [PlacementOrder::Fastest, PlacementOrder::Priority] {
                let rounds = 200u32;
                let start = std::time::Instant::now();
                for _ in 0..rounds {
                    std::hint::black_box(ranking(order, std::hint::black_box(&entries)));
                }
                let per_round = start.elapsed() / rounds;
                println!(
                    "ranking_cost workers={workers} order={} per_round_ns={}",
                    order.as_str(),
                    per_round.as_nanos()
                );
                assert!(
                    per_round.as_micros() < bound_us,
                    "ordering {workers} workers took {per_round:?} per round"
                );
            }
        }
    }

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
        assert_eq!(desk.submit(keys[3], 3), Submitted::Start);
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
