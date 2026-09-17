//! Placement, reservations, offers and leases (W02).
//!
//! The ready queue is the `jobs_ready` partial index: a job is queued when its
//! row says so, and nothing in memory has to be rebuilt after a restart. A
//! reservation is the attempt row itself — created with the lease in one
//! transaction, holding the worker's capacity until `released_ms` is set —
//! so capacity can never leak from a forgotten side table. Every mutation is
//! compare-and-set on the attempt's worker and fence: a stale worker's
//! acknowledgement, renewal or report touches zero rows and is told so.
//!
//! Trusted controller operations. Nothing here authorizes a client; the
//! worker's identity was decided by the link before any of this is called.

use std::collections::HashMap;

use rusqlite::{Connection, OptionalExtension, Transaction, params};
use sentinel_core::{
    Actor, AttemptId, DependencyPolicy, Event, FailureClass, Fence, JobId, JobState, Outcome,
    PoolId, RepoId, RunId, TenantId, UnixMillis, WorkerId, dependency_decision,
};
use sentinel_pipeline::schema::ArtifactWhen;
use sentinel_protocol::{limits::MAX_LIST_ITEMS, summary::MAX_SUMMARY_BYTES};

use crate::{
    Error, Result, artifacts,
    codec::{READY, TERMINAL_BASE, decode_state},
    jobs,
    logs::LogStore,
    runs::{self, ResolvedImage},
};

/// How long a lease lasts without renewal. Renewal rides on the heartbeat
/// (every 5 s), so a worker misses several beats before its lease lapses.
pub const DEFAULT_LEASE_MS: i64 = 30_000;
/// How long an offer waits for its acknowledgement before it lapses and the
/// job returns to the queue.
pub const OFFER_ACK_MS: i64 = 5_000;
/// Attempts one worker may hold at once; also the bound on a renewal list.
pub const MAX_HELD_ATTEMPTS: usize = MAX_LIST_ITEMS;
/// How long a job may wait in the queue before it is `QueueTimedOut`.
/// Server policy, not a pipeline setting; finite so nothing waits forever.
pub const QUEUE_TIMEOUT_MS: i64 = 6 * 60 * 60 * 1000;
/// Slack past the job's own timeout before the controller stops trusting
/// the worker to enforce it: the worker's clock is the real deadline, this
/// is the backstop for a worker that renews its lease but never finishes.
pub const EXECUTION_GRACE_MS: i64 = 10 * 60 * 1000;
/// Rows one sweep handles; the next pass takes the rest.
const SWEEP_BATCH: usize = 256;
/// Offers the ack-timeout sweep lapses per pass.
const SWEEP_LIMIT: usize = 256;

/// A job at or above this CPU (millicores) reserves a path: capacity that
/// would leave the worker unable to run a waiting large job is not spent on
/// smaller work while that job waits (Q02).
pub const LARGE_JOB_CPU: i64 = 8_000;
/// The fraction of a host's reported millicpu kept free for pull-request
/// feedback while one of its jobs waits: a quarter (plan §2).
pub const PR_RESERVE_DIVISOR: i64 = 4;
/// How long a job may wait for a worker with its image warm before any
/// eligible worker may take it. Bounded so locality never strands a job.
pub const LOCALITY_WAIT_MS: i64 = 30_000;

/// Whether the attempt's `end` marker was durable when its job went terminal
/// (`attempts.log_state`, migration 26). The codes order the states — the
/// `attempt_update` trigger refuses any regression.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum LogState {
    /// The attempt is live, or its end marker was never seen.
    Pending = 0,
    /// The job reached terminal before a durable end marker: worker loss, a
    /// `LogEnd` acknowledged-but-dropped on an older protocol, or the flush
    /// timeout running out. Reads still report the stored frames and gaps;
    /// a retransmitted end from the owning worker — released or not —
    /// upgrades this.
    Incomplete = 1,
    /// The `end` marker was durable.
    Complete = 2,
}

impl LogState {
    fn code(self) -> i64 {
        self as i64
    }
    pub fn from_code(code: i64) -> Result<LogState> {
        match code {
            0 => Ok(LogState::Pending),
            1 => Ok(LogState::Incomplete),
            2 => Ok(LogState::Complete),
            _ => Err(Error::Corrupt("log_state")),
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            LogState::Pending => "pending",
            LogState::Incomplete => "incomplete",
            LogState::Complete => "complete",
        }
    }
}

/// Resources as the scheduler counts them: CPU in thousandths of a core,
/// bytes of memory and bytes of scratch disk. A zero capacity is a worker
/// that takes no work. `disk_bytes = 0` on a worker additionally means it
/// has never reported disk capacity (migration 28), and disk is then not
/// part of its admission: unreported is not the same as zero.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Capacity {
    pub cpu_millis: i64,
    pub memory_bytes: i64,
    pub disk_bytes: i64,
}

/// Record what a worker has, as it reported at its hello. Replaces the
/// previous report: the measurement is the worker's, made each session.
/// Protocol 6 workers report no disk, and `disk_bytes = 0` records that
/// absence rather than claiming a zero-sized scratch area.
pub fn report_capacity(tx: &Transaction<'_>, worker: WorkerId, capacity: Capacity) -> Result<()> {
    if capacity.cpu_millis < 0 || capacity.memory_bytes < 0 || capacity.disk_bytes < 0 {
        return Err(Error::InvalidInput("capacity"));
    }
    let changed = tx
        .prepare_cached(
            "UPDATE workers SET cpu_millis = ?2, memory_bytes = ?3, disk_bytes = ?4
             WHERE id = ?1 AND revoked_ms IS NULL",
        )?
        .execute(params![
            worker.as_bytes(),
            capacity.cpu_millis,
            capacity.memory_bytes,
            capacity.disk_bytes
        ])?;
    if changed == 0 {
        return Err(Error::NotFound);
    }
    Ok(())
}

/// What the worker has left: its reported capacity less every attempt still
/// held that the host counts. Attempts of every worker sharing the same
/// `host_id` are subtracted — worker identities on one machine must not
/// each claim the whole machine's memory, CPU or scratch — while a worker
/// with no host on record accounts for its own attempts alone. One statement
/// over the held-attempts partial index; values may go negative when a
/// report shrinks under existing reservations.
pub fn free_capacity(conn: &Connection, worker: WorkerId) -> Result<Capacity> {
    conn.prepare_cached(
        "SELECT w.cpu_millis - COALESCE((
                    SELECT SUM(a.cpu_millis) FROM attempts a JOIN workers h ON h.id = a.worker_id
                    WHERE a.released_ms IS NULL
                      AND ((w.host_id IS NOT NULL AND h.host_id = w.host_id)
                           OR (w.host_id IS NULL AND h.id = w.id))), 0),
                w.memory_bytes - COALESCE((
                    SELECT SUM(a.memory_bytes) FROM attempts a JOIN workers h ON h.id = a.worker_id
                    WHERE a.released_ms IS NULL
                      AND ((w.host_id IS NOT NULL AND h.host_id = w.host_id)
                           OR (w.host_id IS NULL AND h.id = w.id))), 0),
                CASE WHEN w.disk_bytes = 0 THEN 0 ELSE w.disk_bytes - COALESCE((
                    SELECT SUM(a.disk_bytes) FROM attempts a JOIN workers h ON h.id = a.worker_id
                    WHERE a.released_ms IS NULL
                      AND ((w.host_id IS NOT NULL AND h.host_id = w.host_id)
                           OR (w.host_id IS NULL AND h.id = w.id))), 0) END
         FROM workers w WHERE w.id = ?1 AND w.revoked_ms IS NULL",
    )?
    .query_row([worker.as_bytes()], |r| {
        Ok(Capacity {
            cpu_millis: r.get(0)?,
            memory_bytes: r.get(1)?,
            disk_bytes: r.get(2)?,
        })
    })
    .optional()?
    .ok_or(Error::NotFound)
}

/// Labels one worker or job may carry (protocol 7 profile bound). The blob
/// is sorted and newline-separated, so equality is one comparison and
/// containment one pass — the format is private to placement.
pub const MAX_LABELS: usize = 16;
/// Longest single label, matching the pipeline's identifier bound.
pub const MAX_LABEL_BYTES: usize = 64;
/// Worker cache images are keyed by the first 8 bytes of the image digest.
pub const IMAGE_KEY_BYTES: usize = 8;

/// Encode labels for the `labels` blob columns: sorted, newline-separated.
/// Ids are bounded and control-free; anything else is `InvalidInput` rather
/// than a blob another reader would misparse.
pub fn encode_labels(labels: &[String]) -> Result<Vec<u8>> {
    if labels.len() > MAX_LABELS {
        return Err(Error::InvalidInput("labels"));
    }
    let mut sorted: Vec<&str> = labels.iter().map(String::as_str).collect();
    sorted.sort_unstable();
    sorted.dedup();
    let mut out = Vec::new();
    for label in sorted {
        if label.is_empty()
            || label.len() > MAX_LABEL_BYTES
            || label.chars().any(|c| c.is_control() || c == '\n')
        {
            return Err(Error::InvalidInput("label"));
        }
        if !out.is_empty() {
            out.push(b'\n');
        }
        out.extend_from_slice(label.as_bytes());
    }
    Ok(out)
}

/// The labels a blob holds. One saved blob is always one of ours, so a
/// malformed one is corruption, never input.
fn parse_labels(blob: &[u8]) -> Result<Vec<String>> {
    if blob.is_empty() {
        return Ok(Vec::new());
    }
    let text = std::str::from_utf8(blob).map_err(|_| Error::Corrupt("labels"))?;
    if text.lines().count() > MAX_LABELS {
        return Err(Error::Corrupt("labels"));
    }
    Ok(text.lines().map(str::to_owned).collect())
}

/// Whether every label the job asks for is one the worker carries. An empty
/// request is satisfied by any worker; a request the worker never reported
/// is not.
fn labels_subset(job: &[u8], worker: &[u8]) -> Result<bool> {
    let worker = parse_labels(worker)?;
    Ok(parse_labels(job)?.iter().all(|l| worker.contains(l)))
}

/// The 8-byte key of a `sha256:<hex>` image digest, as a worker reports
/// cached images. Anything else has no key and never matches a cache.
fn image_key(digest: &str) -> Option<[u8; IMAGE_KEY_BYTES]> {
    let hex = digest.strip_prefix("sha256:")?.as_bytes();
    if hex.len() < IMAGE_KEY_BYTES * 2 {
        return None;
    }
    let mut key = [0u8; IMAGE_KEY_BYTES];
    for (i, slot) in key.iter_mut().enumerate() {
        let pair = std::str::from_utf8(&hex[i * 2..i * 2 + 2]).ok()?;
        *slot = u8::from_str_radix(pair, 16).ok()?;
    }
    Some(key)
}

/// Whether a worker's `avail_images` blob holds `key`.
fn caches_image(avail_images: &[u8], key: &[u8; IMAGE_KEY_BYTES]) -> bool {
    avail_images
        .chunks_exact(IMAGE_KEY_BYTES)
        .any(|chunk| chunk == key)
}

/// What a protocol-7 worker reports of itself beyond CPU and memory, written
/// by [`report_profile`]. Everything is optional measurement: unreported
/// facts stay absent rather than claiming a value.
pub struct ReportedProfile<'a> {
    /// Placement labels, bounded by [`MAX_LABELS`].
    pub labels: &'a [String],
    /// The machine hosting this worker; a host-level failure sweep and
    /// host-level reservations key on it. `None` when unreported.
    pub host_id: Option<[u8; 16]>,
    /// Images warm on the worker, as 8-byte keys.
    pub avail_images: &'a [[u8; IMAGE_KEY_BYTES]],
    /// Warm cache bytes it can offer. `None` when unmeasured.
    pub cache_bytes: Option<i64>,
    /// Last reported load. `None` when unmeasured.
    pub load_ns: Option<i64>,
}

/// Record the placement half of a worker's profile. Disjoint from
/// [`report_capacity`], which owns CPU, memory and disk: either call order
/// leaves both halves current.
pub fn report_profile(
    tx: &Transaction<'_>,
    worker: WorkerId,
    profile: &ReportedProfile<'_>,
) -> Result<()> {
    let labels = encode_labels(profile.labels)?;
    if let Some(cache_bytes) = profile.cache_bytes
        && cache_bytes < 0
    {
        return Err(Error::InvalidInput("cache_bytes"));
    }
    if let Some(load_ns) = profile.load_ns
        && load_ns < 0
    {
        return Err(Error::InvalidInput("load_ns"));
    }
    let mut images = Vec::with_capacity(profile.avail_images.len() * IMAGE_KEY_BYTES);
    for key in profile.avail_images {
        images.extend_from_slice(key);
    }
    let changed = tx
        .prepare_cached(
            "UPDATE workers SET labels = ?2, host_id = COALESCE(?3, host_id),
                    avail_images = ?4, cache_bytes = COALESCE(?5, cache_bytes),
                    load_ns = COALESCE(?6, load_ns)
             WHERE id = ?1 AND revoked_ms IS NULL",
        )?
        .execute(params![
            worker.as_bytes(),
            labels,
            profile.host_id.as_ref().map(|h| h.as_slice()),
            images,
            profile.cache_bytes,
            profile.load_ns
        ])?;
    if changed == 0 {
        return Err(Error::NotFound);
    }
    Ok(())
}

/// A lease the controller has just taken on a worker's behalf: everything the
/// worker needs to acknowledge and, later, to prepare.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Offer {
    pub attempt: AttemptId,
    pub tenant: TenantId,
    pub run: RunId,
    pub job: JobId,
    pub fence: Fence,
    pub lease_until: UnixMillis,
    pub cpu_millis: i64,
    pub memory_bytes: i64,
    pub image: ResolvedImage,
    /// Position of the job in the run's compiled spec.
    pub job_index: u32,
}

/// A ready job as placement sees it: what it needs, whom it belongs to and
/// the facts fairness keys on. Blobs stay raw so the SQL and the Rust pass
/// read the same bytes.
#[derive(Clone, Debug)]
struct Pick {
    tenant: TenantId,
    job: JobId,
    run: RunId,
    cpu_millis: i64,
    memory_bytes: i64,
    disk_bytes: i64,
    image_digest: String,
    image_platform: String,
    spec_index: i64,
    arch: Option<String>,
    labels: Vec<u8>,
    pull_request: bool,
    queued_ms: i64,
}

type PickRow = (
    [u8; 16],
    [u8; 16],
    [u8; 16],
    i64,
    i64,
    i64,
    String,
    String,
    i64,
    Option<String>,
    Vec<u8>,
    i64,
    i64,
);

fn pick_of(row: PickRow) -> Result<Pick> {
    let (
        tenant,
        job,
        run,
        cpu_millis,
        memory_bytes,
        disk_bytes,
        image_digest,
        image_platform,
        spec_index,
        arch,
        labels,
        queued_ms,
        pull_request,
    ) = row;
    Ok(Pick {
        tenant: TenantId::from_bytes(tenant).map_err(|_| Error::Corrupt("tenant_id"))?,
        job: JobId::from_bytes(job).map_err(|_| Error::Corrupt("job_id"))?,
        run: RunId::from_bytes(run).map_err(|_| Error::Corrupt("run_id"))?,
        cpu_millis,
        memory_bytes,
        disk_bytes,
        image_digest,
        image_platform,
        spec_index,
        arch,
        labels,
        pull_request: pull_request != 0,
        queued_ms,
    })
}

/// Everything placement needs to know about one worker beyond capacity.
#[derive(Clone, Debug)]
struct WorkerFacts {
    pool: PoolId,
    arch: String,
    labels: Vec<u8>,
    draining: bool,
    /// `false` when the worker has never reported disk (protocol 6): disk is
    /// then not part of its admission, never read as a zero-sized scratch.
    disk_reported: bool,
    avail_images: Vec<u8>,
    cpu_millis: i64,
    memory_bytes: i64,
    disk_bytes: i64,
}
type WorkerFactsRow = ([u8; 16], String, Vec<u8>, bool, i64, Vec<u8>, i64, i64);

fn worker_facts(conn: &Connection, worker: WorkerId) -> Result<Option<(WorkerId, WorkerFacts)>> {
    let row: Option<WorkerFactsRow> = conn
        .prepare_cached(
            "SELECT pool_id, arch, labels, drain_ms IS NOT NULL, disk_bytes, avail_images,
                    cpu_millis, memory_bytes
             FROM workers WHERE id = ?1 AND revoked_ms IS NULL",
        )?
        .query_row([worker.as_bytes()], |r| {
            Ok((
                r.get(0)?,
                r.get(1)?,
                r.get(2)?,
                r.get(3)?,
                r.get(4)?,
                r.get(5)?,
                r.get(6)?,
                r.get(7)?,
            ))
        })
        .optional()?;
    let Some((pool, arch, labels, draining, disk_bytes, avail_images, cpu, memory)) = row else {
        return Ok(None);
    };
    let id = worker;
    Ok(Some((
        id,
        WorkerFacts {
            pool: PoolId::from_bytes(pool).map_err(|_| Error::Corrupt("pool id"))?,
            arch,
            labels,
            draining,
            disk_reported: disk_bytes > 0,
            avail_images,
            cpu_millis: cpu,
            memory_bytes: memory,
            disk_bytes,
        },
    )))
}

/// Every worker of a pool the tenant may use: the candidate set both
/// placement and the queue explanation read. Pool access is A07's rule —
/// tenant active, pool active, owner or explicitly granted — evaluated per
/// call so suspension and withdrawal stop the next transaction.
fn pool_workers(conn: &Connection, tenant: TenantId) -> Result<Vec<(WorkerId, WorkerFacts)>> {
    let mut stmt = conn.prepare_cached(
        "SELECT w.id, w.pool_id, w.arch, w.labels, w.drain_ms IS NOT NULL, w.disk_bytes,
                w.avail_images, w.cpu_millis, w.memory_bytes
         FROM workers w
         JOIN pools p ON p.id = w.pool_id AND p.active = 1
         JOIN tenants t ON t.id = ?1 AND t.active = 1
         LEFT JOIN pool_grants g ON g.pool_id = p.id AND g.tenant_id = t.id
         WHERE w.revoked_ms IS NULL AND (p.owner_tenant_id = t.id OR g.tenant_id IS NOT NULL)",
    )?;
    let rows = stmt.query_map([tenant.as_bytes()], |r| {
        Ok((
            r.get::<_, [u8; 16]>(0)?,
            r.get::<_, [u8; 16]>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, Vec<u8>>(3)?,
            r.get::<_, bool>(4)?,
            r.get::<_, i64>(5)?,
            r.get::<_, Vec<u8>>(6)?,
            r.get::<_, i64>(7)?,
            r.get::<_, i64>(8)?,
        ))
    })?;
    let mut out = Vec::new();
    for row in rows {
        let (id, pool, arch, labels, draining, disk, images, cpu, memory) = row?;
        out.push((
            WorkerId::from_bytes(id).map_err(|_| Error::Corrupt("worker id"))?,
            WorkerFacts {
                pool: PoolId::from_bytes(pool).map_err(|_| Error::Corrupt("pool id"))?,
                arch,
                labels,
                draining,
                disk_reported: disk > 0,
                avail_images: images,
                cpu_millis: cpu,
                memory_bytes: memory,
                disk_bytes: disk,
            },
        ));
    }
    Ok(out)
}

/// One ready job that this worker may serve, for one tenant: the oldest
/// fitting job of that tenant. Placement then ranks one pick per tenant by
/// live-attempt deficit so a noisy tenant cannot fill a global window.
const CANDIDATES_SQL: &str = "SELECT j.tenant_id, j.id, j.run_id, j.cpu_millis, j.memory_bytes,
            j.disk_bytes, j.image_digest, j.image_platform, j.spec_index, j.arch, j.labels,
            j.queued_ms, COALESCE(p.trigger = 'pull_request', 0)
     FROM jobs j
     JOIN tenants t ON t.id = j.tenant_id AND t.active = 1
     JOIN pools p2 ON p2.id = ?1 AND p2.active = 1
     LEFT JOIN pool_grants g ON g.pool_id = p2.id AND g.tenant_id = t.id
     LEFT JOIN run_provenance p ON p.run_id = j.run_id
     WHERE j.state_code = 1 AND j.cancel_requested = 0
       AND j.image_digest IS NOT NULL AND j.image_platform IS NOT NULL
       AND (p2.owner_tenant_id = t.id OR g.tenant_id IS NOT NULL)
       AND (j.arch IS NULL OR j.arch = ?2)
       AND j.cpu_millis <= ?3 AND j.memory_bytes <= ?4
       AND (j.disk_bytes = 0 OR ?5 = 0 OR j.disk_bytes <= ?6)
       AND NOT EXISTS (
           SELECT 1 FROM jobs o
           WHERE o.tenant_id = j.tenant_id AND o.concurrency_group IS NOT NULL
             AND o.concurrency_group = j.concurrency_group AND o.run_id <> j.run_id
             AND o.state_code < ?7)
       AND j.tenant_id = ?8
     ORDER BY j.priority, j.queued_ms, j.created_seq
     LIMIT 32";

fn ready_tenants(conn: &Connection, _pool: PoolId) -> Result<Vec<TenantId>> {
    // `state_code = 1` stays a literal: SQLite only uses the partial
    // ready-queue indexes when the predicate is a constant. Probing each
    // tenant with EXISTS costs one index descent per tenant; grouping the
    // ready set itself would visit every queued job.
    let mut stmt = conn.prepare_cached(
        "SELECT t.id FROM tenants t
         WHERE t.active = 1 AND EXISTS(
             SELECT 1 FROM jobs j
             WHERE j.tenant_id = t.id AND j.state_code = 1
               AND j.cancel_requested = 0 AND j.image_digest IS NOT NULL
             LIMIT 1)",
    )?;
    let rows = stmt.query_map([], |r| r.get::<_, [u8; 16]>(0))?;
    let mut out = Vec::new();
    for row in rows {
        out.push(TenantId::from_bytes(row?).map_err(|_| Error::Corrupt("tenant_id"))?);
    }
    Ok(out)
}

fn tenant_held(conn: &Connection) -> Result<HashMap<TenantId, i64>> {
    // Per-tenant index counts over the held-attempts partial index: counting
    // all held rows once per placement would scale with fleet load, not with
    // the number of tenants.
    let mut stmt = conn.prepare_cached(
        "SELECT t.id,
                (SELECT COUNT(*) FROM attempts a
                 WHERE a.tenant_id = t.id AND a.released_ms IS NULL)
         FROM tenants t",
    )?;
    let rows = stmt.query_map([], |r| Ok((r.get::<_, [u8; 16]>(0)?, r.get::<_, i64>(1)?)))?;
    let mut out = HashMap::new();
    for row in rows {
        let (id, n) = row?;
        if n > 0 {
            out.insert(
                TenantId::from_bytes(id).map_err(|_| Error::Corrupt("tenant_id"))?,
                n,
            );
        }
    }
    Ok(out)
}

fn candidates(
    conn: &Connection,
    pool: PoolId,
    facts: &WorkerFacts,
    free: Capacity,
) -> Result<Vec<Pick>> {
    let reported = if facts.disk_reported { 1i64 } else { 0 };
    let tenants = ready_tenants(conn, pool)?;
    // The held counts only rank tenants against each other; with one tenant
    // there is nothing to rank and the count scan is wasted work.
    let held = if tenants.len() > 1 {
        tenant_held(conn)?
    } else {
        HashMap::new()
    };
    let mut stmt = conn.prepare_cached(CANDIDATES_SQL)?;
    let mut out = Vec::new();
    for tenant in tenants {
        let rows = stmt.query_map(
            params![
                pool.as_bytes(),
                facts.arch,
                free.cpu_millis,
                free.memory_bytes,
                reported,
                free.disk_bytes,
                TERMINAL_BASE,
                tenant.as_bytes()
            ],
            |r| {
                Ok((
                    r.get::<_, [u8; 16]>(0)?,
                    r.get::<_, [u8; 16]>(1)?,
                    r.get::<_, [u8; 16]>(2)?,
                    r.get::<_, i64>(3)?,
                    r.get::<_, i64>(4)?,
                    r.get::<_, i64>(5)?,
                    r.get::<_, String>(6)?,
                    r.get::<_, String>(7)?,
                    r.get::<_, i64>(8)?,
                    r.get::<_, Option<String>>(9)?,
                    r.get::<_, Vec<u8>>(10)?,
                    r.get::<_, i64>(11)?,
                    r.get::<_, i64>(12)?,
                ))
            },
        )?;
        for row in rows {
            out.push(pick_of(row?)?);
        }
    }
    out.sort_by(|a, b| {
        held.get(&a.tenant)
            .copied()
            .unwrap_or(0)
            .cmp(&held.get(&b.tenant).copied().unwrap_or(0))
            .then(a.queued_ms.cmp(&b.queued_ms))
    });
    Ok(out)
}

/// What waiting work reserves on a worker's free capacity: a path for the
/// largest waiting large job and, while a pull-request job waits, a quarter
/// of the host's reported millicpu.
#[derive(Clone, Copy, Debug, Default)]
struct Fairness {
    /// `(cpu_millis, queued_ms)` of the largest waiting job at or above
    /// [`LARGE_JOB_CPU`] this worker could run, and when it first waited.
    large: Option<(i64, i64)>,
    /// A pull-request job this worker could run is waiting.
    pull_request: bool,
    /// The host's reported millicpu: the base of the PR reserve.
    host_cpu_millis: i64,
}

/// Total millicpu of the workers sharing this worker's host, or its own when
/// no host is on record.
fn host_millis(conn: &Connection, worker: WorkerId) -> Result<i64> {
    Ok(conn
        .prepare_cached(
            "SELECT COALESCE(SUM(cpu_millis), 0) FROM workers WHERE revoked_ms IS NULL
               AND (id = ?1 OR (host_id IS NOT NULL
                    AND host_id = (SELECT host_id FROM workers WHERE id = ?1)))",
        )?
        .query_row([worker.as_bytes()], |r| r.get(0))?)
}

fn waiting_fairness(
    conn: &Connection,
    worker: WorkerId,
    _pool: PoolId,
    facts: &WorkerFacts,
) -> Result<Fairness> {
    let mut fairness = Fairness::default();
    let large: Option<(i64, i64)> = conn
        .prepare_cached(
            "SELECT cpu_millis, queued_ms FROM jobs
             WHERE state_code = 1 AND cancel_requested = 0
               AND cpu_millis >= ?1 AND cpu_millis <= ?2
             ORDER BY cpu_millis DESC LIMIT 1",
        )?
        .query_row(params![LARGE_JOB_CPU, facts.cpu_millis], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .optional()?;
    fairness.large = large;
    let pr: bool = conn
        .prepare_cached(
            "SELECT EXISTS(
                SELECT 1 FROM run_provenance p JOIN jobs j ON j.run_id = p.run_id
                WHERE p.trigger = 'pull_request'
                  AND j.state_code = 1 AND j.cancel_requested = 0)",
        )?
        .query_row([], |r| r.get(0))?;
    if pr {
        fairness.pull_request = true;
        fairness.host_cpu_millis = host_millis(conn, worker)?;
    }
    Ok(fairness)
}

/// Whether placing `pick` would spend capacity a waiting job reserved.
fn fairness_hold(fairness: &Fairness, pick: &Pick, free_cpu: i64) -> bool {
    let after = free_cpu.saturating_sub(pick.cpu_millis);
    if let Some((need, since)) = fairness.large
        && pick.cpu_millis < need
        && after < need
        && since <= pick.queued_ms
    {
        return true;
    }
    fairness.pull_request
        && !pick.pull_request
        && after < fairness.host_cpu_millis / PR_RESERVE_DIVISOR
}

/// A worker that could run a waiting job and has its image warm.
struct LocalityWorker {
    arch: String,
    labels: Vec<u8>,
    cpu_millis: i64,
    memory_bytes: i64,
    disk_bytes: i64,
    avail_images: Vec<u8>,
    /// Earliest lease release among the attempts it holds; `None` when free.
    free_at: Option<i64>,
}

/// Workers other than `exclude` that a warm job could run on, for the
/// bounded locality wait.
fn locality_view(
    conn: &Connection,
    tenant: TenantId,
    exclude: WorkerId,
) -> Result<Vec<LocalityWorker>> {
    let mut stmt = conn.prepare_cached(
        "SELECT w.arch, w.labels, w.cpu_millis, w.memory_bytes, w.disk_bytes, w.avail_images,
                (SELECT MIN(a.lease_until_ms) FROM attempts a
                 WHERE a.worker_id = w.id AND a.released_ms IS NULL)
         FROM workers w
         JOIN pools p ON p.id = w.pool_id AND p.active = 1
         JOIN tenants t ON t.id = ?2 AND t.active = 1
         LEFT JOIN pool_grants g ON g.pool_id = p.id AND g.tenant_id = t.id
         WHERE w.id <> ?1 AND w.revoked_ms IS NULL AND w.drain_ms IS NULL
           AND (p.owner_tenant_id = t.id OR g.tenant_id IS NOT NULL)",
    )?;
    let rows = stmt.query_map(params![exclude.as_bytes(), tenant.as_bytes()], |r| {
        Ok(LocalityWorker {
            arch: r.get(0)?,
            labels: r.get(1)?,
            cpu_millis: r.get(2)?,
            memory_bytes: r.get(3)?,
            disk_bytes: r.get(4)?,
            avail_images: r.get(5)?,
            free_at: r.get(6)?,
        })
    })?;
    rows.collect::<std::result::Result<_, _>>()
        .map_err(Error::from)
}

/// Whether this job should wait for a worker that has its image warm: only
/// while it is inside [`LOCALITY_WAIT_MS`] and a worker that could run it
/// holds the image and is expected to free within the bound. Past the bound
/// any eligible worker takes it, so locality never strands work.
fn locality_hold(view: &[LocalityWorker], pick: &Pick, now: UnixMillis) -> Result<bool> {
    if now.0.saturating_sub(pick.queued_ms) >= LOCALITY_WAIT_MS {
        return Ok(false);
    }
    let Some(key) = image_key(&pick.image_digest) else {
        return Ok(false);
    };
    let bound = now.0.saturating_add(LOCALITY_WAIT_MS);
    for worker in view {
        if !pick
            .arch
            .as_deref()
            .is_none_or(|arch| arch == worker.arch.as_str())
        {
            continue;
        }
        if !labels_subset(&pick.labels, &worker.labels)?
            || worker.cpu_millis < pick.cpu_millis
            || worker.memory_bytes < pick.memory_bytes
            || (pick.disk_bytes > 0 && worker.disk_bytes > 0 && worker.disk_bytes < pick.disk_bytes)
            || !caches_image(&worker.avail_images, &key)
        {
            continue;
        }
        if worker.free_at.is_none_or(|until| until <= bound) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Place one job on `worker`: the next ready job of the pool's fair order
/// that fits the worker's free capacity, leased with its reservation in the
/// calling transaction. `None` means nothing may be placed here now — no
/// eligible job, a draining worker, or a waiting large job whose path this
/// placement would spend. A job behind a large one is backfilled while the
/// large job keeps its reserved remainder, and a job whose image is warm
/// elsewhere waits only inside [`LOCALITY_WAIT_MS`].
///
/// Pool access is A07's rule, evaluated here per placement rather than
/// cached: the tenant active, the pool active, the tenant its owner or
/// explicitly granted. Suspended tenants and withdrawn grants stop placing
/// at their next transaction.
pub fn place(
    tx: &Transaction<'_>,
    worker: WorkerId,
    pool: PoolId,
    lease_ms: i64,
    now: UnixMillis,
) -> Result<Option<Offer>> {
    let Some((_, facts)) = worker_facts(tx, worker)? else {
        return Ok(None);
    };
    if facts.pool != pool || facts.draining {
        return Ok(None);
    }
    let free = free_capacity(tx, worker)?;
    if free.cpu_millis <= 0 || free.memory_bytes <= 0 {
        return Ok(None);
    }
    if facts.disk_reported && free.disk_bytes <= 0 {
        return Ok(None);
    }
    let candidates = candidates(tx, pool, &facts, free)?;
    if candidates.is_empty() {
        return Ok(None);
    }
    let fairness = waiting_fairness(tx, worker, pool, &facts)?;
    let mut locality: Option<Vec<LocalityWorker>> = None;
    for pick in candidates {
        if !labels_subset(&pick.labels, &facts.labels)? {
            continue;
        }
        if fairness_hold(&fairness, &pick, free.cpu_millis) {
            continue;
        }
        let cold = image_key(&pick.image_digest)
            .is_some_and(|key| !caches_image(&facts.avail_images, &key));
        if cold {
            if locality.is_none() {
                // Skip the workers scan entirely when no worker in the fleet
                // has reported an image: locality can never hold then, and
                // the scan would cost one pass over the fleet per placement.
                let any_images: bool = tx
                    .prepare_cached(
                        "SELECT EXISTS(SELECT 1 FROM workers
                          WHERE revoked_ms IS NULL AND avail_images <> X'')",
                    )?
                    .query_row([], |r| r.get(0))?;
                let view = if any_images {
                    locality_view(tx, pick.tenant, worker)?
                } else {
                    Vec::new()
                };
                let useful = view.iter().any(|w| !w.avail_images.is_empty());
                locality = Some(if useful { view } else { Vec::new() });
            }
            let view = locality.as_deref().unwrap_or_default();
            if !view.is_empty() && locality_hold(view, &pick, now)? {
                continue;
            }
        }
        let lease_until = UnixMillis(now.0.saturating_add(lease_ms));
        let (attempt, fence) = jobs::lease(tx, pick.tenant, pick.job, worker, lease_until, now)?;
        return Ok(Some(Offer {
            attempt,
            tenant: pick.tenant,
            run: pick.run,
            job: pick.job,
            fence,
            lease_until,
            cpu_millis: pick.cpu_millis,
            memory_bytes: pick.memory_bytes,
            image: ResolvedImage {
                digest: pick.image_digest,
                platform: pick.image_platform,
            },
            job_index: u32::try_from(pick.spec_index).map_err(|_| Error::Corrupt("spec_index"))?,
        }));
    }
    Ok(None)
}

/// The worker accepted the offer. Compare-and-set on worker and fence; a
/// repeated acknowledgement of a held attempt is idempotent (the link may
/// retransmit), one for a lapsed or foreign attempt is `Conflict`.
/// Returns the lease deadline the worker must renew by.
pub fn acknowledge(
    tx: &Transaction<'_>,
    worker: WorkerId,
    attempt: AttemptId,
    fence: Fence,
    now: UnixMillis,
) -> Result<UnixMillis> {
    tx.prepare_cached(
        "UPDATE attempts SET acked_ms = ?4
         WHERE id = ?1 AND worker_id = ?2 AND fence = ?3 AND acked_ms IS NULL AND released_ms IS NULL",
    )?
    .execute(params![
        attempt.as_bytes(),
        worker.as_bytes(),
        fence.0 as i64,
        now.0
    ])?;
    let held: Option<(bool, i64)> = tx
        .prepare_cached(
            "SELECT released_ms IS NULL, lease_until_ms FROM attempts
             WHERE id = ?1 AND worker_id = ?2 AND fence = ?3",
        )?
        .query_row(
            params![attempt.as_bytes(), worker.as_bytes(), fence.0 as i64],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    match held {
        Some((true, until)) => Ok(UnixMillis(until)),
        Some((false, _)) => Err(Error::Conflict),
        None => Err(Error::NotFound),
    }
}

/// The offer was declined or never acknowledged: release the reservation and
/// return the job to the queue under its advanced fence. Only an
/// unacknowledged, held attempt can lapse; anything else is `NotFound`.
pub fn lapse(tx: &Transaction<'_>, attempt: AttemptId, now: UnixMillis) -> Result<()> {
    let row: Option<([u8; 16], [u8; 16], i64)> = tx
        .prepare_cached(
            "SELECT tenant_id, job_id, fence FROM attempts
             WHERE id = ?1 AND acked_ms IS NULL AND released_ms IS NULL",
        )?
        .query_row([attempt.as_bytes()], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?))
        })
        .optional()?;
    let Some((tenant, job, fence)) = row else {
        return Err(Error::NotFound);
    };
    let tenant = TenantId::from_bytes(tenant).map_err(|_| Error::Corrupt("tenant_id"))?;
    let job = JobId::from_bytes(job).map_err(|_| Error::Corrupt("job_id"))?;
    let current = jobs::get_job(tx, tenant, job)?;
    if current.fence.0 != fence as u64 {
        return Err(Error::Conflict);
    }
    jobs::transition(tx, tenant, job, Actor::Controller, Event::OfferLapsed, now)?;
    tx.prepare_cached("UPDATE attempts SET released_ms = ?2 WHERE id = ?1")?
        .execute(params![attempt.as_bytes(), now.0])?;
    Ok(())
}

/// Offers whose [`OFFER_ACK_MS`] has passed at `now` without an
/// acknowledgement, oldest first, for the sweep to [`lapse`].
pub fn unacknowledged(conn: &Connection, now: UnixMillis) -> Result<Vec<AttemptId>> {
    let before = UnixMillis(now.0.saturating_sub(OFFER_ACK_MS));
    let mut stmt = conn.prepare_cached(
        "SELECT id FROM attempts WHERE acked_ms IS NULL AND released_ms IS NULL
         AND offered_ms <= ?1 ORDER BY offered_ms LIMIT ?2",
    )?;
    let rows = stmt.query_map(params![before.0, SWEEP_LIMIT as i64], |r| {
        r.get::<_, [u8; 16]>(0)
    })?;
    rows.map(|row| AttemptId::from_bytes(row?).map_err(|_| Error::Corrupt("attempt_id")))
        .collect()
}

/// An attempt a worker holds, for reconciliation and renewal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Held {
    pub attempt: AttemptId,
    pub tenant: TenantId,
    pub job: JobId,
    pub fence: Fence,
    pub acknowledged: bool,
    pub lease_until: UnixMillis,
}

/// The newest attempt of a job (highest fence), for status and tests.
pub fn latest_attempt(
    conn: &Connection,
    tenant: TenantId,
    job: JobId,
) -> Result<Option<AttemptId>> {
    conn.prepare_cached(
        "SELECT id FROM attempts WHERE job_id = ?1 AND tenant_id = ?2 ORDER BY fence DESC LIMIT 1",
    )?
    .query_row(params![job.as_bytes(), tenant.as_bytes()], |r| {
        r.get::<_, [u8; 16]>(0)
    })
    .optional()?
    .map(|b| AttemptId::from_bytes(b).map_err(|_| Error::Corrupt("attempt_id")))
    .transpose()
}

/// Every attempt still reserved on `worker`, oldest offer first.
pub fn held_by(conn: &Connection, worker: WorkerId) -> Result<Vec<Held>> {
    let mut stmt = conn.prepare_cached(
        "SELECT id, tenant_id, job_id, fence, acked_ms IS NOT NULL, lease_until_ms
         FROM attempts WHERE worker_id = ?1 AND released_ms IS NULL ORDER BY offered_ms, id",
    )?;
    let rows = stmt.query_map([worker.as_bytes()], |r| {
        Ok((
            r.get::<_, [u8; 16]>(0)?,
            r.get::<_, [u8; 16]>(1)?,
            r.get::<_, [u8; 16]>(2)?,
            r.get::<_, i64>(3)?,
            r.get::<_, bool>(4)?,
            r.get::<_, i64>(5)?,
        ))
    })?;
    rows.map(|row| {
        let (attempt, tenant, job, fence, acknowledged, until) = row?;
        Ok(Held {
            attempt: AttemptId::from_bytes(attempt).map_err(|_| Error::Corrupt("attempt_id"))?,
            tenant: TenantId::from_bytes(tenant).map_err(|_| Error::Corrupt("tenant_id"))?,
            job: JobId::from_bytes(job).map_err(|_| Error::Corrupt("job_id"))?,
            fence: Fence(fence as u64),
            acknowledged,
            lease_until: UnixMillis(until),
        })
    })
    .collect()
}

/// Renew the leases of the attempts a worker says it holds, to
/// `now + lease_ms` (never backwards). Returns the new deadline and the
/// attempts the controller does **not** recognise as held by this worker —
/// lapsed, finished, or never its — which the worker must stop at once.
pub fn renew(
    tx: &Transaction<'_>,
    worker: WorkerId,
    held: &[AttemptId],
    lease_ms: i64,
    now: UnixMillis,
) -> Result<(UnixMillis, Vec<AttemptId>)> {
    if held.len() > MAX_HELD_ATTEMPTS {
        return Err(Error::InvalidInput("held attempts"));
    }
    let until = UnixMillis(now.0.saturating_add(lease_ms));
    let mut stmt = tx.prepare_cached(
        "UPDATE attempts SET lease_until_ms = MAX(lease_until_ms, ?3)
         WHERE id = ?1 AND worker_id = ?2 AND acked_ms IS NOT NULL AND released_ms IS NULL",
    )?;
    let mut stop = Vec::new();
    for attempt in held {
        if stmt.execute(params![attempt.as_bytes(), worker.as_bytes(), until.0])? == 0 {
            stop.push(*attempt);
        }
    }
    Ok((until, stop))
}

/// Artifact coverage of a finishing attempt under `passed`: the declarations
/// due under that outcome that have no row at all — each gets a `failed` row
/// so the loss is on record — and whether any due *required* artifact lacks
/// a `captured` row, which a reported `Passed` cannot stand over. The
/// declarations come from the stored run spec, so a report cannot omit one
/// silently.
fn due_coverage(
    tx: &Transaction<'_>,
    tenant: TenantId,
    run: RunId,
    spec_index: u32,
    attempt: AttemptId,
    passed: bool,
) -> Result<(Vec<sentinel_pipeline::schema::Artifact>, bool)> {
    let spec = runs::get_run_spec(tx, tenant, run)?;
    let job = spec
        .pipeline
        .jobs
        .get(spec_index as usize)
        .ok_or(Error::Corrupt("spec_index"))?;
    let settled = artifacts::for_attempt(tx, attempt)?;
    let mut missing = Vec::new();
    let mut required_lost = false;
    for decl in &job.spec.artifacts {
        let due = match decl.when {
            ArtifactWhen::Success => passed,
            ArtifactWhen::Failure => !passed,
            ArtifactWhen::Always => true,
        };
        if !due {
            continue;
        }
        match settled.iter().find(|(n, _)| *n == decl.name) {
            None => {
                missing.push(decl.clone());
                required_lost |= decl.required;
            }
            Some((_, state)) if decl.required && *state != artifacts::State::Captured => {
                required_lost = true;
            }
            _ => {}
        }
    }
    Ok((missing, required_lost))
}

/// End an attempt: apply `event` as `actor` through the state machine, release
/// the reservation, and if the job reached terminal, decide its dependents.
/// A worker's report is fenced by the machine; a stale one changes nothing.
///
/// Terminal publication persists the attempt's data status first: a reported
/// `Passed` stands only if every due *required* artifact has a `captured`
/// row — otherwise the event is applied as `Failed(Publication)`; every due
/// artifact without a row gets `failed` so the loss is on record; and
/// `log_state` records whether the log's end marker was durable (`logs`
/// answers it; `None` for callers without a log store answers incomplete).
pub fn finish(
    tx: &Transaction<'_>,
    attempt: AttemptId,
    actor: Actor,
    event: Event,
    now: UnixMillis,
    logs: Option<&LogStore>,
) -> Result<JobState> {
    let row = tx
        .prepare_cached(
            "SELECT a.tenant_id, a.job_id, j.run_id, j.spec_index
             FROM attempts a JOIN jobs j ON j.id = a.job_id
             WHERE a.id = ?1 AND a.released_ms IS NULL",
        )?
        .query_row([attempt.as_bytes()], |r| {
            Ok((
                r.get::<_, [u8; 16]>(0)?,
                r.get::<_, [u8; 16]>(1)?,
                r.get::<_, [u8; 16]>(2)?,
                r.get::<_, i64>(3)?,
            ))
        })
        .optional()?;
    let Some((tenant, job, run, index)) = row else {
        return Err(Error::NotFound);
    };
    let tenant = TenantId::from_bytes(tenant).map_err(|_| Error::Corrupt("tenant_id"))?;
    let job = JobId::from_bytes(job).map_err(|_| Error::Corrupt("job_id"))?;
    let run = RunId::from_bytes(run).map_err(|_| Error::Corrupt("run_id"))?;
    let index = u32::try_from(index).map_err(|_| Error::Corrupt("spec_index"))?;
    let finishing = matches!(
        event,
        Event::Passed
            | Event::Failed(_)
            | Event::LeaseExpired
            | Event::WorkerLost
            | Event::Reconciled
    );
    let mut missing = Vec::new();
    let mut event = event;
    if finishing {
        let lost;
        (missing, lost) = due_coverage(tx, tenant, run, index, attempt, event == Event::Passed)?;
        if event == Event::Passed && lost {
            event = Event::Failed(FailureClass::Publication);
        }
    }
    let next = jobs::transition(tx, tenant, job, actor, event, now)?;
    if !next.is_terminal() {
        // Preparing/Running/Finalizing keep the reservation.
        return Ok(next);
    }
    let ended = logs.is_some_and(|l| l.has_end(run, job, attempt));
    tx.prepare_cached(
        "UPDATE attempts SET released_ms = ?2,
             log_state = CASE WHEN log_state = 0 THEN ?3 ELSE log_state END
         WHERE id = ?1",
    )?
    .execute(params![
        attempt.as_bytes(),
        now.0,
        if ended {
            LogState::Complete
        } else {
            LogState::Incomplete
        }
        .code(),
    ])?;
    for decl in &missing {
        artifacts::record(
            tx,
            tenant,
            run,
            job,
            attempt,
            &decl.name,
            artifacts::State::Failed,
            None,
            0,
            0,
            UnixMillis(
                now.0
                    .saturating_add(decl.retain_secs.saturating_mul(1000) as i64),
            ),
            now,
        )?;
    }
    release_dependents(tx, tenant, run, now)?;
    Ok(next)
}

/// The attempt's log end marker is durable on the controller: the row says
/// so before the worker is acknowledged. Monotonic — a recorded `complete`
/// is never taken back.
pub fn log_ended(tx: &Transaction<'_>, attempt: AttemptId) -> Result<()> {
    tx.prepare_cached("UPDATE attempts SET log_state = ?2 WHERE id = ?1 AND log_state <> ?2")?
        .execute(params![attempt.as_bytes(), LogState::Complete.code()])?;
    Ok(())
}

/// What cancelling a job did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cancelled {
    /// No worker owned it: terminal `Canceled` now.
    Terminal,
    /// A worker owns it: the desired state is recorded, the worker is told
    /// on its next heartbeat, and the attempt reports its own end.
    Requested,
    /// Already terminal; nothing to do.
    AlreadyTerminal,
}

/// Cancellation as durable desired state: recorded first, effective at once
/// for an unstarted job, delivered to the owning worker for a running one.
/// Never cleared; a cancelled job cannot be rerun.
pub fn cancel(
    tx: &Transaction<'_>,
    tenant: TenantId,
    job: JobId,
    now: UnixMillis,
) -> Result<Cancelled> {
    let row = jobs::get_job(tx, tenant, job)?;
    if row.state.is_terminal() {
        return Ok(Cancelled::AlreadyTerminal);
    }
    let unstarted = jobs::request_cancel(tx, tenant, job)?;
    if unstarted {
        jobs::transition(
            tx,
            tenant,
            job,
            Actor::Controller,
            Event::CancelBeforeStart,
            now,
        )?;
        Ok(Cancelled::Terminal)
    } else {
        Ok(Cancelled::Requested)
    }
}

/// Cancel every job of a run that is not terminal yet.
pub fn cancel_run(
    tx: &Transaction<'_>,
    tenant: TenantId,
    run: RunId,
    now: UnixMillis,
) -> Result<usize> {
    let mut count = 0;
    for (job, state) in runs::run_jobs(tx, tenant, run)? {
        if !state.is_terminal() {
            cancel(tx, tenant, job, now)?;
            count += 1;
        }
    }
    Ok(count)
}

/// Among the attempts a worker holds, those whose job has cancellation
/// desired: told to the worker with every heartbeat until it reports.
pub fn cancel_requested(
    conn: &Connection,
    worker: WorkerId,
    held: &[AttemptId],
) -> Result<Vec<AttemptId>> {
    let mut stmt = conn.prepare_cached(
        "SELECT EXISTS(SELECT 1 FROM attempts a JOIN jobs j ON j.id = a.job_id
         WHERE a.id = ?1 AND a.worker_id = ?2 AND a.released_ms IS NULL AND j.cancel_requested = 1)",
    )?;
    let mut out = Vec::new();
    for attempt in held {
        let wanted: bool =
            stmt.query_row(params![attempt.as_bytes(), worker.as_bytes()], |r| r.get(0))?;
        if wanted {
            out.push(*attempt);
        }
    }
    Ok(out)
}

/// Acknowledged attempts whose lease has passed, or which have run past
/// their job's timeout plus [`EXECUTION_GRACE_MS`]: the worker stopped
/// renewing, or renews but is not enforcing. Oldest first. An offer that
/// was never acknowledged is not here — it never ran, so it lapses back to
/// the queue through [`unacknowledged`] instead.
pub fn expired(conn: &Connection, now: UnixMillis) -> Result<Vec<AttemptId>> {
    let mut stmt = conn.prepare_cached(
        "SELECT a.id FROM attempts a
         WHERE a.released_ms IS NULL AND a.acked_ms IS NOT NULL AND a.lease_until_ms < ?1
         ORDER BY a.lease_until_ms LIMIT ?2",
    )?;
    let rows = stmt.query_map(params![now.0, SWEEP_BATCH as i64], |r| {
        r.get::<_, [u8; 16]>(0)
    })?;
    let mut out: Vec<AttemptId> = rows
        .map(|row| AttemptId::from_bytes(row?).map_err(|_| Error::Corrupt("attempt_id")))
        .collect::<Result<_>>()?;
    let mut overrun = conn.prepare_cached(
        "SELECT a.id FROM attempts a JOIN jobs j ON j.id = a.job_id
         WHERE a.released_ms IS NULL AND a.acked_ms IS NOT NULL
           AND a.acked_ms + j.timeout_ms + ?2 < ?1
         LIMIT ?3",
    )?;
    let rows = overrun.query_map(
        params![now.0, EXECUTION_GRACE_MS, SWEEP_BATCH as i64],
        |r| r.get::<_, [u8; 16]>(0),
    )?;
    for row in rows {
        let id = AttemptId::from_bytes(row?).map_err(|_| Error::Corrupt("attempt_id"))?;
        if !out.contains(&id) {
            out.push(id);
        }
    }
    Ok(out)
}

/// Expire one attempt: `LeaseExpired` through the machine, capacity back,
/// dependents decided. The job is terminal `infra_failed` — never re-queued
/// on its own, because whether its side effects happened is unknown.
pub fn expire(
    tx: &Transaction<'_>,
    attempt: AttemptId,
    now: UnixMillis,
    logs: Option<&LogStore>,
) -> Result<JobState> {
    finish(
        tx,
        attempt,
        Actor::Controller,
        Event::LeaseExpired,
        now,
        logs,
    )
}

/// A worker found this attempt in its own leftovers after a restart and
/// cannot say what happened: `Reconciled` through the machine as the
/// reconciler, capacity back, dependents decided, never replayed. The
/// attempt must still be held by that worker under that fence; anything
/// else is a stale claim and is refused.
pub fn abandon(
    tx: &Transaction<'_>,
    worker: WorkerId,
    attempt: AttemptId,
    fence: Fence,
    now: UnixMillis,
    logs: Option<&LogStore>,
) -> Result<JobState> {
    let held: bool = tx
        .prepare_cached(
            "SELECT EXISTS(SELECT 1 FROM attempts WHERE id = ?1 AND worker_id = ?2 AND fence = ?3
                           AND released_ms IS NULL)",
        )?
        .query_row(
            params![attempt.as_bytes(), worker.as_bytes(), fence.0 as i64],
            |r| r.get(0),
        )?;
    if !held {
        return Err(Error::NotFound);
    }
    let acked: bool = tx
        .prepare_cached("SELECT acked_ms IS NOT NULL FROM attempts WHERE id = ?1")?
        .query_row([attempt.as_bytes()], |r| r.get(0))?;
    if !acked {
        // Never acknowledged: it never started, so back to the queue.
        lapse(tx, attempt, now)?;
        return Ok(JobState::Queued);
    }
    finish(tx, attempt, Actor::Reconciler, Event::Reconciled, now, logs)
}

/// What a controller start found and settled.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Reconciled {
    /// Held attempts whose lease had already passed while the controller was
    /// down: `LeaseExpired`.
    pub expired: usize,
    /// Offers never acknowledged within the ack timeout: back to the queue.
    pub lapsed: usize,
    /// Attempts held by a worker that has been revoked meanwhile:
    /// `Reconciled` — no session will ever report them.
    pub orphaned: usize,
}

/// Startup reconciliation: the rows are the truth, and every one that could
/// only have moved with a controller running is moved now, in one
/// transaction, before any worker is admitted. Nothing is re-queued that
/// may have run.
pub fn reconcile_startup(
    tx: &Transaction<'_>,
    now: UnixMillis,
    logs: Option<&LogStore>,
) -> Result<Reconciled> {
    let mut done = Reconciled::default();
    for attempt in expired(tx, now)? {
        expire(tx, attempt, now, logs)?;
        done.expired += 1;
    }
    for attempt in unacknowledged(tx, now)? {
        lapse(tx, attempt, now)?;
        done.lapsed += 1;
    }
    let orphans: Vec<[u8; 16]> = tx
        .prepare_cached(
            "SELECT a.id FROM attempts a JOIN workers w ON w.id = a.worker_id
             WHERE a.released_ms IS NULL AND a.acked_ms IS NOT NULL AND w.revoked_ms IS NOT NULL
             LIMIT ?1",
        )?
        .query_map([SWEEP_BATCH as i64], |r| r.get(0))?
        .collect::<std::result::Result<_, _>>()?;
    for attempt in orphans {
        let attempt = AttemptId::from_bytes(attempt).map_err(|_| Error::Corrupt("attempt_id"))?;
        finish(tx, attempt, Actor::Reconciler, Event::Reconciled, now, logs)?;
        done.orphaned += 1;
    }
    Ok(done)
}

/// Queued jobs that waited longer than [`QUEUE_TIMEOUT_MS`]: `QueueTimedOut`.
/// Returns how many were timed out this pass.
pub fn sweep_queue_timeouts(tx: &Transaction<'_>, now: UnixMillis) -> Result<usize> {
    let cutoff = now.0.saturating_sub(QUEUE_TIMEOUT_MS);
    let rows: Vec<([u8; 16], [u8; 16])> = tx
        .prepare_cached(
            "SELECT tenant_id, id FROM jobs WHERE state_code = ?1 AND queued_ms <= ?2
             ORDER BY queued_ms LIMIT ?3",
        )?
        .query_map(params![READY, cutoff, SWEEP_BATCH as i64], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })?
        .collect::<std::result::Result<_, _>>()?;
    let mut count = 0;
    for (tenant, job) in rows {
        let tenant = TenantId::from_bytes(tenant).map_err(|_| Error::Corrupt("tenant_id"))?;
        let job = JobId::from_bytes(job).map_err(|_| Error::Corrupt("job_id"))?;
        jobs::transition(
            tx,
            tenant,
            job,
            Actor::Controller,
            Event::QueueTimedOut,
            now,
        )?;
        let run = run_of(tx, tenant, job)?;
        release_dependents(tx, tenant, run, now)?;
        count += 1;
    }
    Ok(count)
}

fn run_of(conn: &Connection, tenant: TenantId, job: JobId) -> Result<RunId> {
    let run: [u8; 16] = conn
        .prepare_cached("SELECT run_id FROM jobs WHERE id = ?1 AND tenant_id = ?2")?
        .query_row(params![job.as_bytes(), tenant.as_bytes()], |r| r.get(0))
        .optional()?
        .ok_or(Error::NotFound)?;
    RunId::from_bytes(run).map_err(|_| Error::Corrupt("run_id"))
}

/// A worker's report over the link: the attempt must be held by that worker
/// under that fence, then [`finish`] applies the event as the worker. A
/// terminal report may carry the attempt's summary, written once.
#[allow(clippy::too_many_arguments)]
pub fn report(
    tx: &Transaction<'_>,
    worker: WorkerId,
    attempt: AttemptId,
    fence: Fence,
    event: Event,
    summary: Option<&[u8]>,
    now: UnixMillis,
    logs: Option<&LogStore>,
) -> Result<JobState> {
    let held: bool = tx
        .prepare_cached(
            "SELECT EXISTS(SELECT 1 FROM attempts WHERE id = ?1 AND worker_id = ?2 AND fence = ?3
                           AND acked_ms IS NOT NULL AND released_ms IS NULL)",
        )?
        .query_row(
            params![attempt.as_bytes(), worker.as_bytes(), fence.0 as i64],
            |r| r.get(0),
        )?;
    if !held {
        return Err(Error::NotFound);
    }
    let next = finish(tx, attempt, Actor::Worker(fence), event, now, logs)?;
    if let Some(summary) = summary
        && next.is_terminal()
    {
        if summary.len() > MAX_SUMMARY_BYTES {
            return Err(Error::InvalidInput("attempt summary"));
        }
        tx.prepare_cached("UPDATE attempts SET summary = ?2 WHERE id = ?1 AND summary IS NULL")?
            .execute(params![attempt.as_bytes(), summary])?;
    }
    Ok(next)
}

/// The summary a worker sent with the attempt's terminal report, if any.
pub fn attempt_summary(
    conn: &Connection,
    tenant: TenantId,
    attempt: AttemptId,
) -> Result<Option<Vec<u8>>> {
    conn.prepare_cached("SELECT summary FROM attempts WHERE id = ?1 AND tenant_id = ?2")?
        .query_row(params![attempt.as_bytes(), tenant.as_bytes()], |r| r.get(0))
        .optional()?
        .ok_or(Error::NotFound)
}

/// What the worker needs to evaluate the job's expressions: identity of the
/// run, repository and job, the event that triggered it, the dependency
/// outcomes by name, and whether cancellation is desired. `tenant` and
/// `trust` are the cache boundary (protocol 6): the tenant the run belongs
/// to and the trust class derived here, once, from the recorded event —
/// `pull_request` scopes to pull-request state, everything else to
/// protected (docs/cache.md).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JobContext {
    /// The tenant the run belongs to; every cache scope is under it.
    pub tenant: TenantId,
    pub run: RunId,
    pub repo: RepoId,
    pub repo_name: String,
    pub job: JobId,
    pub job_name: String,
    pub sha: String,
    /// The event facts recorded as the run's provenance.
    pub event: crate::provenance::EventFacts,
    /// `sentinel_protocol::cache::Trust::of_event` applied to `event.name`:
    /// exactly `pull_request` is pull-request trust, every other event —
    /// or none recorded — is protected. Derived here so no consumer can
    /// pick a different rule.
    pub trust: sentinel_protocol::cache::Trust,
    pub cancelled: bool,
    /// `(dependency job name, outcome)` for every `needs` entry.
    pub needs: Vec<(String, Outcome)>,
}

type ContextRow = (
    [u8; 16],
    [u8; 16],
    [u8; 16],
    String,
    [u8; 16],
    String,
    String,
    i64,
    i64,
);

/// Context for an attempt the worker holds. One statement for the identity
/// row, one for the run's job states; the spec (already sent to the worker)
/// names the dependencies.
pub fn job_context(conn: &Connection, worker: WorkerId, attempt: AttemptId) -> Result<JobContext> {
    let row: Option<ContextRow> = conn
        .prepare_cached(
            "SELECT j.tenant_id, j.run_id, r.repo_id, p.name, j.id, j.name, r.source_sha,
                    j.cancel_requested, j.spec_index
             FROM attempts a JOIN jobs j ON j.id = a.job_id JOIN runs r ON r.id = j.run_id
             JOIN repos p ON p.id = r.repo_id
             WHERE a.id = ?1 AND a.worker_id = ?2 AND a.released_ms IS NULL",
        )?
        .query_row(params![attempt.as_bytes(), worker.as_bytes()], |r| {
            Ok((
                r.get(0)?,
                r.get(1)?,
                r.get(2)?,
                r.get(3)?,
                r.get(4)?,
                r.get(5)?,
                r.get(6)?,
                r.get(7)?,
                r.get(8)?,
            ))
        })
        .optional()?;
    let Some((tenant, run, repo, repo_name, job, job_name, sha, cancel, index)) = row else {
        return Err(Error::NotFound);
    };
    let tenant = TenantId::from_bytes(tenant).map_err(|_| Error::Corrupt("tenant_id"))?;
    let run = RunId::from_bytes(run).map_err(|_| Error::Corrupt("run_id"))?;
    let states = runs::run_jobs(conn, tenant, run)?;
    let spec = runs::get_run_spec(conn, tenant, run)?;
    let compiled = spec
        .pipeline
        .jobs
        .get(usize::try_from(index).map_err(|_| Error::Corrupt("spec_index"))?)
        .ok_or(Error::Corrupt("run_specs.spec"))?;
    let mut needs = Vec::with_capacity(compiled.needs.len());
    for need in &compiled.needs {
        let upstream = spec
            .pipeline
            .jobs
            .get(usize::from(*need))
            .ok_or(Error::Corrupt("run_specs.spec"))?;
        let state = states
            .get(usize::from(*need))
            .map(|(_, s)| *s)
            .ok_or(Error::Corrupt("run_specs.spec"))?;
        let JobState::Terminal(outcome) = state else {
            // A queued job's dependencies are terminal by construction.
            return Err(Error::Corrupt("dependency not terminal"));
        };
        needs.push((upstream.name.clone(), outcome));
    }
    let event = crate::provenance::event_facts(conn, run)?;
    Ok(JobContext {
        tenant,
        run,
        repo: RepoId::from_bytes(repo).map_err(|_| Error::Corrupt("repo_id"))?,
        repo_name,
        job: JobId::from_bytes(job).map_err(|_| Error::Corrupt("job_id"))?,
        job_name,
        sha,
        trust: sentinel_protocol::cache::Trust::of_event(&event.name),
        event,
        cancelled: cancel != 0,
        needs,
    })
}

/// Whether the attempt is reserved on `worker` and not yet released: the
/// gate for log frames and reports.
pub fn is_held(conn: &Connection, worker: WorkerId, attempt: AttemptId) -> Result<bool> {
    Ok(conn
        .prepare_cached(
            "SELECT EXISTS(SELECT 1 FROM attempts WHERE id = ?1 AND worker_id = ?2 AND released_ms IS NULL)",
        )?
        .query_row(params![attempt.as_bytes(), worker.as_bytes()], |r| r.get(0))?)
}

/// The tenant/run/job/spec-index a held attempt executes under — the
/// artifact publisher's scope. `NotFound` when the attempt is not held by
/// `worker` (released, foreign or unknown), so a stale fence cannot publish.
pub fn attempt_scope(
    conn: &Connection,
    worker: WorkerId,
    attempt: AttemptId,
) -> Result<(TenantId, RunId, JobId, u32)> {
    let Some((tenant, run, job, index)) = conn
        .prepare_cached(
            "SELECT j.tenant_id, j.run_id, j.id, j.spec_index
             FROM attempts a JOIN jobs j ON j.id = a.job_id
             WHERE a.id = ?1 AND a.worker_id = ?2 AND a.released_ms IS NULL",
        )?
        .query_row(params![attempt.as_bytes(), worker.as_bytes()], |r| {
            Ok((
                r.get::<_, Vec<u8>>(0)?,
                r.get::<_, Vec<u8>>(1)?,
                r.get::<_, Vec<u8>>(2)?,
                r.get::<_, i64>(3)?,
            ))
        })
        .optional()?
    else {
        return Err(Error::NotFound);
    };
    Ok((
        TenantId::from_bytes(
            <[u8; 16]>::try_from(tenant.as_slice()).map_err(|_| Error::Corrupt("tenant_id"))?,
        )
        .map_err(|_| Error::Corrupt("tenant_id"))?,
        RunId::from_bytes(
            <[u8; 16]>::try_from(run.as_slice()).map_err(|_| Error::Corrupt("run_id"))?,
        )
        .map_err(|_| Error::Corrupt("run_id"))?,
        JobId::from_bytes(
            <[u8; 16]>::try_from(job.as_slice()).map_err(|_| Error::Corrupt("job_id"))?,
        )
        .map_err(|_| Error::Corrupt("job_id"))?,
        u32::try_from(index).map_err(|_| Error::Corrupt("spec_index"))?,
    ))
}

/// The attempt's run/job for log purposes: owned by that worker, released
/// or not. A released attempt may still receive retransmitted frames and its
/// end — the log is evidence, and late bytes only complete the record. The
/// verdict itself was already decided.
pub fn attempt_log_scope(
    conn: &Connection,
    worker: WorkerId,
    attempt: AttemptId,
) -> Result<(RunId, JobId)> {
    let Some((run, job)) = conn
        .prepare_cached(
            "SELECT j.run_id, j.id FROM attempts a JOIN jobs j ON j.id = a.job_id
             WHERE a.id = ?1 AND a.worker_id = ?2",
        )?
        .query_row(params![attempt.as_bytes(), worker.as_bytes()], |r| {
            Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, Vec<u8>>(1)?))
        })
        .optional()?
    else {
        return Err(Error::NotFound);
    };
    Ok((
        RunId::from_bytes(
            <[u8; 16]>::try_from(run.as_slice()).map_err(|_| Error::Corrupt("run_id"))?,
        )
        .map_err(|_| Error::Corrupt("run_id"))?,
        JobId::from_bytes(
            <[u8; 16]>::try_from(job.as_slice()).map_err(|_| Error::Corrupt("job_id"))?,
        )
        .map_err(|_| Error::Corrupt("job_id"))?,
    ))
}

/// The encoded run spec of an attempt the worker holds, exactly as stored.
pub fn spec_bytes(conn: &Connection, worker: WorkerId, attempt: AttemptId) -> Result<Vec<u8>> {
    conn.prepare_cached(
        "SELECT s.spec FROM attempts a JOIN jobs j ON j.id = a.job_id
         JOIN run_specs s ON s.run_id = j.run_id
         WHERE a.id = ?1 AND a.worker_id = ?2 AND a.released_ms IS NULL",
    )?
    .query_row(params![attempt.as_bytes(), worker.as_bytes()], |r| r.get(0))
    .optional()?
    .ok_or(Error::NotFound)
}

/// Decide every blocked job of the run whose dependencies have all finished:
/// queue it, or skip it when a dependency rules it out. Reads the spec once,
/// and only when the run still has a blocked job.
pub fn release_dependents(
    tx: &Transaction<'_>,
    tenant: TenantId,
    run: RunId,
    now: UnixMillis,
) -> Result<usize> {
    let states = runs::run_jobs(tx, tenant, run)?;
    if !states.iter().any(|(_, s)| *s == JobState::Blocked) {
        return Ok(0);
    }
    let spec = runs::get_run_spec(tx, tenant, run)?;
    let mut released = 0;
    for (index, (job, state)) in states.iter().enumerate() {
        if *state != JobState::Blocked {
            continue;
        }
        let Some(compiled) = spec.pipeline.jobs.get(index) else {
            return Err(Error::Corrupt("run_specs.spec"));
        };
        let mut decision = Some(true);
        for need in &compiled.needs {
            let upstream = states
                .get(usize::from(*need))
                .map(|(_, s)| *s)
                .ok_or(Error::Corrupt("run_specs.spec"))?;
            match dependency_decision(DependencyPolicy::OnSuccess, upstream) {
                Some(true) => {}
                Some(false) => {
                    decision = Some(false);
                    break;
                }
                None => {
                    decision = None;
                    break;
                }
            }
        }
        let event = match decision {
            Some(true) => Event::DependenciesSatisfied,
            Some(false) => Event::Skip,
            None => continue,
        };
        jobs::transition(tx, tenant, *job, Actor::Controller, event, now)?;
        released += 1;
    }
    Ok(released)
}

/// Why a job is not running, as the plan's structured reason.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WaitReason {
    /// Blocked on a dependency that has not finished.
    Dependency,
    /// Ready, but not admissible: the image is not resolved yet, or
    /// cancellation is pending.
    Policy(&'static str),
    /// No enrolled worker of a pool this tenant may use could ever fit it.
    NoMatchingWorker { cpu_short: i64, memory_short: i64 },
    /// Workers could fit its CPU and memory, but none that reported disk has
    /// room for the scratch it reserves.
    DiskShort { disk_short: i64 },
    /// No worker of an admissible pool runs the architecture it asks for.
    ArchMismatch,
    /// No worker of an admissible pool carries every label it asks for.
    LabelMissing,
    /// A live run of the tenant still holds its concurrency group.
    ConcurrencyLimit,
    /// Workers that could fit it exist, but none is connected.
    WorkerOffline,
    /// A connected worker could fit it once its current work releases.
    Capacity,
    /// Every worker that could fit it is draining.
    Drain,
    /// A connected worker has the capacity, but placement is holding it for
    /// a waiting large job or for pull-request feedback.
    FairnessHold,
    /// A worker that has its image warm is expected to free inside the
    /// bounded locality wait; past the bound any eligible worker takes it.
    LocalityWait,
}

/// One waiting job and why it has not started, for the queue listing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueuedJob {
    pub job: JobId,
    pub run: RunId,
    pub repo: RepoId,
    /// How long it has waited, from the controller's clock at this read;
    /// zero for a job still blocked on its dependencies.
    pub age_ms: i64,
    pub reason: WaitReason,
}

/// Every waiting job of a tenant — ready and blocked — oldest queued first,
/// each with the live reason it has not started. No cap here: the caller
/// bounds what it renders. `connected` is the controller's live session set,
/// the one fact the database does not hold.
pub fn list_queue(
    conn: &Connection,
    tenant: TenantId,
    connected: &[WorkerId],
) -> Result<Vec<QueuedJob>> {
    let now = UnixMillis::now();
    let mut stmt = conn.prepare_cached(
        "SELECT j.id, j.run_id, r.repo_id, j.queued_ms
         FROM jobs j JOIN runs r ON r.id = j.run_id
         WHERE j.tenant_id = ?1 AND j.state_code IN (0, ?2)
         ORDER BY j.queued_ms IS NULL, j.queued_ms, j.created_seq",
    )?;
    let rows = stmt.query_map(params![tenant.as_bytes(), READY], |r| {
        Ok((
            r.get::<_, [u8; 16]>(0)?,
            r.get::<_, [u8; 16]>(1)?,
            r.get::<_, [u8; 16]>(2)?,
            r.get::<_, Option<i64>>(3)?,
        ))
    })?;
    let mut out = Vec::new();
    for row in rows {
        let (job, run, repo, queued) = row?;
        let job = JobId::from_bytes(job).map_err(|_| Error::Corrupt("job_id"))?;
        out.push(QueuedJob {
            job,
            run: RunId::from_bytes(run).map_err(|_| Error::Corrupt("run_id"))?,
            repo: RepoId::from_bytes(repo).map_err(|_| Error::Corrupt("repo_id"))?,
            age_ms: queued.map_or(0, |queued| now.0.saturating_sub(queued).max(0)),
            reason: wait_reason(conn, tenant, job, connected)?,
        });
    }
    Ok(out)
}

type WaitRow = (
    i64,
    i64,
    i64,
    i64,
    i64,
    Option<String>,
    Vec<u8>,
    Option<i64>,
    [u8; 16],
    Option<String>,
    Option<String>,
    i64,
    Option<String>,
    bool,
    i64,
);

/// Explain a queued or blocked job. `connected` is the controller's live
/// session set — the one fact the database does not hold.
pub fn wait_reason(
    conn: &Connection,
    tenant: TenantId,
    job: JobId,
    connected: &[WorkerId],
) -> Result<WaitReason> {
    let row: Option<WaitRow> = conn
        .prepare_cached(
            "SELECT j.state_code, j.cpu_millis, j.memory_bytes, j.disk_bytes, j.cancel_requested,
                    j.arch, j.labels, j.queued_ms, j.run_id, j.image_digest, j.image_platform,
                    j.spec_index, j.concurrency_group,
                    j.image_digest IS NOT NULL AND j.image_platform IS NOT NULL,
                    COALESCE(p.trigger = 'pull_request', 0)
             FROM jobs j LEFT JOIN run_provenance p ON p.run_id = j.run_id
             WHERE j.id = ?1 AND j.tenant_id = ?2",
        )?
        .query_row(params![job.as_bytes(), tenant.as_bytes()], |r| {
            Ok((
                r.get(0)?,
                r.get(1)?,
                r.get(2)?,
                r.get(3)?,
                r.get(4)?,
                r.get(5)?,
                r.get(6)?,
                r.get(7)?,
                r.get(8)?,
                r.get(9)?,
                r.get(10)?,
                r.get(11)?,
                r.get(12)?,
                r.get(13)?,
                r.get(14)?,
            ))
        })
        .optional()?;
    let Some((
        code,
        cpu,
        memory,
        disk,
        cancel,
        arch,
        labels,
        queued,
        run,
        digest,
        platform,
        spec_index,
        group,
        resolved,
        pull_request,
    )) = row
    else {
        return Err(Error::NotFound);
    };
    match decode_state(code).ok_or(Error::Corrupt("state_code"))? {
        JobState::Blocked => return Ok(WaitReason::Dependency),
        JobState::Queued => {}
        _ => return Err(Error::InvalidInput("job is not waiting")),
    }
    if cancel != 0 {
        return Ok(WaitReason::Policy("cancel requested"));
    }
    if !resolved {
        return Ok(WaitReason::Policy("image unresolved"));
    }
    let run = RunId::from_bytes(run).map_err(|_| Error::Corrupt("run_id"))?;
    // `place` never considers a job whose group another run of the tenant
    // still holds; saying `capacity` here would be a lie.
    if let Some(group) = group.as_deref() {
        let held: bool = conn
            .prepare_cached(
                "SELECT EXISTS(SELECT 1 FROM jobs o
                 WHERE o.tenant_id = ?1 AND o.concurrency_group = ?2 AND o.run_id <> ?3
                   AND o.state_code < ?4)",
            )?
            .query_row(
                params![tenant.as_bytes(), group, run.as_bytes(), TERMINAL_BASE],
                |r| r.get(0),
            )?;
        if held {
            return Ok(WaitReason::ConcurrencyLimit);
        }
    }
    let pick = Pick {
        tenant,
        job,
        run,
        cpu_millis: cpu,
        memory_bytes: memory,
        disk_bytes: disk,
        image_digest: digest.unwrap_or_default(),
        image_platform: platform.unwrap_or_default(),
        spec_index,
        arch,
        labels,
        pull_request: pull_request != 0,
        queued_ms: queued.unwrap_or(0),
    };
    let workers = pool_workers(conn, tenant)?;
    let (mut best_cpu, mut best_memory, mut best_disk) = (0i64, 0i64, 0i64);
    let (mut arch_ok, mut labels_ok, mut fits_compute, mut fits_disk) =
        (false, false, false, false);
    let (mut draining_fit, mut offline_fit) = (false, false);
    let mut connected_fit: Option<&(WorkerId, WorkerFacts)> = None;
    for entry in &workers {
        let (id, facts) = entry;
        let arch_matches = pick
            .arch
            .as_deref()
            .is_none_or(|arch| arch == facts.arch.as_str());
        let labels_match = labels_subset(&pick.labels, &facts.labels)?;
        if arch_matches && labels_match {
            best_cpu = best_cpu.max(facts.cpu_millis);
            best_memory = best_memory.max(facts.memory_bytes);
        }
        if !arch_matches {
            continue;
        }
        arch_ok = true;
        if !labels_match {
            continue;
        }
        labels_ok = true;
        if facts.cpu_millis < pick.cpu_millis || facts.memory_bytes < pick.memory_bytes {
            continue;
        }
        fits_compute = true;
        best_disk = best_disk.max(facts.disk_bytes);
        if pick.disk_bytes > 0 && facts.disk_reported && facts.disk_bytes < pick.disk_bytes {
            continue;
        }
        fits_disk = true;
        if facts.draining {
            draining_fit = true;
        } else if connected.contains(id) {
            if connected_fit.is_none() {
                connected_fit = Some(entry);
            }
        } else {
            offline_fit = true;
        }
    }
    if !arch_ok {
        // No worker at all is a capacity story, not an architecture one: a
        // suspended tenant or an empty pool must not be told to change arch.
        return Ok(if workers.is_empty() {
            WaitReason::NoMatchingWorker {
                cpu_short: pick.cpu_millis,
                memory_short: pick.memory_bytes,
            }
        } else {
            WaitReason::ArchMismatch
        });
    }
    if !labels_ok {
        return Ok(WaitReason::LabelMissing);
    }
    if !fits_compute {
        return Ok(WaitReason::NoMatchingWorker {
            cpu_short: (pick.cpu_millis - best_cpu).max(0),
            memory_short: (pick.memory_bytes - best_memory).max(0),
        });
    }
    if !fits_disk {
        return Ok(WaitReason::DiskShort {
            disk_short: (pick.disk_bytes - best_disk).max(0),
        });
    }
    if let Some((worker, facts)) = connected_fit {
        let free = free_capacity(conn, *worker)?;
        let free_fits = free.cpu_millis >= pick.cpu_millis
            && free.memory_bytes >= pick.memory_bytes
            && (pick.disk_bytes == 0 || !facts.disk_reported || free.disk_bytes >= pick.disk_bytes);
        if free_fits {
            let fairness = waiting_fairness(conn, *worker, facts.pool, facts)?;
            if fairness_hold(&fairness, &pick, free.cpu_millis) {
                return Ok(WaitReason::FairnessHold);
            }
            let cold = image_key(&pick.image_digest)
                .is_some_and(|key| !caches_image(&facts.avail_images, &key));
            if cold {
                let view = locality_view(conn, tenant, *worker)?;
                if locality_hold(&view, &pick, UnixMillis::now())? {
                    return Ok(WaitReason::LocalityWait);
                }
            }
        }
        return Ok(WaitReason::Capacity);
    }
    if draining_fit {
        return Ok(WaitReason::Drain);
    }
    if offline_fit {
        return Ok(WaitReason::WorkerOffline);
    }
    Ok(WaitReason::Capacity)
}
