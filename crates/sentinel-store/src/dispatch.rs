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

use rusqlite::{Connection, OptionalExtension, Transaction, named_params, params};
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
/// The worker protocol's constant: the worker measures the same duration
/// from its own heartbeat, never by comparing wall clocks.
pub const DEFAULT_LEASE_MS: i64 = sentinel_protocol::limits::LEASE_MS;
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

/// [`free_capacity`]'s statement: one pass over the held-attempts partial
/// index, driven from `workers` into `attempts_held_by_worker` (asserted by
/// a test), so summing held attempts never scans the attempts table.
const FREE_CAPACITY_SQL: &str = "SELECT w.cpu_millis - COALESCE((
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
     FROM workers w WHERE w.id = ?1 AND w.revoked_ms IS NULL";

/// What the worker has left: its reported capacity less every attempt still
/// held that the host counts. Attempts of every worker sharing the same
/// `host_id` are subtracted — worker identities on one machine must not
/// each claim the whole machine's memory, CPU or scratch — while a worker
/// with no host on record accounts for its own attempts alone. Values may
/// go negative when a report shrinks under existing reservations.
pub fn free_capacity(conn: &Connection, worker: WorkerId) -> Result<Capacity> {
    conn.prepare_cached(FREE_CAPACITY_SQL)?
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

/// Whether every label the job asks for is one the worker carries, over the
/// encoded blobs as stored. Both are sorted and deduplicated by
/// [`encode_labels`] (byte order), so containment is one merge walk with no
/// allocation. An empty request is satisfied by any worker; a request the
/// worker never reported is not. This is also the SQL function
/// `sentinel_labels_subset` placement filters with (see
/// [`crate::register_functions`]), so the candidate scan and every Rust-side
/// check answer the same question the same way.
pub fn labels_subset(job: &[u8], worker: &[u8]) -> bool {
    if job.is_empty() {
        return true;
    }
    let mut have = worker.split(|b| *b == b'\n').filter(|l| !l.is_empty());
    'wanted: for label in job.split(|b| *b == b'\n') {
        for held in have.by_ref() {
            match held.cmp(label) {
                std::cmp::Ordering::Less => {}
                std::cmp::Ordering::Equal => continue 'wanted,
                std::cmp::Ordering::Greater => return false,
            }
        }
        return false;
    }
    true
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
    repo: Option<[u8; 16]>,
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
    requires_secret_delivery: bool,
    queued_ms: i64,
    /// The fair-order key after `queued_ms`: the keyset a next page resumes
    /// from.
    priority: i64,
    created_seq: i64,
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
    secret_delivery: bool,
}
type WorkerFactsRow = (
    [u8; 16],
    String,
    Vec<u8>,
    bool,
    i64,
    Vec<u8>,
    i64,
    i64,
    i64,
    i64,
);

/// Whether a worker can receive a secret bundle: the capability bit **and**
/// a negotiated protocol that carries it (P10D-6). A session that sets the
/// bit on an older protocol would be placed a job it can only fail.
fn secret_capable(capabilities: i64, protocol: i64) -> bool {
    protocol >= 10
        && capabilities as u64 & sentinel_protocol::negotiate::Capabilities::SECRET_DELIVERY.0 != 0
}

fn worker_facts(conn: &Connection, worker: WorkerId) -> Result<Option<(WorkerId, WorkerFacts)>> {
    let row: Option<WorkerFactsRow> = conn
        .prepare_cached(
            "SELECT pool_id, arch, labels, drain_ms IS NOT NULL, disk_bytes, avail_images,
                    cpu_millis, memory_bytes, capabilities, protocol
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
                r.get(8)?,
                r.get(9)?,
            ))
        })
        .optional()?;
    let Some((
        pool,
        arch,
        labels,
        draining,
        disk_bytes,
        avail_images,
        cpu,
        memory,
        capabilities,
        protocol,
    )) = row
    else {
        return Ok(None);
    };
    Ok(Some((
        worker,
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
            secret_delivery: secret_capable(capabilities, protocol),
        },
    )))
}

/// Every worker of a pool the tenant may use: the candidate set the queue
/// explanation reads. Pool access is A07's rule — tenant active, pool
/// active, owner or explicitly granted — evaluated per call so suspension
/// and withdrawal stop the next transaction.
fn pool_workers(conn: &Connection, tenant: TenantId) -> Result<Vec<(WorkerId, WorkerFacts)>> {
    let mut stmt = conn.prepare_cached(
        "SELECT w.id, w.pool_id, w.arch, w.labels, w.drain_ms IS NOT NULL, w.disk_bytes,
                w.avail_images, w.cpu_millis, w.memory_bytes, w.capabilities, w.protocol
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
            r.get::<_, i64>(9)?,
            r.get::<_, i64>(10)?,
        ))
    })?;
    let mut out = Vec::new();
    for row in rows {
        let (id, pool, arch, labels, draining, disk, images, cpu, memory, capabilities, protocol) =
            row?;
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
                secret_delivery: secret_capable(capabilities, protocol),
            },
        ));
    }
    Ok(out)
}

// Placement's shared predicates. They are string literals spliced into each
// statement with `concat!`, so every statement that asks "could this job run
// here?" asks it with the same words, and `state_code = 1` stays a literal
// (see "Placement cost" in docs/storage.md).

/// A ready job `j` that fits the bounds `:arch`, `:cpu`, `:memory`,
/// `:disk_reported`/`:disk` and carries only labels in `:labels`. Labels are
/// tested here, before any `LIMIT`, so a page of label-mismatched jobs can
/// never hide a fitting one (P08-4); the unlabeled case never calls the
/// function.
macro_rules! eligible_sql {
    () => {
        "j.state_code = 1 AND j.cancel_requested = 0
           AND j.image_digest IS NOT NULL AND j.image_platform IS NOT NULL
           AND (j.arch IS NULL OR j.arch = :arch)
           AND j.cpu_millis <= :cpu AND j.memory_bytes <= :memory
           AND (j.disk_bytes = 0 OR :disk_reported = 0 OR j.disk_bytes <= :disk)
           AND (j.requires_secret_delivery = 0 OR :worker_secret_delivery = 1)
           AND (j.labels = X'' OR sentinel_labels_subset(j.labels, :labels))"
    };
}

/// `j`'s concurrency group is free for it: no other run of the same
/// (tenant, repository, group) has a job a worker owns (`Leased` through
/// `Finalizing`), and no *older* run — by `(created_ms, id)`, a total order —
/// has any live job. A queued run therefore waits only for runs ahead of it,
/// so two queued runs of a serializing group never block each other (P08-1).
/// `16` is `TERMINAL_BASE` and `2` is `Leased` (asserted below).
macro_rules! group_free_sql {
    () => {
        "(j.concurrency_group IS NULL OR NOT EXISTS (
             SELECT 1 FROM jobs o JOIN runs ro ON ro.id = o.run_id
             WHERE o.tenant_id = j.tenant_id AND o.repo_id = j.repo_id
               AND o.concurrency_group = j.concurrency_group
               AND o.run_id <> j.run_id AND o.state_code < 16
               AND (o.state_code >= 2
                    OR (ro.created_ms, ro.id)
                       < (SELECT r.created_ms, r.id FROM runs r WHERE r.id = j.run_id))))"
    };
}

/// Pool access for `j` on the pool `:pool`, joined as `t`, `p` and `g`; the
/// statement adds `(p.owner_tenant_id = j.tenant_id OR g.tenant_id IS NOT
/// NULL)` to its `WHERE`.
macro_rules! pool_access_sql {
    () => {
        "JOIN tenants t ON t.id = j.tenant_id AND t.active = 1
         JOIN pools p ON p.id = :pool AND p.active = 1
         LEFT JOIN pool_grants g ON g.pool_id = p.id AND g.tenant_id = j.tenant_id"
    };
}

const _: () = assert!(
    TERMINAL_BASE == 16,
    "group_free_sql hardcodes TERMINAL_BASE"
);
const _: () = assert!(
    crate::codec::encode_state(JobState::Leased) == 2,
    "group_free_sql hardcodes the first worker-owned state"
);

/// Rows one candidate page holds, and the pages one placement reads from one
/// (tenant, repository) stream. Every hard constraint and the fairness
/// reservations are in the SQL, so the only rows a page can spend are jobs
/// held for bounded locality; a stream whose first `PAGE * MAX_PAGES` ready
/// jobs are all waiting for a warm worker yields nothing this placement and
/// the next stream is tried — never an unbounded walk.
const PAGE: usize = 16;
const MAX_PAGES: usize = 8;

/// One (tenant, repository) stream's candidates that fit this worker's free
/// capacity now, in the fair order after the keyset, with the pool's
/// reservations applied: a job younger than the waiting large job whose
/// placement would leave less than that job's CPU free is excluded (the
/// large-job path), as is a non-PR job that would leave less than the PR
/// reserve free. `:exclusive = 1` keeps only jobs beyond what any other
/// connected worker of the pool can hold (`:far_*`, Q10).
macro_rules! candidates_sql {
    ($from:literal, $only:literal) => {
        concat!(
            "SELECT j.id, j.run_id, j.cpu_millis, j.memory_bytes, j.disk_bytes, j.image_digest,
                    j.image_platform, j.spec_index, j.arch, j.labels, j.queued_ms,
                    j.pull_request, j.priority, j.created_seq, j.requires_secret_delivery
             FROM ",
            $from,
            "
             WHERE j.tenant_id = :tenant AND j.repo_id = :repo AND ",
            $only,
            eligible_sql!(),
            "
               AND (j.priority, j.queued_ms, j.created_seq)
                   > (:after_priority, :after_queued, :after_seq)
               AND NOT (j.cpu_millis < :large AND :cpu - j.cpu_millis < :large
                        AND j.queued_ms >= :large_since)
               AND NOT (j.pull_request = 0 AND :cpu - j.cpu_millis < :pr_reserve)
               AND (:exclusive = 0 OR j.cpu_millis > :far_cpu OR j.memory_bytes > :far_memory
                    OR j.disk_bytes > :far_disk)
               AND ",
            group_free_sql!(),
            "
             ORDER BY j.priority, j.queued_ms, j.created_seq
             LIMIT 16"
        )
    };
}

const CANDIDATES_SQL: &str = candidates_sql!("jobs j INDEXED BY jobs_ready_repo", "");

/// [`CANDIDATES_SQL`] over ready pull-request jobs only, for a worker whose
/// free room is at or inside the PR reserve: no other job can pass the
/// reserve there, and walking the stream's whole ready index to reject each
/// one was the cost of every such placement.
const PR_CANDIDATES_SQL: &str =
    candidates_sql!("jobs j INDEXED BY jobs_ready_pr", "j.pull_request = 1 AND ");

const _: () = assert!(PAGE == 16, "CANDIDATES_SQL hardcodes the page size");

/// Tenants the pool admits that have ready work: one `EXISTS` descent per
/// tenant into the ready index, never a `GROUP BY` over the whole ready set.
/// Pool access is decided here once per placement instead of per candidate.
const READY_TENANTS_SQL: &str = "SELECT t.id FROM tenants t
     JOIN pools p ON p.id = ?1 AND p.active = 1
     LEFT JOIN pool_grants g ON g.pool_id = p.id AND g.tenant_id = t.id
     WHERE t.active = 1 AND (p.owner_tenant_id = t.id OR g.tenant_id IS NOT NULL)
       AND EXISTS(
         SELECT 1 FROM jobs j
         WHERE j.tenant_id = t.id AND j.state_code = 1
           AND j.cancel_requested = 0 AND j.image_digest IS NOT NULL
         LIMIT 1)";

fn ready_tenants(conn: &Connection, pool: PoolId) -> Result<Vec<TenantId>> {
    let mut stmt = conn.prepare_cached(READY_TENANTS_SQL)?;
    let rows = stmt.query_map([pool.as_bytes()], |r| r.get::<_, [u8; 16]>(0))?;
    let mut out = Vec::new();
    for row in rows {
        out.push(TenantId::from_bytes(row?).map_err(|_| Error::Corrupt("tenant_id"))?);
    }
    Ok(out)
}

/// A tenant's repositories with ready work, each with the fair-order key of
/// its head job: a loose index scan over `jobs_ready_repo` (one `MIN` seek
/// per ready repository), never a scan of the tenant's ready jobs.
const READY_REPOS_SQL: &str = "WITH RECURSIVE ready(repo) AS (
         SELECT (SELECT MIN(j.repo_id) FROM jobs j
                 WHERE j.tenant_id = ?1 AND j.state_code = 1)
         UNION ALL
         SELECT (SELECT MIN(j.repo_id) FROM jobs j
                 WHERE j.tenant_id = ?1 AND j.state_code = 1 AND j.repo_id > ready.repo)
         FROM ready WHERE ready.repo IS NOT NULL)
     SELECT ready.repo,
            (SELECT j.priority FROM jobs j
             WHERE j.tenant_id = ?1 AND j.repo_id = ready.repo AND j.state_code = 1
             ORDER BY j.priority, j.queued_ms, j.created_seq LIMIT 1),
            (SELECT j.queued_ms FROM jobs j
             WHERE j.tenant_id = ?1 AND j.repo_id = ready.repo AND j.state_code = 1
             ORDER BY j.priority, j.queued_ms, j.created_seq LIMIT 1)
     FROM ready WHERE ready.repo IS NOT NULL";

/// Millicpu a tenant's (or one repository's) unreleased attempts hold:
/// index-only sums over the covering `attempts_held_by_repo`.
const TENANT_HELD_SQL: &str = "SELECT COALESCE(SUM(cpu_millis), 0) FROM attempts
     WHERE tenant_id = ?1 AND released_ms IS NULL";
const REPO_HELD_SQL: &str = "SELECT COALESCE(SUM(cpu_millis), 0) FROM attempts
     WHERE tenant_id = ?1 AND repo_id = ?2 AND released_ms IS NULL";

/// One (tenant, repository) queue of ready work and where it stands in the
/// fair order.
#[derive(Clone, Debug)]
struct Stream {
    tenant: TenantId,
    repo: [u8; 16],
    /// `(tenant held millicpu, repository held millicpu, head priority, head
    /// queued_ms)`: the tenant executing least goes first, then within it the
    /// repository executing least, then the one whose head job has waited
    /// longest (aging). A repository with a thousand-job backlog therefore
    /// takes turns with its siblings instead of draining first (P08-5).
    key: (i64, i64, i64, i64),
}

/// The fair order over every admitted tenant's ready repositories. Held
/// sums are skipped where there is nothing to rank: with one ready tenant
/// the tenant term, and with one ready repository in a tenant its repository
/// term.
fn streams(conn: &Connection, tenants: &[TenantId]) -> Result<Vec<Stream>> {
    let mut repos_stmt = conn.prepare_cached(READY_REPOS_SQL)?;
    let mut out = Vec::new();
    for tenant in tenants {
        let tenant_held: i64 = if tenants.len() > 1 {
            conn.prepare_cached(TENANT_HELD_SQL)?
                .query_row([tenant.as_bytes()], |r| r.get(0))?
        } else {
            0
        };
        let first = out.len();
        let rows = repos_stmt.query_map([tenant.as_bytes()], |r| {
            Ok((
                r.get::<_, [u8; 16]>(0)?,
                r.get::<_, Option<i64>>(1)?,
                r.get::<_, Option<i64>>(2)?,
            ))
        })?;
        for row in rows {
            let (repo, priority, queued) = row?;
            out.push(Stream {
                tenant: *tenant,
                repo,
                key: (
                    tenant_held,
                    0,
                    priority.unwrap_or(i64::MAX),
                    queued.unwrap_or(i64::MAX),
                ),
            });
        }
        if out.len() - first > 1 {
            let mut held = conn.prepare_cached(REPO_HELD_SQL)?;
            for stream in &mut out[first..] {
                stream.key.1 =
                    held.query_row(params![tenant.as_bytes(), stream.repo], |r| r.get(0))?;
            }
        }
    }
    out.sort_by(|a, b| {
        a.key
            .cmp(&b.key)
            .then_with(|| a.tenant.as_bytes().cmp(b.tenant.as_bytes()))
            .then_with(|| a.repo.cmp(&b.repo))
    });
    Ok(out)
}

/// What waiting work reserves on a worker: a path for the largest waiting
/// large job and, while a pull-request job waits, a quarter of the host.
/// Both count only jobs *this worker could run* — its pool admits the
/// tenant, and the job's architecture, labels, resources and group allow it
/// here — so a job in another pool, or one no worker here can ever run,
/// reserves nothing (P08-2).
#[derive(Clone, Copy, Debug, Default)]
struct Fairness {
    /// `(cpu_millis, queued_ms)` of the largest such job at or above
    /// [`LARGE_JOB_CPU`], and when it first waited.
    large: Option<(i64, i64)>,
    /// Millicpu kept free for pull-request feedback; 0 when none waits.
    pr_reserve: i64,
}

/// The largest waiting job at or above [`LARGE_JOB_CPU`] this worker could
/// run, driven from the partial `jobs_ready_large` index (`state_code = 1`
/// and `8000` are literals so the index is chosen at prepare time, without
/// a re-prepare per execution).
const LARGE_WAITING_SQL: &str = concat!(
    "SELECT j.cpu_millis, j.queued_ms FROM jobs j INDEXED BY jobs_ready_large ",
    pool_access_sql!(),
    "
     WHERE j.cpu_millis >= 8000 AND ",
    eligible_sql!(),
    "
       AND (p.owner_tenant_id = j.tenant_id OR g.tenant_id IS NOT NULL)
       AND ",
    group_free_sql!(),
    "
     ORDER BY j.cpu_millis DESC LIMIT 1"
);

const _: () = assert!(
    LARGE_JOB_CPU == 8000,
    "LARGE_WAITING_SQL hardcodes the large-job threshold; migration 028's jobs_ready_large index does too"
);

/// A pull-request job this worker could run is waiting. Driven from
/// `jobs_ready_pr`, which holds ready pull-request jobs and nothing else, so
/// the common case — none waiting — is one empty index probe regardless of
/// queue depth or pull-request history (P08-9).
const PR_WAITING_SQL: &str = concat!(
    "SELECT EXISTS(SELECT 1 FROM jobs j INDEXED BY jobs_ready_pr ",
    pool_access_sql!(),
    "
     WHERE j.pull_request = 1 AND ",
    eligible_sql!(),
    "
       AND (p.owner_tenant_id = j.tenant_id OR g.tenant_id IS NOT NULL)
       AND ",
    group_free_sql!(),
    ")"
);

fn waiting_fairness(conn: &Connection, pool: PoolId, facts: &WorkerFacts) -> Result<Fairness> {
    let reported = i64::from(facts.disk_reported);
    let bounds = named_params! {
        ":pool": pool.as_bytes(),
        ":arch": facts.arch,
        ":cpu": facts.cpu_millis,
        ":memory": facts.memory_bytes,
        ":disk_reported": reported,
        ":disk": facts.disk_bytes,
        ":labels": facts.labels,
        ":worker_secret_delivery": i64::from(facts.secret_delivery),
    };
    let large: Option<(i64, i64)> = conn
        .prepare_cached(LARGE_WAITING_SQL)?
        .query_row(bounds, |r| Ok((r.get(0)?, r.get(1)?)))
        .optional()?;
    let pr: bool = conn
        .prepare_cached(PR_WAITING_SQL)?
        .query_row(bounds, |r| r.get(0))?;
    Ok(Fairness {
        large,
        // A quarter of this worker's own report, which is the whole host's
        // (several identities on one machine each measure that machine —
        // summing them would reserve the host once per identity, P08-3).
        pr_reserve: if pr {
            facts.cpu_millis / PR_RESERVE_DIVISOR
        } else {
            0
        },
    })
}

/// Whether placing `pick` would spend capacity a waiting job reserved: the
/// Rust statement of `CANDIDATES_SQL`'s reservation terms, for explanations.
fn fairness_hold(fairness: &Fairness, pick: &Pick, free_cpu: i64) -> bool {
    let after = free_cpu.saturating_sub(pick.cpu_millis);
    if let Some((need, since)) = fairness.large
        && pick.cpu_millis < need
        && after < need
        && since <= pick.queued_ms
    {
        return true;
    }
    !pick.pull_request && after < fairness.pr_reserve
}

/// A worker that could run a waiting job and has its image warm.
struct LocalityWorker {
    id: WorkerId,
    arch: String,
    labels: Vec<u8>,
    cpu_millis: i64,
    memory_bytes: i64,
    disk_bytes: i64,
    avail_images: Vec<u8>,
    /// When the earliest attempt it holds must have ended: its offer plus
    /// its job's timeout. `None` when it holds nothing. This is an upper
    /// bound on completion, never the lease deadline — renewal keeps a lease
    /// inside the locality window forever, which made every busy warm worker
    /// look about to free (P08-6).
    frees_by: Option<i64>,
}

/// Workers of pools `tenant` may use with at least one warm image, for the
/// bounded locality wait.
fn locality_view(conn: &Connection, tenant: TenantId) -> Result<Vec<LocalityWorker>> {
    let mut stmt = conn.prepare_cached(
        "SELECT w.id, w.arch, w.labels, w.cpu_millis, w.memory_bytes, w.disk_bytes,
                w.avail_images,
                (SELECT MIN(a.offered_ms + j.timeout_ms) FROM attempts a
                 JOIN jobs j ON j.id = a.job_id
                 WHERE a.worker_id = w.id AND a.released_ms IS NULL)
         FROM workers w
         JOIN pools p ON p.id = w.pool_id AND p.active = 1
         JOIN tenants t ON t.id = ?1 AND t.active = 1
         LEFT JOIN pool_grants g ON g.pool_id = p.id AND g.tenant_id = t.id
         WHERE w.revoked_ms IS NULL AND w.drain_ms IS NULL AND w.avail_images <> X''
           AND (p.owner_tenant_id = t.id OR g.tenant_id IS NOT NULL)",
    )?;
    let rows = stmt.query_map([tenant.as_bytes()], |r| {
        Ok((
            r.get::<_, [u8; 16]>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, Vec<u8>>(2)?,
            (
                r.get::<_, i64>(3)?,
                r.get::<_, i64>(4)?,
                r.get::<_, i64>(5)?,
            ),
            r.get::<_, Vec<u8>>(6)?,
            r.get::<_, Option<i64>>(7)?,
        ))
    })?;
    let mut out = Vec::new();
    for row in rows {
        let (id, arch, labels, (cpu_millis, memory_bytes, disk_bytes), avail_images, frees_by) =
            row?;
        out.push(LocalityWorker {
            id: WorkerId::from_bytes(id).map_err(|_| Error::Corrupt("worker id"))?,
            arch,
            labels,
            cpu_millis,
            memory_bytes,
            disk_bytes,
            avail_images,
            frees_by,
        });
    }
    Ok(out)
}

/// Whether this job should wait for a worker other than `exclude` that has
/// its image warm: only while it is inside [`LOCALITY_WAIT_MS`] and such a
/// worker could run it and is expected to free within the bound. Past the
/// bound any eligible worker takes it, so locality never strands work.
fn locality_hold(view: &[LocalityWorker], exclude: WorkerId, pick: &Pick, now: UnixMillis) -> bool {
    if now.0.saturating_sub(pick.queued_ms) >= LOCALITY_WAIT_MS {
        return false;
    }
    let Some(key) = image_key(&pick.image_digest) else {
        return false;
    };
    let bound = now.0.saturating_add(LOCALITY_WAIT_MS);
    view.iter().any(|worker| {
        worker.id != exclude
            && pick
                .arch
                .as_deref()
                .is_none_or(|arch| arch == worker.arch.as_str())
            && labels_subset(&pick.labels, &worker.labels)
            && worker.cpu_millis >= pick.cpu_millis
            && worker.memory_bytes >= pick.memory_bytes
            && !(pick.disk_bytes > 0
                && worker.disk_bytes > 0
                && worker.disk_bytes < pick.disk_bytes)
            && caches_image(&worker.avail_images, &key)
            && worker.frees_by.is_none_or(|until| until <= bound)
    })
}

// ——— bounded image prefetch (K05, B04) ———————————————————————————

/// Image references one worker is hinted at most.
pub const MAX_PREFETCH_HINTS: usize = 4;
/// Workers one image is hinted to per pass: the likeliest next hosts of the
/// job, not the whole fleet — a burst of one image never becomes a
/// fleet-wide pull.
pub const PREFETCH_FANOUT: usize = 2;
/// Ready jobs a pass reads, longest-waiting first. Hints are best effort:
/// work past them is hinted once it gets there.
pub const PREFETCH_SCAN: usize = 256;

/// Whether `name` — the repository part of a job's image reference — may
/// travel in a hint: 1–255 bytes of the OCI reference charset. Anything
/// else is never hinted (the job still pulls it itself when it runs).
pub fn prefetch_name(name: &str) -> bool {
    (1..=255).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'/' | b':'))
        && !name.starts_with(['/', '-', ':', '.'])
}

/// A ready job as a prefetch pass sees it.
struct PrefetchJob {
    tenant: TenantId,
    reference: String,
    key: [u8; IMAGE_KEY_BYTES],
    arch: Option<String>,
    labels: Vec<u8>,
    cpu_millis: i64,
    memory_bytes: i64,
    disk_bytes: i64,
}

/// The longest-waiting ready jobs, at most [`PREFETCH_SCAN`] read off the
/// `jobs_queued_since` partial index — never a scan or a sort of the queue.
const PREFETCH_HEAD_SQL: &str = "SELECT j.tenant_id, j.image_name, j.image_digest, j.arch,
            j.labels, j.cpu_millis, j.memory_bytes, j.disk_bytes, j.priority, j.queued_ms,
            j.created_seq
     FROM (SELECT id FROM jobs INDEXED BY jobs_queued_since WHERE state_code = 1
           ORDER BY queued_ms LIMIT ?1) h
     JOIN jobs j ON j.id = h.id
     WHERE j.cancel_requested = 0 AND j.image_name IS NOT NULL
       AND j.image_digest IS NOT NULL AND j.image_platform IS NOT NULL";

/// [`PREFETCH_HEAD_SQL`]'s rows with a hintable image, in the fair order's
/// priority-then-age sequence (sorted here: at most [`PREFETCH_SCAN`]).
fn prefetch_head(conn: &Connection) -> Result<Vec<PrefetchJob>> {
    let mut stmt = conn.prepare_cached(PREFETCH_HEAD_SQL)?;
    let rows = stmt.query_map([PREFETCH_SCAN as i64], |r| {
        Ok((
            r.get::<_, [u8; 16]>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, Option<String>>(3)?,
            r.get::<_, Vec<u8>>(4)?,
            (
                r.get::<_, i64>(5)?,
                r.get::<_, i64>(6)?,
                r.get::<_, i64>(7)?,
            ),
            (
                r.get::<_, i64>(8)?,
                r.get::<_, i64>(9)?,
                r.get::<_, i64>(10)?,
            ),
        ))
    })?;
    let mut out = Vec::new();
    for row in rows {
        let (tenant, name, digest, arch, labels, (cpu_millis, memory_bytes, disk_bytes), order) =
            row?;
        let Some(key) = image_key(&digest) else {
            continue;
        };
        if !prefetch_name(&name) {
            continue;
        }
        out.push((
            order,
            PrefetchJob {
                tenant: TenantId::from_bytes(tenant).map_err(|_| Error::Corrupt("tenant_id"))?,
                reference: format!("{name}@{digest}"),
                key,
                arch,
                labels,
                cpu_millis,
                memory_bytes,
                disk_bytes,
            },
        ));
    }
    out.sort_unstable_by_key(|(order, _)| *order);
    Ok(out.into_iter().map(|(_, job)| job).collect())
}

/// A07's pool access, asked once per (tenant, pool) a pass meets.
fn pool_admits(conn: &Connection, tenant: TenantId, pool: PoolId) -> Result<bool> {
    Ok(conn
        .prepare_cached(
            "SELECT EXISTS(SELECT 1 FROM tenants t
               JOIN pools p ON p.id = ?2 AND p.active = 1
               LEFT JOIN pool_grants g ON g.pool_id = p.id AND g.tenant_id = t.id
               WHERE t.id = ?1 AND t.active = 1
                 AND (p.owner_tenant_id = t.id OR g.tenant_id IS NOT NULL))",
        )?
        .query_row(params![tenant.as_bytes(), pool.as_bytes()], |r| r.get(0))?)
}

/// What each of `workers` should prefetch now (K05): image references of
/// ready jobs at the head of the queue that it could run and does not hold
/// warm, at most [`MAX_PREFETCH_HINTS`] per worker and [`PREFETCH_FANOUT`]
/// workers per image. Every worker named gets an entry — an empty one means
/// "nothing": a hint set replaces the last, so stale prefetches stop.
///
/// Only an idle or underused worker is hinted: one whose held attempts take
/// less than its reported CPU. The job must be one the worker could be
/// placed: its tenant may use the worker's pool (A07: tenant active, pool
/// active, owner or granted), and its architecture, labels, CPU, memory and
/// disk fit the worker's reported capacity — so a worker is only ever told
/// to pull what it would pull anyway for an eligible job, under the same
/// worker-wide registry authority (tenant-scoped registry credentials are
/// S05). A draining or revoked worker gets nothing. Within a pool, the
/// most idle workers are hinted first: they are the likeliest next hosts.
///
/// Reads only: the head of `jobs_ready` (bounded by [`PREFETCH_SCAN`]), one
/// grouped read of held CPU, one point read per worker and one access probe
/// per (tenant, pool) met.
pub fn prefetch_hints(
    conn: &Connection,
    workers: &[WorkerId],
) -> Result<Vec<(WorkerId, Vec<String>)>> {
    let mut out: Vec<(WorkerId, Vec<String>)> = workers.iter().map(|w| (*w, Vec::new())).collect();
    if workers.is_empty() || !any_ready(conn)? {
        return Ok(out);
    }
    let held = held_by_worker(conn)?;
    // (index into `out`, facts, free CPU) of every worker a hint may reach.
    let mut eligible: Vec<(usize, WorkerFacts, i64)> = Vec::new();
    for (index, worker) in workers.iter().enumerate() {
        let Some((_, facts)) = worker_facts(conn, *worker)? else {
            continue;
        };
        let free = facts.cpu_millis - held.get(worker).copied().unwrap_or(0);
        if facts.draining || free <= 0 {
            continue;
        }
        eligible.push((index, facts, free));
    }
    if eligible.is_empty() {
        return Ok(out);
    }
    // Most idle first; the id keeps the order stable between passes, so an
    // unchanged queue yields an unchanged hint set.
    eligible.sort_by(|a, b| b.2.cmp(&a.2).then(workers[a.0].cmp(&workers[b.0])));
    let head = prefetch_head(conn)?;
    let mut access: HashMap<(TenantId, PoolId), bool> = HashMap::new();
    let mut hinted: HashMap<&str, usize> = HashMap::new();
    for job in &head {
        let count = hinted.entry(job.reference.as_str()).or_insert(0);
        for (index, facts, _) in &eligible {
            if *count >= PREFETCH_FANOUT {
                break;
            }
            let hints = &mut out[*index].1;
            if hints.len() >= MAX_PREFETCH_HINTS
                || hints.contains(&job.reference)
                || caches_image(&facts.avail_images, &job.key)
                || job.arch.as_deref().is_some_and(|arch| arch != facts.arch)
                || !labels_subset(&job.labels, &facts.labels)
                || job.cpu_millis > facts.cpu_millis
                || job.memory_bytes > facts.memory_bytes
                || (job.disk_bytes > 0 && facts.disk_reported && job.disk_bytes > facts.disk_bytes)
            {
                continue;
            }
            let admits = match access.get(&(job.tenant, facts.pool)) {
                Some(admits) => *admits,
                None => {
                    let admits = pool_admits(conn, job.tenant, facts.pool)?;
                    access.insert((job.tenant, facts.pool), admits);
                    admits
                }
            };
            if !admits {
                continue;
            }
            hints.push(job.reference.clone());
            *count += 1;
        }
    }
    Ok(out)
}

/// The locality views one placement has read, per tenant, and whether any
/// worker reported an image at all (when none has, locality never holds and
/// no view is read).
#[derive(Default)]
struct LocalityCache {
    any_images: Option<bool>,
    views: Vec<(TenantId, Vec<LocalityWorker>)>,
}

impl LocalityCache {
    fn holds(
        &mut self,
        conn: &Connection,
        worker: WorkerId,
        facts: &WorkerFacts,
        pick: &Pick,
        now: UnixMillis,
    ) -> Result<bool> {
        let cold = image_key(&pick.image_digest)
            .is_some_and(|key| !caches_image(&facts.avail_images, &key));
        if !cold {
            return Ok(false);
        }
        let any = match self.any_images {
            Some(any) => any,
            None => {
                let any: bool = conn
                    .prepare_cached(
                        "SELECT EXISTS(SELECT 1 FROM workers
                          WHERE revoked_ms IS NULL AND avail_images <> X'')",
                    )?
                    .query_row([], |r| r.get(0))?;
                self.any_images = Some(any);
                any
            }
        };
        if !any {
            return Ok(false);
        }
        let at = match self.views.iter().position(|(t, _)| *t == pick.tenant) {
            Some(at) => at,
            None => {
                self.views
                    .push((pick.tenant, locality_view(conn, pick.tenant)?));
                self.views.len() - 1
            }
        };
        Ok(locality_hold(&self.views[at].1, worker, pick, now))
    }
}

/// Place one job on `worker`: the next ready job of the pool's fair order
/// that fits the worker's free capacity, leased with its reservation in the
/// calling transaction. `None` means nothing may be placed here now — no
/// eligible job, a draining worker, or waiting work whose reservation this
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
    place_in_fleet(tx, worker, pool, None, lease_ms, now)
}

/// [`place`], told what the rest of the connected fleet can hold.
/// `elsewhere` is, per resource, the most any *other* connected worker of
/// the pool reports (disk: `i64::MAX` when one reports none, since disk is
/// then not part of its admission). A ready job that exceeds `elsewhere` in
/// any resource can run on no other connected worker, so this worker offers
/// it first, ahead of the fair order: spending the room on work a smaller
/// worker could take would strand it until this worker's work finishes (Q10).
/// Only the order changes; every hold still applies, and a job that does not
/// fit the free capacity now is not reserved for (that is Q02's large-job
/// path). The exclusive pass runs only when this worker's free room exceeds
/// `elsewhere` somewhere — otherwise no fitting job can be exclusive. `None`
/// is plain [`place`].
pub fn place_in_fleet(
    tx: &Transaction<'_>,
    worker: WorkerId,
    pool: PoolId,
    elsewhere: Option<Capacity>,
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
    let tenants = ready_tenants(tx, pool)?;
    if tenants.is_empty() {
        return Ok(None);
    }
    let fairness = waiting_fairness(tx, pool, &facts)?;
    let streams = streams(tx, &tenants)?;
    let free_disk = if facts.disk_reported {
        free.disk_bytes
    } else {
        i64::MAX
    };
    let exclusive = elsewhere.filter(|far| {
        free.cpu_millis > far.cpu_millis
            || free.memory_bytes > far.memory_bytes
            || free_disk > far.disk_bytes
    });
    let mut placement = Placement {
        tx,
        worker,
        facts: &facts,
        free,
        fairness,
        locality: LocalityCache::default(),
        now,
    };
    if let Some(far) = exclusive
        && let Some(offer) = placement.place_from_streams(&streams, Some(far), lease_ms)?
    {
        return Ok(Some(offer));
    }
    placement.place_from_streams(&streams, None, lease_ms)
}

/// One placement's facts, read once and shared by its passes.
struct Placement<'a, 't> {
    tx: &'a Transaction<'t>,
    worker: WorkerId,
    facts: &'a WorkerFacts,
    free: Capacity,
    fairness: Fairness,
    locality: LocalityCache,
    now: UnixMillis,
}

impl Placement<'_, '_> {
    /// Walk the streams in fair order and lease the first candidate not held
    /// for locality, reading each stream a page at a time.
    fn place_from_streams(
        &mut self,
        streams: &[Stream],
        far: Option<Capacity>,
        lease_ms: i64,
    ) -> Result<Option<Offer>> {
        for stream in streams {
            let mut after = (i64::MIN, i64::MIN, i64::MIN);
            for _ in 0..MAX_PAGES {
                let page = self.page(stream, far, after)?;
                let full = page.len() == PAGE;
                for pick in page {
                    after = (pick.priority, pick.queued_ms, pick.created_seq);
                    if self
                        .locality
                        .holds(self.tx, self.worker, self.facts, &pick, self.now)?
                    {
                        continue;
                    }
                    return self.lease(pick, lease_ms).map(Some);
                }
                if !full {
                    break;
                }
            }
        }
        Ok(None)
    }

    fn page(
        &self,
        stream: &Stream,
        far: Option<Capacity>,
        after: (i64, i64, i64),
    ) -> Result<Vec<Pick>> {
        let (large, large_since) = self.fairness.large.unwrap_or((0, 0));
        let far = far.map(|far| (1i64, far));
        let (exclusive, far) = far.unwrap_or((0, Capacity::default()));
        // Inside the PR reserve only a pull-request job can pass it: read
        // those from their own index rather than rejecting every other row.
        let sql =
            if self.fairness.pr_reserve > 0 && self.free.cpu_millis <= self.fairness.pr_reserve {
                PR_CANDIDATES_SQL
            } else {
                CANDIDATES_SQL
            };
        let mut stmt = self.tx.prepare_cached(sql)?;
        let rows = stmt.query_map(
            named_params! {
                ":tenant": stream.tenant.as_bytes(),
                ":repo": stream.repo,
                ":arch": self.facts.arch,
                ":cpu": self.free.cpu_millis,
                ":memory": self.free.memory_bytes,
                ":disk_reported": i64::from(self.facts.disk_reported),
                ":disk": self.free.disk_bytes,
                ":labels": self.facts.labels,
                ":worker_secret_delivery": i64::from(self.facts.secret_delivery),
                ":after_priority": after.0,
                ":after_queued": after.1,
                ":after_seq": after.2,
                ":large": large,
                ":large_since": large_since,
                ":pr_reserve": self.fairness.pr_reserve,
                ":exclusive": exclusive,
                ":far_cpu": far.cpu_millis,
                ":far_memory": far.memory_bytes,
                ":far_disk": far.disk_bytes,
            },
            |r| {
                Ok((
                    r.get::<_, [u8; 16]>(0)?,
                    r.get::<_, [u8; 16]>(1)?,
                    r.get::<_, i64>(2)?,
                    r.get::<_, i64>(3)?,
                    r.get::<_, i64>(4)?,
                    r.get::<_, String>(5)?,
                    r.get::<_, String>(6)?,
                    r.get::<_, i64>(7)?,
                    r.get::<_, Option<String>>(8)?,
                    r.get::<_, Vec<u8>>(9)?,
                    r.get::<_, i64>(10)?,
                    r.get::<_, bool>(11)?,
                    (r.get::<_, i64>(12)?, r.get::<_, i64>(13)?),
                    r.get::<_, bool>(14)?,
                ))
            },
        )?;
        let mut out = Vec::with_capacity(PAGE);
        for row in rows {
            let (
                job,
                run,
                cpu,
                memory,
                disk,
                digest,
                platform,
                index,
                arch,
                labels,
                queued,
                pr,
                order,
                requires_secret_delivery,
            ) = row?;
            out.push(Pick {
                tenant: stream.tenant,
                repo: Some(stream.repo),
                job: JobId::from_bytes(job).map_err(|_| Error::Corrupt("job_id"))?,
                run: RunId::from_bytes(run).map_err(|_| Error::Corrupt("run_id"))?,
                cpu_millis: cpu,
                memory_bytes: memory,
                disk_bytes: disk,
                image_digest: digest,
                image_platform: platform,
                spec_index: index,
                arch,
                labels,
                pull_request: pr,
                requires_secret_delivery,
                queued_ms: queued,
                priority: order.0,
                created_seq: order.1,
            });
        }
        Ok(out)
    }

    fn lease(&self, pick: Pick, lease_ms: i64) -> Result<Offer> {
        let lease_until = UnixMillis(self.now.0.saturating_add(lease_ms));
        let (attempt, fence) = jobs::lease_reserved(
            self.tx,
            pick.tenant,
            pick.job,
            self.worker,
            &jobs::Reservation {
                cpu_millis: pick.cpu_millis,
                memory_bytes: pick.memory_bytes,
                disk_bytes: pick.disk_bytes,
                repo: pick.repo,
            },
            lease_until,
            self.now,
        )?;
        Ok(Offer {
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
        })
    }
}

/// Whether any job is ready at all: the dispatcher's one probe before it
/// asks every connected worker, so a wake with an empty queue costs one
/// index seek instead of a writer transaction per worker (P08-14).
pub fn any_ready(conn: &Connection) -> Result<bool> {
    Ok(conn
        .prepare_cached(
            "SELECT EXISTS(SELECT 1 FROM jobs WHERE state_code = 1 AND cancel_requested = 0
                           AND image_digest IS NOT NULL)",
        )?
        .query_row([], |r| r.get(0))?)
}

/// Millicpu each worker's unreleased attempts hold, from the covering
/// `attempts_held_by_worker` index: the dispatcher reads it once per pass to
/// rank the connected workers, then keeps it current in memory.
pub fn held_by_worker(conn: &Connection) -> Result<HashMap<WorkerId, i64>> {
    let mut stmt = conn.prepare_cached(
        "SELECT worker_id, SUM(cpu_millis) FROM attempts
         WHERE released_ms IS NULL GROUP BY worker_id",
    )?;
    let rows = stmt.query_map([], |r| Ok((r.get::<_, [u8; 16]>(0)?, r.get::<_, i64>(1)?)))?;
    let mut out = HashMap::new();
    for row in rows {
        let (worker, held) = row?;
        out.insert(
            WorkerId::from_bytes(worker).map_err(|_| Error::Corrupt("worker id"))?,
            held,
        );
    }
    Ok(out)
}

/// A fingerprint of every revocation on record — the latest `revoked_ms`
/// and how many workers are revoked — from the `workers_revoked` index. A
/// revocation is written by the host-local admin command, a different
/// process; the dispatcher compares this each pass and acts only when it
/// changed.
pub fn revocations(conn: &Connection) -> Result<(i64, i64)> {
    Ok(conn
        .prepare_cached(
            "SELECT COALESCE(MAX(revoked_ms), 0), COUNT(*) FROM workers
             WHERE revoked_ms IS NOT NULL",
        )?
        .query_row([], |r| Ok((r.get(0)?, r.get(1)?)))?)
}

/// Whether `worker` is enrolled and not revoked: one primary-key probe.
fn worker_live(conn: &Connection, worker: WorkerId) -> Result<bool> {
    Ok(conn
        .prepare_cached(
            "SELECT EXISTS(SELECT 1 FROM workers WHERE id = ?1 AND revoked_ms IS NULL)",
        )?
        .query_row([worker.as_bytes()], |r| r.get(0))?)
}

/// Which of `workers` are revoked (or unknown): one primary-key probe each.
pub fn revoked_among(conn: &Connection, workers: &[WorkerId]) -> Result<Vec<WorkerId>> {
    let mut out = Vec::new();
    for worker in workers {
        if !worker_live(conn, *worker)? {
            out.push(*worker);
        }
    }
    Ok(out)
}

/// Fence every attempt a revoked worker still holds: an acknowledged one
/// ends `Reconciled` (whether it ran is unknown, so it is never replayed), an
/// unacknowledged offer lapses back to the queue (it never started). At most
/// one sweep batch per call; returns how many were settled, so a caller that
/// settled a full batch runs again. Driven from `workers_revoked`, so the
/// cost follows revoked workers' held attempts, not the fleet.
pub fn reconcile_revoked(
    tx: &Transaction<'_>,
    now: UnixMillis,
    logs: Option<&LogStore>,
) -> Result<usize> {
    let held: Vec<([u8; 16], bool)> = tx
        .prepare_cached(
            "SELECT a.id, a.acked_ms IS NOT NULL FROM workers w
             JOIN attempts a ON a.worker_id = w.id AND a.released_ms IS NULL
             WHERE w.revoked_ms IS NOT NULL
             LIMIT ?1",
        )?
        .query_map([SWEEP_BATCH as i64], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect::<std::result::Result<_, _>>()?;
    let settled = held.len();
    for (attempt, acked) in held {
        let attempt = AttemptId::from_bytes(attempt).map_err(|_| Error::Corrupt("attempt_id"))?;
        if acked {
            finish(tx, attempt, Actor::Reconciler, Event::Reconciled, now, logs)?;
        } else {
            lapse(tx, attempt, now)?;
        }
    }
    Ok(settled)
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
    // A revoked worker's acknowledgement is refused like a stranger's: its
    // offers are fenced the moment it is revoked (P08-7).
    tx.prepare_cached(
        "UPDATE attempts SET acked_ms = ?4
         WHERE id = ?1 AND worker_id = ?2 AND fence = ?3 AND acked_ms IS NULL AND released_ms IS NULL
           AND EXISTS(SELECT 1 FROM workers w WHERE w.id = ?2 AND w.revoked_ms IS NULL)",
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
             WHERE id = ?1 AND worker_id = ?2 AND fence = ?3
               AND EXISTS(SELECT 1 FROM workers w WHERE w.id = ?2 AND w.revoked_ms IS NULL)",
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
/// A job whose cancellation was recorded while the offer was out does not
/// wait in the queue for a placement it can never get: it ends `canceled`
/// in the same transaction and its dependents are decided.
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
    give_back(tx, attempt, tenant, job, Fence(fence as u64), now).map(|_| ())
}

/// Release an attempt that never started and return its job to the queue
/// (`OfferLapsed`, fence kept advanced); with cancellation desired, straight
/// on to `canceled` with the dependents decided. The job must still be
/// `Leased` under `fence`: once the worker reported a phase, only a report
/// or an expiry may settle it.
fn give_back(
    tx: &Transaction<'_>,
    attempt: AttemptId,
    tenant: TenantId,
    job: JobId,
    fence: Fence,
    now: UnixMillis,
) -> Result<JobState> {
    let current = jobs::get_job(tx, tenant, job)?;
    if current.fence != fence || current.state != JobState::Leased {
        return Err(Error::Conflict);
    }
    let mut next = jobs::transition(tx, tenant, job, Actor::Controller, Event::OfferLapsed, now)?;
    // The durable requeue marker (P11D-2 residual): the job is no longer
    // leased, so its lease stamp goes with the offer, as a rerun clears it.
    // Only the next lease stamps it again (under a new fence), so a cancel
    // or queue timeout before then is never the lapsed attempt's verdict,
    // and the job's `leased_ms` no longer shows a lease that lapsed.
    tx.prepare_cached("UPDATE jobs SET leased_ms = NULL WHERE id = ?1 AND tenant_id = ?2")?
        .execute(params![job.as_bytes(), tenant.as_bytes()])?;
    tx.prepare_cached("UPDATE attempts SET released_ms = ?2 WHERE id = ?1")?
        .execute(params![attempt.as_bytes(), now.0])?;
    if current.cancel_requested {
        next = jobs::transition(
            tx,
            tenant,
            job,
            Actor::Controller,
            Event::CancelBeforeStart,
            now,
        )?;
        let run = run_of(tx, tenant, job)?;
        release_dependents(tx, tenant, run, now)?;
    }
    Ok(next)
}

/// The worker hands an attempt back without having run it: an offer it
/// declined, or an acknowledged attempt whose run spec never reached it
/// (the worker never started it, so the job is still `Leased`). Fenced on
/// the holder: another worker naming the attempt, a stale fence or an
/// attempt that already started is refused and nothing changes. The job
/// returns to the queue — nothing ran, so this is not an execution and not
/// an infrastructure failure — or ends `canceled` when that is desired. A
/// revoked worker's hand-back is refused like a stranger's; the revocation
/// sweep settles what it held (P08-7).
pub fn decline(
    tx: &Transaction<'_>,
    worker: WorkerId,
    attempt: AttemptId,
    fence: Fence,
    now: UnixMillis,
) -> Result<JobState> {
    let row: Option<([u8; 16], [u8; 16])> = tx
        .prepare_cached(
            "SELECT a.tenant_id, a.job_id FROM attempts a JOIN workers w ON w.id = a.worker_id
             WHERE a.id = ?1 AND a.worker_id = ?2 AND a.fence = ?3 AND a.released_ms IS NULL
               AND w.revoked_ms IS NULL",
        )?
        .query_row(
            params![attempt.as_bytes(), worker.as_bytes(), fence.0 as i64],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let Some((tenant, job)) = row else {
        return Err(Error::NotFound);
    };
    let tenant = TenantId::from_bytes(tenant).map_err(|_| Error::Corrupt("tenant_id"))?;
    let job = JobId::from_bytes(job).map_err(|_| Error::Corrupt("job_id"))?;
    give_back(tx, attempt, tenant, job, fence, now)
}

/// Where an attempt's run spec stands for the worker asking for it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SpecGate {
    /// Held and acknowledged: the spec may be served.
    Ready,
    /// Held, but the acknowledgement has not committed yet. It is in flight
    /// on the control connection, or its write failed and the offer will
    /// lapse — either way nothing may run before it is durable.
    Unacknowledged,
    /// Held and acknowledged, never started, and its job has cancellation
    /// desired: settle it `canceled` (see [`decline`]) instead of serving.
    Canceled(Fence),
    /// Not this worker's live attempt.
    NotHeld,
}

/// Whether the spec of `attempt` may go to `worker` now. One indexed read.
/// A revoked worker holds nothing: its spec requests are `NotHeld` (P08-7).
pub fn spec_gate(conn: &Connection, worker: WorkerId, attempt: AttemptId) -> Result<SpecGate> {
    let row: Option<(bool, i64, bool, i64)> = conn
        .prepare_cached(
            "SELECT a.acked_ms IS NOT NULL, a.fence, j.cancel_requested, j.state_code
             FROM attempts a JOIN jobs j ON j.id = a.job_id JOIN workers w ON w.id = a.worker_id
             WHERE a.id = ?1 AND a.worker_id = ?2 AND a.released_ms IS NULL
               AND w.revoked_ms IS NULL",
        )?
        .query_row(params![attempt.as_bytes(), worker.as_bytes()], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
        })
        .optional()?;
    Ok(match row {
        None => SpecGate::NotHeld,
        Some((false, _, _, _)) => SpecGate::Unacknowledged,
        Some((true, fence, true, state))
            if decode_state(state).ok_or(Error::Corrupt("state_code"))? == JobState::Leased =>
        {
            SpecGate::Canceled(Fence(fence as u64))
        }
        Some(_) => SpecGate::Ready,
    })
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
///
/// A lease that has already passed is not renewed: it is expired, whatever
/// the worker says, and the expiry sweep settles it (P08-13). A revoked
/// worker renews nothing — `Forbidden`, which ends its session (P08-7).
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
    let revoked: bool = tx
        .prepare_cached(
            "SELECT EXISTS(SELECT 1 FROM workers WHERE id = ?1 AND revoked_ms IS NOT NULL)",
        )?
        .query_row([worker.as_bytes()], |r| r.get(0))?;
    if revoked {
        return Err(Error::Forbidden);
    }
    let until = UnixMillis(now.0.saturating_add(lease_ms));
    let mut stmt = tx.prepare_cached(
        "UPDATE attempts SET lease_until_ms = MAX(lease_until_ms, ?3)
         WHERE id = ?1 AND worker_id = ?2 AND acked_ms IS NOT NULL AND released_ms IS NULL
           AND lease_until_ms >= ?4",
    )?;
    let mut stop = Vec::new();
    for attempt in held {
        if stmt.execute(params![
            attempt.as_bytes(),
            worker.as_bytes(),
            until.0,
            now.0
        ])? == 0
        {
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
/// An unstarted job that ends here decides its dependents in the same
/// transaction, exactly as any other terminal edge does — a dependent left
/// `blocked` would hold its run open forever. Operator and API cancels never
/// clear the flag; the one exception is a GitHub check-run rerequest, which
/// starts a cancelled job over (see docs/checks.md).
pub fn cancel(
    tx: &Transaction<'_>,
    tenant: TenantId,
    job: JobId,
    now: UnixMillis,
) -> Result<Cancelled> {
    let outcome = cancel_one(tx, tenant, job, now)?;
    if outcome == Cancelled::Terminal {
        let run = run_of(tx, tenant, job)?;
        release_dependents(tx, tenant, run, now)?;
    }
    Ok(outcome)
}

/// [`cancel`] without deciding dependents: the caller does that once.
fn cancel_one(
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

/// Cancel every job of a run that is not terminal yet; returns how many
/// were cancelled or asked to stop. Every job is cancelled before
/// dependents are decided, once, so nothing is decided against a sibling
/// about to be cancelled too.
pub fn cancel_run(
    tx: &Transaction<'_>,
    tenant: TenantId,
    run: RunId,
    now: UnixMillis,
) -> Result<usize> {
    let mut count = 0;
    for (job, state) in runs::run_jobs(tx, tenant, run)? {
        if !state.is_terminal() && cancel_one(tx, tenant, job, now)? != Cancelled::AlreadyTerminal {
            count += 1;
        }
    }
    release_dependents(tx, tenant, run, now)?;
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
    Ok(expired_scoped(conn, now)?
        .into_iter()
        .map(|(attempt, _, _)| attempt)
        .collect())
}

/// [`expired`] with each attempt's run and job, so a caller can learn
/// whether its log ended before it takes the writer.
pub fn expired_scoped(
    conn: &Connection,
    now: UnixMillis,
) -> Result<Vec<(AttemptId, RunId, JobId)>> {
    let decode = |r: &rusqlite::Row<'_>| -> rusqlite::Result<([u8; 16], [u8; 16], [u8; 16])> {
        Ok((r.get(0)?, r.get(1)?, r.get(2)?))
    };
    let typed = |(a, r, j): ([u8; 16], [u8; 16], [u8; 16])| -> Result<(AttemptId, RunId, JobId)> {
        Ok((
            AttemptId::from_bytes(a).map_err(|_| Error::Corrupt("attempt_id"))?,
            RunId::from_bytes(r).map_err(|_| Error::Corrupt("run_id"))?,
            JobId::from_bytes(j).map_err(|_| Error::Corrupt("job_id"))?,
        ))
    };
    let mut stmt = conn.prepare_cached(
        "SELECT a.id, j.run_id, j.id FROM attempts a JOIN jobs j ON j.id = a.job_id
         WHERE a.released_ms IS NULL AND a.acked_ms IS NOT NULL AND a.lease_until_ms < ?1
         ORDER BY a.lease_until_ms LIMIT ?2",
    )?;
    let mut out = Vec::new();
    for row in stmt.query_map(params![now.0, SWEEP_BATCH as i64], decode)? {
        out.push(typed(row?)?);
    }
    let mut overrun = conn.prepare_cached(
        "SELECT a.id, j.run_id, j.id FROM attempts a JOIN jobs j ON j.id = a.job_id
         WHERE a.released_ms IS NULL AND a.acked_ms IS NOT NULL
           AND a.acked_ms + j.timeout_ms + ?2 < ?1
         LIMIT ?3",
    )?;
    for row in overrun.query_map(
        params![now.0, EXECUTION_GRACE_MS, SWEEP_BATCH as i64],
        decode,
    )? {
        let row = typed(row?)?;
        if !out.iter().any(|(a, _, _)| *a == row.0) {
            out.push(row);
        }
    }
    Ok(out)
}

/// Expire one attempt: `LeaseExpired` through the machine, capacity back,
/// dependents decided. The job is terminal `infra_failed` — never re-queued
/// on its own, because whether its side effects happened is unknown.
///
/// The sweep finds candidates in a read snapshot and expires them in later
/// writer transactions, so the deadline is checked again here, in the same
/// transaction as the transition: a renewal that committed after the sweep
/// read the attempt as due (a worker reconnecting at its deadline) wins, and
/// the attempt is `Conflict` here rather than failed under a worker that was
/// just granted more time — and renewal refuses a passed lease (P08-13), so a
/// lapsed one cannot be revived to dodge this.
pub fn expire(
    tx: &Transaction<'_>,
    attempt: AttemptId,
    now: UnixMillis,
    logs: Option<&LogStore>,
) -> Result<JobState> {
    let due: bool = tx
        .prepare_cached(
            "SELECT EXISTS(SELECT 1 FROM attempts a JOIN jobs j ON j.id = a.job_id
             WHERE a.id = ?1 AND a.released_ms IS NULL AND a.acked_ms IS NOT NULL
               AND (a.lease_until_ms < ?2 OR a.acked_ms + j.timeout_ms + ?3 < ?2))",
        )?
        .query_row(
            params![attempt.as_bytes(), now.0, EXECUTION_GRACE_MS],
            |r| r.get(0),
        )?;
    if !due {
        return Err(Error::Conflict);
    }
    finish(
        tx,
        attempt,
        Actor::Controller,
        Event::LeaseExpired,
        now,
        logs,
    )
}

/// Run `f` inside a savepoint: its writes stay when it succeeds and are
/// undone alone when it fails, so one bad row cannot sink a batch.
fn isolated<T>(tx: &Transaction<'_>, f: impl FnOnce() -> Result<T>) -> Result<T> {
    tx.execute_batch("SAVEPOINT one")?;
    match f() {
        Ok(value) => {
            tx.execute_batch("RELEASE one")?;
            Ok(value)
        }
        Err(e) => {
            tx.execute_batch("ROLLBACK TO one; RELEASE one")?;
            Err(e)
        }
    }
}

/// What a batched sweep did: rows settled, and rows that failed for a
/// reason other than having moved first (renewed, acknowledged, released —
/// `Conflict`/`NotFound`, which leave nothing to do). `error` is the first
/// such failure, for the caller's counters and log.
#[derive(Debug, Default)]
pub struct Swept {
    pub done: usize,
    pub failed: usize,
    pub error: Option<Error>,
}

impl Swept {
    fn record<T>(&mut self, outcome: Result<T>) {
        match outcome {
            Ok(_) => self.done += 1,
            Err(Error::Conflict | Error::NotFound) => {}
            Err(e) => {
                self.failed += 1;
                self.error.get_or_insert(e);
            }
        }
    }
}

/// Expire every attempt in `due` (from [`expired_scoped`]) in one
/// transaction, re-checking each lease. `ended` says, per attempt, whether
/// its log end marker was durable when the caller looked — computed before
/// the writer was taken, so the writer never waits on log I/O. A renewed or
/// already-settled attempt is skipped; any other failure is rolled back to
/// its savepoint and reported in [`Swept`].
pub fn expire_batch(
    tx: &Transaction<'_>,
    due: &[(AttemptId, bool)],
    now: UnixMillis,
) -> Result<Swept> {
    let mut swept = Swept::default();
    for &(attempt, ended) in due {
        swept.record(isolated(tx, || {
            let state = expire(tx, attempt, now, None)?;
            if ended {
                log_ended(tx, attempt)?;
            }
            Ok(state)
        }));
    }
    Ok(swept)
}

/// Lapse every offer past its acknowledgement timeout in one transaction.
/// One that was acknowledged meanwhile is skipped; any other failure is
/// rolled back to its savepoint and reported in [`Swept`].
pub fn lapse_due(tx: &Transaction<'_>, now: UnixMillis) -> Result<Swept> {
    let mut swept = Swept::default();
    for attempt in unacknowledged(tx, now)? {
        swept.record(isolated(tx, || lapse(tx, attempt, now)));
    }
    Ok(swept)
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
        // Never acknowledged: it never started, so back to the queue (or
        // `canceled`, when that is desired).
        let (tenant, job): ([u8; 16], [u8; 16]) = tx
            .prepare_cached("SELECT tenant_id, job_id FROM attempts WHERE id = ?1")?
            .query_row([attempt.as_bytes()], |r| Ok((r.get(0)?, r.get(1)?)))?;
        lapse(tx, attempt, now)?;
        let tenant = TenantId::from_bytes(tenant).map_err(|_| Error::Corrupt("tenant_id"))?;
        let job = JobId::from_bytes(job).map_err(|_| Error::Corrupt("job_id"))?;
        return Ok(jobs::get_job(tx, tenant, job)?.state);
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
    // The same sweep the dispatcher runs whenever a revocation lands.
    done.orphaned = reconcile_revoked(tx, now, logs)?;
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
    // A revoked worker reports nothing: its verdicts are not evidence
    // (P08-7). The attempt is settled `Reconciled` by the dispatcher instead.
    let cancel_requested: Option<bool> = tx
        .prepare_cached(
            "SELECT j.cancel_requested FROM attempts a JOIN jobs j ON j.id = a.job_id
                                        JOIN workers w ON w.id = a.worker_id
             WHERE a.id = ?1 AND a.worker_id = ?2 AND a.fence = ?3
               AND a.acked_ms IS NOT NULL AND a.released_ms IS NULL
               AND w.revoked_ms IS NULL",
        )?
        .query_row(
            params![attempt.as_bytes(), worker.as_bytes(), fence.0 as i64],
            |r| r.get(0),
        )
        .optional()?;
    let Some(cancel_requested) = cancel_requested else {
        return Err(Error::NotFound);
    };
    // `canceled` is the user's verdict: a worker that ended the attempt on
    // its own (its lease watchdog, its own shutdown) with no cancel ever
    // requested is reporting an infrastructure event, not a cancellation.
    let event = match event {
        Event::Failed(FailureClass::Canceled) if !cancel_requested => {
            Event::Failed(FailureClass::Runtime)
        }
        event => event,
    };
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
/// to and the trust class derived here, once, from the recorded provenance
/// and the repository's binding (`provenance::cache_trust`, docs/cache.md).
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
    /// `provenance::cache_trust`: protected only for a verified push/tag
    /// to a ref the binding names exactly, pull-request for PR runs,
    /// unprotected otherwise. Derived here so no consumer can pick a
    /// different rule.
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

/// Context for an attempt the (unrevoked) worker holds and has acknowledged — nothing
/// that could start work leaves before the acknowledgement is durable, so
/// an offer that lapses for a lost ack write never also runs (P04-10). One
/// statement for the identity
/// row, one for the run's job states; the spec (already sent to the worker)
/// names the dependencies.
pub fn job_context(conn: &Connection, worker: WorkerId, attempt: AttemptId) -> Result<JobContext> {
    let row: Option<ContextRow> = conn
        .prepare_cached(
            "SELECT j.tenant_id, j.run_id, r.repo_id, p.name, j.id, j.name, r.source_sha,
                    j.cancel_requested, j.spec_index
             FROM attempts a JOIN jobs j ON j.id = a.job_id JOIN runs r ON r.id = j.run_id
             JOIN repos p ON p.id = r.repo_id JOIN workers w ON w.id = a.worker_id
             WHERE a.id = ?1 AND a.worker_id = ?2 AND a.acked_ms IS NOT NULL
               AND a.released_ms IS NULL AND w.revoked_ms IS NULL",
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
    let repo = RepoId::from_bytes(repo).map_err(|_| Error::Corrupt("repo_id"))?;
    Ok(JobContext {
        tenant,
        run,
        repo,
        repo_name,
        job: JobId::from_bytes(job).map_err(|_| Error::Corrupt("job_id"))?,
        job_name,
        sha,
        trust: crate::provenance::cache_trust(conn, run, repo)?,
        event,
        cancelled: cancel != 0,
        needs,
    })
}

/// Whether the attempt is reserved on `worker`, not yet released, and the
/// worker is not revoked: the gate for artifact publication and cache
/// transfers. A revoked worker holds nothing (P08-7).
pub fn is_held(conn: &Connection, worker: WorkerId, attempt: AttemptId) -> Result<bool> {
    Ok(conn
        .prepare_cached(
            "SELECT EXISTS(SELECT 1 FROM attempts a JOIN workers w ON w.id = a.worker_id
                           WHERE a.id = ?1 AND a.worker_id = ?2 AND a.released_ms IS NULL
                             AND w.revoked_ms IS NULL)",
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
             FROM attempts a JOIN jobs j ON j.id = a.job_id JOIN workers w ON w.id = a.worker_id
             WHERE a.id = ?1 AND a.worker_id = ?2 AND a.released_ms IS NULL
               AND w.revoked_ms IS NULL",
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

/// The cache boundary of an attempt `worker` owns — its tenant, repository
/// and trust class — for remote-cache authorization (Q08). A fetch passes
/// `released_since: None`: the attempt must still be held. An offer passes
/// the oldest release it accepts: a worker offers what it sealed only after
/// its terminal report released the attempt (P07-7), so a recently
/// released attempt of the same worker still names its boundary.
/// `NotFound` for a foreign, unknown or long-released attempt, or a revoked
/// worker (P08-7). One indexed
/// row plus the trust probe — none of `job_context`'s spec work.
pub fn cache_scope(
    conn: &Connection,
    worker: WorkerId,
    attempt: AttemptId,
    released_since: Option<UnixMillis>,
) -> Result<(TenantId, RepoId, sentinel_protocol::cache::Trust)> {
    let row: Option<([u8; 16], [u8; 16], [u8; 16])> = conn
        .prepare_cached(
            "SELECT j.tenant_id, j.run_id, r.repo_id
             FROM attempts a JOIN jobs j ON j.id = a.job_id JOIN runs r ON r.id = j.run_id
             JOIN workers w ON w.id = a.worker_id
             WHERE a.id = ?1 AND a.worker_id = ?2 AND w.revoked_ms IS NULL
               AND (a.released_ms IS NULL OR (?3 IS NOT NULL AND a.released_ms >= ?3))",
        )?
        .query_row(
            params![
                attempt.as_bytes(),
                worker.as_bytes(),
                released_since.map(|t| t.0)
            ],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()?;
    let (tenant, run, repo) = row.ok_or(Error::NotFound)?;
    let run = RunId::from_bytes(run).map_err(|_| Error::Corrupt("run_id"))?;
    let repo = RepoId::from_bytes(repo).map_err(|_| Error::Corrupt("repo_id"))?;
    Ok((
        TenantId::from_bytes(tenant).map_err(|_| Error::Corrupt("tenant_id"))?,
        repo,
        crate::provenance::cache_trust(conn, run, repo)?,
    ))
}

/// The attempt's run/job for log purposes: owned by that worker, released
/// or not. A released attempt may still receive retransmitted frames and its
/// end — the log is evidence, and late bytes only complete the record. The
/// verdict itself was already decided. A revoked worker's bytes are not
/// evidence: refused like a stranger's (P08-7).
pub fn attempt_log_scope(
    conn: &Connection,
    worker: WorkerId,
    attempt: AttemptId,
) -> Result<(RunId, JobId)> {
    let Some((run, job)) = conn
        .prepare_cached(
            "SELECT j.run_id, j.id FROM attempts a JOIN jobs j ON j.id = a.job_id
             JOIN workers w ON w.id = a.worker_id
             WHERE a.id = ?1 AND a.worker_id = ?2 AND w.revoked_ms IS NULL",
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

/// The encoded run spec of an attempt the worker holds and has
/// acknowledged, exactly as stored. Never for a revoked worker (P08-7).
pub fn spec_bytes(conn: &Connection, worker: WorkerId, attempt: AttemptId) -> Result<Vec<u8>> {
    conn.prepare_cached(
        "SELECT s.spec FROM attempts a JOIN jobs j ON j.id = a.job_id
         JOIN run_specs s ON s.run_id = j.run_id JOIN workers w ON w.id = a.worker_id
         WHERE a.id = ?1 AND a.worker_id = ?2 AND a.acked_ms IS NOT NULL
           AND a.released_ms IS NULL AND w.revoked_ms IS NULL",
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
///
/// Non-exhaustive so the API's rendering keeps a guard arm for a reason
/// added here before the API names it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
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
    /// An older live run of the same repository and group, or a run whose
    /// job a worker is executing, still holds its concurrency group.
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
    /// Nothing holds it: a connected worker has the room now and every
    /// constraint and reservation allows it there. The next dispatch pass
    /// places it, unless work ahead of it in the fair order takes that room
    /// first. Reported instead of `Capacity`, which would claim the worker
    /// is full when it is not (P08-4).
    Ready,
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

/// A bounded page of a tenant's waiting jobs and how many are waiting.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueuePage {
    /// At most the requested number, oldest queued first, then blocked.
    pub jobs: Vec<QueuedJob>,
    /// Every waiting (queued or blocked) job of the tenant.
    pub total: usize,
}

/// The columns one explanation needs, read with the listing itself so no
/// job is looked up twice.
macro_rules! waiting_columns {
    () => {
        "SELECT j.id, j.run_id, j.repo_id, j.queued_ms, j.state_code, j.cpu_millis,
                j.memory_bytes, j.disk_bytes, j.cancel_requested, j.arch, j.labels,
                j.image_digest, j.image_platform IS NOT NULL,
                j.concurrency_group IS NOT NULL, j.pull_request, j.spec_index,
                j.requires_secret_delivery
         FROM jobs j "
    };
}

/// Queued jobs of a tenant, oldest first, from the `jobs_waiting` partial
/// index: a range read that stops at the limit, no sort.
const QUEUED_PAGE_SQL: &str = concat!(
    waiting_columns!(),
    "WHERE j.tenant_id = ?1 AND j.state_code IN (0, 1) AND j.queued_ms IS NOT NULL
     ORDER BY j.queued_ms, j.created_seq LIMIT ?2"
);
/// Blocked jobs (never queued, so no `queued_ms`) after the queued ones.
const BLOCKED_PAGE_SQL: &str = concat!(
    waiting_columns!(),
    "WHERE j.tenant_id = ?1 AND j.state_code IN (0, 1) AND j.queued_ms IS NULL
     ORDER BY j.queued_ms, j.created_seq LIMIT ?2"
);
const WAITING_COUNT_SQL: &str =
    "SELECT COUNT(*) FROM jobs WHERE tenant_id = ?1 AND state_code IN (0, 1)";
const WAITING_ONE_SQL: &str = concat!(waiting_columns!(), "WHERE j.id = ?1 AND j.tenant_id = ?2");
/// Whether `j`'s group is held for it: exactly placement's predicate, negated.
const GROUP_HELD_SQL: &str = concat!(
    "SELECT NOT ",
    group_free_sql!(),
    " FROM jobs j WHERE j.id = ?1"
);

struct Waiting {
    job: JobId,
    run: RunId,
    repo: Option<[u8; 16]>,
    queued: Option<i64>,
    state: i64,
    cancel: bool,
    resolved: bool,
    grouped: bool,
    pick: Pick,
}

fn waiting_row(tenant: TenantId, r: &rusqlite::Row<'_>) -> rusqlite::Result<Result<Waiting>> {
    let job: [u8; 16] = r.get(0)?;
    let run: [u8; 16] = r.get(1)?;
    let repo: Option<[u8; 16]> = r.get(2)?;
    let queued: Option<i64> = r.get(3)?;
    let digest: Option<String> = r.get(11)?;
    let pick = (
        r.get::<_, i64>(5)?,
        r.get::<_, i64>(6)?,
        r.get::<_, i64>(7)?,
        r.get::<_, Option<String>>(9)?,
        r.get::<_, Vec<u8>>(10)?,
        r.get::<_, bool>(14)?,
        r.get::<_, i64>(15)?,
        r.get::<_, bool>(16)?,
    );
    let (state, cancel, resolved, grouped) = (
        r.get::<_, i64>(4)?,
        r.get::<_, bool>(8)?,
        r.get::<_, bool>(12)?,
        r.get::<_, bool>(13)?,
    );
    Ok((|| {
        let job = JobId::from_bytes(job).map_err(|_| Error::Corrupt("job_id"))?;
        let run = RunId::from_bytes(run).map_err(|_| Error::Corrupt("run_id"))?;
        let (
            cpu_millis,
            memory_bytes,
            disk_bytes,
            arch,
            labels,
            pull_request,
            spec_index,
            requires_secret_delivery,
        ) = pick;
        Ok(Waiting {
            job,
            run,
            repo,
            queued,
            state,
            cancel,
            resolved: resolved && digest.is_some(),
            grouped,
            pick: Pick {
                tenant,
                repo,
                job,
                run,
                cpu_millis,
                memory_bytes,
                disk_bytes,
                image_digest: digest.unwrap_or_default(),
                image_platform: String::new(),
                spec_index,
                arch,
                labels,
                pull_request,
                requires_secret_delivery,
                queued_ms: queued.unwrap_or(0),
                priority: 0,
                created_seq: 0,
            },
        })
    })())
}

/// Everything explanations read that does not depend on the job, read at
/// most once per listing: the admissible workers, and per connected worker
/// its free capacity, its reservations and the tenant's locality view.
struct Explainer<'c> {
    conn: &'c Connection,
    tenant: TenantId,
    connected: &'c [WorkerId],
    now: UnixMillis,
    workers: Option<Vec<(WorkerId, WorkerFacts)>>,
    free: HashMap<WorkerId, Capacity>,
    fairness: HashMap<WorkerId, Fairness>,
    locality: LocalityCache,
}

impl<'c> Explainer<'c> {
    fn new(conn: &'c Connection, tenant: TenantId, connected: &'c [WorkerId]) -> Self {
        Explainer {
            conn,
            tenant,
            connected,
            now: UnixMillis::now(),
            workers: None,
            free: HashMap::new(),
            fairness: HashMap::new(),
            locality: LocalityCache::default(),
        }
    }

    fn explain(&mut self, w: &Waiting) -> Result<WaitReason> {
        match decode_state(w.state).ok_or(Error::Corrupt("state_code"))? {
            JobState::Blocked => return Ok(WaitReason::Dependency),
            JobState::Queued => {}
            _ => return Err(Error::InvalidInput("job is not waiting")),
        }
        if w.cancel {
            return Ok(WaitReason::Policy("cancel requested"));
        }
        if !w.resolved {
            return Ok(WaitReason::Policy("image unresolved"));
        }
        // `place` never considers a job whose group is held for it; saying
        // `capacity` here would be a lie.
        if w.grouped {
            let held: bool = self
                .conn
                .prepare_cached(GROUP_HELD_SQL)?
                .query_row([w.job.as_bytes()], |r| r.get(0))?;
            if held {
                return Ok(WaitReason::ConcurrencyLimit);
            }
        }
        let pick = &w.pick;
        let workers = match self.workers.take() {
            Some(workers) => workers,
            None => pool_workers(self.conn, self.tenant)?,
        };
        if pick.requires_secret_delivery
            && !workers.iter().any(|(_, facts)| {
                facts.secret_delivery
                    && pick
                        .arch
                        .as_deref()
                        .is_none_or(|arch| arch == facts.arch.as_str())
                    && labels_subset(&pick.labels, &facts.labels)
            })
        {
            self.workers = Some(workers);
            return Ok(WaitReason::Policy(
                "no matching worker supports secret delivery",
            ));
        }
        let reason = self.against(&workers, pick);
        self.workers = Some(workers);
        reason
    }

    fn against(&mut self, workers: &[(WorkerId, WorkerFacts)], pick: &Pick) -> Result<WaitReason> {
        let (mut best_cpu, mut best_memory, mut best_disk) = (0i64, 0i64, 0i64);
        let (mut arch_ok, mut labels_ok, mut fits_compute, mut fits_disk) =
            (false, false, false, false);
        let (mut draining_fit, mut offline_fit) = (false, false);
        let (mut any_connected, mut held_fairness, mut held_locality) = (false, false, false);
        for (id, facts) in workers {
            if pick.requires_secret_delivery && !facts.secret_delivery {
                continue;
            }
            let arch_matches = pick
                .arch
                .as_deref()
                .is_none_or(|arch| arch == facts.arch.as_str());
            let labels_match = labels_subset(&pick.labels, &facts.labels);
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
                continue;
            }
            if !self.connected.contains(id) {
                offline_fit = true;
                continue;
            }
            any_connected = true;
            // Placement's own question, asked of this worker: does the room
            // exist now, and does any reservation or locality hold stop it?
            let free = match self.free.get(id) {
                Some(free) => *free,
                None => {
                    let free = free_capacity(self.conn, *id)?;
                    self.free.insert(*id, free);
                    free
                }
            };
            let fits_now = free.cpu_millis >= pick.cpu_millis
                && free.memory_bytes >= pick.memory_bytes
                && (pick.disk_bytes == 0
                    || !facts.disk_reported
                    || free.disk_bytes >= pick.disk_bytes);
            if !fits_now {
                continue;
            }
            let fairness = match self.fairness.get(id) {
                Some(fairness) => *fairness,
                None => {
                    let fairness = waiting_fairness(self.conn, facts.pool, facts)?;
                    self.fairness.insert(*id, fairness);
                    fairness
                }
            };
            if fairness_hold(&fairness, pick, free.cpu_millis) {
                held_fairness = true;
                continue;
            }
            if self.locality.holds(self.conn, *id, facts, pick, self.now)? {
                held_locality = true;
                continue;
            }
            return Ok(WaitReason::Ready);
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
        if held_fairness {
            return Ok(WaitReason::FairnessHold);
        }
        if held_locality {
            return Ok(WaitReason::LocalityWait);
        }
        if any_connected {
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
}

/// A tenant's waiting jobs — queued oldest first, then blocked — at most
/// `limit` of them, each with the live reason it has not started, and the
/// total waiting. The limit is applied in the query, before any reason is
/// computed, and everything a reason reads that is not the job's own row is
/// read once per call (P08-8): the cost is `limit` explanations over one
/// worker scan, not the tenant's whole queue times the fleet. `connected` is
/// the controller's live session set, the one fact the database does not
/// hold.
pub fn list_queue(
    conn: &Connection,
    tenant: TenantId,
    connected: &[WorkerId],
    limit: usize,
) -> Result<QueuePage> {
    let total: i64 = conn
        .prepare_cached(WAITING_COUNT_SQL)?
        .query_row([tenant.as_bytes()], |r| r.get(0))?;
    let mut rows: Vec<Waiting> = Vec::with_capacity(limit.min(total.max(0) as usize));
    for sql in [QUEUED_PAGE_SQL, BLOCKED_PAGE_SQL] {
        let left = limit - rows.len();
        if left == 0 {
            break;
        }
        let mut stmt = conn.prepare_cached(sql)?;
        let page = stmt.query_map(params![tenant.as_bytes(), left as i64], |r| {
            waiting_row(tenant, r)
        })?;
        for row in page {
            rows.push(row??);
        }
    }
    let mut explainer = Explainer::new(conn, tenant, connected);
    let mut jobs = Vec::with_capacity(rows.len());
    for row in &rows {
        jobs.push(QueuedJob {
            job: row.job,
            run: row.run,
            repo: RepoId::from_bytes(row.repo.ok_or(Error::Corrupt("jobs.repo_id"))?)
                .map_err(|_| Error::Corrupt("repo_id"))?,
            age_ms: row
                .queued
                .map_or(0, |queued| explainer.now.0.saturating_sub(queued).max(0)),
            reason: explainer.explain(row)?,
        });
    }
    Ok(QueuePage {
        jobs,
        total: usize::try_from(total).map_err(|_| Error::Corrupt("waiting count"))?,
    })
}

/// Explain a queued or blocked job. `connected` is the controller's live
/// session set — the one fact the database does not hold.
pub fn wait_reason(
    conn: &Connection,
    tenant: TenantId,
    job: JobId,
    connected: &[WorkerId],
) -> Result<WaitReason> {
    let row = conn
        .prepare_cached(WAITING_ONE_SQL)?
        .query_row(params![job.as_bytes(), tenant.as_bytes()], |r| {
            waiting_row(tenant, r)
        })
        .optional()?
        .ok_or(Error::NotFound)??;
    Explainer::new(conn, tenant, connected).explain(&row)
}

#[cfg(test)]
mod tests {
    use rusqlite::{Connection, StatementStatus};
    use sentinel_core::{
        UserId,
        auth::{Namespace, Permissions as P, Principal},
    };

    use super::*;
    use crate::{
        Durability, Store,
        auth::{self, Authority, NamespaceKind, provisioning},
        tenancy::{self, PoolKind},
    };

    /// Every placement and listing statement, the partial or covering index
    /// it must read, and the table alias whose scan would mean it does not.
    const STATEMENTS: &[(&str, &str, &str)] = &[
        ("candidate page", CANDIDATES_SQL, "jobs_ready_repo"),
        ("candidate page group check", CANDIDATES_SQL, "jobs_conc"),
        (
            "pull-request candidate page",
            PR_CANDIDATES_SQL,
            "jobs_ready_pr",
        ),
        ("large-job probe", LARGE_WAITING_SQL, "jobs_ready_large"),
        ("pull-request probe", PR_WAITING_SQL, "jobs_ready_pr"),
        ("ready tenants", READY_TENANTS_SQL, "jobs_ready_repo"),
        ("ready repositories", READY_REPOS_SQL, "jobs_ready_repo"),
        ("tenant held", TENANT_HELD_SQL, "attempts_held_by_repo"),
        ("repository held", REPO_HELD_SQL, "attempts_held_by_repo"),
        (
            "free capacity",
            FREE_CAPACITY_SQL,
            "attempts_held_by_worker",
        ),
        ("queued page", QUEUED_PAGE_SQL, "jobs_waiting"),
        ("blocked page", BLOCKED_PAGE_SQL, "jobs_waiting"),
        ("waiting count", WAITING_COUNT_SQL, "jobs_waiting"),
        ("group held", GROUP_HELD_SQL, "jobs_conc"),
        ("prefetch head", PREFETCH_HEAD_SQL, "jobs_queued_since"),
    ];

    fn migrated() -> Connection {
        let mut conn = Connection::open_in_memory().unwrap();
        crate::migrate(&mut conn).unwrap();
        crate::register_functions(&conn).unwrap();
        conn
    }

    fn explain(conn: &Connection, sql: &str) -> Vec<String> {
        let mut stmt = conn.prepare(&format!("EXPLAIN QUERY PLAN {sql}")).unwrap();
        let values = vec![rusqlite::types::Value::Null; stmt.parameter_count()];
        stmt.query_map(rusqlite::params_from_iter(values), |r| r.get(3))
            .unwrap()
            .map(|r| r.unwrap())
            .collect()
    }

    /// The compiled plans: each statement names its index, never sorts, and
    /// never scans `jobs` or `attempts`. Every statement writes its
    /// partial-index predicate (`state_code = 1`, `8000`, `pull_request = 1`,
    /// `state_code IN (0, 1)`, `released_ms IS NULL`) as a literal, so the
    /// plan chosen here is the plan every execution runs — no re-prepare per
    /// bound value. The runtime test below checks what executions do.
    #[test]
    fn placement_statements_plan_their_indexes() {
        let conn = migrated();
        for (name, sql, index) in STATEMENTS {
            let plans = explain(&conn, sql);
            assert!(
                plans.iter().any(|p| p.contains(index)),
                "{name} does not use {index}: {plans:?}"
            );
            assert!(
                plans.iter().all(|p| !p.contains("TEMP B-TREE")),
                "{name} sorts: {plans:?}"
            );
            // A scan is allowed only of the statement's own partial index
            // (`jobs_ready_pr` holds ready pull-request jobs and nothing else).
            let scans_queue = |p: &String| {
                ["SCAN j", "SCAN jobs", "SCAN attempts", "SCAN o", "SCAN a"]
                    .iter()
                    .any(|table| p == table || p.starts_with(&format!("{table} ")))
                    && !p.contains(index)
            };
            assert!(
                !plans.iter().any(scans_queue),
                "{name} scans the queue: {plans:?}"
            );
        }
    }

    const DIGEST: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    /// A store with `runs` runs of 50 quarter-core jobs queued in one
    /// dedicated pool and one enrolled worker; returns the store, its
    /// directory, the tenant, the pool and the worker.
    fn seeded(runs: usize) -> (tempfile::TempDir, Store, TenantId, PoolId, WorkerId) {
        use sentinel_auth::secret::Secret;
        use sentinel_pipeline::{PinnedSource, RunSpec, compile_str};
        use sentinel_protocol::negotiate::{Arch, Capabilities, Negotiated, ProtocolVersion};
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("metadata.sqlite"), Durability::Normal).unwrap();
        let (root, tenant, repo, pool, worker) = (
            UserId::new(),
            TenantId::new(),
            RepoId::new(),
            PoolId::new(),
            WorkerId::new(),
        );
        let mut yaml = String::from("schema: 1\non: [push]\njobs:\n");
        for i in 0..50 {
            yaml.push_str(&format!(
                "  j{i:03}:\n    image: alpine:3\n    resources: {{ cpu: \"0.25\", memory: 128MiB, disk: 1GiB }}\n    steps: [{{ id: s, run: 'true' }}]\n"
            ));
        }
        let spec = RunSpec::new(
            PinnedSource::new(
                "https://github.com/o/r.git",
                "0123456789abcdef0123456789abcdef01234567",
                Some("main"),
            )
            .unwrap(),
            compile_str(&yaml).unwrap(),
        )
        .unwrap();
        let now = UnixMillis(1_000);
        store
            .writer()
            .write(move |tx| {
                provisioning::insert_human(tx, root, "Root", true, now)?;
                auth::create_namespace(
                    tx,
                    Principal::new(root, P::ALL, None, None),
                    tenant,
                    Namespace::parse("acme").unwrap(),
                    NamespaceKind::Organization,
                    now,
                )?;
                jobs::insert_repo(tx, tenant, repo, "app", now)?;
                tenancy::create_pool(
                    tx,
                    Authority::HostLocal,
                    pool,
                    "farm",
                    PoolKind::Dedicated(tenant),
                    now,
                )?;
                let issued =
                    crate::workers::issue_enrollment(tx, Authority::HostLocal, pool, 60_000, now)?;
                let mut text = String::new();
                issued.secret.expose(&mut text);
                crate::workers::enroll(
                    tx,
                    &Secret::parse(&text).unwrap(),
                    crate::workers::Presentation {
                        worker,
                        fingerprint: Secret::generate().digest(),
                        name: "w",
                        negotiated: Negotiated {
                            protocol: ProtocolVersion(7),
                            capabilities: Capabilities::REQUIRED,
                            arch: Arch::X86_64,
                        },
                    },
                    now,
                )?;
                report_capacity(
                    tx,
                    worker,
                    Capacity {
                        cpu_millis: 8_000,
                        memory_bytes: 8 << 30,
                        disk_bytes: 64 << 30,
                    },
                )?;
                for _ in 0..runs {
                    let ids = runs::create_run(tx, tenant, repo, RunId::new(), &spec, now)?;
                    for job in ids {
                        runs::resolve_image(tx, tenant, job, DIGEST, "linux/amd64")?;
                    }
                }
                Ok(())
            })
            .unwrap();
        (dir, store, tenant, pool, worker)
    }

    /// What each statement actually does against a 2,000-job queue with no
    /// pull-request or large job waiting — the common case, and the one
    /// where the shipped PR probe walked the whole ready queue (P08-9):
    /// zero full-scan steps and zero sorts. SQLite's own counters, not a
    /// plan: a bound parameter that changed the runtime plan would show here.
    #[test]
    fn placement_statements_never_scan_the_queue_at_runtime() {
        let (dir, store, tenant, pool, worker) = seeded(40);
        drop(store);
        let conn = Connection::open(dir.path().join("metadata.sqlite")).unwrap();
        crate::register_functions(&conn).unwrap();
        let repo: [u8; 16] = conn
            .query_row("SELECT id FROM repos LIMIT 1", [], |r| r.get(0))
            .unwrap();
        let job: [u8; 16] = conn
            .query_row("SELECT id FROM jobs LIMIT 1", [], |r| r.get(0))
            .unwrap();
        let bounds = named_params! {
            ":pool": pool.as_bytes(),
            ":arch": "x86_64",
            ":cpu": 8_000i64,
            ":memory": 8i64 << 30,
            ":disk_reported": 1i64,
            ":disk": 64i64 << 30,
            ":labels": Vec::<u8>::new(),
            ":worker_secret_delivery": 0i64,
        };
        let page = named_params! {
            ":tenant": tenant.as_bytes(),
            ":repo": repo,
            ":arch": "x86_64",
            ":cpu": 8_000i64,
            ":memory": 8i64 << 30,
            ":disk_reported": 1i64,
            ":disk": 64i64 << 30,
            ":labels": Vec::<u8>::new(),
            ":worker_secret_delivery": 0i64,
            ":after_priority": i64::MIN,
            ":after_queued": i64::MIN,
            ":after_seq": i64::MIN,
            ":large": 0i64,
            ":large_since": 0i64,
            ":pr_reserve": 0i64,
            ":exclusive": 0i64,
            ":far_cpu": 0i64,
            ":far_memory": 0i64,
            ":far_disk": 0i64,
        };
        let run = |name: &str, sql: &str, params: &[(&str, &dyn rusqlite::ToSql)]| {
            let mut stmt = conn.prepare(sql).unwrap();
            let mut rows = stmt.query(params).unwrap();
            let mut n = 0;
            while rows.next().unwrap().is_some() {
                n += 1;
            }
            drop(rows);
            let (scans, sorts) = (
                stmt.get_status(StatementStatus::FullscanStep),
                stmt.get_status(StatementStatus::Sort),
            );
            assert_eq!((scans, sorts), (0, 0), "{name} ({n} rows): scans/sorts");
            n
        };
        let t = tenant.as_bytes().to_vec();
        // The prefetch head is a scan by design — of its partial index, in
        // order, stopped by its bound: 2,000 ready jobs, `PREFETCH_SCAN`
        // rows read, and no more index steps than that, never a sort.
        {
            let mut stmt = conn.prepare(PREFETCH_HEAD_SQL).unwrap();
            let rows = stmt
                .query_map([PREFETCH_SCAN as i64], |_| Ok(()))
                .unwrap()
                .count();
            assert_eq!(rows, PREFETCH_SCAN);
            let (steps, sorts) = (
                stmt.get_status(StatementStatus::FullscanStep),
                stmt.get_status(StatementStatus::Sort),
            );
            assert!(steps < PREFETCH_SCAN as i32, "prefetch head: {steps} steps");
            assert_eq!(sorts, 0, "prefetch head sorts");
        }
        assert_eq!(run("candidate page", CANDIDATES_SQL, page), PAGE);
        assert_eq!(run("pull-request page", PR_CANDIDATES_SQL, page), 0);
        assert_eq!(run("large-job probe", LARGE_WAITING_SQL, bounds), 0);
        assert_eq!(run("pull-request probe", PR_WAITING_SQL, bounds), 1);
        assert_eq!(
            run(
                "ready tenants",
                READY_TENANTS_SQL,
                &[("?1", &pool.as_bytes().to_vec())]
            ),
            1
        );
        assert_eq!(run("ready repositories", READY_REPOS_SQL, &[("?1", &t)]), 1);
        run("tenant held", TENANT_HELD_SQL, &[("?1", &t)]);
        run(
            "repository held",
            REPO_HELD_SQL,
            &[("?1", &t), ("?2", &repo.to_vec())],
        );
        run(
            "free capacity",
            FREE_CAPACITY_SQL,
            &[("?1", &worker.as_bytes().to_vec())],
        );
        assert_eq!(
            run(
                "queued page",
                QUEUED_PAGE_SQL,
                &[("?1", &t), ("?2", &100i64)]
            ),
            100
        );
        run(
            "blocked page",
            BLOCKED_PAGE_SQL,
            &[("?1", &t), ("?2", &100i64)],
        );
        run("waiting count", WAITING_COUNT_SQL, &[("?1", &t)]);
        run("group held", GROUP_HELD_SQL, &[("?1", &job.to_vec())]);
    }

    #[test]
    fn labels_are_contained_by_one_merge_walk() {
        let enc = |labels: &[&str]| {
            encode_labels(&labels.iter().map(|l| (*l).to_owned()).collect::<Vec<_>>()).unwrap()
        };
        let worker = enc(&["gpu", "linux", "ssd"]);
        assert!(labels_subset(&enc(&[]), &worker));
        assert!(labels_subset(&enc(&[]), &enc(&[])));
        assert!(labels_subset(&enc(&["linux"]), &worker));
        assert!(labels_subset(&enc(&["ssd", "gpu"]), &worker));
        assert!(labels_subset(&worker, &worker));
        assert!(!labels_subset(&enc(&["arm"]), &worker));
        assert!(!labels_subset(&enc(&["zfs"]), &worker));
        assert!(!labels_subset(&enc(&["gpu", "tpu"]), &worker));
        assert!(!labels_subset(&enc(&["gpu"]), &enc(&[])));
        // A prefix of a label is not the label.
        assert!(!labels_subset(&enc(&["gp"]), &worker));
        assert!(!labels_subset(&enc(&["gpus"]), &worker));
    }
}
