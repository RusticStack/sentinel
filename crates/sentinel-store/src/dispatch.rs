//! The link authenticates the worker before any of this runs; nothing here authorizes a client.

use std::collections::HashMap;

use rusqlite::{Connection, OptionalExtension, Transaction, named_params, params};
use sentinel_core::{
    Actor, AttemptId, DependencyPolicy, Event, FailureClass, Fence, JobId, JobState, Outcome,
    PoolId, RepoId, RunId, TenantId, UnixMillis, WorkerId, dependency_decision,
};
use sentinel_pipeline::{
    expr::{Context, DependencySummary, HashFilesError, Lookup, Phase, Value},
    schema::ArtifactWhen,
};
use sentinel_protocol::{limits::MAX_LIST_ITEMS, summary::MAX_SUMMARY_BYTES};

use crate::{
    Error, Result, artifacts,
    codec::{READY, TERMINAL_BASE, decode_state},
    jobs,
    logs::LogStore,
    runs::{self, ResolvedImage},
};

/// Workers time their own lease from their heartbeat, never by comparing wall clocks.
pub const DEFAULT_LEASE_MS: i64 = sentinel_protocol::limits::LEASE_MS;
pub const OFFER_ACK_MS: i64 = 5_000;
pub const MAX_HELD_ATTEMPTS: usize = MAX_LIST_ITEMS;
pub const QUEUE_TIMEOUT_MS: i64 = 6 * 60 * 60 * 1000;
pub const EXECUTION_GRACE_MS: i64 = 10 * 60 * 1000;
const SWEEP_BATCH: usize = 256;
const SWEEP_LIMIT: usize = 256;

pub const LARGE_JOB_CPU: i64 = 8_000;
pub const PR_RESERVE_DIVISOR: i64 = 4;
pub const LOCALITY_WAIT_MS: i64 = 30_000;

/// Codes are ordered: the attempt_update trigger refuses any regression.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum LogState {
    Pending = 0,
    Incomplete = 1,
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

/// Disk zero means not reported only from workers older than protocol 7; from them it is a real limit.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Capacity {
    pub cpu_millis: i64,
    pub memory_bytes: i64,
    pub disk_bytes: i64,
}

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

const FREE_CAPACITY_SQL: &str = "SELECT w.cpu_millis - COALESCE(s.cpu, 0),
            w.memory_bytes - COALESCE(s.memory, 0),
            CASE WHEN w.disk_bytes = 0 THEN 0 ELSE w.disk_bytes - COALESCE(s.disk, 0) END
     FROM workers w,
          (SELECT SUM(a.cpu_millis) AS cpu, SUM(a.memory_bytes) AS memory,
                  SUM(a.disk_bytes) AS disk
           FROM workers me JOIN workers h
                ON ((me.host_id IS NOT NULL AND h.host_id = me.host_id)
                    OR (me.host_id IS NULL AND h.id = me.id))
           JOIN attempts a ON a.worker_id = h.id AND a.released_ms IS NULL
           WHERE me.id = ?1) s
     WHERE w.id = ?1 AND w.revoked_ms IS NULL";

fn disk_reported(protocol: i64) -> bool {
    protocol >= i64::from(sentinel_protocol::negotiate::PROFILE_MIN.0)
}

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

pub const MAX_LABELS: usize = 16;
pub const MAX_LABEL_BYTES: usize = 64;
pub const IMAGE_KEY_BYTES: usize = 8;

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

fn caches_image(avail_images: &[u8], key: &[u8; IMAGE_KEY_BYTES]) -> bool {
    avail_images
        .chunks_exact(IMAGE_KEY_BYTES)
        .any(|chunk| chunk == key)
}

pub struct ReportedProfile<'a> {
    pub labels: &'a [String],
    pub host_id: Option<[u8; 16]>,
    pub avail_images: &'a [[u8; IMAGE_KEY_BYTES]],
    pub cache_bytes: Option<i64>,
    pub load_ns: Option<i64>,
}

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
    pub job_index: u32,
}

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
    priority: i64,
    created_seq: i64,
}

#[derive(Clone, Debug)]
struct WorkerFacts {
    pool: PoolId,
    arch: String,
    labels: Vec<u8>,
    draining: bool,
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
            disk_reported: disk_reported(protocol),
            avail_images,
            cpu_millis: cpu,
            memory_bytes: memory,
            disk_bytes,
            secret_delivery: secret_capable(capabilities, protocol),
        },
    )))
}

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
                disk_reported: disk_reported(protocol),
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

const PAGE: usize = 16;
const MAX_PAGES: usize = 8;

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

const PR_CANDIDATES_SQL: &str =
    candidates_sql!("jobs j INDEXED BY jobs_ready_pr", "j.pull_request = 1 AND ");

const _: () = assert!(PAGE == 16, "CANDIDATES_SQL hardcodes the page size");

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

const TENANT_HELD_SQL: &str = "SELECT COALESCE(SUM(cpu_millis), 0) FROM attempts
     WHERE tenant_id = ?1 AND released_ms IS NULL";
const REPO_HELD_SQL: &str = "SELECT COALESCE(SUM(cpu_millis), 0) FROM attempts
     WHERE tenant_id = ?1 AND repo_id = ?2 AND released_ms IS NULL";

#[derive(Clone, Debug)]
struct Stream {
    tenant: TenantId,
    repo: [u8; 16],
    key: (i64, i64, i64, i64),
}

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

#[derive(Clone, Copy, Debug, Default)]
struct Fairness {
    large: Option<(i64, i64)>,
    pr_reserve: i64,
}

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
        pr_reserve: if pr {
            facts.cpu_millis / PR_RESERVE_DIVISOR
        } else {
            0
        },
    })
}

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

struct LocalityWorker {
    id: WorkerId,
    arch: String,
    labels: Vec<u8>,
    cpu_millis: i64,
    memory_bytes: i64,
    disk_bytes: i64,
    disk_reported: bool,
    avail_images: Vec<u8>,
    /// An upper bound on completion, never the lease deadline: renewal would keep busy warm workers looking about to free.
    frees_by: Option<i64>,
}

fn locality_view(conn: &Connection, tenant: TenantId) -> Result<Vec<LocalityWorker>> {
    let mut stmt = conn.prepare_cached(
        "SELECT w.id, w.arch, w.labels, w.cpu_millis, w.memory_bytes, w.disk_bytes,
                w.avail_images, w.protocol,
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
            r.get::<_, i64>(7)?,
            r.get::<_, Option<i64>>(8)?,
        ))
    })?;
    let mut out = Vec::new();
    for row in rows {
        let (
            id,
            arch,
            labels,
            (cpu_millis, memory_bytes, disk_bytes),
            avail_images,
            protocol,
            frees_by,
        ) = row?;
        out.push(LocalityWorker {
            id: WorkerId::from_bytes(id).map_err(|_| Error::Corrupt("worker id"))?,
            arch,
            labels,
            cpu_millis,
            memory_bytes,
            disk_bytes,
            disk_reported: disk_reported(protocol),
            avail_images,
            frees_by,
        });
    }
    Ok(out)
}

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
            && !(pick.disk_bytes > 0 && worker.disk_reported && worker.disk_bytes < pick.disk_bytes)
            && caches_image(&worker.avail_images, &key)
            && worker.frees_by.is_none_or(|until| until <= bound)
    })
}

pub const MAX_PREFETCH_HINTS: usize = 4;
pub const PREFETCH_FANOUT: usize = 2;
pub const PREFETCH_SCAN: usize = 256;

pub fn prefetch_name(name: &str) -> bool {
    (1..=255).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'/' | b':'))
        && !name.starts_with(['/', '-', ':', '.'])
}

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

const PREFETCH_HEAD_SQL: &str = "SELECT j.tenant_id, j.image_name, j.image_digest, j.arch,
            j.labels, j.cpu_millis, j.memory_bytes, j.disk_bytes, j.priority, j.queued_ms,
            j.created_seq
     FROM (SELECT id FROM jobs INDEXED BY jobs_queued_since WHERE state_code = 1
           ORDER BY queued_ms LIMIT ?1) h
     JOIN jobs j ON j.id = h.id
     WHERE j.cancel_requested = 0 AND j.image_name IS NOT NULL
       AND j.image_digest IS NOT NULL AND j.image_platform IS NOT NULL";

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

pub fn prefetch_hints(
    conn: &Connection,
    workers: &[WorkerId],
) -> Result<Vec<(WorkerId, Vec<String>)>> {
    let mut out: Vec<(WorkerId, Vec<String>)> = workers.iter().map(|w| (*w, Vec::new())).collect();
    if workers.is_empty() || !any_ready(conn)? {
        return Ok(out);
    }
    let held = held_by_worker(conn)?;
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

pub fn place(
    tx: &Transaction<'_>,
    worker: WorkerId,
    pool: PoolId,
    lease_ms: i64,
    now: UnixMillis,
) -> Result<Option<Offer>> {
    place_in_fleet(tx, worker, pool, None, lease_ms, now)
}

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
    fn place_from_streams(
        &mut self,
        streams: &[Stream],
        far: Option<Capacity>,
        lease_ms: i64,
    ) -> Result<Option<Offer>> {
        for stream in streams {
            let mut after = (i64::MIN, i64::MIN, i64::MIN);
            for _ in 0..MAX_PAGES {
                let (found, full) = self.scan_page(stream, far, &mut after)?;
                if let Some(pick) = found {
                    return self.lease(pick, lease_ms).map(Some);
                }
                if !full {
                    break;
                }
            }
        }
        Ok(None)
    }

    /// Rows are dropped before a pick is returned, so the lease's writes never run under a live read cursor.
    fn scan_page(
        &mut self,
        stream: &Stream,
        far: Option<Capacity>,
        after: &mut (i64, i64, i64),
    ) -> Result<(Option<Pick>, bool)> {
        let tx = self.tx;
        let (large, large_since) = self.fairness.large.unwrap_or((0, 0));
        let far = far.map(|far| (1i64, far));
        let (exclusive, far) = far.unwrap_or((0, Capacity::default()));
        let sql =
            if self.fairness.pr_reserve > 0 && self.free.cpu_millis <= self.fairness.pr_reserve {
                PR_CANDIDATES_SQL
            } else {
                CANDIDATES_SQL
            };
        let mut stmt = tx.prepare_cached(sql)?;
        let mut rows = stmt.query(named_params! {
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
        })?;
        let mut seen = 0;
        while let Some(r) = rows.next()? {
            seen += 1;
            let order = (r.get::<_, i64>(12)?, r.get::<_, i64>(13)?);
            let pick = Pick {
                tenant: stream.tenant,
                repo: Some(stream.repo),
                job: JobId::from_bytes(r.get(0)?).map_err(|_| Error::Corrupt("job_id"))?,
                run: RunId::from_bytes(r.get(1)?).map_err(|_| Error::Corrupt("run_id"))?,
                cpu_millis: r.get(2)?,
                memory_bytes: r.get(3)?,
                disk_bytes: r.get(4)?,
                image_digest: r.get(5)?,
                image_platform: r.get(6)?,
                spec_index: r.get(7)?,
                arch: r.get(8)?,
                labels: r.get(9)?,
                queued_ms: r.get(10)?,
                pull_request: r.get(11)?,
                priority: order.0,
                created_seq: order.1,
                requires_secret_delivery: r.get(14)?,
            };
            *after = (pick.priority, pick.queued_ms, pick.created_seq);
            if !self
                .locality
                .holds(tx, self.worker, self.facts, &pick, self.now)?
            {
                return Ok((Some(pick), true));
            }
        }
        Ok((None, seen == PAGE))
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

pub fn any_ready(conn: &Connection) -> Result<bool> {
    Ok(conn
        .prepare_cached(
            "SELECT EXISTS(SELECT 1 FROM jobs WHERE state_code = 1 AND cancel_requested = 0
                           AND image_digest IS NOT NULL)",
        )?
        .query_row([], |r| r.get(0))?)
}

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

pub fn revocations(conn: &Connection) -> Result<(i64, i64)> {
    Ok(conn
        .prepare_cached(
            "SELECT COALESCE(MAX(revoked_ms), 0), COUNT(*) FROM workers
             WHERE revoked_ms IS NOT NULL",
        )?
        .query_row([], |r| Ok((r.get(0)?, r.get(1)?)))?)
}

fn worker_live(conn: &Connection, worker: WorkerId) -> Result<bool> {
    Ok(conn
        .prepare_cached(
            "SELECT EXISTS(SELECT 1 FROM workers WHERE id = ?1 AND revoked_ms IS NULL)",
        )?
        .query_row([worker.as_bytes()], |r| r.get(0))?)
}

pub fn revoked_among(conn: &Connection, workers: &[WorkerId]) -> Result<Vec<WorkerId>> {
    let mut out = Vec::new();
    for worker in workers {
        if !worker_live(conn, *worker)? {
            out.push(*worker);
        }
    }
    Ok(out)
}

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

pub fn acknowledge(
    tx: &Transaction<'_>,
    worker: WorkerId,
    attempt: AttemptId,
    fence: Fence,
    now: UnixMillis,
) -> Result<UnixMillis> {
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SpecGate {
    Ready,
    Unacknowledged,
    Canceled(Fence),
    NotHeld,
}

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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Held {
    pub attempt: AttemptId,
    pub tenant: TenantId,
    pub job: JobId,
    pub fence: Fence,
    pub acknowledged: bool,
    pub lease_until: UnixMillis,
}

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

fn due_coverage(
    tx: &Transaction<'_>,
    spec: &sentinel_pipeline::RunSpec,
    spec_index: u32,
    attempt: AttemptId,
    passed: bool,
) -> Result<(Vec<sentinel_pipeline::schema::Artifact>, bool)> {
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
    let mut spec = None;
    if finishing {
        let decoded = runs::get_run_spec(tx, tenant, run)?;
        let lost;
        (missing, lost) = due_coverage(tx, &decoded, index, attempt, event == Event::Passed)?;
        spec = Some(decoded);
        if event == Event::Passed && lost {
            event = Event::Failed(FailureClass::Publication);
        }
    }
    let next = jobs::transition(tx, tenant, job, actor, event, now)?;
    if !next.is_terminal() {
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
    release_dependents_with(tx, tenant, run, now, &mut spec)?;
    Ok(next)
}

pub fn log_ended(tx: &Transaction<'_>, attempt: AttemptId) -> Result<()> {
    tx.prepare_cached("UPDATE attempts SET log_state = ?2 WHERE id = ?1 AND log_state <> ?2")?
        .execute(params![attempt.as_bytes(), LogState::Complete.code()])?;
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cancelled {
    Terminal,
    Requested,
    AlreadyTerminal,
}

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

pub fn cancel_run(
    tx: &Transaction<'_>,
    tenant: TenantId,
    run: RunId,
    now: UnixMillis,
) -> Result<usize> {
    let mut count = 0;
    tx.prepare_cached("UPDATE runs SET cancel_requested = 1 WHERE id = ?1 AND tenant_id = ?2")?
        .execute(params![run.as_bytes(), tenant.as_bytes()])?;
    for (job, state) in runs::run_jobs(tx, tenant, run)? {
        if !state.is_terminal() && cancel_one(tx, tenant, job, now)? != Cancelled::AlreadyTerminal {
            count += 1;
        }
    }
    release_dependents(tx, tenant, run, now)?;
    Ok(count)
}

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

pub fn expired(conn: &Connection, now: UnixMillis) -> Result<Vec<AttemptId>> {
    Ok(expired_scoped(conn, now)?
        .into_iter()
        .map(|(attempt, _, _)| attempt)
        .collect())
}

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

/// The deadline is re-checked here, in the same transaction as the transition, so a renewal
/// that committed after the sweep read the lease as due wins.
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

pub fn lapse_due(tx: &Transaction<'_>, now: UnixMillis) -> Result<Swept> {
    let mut swept = Swept::default();
    for attempt in unacknowledged(tx, now)? {
        swept.record(isolated(tx, || lapse(tx, attempt, now)));
    }
    Ok(swept)
}

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

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Reconciled {
    pub expired: usize,
    pub lapsed: usize,
    pub orphaned: usize,
}

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
    done.orphaned = reconcile_revoked(tx, now, logs)?;
    Ok(done)
}

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
    let event = match event {
        Event::Failed(FailureClass::Canceled) if !cancel_requested => {
            Event::Failed(FailureClass::Runtime)
        }
        event => event,
    };
    let summary = summary.filter(|s| s.len() <= MAX_SUMMARY_BYTES);
    let next = finish(tx, attempt, Actor::Worker(fence), event, now, logs)?;
    if let Some(summary) = summary
        && next.is_terminal()
    {
        tx.prepare_cached("UPDATE attempts SET summary = ?2 WHERE id = ?1 AND summary IS NULL")?
            .execute(params![attempt.as_bytes(), summary])?;
    }
    Ok(next)
}

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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JobContext {
    pub tenant: TenantId,
    pub run: RunId,
    pub repo: RepoId,
    pub repo_name: String,
    pub job: JobId,
    pub job_name: String,
    pub sha: String,
    pub event: crate::provenance::EventFacts,
    pub trust: sentinel_protocol::cache::Trust,
    pub cancelled: bool,
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

/// Nothing that could start work leaves before the acknowledgement is durable, so a lapsed offer never also runs.
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

pub fn is_held(conn: &Connection, worker: WorkerId, attempt: AttemptId) -> Result<bool> {
    Ok(conn
        .prepare_cached(
            "SELECT EXISTS(SELECT 1 FROM attempts a JOIN workers w ON w.id = a.worker_id
                           WHERE a.id = ?1 AND a.worker_id = ?2 AND a.released_ms IS NULL
                             AND w.revoked_ms IS NULL)",
        )?
        .query_row(params![attempt.as_bytes(), worker.as_bytes()], |r| r.get(0))?)
}

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

pub fn attempt_log_scope(
    conn: &Connection,
    worker: WorkerId,
    attempt: AttemptId,
) -> Result<(RunId, JobId)> {
    let Some((run, job)) = conn
        .prepare_cached(
            "SELECT j.run_id, j.id FROM attempts a JOIN jobs j ON j.id = a.job_id
             JOIN workers w ON w.id = a.worker_id
             WHERE a.id = ?1 AND a.worker_id = ?2 AND w.revoked_ms IS NULL
               AND a.log_expired_ms IS NULL",
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

pub fn release_dependents(
    tx: &Transaction<'_>,
    tenant: TenantId,
    run: RunId,
    now: UnixMillis,
) -> Result<usize> {
    release_dependents_with(tx, tenant, run, now, &mut None)
}

fn release_dependents_with(
    tx: &Transaction<'_>,
    tenant: TenantId,
    run: RunId,
    now: UnixMillis,
    cached: &mut Option<sentinel_pipeline::RunSpec>,
) -> Result<usize> {
    let mut states = runs::run_jobs(tx, tenant, run)?;
    if !states.iter().any(|(_, s)| *s == JobState::Blocked) {
        return Ok(0);
    }
    if cached.is_none() {
        *cached = Some(runs::get_run_spec(tx, tenant, run)?);
    }
    let spec = cached.as_ref().ok_or(Error::Corrupt("run_specs.spec"))?;
    let mut by_failure = failure_skips(&states, spec)?;
    let mut facts: Option<RunFacts> = None;
    let mut released = 0;
    for index in 0..states.len() {
        let (job, state) = states[index];
        if state != JobState::Blocked {
            continue;
        }
        let effective = |need: u16| effective_state(&states, &by_failure, usize::from(need));
        let Some(compiled) = spec.pipeline.jobs.get(index) else {
            return Err(Error::Corrupt("run_specs.spec"));
        };
        if compiled
            .needs
            .iter()
            .any(|need| usize::from(*need) >= index)
        {
            return Err(Error::Corrupt("run_specs.spec"));
        }
        let event = match &compiled.spec.condition {
            None => {
                let mut decision = Some(true);
                for need in &compiled.needs {
                    match dependency_decision(DependencyPolicy::OnSuccess, effective(*need)) {
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
                match decision {
                    Some(true) => Event::DependenciesSatisfied,
                    Some(false) => Event::Skip,
                    None => continue,
                }
            }
            Some(condition) => {
                let mut summary = DependencySummary {
                    all_succeeded: true,
                    any_failed: false,
                };
                let mut results = Vec::with_capacity(compiled.needs.len());
                let mut waiting = false;
                for need in &compiled.needs {
                    let JobState::Terminal(counted) = effective(*need) else {
                        waiting = true;
                        break;
                    };
                    let need = usize::from(*need);
                    let JobState::Terminal(actual) = states[need].1 else {
                        return Err(Error::Corrupt("run_specs.spec"));
                    };
                    summary.all_succeeded &= counted.is_success();
                    summary.any_failed |= !counted.is_success();
                    results.push((spec.pipeline.jobs[need].name.as_str(), actual));
                }
                if waiting {
                    continue;
                }
                if facts.is_none() {
                    facts = Some(run_facts(tx, tenant, run)?);
                }
                let Some(facts) = facts.as_ref() else {
                    return Err(Error::Corrupt("run facts"));
                };
                if !condition.uses_status_function() && (!summary.all_succeeded || facts.cancelled)
                {
                    Event::Skip
                } else {
                    let context = ScheduleContext {
                        facts,
                        sha: &spec.source.sha,
                        run,
                        job,
                        job_name: &compiled.name,
                        summary,
                        results,
                    };
                    match condition.eval(&context).map(|v| v.as_condition()) {
                        Ok(Some(true)) => Event::DependenciesSatisfied,
                        Ok(Some(false)) => Event::Skip,
                        Ok(None) | Err(_) => Event::ConditionFailed,
                    }
                }
            }
        };
        let next = jobs::transition(tx, tenant, job, Actor::Controller, event, now)?;
        let ended_by_failure = next == JobState::Terminal(Outcome::Skipped)
            && compiled.needs.iter().any(|need| {
                matches!(
                    effective_state(&states, &by_failure, usize::from(*need)),
                    JobState::Terminal(o) if !o.is_success()
                )
            });
        states[index].1 = next;
        by_failure[index] = ended_by_failure;
        released += 1;
    }
    Ok(released)
}

fn effective_state(states: &[(JobId, JobState)], by_failure: &[bool], index: usize) -> JobState {
    if by_failure[index] {
        JobState::Terminal(Outcome::Failed)
    } else {
        states[index].1
    }
}

fn failure_skips(
    states: &[(JobId, JobState)],
    spec: &sentinel_pipeline::RunSpec,
) -> Result<Vec<bool>> {
    let mut blocked = vec![false; states.len()];
    for (index, (_, state)) in states.iter().enumerate() {
        if *state != JobState::Terminal(Outcome::Skipped) {
            continue;
        }
        let compiled = spec
            .pipeline
            .jobs
            .get(index)
            .ok_or(Error::Corrupt("run_specs.spec"))?;
        let mut by_failure = false;
        for need in &compiled.needs {
            let need = usize::from(*need);
            if need >= index {
                return Err(Error::Corrupt("run_specs.spec"));
            }
            by_failure |=
                blocked[need] || matches!(states[need].1, JobState::Terminal(o) if !o.is_success());
        }
        blocked[index] = by_failure;
    }
    Ok(blocked)
}

struct RunFacts {
    repo: RepoId,
    repo_name: String,
    cancelled: bool,
    event: crate::provenance::EventFacts,
}

fn run_facts(conn: &Connection, tenant: TenantId, run: RunId) -> Result<RunFacts> {
    let (repo, repo_name, cancelled): ([u8; 16], String, i64) = conn
        .prepare_cached(
            "SELECT r.repo_id, p.name, r.cancel_requested FROM runs r
             JOIN repos p ON p.id = r.repo_id AND p.tenant_id = r.tenant_id
             WHERE r.id = ?1 AND r.tenant_id = ?2",
        )?
        .query_row(params![run.as_bytes(), tenant.as_bytes()], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?))
        })
        .optional()?
        .ok_or(Error::NotFound)?;
    Ok(RunFacts {
        repo: RepoId::from_bytes(repo).map_err(|_| Error::Corrupt("repo_id"))?,
        repo_name,
        cancelled: cancelled != 0,
        event: crate::provenance::event_facts(conn, run)?,
    })
}

struct ScheduleContext<'a> {
    facts: &'a RunFacts,
    sha: &'a str,
    run: RunId,
    job: JobId,
    job_name: &'a str,
    summary: DependencySummary,
    results: Vec<(&'a str, Outcome)>,
}

impl Context for ScheduleContext<'_> {
    fn phase(&self) -> Phase {
        Phase::Schedule
    }

    fn lookup(&self, path: &[String]) -> Lookup {
        let key: Vec<&str> = path.iter().map(String::as_str).collect();
        let event = &self.facts.event;
        Lookup::Value(match key.as_slice() {
            ["event", "sha"] => Value::Str(self.sha.to_owned()),
            ["event", "name"] => Value::Str(event.name.clone()),
            ["event", "ref"] => Value::Str(event.ref_name.clone()),
            ["event", "key"] => Value::Str(event.key.clone()),
            ["event", "base_ref"] => match &event.base_ref {
                Some(base) => Value::Str(base.clone()),
                None => Value::Null,
            },
            ["event", "pr_number"] => match event.pr_number {
                Some(number) => Value::Int(number as i64),
                None => Value::Null,
            },
            ["repo", "id"] => Value::Str(self.facts.repo.to_string()),
            ["repo", "name"] => Value::Str(self.facts.repo_name.clone()),
            ["run", "id"] => Value::Str(self.run.to_string()),
            ["job", "id"] => Value::Str(self.job.to_string()),
            ["job", "name"] => Value::Str(self.job_name.to_owned()),
            ["needs", name, "result"] => match self.results.iter().find(|(n, _)| n == name) {
                Some((_, outcome)) => Value::Str(outcome.as_str().to_owned()),
                None => return Lookup::Unresolved,
            },
            _ => return Lookup::Unresolved,
        })
    }

    fn dependency_summary(&self) -> Option<DependencySummary> {
        Some(self.summary)
    }

    fn cancelled(&self) -> Option<bool> {
        Some(self.facts.cancelled)
    }

    fn hash_files(&self, _patterns: &[&str]) -> std::result::Result<String, HashFilesError> {
        Err(HashFilesError::UnsupportedPlatform)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum WaitReason {
    Dependency,
    Policy(&'static str),
    NoMatchingWorker { cpu_short: i64, memory_short: i64 },
    DiskShort { disk_short: i64 },
    ArchMismatch,
    LabelMissing,
    ConcurrencyLimit,
    WorkerOffline,
    Capacity,
    Drain,
    FairnessHold,
    LocalityWait,
    Ready,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueuedJob {
    pub job: JobId,
    pub run: RunId,
    pub repo: RepoId,
    pub age_ms: i64,
    pub reason: WaitReason,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueuePage {
    pub jobs: Vec<QueuedJob>,
    pub total: usize,
}

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

const QUEUED_PAGE_SQL: &str = concat!(
    waiting_columns!(),
    "WHERE j.tenant_id = ?1 AND j.state_code IN (0, 1) AND j.queued_ms IS NOT NULL
     ORDER BY j.queued_ms, j.created_seq LIMIT ?2"
);
const BLOCKED_PAGE_SQL: &str = concat!(
    waiting_columns!(),
    "WHERE j.tenant_id = ?1 AND j.state_code IN (0, 1) AND j.queued_ms IS NULL
     ORDER BY j.queued_ms, j.created_seq LIMIT ?2"
);
const WAITING_COUNT_SQL: &str =
    "SELECT COUNT(*) FROM jobs WHERE tenant_id = ?1 AND state_code IN (0, 1)";
const WAITING_ONE_SQL: &str = concat!(waiting_columns!(), "WHERE j.id = ?1 AND j.tenant_id = ?2");
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
        assert!(!labels_subset(&enc(&["gp"]), &worker));
        assert!(!labels_subset(&enc(&["gpus"]), &worker));
    }
}
