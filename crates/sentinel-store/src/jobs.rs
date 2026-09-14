//! Trusted controller row operations, not client authorization. Client entry
//! points must use `crate::auth`. Tenant-owned operations take `TenantId`
//! and includes it in the predicate, so a guessed ID from another tenant is
//! indistinguishable from a missing row. Transitions are compare-and-set on
//! `(state_code, fence)` using the pure state machine from `sentinel-core`.
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use sentinel_core::{
    Actor, AttemptId, AttemptTimestamps, Event, FailureClass, Fence, JobId, JobState, RepoId,
    RunId, RunState, TenantId, UnixMillis, WorkerId, aggregate,
};

use crate::{
    Error, Result,
    codec::{READY, decode_state, encode_failure, encode_state},
};

pub fn insert_tenant(
    tx: &Transaction<'_>,
    id: TenantId,
    slug: &str,
    now: UnixMillis,
) -> Result<()> {
    tx.execute(
        "INSERT INTO tenants(id, slug, created_ms) VALUES (?1, ?2, ?3)",
        params![id.as_bytes(), slug, now.0],
    )?;
    Ok(())
}

pub fn insert_repo(
    tx: &Transaction<'_>,
    tenant: TenantId,
    id: RepoId,
    name: &str,
    now: UnixMillis,
) -> Result<()> {
    tx.execute(
        "INSERT INTO repos(id, tenant_id, name, created_ms) VALUES (?1, ?2, ?3, ?4)",
        params![id.as_bytes(), tenant.as_bytes(), name, now.0],
    )?;
    Ok(())
}

pub fn insert_run(
    tx: &Transaction<'_>,
    tenant: TenantId,
    repo: RepoId,
    id: RunId,
    source_sha: &str,
    now: UnixMillis,
) -> Result<()> {
    // The repo must belong to the tenant; the subquery makes a foreign repo a constraint failure.
    let n = tx.execute(
        "INSERT INTO runs(id, tenant_id, repo_id, source_sha, created_ms)
         SELECT ?1, ?2, id, ?4, ?5 FROM repos WHERE id = ?3 AND tenant_id = ?2",
        params![
            id.as_bytes(),
            tenant.as_bytes(),
            repo.as_bytes(),
            source_sha,
            now.0
        ],
    )?;
    if n == 0 {
        return Err(Error::NotFound);
    }
    Ok(())
}

/// Insert a compiled job in `Blocked`. `created_seq` orders jobs of equal
/// priority; callers pass a monotonic per-run or global sequence.
pub fn insert_job(
    tx: &Transaction<'_>,
    tenant: TenantId,
    run: RunId,
    id: JobId,
    name: &str,
    priority: u8,
    created_seq: i64,
) -> Result<()> {
    let n = tx.execute(
        "INSERT INTO jobs(id, tenant_id, run_id, name, state_code, priority, created_seq)
         SELECT ?1, ?2, id, ?4, ?5, ?6, ?7 FROM runs WHERE id = ?3 AND tenant_id = ?2",
        params![
            id.as_bytes(),
            tenant.as_bytes(),
            run.as_bytes(),
            name,
            encode_state(JobState::Blocked),
            priority as i64,
            created_seq
        ],
    )?;
    if n == 0 {
        return Err(Error::NotFound);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JobRow {
    pub state: JobState,
    pub fence: Fence,
    pub cancel_requested: bool,
    pub failure_class: Option<FailureClass>,
    pub timestamps: AttemptTimestamps,
}

fn read_job(conn: &Connection, tenant: TenantId, job: JobId) -> Result<JobRow> {
    conn.query_row(
        "SELECT state_code, fence, cancel_requested, failure_class,
                queued_ms, leased_ms, preparing_ms, running_ms, finalizing_ms, terminal_ms
         FROM jobs WHERE id = ?1 AND tenant_id = ?2",
        params![job.as_bytes(), tenant.as_bytes()],
        |r| {
            let ms = |i: usize| -> rusqlite::Result<Option<UnixMillis>> {
                Ok(r.get::<_, Option<i64>>(i)?.map(UnixMillis))
            };
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, Option<i64>>(3)?,
                AttemptTimestamps {
                    queued: ms(4)?,
                    leased: ms(5)?,
                    preparing: ms(6)?,
                    running: ms(7)?,
                    finalizing: ms(8)?,
                    terminal: ms(9)?,
                },
            ))
        },
    )
    .optional()?
    .ok_or(Error::NotFound)
    .and_then(|(code, fence, cancel, class, timestamps)| {
        Ok(JobRow {
            state: decode_state(code).ok_or(Error::Corrupt("state_code"))?,
            fence: Fence(fence as u64),
            cancel_requested: cancel != 0,
            failure_class: match class {
                None => None,
                Some(c) => {
                    Some(crate::codec::decode_failure(c).ok_or(Error::Corrupt("failure_class"))?)
                }
            },
            timestamps,
        })
    })
}

pub fn get_job(conn: &Connection, tenant: TenantId, job: JobId) -> Result<JobRow> {
    read_job(conn, tenant, job)
}

/// Apply `event` to the job as `actor`. The row is read, the pure machine
/// decides, and the `UPDATE` is guarded by the state and fence that were
/// read: if anything changed in between the update touches zero rows and
/// `Conflict` is returned, so retrying from a fresh read is always safe.
pub fn transition(
    tx: &Transaction<'_>,
    tenant: TenantId,
    job: JobId,
    actor: Actor,
    event: Event,
    now: UnixMillis,
) -> Result<JobState> {
    let row = read_job(tx, tenant, job)?;
    let mut control = sentinel_core::JobControl {
        state: row.state,
        fence: row.fence,
        cancel_requested: row.cancel_requested,
    };
    let next = control.apply(actor, event)?;
    // Static SQL per entered state keeps the statement cache small and avoids
    // formatting on the hot path.
    let sql = match next {
        JobState::Queued => UPDATE_QUEUED,
        JobState::Leased => UPDATE_LEASED,
        JobState::Preparing => UPDATE_PREPARING,
        JobState::Running => UPDATE_RUNNING,
        JobState::Finalizing => UPDATE_FINALIZING,
        JobState::Terminal(_) => UPDATE_TERMINAL,
        JobState::Blocked => unreachable!("no event enters Blocked"),
    };
    let failure = match event {
        Event::Failed(class) => Some(encode_failure(class)),
        Event::LeaseExpired => Some(encode_failure(FailureClass::LeaseExpired)),
        Event::WorkerLost => Some(encode_failure(FailureClass::WorkerLost)),
        Event::Reconciled => Some(encode_failure(FailureClass::Reconciled)),
        Event::CancelBeforeStart => Some(encode_failure(FailureClass::Canceled)),
        Event::QueueTimedOut => Some(encode_failure(FailureClass::QueueTimeout)),
        _ => None,
    };
    let mut stmt = tx.prepare_cached(sql)?;
    let changed = stmt.execute(params![
        encode_state(next),
        control.fence.0 as i64,
        failure,
        now.0,
        job.as_bytes(),
        tenant.as_bytes(),
        encode_state(row.state),
        row.fence.0 as i64,
    ])?;
    if changed != 1 {
        return Err(Error::Conflict);
    }
    Ok(next)
}

macro_rules! update_sql {
    ($col:literal) => {
        concat!(
            "UPDATE jobs SET state_code = ?1, fence = ?2, failure_class = COALESCE(?3, failure_class), ",
            $col,
            " = COALESCE(",
            $col,
            ", ?4) WHERE id = ?5 AND tenant_id = ?6 AND state_code = ?7 AND fence = ?8"
        )
    };
}
const UPDATE_QUEUED: &str = update_sql!("queued_ms");
const UPDATE_LEASED: &str = update_sql!("leased_ms");
const UPDATE_PREPARING: &str = update_sql!("preparing_ms");
const UPDATE_RUNNING: &str = update_sql!("running_ms");
const UPDATE_FINALIZING: &str = update_sql!("finalizing_ms");
const UPDATE_TERMINAL: &str = update_sql!("terminal_ms");

/// Durable cancel desired state. Returns whether the job was still unstarted,
/// in which case the caller also applies `Event::CancelBeforeStart`.
pub fn request_cancel(tx: &Transaction<'_>, tenant: TenantId, job: JobId) -> Result<bool> {
    let n = tx.execute(
        "UPDATE jobs SET cancel_requested = 1 WHERE id = ?1 AND tenant_id = ?2",
        params![job.as_bytes(), tenant.as_bytes()],
    )?;
    if n == 0 {
        return Err(Error::NotFound);
    }
    let row = read_job(tx, tenant, job)?;
    Ok(matches!(row.state, JobState::Blocked | JobState::Queued))
}

/// The dispatcher's pick: the best ready job across all tenants (fairness
/// between tenants is a scheduler concern layered above this query). Uses
/// the partial index only; no table scan.
pub fn pick_ready(conn: &Connection) -> Result<Option<(TenantId, JobId)>> {
    conn.query_row(
        "SELECT tenant_id, id FROM jobs WHERE state_code = ?1
         ORDER BY priority, created_seq LIMIT 1",
        [READY],
        |r| Ok((r.get::<_, [u8; 16]>(0)?, r.get::<_, [u8; 16]>(1)?)),
    )
    .optional()?
    .map(|(t, j)| {
        Ok((
            TenantId::from_bytes(t).map_err(|_| Error::Corrupt("tenant_id"))?,
            JobId::from_bytes(j).map_err(|_| Error::Corrupt("job_id"))?,
        ))
    })
    .transpose()
}

/// Lease the job to `worker` with the next fence in one transaction: the
/// attempt row — which is also the resource reservation, copied from the job
/// — and the `Leased` transition commit together or not at all. Whether the
/// worker has room is [`crate::dispatch::place`]'s check, made in the same
/// transaction; this is the durable half.
///
/// Executable admission: a job whose image digest and platform are not yet
/// durably resolved is refused with `Unresolved`. Its spec may exist; its
/// existence is not readiness.
pub fn lease(
    tx: &Transaction<'_>,
    tenant: TenantId,
    job: JobId,
    worker: WorkerId,
    lease_until: UnixMillis,
    now: UnixMillis,
) -> Result<(AttemptId, Fence)> {
    let (resolved, cpu_millis, memory_bytes): (bool, i64, i64) = tx
        .prepare_cached(
            "SELECT image_digest IS NOT NULL AND image_platform IS NOT NULL, cpu_millis, memory_bytes
             FROM jobs WHERE id = ?1 AND tenant_id = ?2",
        )?
        .query_row(params![job.as_bytes(), tenant.as_bytes()], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?))
        })
        .optional()?
        .ok_or(Error::NotFound)?;
    if !resolved {
        return Err(Error::Unresolved);
    }
    let row = read_job(tx, tenant, job)?;
    let fence = row.fence.next();
    transition(
        tx,
        tenant,
        job,
        Actor::Controller,
        Event::Leased(fence),
        now,
    )?;
    let attempt = AttemptId::new();
    tx.execute(
        "INSERT INTO attempts(id, tenant_id, job_id, fence, worker_id, lease_until_ms,
                              cpu_millis, memory_bytes, offered_ms)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            attempt.as_bytes(),
            tenant.as_bytes(),
            job.as_bytes(),
            fence.0 as i64,
            worker.as_bytes(),
            lease_until.0,
            cpu_millis,
            memory_bytes,
            now.0
        ],
    )?;
    Ok((attempt, fence))
}

/// Derived run state from its job rows (indexed by `run_id`).
pub fn run_state(conn: &Connection, tenant: TenantId, run: RunId) -> Result<RunState> {
    let mut stmt =
        conn.prepare_cached("SELECT state_code FROM jobs WHERE run_id = ?1 AND tenant_id = ?2")?;
    let rows = stmt.query_map(params![run.as_bytes(), tenant.as_bytes()], |r| {
        r.get::<_, i64>(0)
    })?;
    let mut states = Vec::new();
    for code in rows {
        states.push(decode_state(code?).ok_or(Error::Corrupt("state_code"))?);
    }
    Ok(aggregate(states))
}
