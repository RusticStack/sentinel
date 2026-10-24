//! Trusted controller operations, not client authorization: client entry points must use `crate::auth`.
//! Tenant-owned rows are read with the tenant in the predicate, so a foreign ID looks like a missing row.
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
        "INSERT INTO jobs(id, tenant_id, run_id, name, state_code, priority, created_seq, repo_id)
         SELECT ?1, ?2, id, ?4, ?5, ?6, ?7, repo_id FROM runs WHERE id = ?3 AND tenant_id = ?2",
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
    conn.prepare_cached(
        "SELECT state_code, fence, cancel_requested, failure_class,
                queued_ms, leased_ms, preparing_ms, running_ms, finalizing_ms, terminal_ms
         FROM jobs WHERE id = ?1 AND tenant_id = ?2",
    )?
    .query_row(params![job.as_bytes(), tenant.as_bytes()], |r| {
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
    })
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

pub fn transition(
    tx: &Transaction<'_>,
    tenant: TenantId,
    job: JobId,
    actor: Actor,
    event: Event,
    now: UnixMillis,
) -> Result<JobState> {
    let row = read_job(tx, tenant, job)?;
    transition_from(tx, tenant, job, &row, actor, event, now)
}

fn transition_from(
    tx: &Transaction<'_>,
    tenant: TenantId,
    job: JobId,
    row: &JobRow,
    actor: Actor,
    event: Event,
    now: UnixMillis,
) -> Result<JobState> {
    let mut control = sentinel_core::JobControl {
        state: row.state,
        fence: row.fence,
        cancel_requested: row.cancel_requested,
    };
    let next = control.apply(actor, event)?;
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
        Event::ConditionFailed => Some(encode_failure(FailureClass::Preparation)),
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
    // Every job state change passes here, so its Checks outbox row cannot be skipped.
    crate::checks::record_job(tx, tenant, job, now)?;
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

pub fn lease(
    tx: &Transaction<'_>,
    tenant: TenantId,
    job: JobId,
    worker: WorkerId,
    lease_until: UnixMillis,
    now: UnixMillis,
) -> Result<(AttemptId, Fence)> {
    let (resolved, reservation): (bool, Reservation) = tx
        .prepare_cached(
            "SELECT image_digest IS NOT NULL AND image_platform IS NOT NULL, cpu_millis,
                    memory_bytes, disk_bytes, repo_id
             FROM jobs WHERE id = ?1 AND tenant_id = ?2",
        )?
        .query_row(params![job.as_bytes(), tenant.as_bytes()], |r| {
            Ok((
                r.get(0)?,
                Reservation {
                    cpu_millis: r.get(1)?,
                    memory_bytes: r.get(2)?,
                    disk_bytes: r.get(3)?,
                    repo: r.get(4)?,
                },
            ))
        })
        .optional()?
        .ok_or(Error::NotFound)?;
    if !resolved {
        return Err(Error::Unresolved);
    }
    lease_reserved(tx, tenant, job, worker, &reservation, lease_until, now)
}

#[derive(Clone, Copy, Debug)]
pub struct Reservation {
    pub cpu_millis: i64,
    pub memory_bytes: i64,
    pub disk_bytes: i64,
    pub repo: Option<[u8; 16]>,
}

pub fn lease_reserved(
    tx: &Transaction<'_>,
    tenant: TenantId,
    job: JobId,
    worker: WorkerId,
    reservation: &Reservation,
    lease_until: UnixMillis,
    now: UnixMillis,
) -> Result<(AttemptId, Fence)> {
    let row = read_job(tx, tenant, job)?;
    let fence = row.fence.next();
    transition_from(
        tx,
        tenant,
        job,
        &row,
        Actor::Controller,
        Event::Leased(fence),
        now,
    )?;
    let attempt = AttemptId::new();
    tx.prepare_cached(
        "INSERT INTO attempts(id, tenant_id, job_id, fence, worker_id, lease_until_ms,
                              cpu_millis, memory_bytes, disk_bytes, offered_ms, repo_id)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
    )?
    .execute(params![
        attempt.as_bytes(),
        tenant.as_bytes(),
        job.as_bytes(),
        fence.0 as i64,
        worker.as_bytes(),
        lease_until.0,
        reservation.cpu_millis,
        reservation.memory_bytes,
        reservation.disk_bytes,
        now.0,
        reservation.repo.as_ref().map(|r| r.as_slice()),
    ])?;
    Ok((attempt, fence))
}

pub fn run_state(conn: &Connection, tenant: TenantId, run: RunId) -> Result<RunState> {
    let mut stmt =
        conn.prepare_cached("SELECT state_code FROM jobs WHERE run_id = ?1 AND tenant_id = ?2")?;
    let mut rows = stmt.query(params![run.as_bytes(), tenant.as_bytes()])?;
    let mut fault = None;
    let state = aggregate(std::iter::from_fn(|| match rows.next() {
        Ok(Some(row)) => match row
            .get::<_, i64>(0)
            .map_err(Error::from)
            .and_then(|code| decode_state(code).ok_or(Error::Corrupt("state_code")))
        {
            Ok(state) => Some(state),
            Err(e) => {
                fault = Some(e);
                None
            }
        },
        Ok(None) => None,
        Err(e) => {
            fault = Some(Error::from(e));
            None
        }
    }));
    match fault {
        Some(e) => Err(e),
        None => Ok(state),
    }
}
