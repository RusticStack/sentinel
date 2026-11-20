//! Named external resources a job needs to itself: a database, a staging host, a device.
//!
//! A hold is a lease over one `(tenant, name)` pair whose owner is an attempt, and whose deadline is
//! that attempt's own lease. Nothing stores a second deadline here, so a hold cannot outlive the lease
//! that justifies it: an attempt whose lease lapsed makes its holds reclaimable by the same statement
//! that takes them, with no expiry pass of its own. The interlock is the primary key — one row per
//! name — so two jobs never hold one name at once.
//!
//! This is not the concurrency group of [`crate::dispatch`]. A group is a `(tenant, repository, key)`
//! lock inside Sentinel that orders one repository's runs and lets a younger run supersede an older
//! one. A resource is a thing outside Sentinel, held by one job of any repository of the tenant, whose
//! holder keeps it until its attempt ends rather than until a newer run arrives.
//!
//! The fence in a row is the owner's: the attempt that took it, at the fence the lease advanced. Once
//! that attempt's lease lapsed and another attempt took the name, every write the dead owner can still
//! make — a renewal, a report, a finish — meets the attempt row it no longer owns, and the row here
//! names the attempt that does.

use rusqlite::{Connection, OptionalExtension, Transaction, params};
use sentinel_core::{Actor, AttemptId, Event, Fence, JobId, RunId, TenantId, UnixMillis};

use crate::{Error, Result, codec::READY, dispatch, jobs};

/// How many waiting jobs one sweep of the bounds visits, matching the other sweeps.
const SWEEP_BATCH: usize = 256;

/// A resource one job holds: the lease that runs it, and the fence it was taken at.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hold {
    pub job: JobId,
    pub run: RunId,
    pub attempt: AttemptId,
    pub fence: Fence,
    pub since: UnixMillis,
}

/// Takes the resource of `name` for `attempt`, replacing a holder whose lease has ended.
const ACQUIRE_SQL: &str = "INSERT INTO resource_locks(tenant_id, name, job_id, run_id, attempt_id,
                                                       fence, acquired_ms)
     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
     ON CONFLICT(tenant_id, name) DO UPDATE SET
         job_id = excluded.job_id, run_id = excluded.run_id,
         attempt_id = excluded.attempt_id, fence = excluded.fence,
         acquired_ms = excluded.acquired_ms
     WHERE NOT EXISTS (SELECT 1 FROM attempts a WHERE a.id = resource_locks.attempt_id
                       AND a.released_ms IS NULL AND a.lease_until_ms >= ?7)";

/// The resource a waiting job is blocked on right now, when a live attempt of another job holds one
/// of the names it declares. The first name in declaration order is the one it reports.
pub const WAITING_FOR_SQL: &str = "SELECT l.name FROM job_locks l
     JOIN resource_locks r ON r.tenant_id = l.tenant_id AND r.name = l.name
     JOIN attempts a ON a.id = r.attempt_id
     WHERE l.tenant_id = ?1 AND l.job_id = ?2 AND r.job_id <> l.job_id
       AND a.released_ms IS NULL AND a.lease_until_ms >= ?3
     ORDER BY l.name LIMIT 1";

/// Takes every resource the job declares for one attempt. A name a live attempt already holds ends the
/// acquisition with [`Error::Locked`] and gives back the names this attempt had already taken, so a
/// refused lease leaves the store exactly as it found it.
///
/// The placement statement screens a job whose resource is held before it is ever read here, so a
/// refusal reaching a placement pass is a defect rather than a busy resource: it fails the pass instead
/// of running the job without the resource it declared.
pub fn acquire(
    tx: &Transaction<'_>,
    tenant: TenantId,
    job: JobId,
    attempt: AttemptId,
    fence: Fence,
    now: UnixMillis,
) -> Result<()> {
    let (names, run): (Vec<String>, RunId) = {
        let mut stmt = tx.prepare_cached(
            "SELECT l.name, j.run_id FROM job_locks l
             JOIN jobs j ON j.id = l.job_id AND j.tenant_id = l.tenant_id
             WHERE l.tenant_id = ?1 AND l.job_id = ?2 ORDER BY l.name",
        )?;
        let mut rows = stmt.query(params![tenant.as_bytes(), job.as_bytes()])?;
        let mut names = Vec::with_capacity(4);
        let mut run = None;
        while let Some(row) = rows.next()? {
            names.push(row.get::<_, String>(0)?);
            if run.is_none() {
                let bytes: [u8; 16] = row.get(1)?;
                run = Some(RunId::from_bytes(bytes).map_err(|_| Error::Corrupt("run_id"))?);
            }
        }
        match run {
            Some(run) => (names, run),
            None => return Ok(()),
        }
    };
    if names.is_empty() {
        return Ok(());
    }
    let mut stmt = tx.prepare_cached(ACQUIRE_SQL)?;
    for name in &names {
        let taken = stmt.execute(params![
            tenant.as_bytes(),
            name,
            job.as_bytes(),
            run.as_bytes(),
            attempt.as_bytes(),
            fence.0 as i64,
            now.0
        ])?;
        if taken == 0 {
            // The names this attempt did take go back with it, so the pass continues from clean state.
            tx.prepare_cached(
                "DELETE FROM resource_locks WHERE tenant_id = ?1 AND attempt_id = ?2",
            )?
            .execute(params![tenant.as_bytes(), attempt.as_bytes()])?;
            return Err(Error::Locked);
        }
    }
    Ok(())
}

/// Who holds `name` under `tenant` right now, if anyone.
pub fn hold(
    conn: &Connection,
    tenant: TenantId,
    name: &str,
    now: UnixMillis,
) -> Result<Option<Hold>> {
    let row = conn
        .prepare_cached(
            "SELECT r.job_id, r.run_id, r.attempt_id, r.fence, r.acquired_ms FROM resource_locks r
             WHERE r.tenant_id = ?1 AND r.name = ?2
               AND EXISTS (SELECT 1 FROM attempts a WHERE a.id = r.attempt_id
                           AND a.released_ms IS NULL AND a.lease_until_ms >= ?3)",
        )?
        .query_row(params![tenant.as_bytes(), name, now.0], |r| {
            Ok((
                r.get::<_, [u8; 16]>(0)?,
                r.get::<_, [u8; 16]>(1)?,
                r.get::<_, [u8; 16]>(2)?,
                r.get::<_, i64>(3)?,
                r.get::<_, i64>(4)?,
            ))
        })
        .optional()?;
    row.map(|(job, run, attempt, fence, since)| {
        Ok(Hold {
            job: JobId::from_bytes(job).map_err(|_| Error::Corrupt("job_id"))?,
            run: RunId::from_bytes(run).map_err(|_| Error::Corrupt("run_id"))?,
            attempt: AttemptId::from_bytes(attempt).map_err(|_| Error::Corrupt("attempt_id"))?,
            fence: Fence(u64::try_from(fence).map_err(|_| Error::Corrupt("fence"))?),
            since: UnixMillis(since),
        })
    })
    .transpose()
}

/// The resource a waiting job is blocked on, when a live attempt of another job holds one it declares.
pub fn waiting_for(
    conn: &Connection,
    tenant: TenantId,
    job: JobId,
    now: UnixMillis,
) -> Result<Option<String>> {
    Ok(conn
        .prepare_cached(WAITING_FOR_SQL)?
        .query_row(params![tenant.as_bytes(), job.as_bytes(), now.0], |r| {
            r.get(0)
        })
        .optional()?)
}

/// Fails every job that has waited out the bound it declared for a resource somebody else still holds,
/// naming that resource on the job. The bound is measured from the moment the job became ready, as the
/// queue timeout is, so a job cannot wait longer than its declaration however many dispatch passes run.
pub fn sweep_waits(tx: &Transaction<'_>, now: UnixMillis) -> Result<usize> {
    let due: Vec<([u8; 16], [u8; 16], String)> = {
        let mut stmt = tx.prepare_cached(
            "SELECT l.tenant_id, l.job_id, l.name FROM job_locks l
             JOIN jobs j ON j.id = l.job_id AND j.tenant_id = l.tenant_id
             JOIN resource_locks r ON r.tenant_id = l.tenant_id AND r.name = l.name
             JOIN attempts a ON a.id = r.attempt_id
             WHERE j.state_code = ?1 AND j.cancel_requested = 0 AND j.queued_ms IS NOT NULL
               AND j.queued_ms <= ?2 - l.wait_ms AND r.job_id <> l.job_id
               AND a.released_ms IS NULL AND a.lease_until_ms >= ?2
             ORDER BY j.queued_ms LIMIT ?3",
        )?;
        stmt.query_map(params![READY, now.0, SWEEP_BATCH as i64], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?))
        })?
        .collect::<std::result::Result<_, _>>()?
    };
    let mut failed = 0;
    for (tenant, job, name) in due {
        let tenant = TenantId::from_bytes(tenant).map_err(|_| Error::Corrupt("tenant_id"))?;
        let job = JobId::from_bytes(job).map_err(|_| Error::Corrupt("job_id"))?;
        jobs::transition(tx, tenant, job, Actor::Controller, Event::LockTimedOut, now)?;
        tx.prepare_cached("UPDATE jobs SET lock_wait = ?1 WHERE id = ?2 AND tenant_id = ?3")?
            .execute(params![name, job.as_bytes(), tenant.as_bytes()])?;
        dispatch::release_after(tx, tenant, job, now)?;
        failed += 1;
    }
    Ok(failed)
}
