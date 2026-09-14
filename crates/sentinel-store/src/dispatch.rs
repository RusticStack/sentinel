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

use rusqlite::{Connection, OptionalExtension, Transaction, params};
use sentinel_core::{
    Actor, AttemptId, DependencyPolicy, Event, Fence, JobId, JobState, PoolId, RunId, TenantId,
    UnixMillis, WorkerId, dependency_decision,
};
use sentinel_protocol::limits::MAX_LIST_ITEMS;

use crate::{
    Error, Result,
    codec::{READY, decode_state},
    jobs,
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
/// Offers the ack-timeout sweep lapses per pass.
const SWEEP_LIMIT: usize = 256;

/// Resources as the scheduler counts them: CPU in thousandths of a core and
/// bytes of memory. A zero capacity is a worker that takes no work.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Capacity {
    pub cpu_millis: i64,
    pub memory_bytes: i64,
}

/// Record what a worker has, as it reported at its hello. Replaces the
/// previous report: the measurement is the worker's, made each session.
pub fn report_capacity(tx: &Transaction<'_>, worker: WorkerId, capacity: Capacity) -> Result<()> {
    if capacity.cpu_millis < 0 || capacity.memory_bytes < 0 {
        return Err(Error::InvalidInput("capacity"));
    }
    let changed = tx
        .prepare_cached(
            "UPDATE workers SET cpu_millis = ?2, memory_bytes = ?3
             WHERE id = ?1 AND revoked_ms IS NULL",
        )?
        .execute(params![
            worker.as_bytes(),
            capacity.cpu_millis,
            capacity.memory_bytes
        ])?;
    if changed == 0 {
        return Err(Error::NotFound);
    }
    Ok(())
}

/// What the worker has left: its reported capacity less every attempt it
/// still holds. One statement over the held-attempts partial index.
pub fn free_capacity(conn: &Connection, worker: WorkerId) -> Result<Capacity> {
    conn.prepare_cached(
        "SELECT w.cpu_millis - COALESCE(h.cpu, 0), w.memory_bytes - COALESCE(h.mem, 0)
         FROM workers w LEFT JOIN (
            SELECT worker_id, SUM(cpu_millis) AS cpu, SUM(memory_bytes) AS mem
            FROM attempts WHERE worker_id = ?1 AND released_ms IS NULL) h ON h.worker_id = w.id
         WHERE w.id = ?1 AND w.revoked_ms IS NULL",
    )?
    .query_row([worker.as_bytes()], |r| {
        Ok(Capacity {
            cpu_millis: r.get(0)?,
            memory_bytes: r.get(1)?,
        })
    })
    .optional()?
    .ok_or(Error::NotFound)
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

/// Place one job on `worker`: the oldest ready job of the best priority that
/// this pool may serve and that fits the worker's free capacity, leased with
/// its reservation in the calling transaction. `None` means nothing fits
/// right now. A larger job at the head of the queue is passed over for a
/// smaller one behind it; keeping it from starving is Q02's aging.
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
    let free = free_capacity(tx, worker)?;
    if free.cpu_millis <= 0 || free.memory_bytes <= 0 {
        return Ok(None);
    }
    let picked = tx
        .prepare_cached(
            "SELECT j.tenant_id, j.id, j.run_id, j.cpu_millis, j.memory_bytes,
                    j.image_digest, j.image_platform, j.spec_index
             FROM jobs j
             JOIN tenants t ON t.id = j.tenant_id AND t.active = 1
             JOIN pools p ON p.id = ?1 AND p.active = 1
             LEFT JOIN pool_grants g ON g.pool_id = p.id AND g.tenant_id = t.id
             WHERE j.state_code = ?2 AND j.cancel_requested = 0
               AND j.image_digest IS NOT NULL AND j.image_platform IS NOT NULL
               AND (p.owner_tenant_id = t.id OR g.tenant_id IS NOT NULL)
               AND j.cpu_millis <= ?3 AND j.memory_bytes <= ?4
             ORDER BY j.priority, j.created_seq LIMIT 1",
        )?
        .query_row(
            params![pool.as_bytes(), READY, free.cpu_millis, free.memory_bytes],
            |r| {
                Ok((
                    r.get::<_, [u8; 16]>(0)?,
                    r.get::<_, [u8; 16]>(1)?,
                    r.get::<_, [u8; 16]>(2)?,
                    r.get::<_, i64>(3)?,
                    r.get::<_, i64>(4)?,
                    r.get::<_, String>(5)?,
                    r.get::<_, String>(6)?,
                    r.get::<_, i64>(7)?,
                ))
            },
        )
        .optional()?;
    let Some((tenant, job, run, cpu_millis, memory_bytes, digest, platform, index)) = picked else {
        return Ok(None);
    };
    let tenant = TenantId::from_bytes(tenant).map_err(|_| Error::Corrupt("tenant_id"))?;
    let job = JobId::from_bytes(job).map_err(|_| Error::Corrupt("job_id"))?;
    let run = RunId::from_bytes(run).map_err(|_| Error::Corrupt("run_id"))?;
    let lease_until = UnixMillis(now.0.saturating_add(lease_ms));
    let (attempt, fence) = jobs::lease(tx, tenant, job, worker, lease_until, now)?;
    Ok(Some(Offer {
        attempt,
        tenant,
        run,
        job,
        fence,
        lease_until,
        cpu_millis,
        memory_bytes,
        image: ResolvedImage { digest, platform },
        job_index: u32::try_from(index).map_err(|_| Error::Corrupt("spec_index"))?,
    }))
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

/// End an attempt: apply `event` as `actor` through the state machine, release
/// the reservation, and if the job reached terminal, decide its dependents.
/// A worker's report is fenced by the machine; a stale one changes nothing.
pub fn finish(
    tx: &Transaction<'_>,
    attempt: AttemptId,
    actor: Actor,
    event: Event,
    now: UnixMillis,
) -> Result<JobState> {
    let row: Option<([u8; 16], [u8; 16], [u8; 16])> = tx
        .prepare_cached(
            "SELECT a.tenant_id, a.job_id, j.run_id FROM attempts a JOIN jobs j ON j.id = a.job_id
             WHERE a.id = ?1 AND a.released_ms IS NULL",
        )?
        .query_row([attempt.as_bytes()], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?))
        })
        .optional()?;
    let Some((tenant, job, run)) = row else {
        return Err(Error::NotFound);
    };
    let tenant = TenantId::from_bytes(tenant).map_err(|_| Error::Corrupt("tenant_id"))?;
    let job = JobId::from_bytes(job).map_err(|_| Error::Corrupt("job_id"))?;
    let run = RunId::from_bytes(run).map_err(|_| Error::Corrupt("run_id"))?;
    let next = jobs::transition(tx, tenant, job, actor, event, now)?;
    if !next.is_terminal() {
        // Preparing/Running/Finalizing keep the reservation.
        return Ok(next);
    }
    tx.prepare_cached("UPDATE attempts SET released_ms = ?2 WHERE id = ?1")?
        .execute(params![attempt.as_bytes(), now.0])?;
    release_dependents(tx, tenant, run, now)?;
    Ok(next)
}

/// A worker's report over the link: the attempt must be held by that worker
/// under that fence, then [`finish`] applies the event as the worker.
pub fn report(
    tx: &Transaction<'_>,
    worker: WorkerId,
    attempt: AttemptId,
    fence: Fence,
    event: Event,
    now: UnixMillis,
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
    finish(tx, attempt, Actor::Worker(fence), event, now)
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
    /// Workers that could fit it exist, but none is connected.
    WorkerOffline,
    /// A connected worker could fit it once its current work releases.
    Capacity,
}

/// Explain a queued or blocked job. `connected` is the controller's live
/// session set — the one fact the database does not hold.
pub fn wait_reason(
    conn: &Connection,
    tenant: TenantId,
    job: JobId,
    connected: &[WorkerId],
) -> Result<WaitReason> {
    let row: Option<(i64, i64, i64, i64, bool)> = conn
        .prepare_cached(
            "SELECT state_code, cpu_millis, memory_bytes, cancel_requested,
                    image_digest IS NOT NULL AND image_platform IS NOT NULL
             FROM jobs WHERE id = ?1 AND tenant_id = ?2",
        )?
        .query_row(params![job.as_bytes(), tenant.as_bytes()], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
        })
        .optional()?;
    let Some((code, cpu, memory, cancel, resolved)) = row else {
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
    let mut stmt = conn.prepare_cached(
        "SELECT w.id, w.cpu_millis, w.memory_bytes
         FROM workers w JOIN pools p ON p.id = w.pool_id AND p.active = 1
         JOIN tenants t ON t.id = ?1 AND t.active = 1
         LEFT JOIN pool_grants g ON g.pool_id = p.id AND g.tenant_id = t.id
         WHERE w.revoked_ms IS NULL AND (p.owner_tenant_id = t.id OR g.tenant_id IS NOT NULL)",
    )?;
    let rows = stmt.query_map([tenant.as_bytes()], |r| {
        Ok((
            r.get::<_, [u8; 16]>(0)?,
            r.get::<_, i64>(1)?,
            r.get::<_, i64>(2)?,
        ))
    })?;
    let (mut best_cpu, mut best_memory) = (0i64, 0i64);
    let mut fits_offline = false;
    for row in rows {
        let (id, wcpu, wmem) = row?;
        best_cpu = best_cpu.max(wcpu);
        best_memory = best_memory.max(wmem);
        if wcpu >= cpu && wmem >= memory {
            let id = WorkerId::from_bytes(id).map_err(|_| Error::Corrupt("worker id"))?;
            if connected.contains(&id) {
                return Ok(WaitReason::Capacity);
            }
            fits_offline = true;
        }
    }
    Ok(if fits_offline {
        WaitReason::WorkerOffline
    } else {
        WaitReason::NoMatchingWorker {
            cpu_short: (cpu - best_cpu).max(0),
            memory_short: (memory - best_memory).max(0),
        }
    })
}
