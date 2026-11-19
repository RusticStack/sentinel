//! Runner-mode provisioning (AR02): leasing a worker's capacity for one ephemeral runner of a
//! label's class, recording the just-in-time configuration GitHub issues for it, and ending the
//! lease together with the registration it created.
//!
//! A lease is placed for one *unmet unit of demand of a label set*, never for one GitHub job:
//! GitHub hands a queued job to whichever idle runner matches its labels, so binding a runner to
//! the job that caused it would be a claim nobody can keep. The `in_progress` delivery that names
//! the runner we registered is what binds a job to its lease (`bind`), and `completed` ends it.

use rusqlite::{Connection, OptionalExtension, Transaction, params};
use sentinel_core::{RepoId, RunnerClass, RunnerLeaseId, TenantId, UnixMillis, WorkerId};

use crate::{Error, Result, dispatch};

/// How long an offer waits for the worker's answer before the capacity returns to the queue.
pub const OFFER_ACK_MS: i64 = dispatch::OFFER_ACK_MS;

/// How long a lease survives without being renewed. The controller renews every lease of a
/// live session on each provisioning pass; a worker that died has its leases released with the
/// session, so this bounds only what a controller that stopped leaves behind.
pub const LEASE_MS: i64 = 60_000;

/// The largest encoded JIT configuration a lease carries. GitHub's is about 3 KiB; the bound
/// is what stops a hostile or broken answer from becoming a frame nobody could write.
pub const MAX_JIT_BYTES: usize = 65_536;

/// The most unmet (repository, class) pairs one placement looks at.
pub const MAX_CANDIDATES: usize = 256;

/// The lease ends for one of these reasons; the column is bounded and a reader maps it.
pub const IDLE: &str = "idle";
pub const JOB_COMPLETED: &str = "job_completed";
pub const LAPSED: &str = "lapsed";
pub const DECLINED: &str = "declined";
pub const SESSION_LOST: &str = "session_lost";
pub const REVOKED: &str = "revoked";
pub const CANCELLED: &str = "cancelled";
pub const REGISTER_FAILED: &str = "register_failed";

/// What one class reserves of a worker: `n` CPUs of the class, and the memory a runner job of it
/// is expected to need (2 GiB per vCPU, stated in [configuration](../../../docs/configuration.md)
/// and used only for capacity accounting — the sandbox itself gets what the class names).
pub const fn class_capacity(vcpus: u16) -> (i64, i64) {
    let cpu = vcpus as i64 * 1_000;
    (cpu, cpu * 2 * 1024 * 1024)
}

/// A lease's lifecycle, which only moves forward.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LeaseState {
    /// Written and offered; the worker has not answered.
    Offered,
    /// The worker holds it, and the JIT configuration is being made or has been delivered.
    Accepted,
    /// Over: nothing holds capacity and the registration is being removed.
    Released,
}

impl LeaseState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Offered => "offered",
            Self::Accepted => "accepted",
            Self::Released => "released",
        }
    }

    fn from_code(code: i64) -> Result<Self> {
        match code {
            0 => Ok(Self::Offered),
            1 => Ok(Self::Accepted),
            2 => Ok(Self::Released),
            _ => Err(Error::Corrupt("runner lease state")),
        }
    }
}

/// One lease as a reader sees it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Lease {
    pub id: RunnerLeaseId,
    pub tenant: TenantId,
    pub repo: RepoId,
    pub class: String,
    pub worker: WorkerId,
    pub fence: i64,
    pub state: LeaseState,
    pub runner_name: String,
    pub runner_id: Option<u64>,
    pub job: Option<u64>,
    pub offered: UnixMillis,
    pub accepted: Option<UnixMillis>,
    pub released: Option<UnixMillis>,
    pub reason: Option<String>,
    pub deleted: Option<UnixMillis>,
}

/// The worker facts placement needs, which a hello or profile may have set.
struct Facts {
    pool: [u8; 16],
    labels: Vec<u8>,
}

fn facts(conn: &Connection, worker: WorkerId) -> Result<Option<Facts>> {
    let row: Option<([u8; 16], Vec<u8>, bool)> = conn
        .prepare_cached(
            "SELECT pool_id, labels, drain_ms IS NOT NULL FROM workers
             WHERE id = ?1 AND revoked_ms IS NULL",
        )?
        .query_row([worker.as_bytes()], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?))
        })
        .optional()?;
    let Some((pool, labels, draining)) = row else {
        return Ok(None);
    };
    Ok((!draining).then_some(Facts { pool, labels }))
}

/// One unmet unit of demand: a (repository, class) pair with queued jobs left over.
struct Candidate {
    tenant: TenantId,
    repo: RepoId,
    class: RunnerClass,
    label: String,
}

/// Fresh demand for the pool, ranked the way the fair queue ranks jobs: the tenant holding the
/// fewest runners first, then the oldest queued job. A pair whose queued jobs are already covered
/// by live leases is not demand and is dropped by `HAVING`.
///
/// A job of a fork pull request is demand only for the hostile-fork pool, and that pool takes
/// nothing else: `q.fork_pr = 0 OR (… ` keeps trusted demand off it, and the first clause keeps a
/// fork job waiting until a pool is marked as one and its tenant opts in. A fork job nobody can
/// serve stays queued at GitHub rather than running unconfined, which is the guarantee AR09 makes.
const DEMAND_SQL: &str = "SELECT q.tenant_id, q.repo_id, q.class
     FROM runner_jobs q
     JOIN tenants t ON t.id = q.tenant_id AND t.active = 1 AND t.runner_mode = 1
     JOIN pools p ON p.id = :pool AND p.active = 1
       AND (p.owner_tenant_id = q.tenant_id
            OR EXISTS(SELECT 1 FROM pool_grants g
                      WHERE g.pool_id = p.id AND g.tenant_id = q.tenant_id))
     WHERE q.state_code = 0
       AND CASE WHEN q.fork_pr = 1
                THEN p.fork_prs = 1 AND t.runner_fork_prs = 1
                ELSE p.fork_prs = 0
           END
     GROUP BY q.tenant_id, q.repo_id, q.class
     HAVING COUNT(*) > (SELECT COUNT(*) FROM runner_leases l
                        WHERE l.tenant_id = q.tenant_id AND l.repo_id = q.repo_id
                          AND l.class = q.class AND l.released_ms IS NULL)
     ORDER BY (SELECT COUNT(*) FROM runner_leases l
               WHERE l.tenant_id = q.tenant_id AND l.released_ms IS NULL),
              MIN(q.queued_ms), q.tenant_id, q.repo_id, q.class
     LIMIT :limit";

/// Place one lease on `worker` for the freshest demand of a class it serves and has room for.
/// `None` when the worker has no room, serves no class with unmet demand, or the demand that is
/// left is already covered by runners another worker is starting.
pub fn place(
    tx: &Transaction<'_>,
    worker: WorkerId,
    lease_ms: i64,
    now: UnixMillis,
) -> Result<Option<Lease>> {
    let Some(facts) = facts(tx, worker)? else {
        return Ok(None);
    };
    let free = dispatch::free_capacity(tx, worker)?;
    if free.cpu_millis <= 0 || free.memory_bytes <= 0 {
        return Ok(None);
    }
    let candidates: Vec<Candidate> = {
        let mut stmt = tx.prepare_cached(DEMAND_SQL)?;
        let limit = MAX_CANDIDATES as i64;
        let rows = stmt.query_map(params![facts.pool, limit], |r| {
            Ok((
                r.get::<_, [u8; 16]>(0)?,
                r.get::<_, [u8; 16]>(1)?,
                r.get::<_, String>(2)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (tenant, repo, label) = row?;
            // A class this build does not know is a row a newer binary wrote: not ours to place.
            let Some(class) = RunnerClass::parse(&label) else {
                continue;
            };
            let (cpu, memory) = class_capacity(class.vcpus);
            if cpu > free.cpu_millis || memory > free.memory_bytes {
                continue;
            }
            out.push(Candidate {
                tenant: TenantId::from_bytes(tenant).map_err(|_| Error::Corrupt("tenant_id"))?,
                repo: RepoId::from_bytes(repo).map_err(|_| Error::Corrupt("repo_id"))?,
                class,
                label,
            });
        }
        out
    };
    for candidate in candidates {
        // The worker serves a class only when it names it among its profile labels: what a
        // machine can run is the machine's statement, never the controller's guess.
        let wanted = dispatch::encode_labels(std::slice::from_ref(&candidate.label))?;
        if !dispatch::labels_subset(&wanted, &facts.labels) {
            continue;
        }
        let (cpu, memory) = class_capacity(candidate.class.vcpus);
        let id = RunnerLeaseId::new();
        let fence: i64 = tx
            .prepare_cached(
                "SELECT COALESCE(MAX(fence), 0) + 1 FROM runner_leases WHERE worker_id = ?1",
            )?
            .query_row([worker.as_bytes()], |r| r.get(0))?;
        let runner_name = runner_name(candidate.repo, id, candidate.class.vcpus);
        let inserted = tx.execute(
            "INSERT INTO runner_leases(id, tenant_id, repo_id, class, pool_id, worker_id, fence,
                state_code, cpu_millis, memory_bytes, runner_name, offered_ms, lease_until_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 0, ?8, ?9, ?10, ?11, ?12)",
            params![
                id.as_bytes(),
                candidate.tenant.as_bytes(),
                candidate.repo.as_bytes(),
                candidate.label,
                facts.pool,
                worker.as_bytes(),
                fence,
                cpu,
                memory,
                runner_name,
                now.0,
                now.0 + lease_ms
            ],
        )?;
        if inserted != 1 {
            return Err(Error::Conflict);
        }
        return Ok(Some(Lease {
            id,
            tenant: candidate.tenant,
            repo: candidate.repo,
            class: candidate.label,
            worker,
            fence,
            state: LeaseState::Offered,
            runner_name,
            runner_id: None,
            job: None,
            offered: now,
            accepted: None,
            released: None,
            reason: None,
            deleted: None,
        }));
    }
    Ok(None)
}

/// The name GitHub registers the runner under: bounded, printable, unique while the lease is live
/// and shown in every `workflow_job` delivery for that runner, which is how a job finds its lease.
fn runner_name(repo: RepoId, id: RunnerLeaseId, vcpus: u16) -> String {
    let mut hex = [0u8; 32];
    for (i, byte) in id.as_bytes().iter().enumerate() {
        const DIGITS: &[u8; 16] = b"0123456789abcdef";
        hex[i * 2] = DIGITS[usize::from(byte >> 4)];
        hex[i * 2 + 1] = DIGITS[usize::from(byte & 0xf)];
    }
    let repo = repo.as_bytes();
    let mut name = String::with_capacity(48);
    name.push_str("sentinel-");
    for byte in &repo[..4] {
        name.push(char::from(b"0123456789abcdef"[usize::from(byte & 0xf)]));
    }
    name.push('-');
    name.push_str(std::str::from_utf8(&hex[..12]).unwrap_or("runner"));
    name.push('-');
    name.push_str(&vcpus.to_string());
    name
}

const LEASE_COLUMNS: &str = "id, tenant_id, repo_id, class, worker_id, fence, state_code,
     runner_name, runner_id, job_id, offered_ms, accepted_ms, released_ms, reason, deleted_ms";

type Row = (
    [u8; 16],
    [u8; 16],
    [u8; 16],
    String,
    [u8; 16],
    i64,
    i64,
    String,
    Option<i64>,
    Option<i64>,
    i64,
    Option<i64>,
    Option<i64>,
    Option<String>,
    Option<i64>,
);

fn decode(row: Row) -> Result<Lease> {
    let positive = |value: i64, what: &'static str| -> Result<u64> {
        u64::try_from(value)
            .ok()
            .filter(|v| *v > 0)
            .ok_or(Error::Corrupt(what))
    };
    Ok(Lease {
        id: RunnerLeaseId::from_bytes(row.0).map_err(|_| Error::Corrupt("runner lease id"))?,
        tenant: TenantId::from_bytes(row.1).map_err(|_| Error::Corrupt("tenant_id"))?,
        repo: RepoId::from_bytes(row.2).map_err(|_| Error::Corrupt("repo_id"))?,
        class: row.3,
        worker: WorkerId::from_bytes(row.4).map_err(|_| Error::Corrupt("worker_id"))?,
        fence: row.5,
        state: LeaseState::from_code(row.6)?,
        runner_name: row.7,
        runner_id: row.8.map(|v| positive(v, "runner id")).transpose()?,
        job: row.9.map(|v| positive(v, "runner job")).transpose()?,
        offered: UnixMillis(row.10),
        accepted: row.11.map(UnixMillis),
        released: row.12.map(UnixMillis),
        reason: row.13,
        deleted: row.14.map(UnixMillis),
    })
}

pub fn get(conn: &Connection, id: RunnerLeaseId) -> Result<Option<Lease>> {
    let sql = format!("SELECT {LEASE_COLUMNS} FROM runner_leases WHERE id = ?1");
    let row: Option<Row> = conn
        .prepare_cached(&sql)?
        .query_row([id.as_bytes()], row_of)
        .optional()?;
    row.map(decode).transpose()
}

fn row_of(r: &rusqlite::Row<'_>) -> rusqlite::Result<Row> {
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
}

/// The CPU a worker's live leases hold, which placement subtracts beside its attempts.
pub fn held(conn: &Connection, worker: WorkerId) -> Result<(i64, i64)> {
    Ok(conn
        .prepare_cached(
            "SELECT COALESCE(SUM(cpu_millis), 0), COALESCE(SUM(memory_bytes), 0)
             FROM runner_leases WHERE worker_id = ?1 AND released_ms IS NULL",
        )?
        .query_row([worker.as_bytes()], |r| Ok((r.get(0)?, r.get(1)?)))?)
}

/// The worker's answer. An offer lapsed between the answer and this write is not an error: the
/// worker holds a lease nothing counts any more, and the stop that follows removes it.
pub fn accept(
    tx: &Transaction<'_>,
    worker: WorkerId,
    lease: RunnerLeaseId,
    now: UnixMillis,
) -> Result<bool> {
    let changed = tx.execute(
        "UPDATE runner_leases SET state_code = 1, accepted_ms = ?3
         WHERE id = ?1 AND worker_id = ?2 AND state_code = 0 AND released_ms IS NULL",
        params![lease.as_bytes(), worker.as_bytes(), now.0],
    )?;
    Ok(changed == 1)
}

/// The worker declined the offer, which returns its capacity to the queue at once.
pub fn decline(
    tx: &Transaction<'_>,
    worker: WorkerId,
    lease: RunnerLeaseId,
    now: UnixMillis,
) -> Result<bool> {
    Ok(tx.execute(
        "UPDATE runner_leases SET state_code = 2, released_ms = ?3, reason = ?4
         WHERE id = ?1 AND worker_id = ?2 AND released_ms IS NULL",
        params![lease.as_bytes(), worker.as_bytes(), now.0, DECLINED],
    )? == 1)
}

/// One lease that is ready to have its configuration made: accepted, unread, and not yet issued.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ToProvision {
    pub id: RunnerLeaseId,
    pub tenant: TenantId,
    pub repo: RepoId,
    pub worker: WorkerId,
    pub class: String,
    /// The name the runner is registered under, which GitHub states back in every delivery for it.
    pub runner_name: String,
}

/// The oldest accepted leases without a configuration, bounded by `limit`.
pub fn awaiting_config(conn: &Connection, limit: u32) -> Result<Vec<ToProvision>> {
    let mut stmt = conn.prepare_cached(
        "SELECT id, tenant_id, repo_id, worker_id, class, runner_name FROM runner_leases
         WHERE state_code = 1 AND jit_ms IS NULL AND released_ms IS NULL
         ORDER BY accepted_ms, offered_ms LIMIT ?1",
    )?;
    let rows = stmt.query_map([limit], |r| {
        Ok((
            r.get::<_, [u8; 16]>(0)?,
            r.get::<_, [u8; 16]>(1)?,
            r.get::<_, [u8; 16]>(2)?,
            r.get::<_, [u8; 16]>(3)?,
            r.get::<_, String>(4)?,
            r.get::<_, String>(5)?,
        ))
    })?;
    let mut out = Vec::new();
    for row in rows {
        let (id, tenant, repo, worker, class, runner_name) = row?;
        out.push(ToProvision {
            id: RunnerLeaseId::from_bytes(id).map_err(|_| Error::Corrupt("runner lease id"))?,
            tenant: TenantId::from_bytes(tenant).map_err(|_| Error::Corrupt("tenant_id"))?,
            repo: RepoId::from_bytes(repo).map_err(|_| Error::Corrupt("repo_id"))?,
            worker: WorkerId::from_bytes(worker).map_err(|_| Error::Corrupt("worker_id"))?,
            class,
            runner_name,
        });
    }
    Ok(out)
}

/// Record the configuration GitHub issued, sealed. Written once: the trigger refuses a second one,
/// and the store is the only place that can clear it (when the worker reads it).
pub fn set_config(
    tx: &Transaction<'_>,
    lease: RunnerLeaseId,
    worker: WorkerId,
    runner_id: u64,
    sealed: &[u8],
    now: UnixMillis,
) -> Result<bool> {
    if sealed.is_empty() || sealed.len() > MAX_JIT_BYTES || runner_id == 0 {
        return Err(Error::InvalidInput("runner configuration"));
    }
    let runner_id = i64::try_from(runner_id).map_err(|_| Error::InvalidInput("runner id"))?;
    Ok(tx.execute(
        "UPDATE runner_leases SET sealed_jit = ?3, runner_id = ?4, jit_ms = ?5
         WHERE id = ?1 AND worker_id = ?2 AND state_code = 1 AND released_ms IS NULL
           AND jit_ms IS NULL",
        params![
            lease.as_bytes(),
            worker.as_bytes(),
            sealed,
            runner_id,
            now.0
        ],
    )? == 1)
}

/// The sealed configuration of a lease whose worker is about to be sent it, so a delivery that
/// loses the connection can be retried from the same bytes.
pub fn sealed_config(
    conn: &Connection,
    lease: RunnerLeaseId,
    worker: WorkerId,
) -> Result<Option<Vec<u8>>> {
    Ok(conn
        .prepare_cached(
            "SELECT sealed_jit FROM runner_leases
             WHERE id = ?1 AND worker_id = ?2 AND taken_ms IS NULL AND released_ms IS NULL
               AND sealed_jit IS NOT NULL",
        )?
        .query_row(params![lease.as_bytes(), worker.as_bytes()], |r| r.get(0))
        .optional()?)
}

/// The configuration is single-use: this clears it in the same statement that stamps the read, so
/// a second reader — another session, a retried frame, a copy of the database — finds nothing.
pub fn take_config(
    tx: &Transaction<'_>,
    lease: RunnerLeaseId,
    worker: WorkerId,
    now: UnixMillis,
) -> Result<Option<Vec<u8>>> {
    let sealed: Option<Vec<u8>> = tx
        .prepare_cached(
            "SELECT sealed_jit FROM runner_leases
             WHERE id = ?1 AND worker_id = ?2 AND taken_ms IS NULL AND released_ms IS NULL
               AND sealed_jit IS NOT NULL",
        )?
        .query_row(params![lease.as_bytes(), worker.as_bytes()], |r| r.get(0))
        .optional()?;
    let Some(sealed) = sealed else {
        return Ok(None);
    };
    let changed = tx.execute(
        "UPDATE runner_leases SET sealed_jit = NULL, taken_ms = ?3
         WHERE id = ?1 AND worker_id = ?2 AND taken_ms IS NULL AND sealed_jit IS NOT NULL",
        params![lease.as_bytes(), worker.as_bytes(), now.0],
    )?;
    if changed != 1 {
        return Ok(None);
    }
    Ok(Some(sealed))
}

/// End a lease. `false` when it was already over, which a sweep must treat as done.
pub fn release(
    tx: &Transaction<'_>,
    lease: RunnerLeaseId,
    reason: &str,
    now: UnixMillis,
) -> Result<bool> {
    if reason.is_empty() || reason.len() > 32 {
        return Err(Error::InvalidInput("runner lease reason"));
    }
    Ok(tx.execute(
        "UPDATE runner_leases SET state_code = 2, released_ms = ?2, reason = ?3
         WHERE id = ?1 AND released_ms IS NULL",
        params![lease.as_bytes(), now.0, reason],
    )? == 1)
}

/// End every live lease of one worker, which is what a lost session means: the machine that held
/// them cannot be handed them again.
pub fn release_worker(
    tx: &Transaction<'_>,
    worker: WorkerId,
    reason: &str,
    now: UnixMillis,
) -> Result<usize> {
    Ok(tx.execute(
        "UPDATE runner_leases SET state_code = 2, released_ms = ?2, reason = ?3
         WHERE worker_id = ?1 AND released_ms IS NULL",
        params![worker.as_bytes(), now.0, reason],
    )?)
}

/// Offers nobody answered, oldest first: their capacity returns to the queue.
pub fn lapsed(tx: &Transaction<'_>, now: UnixMillis) -> Result<Vec<(RunnerLeaseId, WorkerId)>> {
    let mut ids = Vec::new();
    {
        let mut stmt = tx.prepare_cached(
            "SELECT id, worker_id FROM runner_leases
             WHERE state_code = 0 AND released_ms IS NULL AND offered_ms + ?1 <= ?2
             LIMIT ?3",
        )?;
        let rows = stmt.query_map(
            params![OFFER_ACK_MS, now.0, dispatch::MAX_HELD_ATTEMPTS as i64],
            |r| Ok((r.get::<_, [u8; 16]>(0)?, r.get::<_, [u8; 16]>(1)?)),
        )?;
        for row in rows {
            let (id, worker) = row?;
            ids.push((
                RunnerLeaseId::from_bytes(id).map_err(|_| Error::Corrupt("runner lease id"))?,
                WorkerId::from_bytes(worker).map_err(|_| Error::Corrupt("worker_id"))?,
            ));
        }
    }
    for (id, _) in &ids {
        let _ = tx.execute(
            "UPDATE runner_leases SET state_code = 2, released_ms = ?2, reason = ?3
             WHERE id = ?1 AND state_code = 0 AND released_ms IS NULL",
            params![id.as_bytes(), now.0, LAPSED],
        )?;
    }
    Ok(ids)
}

/// Live leases whose lease was not renewed: a controller that stopped owes them nothing, and a
/// runner it cannot account for must not stay registered.
pub fn expired(tx: &Transaction<'_>, now: UnixMillis) -> Result<Vec<(RunnerLeaseId, WorkerId)>> {
    let mut ids = Vec::new();
    {
        let mut stmt = tx.prepare_cached(
            "SELECT id, worker_id FROM runner_leases
             WHERE released_ms IS NULL AND accepted_ms IS NOT NULL AND lease_until_ms <= ?1
             LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![now.0, dispatch::MAX_HELD_ATTEMPTS as i64], |r| {
            Ok((r.get::<_, [u8; 16]>(0)?, r.get::<_, [u8; 16]>(1)?))
        })?;
        for row in rows {
            let (id, worker) = row?;
            ids.push((
                RunnerLeaseId::from_bytes(id).map_err(|_| Error::Corrupt("runner lease id"))?,
                WorkerId::from_bytes(worker).map_err(|_| Error::Corrupt("worker_id"))?,
            ));
        }
    }
    for (id, _) in &ids {
        let _ = release(tx, *id, LAPSED, now)?;
    }
    Ok(ids)
}

/// Renew every lease of one worker, which its live session does on each provisioning pass.
pub fn renew(tx: &Transaction<'_>, worker: WorkerId, until: UnixMillis) -> Result<usize> {
    Ok(tx.execute(
        "UPDATE runner_leases SET lease_until_ms = ?2
         WHERE worker_id = ?1 AND released_ms IS NULL AND lease_until_ms < ?2",
        params![worker.as_bytes(), until.0],
    )?)
}

/// Live leases whose idle bound passed without a job: a runner nobody handed work to is not work.
pub fn idle(
    tx: &Transaction<'_>,
    now: UnixMillis,
    idle_ms: i64,
) -> Result<Vec<(RunnerLeaseId, WorkerId)>> {
    let mut ids = Vec::new();
    {
        let mut stmt = tx.prepare_cached(
            "SELECT id, worker_id FROM runner_leases
             WHERE released_ms IS NULL AND job_id IS NULL AND offered_ms + ?1 <= ?2
             LIMIT ?3",
        )?;
        let rows = stmt.query_map(
            params![idle_ms, now.0, dispatch::MAX_HELD_ATTEMPTS as i64],
            |r| Ok((r.get::<_, [u8; 16]>(0)?, r.get::<_, [u8; 16]>(1)?)),
        )?;
        for row in rows {
            let (id, worker) = row?;
            ids.push((
                RunnerLeaseId::from_bytes(id).map_err(|_| Error::Corrupt("runner lease id"))?,
                WorkerId::from_bytes(worker).map_err(|_| Error::Corrupt("worker_id"))?,
            ));
        }
    }
    for (id, _) in &ids {
        let _ = release(tx, *id, IDLE, now)?;
    }
    Ok(ids)
}

/// Bind a GitHub job to the runner this store registered under that name. Called from the
/// `in_progress` delivery in its own transaction: the job is bound to exactly one lease, and the
/// fact is never rewritten.
pub fn bind(
    tx: &Transaction<'_>,
    tenant: TenantId,
    repo: RepoId,
    runner_name: &str,
    job: u64,
    now: UnixMillis,
) -> Result<Option<RunnerLeaseId>> {
    let job = i64::try_from(job).map_err(|_| Error::InvalidInput("runner job"))?;
    let row: Option<[u8; 16]> = tx
        .prepare_cached(
            "SELECT id FROM runner_leases
             WHERE tenant_id = ?1 AND repo_id = ?2 AND runner_name = ?3 AND job_id IS NULL
               AND released_ms IS NULL",
        )?
        .query_row(
            params![tenant.as_bytes(), repo.as_bytes(), runner_name],
            |r| r.get(0),
        )
        .optional()?;
    let Some(id) = row else {
        return Ok(None);
    };
    let changed = tx.execute(
        "UPDATE runner_leases SET state_code = 1, job_id = ?4
         WHERE tenant_id = ?1 AND repo_id = ?2 AND runner_name = ?3 AND job_id IS NULL
           AND released_ms IS NULL",
        params![tenant.as_bytes(), repo.as_bytes(), runner_name, job],
    )?;
    if changed != 1 {
        return Ok(None);
    }
    // A runner that took a job is no longer idle, whatever it was offered as: stamp the deadline
    // so the idle sweep cannot retire it mid-job.
    tx.execute(
        "UPDATE runner_leases SET lease_until_ms = MAX(lease_until_ms, ?2) WHERE id = ?1",
        params![id, now.0],
    )?;
    Ok(Some(
        RunnerLeaseId::from_bytes(id).map_err(|_| Error::Corrupt("runner lease id"))?,
    ))
}

/// The GitHub job finished (or was cancelled): end the lease that took it. A job no lease took —
/// one GitHub ran elsewhere — changes nothing.
pub fn complete(
    tx: &Transaction<'_>,
    tenant: TenantId,
    repo: RepoId,
    job: u64,
    reason: &str,
    now: UnixMillis,
) -> Result<Option<RunnerLeaseId>> {
    let job = i64::try_from(job).map_err(|_| Error::InvalidInput("runner job"))?;
    let row: Option<[u8; 16]> = tx
        .prepare_cached(
            "SELECT id FROM runner_leases
             WHERE tenant_id = ?1 AND repo_id = ?2 AND job_id = ?3 AND released_ms IS NULL",
        )?
        .query_row(params![tenant.as_bytes(), repo.as_bytes(), job], |r| {
            r.get(0)
        })
        .optional()?;
    let Some(id) = row else {
        return Ok(None);
    };
    let id = RunnerLeaseId::from_bytes(id).map_err(|_| Error::Corrupt("runner lease id"))?;
    release(tx, id, reason, now)?;
    Ok(Some(id))
}

/// A registration that has to be removed at GitHub: the lease id, the tenant and repository it
/// was made for, and the id GitHub gave the runner.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Registered {
    pub lease: RunnerLeaseId,
    pub tenant: TenantId,
    pub repo: RepoId,
    pub runner_id: u64,
}

/// Registrations still standing at GitHub, oldest first: a lease that is over is de-registered
/// before its capacity is reused, and one that never took a job is de-registered at its idle bound.
pub fn to_unregister(conn: &Connection, limit: u32) -> Result<Vec<Registered>> {
    let mut stmt = conn.prepare_cached(
        "SELECT id, tenant_id, repo_id, runner_id FROM runner_leases
         WHERE runner_id IS NOT NULL AND deleted_ms IS NULL
         ORDER BY offered_ms LIMIT ?1",
    )?;
    let rows = stmt.query_map([limit], |r| {
        Ok((
            r.get::<_, [u8; 16]>(0)?,
            r.get::<_, [u8; 16]>(1)?,
            r.get::<_, [u8; 16]>(2)?,
            r.get::<_, i64>(3)?,
        ))
    })?;
    let mut out = Vec::new();
    for row in rows {
        let (lease, tenant, repo, runner) = row?;
        out.push(Registered {
            lease: RunnerLeaseId::from_bytes(lease)
                .map_err(|_| Error::Corrupt("runner lease id"))?,
            tenant: TenantId::from_bytes(tenant).map_err(|_| Error::Corrupt("tenant_id"))?,
            repo: RepoId::from_bytes(repo).map_err(|_| Error::Corrupt("repo_id"))?,
            runner_id: u64::try_from(runner).map_err(|_| Error::Corrupt("runner id"))?,
        });
    }
    Ok(out)
}

/// The runner is no longer registered at GitHub: either we removed it or GitHub already had (an
/// ephemeral runner de-registers itself when its job ends).
pub fn unregistered(tx: &Transaction<'_>, lease: RunnerLeaseId, now: UnixMillis) -> Result<bool> {
    Ok(tx.execute(
        "UPDATE runner_leases SET deleted_ms = ?2 WHERE id = ?1 AND deleted_ms IS NULL",
        params![lease.as_bytes(), now.0],
    )? == 1)
}

/// One repository whose queued jobs a reconciliation pass reads from GitHub.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BoundRepo {
    pub tenant: TenantId,
    pub repo: RepoId,
}

/// The repositories a reconciliation pass covers: live bindings of tenants with runner mode on, in
/// a stable order, starting after `after` so successive passes reach every repository even when there
/// are more than one pass reads.
pub fn reconcile_targets(
    conn: &Connection,
    after: Option<(TenantId, RepoId)>,
    limit: u32,
) -> Result<Vec<BoundRepo>> {
    let (tenant, repo) = match after {
        Some((tenant, repo)) => (*tenant.as_bytes(), *repo.as_bytes()),
        None => ([0u8; 16], [0u8; 16]),
    };
    let mut stmt = conn.prepare_cached(
        "SELECT b.tenant_id, b.repo_id FROM source_bindings b
         JOIN tenants t ON t.id = b.tenant_id AND t.active = 1 AND t.runner_mode = 1
         JOIN installations i ON i.id = b.installation_id AND i.suspended = 0
             AND i.permissions_valid = 1
         WHERE b.revoked = 0 AND (b.tenant_id, b.repo_id) > (?1, ?2)
         ORDER BY b.tenant_id, b.repo_id LIMIT ?3",
    )?;
    let rows = stmt.query_map(params![tenant, repo, limit], |r| {
        Ok((r.get::<_, [u8; 16]>(0)?, r.get::<_, [u8; 16]>(1)?))
    })?;
    let mut out = Vec::new();
    for row in rows {
        let (tenant, repo) = row?;
        out.push(BoundRepo {
            tenant: TenantId::from_bytes(tenant).map_err(|_| Error::Corrupt("tenant_id"))?,
            repo: RepoId::from_bytes(repo).map_err(|_| Error::Corrupt("repo_id"))?,
        });
    }
    Ok(out)
}

/// A queued job GitHub states but no delivery announced, recorded as demand like any other.
/// Idempotent against the delivery path: the row is written only when the job is unknown, and the
/// first sighting keeps its own stamp.
pub fn observe(
    tx: &Transaction<'_>,
    tenant: TenantId,
    repo: RepoId,
    job: u64,
    run: u64,
    class: &str,
    now: UnixMillis,
) -> Result<bool> {
    let (job, run) = (
        i64::try_from(job).map_err(|_| Error::InvalidInput("runner job"))?,
        i64::try_from(run).map_err(|_| Error::InvalidInput("runner run"))?,
    );
    if job <= 0 || run <= 0 || RunnerClass::parse(class).is_none() {
        return Err(Error::InvalidInput("runner job"));
    }
    let changed = tx.execute(
        "INSERT INTO runner_jobs(tenant_id, repo_id, job_id, run_id, class, state_code,
            runner, conclusion, queued_ms, started_ms, completed_ms)
         VALUES (?1, ?2, ?3, ?4, ?5, 0, NULL, NULL, ?6, NULL, NULL)
         ON CONFLICT(tenant_id, repo_id, job_id) DO NOTHING",
        params![tenant.as_bytes(), repo.as_bytes(), job, run, class, now.0],
    )?;
    Ok(changed == 1)
}

/// The live leases of one repository, for a reader that reports what runner mode is doing.
pub fn live(conn: &Connection, tenant: TenantId, repo: RepoId) -> Result<Vec<Lease>> {
    let sql = format!(
        "SELECT {LEASE_COLUMNS} FROM runner_leases
         WHERE tenant_id = ?1 AND repo_id = ?2 AND released_ms IS NULL ORDER BY offered_ms"
    );
    let mut stmt = conn.prepare_cached(&sql)?;
    let rows = stmt.query_map(params![tenant.as_bytes(), repo.as_bytes()], row_of)?;
    let mut out = Vec::new();
    for row in rows {
        out.push(decode(row?)?);
    }
    Ok(out)
}

/// What a pass needs to register a runner of one repository: the remote its binding names (which
/// spells the GitHub owner and repository), and the installation that may register it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProvisionBinding {
    pub remote: String,
    pub installation: u64,
    pub account: u64,
    /// GitHub's numeric id for the repository, which a repository-scoped token names.
    pub repo_id: u64,
    pub login: String,
    pub personal: bool,
}

pub fn provision_binding(
    conn: &Connection,
    tenant: TenantId,
    repo: RepoId,
) -> Result<Option<ProvisionBinding>> {
    let row: Option<(Vec<u8>, String, i64, i64, String, i64)> = conn
        .prepare_cached(
            "SELECT b.binding, i.external_id, i.account_id, b.forge_repo_id, i.account_login,
                    i.account_personal
             FROM source_bindings b
             JOIN tenants t ON t.id = b.tenant_id AND t.active = 1
             JOIN installations i ON i.id = b.installation_id AND i.tenant_id = b.tenant_id
                 AND i.suspended = 0 AND i.permissions_valid = 1
             WHERE b.tenant_id = ?1 AND b.repo_id = ?2 AND b.revoked = 0",
        )?
        .query_row(params![tenant.as_bytes(), repo.as_bytes()], |r| {
            Ok((
                r.get(0)?,
                r.get(1)?,
                r.get(2)?,
                r.get(3)?,
                r.get(4)?,
                r.get(5)?,
            ))
        })
        .optional()?;
    let Some((binding, installation, account, repo_id, login, personal)) = row else {
        return Ok(None);
    };
    let binding: sentinel_protocol::source::Binding =
        serde_json::from_slice(&binding).map_err(|_| Error::Corrupt("source binding"))?;
    Ok(Some(ProvisionBinding {
        remote: binding.remote,
        installation: installation
            .parse()
            .map_err(|_| Error::Corrupt("installation id"))?,
        account: u64::try_from(account).map_err(|_| Error::Corrupt("installation account"))?,
        repo_id: u64::try_from(repo_id).map_err(|_| Error::Corrupt("repository id"))?,
        login,
        personal: personal == 1,
    }))
}

/// One lease whose configuration is made but not yet delivered: the worker to send it to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pending {
    pub lease: RunnerLeaseId,
    pub tenant: TenantId,
    pub repo: RepoId,
    pub worker: WorkerId,
}

pub fn pending_delivery(conn: &Connection, limit: u32) -> Result<Vec<Pending>> {
    let mut stmt = conn.prepare_cached(
        "SELECT id, tenant_id, repo_id, worker_id FROM runner_leases
         WHERE released_ms IS NULL AND jit_ms IS NOT NULL AND taken_ms IS NULL
           AND sealed_jit IS NOT NULL
         ORDER BY jit_ms LIMIT ?1",
    )?;
    let rows = stmt.query_map([limit], |r| {
        Ok((
            r.get::<_, [u8; 16]>(0)?,
            r.get::<_, [u8; 16]>(1)?,
            r.get::<_, [u8; 16]>(2)?,
            r.get::<_, [u8; 16]>(3)?,
        ))
    })?;
    let mut out = Vec::new();
    for row in rows {
        let (lease, tenant, repo, worker) = row?;
        out.push(Pending {
            lease: RunnerLeaseId::from_bytes(lease)
                .map_err(|_| Error::Corrupt("runner lease id"))?,
            tenant: TenantId::from_bytes(tenant).map_err(|_| Error::Corrupt("tenant_id"))?,
            repo: RepoId::from_bytes(repo).map_err(|_| Error::Corrupt("repo_id"))?,
            worker: WorkerId::from_bytes(worker).map_err(|_| Error::Corrupt("worker_id"))?,
        });
    }
    Ok(out)
}

/// The worker that holds one lease, held or ended: what a stop names.
pub fn owner(conn: &Connection, lease: RunnerLeaseId) -> Result<Option<WorkerId>> {
    conn.prepare_cached("SELECT worker_id FROM runner_leases WHERE id = ?1")?
        .query_row([lease.as_bytes()], |r| r.get(0))
        .optional()?
        .map(|bytes| WorkerId::from_bytes(bytes).map_err(|_| Error::Corrupt("worker_id")))
        .transpose()
}
