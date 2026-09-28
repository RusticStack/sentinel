//! Storage quotas and retention at deployment, tenant, repository and run
//! level (R01).
//!
//! The deployment's configuration sets the defaults ([`Deployment`]); a
//! `storage_policies` row overrides them for one tenant (`repo_id = X''`) or
//! one repository. A NULL column inherits. Retention only ever narrows going
//! down: a repository's effective retention is the smaller of its own and its
//! tenant's, so a tenant administrator can shorten a repository's retention
//! but never keep its data longer than the platform allows the tenant.
//! Quotas are separate caps at each level, all enforced:
//!
//! | Level | Counts | Enforced when |
//! |---|---|---|
//! | deployment | every tenant's objects, open uploads and logs | an object or upload would add bytes |
//! | tenant | its objects, open uploads and logs | the same |
//! | repository | its artifacts' logical bytes and its logs | an artifact begins |
//! | run | its artifacts | an artifact begins and while it streams |
//!
//! Logs are counted but never refused for quota: a log is the evidence of
//! what ran, and refusing it would hide a failure. They are bounded instead
//! by the per-attempt cap and their retention.
//!
//! **Log expiry is database-driven.** Once an attempt is released, the
//! maintenance pass stamps its log's stored bytes and its expiry deadline
//! (release plus the effective log retention) — [`unstamped`] then
//! [`stamp`]. [`expiring`] and [`expire`] then retire logs past their deadline:
//! the row records `log_expired_ms` and drops its bytes from usage in one
//! transaction, and the files go after that commits. A crash between the two
//! leaves files whose row says expired; the log store's directory sweep
//! removes those, and any directory no attempt row names. Changing a policy
//! re-stamps the logs and re-clamps the artifacts it covers in the same
//! transaction, so a lowered retention frees space on the next pass rather
//! than for new data only.

use std::collections::HashMap;

use rusqlite::{Connection, OptionalExtension, Transaction, params};
use sentinel_core::{AttemptId, JobId, RepoId, RunId, TenantId, UnixMillis};

use crate::{Error, Result, auth::Authority};

const DAY_MS: i64 = 24 * 3_600_000;

/// Shortest and longest retention a policy may set.
pub const MIN_RETENTION_MS: i64 = 3_600_000;
pub const MAX_RETENTION_MS: i64 = 366 * DAY_MS;

/// The deployment's own storage limits, from configuration. `0` quotas mean
/// unlimited.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Deployment {
    /// Cap on everything every tenant stores together.
    pub quota_bytes: u64,
    /// Quota for a tenant without its own.
    pub tenant_quota_bytes: u64,
    /// Log retention for a tenant without its own.
    pub log_retention_ms: i64,
    /// Longest artifact retention a pipeline may ask for, for a tenant
    /// without its own limit; a longer `retain` is shortened to it.
    pub artifact_retention_ms: i64,
    /// Artifact bytes one run may store.
    pub run_artifact_bytes: u64,
}

impl Default for Deployment {
    fn default() -> Self {
        Deployment {
            quota_bytes: 0,
            tenant_quota_bytes: 0,
            log_retention_ms: 14 * DAY_MS,
            artifact_retention_ms: 90 * DAY_MS,
            run_artifact_bytes: sentinel_protocol::limits::MAX_RUN_ARTIFACT_BYTES,
        }
    }
}

/// One `storage_policies` row as set: `None` inherits.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Policy {
    pub quota_bytes: Option<u64>,
    pub log_retention_ms: Option<i64>,
    pub artifact_retention_ms: Option<i64>,
}

impl Policy {
    fn is_empty(&self) -> bool {
        *self == Policy::default()
    }
    fn validate(&self) -> Result<()> {
        if self.quota_bytes == Some(0) || self.quota_bytes.is_some_and(|q| q > i64::MAX as u64) {
            return Err(Error::InvalidInput("quota"));
        }
        for ms in [self.log_retention_ms, self.artifact_retention_ms]
            .into_iter()
            .flatten()
        {
            if !(MIN_RETENTION_MS..=MAX_RETENTION_MS).contains(&ms) {
                return Err(Error::InvalidInput("retention"));
            }
        }
        Ok(())
    }
}

/// The limits that apply to one tenant, or one repository of it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Effective {
    /// The tenant's quota; 0 unlimited.
    pub tenant_quota_bytes: u64,
    /// The repository's own quota; 0 none (only the tenant's applies).
    pub repo_quota_bytes: u64,
    pub log_retention_ms: i64,
    pub artifact_retention_ms: i64,
}

fn blob_repo(repo: Option<RepoId>) -> Vec<u8> {
    repo.map_or_else(Vec::new, |r| r.as_bytes().to_vec())
}

/// The policy row of a tenant (`repo = None`) or repository; all `None`
/// when there is none.
pub fn policy(conn: &Connection, tenant: TenantId, repo: Option<RepoId>) -> Result<Policy> {
    Ok(conn
        .prepare_cached(
            "SELECT quota_bytes, log_retention_ms, artifact_retention_ms
             FROM storage_policies WHERE tenant_id = ?1 AND repo_id = ?2",
        )?
        .query_row(
            params![tenant.as_bytes().as_slice(), blob_repo(repo)],
            |r| {
                Ok(Policy {
                    quota_bytes: r.get::<_, Option<i64>>(0)?.map(|q| q as u64),
                    log_retention_ms: r.get(1)?,
                    artifact_retention_ms: r.get(2)?,
                })
            },
        )
        .optional()?
        .unwrap_or_default())
}

/// What applies to `tenant`, or to one repository of it.
pub fn effective(
    conn: &Connection,
    d: &Deployment,
    tenant: TenantId,
    repo: Option<RepoId>,
) -> Result<Effective> {
    let own = policy(conn, tenant, None)?;
    let tenant_logs = own.log_retention_ms.unwrap_or(d.log_retention_ms);
    let tenant_artifacts = own.artifact_retention_ms.unwrap_or(d.artifact_retention_ms);
    let mut out = Effective {
        tenant_quota_bytes: own.quota_bytes.unwrap_or(d.tenant_quota_bytes),
        repo_quota_bytes: 0,
        log_retention_ms: tenant_logs,
        artifact_retention_ms: tenant_artifacts,
    };
    if repo.is_some() {
        let narrow = policy(conn, tenant, repo)?;
        out.repo_quota_bytes = narrow.quota_bytes.unwrap_or(0);
        out.log_retention_ms = narrow
            .log_retention_ms
            .map_or(tenant_logs, |ms| ms.min(tenant_logs));
        out.artifact_retention_ms = narrow
            .artifact_retention_ms
            .map_or(tenant_artifacts, |ms| ms.min(tenant_artifacts));
    }
    Ok(out)
}

/// Set (or, when every field is `None`, remove) the policy of a tenant or
/// one of its repositories, then re-apply retention to what it covers.
///
/// A tenant's policy is platform administration. A repository's is its
/// tenant's administration, and may only narrow: its retention cannot exceed
/// the tenant's effective retention, nor its quota the tenant's quota.
pub fn set(
    tx: &Transaction<'_>,
    authority: &Authority,
    d: &Deployment,
    tenant: TenantId,
    repo: Option<RepoId>,
    policy: Policy,
    now: UnixMillis,
) -> Result<()> {
    policy.validate()?;
    match (repo, authority) {
        (None, _) => authority.require_platform(tx)?,
        (Some(_), Authority::HostLocal) => {}
        (Some(_), Authority::Credential { principal, .. }) => {
            crate::auth::require_tenant_admin(tx, *principal, tenant)?
        }
    }
    let tenant_known: bool = tx
        .prepare_cached("SELECT EXISTS(SELECT 1 FROM tenants WHERE id = ?1)")?
        .query_row([tenant.as_bytes().as_slice()], |r| r.get(0))?;
    if !tenant_known {
        return Err(Error::NotFound);
    }
    if let Some(repo) = repo {
        let owned: bool = tx
            .prepare_cached("SELECT EXISTS(SELECT 1 FROM repos WHERE id = ?1 AND tenant_id = ?2)")?
            .query_row(
                params![repo.as_bytes().as_slice(), tenant.as_bytes().as_slice()],
                |r| r.get(0),
            )?;
        if !owned {
            return Err(Error::NotFound);
        }
        let limit = effective(tx, d, tenant, None)?;
        if policy
            .log_retention_ms
            .is_some_and(|ms| ms > limit.log_retention_ms)
            || policy
                .artifact_retention_ms
                .is_some_and(|ms| ms > limit.artifact_retention_ms)
        {
            return Err(Error::InvalidInput("retention above the tenant's"));
        }
        if limit.tenant_quota_bytes > 0
            && policy
                .quota_bytes
                .is_some_and(|q| q > limit.tenant_quota_bytes)
        {
            return Err(Error::InvalidInput("quota above the tenant's"));
        }
    }
    if policy.is_empty() {
        tx.prepare_cached("DELETE FROM storage_policies WHERE tenant_id = ?1 AND repo_id = ?2")?
            .execute(params![tenant.as_bytes().as_slice(), blob_repo(repo)])?;
    } else {
        tx.prepare_cached(
            "INSERT INTO storage_policies(tenant_id, repo_id, quota_bytes, log_retention_ms,
                 artifact_retention_ms, updated_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(tenant_id, repo_id) DO UPDATE SET
                 quota_bytes = excluded.quota_bytes,
                 log_retention_ms = excluded.log_retention_ms,
                 artifact_retention_ms = excluded.artifact_retention_ms,
                 updated_ms = excluded.updated_ms",
        )?
        .execute(params![
            tenant.as_bytes().as_slice(),
            blob_repo(repo),
            policy.quota_bytes.map(|q| q as i64),
            policy.log_retention_ms,
            policy.artifact_retention_ms,
            now.0,
        ])?;
    }
    reapply(tx, d, tenant, repo)
}

/// The effective log and artifact retention of an attempt's or artifact's
/// repository, as SQL over `storage_policies`: `?1` tenant, `?2` the
/// deployment's value, `{col}` the policy column and `{repo}` the row's
/// repository expression.
fn effective_sql(col: &str, repo: &str) -> String {
    format!(
        "(SELECT MIN(COALESCE(rp.{col}, tp), tp) FROM
            (SELECT COALESCE((SELECT {col} FROM storage_policies
                WHERE tenant_id = ?1 AND repo_id = X''), ?2) AS tp)
          LEFT JOIN storage_policies rp ON rp.tenant_id = ?1 AND rp.repo_id = {repo})"
    )
}

/// Re-stamp the stamped, unexpired logs and re-clamp the artifacts of a
/// tenant (every repository without its own narrower value follows it) or
/// of one repository, to the policy now in force. One statement per kind;
/// an administrative change is rare and may scan the tenant's rows.
fn reapply(
    tx: &Transaction<'_>,
    d: &Deployment,
    tenant: TenantId,
    repo: Option<RepoId>,
) -> Result<()> {
    let scope = if repo.is_some() {
        " AND repo_id = ?3"
    } else {
        ""
    };
    let logs = format!(
        "UPDATE attempts SET log_expires_ms = released_ms + {}
         WHERE tenant_id = ?1 AND log_expires_ms IS NOT NULL
           AND log_expired_ms IS NULL{scope}",
        effective_sql("log_retention_ms", "COALESCE(attempts.repo_id, X'')"),
    );
    let run_scope = if repo.is_some() {
        " AND run_id IN (SELECT id FROM runs WHERE tenant_id = ?1 AND repo_id = ?3)"
    } else {
        ""
    };
    let artifacts = format!(
        "UPDATE artifacts SET retain_until_ms = MIN(retain_until_ms, created_ms + {})
         WHERE tenant_id = ?1{run_scope}",
        effective_sql(
            "artifact_retention_ms",
            "(SELECT repo_id FROM runs WHERE id = artifacts.run_id)"
        ),
    );
    let t = tenant.as_bytes().as_slice();
    match repo {
        Some(repo) => {
            let r = repo.as_bytes().as_slice();
            tx.execute(&logs, params![t, d.log_retention_ms, r])?;
            tx.execute(&artifacts, params![t, d.artifact_retention_ms, r])?;
        }
        None => {
            tx.execute(&logs, params![t, d.log_retention_ms])?;
            tx.execute(&artifacts, params![t, d.artifact_retention_ms])?;
        }
    }
    Ok(())
}

/// A tenant's stored bytes: objects plus open uploads, and logs.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Usage {
    pub object_bytes: u64,
    pub log_bytes: u64,
}

impl Usage {
    pub fn total(&self) -> u64 {
        self.object_bytes.saturating_add(self.log_bytes)
    }
}

pub fn tenant_usage(conn: &Connection, tenant: TenantId) -> Result<Usage> {
    Ok(conn
        .prepare_cached("SELECT bytes, log_bytes FROM tenant_usage WHERE tenant_id = ?1")?
        .query_row([tenant.as_bytes().as_slice()], |r| {
            Ok(Usage {
                object_bytes: r.get::<_, i64>(0)?.max(0) as u64,
                log_bytes: r.get::<_, i64>(1)?.max(0) as u64,
            })
        })
        .optional()?
        .unwrap_or_default())
}

/// Everything every tenant stores.
pub fn deployment_usage(conn: &Connection) -> Result<u64> {
    let total: i64 = conn
        .prepare_cached("SELECT COALESCE(SUM(bytes + log_bytes), 0) FROM tenant_usage")?
        .query_row([], |r| r.get(0))?;
    Ok(total.max(0) as u64)
}

/// A repository's stored bytes: its artifacts' logical bytes and its logs.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RepoUsage {
    pub artifact_bytes: u64,
    pub log_bytes: u64,
}

impl RepoUsage {
    pub fn total(&self) -> u64 {
        self.artifact_bytes.saturating_add(self.log_bytes)
    }
}

pub fn repo_usage(conn: &Connection, tenant: TenantId, repo: RepoId) -> Result<RepoUsage> {
    Ok(conn
        .prepare_cached(
            "SELECT artifact_bytes, log_bytes FROM repo_usage
             WHERE tenant_id = ?1 AND repo_id = ?2",
        )?
        .query_row(
            params![tenant.as_bytes().as_slice(), repo.as_bytes().as_slice()],
            |r| {
                Ok(RepoUsage {
                    artifact_bytes: r.get::<_, i64>(0)?.max(0) as u64,
                    log_bytes: r.get::<_, i64>(1)?.max(0) as u64,
                })
            },
        )
        .optional()?
        .unwrap_or_default())
}

/// One repository's storage as its tenant sees it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RepoStorage {
    pub repo: RepoId,
    pub name: String,
    pub usage: RepoUsage,
    pub policy: Policy,
}

/// Every repository of a tenant with its usage and its own policy, by name.
pub fn repos(conn: &Connection, tenant: TenantId) -> Result<Vec<RepoStorage>> {
    let mut stmt = conn.prepare_cached(
        "SELECT r.id, r.name, COALESCE(u.artifact_bytes, 0), COALESCE(u.log_bytes, 0),
                p.quota_bytes, p.log_retention_ms, p.artifact_retention_ms
         FROM repos r
         LEFT JOIN repo_usage u ON u.tenant_id = r.tenant_id AND u.repo_id = r.id
         LEFT JOIN storage_policies p ON p.tenant_id = r.tenant_id AND p.repo_id = r.id
         WHERE r.tenant_id = ?1 ORDER BY r.name",
    )?;
    let rows = stmt.query_map([tenant.as_bytes().as_slice()], |r| {
        Ok((
            r.get::<_, [u8; 16]>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, i64>(2)?,
            r.get::<_, i64>(3)?,
            r.get::<_, Option<i64>>(4)?,
            r.get::<_, Option<i64>>(5)?,
            r.get::<_, Option<i64>>(6)?,
        ))
    })?;
    let mut out = Vec::new();
    for row in rows {
        let (id, name, artifacts, logs, quota, log_ms, art_ms) = row?;
        out.push(RepoStorage {
            repo: RepoId::from_bytes(id).map_err(|_| Error::Corrupt("repo_id"))?,
            name,
            usage: RepoUsage {
                artifact_bytes: artifacts.max(0) as u64,
                log_bytes: logs.max(0) as u64,
            },
            policy: Policy {
                quota_bytes: quota.map(|q| q as u64),
                log_retention_ms: log_ms,
                artifact_retention_ms: art_ms,
            },
        });
    }
    Ok(out)
}

/// Refuse `extra` more bytes for `tenant` when that would pass its quota or
/// the deployment's. `owed` is what the tenant already owes (its usage plus
/// what the caller knows is in flight for it).
pub fn check_tenant(
    conn: &Connection,
    d: &Deployment,
    tenant: TenantId,
    owed: u64,
    extra: u64,
) -> Result<()> {
    let quota = effective(conn, d, tenant, None)?.tenant_quota_bytes;
    if quota > 0 && owed.saturating_add(extra) > quota {
        return Err(Error::QuotaExceeded);
    }
    if d.quota_bytes > 0 && deployment_usage(conn)?.saturating_add(extra) > d.quota_bytes {
        return Err(Error::QuotaExceeded);
    }
    Ok(())
}

/// Refuse `extra` more artifact bytes for a repository over its own quota.
pub fn check_repo(
    conn: &Connection,
    d: &Deployment,
    tenant: TenantId,
    repo: RepoId,
    extra: u64,
) -> Result<()> {
    let quota = effective(conn, d, tenant, Some(repo))?.repo_quota_bytes;
    if quota > 0
        && repo_usage(conn, tenant, repo)?
            .total()
            .saturating_add(extra)
            > quota
    {
        return Err(Error::QuotaExceeded);
    }
    Ok(())
}

/// [`check_repo`] for the repository a run belongs to: refuse `extra`
/// more artifact bytes when that repository is over its own quota.
pub fn check_run_repo(
    conn: &Connection,
    d: &Deployment,
    tenant: TenantId,
    run: RunId,
    extra: u64,
) -> Result<()> {
    let repo: Option<[u8; 16]> = conn
        .prepare_cached("SELECT repo_id FROM runs WHERE id = ?1 AND tenant_id = ?2")?
        .query_row(
            params![run.as_bytes().as_slice(), tenant.as_bytes().as_slice()],
            |r| r.get(0),
        )
        .optional()?
        .flatten();
    match repo.map(RepoId::from_bytes) {
        Some(Ok(repo)) => check_repo(conn, d, tenant, repo, extra),
        Some(Err(_)) => Err(Error::Corrupt("repo_id")),
        None => Ok(()),
    }
}

/// Record the deployment's limits where the database's own triggers read
/// them (the artifact retention cap) and host-local tools find them
/// ([`installed`]). The controller calls it at every start, so a
/// configuration change applies from then on.
pub fn install(tx: &Transaction<'_>, d: &Deployment) -> Result<()> {
    let fits = |v: u64| i64::try_from(v).map_err(|_| Error::InvalidInput("storage limit"));
    if d.log_retention_ms <= 0 || d.artifact_retention_ms <= 0 || d.run_artifact_bytes == 0 {
        return Err(Error::InvalidInput("storage limit"));
    }
    tx.prepare_cached(
        "INSERT INTO storage_defaults(id, quota_bytes, tenant_quota_bytes, log_retention_ms,
             artifact_retention_ms, run_artifact_bytes, installed_ms)
         VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6)
         ON CONFLICT(id) DO UPDATE SET quota_bytes = excluded.quota_bytes,
             tenant_quota_bytes = excluded.tenant_quota_bytes,
             log_retention_ms = excluded.log_retention_ms,
             artifact_retention_ms = excluded.artifact_retention_ms,
             run_artifact_bytes = excluded.run_artifact_bytes,
             installed_ms = excluded.installed_ms",
    )?
    .execute(params![
        fits(d.quota_bytes)?,
        fits(d.tenant_quota_bytes)?,
        d.log_retention_ms,
        d.artifact_retention_ms,
        fits(d.run_artifact_bytes)?,
        UnixMillis::now().0,
    ])?;
    Ok(())
}

/// The limits the controller last started with, or the built-in defaults
/// when it never has — what host-local administration validates against.
pub fn installed(conn: &Connection) -> Result<Deployment> {
    Ok(conn
        .prepare_cached(
            "SELECT quota_bytes, tenant_quota_bytes, log_retention_ms, artifact_retention_ms,
                    run_artifact_bytes
             FROM storage_defaults WHERE id = 1",
        )?
        .query_row([], |r| {
            Ok(Deployment {
                quota_bytes: r.get::<_, i64>(0)?.max(0) as u64,
                tenant_quota_bytes: r.get::<_, i64>(1)?.max(0) as u64,
                log_retention_ms: r.get(2)?,
                artifact_retention_ms: r.get(3)?,
                run_artifact_bytes: r.get::<_, i64>(4)?.max(1) as u64,
            })
        })
        .optional()?
        .unwrap_or_default())
}

/// A released attempt whose log has no stored size or deadline yet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Unstamped {
    pub attempt: AttemptId,
    pub run: RunId,
    pub job: JobId,
    pub tenant: TenantId,
    pub repo: Option<RepoId>,
    pub released_ms: i64,
}

fn id<T>(
    bytes: [u8; 16],
    f: fn([u8; 16]) -> std::result::Result<T, sentinel_core::InvalidId>,
    what: &'static str,
) -> Result<T> {
    f(bytes).map_err(|_| Error::Corrupt(what))
}

/// Up to `limit` released attempts whose logs are not stamped yet, oldest
/// release first (the `attempts_log_unstamped` index).
pub fn unstamped(conn: &Connection, limit: u32) -> Result<Vec<Unstamped>> {
    let mut stmt = conn.prepare_cached(
        "SELECT a.id, j.run_id, a.job_id, a.tenant_id, a.repo_id, a.released_ms
         FROM attempts a INDEXED BY attempts_log_unstamped
         JOIN jobs j ON j.id = a.job_id
         WHERE a.released_ms IS NOT NULL AND a.log_expires_ms IS NULL
         ORDER BY a.released_ms LIMIT ?1",
    )?;
    let rows = stmt.query_map([i64::from(limit)], |r| {
        Ok((
            r.get::<_, [u8; 16]>(0)?,
            r.get::<_, [u8; 16]>(1)?,
            r.get::<_, [u8; 16]>(2)?,
            r.get::<_, [u8; 16]>(3)?,
            r.get::<_, Option<[u8; 16]>>(4)?,
            r.get::<_, i64>(5)?,
        ))
    })?;
    let mut out = Vec::new();
    for row in rows {
        let (attempt, run, job, tenant, repo, released_ms) = row?;
        out.push(Unstamped {
            attempt: id(attempt, AttemptId::from_bytes, "attempt_id")?,
            run: id(run, RunId::from_bytes, "run_id")?,
            job: id(job, JobId::from_bytes, "job_id")?,
            tenant: id(tenant, TenantId::from_bytes, "tenant_id")?,
            repo: repo
                .map(|r| id(r, RepoId::from_bytes, "repo_id"))
                .transpose()?,
            released_ms,
        });
    }
    Ok(out)
}

/// Stamp each log's stored bytes and its deadline (release plus the
/// effective retention). Rows stamped meanwhile are left alone.
pub fn stamp(tx: &Transaction<'_>, d: &Deployment, logs: &[(Unstamped, u64)]) -> Result<u32> {
    let mut retention: HashMap<(TenantId, Option<RepoId>), i64> = HashMap::new();
    let mut stamped = 0u32;
    for (row, bytes) in logs {
        let key = (row.tenant, row.repo);
        let ms = match retention.get(&key) {
            Some(ms) => *ms,
            None => {
                let ms = effective(tx, d, row.tenant, row.repo)?.log_retention_ms;
                retention.insert(key, ms);
                ms
            }
        };
        stamped += tx
            .prepare_cached(
                "UPDATE attempts SET log_bytes = ?2, log_expires_ms = ?3
                 WHERE id = ?1 AND log_expires_ms IS NULL",
            )?
            .execute(params![
                row.attempt.as_bytes().as_slice(),
                i64::try_from(*bytes).unwrap_or(i64::MAX),
                row.released_ms.saturating_add(ms),
            ])? as u32;
    }
    Ok(stamped)
}

/// A log past its deadline.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Expiring {
    pub attempt: AttemptId,
    pub run: RunId,
    pub job: JobId,
}

/// Up to `limit` logs whose deadline has passed, earliest first.
pub fn expiring(conn: &Connection, now: UnixMillis, limit: u32) -> Result<Vec<Expiring>> {
    let mut stmt = conn.prepare_cached(
        "SELECT a.id, j.run_id, a.job_id
         FROM attempts a INDEXED BY attempts_log_expiry
         JOIN jobs j ON j.id = a.job_id
         WHERE a.log_expires_ms IS NOT NULL AND a.log_expired_ms IS NULL
           AND a.log_expires_ms <= ?1
         ORDER BY a.log_expires_ms LIMIT ?2",
    )?;
    let rows = stmt.query_map(params![now.0, i64::from(limit)], |r| {
        Ok((
            r.get::<_, [u8; 16]>(0)?,
            r.get::<_, [u8; 16]>(1)?,
            r.get::<_, [u8; 16]>(2)?,
        ))
    })?;
    let mut out = Vec::new();
    for row in rows {
        let (attempt, run, job) = row?;
        out.push(Expiring {
            attempt: id(attempt, AttemptId::from_bytes, "attempt_id")?,
            run: id(run, RunId::from_bytes, "run_id")?,
            job: id(job, JobId::from_bytes, "job_id")?,
        });
    }
    Ok(out)
}

/// Record the logs as expired and drop their bytes from usage; re-checks the
/// deadline, so a log whose retention was raised meanwhile stays. Returns
/// the attempts whose files the caller now removes, after this commits.
pub fn expire(tx: &Transaction<'_>, logs: &[Expiring], now: UnixMillis) -> Result<Vec<Expiring>> {
    let mut out = Vec::with_capacity(logs.len());
    for log in logs {
        let changed = tx
            .prepare_cached(
                "UPDATE attempts SET log_expired_ms = ?2, log_bytes = 0
                 WHERE id = ?1 AND log_expired_ms IS NULL
                   AND log_expires_ms IS NOT NULL AND log_expires_ms <= ?2",
            )?
            .execute(params![log.attempt.as_bytes().as_slice(), now.0])?;
        if changed == 1 {
            out.push(*log);
        }
    }
    Ok(out)
}

/// Whether an attempt's log files may be deleted by the directory sweep: no
/// attempt row names it, or retention already expired it.
pub fn log_gone(conn: &Connection, attempt: AttemptId) -> Result<bool> {
    let expired: Option<bool> = conn
        .prepare_cached("SELECT log_expired_ms IS NOT NULL FROM attempts WHERE id = ?1")?
        .query_row([attempt.as_bytes().as_slice()], |r| r.get(0))
        .optional()?;
    Ok(expired.unwrap_or(true))
}

/// When retention removed an attempt's log, if it did.
pub fn log_expired(conn: &Connection, attempt: AttemptId) -> Result<Option<UnixMillis>> {
    Ok(conn
        .prepare_cached("SELECT log_expired_ms FROM attempts WHERE id = ?1")?
        .query_row([attempt.as_bytes().as_slice()], |r| {
            r.get::<_, Option<i64>>(0)
        })
        .optional()?
        .flatten()
        .map(UnixMillis))
}

/// How long aborted upload rows are kept for explanation before they go.
pub const ABORTED_UPLOAD_KEEP_MS: i64 = 7 * DAY_MS;

/// Delete up to `limit` aborted upload sessions whose expiry is older than
/// [`ABORTED_UPLOAD_KEEP_MS`]. Committed sessions are kept: they authorize
/// reads of the object they produced.
pub fn purge_aborted_uploads(tx: &Transaction<'_>, now: UnixMillis, limit: u32) -> Result<u32> {
    let ids: Vec<Vec<u8>> = tx
        .prepare_cached(
            "SELECT id FROM uploads INDEXED BY uploads_aborted
             WHERE state_code = 2 AND expires_ms < ?1 LIMIT ?2",
        )?
        .query_map(
            params![now.0 - ABORTED_UPLOAD_KEEP_MS, i64::from(limit)],
            |r| r.get(0),
        )?
        .collect::<std::result::Result<_, _>>()?;
    let mut purged = 0u32;
    for id in ids {
        purged += tx
            .prepare_cached("DELETE FROM uploads WHERE id = ?1 AND state_code = 2")?
            .execute([id])? as u32;
    }
    Ok(purged)
}
