//! Read models for the human web interface (U02, U04, U05): tenant members,
//! the deployment's tenants and pools, the audit trails a page by page,
//! GitHub synchronization lag and a worker's load. Every function checks its
//! own authority first, so a route cannot forget to; a tenant the caller may
//! not see is `NotFound`, exactly like one that does not exist.

use rusqlite::{Connection, OptionalExtension, params};
use sentinel_core::{
    PoolId, RepoId, TenantId, UnixMillis, UserId, WorkerId,
    auth::{Principal, Role},
};

use crate::{
    Error, Result,
    auth::{self, Authority},
    dispatch::{self, Capacity},
    local_auth::{self, AuditRecord},
    operations,
    tenancy::PoolKind,
};

/// Largest page any listing here returns.
pub const MAX_PAGE: u16 = 100;

fn page(limit: u16) -> Result<i64> {
    if !(1..=MAX_PAGE).contains(&limit) {
        return Err(Error::InvalidInput("page size"));
    }
    Ok(i64::from(limit))
}

fn user_id(bytes: [u8; 16]) -> Result<UserId> {
    UserId::from_bytes(bytes).map_err(|_| Error::Corrupt("user_id"))
}

fn role(code: u8) -> Result<Role> {
    Ok(match code {
        1 => Role::Reader,
        2 => Role::Operator,
        3 => Role::TenantAdmin,
        _ => return Err(Error::Corrupt("memberships.role")),
    })
}

/// One member of a tenant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Member {
    pub user: UserId,
    pub display_name: String,
    /// The local sign-in name, when the account has a password.
    pub username: Option<String>,
    /// A service principal confined to this tenant, not a person.
    pub service: bool,
    pub role: Role,
    pub active: bool,
}

/// A tenant's members in user-id order, a keyset page after `after`.
/// Tenant administration (or platform administration) is required: the
/// member list says who can reach the tenant's code.
pub fn members(
    conn: &Connection,
    principal: Principal,
    tenant: TenantId,
    after: Option<UserId>,
    limit: u16,
) -> Result<Vec<Member>> {
    auth::require_tenant_admin(conn, principal, tenant)?;
    let limit = page(limit)?;
    let mut stmt = conn.prepare_cached(
        "SELECT m.user_id, u.display_name, c.username, u.kind, m.role, u.active
         FROM memberships m JOIN users u ON u.id = m.user_id
         LEFT JOIN local_credentials c ON c.user_id = m.user_id
         WHERE m.tenant_id = ?1 AND m.user_id > ?2
         ORDER BY m.user_id LIMIT ?3",
    )?;
    let after = after.map_or([0u8; 16], |u| *u.as_bytes());
    let rows = stmt.query_map(params![tenant.as_bytes(), &after[..], limit], |r| {
        Ok((
            r.get::<_, [u8; 16]>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, Option<String>>(2)?,
            r.get::<_, i64>(3)?,
            r.get::<_, u8>(4)?,
            r.get::<_, bool>(5)?,
        ))
    })?;
    rows.map(|row| {
        let (user, display_name, username, kind, code, active) = row?;
        Ok(Member {
            user: user_id(user)?,
            display_name,
            username,
            service: kind == 1,
            role: role(code)?,
            active,
        })
    })
    .collect()
}

/// The account with this local sign-in name, if any: how an administrator
/// names a person to add. Existence is not secret from a tenant admin, who
/// can invite anyone.
pub fn user_by_username(conn: &Connection, username: &str) -> Result<Option<UserId>> {
    conn.prepare_cached("SELECT user_id FROM local_credentials WHERE username = ?1")?
        .query_row([username], |r| r.get::<_, [u8; 16]>(0))
        .optional()?
        .map(user_id)
        .transpose()
}

/// A `usr_…` id as given, or else the account with that local sign-in name.
pub fn resolve_user(conn: &Connection, text: &str) -> Result<UserId> {
    if let Ok(user) = text.parse::<UserId>() {
        return Ok(user);
    }
    user_by_username(conn, text)?.ok_or(Error::NotFound)
}

/// One tenant of the deployment, as platform administration lists it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TenantRow {
    pub id: TenantId,
    pub slug: String,
    pub personal: bool,
    pub active: bool,
    pub created: UnixMillis,
    pub members: u64,
    /// Committed and reserved object bytes plus stamped log bytes
    /// (`tenant_usage`).
    pub usage_bytes: u64,
    /// The tenant's own storage policy (R01); `None` fields inherit the
    /// deployment's.
    pub quota_bytes: Option<u64>,
    pub log_retention_ms: Option<i64>,
    pub artifact_retention_ms: Option<i64>,
}

/// Every tenant, by slug, a keyset page after `after`. Platform
/// administration only.
pub fn tenants(
    conn: &Connection,
    authority: Authority,
    after: Option<&str>,
    limit: u16,
) -> Result<Vec<TenantRow>> {
    authority.require_platform(conn)?;
    let limit = page(limit)?;
    let mut stmt = conn.prepare_cached(
        "SELECT t.id, t.slug, t.kind, t.active, t.created_ms,
            (SELECT COUNT(*) FROM memberships m WHERE m.tenant_id = t.id),
            COALESCE((SELECT bytes + log_bytes FROM tenant_usage u WHERE u.tenant_id = t.id), 0),
            p.quota_bytes, p.log_retention_ms, p.artifact_retention_ms
         FROM tenants t
         LEFT JOIN storage_policies p ON p.tenant_id = t.id AND p.repo_id = X''
         WHERE t.slug > ?1 ORDER BY t.slug LIMIT ?2",
    )?;
    let rows = stmt.query_map(params![after.unwrap_or(""), limit], |r| {
        Ok((
            r.get::<_, [u8; 16]>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, i64>(2)?,
            r.get::<_, bool>(3)?,
            r.get::<_, i64>(4)?,
            r.get::<_, i64>(5)?,
            r.get::<_, i64>(6)?,
            r.get::<_, Option<i64>>(7)?,
            r.get::<_, Option<i64>>(8)?,
            r.get::<_, Option<i64>>(9)?,
        ))
    })?;
    rows.map(|row| {
        let (id, slug, kind, active, created, members, usage, quota, logs, artifacts) = row?;
        Ok(TenantRow {
            id: TenantId::from_bytes(id).map_err(|_| Error::Corrupt("tenant_id"))?,
            slug,
            personal: kind == 1,
            active,
            created: UnixMillis(created),
            members: u64::try_from(members).unwrap_or(0),
            usage_bytes: u64::try_from(usage).unwrap_or(0),
            quota_bytes: quota.and_then(|q| u64::try_from(q).ok()),
            log_retention_ms: logs,
            artifact_retention_ms: artifacts,
        })
    })
    .collect()
}

/// A tenant by slug whatever its state, for platform administration (a
/// suspended tenant must still be reachable to reactivate it).
pub fn tenant_for_platform(
    conn: &Connection,
    authority: Authority,
    slug: &str,
) -> Result<TenantId> {
    authority.require_platform(conn)?;
    crate::lookup::tenant_by_slug_any(conn, slug)
}

/// One worker pool of the deployment, with who may use it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PoolRow {
    pub id: PoolId,
    pub name: String,
    pub kind: PoolKind,
    /// The owner's slug for a dedicated pool.
    pub owner: Option<String>,
    pub active: bool,
    /// Slugs of the tenants granted a shared pool, by slug.
    pub grants: Vec<String>,
    /// Enrolled, unrevoked workers.
    pub workers: u64,
}

/// Every pool, by name. Platform administration only; bounded by the
/// deployment's pool count, which only a platform administrator can grow.
pub fn pools(conn: &Connection, authority: Authority) -> Result<Vec<PoolRow>> {
    authority.require_platform(conn)?;
    let mut stmt = conn.prepare_cached(
        "SELECT p.id, p.name, p.kind, o.slug, p.active,
            (SELECT COUNT(*) FROM workers w WHERE w.pool_id = p.id AND w.revoked_ms IS NULL)
         FROM pools p LEFT JOIN tenants o ON o.id = p.owner_tenant_id
         ORDER BY p.name",
    )?;
    let rows = stmt.query_map([], |r| {
        Ok((
            r.get::<_, [u8; 16]>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, i64>(2)?,
            r.get::<_, Option<String>>(3)?,
            r.get::<_, bool>(4)?,
            r.get::<_, i64>(5)?,
        ))
    })?;
    let mut grants = conn.prepare_cached(
        "SELECT t.slug FROM pool_grants g JOIN tenants t ON t.id = g.tenant_id
         WHERE g.pool_id = ?1 ORDER BY t.slug",
    )?;
    let mut out = Vec::new();
    for row in rows {
        let (id, name, kind, owner, active, workers) = row?;
        let id = PoolId::from_bytes(id).map_err(|_| Error::Corrupt("pool_id"))?;
        let kind = match (kind, &owner) {
            (1, _) => PoolKind::Shared,
            (0, Some(_)) => {
                let owner: [u8; 16] = conn
                    .prepare_cached("SELECT owner_tenant_id FROM pools WHERE id = ?1")?
                    .query_row([id.as_bytes()], |r| r.get(0))?;
                PoolKind::Dedicated(
                    TenantId::from_bytes(owner).map_err(|_| Error::Corrupt("owner_tenant_id"))?,
                )
            }
            _ => return Err(Error::Corrupt("pools.kind")),
        };
        let granted = grants
            .query_map([id.as_bytes()], |r| r.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        out.push(PoolRow {
            id,
            name,
            kind,
            owner,
            active,
            grants: granted,
            workers: u64::try_from(workers).unwrap_or(0),
        });
    }
    Ok(out)
}

/// The deployment's authentication and administration audit, newest first,
/// strictly before sequence `before`. Platform administration only.
pub fn audit(
    conn: &Connection,
    authority: Authority,
    before: Option<i64>,
    limit: u16,
) -> Result<Vec<AuditRecord>> {
    authority.require_platform(conn)?;
    local_auth::audit_page(conn, before, limit)
}

/// A tenant's run control audit (cancel, rerun) with sequence numbers,
/// newest first, strictly before `before`. Tenant administration.
pub fn operations(
    conn: &Connection,
    principal: Principal,
    tenant: TenantId,
    before: Option<i64>,
    limit: u16,
) -> Result<Vec<(i64, operations::Record)>> {
    auth::require_tenant_admin(conn, principal, tenant)?;
    operations::page(conn, tenant, before, u32::from(limit.clamp(1, MAX_PAGE)))
}

/// A repository's GitHub synchronization: what is waiting to be published,
/// what GitHub refused, and when it last accepted something; plus the
/// deliveries not yet turned into runs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RepoSync {
    pub repo: RepoId,
    pub name: String,
    /// Check publications not yet delivered.
    pub pending: u64,
    /// The oldest pending publication's last change: its lag started then.
    pub oldest_pending_ms: Option<i64>,
    /// Publications refused permanently since `since_ms`.
    pub refused: u64,
    pub last_refused_ms: Option<i64>,
    /// The newest successful publication.
    pub last_published_ms: Option<i64>,
    /// Webhook or generic deliveries received but not yet resolved.
    pub open_deliveries: u64,
    pub oldest_delivery_ms: Option<i64>,
}

/// [`RepoSync`] for up to `limit` repositories of `tenant` the caller may
/// read, in id order after `after`. Each figure is one probe of an index
/// over rows in that state only (migration 45), so the cost is per
/// repository, never per publication ever made.
pub fn sync(
    conn: &Connection,
    principal: Principal,
    tenant: TenantId,
    since: UnixMillis,
    after: Option<RepoId>,
    limit: u16,
) -> Result<Vec<RepoSync>> {
    let repos = auth::list_repos(conn, principal, tenant, after, limit)?;
    let mut pending = conn.prepare_cached(
        "SELECT COUNT(*), MIN(updated_ms) FROM check_publications
         WHERE tenant_id = ?1 AND repo_id = ?2 AND state = 0",
    )?;
    let mut refused = conn.prepare_cached(
        "SELECT COUNT(*), MAX(settled_ms) FROM check_publications
         WHERE tenant_id = ?1 AND repo_id = ?2 AND state = 2 AND settled_ms >= ?3",
    )?;
    let mut published = conn.prepare_cached(
        "SELECT MAX(settled_ms) FROM check_publications
         WHERE tenant_id = ?1 AND repo_id = ?2 AND state = 1",
    )?;
    let mut deliveries = conn.prepare_cached(
        "SELECT COUNT(*), MIN(received_ms) FROM webhook_deliveries
         WHERE repo_id = ?1 AND state IN (0, 1)",
    )?;
    let mut out = Vec::with_capacity(repos.len());
    for repo in repos {
        let key = params![tenant.as_bytes(), repo.id.as_bytes()];
        let (pending_n, oldest): (i64, Option<i64>) =
            pending.query_row(key, |r| Ok((r.get(0)?, r.get(1)?)))?;
        let (refused_n, last_refused): (i64, Option<i64>) = refused.query_row(
            params![tenant.as_bytes(), repo.id.as_bytes(), since.0],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        let last_published: Option<i64> = published.query_row(key, |r| r.get(0))?;
        let (open, oldest_delivery): (i64, Option<i64>) =
            deliveries.query_row([repo.id.as_bytes()], |r| Ok((r.get(0)?, r.get(1)?)))?;
        out.push(RepoSync {
            repo: repo.id,
            name: repo.name,
            pending: u64::try_from(pending_n).unwrap_or(0),
            oldest_pending_ms: oldest,
            refused: u64::try_from(refused_n).unwrap_or(0),
            last_refused_ms: last_refused,
            last_published_ms: last_published,
            open_deliveries: u64::try_from(open).unwrap_or(0),
            oldest_delivery_ms: oldest_delivery,
        });
    }
    Ok(out)
}

/// What a worker reported and what is held on it now. Reservations are
/// totals: which tenant's attempts hold a shared worker is not another
/// tenant's business.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkerLoad {
    /// Reported capacity; `disk_bytes` 0 means not reported.
    pub capacity: Capacity,
    /// Capacity left after every reservation on the same host.
    pub free: Capacity,
    /// Attempts this worker holds, and what they reserve.
    pub held_attempts: u64,
    pub held: Capacity,
    pub labels: Vec<String>,
    /// Set while draining: when the drain began.
    pub draining_since: Option<i64>,
    /// Warm cache bytes the worker last reported.
    pub cache_bytes: Option<u64>,
    /// Workers sharing this worker's host (itself included), when the host
    /// is known.
    pub host_workers: Option<u64>,
}

/// [`WorkerLoad`] of one worker. The caller has already authorized the
/// worker's pool ([`crate::workers::in_pool`]).
pub fn worker_load(conn: &Connection, worker: WorkerId) -> Result<WorkerLoad> {
    let row = conn
        .prepare_cached(
            "SELECT cpu_millis, memory_bytes, disk_bytes, labels, drain_ms, cache_bytes,
                CASE WHEN host_id IS NULL THEN NULL
                     ELSE (SELECT COUNT(*) FROM workers h
                           WHERE h.host_id = w.host_id AND h.revoked_ms IS NULL) END
             FROM workers w WHERE id = ?1 AND revoked_ms IS NULL",
        )?
        .query_row([worker.as_bytes()], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, Vec<u8>>(3)?,
                r.get::<_, Option<i64>>(4)?,
                r.get::<_, i64>(5)?,
                r.get::<_, Option<i64>>(6)?,
            ))
        })
        .optional()?
        .ok_or(Error::NotFound)?;
    let (count, cpu, memory, disk): (i64, i64, i64, i64) = conn
        .prepare_cached(
            "SELECT COUNT(*), COALESCE(SUM(cpu_millis), 0), COALESCE(SUM(memory_bytes), 0),
                COALESCE(SUM(disk_bytes), 0)
             FROM attempts WHERE worker_id = ?1 AND released_ms IS NULL",
        )?
        .query_row([worker.as_bytes()], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
        })?;
    let labels = row
        .3
        .split(|b| *b == b'\n')
        .filter(|l| !l.is_empty())
        .map(|l| String::from_utf8_lossy(l).into_owned())
        .collect();
    Ok(WorkerLoad {
        capacity: Capacity {
            cpu_millis: row.0,
            memory_bytes: row.1,
            disk_bytes: row.2,
        },
        free: dispatch::free_capacity(conn, worker)?,
        held_attempts: u64::try_from(count).unwrap_or(0),
        held: Capacity {
            cpu_millis: cpu,
            memory_bytes: memory,
            disk_bytes: disk,
        },
        labels,
        draining_since: row.4,
        // 0 is the column's "never reported", not an empty cache.
        cache_bytes: u64::try_from(row.5).ok().filter(|b| *b > 0),
        host_workers: row.6.and_then(|n| u64::try_from(n).ok()),
    })
}
