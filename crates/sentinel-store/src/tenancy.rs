//! Suspension stops work but never deletes retained evidence: runs, logs and artifacts stay.

use rusqlite::{Connection, OptionalExtension, Transaction, params};
use sentinel_core::{
    Actor, Event as JobEvent, JobId, PoolId, TenantId, UnixMillis, UserId, auth::Namespace,
};

use crate::{
    Error, Result,
    auth::Authority,
    codec::TERMINAL_BASE,
    local_auth::{Event, audit},
};

pub fn epoch(conn: &Connection, tenant: TenantId) -> Result<i64> {
    conn.prepare_cached("SELECT authz_epoch FROM tenants WHERE id = ?1")?
        .query_row([tenant.as_bytes()], |r| r.get(0))
        .optional()?
        .ok_or(Error::NotFound)
}

pub(crate) fn bump_epoch(tx: &Transaction<'_>, tenant: TenantId) -> Result<()> {
    let changed = tx.execute(
        "UPDATE tenants SET authz_epoch = authz_epoch + 1 WHERE id = ?1",
        [tenant.as_bytes()],
    )?;
    if changed == 0 {
        return Err(Error::NotFound);
    }
    Ok(())
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Suspension {
    pub tokens_revoked: usize,
    pub invitations_revoked: usize,
    pub jobs_canceled: usize,
    pub jobs_cancel_requested: usize,
}

// Sessions survive suspension (people can belong to other tenants), but every predicate joins `tenants.active`.
pub fn suspend(
    tx: &Transaction<'_>,
    authority: Authority,
    tenant: TenantId,
    now: UnixMillis,
) -> Result<Suspension> {
    authority.require_privileged(tx)?;
    let changed = tx.execute(
        "UPDATE tenants SET active = 0 WHERE id = ?1 AND active = 1",
        [tenant.as_bytes()],
    )?;
    if changed == 0 {
        return Err(Error::NotFound);
    }
    bump_epoch(tx, tenant)?;
    let mut done = Suspension {
        tokens_revoked: tx.execute(
            "UPDATE api_tokens SET revoked_ms = ?2 WHERE tenant_id = ?1 AND revoked_ms IS NULL",
            params![tenant.as_bytes(), now.0],
        )?,
        invitations_revoked: tx.execute(
            "UPDATE invitations SET revoked_ms = ?2 WHERE tenant_id = ?1
             AND revoked_ms IS NULL AND redeemed_ms IS NULL",
            params![tenant.as_bytes(), now.0],
        )?,
        ..Suspension::default()
    };
    done.tokens_revoked += crate::oauth::revoke_for_tenant(tx, tenant, now)?;

    let live: Vec<([u8; 16], i64)> = tx
        .prepare_cached("SELECT id, state_code FROM jobs WHERE tenant_id = ?1 AND state_code < ?2")?
        .query_map(params![tenant.as_bytes(), TERMINAL_BASE], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })?
        .collect::<std::result::Result<_, _>>()?;
    tx.execute(
        "UPDATE runs SET cancel_requested = 1 WHERE tenant_id = ?1 AND id IN (
            SELECT run_id FROM jobs WHERE tenant_id = ?1 AND state_code < ?2)",
        params![tenant.as_bytes(), TERMINAL_BASE],
    )?;
    tx.execute(
        "UPDATE jobs SET cancel_requested = 1 WHERE tenant_id = ?1 AND state_code < ?2",
        params![tenant.as_bytes(), TERMINAL_BASE],
    )?;
    for (id, state_code) in live {
        let job = JobId::from_bytes(id).map_err(|_| Error::Corrupt("job_id"))?;
        if state_code <= crate::codec::READY {
            crate::jobs::transition(
                tx,
                tenant,
                job,
                Actor::Controller,
                JobEvent::CancelBeforeStart,
                now,
            )?;
            done.jobs_canceled += 1;
        } else {
            done.jobs_cancel_requested += 1;
        }
    }
    let detail = format!(
        "tokens={} invitations={} canceled={} requested={}",
        done.tokens_revoked,
        done.invitations_revoked,
        done.jobs_canceled,
        done.jobs_cancel_requested
    );
    audit(
        tx,
        Event::TenantSuspended,
        authority.actor(),
        None,
        authority.host_local(),
        Some(&detail),
    )?;
    Ok(done)
}

pub fn reactivate(
    tx: &Transaction<'_>,
    authority: Authority,
    tenant: TenantId,
    now: UnixMillis,
) -> Result<()> {
    let _ = now;
    authority.require_privileged(tx)?;
    let changed = tx.execute(
        "UPDATE tenants SET active = 1 WHERE id = ?1 AND active = 0",
        [tenant.as_bytes()],
    )?;
    if changed == 0 {
        return Err(Error::NotFound);
    }
    bump_epoch(tx, tenant)?;
    audit(
        tx,
        Event::TenantReactivated,
        authority.actor(),
        None,
        authority.host_local(),
        None,
    )
}

pub fn create_organization(
    tx: &Transaction<'_>,
    authority: Authority,
    tenant: TenantId,
    slug: Namespace<'_>,
    now: UnixMillis,
) -> Result<()> {
    authority.require_platform(tx)?;
    crate::auth::insert_namespace(
        tx,
        tenant,
        slug,
        crate::auth::NamespaceKind::Organization,
        now,
    )?;
    audit(
        tx,
        Event::NamespaceCreated,
        authority.actor(),
        None,
        authority.host_local(),
        Some(slug.as_str()),
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PoolKind {
    Dedicated(TenantId),
    Shared,
}

pub fn create_pool(
    tx: &Transaction<'_>,
    authority: Authority,
    pool: PoolId,
    name: &str,
    kind: PoolKind,
    now: UnixMillis,
) -> Result<()> {
    authority.require_platform(tx)?;
    if name.is_empty()
        || name.len() > 64
        || !name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return Err(Error::InvalidInput("pool name"));
    }
    let (code, owner) = match kind {
        PoolKind::Dedicated(tenant) => (0, Some(tenant)),
        PoolKind::Shared => (1, None),
    };
    tx.execute(
        "INSERT INTO pools(id, name, kind, owner_tenant_id, created_ms) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            pool.as_bytes(),
            name,
            code,
            owner.as_ref().map(TenantId::as_bytes),
            now.0
        ],
    )?;
    audit(
        tx,
        Event::PoolCreated,
        authority.actor(),
        None,
        authority.host_local(),
        Some(name),
    )
}

pub fn grant_pool(
    tx: &Transaction<'_>,
    authority: Authority,
    pool: PoolId,
    tenant: TenantId,
    now: UnixMillis,
) -> Result<()> {
    authority.require_platform(tx)?;
    tx.execute(
        "INSERT INTO pool_grants(pool_id, tenant_id, granted_by, granted_ms) VALUES (?1, ?2, ?3, ?4)",
        params![
            pool.as_bytes(),
            tenant.as_bytes(),
            authority.actor().as_ref().map(UserId::as_bytes),
            now.0
        ],
    )?;
    bump_epoch(tx, tenant)?;
    audit(
        tx,
        Event::PoolGranted,
        authority.actor(),
        None,
        authority.host_local(),
        None,
    )
}

pub fn revoke_pool_grant(
    tx: &Transaction<'_>,
    authority: Authority,
    pool: PoolId,
    tenant: TenantId,
    now: UnixMillis,
) -> Result<()> {
    let _ = now;
    authority.require_platform(tx)?;
    let removed = tx.execute(
        "DELETE FROM pool_grants WHERE pool_id = ?1 AND tenant_id = ?2",
        params![pool.as_bytes(), tenant.as_bytes()],
    )?;
    if removed == 0 {
        return Err(Error::NotFound);
    }
    bump_epoch(tx, tenant)?;
    audit(
        tx,
        Event::PoolGrantRevoked,
        authority.actor(),
        None,
        authority.host_local(),
        None,
    )
}

// Checked per placement and never cached, so a revoked grant stops placement at once.
pub fn require_pool_access(conn: &Connection, tenant: TenantId, pool: PoolId) -> Result<()> {
    let allowed: bool = conn
        .prepare_cached(
            "SELECT EXISTS(
                SELECT 1 FROM pools p JOIN tenants t ON t.id = ?2
                LEFT JOIN pool_grants g ON g.pool_id = p.id AND g.tenant_id = t.id
                WHERE p.id = ?1 AND p.active = 1 AND t.active = 1
                AND (p.owner_tenant_id = t.id OR g.tenant_id IS NOT NULL))",
        )?
        .query_row(params![pool.as_bytes(), tenant.as_bytes()], |r| r.get(0))?;
    if allowed {
        Ok(())
    } else {
        Err(Error::Forbidden)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct PoolRecord {
    pub id: PoolId,
    pub name: String,
    pub kind: PoolKind,
    pub active: bool,
}

pub fn pools_for_tenant(
    conn: &Connection,
    authority: Authority,
    tenant: TenantId,
) -> Result<Vec<PoolRecord>> {
    if authority.require_platform(conn).is_err() {
        let principal = authority.principal().ok_or(Error::NotFound)?;
        crate::auth::get_namespace_by_id(conn, principal, tenant).map_err(|_| Error::NotFound)?;
    }
    let mut stmt = conn.prepare_cached(
        "SELECT p.id, p.name, p.kind, p.owner_tenant_id, p.active FROM pools p
         LEFT JOIN pool_grants g ON g.pool_id = p.id AND g.tenant_id = ?1
         WHERE p.owner_tenant_id = ?1 OR g.tenant_id IS NOT NULL
         ORDER BY p.name",
    )?;
    let rows = stmt.query_map([tenant.as_bytes()], |r| {
        Ok((
            r.get::<_, [u8; 16]>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, i64>(2)?,
            r.get::<_, Option<[u8; 16]>>(3)?,
            r.get::<_, bool>(4)?,
        ))
    })?;
    rows.map(|row| {
        let row = row?;
        Ok(PoolRecord {
            id: PoolId::from_bytes(row.0).map_err(|_| Error::Corrupt("pool id"))?,
            name: row.1,
            kind: match (row.2, row.3) {
                (0, Some(owner)) => PoolKind::Dedicated(
                    TenantId::from_bytes(owner).map_err(|_| Error::Corrupt("tenant_id"))?,
                ),
                (1, None) => PoolKind::Shared,
                _ => return Err(Error::Corrupt("pools.kind")),
            },
            active: row.4,
        })
    })
    .collect()
}
