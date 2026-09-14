//! Tenant suspension, revocation propagation and pool grants (A07).
//!
//! Revoking authority is only half a decision; the other half is what happens
//! to the work and the connections that already hold it. This module makes
//! both halves one transaction: suspending a tenant stops intake by flipping
//! the flag every predicate already joins on, revokes the credentials scoped to
//! it, requests cancellation of its live jobs, and bumps the tenant's
//! authorization epoch so anything long-lived re-authorizes.
//!
//! Retained evidence — runs, logs, artifacts — is not touched: suspension is a
//! stop, not a deletion, and later retention policy (Part 13) decides the rest.

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

/// A tenant's current authorization epoch. A subscription records this when it
/// is authorized and re-authorizes when [`epoch`] no longer returns it.
pub fn epoch(conn: &Connection, tenant: TenantId) -> Result<i64> {
    conn.prepare_cached("SELECT authz_epoch FROM tenants WHERE id = ?1")?
        .query_row([tenant.as_bytes()], |r| r.get(0))
        .optional()?
        .ok_or(Error::NotFound)
}

/// Move the epoch forward. Called by every change to who may act in a tenant;
/// `pub(crate)` so `auth`'s membership and grant mutations bump it too.
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

/// What suspension did, so the caller can report it truthfully.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Suspension {
    /// Credentials scoped to the tenant, including every service account's.
    pub tokens_revoked: usize,
    /// Unspent invitations into the tenant.
    pub invitations_revoked: usize,
    /// Jobs that had not started and went straight to `Canceled`.
    pub jobs_canceled: usize,
    /// Jobs a worker owns; cancellation is requested, the worker terminates.
    pub jobs_cancel_requested: usize,
}

/// Suspend a tenant. Platform administration with step-up: it ends service for
/// every member at once.
///
/// Sessions are deployment-wide and are not revoked — a person may belong to
/// other tenants — but nothing they hold reaches this tenant afterwards, since
/// every predicate joins `tenants.active`. Jobs that a worker already owns are
/// asked to stop through the durable cancel flag; the running attempt reports
/// its own terminal state, never faked here.
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

    // Every live job gets the durable cancel flag; the ones nobody owns yet are
    // finished here through the state machine, so the run aggregates honestly.
    let live: Vec<([u8; 16], i64)> = tx
        .prepare_cached("SELECT id, state_code FROM jobs WHERE tenant_id = ?1 AND state_code < ?2")?
        .query_map(params![tenant.as_bytes(), TERMINAL_BASE], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })?
        .collect::<std::result::Result<_, _>>()?;
    tx.execute(
        "UPDATE jobs SET cancel_requested = 1 WHERE tenant_id = ?1 AND state_code < ?2",
        params![tenant.as_bytes(), TERMINAL_BASE],
    )?;
    for (id, state_code) in live {
        let job = JobId::from_bytes(id).map_err(|_| Error::Corrupt("job_id"))?;
        // Blocked (0) and Queued (1) have no owner: cancel them outright.
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

/// Lift a suspension. Nothing revoked comes back: credentials are reissued,
/// canceled jobs are rerun. Only the flag and the epoch change.
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

/// Create an organization namespace. Platform administration; the first
/// tenant of a deployment has to come from somewhere before any route exists,
/// and that somewhere is the host-local operator. Audited, unlike A01's
/// unaudited primitive, which this supersedes for administrative use.
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
    /// Owned by one tenant; no grant needed and none possible.
    Dedicated(TenantId),
    /// Platform-managed; admits only tenants with an explicit grant.
    Shared,
}

/// Register a pool. Platform administration: pools are capacity, and capacity
/// is the platform's to allocate. Worker enrollment into a pool is W01.
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

/// Admit a tenant to a shared pool. Platform administration; the database
/// refuses a grant on a dedicated pool.
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

/// Withdraw a tenant from a shared pool. Jobs already leased on the pool's
/// workers finish or are canceled by their own tenant's policy; new placement
/// stops at once, because [`require_pool_access`] is checked at dispatch.
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

/// Whether this tenant's work may be placed on this pool, right now. One
/// statement: the tenant must be active, the pool active, and the tenant
/// either the pool's owner or explicitly granted. The scheduler (W02) asks
/// this per placement; it is not cached.
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

/// Every pool a tenant may use: its dedicated pools and the shared pools it is
/// granted. Membership of the tenant (or platform administration) is required
/// to look; the pools of a tenant are part of its capacity, not public.
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
