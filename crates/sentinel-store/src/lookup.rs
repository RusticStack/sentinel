//! Host-local name resolution for the administration command.
//!
//! Trusted controller internals, like [`crate::auth::provisioning`]: these
//! functions answer "which row does this operator-typed name mean" and perform
//! no authorization. Their only caller is a process that can already open the
//! database file. No route may expose them — an authorized client resolves
//! names through [`crate::auth`], which checks live membership.

use rusqlite::{Connection, OptionalExtension, params};
use sentinel_core::{RepoId, TenantId, UserId};

use crate::{Error, Result};

/// The account behind a local login name, whatever its status: an operator
/// approving or rejecting an application names it the same way.
pub fn user_by_username(conn: &Connection, username: &str) -> Result<UserId> {
    let bytes: [u8; 16] = conn
        .prepare_cached("SELECT user_id FROM local_credentials WHERE username = ?1")?
        .query_row([username], |r| r.get(0))
        .optional()?
        .ok_or(Error::NotFound)?;
    UserId::from_bytes(bytes).map_err(|_| Error::Corrupt("user_id"))
}

/// Confirm that an account exists and is active, without revealing anything else.
pub fn active_user(conn: &Connection, user: UserId) -> Result<()> {
    exists(conn, user, "active = 1")
}

/// Confirm that an account exists at all, whatever its status. Pending and
/// rejected accounts are exactly the ones an operator needs to name.
pub fn known_user(conn: &Connection, user: UserId) -> Result<()> {
    exists(conn, user, "1 = 1")
}

fn exists(conn: &Connection, user: UserId, predicate: &str) -> Result<()> {
    let found: bool = conn
        .prepare_cached(&format!(
            "SELECT EXISTS(SELECT 1 FROM users WHERE id = ?1 AND {predicate})"
        ))?
        .query_row([user.as_bytes()], |r| r.get(0))?;
    if found { Ok(()) } else { Err(Error::NotFound) }
}

/// The active namespace with this canonical slug.
pub fn tenant_by_slug(conn: &Connection, slug: &str) -> Result<TenantId> {
    let bytes: [u8; 16] = conn
        .prepare_cached("SELECT id FROM tenants WHERE slug = ?1 AND active = 1")?
        .query_row([slug], |r| r.get(0))
        .optional()?
        .ok_or(Error::NotFound)?;
    TenantId::from_bytes(bytes).map_err(|_| Error::Corrupt("tenant_id"))
}

/// A namespace by slug whatever its state: an operator lifting a suspension
/// must be able to name a suspended tenant.
pub fn tenant_by_slug_any(conn: &Connection, slug: &str) -> Result<TenantId> {
    let bytes: [u8; 16] = conn
        .prepare_cached("SELECT id FROM tenants WHERE slug = ?1")?
        .query_row([slug], |r| r.get(0))
        .optional()?
        .ok_or(Error::NotFound)?;
    TenantId::from_bytes(bytes).map_err(|_| Error::Corrupt("tenant_id"))
}

/// A pool by its unique name.
/// The tenant a job belongs to, for host-local commands that name a job.
pub fn job_tenant(conn: &Connection, job: sentinel_core::JobId) -> Result<sentinel_core::TenantId> {
    let tenant: [u8; 16] = conn
        .prepare_cached("SELECT tenant_id FROM jobs WHERE id = ?1")?
        .query_row([job.as_bytes()], |r| r.get(0))
        .optional()?
        .ok_or(Error::NotFound)?;
    sentinel_core::TenantId::from_bytes(tenant).map_err(|_| Error::Corrupt("tenant_id"))
}

/// The tenant a run belongs to.
pub fn run_tenant(conn: &Connection, run: sentinel_core::RunId) -> Result<sentinel_core::TenantId> {
    let tenant: [u8; 16] = conn
        .prepare_cached("SELECT tenant_id FROM runs WHERE id = ?1")?
        .query_row([run.as_bytes()], |r| r.get(0))
        .optional()?
        .ok_or(Error::NotFound)?;
    sentinel_core::TenantId::from_bytes(tenant).map_err(|_| Error::Corrupt("tenant_id"))
}

pub fn pool_by_name(conn: &Connection, name: &str) -> Result<sentinel_core::PoolId> {
    let bytes: [u8; 16] = conn
        .prepare_cached("SELECT id FROM pools WHERE name = ?1")?
        .query_row([name], |r| r.get(0))
        .optional()?
        .ok_or(Error::NotFound)?;
    sentinel_core::PoolId::from_bytes(bytes).map_err(|_| Error::Corrupt("pool id"))
}

/// A repository by name inside one tenant; the pair is the unique key.
pub fn repo_by_name(conn: &Connection, tenant: TenantId, name: &str) -> Result<RepoId> {
    let bytes: [u8; 16] = conn
        .prepare_cached("SELECT id FROM repos WHERE tenant_id = ?1 AND name = ?2")?
        .query_row(params![tenant.as_bytes(), name], |r| r.get(0))
        .optional()?
        .ok_or(Error::NotFound)?;
    RepoId::from_bytes(bytes).map_err(|_| Error::Corrupt("repo_id"))
}
