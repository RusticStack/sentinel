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

/// The account behind a local login name.
pub fn user_by_username(conn: &Connection, username: &str) -> Result<UserId> {
    let bytes: [u8; 16] = conn
        .prepare_cached(
            "SELECT c.user_id FROM local_credentials c JOIN users u ON u.id = c.user_id
             WHERE c.username = ?1 AND u.active = 1",
        )?
        .query_row([username], |r| r.get(0))
        .optional()?
        .ok_or(Error::NotFound)?;
    UserId::from_bytes(bytes).map_err(|_| Error::Corrupt("user_id"))
}

/// Confirm that an account exists and is active, without revealing anything else.
pub fn active_user(conn: &Connection, user: UserId) -> Result<()> {
    let active: bool = conn
        .prepare_cached("SELECT EXISTS(SELECT 1 FROM users WHERE id = ?1 AND active = 1)")?
        .query_row([user.as_bytes()], |r| r.get(0))?;
    if active { Ok(()) } else { Err(Error::NotFound) }
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

/// A repository by name inside one tenant; the pair is the unique key.
pub fn repo_by_name(conn: &Connection, tenant: TenantId, name: &str) -> Result<RepoId> {
    let bytes: [u8; 16] = conn
        .prepare_cached("SELECT id FROM repos WHERE tenant_id = ?1 AND name = ?2")?
        .query_row(params![tenant.as_bytes(), name], |r| r.get(0))
        .optional()?
        .ok_or(Error::NotFound)?;
    RepoId::from_bytes(bytes).map_err(|_| Error::Corrupt("repo_id"))
}
