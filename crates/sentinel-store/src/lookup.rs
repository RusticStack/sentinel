//! Unauthorized name resolution: "which row does this name mean".
//!
//! Trusted controller internals, like [`crate::auth::provisioning`]: these
//! functions perform no authorization. The host-local administration command
//! uses them freely, because it can already open the database file.
//!
//! A client route may use one only as the first half of an authorization
//! decision taken in the same snapshot, where the second half answers
//! `NotFound` for a denied row exactly as for an absent one (for example
//! `repo_by_name` followed by [`crate::auth::require_repo`]). Nothing a
//! route returns may depend on the lookup alone: a route that would answer
//! differently for "exists but not yours" and "does not exist" must resolve
//! through [`crate::auth`] instead ([`crate::auth::member_tenant_by_slug`],
//! [`crate::auth::narrowing_by_name`]), which checks live membership in the
//! resolving statement.

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

/// The repository a run belongs to.
pub fn run_repo(conn: &Connection, run: sentinel_core::RunId) -> Result<RepoId> {
    let repo: [u8; 16] = conn
        .prepare_cached("SELECT repo_id FROM runs WHERE id = ?1")?
        .query_row([run.as_bytes()], |r| r.get(0))
        .optional()?
        .ok_or(Error::NotFound)?;
    RepoId::from_bytes(repo).map_err(|_| Error::Corrupt("repo_id"))
}

/// The run a job belongs to.
pub fn job_run(conn: &Connection, job: sentinel_core::JobId) -> Result<sentinel_core::RunId> {
    let run: [u8; 16] = conn
        .prepare_cached("SELECT run_id FROM jobs WHERE id = ?1")?
        .query_row([job.as_bytes()], |r| r.get(0))
        .optional()?
        .ok_or(Error::NotFound)?;
    sentinel_core::RunId::from_bytes(run).map_err(|_| Error::Corrupt("run_id"))
}

/// The job an attempt belongs to.
pub fn attempt_job(
    conn: &Connection,
    attempt: sentinel_core::AttemptId,
) -> Result<sentinel_core::JobId> {
    let job: [u8; 16] = conn
        .prepare_cached("SELECT job_id FROM attempts WHERE id = ?1")?
        .query_row([attempt.as_bytes()], |r| r.get(0))
        .optional()?
        .ok_or(Error::NotFound)?;
    sentinel_core::JobId::from_bytes(job).map_err(|_| Error::Corrupt("job_id"))
}

pub fn pool_by_name(conn: &Connection, name: &str) -> Result<sentinel_core::PoolId> {
    let bytes: [u8; 16] = conn
        .prepare_cached("SELECT id FROM pools WHERE name = ?1")?
        .query_row([name], |r| r.get(0))
        .optional()?
        .ok_or(Error::NotFound)?;
    sentinel_core::PoolId::from_bytes(bytes).map_err(|_| Error::Corrupt("pool id"))
}

/// The tenant that owns a repository, whatever the tenant's state: an
/// operator listing intake records must be able to name a suspended tenant.
pub fn repo_tenant(
    conn: &Connection,
    repo: sentinel_core::RepoId,
) -> Result<sentinel_core::TenantId> {
    let tenant: [u8; 16] = conn
        .prepare_cached("SELECT tenant_id FROM repos WHERE id = ?1")?
        .query_row([repo.as_bytes()], |r| r.get(0))
        .optional()?
        .ok_or(Error::NotFound)?;
    sentinel_core::TenantId::from_bytes(tenant).map_err(|_| Error::Corrupt("tenant_id"))
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
