//! Service-account grants (O06): a tenant administrator issues a bounded,
//! scoped refresh-token grant to a service principal of that tenant.
//!
//! Stub: the signatures are the contract; Unit C implements the bodies.

use rusqlite::{Connection, Transaction};
use sentinel_auth::secret::Secret;
use sentinel_core::{
    GrantId, RepoId, TenantId, UnixMillis, UserId,
    auth::{Principal, Scopes},
};

use super::GrantRecord;
use crate::{Error, Result};

/// Issue a service grant; returns its handle, the refresh token (shown
/// once) and the grant's absolute expiry.
#[allow(clippy::too_many_arguments)]
pub fn issue_service_grant(
    tx: &Transaction<'_>,
    principal: Principal,
    tenant: TenantId,
    account: UserId,
    name: &str,
    scopes: Scopes,
    repo: Option<RepoId>,
    lifetime_ms: i64,
    now: UnixMillis,
) -> Result<(GrantId, Secret, UnixMillis)> {
    let _ = (
        tx,
        principal,
        tenant,
        account,
        name,
        scopes,
        repo,
        lifetime_ms,
        now,
    );
    Err(Error::InvalidInput("not implemented"))
}

/// A service principal's grants as metadata.
pub fn service_grants(
    conn: &Connection,
    principal: Principal,
    tenant: TenantId,
    account: UserId,
) -> Result<Vec<GrantRecord>> {
    let _ = (conn, principal, tenant, account);
    Err(Error::InvalidInput("not implemented"))
}
