//! Service-account grants (O06): a tenant administrator issues a bounded,
//! scoped refresh-token grant to a service principal of that tenant.
//!
//! A service grant is an ordinary grant row of kind 3 for the first-party
//! CLI client, narrowed to the principal's home tenant (and optionally one
//! repository of it), named by the administrator, and bounded to
//! [`SERVICE_MIN_MS`]..=[`SERVICE_MAX_MS`]. Issuance writes the grant and
//! one refresh token (generation 1, whose idle expiry is the grant's); no
//! access token is minted, since the holder refreshes first. The refresh
//! token is returned once and only its digest is stored. `tenant:admin` and
//! `platform:admin` are never issued to a service principal; the insert
//! trigger refuses them too.
//!
//! Revocation goes through [`super::revoke_grant`], which already admits the
//! owner, a platform administrator, or an administrator of the service
//! principal's home tenant.

use rusqlite::{Connection, Transaction, params};
use sentinel_auth::secret::Secret;
use sentinel_core::{
    GrantId, RepoId, TenantId, UnixMillis, UserId,
    auth::{Audience, Permissions, Principal, Scopes},
};
use sentinel_protocol::oauth::CLI_CLIENT_ID;

use super::{
    GRANT_COLUMNS, GrantKind, GrantRecord, NewGrant, SERVICE_MAX_MS, SERVICE_MIN_MS, grant_record,
    insert_grant, raw_grant,
};
use crate::{
    Error, Result,
    auth::require_tenant_admin,
    local_auth::{Event, audit},
};

/// Scopes a service principal can never hold.
const ADMIN_SCOPES: Scopes = Scopes::TENANT_ADMIN.union(Scopes::PLATFORM_ADMIN);

/// At most this many grants are listed per service principal.
const LIST_LIMIT: i64 = 100;

/// `NotFound` unless `account` is an active service principal of `tenant`.
fn require_account(conn: &Connection, tenant: TenantId, account: UserId) -> Result<()> {
    let found: bool = conn
        .prepare_cached(
            "SELECT EXISTS(SELECT 1 FROM users
             WHERE id = ?1 AND kind = 1 AND service_tenant_id = ?2 AND active = 1)",
        )?
        .query_row(params![account.as_bytes(), tenant.as_bytes()], |r| r.get(0))?;
    if found { Ok(()) } else { Err(Error::NotFound) }
}

/// Issue a service grant; returns its handle, the refresh token (shown
/// once) and the grant's absolute expiry.
///
/// `Forbidden`: `principal` does not administer `tenant` (a platform
/// administrator does). `NotFound`: `account` is not an active service
/// principal of `tenant`, or `repo` is not a repository of it.
/// `InvalidInput`: empty scopes or an administrative scope, a lifetime
/// outside [`SERVICE_MIN_MS`]..=[`SERVICE_MAX_MS`], or a bad name.
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
    require_tenant_admin(tx, principal, tenant)?;
    if scopes.is_empty() || !scopes.intersect(ADMIN_SCOPES).is_empty() {
        return Err(Error::InvalidInput("scope"));
    }
    if !(SERVICE_MIN_MS..=SERVICE_MAX_MS).contains(&lifetime_ms) {
        return Err(Error::InvalidInput("grant lifetime"));
    }
    require_account(tx, tenant, account)?;
    if let Some(repo) = repo {
        let owned: bool = tx
            .prepare_cached("SELECT EXISTS(SELECT 1 FROM repos WHERE id = ?1 AND tenant_id = ?2)")?
            .query_row(params![repo.as_bytes(), tenant.as_bytes()], |r| r.get(0))?;
        if !owned {
            return Err(Error::NotFound);
        }
    }
    let grant = insert_grant(
        tx,
        &NewGrant {
            user: account,
            client_id: CLI_CLIENT_ID,
            kind: GrantKind::Service,
            scopes,
            tenant: Some(tenant),
            repo,
            audience: Audience::Api,
            name: Some(name),
            lifetime_ms,
            created_by: Some(principal.user),
        },
        now,
    )?;
    let expires = now.0.saturating_add(lifetime_ms);
    let refresh = Secret::generate();
    tx.prepare_cached(
        "INSERT INTO oauth_refresh_tokens(token_digest, grant_id, generation, parent,
            created_ms, idle_expires_ms) VALUES (?1, ?2, 1, NULL, ?3, ?4)",
    )?
    .execute(params![
        refresh.digest().0,
        grant.as_bytes(),
        now.0,
        expires
    ])?;
    audit(
        tx,
        Event::ServiceGrantIssued,
        Some(principal.user),
        Some(account),
        false,
        None,
    )?;
    Ok((grant, refresh, UnixMillis(expires)))
}

/// A service principal's grants as metadata (never a token or a digest),
/// newest first, at most 100, revoked ones included. `Forbidden` unless
/// `principal` administers `tenant`; `NotFound` unless `account` is a
/// service principal of it.
pub fn service_grants(
    conn: &Connection,
    principal: Principal,
    tenant: TenantId,
    account: UserId,
) -> Result<Vec<GrantRecord>> {
    require_tenant_admin(conn, principal, tenant)?;
    let service: bool = conn
        .prepare_cached(
            "SELECT EXISTS(SELECT 1 FROM users WHERE id = ?1 AND kind = 1 AND service_tenant_id = ?2)",
        )?
        .query_row(params![account.as_bytes(), tenant.as_bytes()], |r| r.get(0))?;
    if !service {
        return Err(Error::NotFound);
    }
    let mut stmt = conn.prepare_cached(&format!(
        "SELECT {GRANT_COLUMNS} FROM oauth_grants WHERE user_id = ?1
         ORDER BY created_ms DESC, id LIMIT ?2"
    ))?;
    let rows = stmt.query_map(params![account.as_bytes(), LIST_LIMIT], raw_grant)?;
    rows.map(|row| grant_record(row?)).collect()
}

/// Allow (or, with `Permissions::NONE`, withdraw) a service principal of
/// `tenant` repository actions on a repository of the same tenant.
/// `Forbidden`: `principal` does not administer `tenant`. `NotFound`: the
/// account is not a service principal of `tenant`, or the repository is
/// not one of its repositories.
pub fn allow_repo(
    tx: &Transaction<'_>,
    principal: Principal,
    tenant: TenantId,
    account: UserId,
    repo: RepoId,
    permissions: Permissions,
) -> Result<()> {
    require_tenant_admin(tx, principal, tenant)?;
    require_account(tx, tenant, account)?;
    let owned: bool = tx
        .prepare_cached("SELECT EXISTS(SELECT 1 FROM repos WHERE id = ?1 AND tenant_id = ?2)")?
        .query_row(params![repo.as_bytes(), tenant.as_bytes()], |r| r.get(0))?;
    if !owned {
        return Err(Error::NotFound);
    }
    crate::auth::set_repo_grant(tx, principal, repo, account, permissions)
}

#[cfg(test)]
mod tests {
    use rusqlite::Connection;

    /// Listing a service principal's grants walks its index, newest first.
    #[test]
    fn listing_is_an_index_walk() {
        let mut conn = Connection::open_in_memory().unwrap();
        crate::migrate(&mut conn).unwrap();
        let sql = format!(
            "EXPLAIN QUERY PLAN SELECT {} FROM oauth_grants WHERE user_id = ?1
             ORDER BY created_ms DESC, id LIMIT ?2",
            super::GRANT_COLUMNS
        );
        let mut stmt = conn.prepare(&sql).unwrap();
        let values = vec![rusqlite::types::Value::Null; stmt.parameter_count()];
        let plans: Vec<String> = stmt
            .query_map(rusqlite::params_from_iter(values), |r| r.get(3))
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        assert!(plans.iter().all(|p| !p.starts_with("SCAN ")), "{plans:?}");
    }
}
