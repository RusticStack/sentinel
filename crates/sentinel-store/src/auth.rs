//! Live identity and repository authorization. Use these operations at client
//! boundaries; `jobs`/`runs` and raw SQL remain trusted controller primitives.
//! Mutations check authority inside the SAME writer transaction as the change.
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use sentinel_core::{
    RepoId, TenantId, UnixMillis, UserId,
    auth::{Namespace, Permissions, Principal, Role},
};

use crate::{Error, Result};

/// Static predicate shared by get/list/require. Every lookup starts from the
/// actual repo owner and intersects credential scope, active identities,
/// membership ceiling and repo grant. Super-admin is deliberately absent.
macro_rules! repo_query {
    ($projection:literal, $tail:literal) => {
        repo_query!($projection, "", $tail)
    };
    ($projection:literal, $join:literal, $tail:literal) => {
        concat!("SELECT ", $projection, " FROM repos r
            JOIN tenants t ON t.id = r.tenant_id
            JOIN users u ON u.id = ?1
            JOIN memberships m ON m.tenant_id = r.tenant_id AND m.user_id = u.id
            LEFT JOIN repo_grants g ON g.tenant_id = r.tenant_id AND g.user_id = u.id AND g.repo_id = r.id ", $join, "
            WHERE u.active = 1 AND t.active = 1
            AND (u.kind = 0 OR u.service_tenant_id = r.tenant_id)
            AND (?3 IS NULL OR r.tenant_id = ?3) AND (?4 IS NULL OR r.id = ?4)
            AND ((m.role = 3 AND u.kind = 0) OR
                (m.role IN (1, 2) AND (g.permissions & ?2) = ?2 AND (m.role = 2 OR (?2 & 2) = 0))) ", $tail)
    };
}

fn repo_scope(principal: Principal, required: Permissions) -> Result<()> {
    if required == Permissions::NONE
        || !Permissions::REPOSITORY.contains(required)
        || !principal.permissions.contains(required)
    {
        return Err(Error::NotFound);
    }
    Ok(())
}

/// No bearer capability is returned: this is a decision for the current
/// transaction/snapshot only. Do not retain it across a mutation boundary.
pub fn require_repo(
    conn: &Connection,
    principal: Principal,
    repo: RepoId,
    required: Permissions,
) -> Result<TenantId> {
    repo_scope(principal, required)?;
    let bytes = conn
        .prepare_cached(repo_query!("r.tenant_id", "AND r.id = ?5"))?
        .query_row(
            params![
                principal.user.as_bytes(),
                required.bits(),
                principal.tenant.as_ref().map(TenantId::as_bytes),
                principal.repo.as_ref().map(RepoId::as_bytes),
                repo.as_bytes()
            ],
            |row| row.get::<_, [u8; 16]>(0),
        )
        .optional()?
        .ok_or(Error::NotFound)?;
    TenantId::from_bytes(bytes).map_err(|_| Error::Corrupt("tenant_id"))
}

/// Client dispatch entry point: derive the tenant from the authorized repository
/// in this writer transaction. A client cannot supply a different run owner.
pub fn create_run(
    tx: &Transaction<'_>,
    principal: Principal,
    repo: RepoId,
    run: sentinel_core::RunId,
    spec: &sentinel_pipeline::run::RunSpec,
    now: UnixMillis,
) -> Result<Vec<sentinel_core::JobId>> {
    let tenant = require_repo(tx, principal, repo, Permissions::RUN)?;
    crate::runs::create_run(tx, tenant, repo, run, spec, now)
}

/// Check access and load the immutable blob in ONE read snapshot/query, joining
/// run -> repository ownership rather than accepting a tenant from the caller.
pub fn get_run_spec(
    conn: &Connection,
    principal: Principal,
    run: sentinel_core::RunId,
) -> Result<sentinel_pipeline::run::RunSpec> {
    repo_scope(principal, Permissions::READ)?;
    let (format, bytes) = conn
        .prepare_cached(repo_query!(
            "s.format, s.spec",
            "JOIN runs x ON x.repo_id = r.id AND x.tenant_id = r.tenant_id
         JOIN run_specs s ON s.run_id = x.id AND s.tenant_id = x.tenant_id",
            "AND x.id = ?5"
        ))?
        .query_row(
            params![
                principal.user.as_bytes(),
                Permissions::READ.bits(),
                principal.tenant.as_ref().map(TenantId::as_bytes),
                principal.repo.as_ref().map(RepoId::as_bytes),
                run.as_bytes()
            ],
            |r| Ok((r.get::<_, i64>(0)?, r.get::<_, Vec<u8>>(1)?)),
        )
        .optional()?
        .ok_or(Error::NotFound)?;
    if format != sentinel_pipeline::run::SPEC_FORMAT as i64 {
        return Err(Error::Corrupt("run_specs.format"));
    }
    sentinel_pipeline::run::RunSpec::decode(&bytes).map_err(|_| Error::Corrupt("run_specs.spec"))
}

#[derive(Debug, PartialEq, Eq)]
pub struct Repository {
    pub id: RepoId,
    pub tenant: TenantId,
    pub name: String,
}

fn repository(row: &rusqlite::Row<'_>) -> rusqlite::Result<([u8; 16], [u8; 16], String)> {
    Ok((row.get(0)?, row.get(1)?, row.get(2)?))
}
fn decode_repo((id, tenant, name): ([u8; 16], [u8; 16], String)) -> Result<Repository> {
    Ok(Repository {
        id: RepoId::from_bytes(id).map_err(|_| Error::Corrupt("repo_id"))?,
        tenant: TenantId::from_bytes(tenant).map_err(|_| Error::Corrupt("tenant_id"))?,
        name,
    })
}

pub fn get_repo(conn: &Connection, principal: Principal, repo: RepoId) -> Result<Repository> {
    repo_scope(principal, Permissions::READ)?;
    let row = conn
        .prepare_cached(repo_query!("r.id, r.tenant_id, r.name", "AND r.id = ?5"))?
        .query_row(
            params![
                principal.user.as_bytes(),
                Permissions::READ.bits(),
                principal.tenant.as_ref().map(TenantId::as_bytes),
                principal.repo.as_ref().map(RepoId::as_bytes),
                repo.as_bytes()
            ],
            repository,
        )
        .optional()?
        .ok_or(Error::NotFound)?;
    decode_repo(row)
}

/// Keyset pagination; tenant and `after` are filters, never authority. Changing
/// either cannot expose a row without the live predicate. At most 100 records.
pub fn list_repos(
    conn: &Connection,
    principal: Principal,
    tenant: TenantId,
    after: Option<RepoId>,
    limit: u16,
) -> Result<Vec<Repository>> {
    if !(1..=100).contains(&limit) {
        return Err(Error::InvalidInput("page size"));
    }
    if repo_scope(principal, Permissions::READ).is_err() {
        return Ok(Vec::new());
    }
    let mut stmt = conn.prepare_cached(repo_query!(
        "r.id, r.tenant_id, r.name",
        "AND r.tenant_id = ?5 AND r.id > ?6 ORDER BY r.id LIMIT ?7"
    ))?;
    let rows = stmt.query_map(
        params![
            principal.user.as_bytes(),
            Permissions::READ.bits(),
            principal.tenant.as_ref().map(TenantId::as_bytes),
            principal.repo.as_ref().map(RepoId::as_bytes),
            tenant.as_bytes(),
            after.as_ref().map_or(&[0; 16], RepoId::as_bytes),
            limit
        ],
        repository,
    )?;
    rows.map(|r| decode_repo(r?)).collect()
}

pub fn require_platform_admin(conn: &Connection, principal: Principal) -> Result<()> {
    if !principal.permissions.contains(Permissions::PLATFORM_ADMIN)
        || principal.tenant.is_some()
        || principal.repo.is_some()
    {
        return Err(Error::Forbidden);
    }
    let allowed: bool = conn.prepare_cached("SELECT EXISTS(SELECT 1 FROM users WHERE id = ?1 AND kind = 0 AND active = 1 AND super_admin = 1)")?
        .query_row([principal.user.as_bytes()], |r| r.get(0))?;
    if allowed {
        Ok(())
    } else {
        Err(Error::Forbidden)
    }
}

pub fn require_tenant_admin(
    conn: &Connection,
    principal: Principal,
    tenant: TenantId,
) -> Result<()> {
    if !principal.permissions.contains(Permissions::TENANT_ADMIN)
        || principal.repo.is_some()
        || principal.tenant.is_some_and(|id| id != tenant)
    {
        return Err(Error::Forbidden);
    }
    let allowed: bool = conn
        .prepare_cached(
            "SELECT EXISTS(
        SELECT 1 FROM users u JOIN tenants t ON t.id = ?2
        LEFT JOIN memberships m ON m.tenant_id = t.id AND m.user_id = u.id
        WHERE u.id = ?1 AND u.kind = 0 AND u.active = 1 AND t.active = 1
        AND (m.role = 3 OR (u.super_admin = 1 AND ?3)))",
        )?
        .query_row(
            params![
                principal.user.as_bytes(),
                tenant.as_bytes(),
                principal.permissions.contains(Permissions::PLATFORM_ADMIN)
            ],
            |r| r.get(0),
        )?;
    if allowed {
        Ok(())
    } else {
        Err(Error::Forbidden)
    }
}

#[derive(Clone, Copy, Debug)]
pub enum NamespaceKind {
    Organization,
    Personal(UserId),
}

/// Tenant creation is platform admission, not a side effect of sign-in. A
/// personal owner receives its required admin membership atomically.
pub fn create_namespace(
    tx: &Transaction<'_>,
    principal: Principal,
    tenant: TenantId,
    slug: Namespace<'_>,
    kind: NamespaceKind,
    now: UnixMillis,
) -> Result<()> {
    require_platform_admin(tx, principal)?;
    let (code, owner) = match kind {
        NamespaceKind::Organization => (0, None),
        NamespaceKind::Personal(id) => (1, Some(id)),
    };
    tx.execute("INSERT INTO tenants(id, slug, created_ms, kind, owner_user_id) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![tenant.as_bytes(), slug.as_str(), now.0, code, owner.as_ref().map(UserId::as_bytes)])?;
    if let Some(owner) = owner {
        tx.execute(
            "INSERT INTO memberships(tenant_id, user_id, role) VALUES (?1, ?2, 3)",
            params![tenant.as_bytes(), owner.as_bytes()],
        )?;
    }
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
pub struct TenantNamespace {
    pub id: TenantId,
    pub slug: String,
    pub personal: bool,
}

/// Namespace resolution itself requires membership (or explicitly scoped
/// platform administration); an installation/slug never admits a caller.
pub fn get_namespace(
    conn: &Connection,
    principal: Principal,
    slug: Namespace<'_>,
) -> Result<TenantNamespace> {
    if principal.repo.is_some() || principal.permissions == Permissions::NONE {
        return Err(Error::NotFound);
    }
    let row = conn
        .prepare_cached(
            "SELECT t.id, t.slug, t.kind FROM tenants t JOIN users u ON u.id = ?1
        LEFT JOIN memberships m ON m.tenant_id = t.id AND m.user_id = u.id
        WHERE t.slug = ?2 AND t.active = 1 AND u.active = 1
        AND (?3 IS NULL OR t.id = ?3) AND (u.kind = 0 OR u.service_tenant_id = t.id)
        AND (m.user_id IS NOT NULL OR (u.kind = 0 AND u.super_admin = 1 AND ?4))",
        )?
        .query_row(
            params![
                principal.user.as_bytes(),
                slug.as_str(),
                principal.tenant.as_ref().map(TenantId::as_bytes),
                principal.permissions.contains(Permissions::PLATFORM_ADMIN)
            ],
            |r| Ok((r.get::<_, [u8; 16]>(0)?, r.get(1)?, r.get::<_, i64>(2)?)),
        )
        .optional()?
        .ok_or(Error::NotFound)?;
    Ok(TenantNamespace {
        id: TenantId::from_bytes(row.0).map_err(|_| Error::Corrupt("tenant_id"))?,
        slug: row.1,
        personal: row.2 == 1,
    })
}

pub fn set_membership(
    tx: &Transaction<'_>,
    principal: Principal,
    tenant: TenantId,
    user: UserId,
    role: Role,
) -> Result<()> {
    require_tenant_admin(tx, principal, tenant)?;
    let changed = tx.execute(
        "INSERT INTO memberships(tenant_id, user_id, role)
        SELECT ?1, id, ?3 FROM users WHERE id = ?2 AND active = 1
        AND (kind = 0 OR (service_tenant_id = ?1 AND ?3 != 3))
        ON CONFLICT(tenant_id, user_id) DO UPDATE SET role = excluded.role",
        params![tenant.as_bytes(), user.as_bytes(), role as u8],
    )?;
    if changed == 0 {
        return Err(Error::NotFound);
    }
    Ok(())
}

pub fn remove_membership(
    tx: &Transaction<'_>,
    principal: Principal,
    tenant: TenantId,
    user: UserId,
) -> Result<()> {
    require_tenant_admin(tx, principal, tenant)?;
    // Grants cascade away, so removing and re-adding membership cannot resurrect them.
    tx.execute(
        "DELETE FROM memberships WHERE tenant_id = ?1 AND user_id = ?2",
        params![tenant.as_bytes(), user.as_bytes()],
    )?;
    Ok(())
}

pub fn create_repo(
    tx: &Transaction<'_>,
    principal: Principal,
    tenant: TenantId,
    repo: RepoId,
    name: &str,
    now: UnixMillis,
) -> Result<()> {
    require_tenant_admin(tx, principal, tenant)?;
    bounded_text(name, 128, "repository name")?;
    crate::jobs::insert_repo(tx, tenant, repo, name, now)
}

/// Grant/revoke repository actions; NONE deletes a grant. Membership is a
/// ceiling: a reader with a RUN bit still cannot run. Secrets are independent.
pub fn set_repo_grant(
    tx: &Transaction<'_>,
    principal: Principal,
    repo: RepoId,
    user: UserId,
    permissions: Permissions,
) -> Result<()> {
    if !Permissions::REPOSITORY.contains(permissions) {
        return Err(Error::InvalidInput("repository permissions"));
    }
    let bytes = tx
        .query_row(
            "SELECT tenant_id FROM repos WHERE id = ?1",
            [repo.as_bytes()],
            |r| r.get::<_, [u8; 16]>(0),
        )
        .optional()?
        .ok_or(Error::NotFound)?;
    let tenant = TenantId::from_bytes(bytes).map_err(|_| Error::Corrupt("tenant_id"))?;
    require_tenant_admin(tx, principal, tenant).map_err(|error| match error {
        Error::Forbidden => Error::NotFound,
        other => other,
    })?;
    if permissions == Permissions::NONE {
        tx.execute(
            "DELETE FROM repo_grants WHERE tenant_id = ?1 AND user_id = ?2 AND repo_id = ?3",
            params![tenant.as_bytes(), user.as_bytes(), repo.as_bytes()],
        )?;
    } else {
        tx.execute("INSERT INTO repo_grants(tenant_id, user_id, repo_id, permissions) VALUES (?1, ?2, ?3, ?4)
            ON CONFLICT(tenant_id, user_id, repo_id) DO UPDATE SET permissions = excluded.permissions",
            params![tenant.as_bytes(), user.as_bytes(), repo.as_bytes(), permissions.bits()])?;
    }
    Ok(())
}

pub fn create_service_account(
    tx: &Transaction<'_>,
    principal: Principal,
    tenant: TenantId,
    user: UserId,
    name: &str,
    role: Role,
    now: UnixMillis,
) -> Result<()> {
    require_tenant_admin(tx, principal, tenant)?;
    if role == Role::TenantAdmin {
        return Err(Error::Forbidden);
    }
    bounded_text(name, 128, "display name")?;
    tx.execute("INSERT INTO users(id, display_name, kind, service_tenant_id, created_ms) VALUES (?1, ?2, 1, ?3, ?4)", params![user.as_bytes(), name, tenant.as_bytes(), now.0])?;
    tx.execute(
        "INSERT INTO memberships(tenant_id, user_id, role) VALUES (?1, ?2, ?3)",
        params![tenant.as_bytes(), user.as_bytes(), role as u8],
    )?;
    Ok(())
}

fn bounded_text(value: &str, max: usize, field: &'static str) -> Result<()> {
    if value.is_empty() || value.len() > max || value.chars().any(char::is_control) {
        return Err(Error::InvalidInput(field));
    }
    Ok(())
}

/// Trusted admission/authentication persistence primitives. No HTTP/CLI route
/// may expose these directly. A02 owns first-admin/password admission, A04 owns
/// verified provider proof and identity linking, and A05 owns registration.
pub mod provisioning {
    use super::*;

    pub fn insert_human(
        tx: &Transaction<'_>,
        user: UserId,
        name: &str,
        super_admin: bool,
        now: UnixMillis,
    ) -> Result<()> {
        bounded_text(name, 128, "display name")?;
        tx.execute(
            "INSERT INTO users(id, display_name, super_admin, created_ms) VALUES (?1, ?2, ?3, ?4)",
            params![user.as_bytes(), name, super_admin, now.0],
        )?;
        Ok(())
    }

    /// Provider is a configured issuer key; subject is the verified immutable
    /// provider user ID, not a login, email or display name. Never relink on conflict.
    pub fn link_verified_identity(
        tx: &Transaction<'_>,
        user: UserId,
        provider: &str,
        subject: &str,
        now: UnixMillis,
    ) -> Result<()> {
        identity_input(provider, subject)?;
        let changed = tx.execute(
            "INSERT INTO external_identities(provider, subject, user_id, created_ms)
            SELECT ?1, ?2, id, ?4 FROM users WHERE id = ?3 AND kind = 0 AND active = 1",
            params![provider, subject, user.as_bytes(), now.0],
        )?;
        if changed == 0 {
            return Err(Error::NotFound);
        }
        Ok(())
    }

    pub fn resolve_verified_identity(
        conn: &Connection,
        provider: &str,
        subject: &str,
    ) -> Result<UserId> {
        identity_input(provider, subject)?;
        let id = conn
            .prepare_cached(
                "SELECT u.id FROM external_identities e JOIN users u ON u.id = e.user_id
            WHERE e.provider = ?1 AND e.subject = ?2 AND u.kind = 0 AND u.active = 1",
            )?
            .query_row(params![provider, subject], |r| r.get::<_, [u8; 16]>(0))
            .optional()?
            .ok_or(Error::NotFound)?;
        UserId::from_bytes(id).map_err(|_| Error::Corrupt("user_id"))
    }

    fn identity_input(provider: &str, subject: &str) -> Result<()> {
        bounded_text(provider, 64, "identity provider")?;
        bounded_text(subject, 255, "identity subject")?;
        if !provider
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
        {
            return Err(Error::InvalidInput("identity provider"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn point_and_page_authorization_use_index_searches_not_table_scans() {
        let mut conn = Connection::open_in_memory().unwrap();
        crate::migrate(&mut conn).unwrap();
        for sql in [
            concat!(
                "EXPLAIN QUERY PLAN ",
                repo_query!("r.tenant_id", "AND r.id = ?5")
            ),
            concat!(
                "EXPLAIN QUERY PLAN ",
                repo_query!(
                    "r.id, r.tenant_id, r.name",
                    "AND r.tenant_id = ?5 AND r.id > ?6 ORDER BY r.id LIMIT ?7"
                )
            ),
        ] {
            let mut stmt = conn.prepare(sql).unwrap();
            let count = stmt.parameter_count();
            let values = vec![rusqlite::types::Value::Null; count];
            let plans: Vec<String> = stmt
                .query_map(rusqlite::params_from_iter(values), |r| r.get(3))
                .unwrap()
                .map(|r| r.unwrap())
                .collect();
            assert!(plans.iter().all(|p| !p.starts_with("SCAN ")), "{plans:?}");
            assert!(
                plans.iter().any(|p| p.contains("SEARCH r USING")),
                "{plans:?}"
            );
            assert!(
                plans.iter().all(|p| !p.contains("TEMP B-TREE")),
                "{plans:?}"
            );
        }
    }
}
