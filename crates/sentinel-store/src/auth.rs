//! Mutations check authority inside the same writer transaction as the change.
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use sentinel_auth::secret::Digest;
use sentinel_core::{
    RepoId, TenantId, UnixMillis, UserId,
    auth::{Namespace, Permissions, Principal, Role},
};

use crate::{Error, Result};

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

pub(crate) use repo_query;

pub(crate) fn repo_scope(principal: Principal, required: Permissions) -> Result<()> {
    if required == Permissions::NONE
        || !Permissions::REPOSITORY.contains(required)
        || !principal.permissions.contains(required)
    {
        return Err(Error::NotFound);
    }
    Ok(())
}

/// Valid only for the current transaction or snapshot; never retain it across a mutation.
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

pub fn require_repo_slug(
    conn: &Connection,
    principal: Principal,
    repo: RepoId,
    required: Permissions,
) -> Result<(TenantId, String)> {
    repo_scope(principal, required)?;
    let (bytes, slug) = conn
        .prepare_cached(repo_query!("r.tenant_id, t.slug", "AND r.id = ?5"))?
        .query_row(
            params![
                principal.user.as_bytes(),
                required.bits(),
                principal.tenant.as_ref().map(TenantId::as_bytes),
                principal.repo.as_ref().map(RepoId::as_bytes),
                repo.as_bytes()
            ],
            |row| Ok((row.get::<_, [u8; 16]>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()?
        .ok_or(Error::NotFound)?;
    Ok((
        TenantId::from_bytes(bytes).map_err(|_| Error::Corrupt("tenant_id"))?,
        slug,
    ))
}

pub fn create_run(
    tx: &Transaction<'_>,
    principal: Principal,
    repo: RepoId,
    run: sentinel_core::RunId,
    spec: &sentinel_pipeline::run::RunSpec,
    now: UnixMillis,
) -> Result<Vec<sentinel_core::JobId>> {
    let tenant = require_repo(tx, principal, repo, Permissions::RUN)?;
    // Only after authorization, so a refusal reveals nothing about the repository's binding.
    crate::sources::validate_manual(tx, repo, &spec.source)?;
    let jobs = crate::runs::create_run(tx, tenant, repo, run, spec, now)?;
    crate::runs::apply_concurrency(tx, tenant, run, now)?;
    crate::dispatch::release_dependents(tx, tenant, run, now)?;
    Ok(jobs)
}

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
    // Older formats stay readable (`RunSpec::decode`), and a spec that states no runtime is still written as 6.
    let readable = sentinel_pipeline::run::SPEC_FORMAT_READ_MIN as i64
        ..=sentinel_pipeline::run::SPEC_FORMAT as i64;
    if !readable.contains(&format) {
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

/// Freshness is re-read inside the writer transaction, so a session revoked mid-request is refused at the mutation.
#[derive(Clone, Copy, Debug)]
pub enum Authority {
    Credential {
        principal: Principal,
        stepped_up: bool,
    },
    Session {
        principal: Principal,
        token: Digest,
        step_up_ms: i64,
    },
    HostLocal,
}

impl Authority {
    pub const fn credential(principal: Principal) -> Self {
        Self::Credential {
            principal,
            stepped_up: false,
        }
    }

    pub fn session(
        session: &crate::local_auth::Session,
        policy: crate::local_auth::Policy,
        now: UnixMillis,
    ) -> Self {
        Self::Credential {
            principal: session.principal(),
            stepped_up: session.stepped_up_within(policy, now),
        }
    }

    pub const fn live_session(
        principal: Principal,
        token: Digest,
        policy: crate::local_auth::Policy,
    ) -> Self {
        Self::Session {
            principal,
            token,
            step_up_ms: policy.step_up_ms,
        }
    }

    pub fn require_platform(&self, conn: &Connection) -> Result<()> {
        match self {
            Authority::Credential { principal, .. } | Authority::Session { principal, .. } => {
                require_platform_admin(conn, *principal)
            }
            Authority::HostLocal => Ok(()),
        }
    }

    pub fn require_fresh(&self, conn: &Connection) -> Result<()> {
        match self {
            Authority::HostLocal
            | Authority::Credential {
                stepped_up: true, ..
            } => Ok(()),
            Authority::Credential { .. } => Err(Error::StepUpRequired),
            Authority::Session {
                token, step_up_ms, ..
            } => {
                let now = UnixMillis::now().0;
                let fresh: bool = conn
                    .prepare_cached(
                        "SELECT EXISTS(SELECT 1 FROM sessions
                         WHERE token_digest = ?1 AND revoked_ms IS NULL
                         AND idle_deadline_ms > ?2 AND absolute_deadline_ms > ?2
                         AND stepped_up_ms IS NOT NULL AND stepped_up_ms <= ?2
                         AND ?2 - stepped_up_ms < ?3)",
                    )?
                    .query_row(params![token.0, now, step_up_ms], |r| r.get(0))?;
                if fresh {
                    Ok(())
                } else {
                    Err(Error::StepUpRequired)
                }
            }
        }
    }

    pub fn require_privileged(&self, conn: &Connection) -> Result<()> {
        self.require_platform(conn)?;
        self.require_fresh(conn)
    }

    pub fn require_tenant_access_change(
        &self,
        tx: &Transaction<'_>,
        tenant: TenantId,
        strict: bool,
        reason: Option<&str>,
    ) -> Result<Principal> {
        let principal = self.principal().ok_or(Error::Forbidden)?;
        require_tenant_admin(tx, principal, tenant)?;
        let member_admin: bool = tx
            .prepare_cached(
                "SELECT EXISTS(SELECT 1 FROM memberships
                 WHERE tenant_id = ?1 AND user_id = ?2 AND role = 3)",
            )?
            .query_row(params![tenant.as_bytes(), principal.user.as_bytes()], |r| {
                r.get(0)
            })?;
        if strict || !member_admin {
            self.require_fresh(tx)?;
        }
        if !member_admin {
            let reason = reason.ok_or(Error::InvalidInput("reason"))?;
            bounded_text(reason, 100, "reason")?;
            crate::local_auth::audit(
                tx,
                crate::local_auth::Event::PlatformOverride,
                Some(principal.user),
                None,
                false,
                Some(reason),
            )?;
        }
        Ok(principal)
    }

    pub fn principal(&self) -> Option<Principal> {
        match self {
            Authority::Credential { principal, .. } | Authority::Session { principal, .. } => {
                Some(*principal)
            }
            Authority::HostLocal => None,
        }
    }

    pub fn actor(&self) -> Option<UserId> {
        self.principal().map(|principal| principal.user)
    }

    pub const fn host_local(&self) -> bool {
        matches!(self, Authority::HostLocal)
    }
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

pub fn require_tenant_member(
    conn: &Connection,
    principal: Principal,
    tenant: TenantId,
    write: bool,
) -> Result<()> {
    let required = if write {
        Permissions::RUN
    } else {
        Permissions::READ
    };
    if !principal.permissions.contains(required)
        || principal.repo.is_some()
        || principal.tenant.is_some_and(|id| id != tenant)
    {
        return Err(Error::NotFound);
    }
    let allowed: bool = conn
        .prepare_cached(
            "SELECT EXISTS(
        SELECT 1 FROM users u JOIN tenants t ON t.id = ?2
        LEFT JOIN memberships m ON m.tenant_id = t.id AND m.user_id = u.id
        WHERE u.id = ?1 AND u.active = 1 AND t.active = 1
        AND (u.kind = 0 OR u.service_tenant_id = t.id)
        AND (m.role >= ?3 OR (u.kind = 0 AND u.super_admin = 1 AND ?4)))",
        )?
        .query_row(
            params![
                principal.user.as_bytes(),
                tenant.as_bytes(),
                if write { 2 } else { 1 },
                principal.permissions.contains(Permissions::PLATFORM_ADMIN)
            ],
            |r| r.get(0),
        )?;
    if allowed {
        Ok(())
    } else {
        Err(Error::NotFound)
    }
}

pub fn require_object_read(
    conn: &Connection,
    principal: Principal,
    tenant: TenantId,
    digest: &[u8; 32],
) -> Result<()> {
    if principal.tenant.is_some_and(|id| id != tenant) {
        return Err(Error::NotFound);
    }
    if repo_scope(principal, Permissions::READ).is_ok() {
        let found = conn
            .prepare_cached(repo_query!(
                "1",
                "JOIN manifest_refs mr ON mr.tenant_id = r.tenant_id AND mr.kind = 0
                 JOIN jobs j ON j.id = unhex(replace(substr(CAST(mr.name AS TEXT), 5, 36), '-', ''))
                    AND j.tenant_id = mr.tenant_id
                 JOIN runs ru ON ru.id = j.run_id AND ru.repo_id = r.id",
                "AND r.tenant_id = ?5 AND mr.digest = ?6 LIMIT 1"
            ))?
            .query_row(
                params![
                    principal.user.as_bytes(),
                    Permissions::READ.bits(),
                    principal.tenant.as_ref().map(TenantId::as_bytes),
                    principal.repo.as_ref().map(RepoId::as_bytes),
                    tenant.as_bytes(),
                    digest.as_slice()
                ],
                |_| Ok(()),
            )
            .optional()?;
        if found.is_some() {
            return Ok(());
        }
    }
    if principal.repo.is_some() || !principal.permissions.contains(Permissions::RUN) {
        return Err(Error::NotFound);
    }
    let uploaded: bool = conn
        .prepare_cached(
            "SELECT EXISTS(
        SELECT 1 FROM users u JOIN tenants t ON t.id = ?2
        JOIN memberships m ON m.tenant_id = t.id AND m.user_id = u.id
        JOIN uploads up ON up.tenant_id = t.id AND up.object_digest = ?3 AND up.state_code = 1
        WHERE u.id = ?1 AND u.active = 1 AND t.active = 1
        AND (u.kind = 0 OR u.service_tenant_id = t.id) AND m.role >= 2)",
        )?
        .query_row(
            params![
                principal.user.as_bytes(),
                tenant.as_bytes(),
                digest.as_slice()
            ],
            |r| r.get(0),
        )?;
    if uploaded {
        Ok(())
    } else {
        Err(Error::NotFound)
    }
}

#[derive(Clone, Copy, Debug)]
pub enum NamespaceKind {
    Organization,
    Personal(UserId),
}

pub fn create_namespace(
    tx: &Transaction<'_>,
    principal: Principal,
    tenant: TenantId,
    slug: Namespace<'_>,
    kind: NamespaceKind,
    now: UnixMillis,
) -> Result<()> {
    require_platform_admin(tx, principal)?;
    insert_namespace(tx, tenant, slug, kind, now)
}

pub(crate) fn insert_namespace(
    tx: &Transaction<'_>,
    tenant: TenantId,
    slug: Namespace<'_>,
    kind: NamespaceKind,
    now: UnixMillis,
) -> Result<()> {
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

pub fn member_tenant_by_slug(
    conn: &Connection,
    principal: Principal,
    slug: &str,
) -> Result<TenantId> {
    if principal.permissions == Permissions::NONE {
        return Err(Error::NotFound);
    }
    let bytes: [u8; 16] = conn
        .prepare_cached(
            "SELECT t.id FROM tenants t JOIN users u ON u.id = ?1
        LEFT JOIN memberships m ON m.tenant_id = t.id AND m.user_id = u.id
        WHERE t.slug = ?2 AND t.active = 1 AND u.active = 1
        AND (?3 IS NULL OR t.id = ?3)
        AND (?4 IS NULL OR EXISTS(SELECT 1 FROM repos r WHERE r.id = ?4 AND r.tenant_id = t.id))
        AND (u.kind = 0 OR u.service_tenant_id = t.id)
        AND (m.user_id IS NOT NULL OR (u.kind = 0 AND u.super_admin = 1 AND ?5))",
        )?
        .query_row(
            params![
                principal.user.as_bytes(),
                slug,
                principal.tenant.as_ref().map(TenantId::as_bytes),
                principal.repo.as_ref().map(RepoId::as_bytes),
                principal.permissions.contains(Permissions::PLATFORM_ADMIN)
            ],
            |r| r.get(0),
        )
        .optional()?
        .ok_or(Error::NotFound)?;
    TenantId::from_bytes(bytes).map_err(|_| Error::Corrupt("tenant_id"))
}

pub fn narrowing_by_name(
    conn: &Connection,
    user: UserId,
    slug: &str,
    repo: Option<&str>,
) -> Result<(TenantId, Option<RepoId>)> {
    let (tenant, found) = conn
        .prepare_cached(
            "SELECT t.id, r.id FROM tenants t
        JOIN memberships m ON m.tenant_id = t.id AND m.user_id = ?1
        JOIN users u ON u.id = m.user_id AND u.active = 1 AND u.kind = 0
        LEFT JOIN repos r ON ?3 IS NOT NULL AND r.tenant_id = t.id AND r.name = ?3
            AND (m.role = 3 OR EXISTS(SELECT 1 FROM repo_grants g
                WHERE g.tenant_id = t.id AND g.user_id = m.user_id AND g.repo_id = r.id))
        WHERE t.slug = ?2 AND t.active = 1",
        )?
        .query_row(params![user.as_bytes(), slug, repo], |r| {
            Ok((r.get::<_, [u8; 16]>(0)?, r.get::<_, Option<[u8; 16]>>(1)?))
        })
        .optional()?
        .ok_or(Error::NotFound)?;
    let tenant = TenantId::from_bytes(tenant).map_err(|_| Error::Corrupt("tenant_id"))?;
    match (repo, found) {
        (None, _) => Ok((tenant, None)),
        (Some(_), None) => Err(Error::NotFound),
        (Some(_), Some(bytes)) => Ok((
            tenant,
            Some(RepoId::from_bytes(bytes).map_err(|_| Error::Corrupt("repo_id"))?),
        )),
    }
}

fn keep_an_admin(tx: &Transaction<'_>, tenant: TenantId, user: UserId) -> Result<()> {
    let last: bool = tx
        .prepare_cached(
            "SELECT EXISTS(SELECT 1 FROM memberships WHERE tenant_id = ?1 AND user_id = ?2
                AND role = 3)
             AND NOT EXISTS(SELECT 1 FROM memberships WHERE tenant_id = ?1 AND role = 3
                AND user_id != ?2)",
        )?
        .query_row(params![tenant.as_bytes(), user.as_bytes()], |r| r.get(0))?;
    if last {
        return Err(Error::Conflict);
    }
    Ok(())
}

pub fn resolve_member(conn: &Connection, tenant: TenantId, text: &str) -> Result<UserId> {
    if let Ok(user) = text.parse::<UserId>() {
        return Ok(user);
    }
    let bytes = conn
        .prepare_cached(
            "SELECT c.user_id FROM local_credentials c
             JOIN memberships m ON m.user_id = c.user_id AND m.tenant_id = ?1
             WHERE c.username = ?2",
        )?
        .query_row(params![tenant.as_bytes(), text], |r| {
            r.get::<_, [u8; 16]>(0)
        })
        .optional()?
        .ok_or(Error::NotFound)?;
    UserId::from_bytes(bytes).map_err(|_| Error::Corrupt("user_id"))
}

pub fn set_membership(
    tx: &Transaction<'_>,
    principal: Principal,
    tenant: TenantId,
    user: UserId,
    role: Role,
) -> Result<()> {
    require_tenant_admin(tx, principal, tenant)?;
    apply_membership(tx, principal, tenant, user, role)
}

pub fn set_membership_as(
    tx: &Transaction<'_>,
    authority: Authority,
    tenant: TenantId,
    user: UserId,
    role: Role,
    reason: Option<&str>,
) -> Result<()> {
    let principal = authority.require_tenant_access_change(tx, tenant, false, reason)?;
    apply_membership(tx, principal, tenant, user, role)
}

fn apply_membership(
    tx: &Transaction<'_>,
    principal: Principal,
    tenant: TenantId,
    user: UserId,
    role: Role,
) -> Result<()> {
    crate::github_members::require_app_managed(tx, tenant, Some(user))?;
    if role != Role::TenantAdmin {
        keep_an_admin(tx, tenant, user)?;
    }
    let was_member: bool = tx
        .prepare_cached(
            "SELECT EXISTS(SELECT 1 FROM memberships WHERE tenant_id = ?1 AND user_id = ?2)",
        )?
        .query_row(params![tenant.as_bytes(), user.as_bytes()], |r| r.get(0))?;
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
    crate::tenancy::bump_epoch(tx, tenant)?;
    if !was_member {
        crate::local_auth::audit(
            tx,
            crate::local_auth::Event::MemberAdded,
            Some(principal.user),
            Some(user),
            false,
            None,
        )?;
    }
    crate::local_auth::audit(
        tx,
        crate::local_auth::Event::MembershipSet,
        Some(principal.user),
        Some(user),
        false,
        Some(match role {
            Role::Reader => "reader",
            Role::Operator => "operator",
            Role::TenantAdmin => "admin",
        }),
    )
}

pub fn remove_membership(
    tx: &Transaction<'_>,
    principal: Principal,
    tenant: TenantId,
    user: UserId,
    now: UnixMillis,
) -> Result<()> {
    require_tenant_admin(tx, principal, tenant)?;
    crate::github_members::require_app_managed(tx, tenant, Some(user))?;
    keep_an_admin(tx, tenant, user)?;
    let removed = tx.execute(
        "DELETE FROM memberships WHERE tenant_id = ?1 AND user_id = ?2",
        params![tenant.as_bytes(), user.as_bytes()],
    )?;
    if removed == 0 {
        return Err(Error::NotFound);
    }
    tx.execute(
        "UPDATE api_tokens SET revoked_ms = ?3 WHERE user_id = ?1 AND tenant_id = ?2
         AND revoked_ms IS NULL",
        params![user.as_bytes(), tenant.as_bytes(), now.0],
    )?;
    crate::oauth::revoke_for_membership(tx, user, tenant, now)?;
    crate::tenancy::bump_epoch(tx, tenant)?;
    crate::local_auth::audit(
        tx,
        crate::local_auth::Event::MembershipRemoved,
        Some(principal.user),
        Some(user),
        false,
        None,
    )
}

pub fn get_namespace_by_id(
    conn: &Connection,
    principal: Principal,
    tenant: TenantId,
) -> Result<TenantNamespace> {
    if principal.repo.is_some() || principal.permissions == Permissions::NONE {
        return Err(Error::NotFound);
    }
    let row = conn
        .prepare_cached(
            "SELECT t.id, t.slug, t.kind FROM tenants t JOIN users u ON u.id = ?1
        LEFT JOIN memberships m ON m.tenant_id = t.id AND m.user_id = u.id
        WHERE t.id = ?2 AND t.active = 1 AND u.active = 1
        AND (?3 IS NULL OR t.id = ?3) AND (u.kind = 0 OR u.service_tenant_id = t.id)
        AND (m.user_id IS NOT NULL OR (u.kind = 0 AND u.super_admin = 1 AND ?4))",
        )?
        .query_row(
            params![
                principal.user.as_bytes(),
                tenant.as_bytes(),
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

pub fn create_repo_trusted(
    tx: &Transaction<'_>,
    tenant: TenantId,
    repo: RepoId,
    name: &str,
    now: UnixMillis,
) -> Result<()> {
    bounded_text(name, 128, "repository name")?;
    crate::jobs::insert_repo(tx, tenant, repo, name, now)
}

pub fn set_repo_grant(
    tx: &Transaction<'_>,
    principal: Principal,
    repo: RepoId,
    user: UserId,
    permissions: Permissions,
) -> Result<()> {
    let tenant = grant_target(tx, repo, permissions)?;
    require_tenant_admin(tx, principal, tenant).map_err(not_found_if_forbidden)?;
    apply_repo_grant(tx, principal, tenant, repo, user, permissions)
}

pub fn set_repo_grant_as(
    tx: &Transaction<'_>,
    authority: Authority,
    repo: RepoId,
    user: UserId,
    permissions: Permissions,
    reason: Option<&str>,
) -> Result<()> {
    let tenant = grant_target(tx, repo, permissions)?;
    let principal = authority
        .require_tenant_access_change(tx, tenant, false, reason)
        .map_err(not_found_if_forbidden)?;
    apply_repo_grant(tx, principal, tenant, repo, user, permissions)
}

fn not_found_if_forbidden(error: Error) -> Error {
    match error {
        Error::Forbidden => Error::NotFound,
        other => other,
    }
}

fn grant_target(tx: &Transaction<'_>, repo: RepoId, permissions: Permissions) -> Result<TenantId> {
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
    TenantId::from_bytes(bytes).map_err(|_| Error::Corrupt("tenant_id"))
}

pub(crate) fn apply_repo_grant(
    tx: &Transaction<'_>,
    principal: Principal,
    tenant: TenantId,
    repo: RepoId,
    user: UserId,
    permissions: Permissions,
) -> Result<()> {
    // A hand-written grant would give a GitHub-backed member more than GitHub grants them.
    crate::github_members::require_app_managed(tx, tenant, Some(user))?;
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
    crate::tenancy::bump_epoch(tx, tenant)?;
    crate::local_auth::audit(
        tx,
        crate::local_auth::Event::GrantChanged,
        Some(principal.user),
        Some(user),
        false,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn create_service_account(
    tx: &Transaction<'_>,
    authority: Authority,
    tenant: TenantId,
    user: UserId,
    name: &str,
    role: Role,
    reason: Option<&str>,
    now: UnixMillis,
) -> Result<()> {
    let principal = authority.require_tenant_access_change(tx, tenant, true, reason)?;
    if role == Role::TenantAdmin {
        return Err(Error::Forbidden);
    }
    bounded_text(name, 128, "display name")?;
    tx.execute("INSERT INTO users(id, display_name, kind, service_tenant_id, created_ms) VALUES (?1, ?2, 1, ?3, ?4)", params![user.as_bytes(), name, tenant.as_bytes(), now.0])?;
    tx.execute(
        "INSERT INTO memberships(tenant_id, user_id, role) VALUES (?1, ?2, ?3)",
        params![tenant.as_bytes(), user.as_bytes(), role as u8],
    )?;
    crate::local_auth::audit(
        tx,
        crate::local_auth::Event::ServiceAccountCreated,
        Some(principal.user),
        Some(user),
        false,
        None,
    )
}

fn bounded_text(value: &str, max: usize, field: &'static str) -> Result<()> {
    if value.is_empty() || value.len() > max || value.chars().any(char::is_control) {
        return Err(Error::InvalidInput(field));
    }
    Ok(())
}

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
            SELECT ?1, ?2, id, ?4 FROM users WHERE id = ?3 AND kind = 0 AND status != 2",
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
