//! Live identity and repository authorization. Use these operations at client
//! boundaries; `jobs`/`runs` and raw SQL remain trusted controller primitives.
//! Mutations check authority inside the SAME writer transaction as the change.
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use sentinel_auth::secret::Digest;
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

/// [`require_repo`] that also returns the owning tenant's slug. The same
/// statement already joins `tenants` for its liveness predicate, so the slug
/// is one more projected column, not another lookup.
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
    // Only after authorization, so an outsider learns nothing about the
    // repository's binding from the refusal.
    crate::sources::validate_manual(tx, repo, &spec.source)?;
    let jobs = crate::runs::create_run(tx, tenant, repo, run, spec, now)?;
    // A manual dispatch records no provenance: a group template over
    // `event.*` resolves to the manual event facts here instead of waiting
    // for an event that will never arrive.
    crate::runs::apply_concurrency(tx, tenant, run, now)?;
    Ok(jobs)
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

/// Who is making an administrative decision.
///
/// Platform administration has two legitimate sources, and the audit trail must
/// tell them apart: a credential that proves a super admin is acting, and an
/// operator on the controller's own host, whose authority is the database file
/// itself. The host-local variant exists so `sentinel admin` does not have to
/// fabricate a `Principal` for somebody who never authenticated.
///
/// Step-up freshness (A06) is freshness, not authority: privileged changes
/// require both it and a live platform-admin check. A browser session carries
/// its token digest so freshness is **read again inside the writer
/// transaction** of the change ([`Authority::require_fresh`]) rather than
/// trusted from a flag computed when the request was identified: a session
/// revoked, or whose window closed, in between is refused at the mutation.
#[derive(Clone, Copy, Debug)]
pub enum Authority {
    /// An authenticated caller whose step-up is a precomputed fact. Platform
    /// administration is checked live. A bearer credential is always
    /// unstepped; the stepped form is for tests and trusted callers that have
    /// verified a proof themselves.
    Credential {
        principal: Principal,
        stepped_up: bool,
    },
    /// A browser session: its step-up stamp is re-read from the `sessions`
    /// row in the transaction that makes the change.
    Session {
        principal: Principal,
        token: Digest,
        /// `Policy::step_up_ms`: how long a stamp stays fresh.
        step_up_ms: i64,
    },
    /// A process that can already open this database, as with bootstrap and
    /// recovery. There is no network path to this variant, and no step-up can
    /// be stronger than holding the file.
    HostLocal,
}

impl Authority {
    /// A credential that has not proven presence: enough for routine
    /// administration, not for changes to who can authenticate.
    pub const fn credential(principal: Principal) -> Self {
        Self::Credential {
            principal,
            stepped_up: false,
        }
    }

    /// A browser session, with its step-up freshness evaluated against policy
    /// now. Prefer [`Authority::live_session`] where the session token is at
    /// hand: it re-checks inside the transaction.
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

    /// A browser session identified by its token digest; freshness is judged
    /// against the session row at the point of each privileged change.
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

    /// Require platform administration.
    pub fn require_platform(&self, conn: &Connection) -> Result<()> {
        match self {
            Authority::Credential { principal, .. } | Authority::Session { principal, .. } => {
                require_platform_admin(conn, *principal)
            }
            Authority::HostLocal => Ok(()),
        }
    }

    /// Require recent proof of presence, judged now. For a browser session
    /// this is one primary-key probe of its row inside `conn`'s transaction:
    /// a revoked or expired session, an un-stamped one, and a stamp outside
    /// the window (or in the future) are all `StepUpRequired`. A bearer
    /// credential never has it; host-local needs none.
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

    /// Require platform administration **and** recent proof of presence: the
    /// bar for changing who can authenticate, or as whom.
    pub fn require_privileged(&self, conn: &Connection) -> Result<()> {
        self.require_platform(conn)?;
        self.require_fresh(conn)
    }

    /// Live administration of `tenant` for a change that grants access.
    ///
    /// The administration check is [`require_tenant_admin`]. On top of it:
    ///
    /// - `strict` demands fresh step-up of everyone (issuing credentials);
    /// - a platform administrator who is **not** an administrator-member of
    ///   the tenant reaches it by platform scope alone, which carries no
    ///   ambient data access (see [`require_object_read`]): that path always
    ///   demands fresh step-up and an explicit `reason` (1..=100 characters)
    ///   and is recorded as [`crate::local_auth::Event::PlatformOverride`].
    ///
    /// Refusals are ordered so a caller without administration learns nothing
    /// (`Forbidden`) and a caller without proof is asked for it
    /// (`StepUpRequired`) before the reason is judged. A host-local authority
    /// is refused: it has no principal to attribute, and host-local
    /// provisioning uses the trusted primitives.
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

/// Tenant-scoped object transfer authority (D02). The tenant comes from the
/// resource row or the namespace lookup — never trusted from the request.
/// `write` distinguishes upload sessions (membership at operator role or
/// above, plus the RUN bit) from object downloads (any live member). A
/// caller without the relationship sees `NotFound`, never the difference.
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

/// Object download authority (D02). Bytes are repository evidence, so a
/// digest is readable only through something that already grants it:
///
/// - an **artifact**: some manifest edge to `(tenant, digest)` belongs to an
///   artifact of a run whose repository the caller may `READ` — the same
///   predicate as the run's artifact listing (one join from the
///   `manifest_refs_object` index; the job id is the manifest name's
///   prefix, `job_<uuid>/<artifact>`);
/// - a **resumable upload** committed in the tenant, for a member at
///   operator role or above holding `RUN` — who could have uploaded it.
///
/// Super admin carries no ambient data access here: platform scope is not
/// a membership. Anything else is `NotFound`, the same as a missing digest,
/// so the route is no existence oracle.
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
    insert_namespace(tx, tenant, slug, kind, now)
}

/// The insertion itself, without an authorization decision. Trusted internal:
/// `create_namespace` above requires platform administration, and
/// [`crate::registration`] applies the deployment's tenant-creation policy.
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

/// Resolve a tenant slug for a client route, answering `NotFound` alike for
/// an absent tenant, a suspended one, and one the caller has no live
/// relationship with, so a slug in a URL never confirms that a namespace
/// exists. Unlike [`get_namespace`] it also admits a credential narrowed to
/// one repository of that tenant, whose routes still narrow further.
///
/// One key probe on `tenants(slug)` plus key joins; it replaces the
/// host-local [`crate::lookup::tenant_by_slug`] at no extra cost.
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

/// Resolve the tenant (by slug) and, optionally, a repository (by name)
/// that a person may narrow an OAuth grant to: an active tenant they are a
/// member of, and a repository of it they can see (tenant admins see every
/// repository; other members the ones granted to them). Anything else —
/// absent, suspended, foreign, or invisible — is the same `NotFound`, so
/// the consent and device pages cannot be used to learn which names exist
/// elsewhere. One statement.
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

/// Refuse (`Conflict`) to take the administrator role from `user` when they
/// are the tenant's last administrator: an organization that loses its last
/// admin can only be recovered by the platform. A personal namespace's owner
/// is already held by the schema. A tenant that has no administrator (one a
/// platform administrator created bare) is not blocked: the change being
/// made is how it gets one.
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

/// Name a person in `tenant`: a `usr_…` id as given, or else the **existing
/// member** with that local sign-in name. A name is never resolved outside the
/// tenant, so an administrator cannot probe which sign-in names exist
/// deployment-wide: a non-member's name and an unknown name are the same
/// `NotFound`. Adding someone who is not yet a member takes their (unguessable)
/// id, which has to come from the person.
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

/// Set or change a member's role. A downgrade takes effect on the next query;
/// the tenant's authorization epoch moves so anything long-lived re-checks.
///
/// This `Principal` form carries no step-up policy: it is for trusted
/// provisioning and fixtures. Client routes use [`set_membership_as`].
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

/// [`set_membership`] for a client route. A platform administrator who is not
/// an administrator of the tenant changes membership only with fresh step-up
/// and an audited `reason` ([`Authority::require_tenant_access_change`]); a
/// tenant administrator needs neither.
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
        // No invitation or acceptance precedes this: record that the person
        // was added by someone else, apart from the role change below.
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

/// Remove a member. Grants cascade away, so removing and re-adding membership
/// cannot resurrect them; credentials narrowed to this tenant are revoked in
/// the same transaction, because nothing they could reach remains.
pub fn remove_membership(
    tx: &Transaction<'_>,
    principal: Principal,
    tenant: TenantId,
    user: UserId,
    now: UnixMillis,
) -> Result<()> {
    require_tenant_admin(tx, principal, tenant)?;
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

/// Resolve a namespace the principal is a member of (or, with platform scope,
/// administers) by its identifier. Same predicate as [`get_namespace`].
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

/// The insertion itself, without an authorization decision: the host-local
/// CLI path and trusted provisioning use it, the client path goes through
/// [`create_repo`] below.
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

/// Grant/revoke repository actions; NONE deletes a grant. Membership is a
/// ceiling: a reader with a RUN bit still cannot run. Secrets are independent.
///
/// This `Principal` form carries no step-up policy: it is for trusted
/// provisioning and fixtures. Client routes use [`set_repo_grant_as`].
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

/// [`set_repo_grant`] for a client route: the same step-up and `reason` rule
/// as [`set_membership_as`] for a platform administrator who does not
/// administer the tenant.
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

/// The tenant that owns `repo`, after the permission bits are checked.
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

/// Write the grant for an already-authorized change.
pub(crate) fn apply_repo_grant(
    tx: &Transaction<'_>,
    principal: Principal,
    tenant: TenantId,
    repo: RepoId,
    user: UserId,
    permissions: Permissions,
) -> Result<()> {
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

/// Create a service principal confined to `tenant`. Minting a principal that
/// can later hold credentials needs fresh step-up
/// ([`Authority::require_tenant_access_change`], strict), and a platform
/// administrator who does not administer the tenant also gives a `reason`.
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
    /// provider user ID, not a login, email or display name. Never relink on
    /// conflict. A pending account may hold a link — holding one is not using
    /// one, since sign-in still requires an active account — but a rejected
    /// account may not acquire one.
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
