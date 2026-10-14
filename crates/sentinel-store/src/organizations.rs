//! Self-service organizations: who may create one, which names are taken by
//! the product itself, how many one account may hold, and the read-only
//! settings an organization shows.
//!
//! The deployment's `tenant_creation` policy ([`crate::registration`]) is the
//! one permission: `approved-users` lets an approved account create its own
//! personal namespace *and* organizations (within the quotas below); the
//! default `super-admin-only` keeps both a platform decision. Membership of
//! the new organization is the creator's, as its administrator.

use rusqlite::{Connection, Transaction, params};
use sentinel_core::{
    TenantId, UnixMillis,
    auth::{Namespace, Principal, Role},
};

use crate::{
    Error, Result,
    local_auth::{Event, audit},
};

/// Namespace names no organization may take: they are first path segments of
/// the web interface and the API, or names a person would mistake for the
/// deployment itself. Sorted, so a lookup is a binary search. Applies to
/// organizations created through [`create_self_service`] and the first-run
/// wizard; personal namespaces and the platform's `create_organization` are
/// unchanged.
pub const RESERVED_SLUGS: &[&str] = &[
    "about",
    "account",
    "admin",
    "administrator",
    "api",
    "assets",
    "attempts",
    "auth",
    "billing",
    "callback",
    "dashboard",
    "device",
    "docs",
    "email",
    "grants",
    "health",
    "help",
    "hooks",
    "intake",
    "invitations",
    "invite",
    "login",
    "logout",
    "mcp",
    "me",
    "metrics",
    "new",
    "null",
    "oauth",
    "onboarding",
    "organizations",
    "orgs",
    "pricing",
    "queue",
    "ready",
    "register",
    "root",
    "runs",
    "security",
    "sentinel",
    "settings",
    "setup",
    "signin",
    "signup",
    "static",
    "status",
    "support",
    "system",
    "tenants",
    "undefined",
    "users",
    "verify-email",
    "version",
    "workers",
    "www",
];

/// Organizations one account may create through the self-service route, and
/// how many in an hour. Bounded so an approved account cannot fill the
/// namespace space; a platform administrator creates more with
/// [`crate::tenancy::create_organization`].
pub const MAX_SELF_SERVICE_ORGS: i64 = 10;
pub const SELF_SERVICE_PER_HOUR: i64 = 3;

const HOUR_MS: i64 = 60 * 60 * 1000;

/// A slug an organization may take: a valid [`Namespace`] of 2 to 63 bytes
/// that is not [reserved](RESERVED_SLUGS). Errors never echo the input.
pub fn slug(value: &str) -> Result<Namespace<'_>> {
    let parsed = Namespace::parse(value).ok_or(Error::InvalidInput("organization name"))?;
    if value.len() < 2 || RESERVED_SLUGS.binary_search(&value).is_ok() {
        return Err(Error::InvalidInput("organization name"));
    }
    Ok(parsed)
}

/// Create an organization for the caller, when policy allows it, and make the
/// caller its administrator.
///
/// A platform administrator may always; anyone else needs the deployment's
/// `tenant_creation` to be `approved-users`, an approved active human account
/// and an unscoped credential, and is held to [`MAX_SELF_SERVICE_ORGS`] in
/// all and [`SELF_SERVICE_PER_HOUR`] per hour (`QuotaExceeded`). A taken name
/// is `Conflict`: the slug check inherently answers whether a name exists, so
/// callers rate-limit it. The tenant, the creator's admin membership and the
/// audit rows are one commit.
pub fn create_self_service(
    tx: &Transaction<'_>,
    principal: Principal,
    tenant: TenantId,
    name: &str,
    now: UnixMillis,
) -> Result<()> {
    let name = slug(name)?;
    let platform = crate::auth::require_platform_admin(tx, principal).is_ok();
    if !platform {
        // Policy is read here, in the deciding transaction.
        if crate::registration::policy(tx)?.tenant_creation
            != crate::registration::TenantCreation::ApprovedUsers
        {
            return Err(Error::Forbidden);
        }
        // A credential scoped to one tenant acts inside it; creating another
        // is outside what it acts under.
        if principal.tenant.is_some() || principal.repo.is_some() {
            return Err(Error::Forbidden);
        }
        let eligible: bool = tx
            .prepare_cached(
                "SELECT EXISTS(SELECT 1 FROM users
                 WHERE id = ?1 AND kind = 0 AND active = 1 AND status = 1)",
            )?
            .query_row([principal.user.as_bytes()], |r| r.get(0))?;
        if !eligible {
            return Err(Error::Forbidden);
        }
        let (total, recent): (i64, i64) = tx
            .prepare_cached(
                "SELECT COUNT(*), COALESCE(SUM(created_ms > ?2), 0) FROM tenants
                 WHERE created_by = ?1",
            )?
            .query_row(params![principal.user.as_bytes(), now.0 - HOUR_MS], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })?;
        if total >= MAX_SELF_SERVICE_ORGS || recent >= SELF_SERVICE_PER_HOUR {
            return Err(Error::QuotaExceeded);
        }
    }
    let taken: bool = tx
        .prepare_cached("SELECT EXISTS(SELECT 1 FROM tenants WHERE slug = ?1)")?
        .query_row([name.as_str()], |r| r.get(0))?;
    if taken {
        return Err(Error::Conflict);
    }
    crate::auth::insert_namespace(
        tx,
        tenant,
        name,
        crate::auth::NamespaceKind::Organization,
        now,
    )?;
    tx.execute(
        "UPDATE tenants SET created_by = ?2 WHERE id = ?1",
        params![tenant.as_bytes(), principal.user.as_bytes()],
    )?;
    tx.execute(
        "INSERT INTO memberships(tenant_id, user_id, role) VALUES (?1, ?2, 3)",
        params![tenant.as_bytes(), principal.user.as_bytes()],
    )?;
    audit(
        tx,
        Event::NamespaceCreated,
        Some(principal.user),
        None,
        false,
        Some(name.as_str()),
    )?;
    audit(
        tx,
        Event::MembershipSet,
        Some(principal.user),
        Some(principal.user),
        false,
        Some("admin"),
    )
}

/// What an organization's settings page shows: its kind and where its
/// membership comes from. Read-only: the membership source is changed by an
/// explicit administrator act, and email-domain auto-join is the operator's
/// environment variable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Settings {
    pub tenant: TenantId,
    pub slug: String,
    pub personal: bool,
    /// Membership is GitHub's to confirm (`membership_source = 1`).
    pub github_backed: bool,
    /// A GitHub App installation is bound to the tenant. An email invitation
    /// is refused for it even before it is converted, and email-domain
    /// auto-join must never apply to it.
    pub installation_bound: bool,
    /// The caller's membership role; `None` for a platform administrator who
    /// is not a member.
    pub role: Option<Role>,
    pub created_ms: i64,
    /// When GitHub last confirmed the caller's own membership; `None` for a
    /// membership managed here (or none).
    pub github_confirmed_ms: Option<i64>,
    /// The caller's scheduled GitHub check, when one exists: how many passes
    /// in a row GitHub could not answer (rate limit, outage, missing App
    /// permission); zero for one that is merely scheduled.
    pub github_check_failures: Option<u32>,
    /// When that check is next due (a settled member keeps a row for the
    /// periodic re-confirmation, so only a due time at or before now means
    /// a check is waiting).
    pub github_check_next_ms: Option<i64>,
}

/// The settings of the tenant `slug` for `principal`, with the same uniform
/// `NotFound` as every slug route ([`crate::auth::member_tenant_by_slug`]):
/// absent, suspended and foreign are indistinguishable.
pub fn settings(conn: &Connection, principal: Principal, slug: &str) -> Result<Settings> {
    let tenant = crate::auth::member_tenant_by_slug(conn, principal, slug)?;
    // Both left joins are primary-key probes of the caller's own rows.
    let (slug, kind, source, created_ms, role, bound, confirmed, failures, next): (
        String,
        i64,
        i64,
        i64,
        Option<i64>,
        bool,
        Option<i64>,
        Option<i64>,
        Option<i64>,
    ) = conn
        .prepare_cached(
            "SELECT t.slug, t.kind, t.membership_source, t.created_ms, m.role,
                    EXISTS(SELECT 1 FROM installations i
                           WHERE i.tenant_id = t.id AND i.provider = 'github'),
                    m.synced_ms, c.attempts, c.next_ms
             FROM tenants t
             LEFT JOIN memberships m ON m.tenant_id = t.id AND m.user_id = ?2
             LEFT JOIN github_member_checks c ON c.tenant_id = t.id AND c.user_id = ?2
             WHERE t.id = ?1",
        )?
        .query_row(params![tenant.as_bytes(), principal.user.as_bytes()], |r| {
            Ok((
                r.get(0)?,
                r.get(1)?,
                r.get(2)?,
                r.get(3)?,
                r.get(4)?,
                r.get(5)?,
                r.get(6)?,
                r.get(7)?,
                r.get(8)?,
            ))
        })?;
    Ok(Settings {
        github_confirmed_ms: confirmed,
        github_check_next_ms: next,
        github_check_failures: failures.map(|n| u32::try_from(n).unwrap_or(u32::MAX)),
        tenant,
        slug,
        personal: kind == 1,
        github_backed: source == 1,
        installation_bound: bound,
        role: match role {
            None => None,
            Some(1) => Some(Role::Reader),
            Some(2) => Some(Role::Operator),
            Some(3) => Some(Role::TenantAdmin),
            Some(_) => return Err(Error::Corrupt("memberships.role")),
        },
        created_ms,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reserved_names_are_sorted_for_binary_search() {
        assert!(RESERVED_SLUGS.windows(2).all(|w| w[0] < w[1]));
    }

    #[test]
    fn slugs_refuse_reserved_short_and_malformed_names() {
        assert!(slug("acme").is_ok());
        assert!(slug("a1").is_ok());
        for bad in [
            "a", "api", "settings", "Acme", "-acme", "acme-", "ac me", "",
        ] {
            assert!(slug(bad).is_err(), "{bad}");
        }
        assert!(slug(&"a".repeat(64)).is_err());
    }
}
