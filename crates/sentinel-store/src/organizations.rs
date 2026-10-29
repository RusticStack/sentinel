use rusqlite::{Connection, Transaction, params};
use sentinel_core::{
    TenantId, UnixMillis,
    auth::{Namespace, Principal, Role},
};

use crate::{
    Error, Result,
    local_auth::{Event, audit},
};

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

pub const MAX_SELF_SERVICE_ORGS: i64 = 10;
pub const SELF_SERVICE_PER_HOUR: i64 = 3;

const HOUR_MS: i64 = 60 * 60 * 1000;

pub fn slug(value: &str) -> Result<Namespace<'_>> {
    let parsed = Namespace::parse(value).ok_or(Error::InvalidInput("organization name"))?;
    if value.len() < 2 || RESERVED_SLUGS.binary_search(&value).is_ok() {
        return Err(Error::InvalidInput("organization name"));
    }
    Ok(parsed)
}

/// Conflict reveals whether a name exists, so callers must rate-limit it.
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
    // A platform administrator is trusted to name an organization before binding its installation;
    // anyone else may not take the name of a GitHub account the App is installed on.
    if !platform && github_login_reserved(tx, name.as_str())? {
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

/// Whether `slug` equals the login of an account the GitHub App is installed on, bound or not, so
/// a self-service organization cannot squat the name of a GitHub organization before its owner
/// installs the App. Logins compare lowercase; `installations_by_github_login` answers it.
fn github_login_reserved(tx: &Transaction<'_>, slug: &str) -> Result<bool> {
    Ok(tx
        .prepare_cached(
            "SELECT EXISTS(SELECT 1 FROM installations
             WHERE provider = 'github' AND lower(account_login) = ?1)",
        )?
        .query_row([slug], |r| r.get(0))?)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Settings {
    pub tenant: TenantId,
    pub slug: String,
    pub personal: bool,
    pub github_backed: bool,
    pub installation_bound: bool,
    pub role: Option<Role>,
    pub created_ms: i64,
    pub github_confirmed_ms: Option<i64>,
    pub github_check_failures: Option<u32>,
    pub github_check_next_ms: Option<i64>,
}

/// Absent, suspended and foreign tenants all return NotFound so existence does not leak.
pub fn settings(conn: &Connection, principal: Principal, slug: &str) -> Result<Settings> {
    let tenant = crate::auth::member_tenant_by_slug(conn, principal, slug)?;
    let (mut settings, role) = conn
        .prepare_cached(
            "SELECT t.slug, t.kind, t.membership_source, t.created_ms, m.role,
                    EXISTS(SELECT 1 FROM installations i
                           WHERE i.tenant_id = t.id AND i.provider = 'github'),
                    m.synced_ms, c.attempts, NULLIF(c.next_ms, 9223372036854775807)
             FROM tenants t
             LEFT JOIN memberships m ON m.tenant_id = t.id AND m.user_id = ?2
             LEFT JOIN github_member_checks c ON c.tenant_id = t.id AND c.user_id = ?2
             WHERE t.id = ?1",
        )?
        .query_row(params![tenant.as_bytes(), principal.user.as_bytes()], |r| {
            let settings = Settings {
                tenant,
                slug: r.get(0)?,
                personal: r.get::<_, i64>(1)? == 1,
                github_backed: r.get::<_, i64>(2)? == 1,
                created_ms: r.get(3)?,
                role: None,
                installation_bound: r.get(5)?,
                github_confirmed_ms: r.get(6)?,
                github_check_failures: r
                    .get::<_, Option<i64>>(7)?
                    .map(|n| u32::try_from(n).unwrap_or(u32::MAX)),
                github_check_next_ms: r.get(8)?,
            };
            Ok((settings, r.get::<_, Option<i64>>(4)?))
        })?;
    settings.role = match role {
        None => None,
        Some(1) => Some(Role::Reader),
        Some(2) => Some(Role::Operator),
        Some(3) => Some(Role::TenantAdmin),
        Some(_) => return Err(Error::Corrupt("memberships.role")),
    };
    Ok(settings)
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
