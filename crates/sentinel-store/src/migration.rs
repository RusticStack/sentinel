//! Guided migration's writes: the tenant's switch, what the installation a repository is bound
//! through grants, and the gate every write path calls before it contacts GitHub. A permission
//! withdrawn on GitHub reaches the gate with the next installation snapshot and a switch turned
//! off reaches it with the next statement, so both stop the next write with no restart, and a
//! refusal leaves an audit row.

use rusqlite::{Connection, OptionalExtension, Transaction, params};
use sentinel_core::{MigrationPermissions, RepoId, TenantId, UnixMillis, UserId};

use crate::{
    Error, Result,
    auth::Authority,
    intake,
    local_auth::{Event, audit},
    sources_forge,
    switch::Switch,
};

/// The audit action of a write the gate refused because an installation no longer grants what a
/// migration writes with; the source audit trail names the missing permissions that way. A switch
/// turned off is `migration_off`, since nothing is missing and the tenant asked for neither.
pub const PERMISSIONS_REFUSED: &str = "migration_permissions";
pub const OFF_REFUSED: &str = "migration_off";

/// The tenant's switch, as a reader sees it.
pub fn mode(conn: &Connection, tenant: TenantId) -> Result<bool> {
    let enabled: i64 = conn
        .prepare_cached("SELECT migration_mode FROM tenants WHERE id = ?1 AND active = 1")?
        .query_row([tenant.as_bytes()], |r| r.get(0))
        .optional()?
        .ok_or(Error::NotFound)?;
    Ok(enabled == 1)
}

/// The migration permissions this tenant's installations do not grant, named as GitHub's App
/// settings name them and in one fixed order; empty when every one of them is granted. Every live
/// installation is judged, not only those a repository is bound through yet: an administrator
/// starts a migration before binding everything, and a later binding must not be the first place
/// a missing permission is noticed.
pub fn missing(conn: &Connection, tenant: TenantId) -> Result<Vec<&'static str>> {
    let mut stmt = conn.prepare_cached(
        "SELECT migration_permissions FROM installations WHERE tenant_id = ?1 AND suspended = 0",
    )?;
    let rows = stmt.query_map([tenant.as_bytes()], |r| r.get::<_, i64>(0))?;
    let mut missing: Vec<&'static str> = Vec::new();
    for row in rows {
        let bits = u8::try_from(row?).map_err(|_| Error::Corrupt("migration permissions"))?;
        let granted =
            MigrationPermissions::from_bits(bits).ok_or(Error::Corrupt("migration permissions"))?;
        for name in granted.missing() {
            if !missing.contains(name) {
                missing.push(name);
            }
        }
    }
    missing.sort_unstable();
    Ok(missing)
}

/// What one write path reads: the tenant's switch and what the installation the repository is
/// bound through grants, taken together so the two can never disagree.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Access {
    pub enabled: bool,
    pub permissions: MigrationPermissions,
}

impl Access {
    /// Whether the installation grants everything a migration writes with, whatever the switch
    /// says.
    pub fn granted(self) -> bool {
        self.permissions.missing().is_empty()
    }
}

/// The switch and the installation the repository is bound through, in one statement.
/// `NotFound` when the repository is bound through no live installation at all.
pub fn access(conn: &Connection, tenant: TenantId, repo: RepoId) -> Result<Access> {
    let row: Option<(i64, i64)> = conn
        .prepare_cached(
            "SELECT t.migration_mode, i.migration_permissions
             FROM source_bindings b
             JOIN installations i ON i.id = b.installation_id AND i.tenant_id = b.tenant_id
                 AND i.suspended = 0 AND i.permissions_valid = 1
             JOIN tenants t ON t.id = b.tenant_id AND t.active = 1
             WHERE b.repo_id = ?1 AND b.tenant_id = ?2 AND b.revoked = 0",
        )?
        .query_row(params![repo.as_bytes(), tenant.as_bytes()], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .optional()?;
    let Some((enabled, bits)) = row else {
        return Err(Error::NotFound);
    };
    let bits = u8::try_from(bits).map_err(|_| Error::Corrupt("migration permissions"))?;
    Ok(Access {
        enabled: enabled == 1,
        permissions: MigrationPermissions::from_bits(bits)
            .ok_or(Error::Corrupt("migration permissions"))?,
    })
}

/// The verdict on one write through the App.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Writes {
    /// Every write path is open: the switch is on and the installation grants the three.
    Permitted,
    /// The tenant never started a migration, or stopped it.
    Off,
    /// The installation GitHub last reported no longer grants these.
    Missing(Vec<&'static str>),
    /// The repository is bound through no live installation to write with.
    Unbound,
}

/// The gate every migration write path calls before it contacts GitHub, in the caller's
/// transaction. It reads the switch and the installation's last snapshot as they are now, so a
/// permission withdrawn on GitHub refuses the next write at once, and it records a refusal in the
/// repository's audit trail, which is what makes an attempt to write without the grant visible.
pub fn authorize(
    tx: &Transaction<'_>,
    tenant: TenantId,
    repo: RepoId,
    actor: Option<UserId>,
    now: UnixMillis,
) -> Result<Writes> {
    let access = match access(tx, tenant, repo) {
        Ok(access) => access,
        Err(Error::NotFound) => return Ok(Writes::Unbound),
        Err(other) => return Err(other),
    };
    let missing = access.permissions.missing();
    let (verdict, action) = if !access.enabled {
        (Writes::Off, OFF_REFUSED)
    } else if !missing.is_empty() {
        (Writes::Missing(missing.to_vec()), PERMISSIONS_REFUSED)
    } else {
        return Ok(Writes::Permitted);
    };
    intake::audit(tx, tenant, repo, actor, action, now)?;
    Ok(verdict)
}

/// Turn guided migration on or off. Enabling is refused while the tenant's live installations do
/// not grant what a migration writes with; disabling never is, and it stops every write path in
/// the same transaction the switch reads.
pub fn set_mode(
    tx: &Transaction<'_>,
    authority: Authority,
    tenant: TenantId,
    enabled: bool,
) -> Result<Switch> {
    if let Some(principal) = authority.principal() {
        crate::auth::require_tenant_admin(tx, principal, tenant)?;
    }
    let current = mode(tx, tenant)?;
    if enabled && !current {
        if !sources_forge::live_installation(tx, tenant)? {
            return Ok(Switch::NoInstallation);
        }
        let missing = missing(tx, tenant)?;
        if !missing.is_empty() {
            return Ok(Switch::Missing(missing));
        }
    }
    if current == enabled {
        return Ok(Switch::Unchanged);
    }
    let changed = tx.execute(
        "UPDATE tenants SET migration_mode = ?2 WHERE id = ?1 AND active = 1 AND migration_mode = ?3",
        params![tenant.as_bytes(), enabled, current],
    )?;
    if changed != 1 {
        return Err(Error::Conflict);
    }
    audit(
        tx,
        Event::MigrationModeChanged,
        authority.actor(),
        None,
        authority.host_local(),
        Some(if enabled { "enabled" } else { "disabled" }),
    )?;
    Ok(Switch::Set)
}
