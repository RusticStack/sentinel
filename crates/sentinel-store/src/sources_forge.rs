//! Trusted GitHub App lifecycle snapshots. A webhook is a refresh hint, never
//! authority to revive a previously bound installation from a stale body.
use crate::{Error, Result};
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use sentinel_core::{InstallationId, RepoId, TenantId, UnixMillis};

pub struct Snapshot<'a> {
    pub external_id: u64,
    pub account_id: u64,
    pub login: &'a str,
    pub personal: bool,
    pub suspended: bool,
    pub permissions_valid: bool,
    pub expected: u64,
}

/// Call only with a freshly authenticated GitHub App API response. The
/// expected local version was read before starting that bounded request.
pub fn refresh(tx: &Transaction<'_>, s: Snapshot<'_>, now: UnixMillis) -> Result<InstallationId> {
    if s.external_id == 0
        || s.account_id == 0
        || s.account_id > i64::MAX as u64
        || s.expected >= i64::MAX as u64
    {
        return Err(Error::InvalidInput("installation snapshot"));
    }
    let id = crate::registration::record_installation(
        tx,
        "github",
        &s.external_id.to_string(),
        s.login,
        now,
    )?;
    let old: Option<i64> = tx.query_row(
        "SELECT account_id FROM installations WHERE id=?1",
        [id.as_bytes()],
        |r| r.get(0),
    )?;
    if old.is_some_and(|old| old != s.account_id as i64) {
        // A transfer never silently reauthorizes old source bindings.
        tx.execute("UPDATE source_bindings SET revoked=1,credential=x'',version=version+1 WHERE installation_id=?1 AND revoked=0",[id.as_bytes()])?;
    }
    if tx.execute("UPDATE installations SET account_id=?2,account_personal=?3,account_login=?4,suspended=?5,permissions_valid=?6,lifecycle_version=lifecycle_version+1 WHERE id=?1 AND lifecycle_version=?7",params![id.as_bytes(),s.account_id as i64,s.personal,s.login,s.suspended,s.permissions_valid,s.expected as i64])? != 1 { return Err(Error::Conflict); }
    Ok(id)
}

/// An authenticated deletion notification (or confirmed API 404) disables
/// issuance immediately. Only a fresh API snapshot can enable it again.
pub fn remove(tx: &Transaction<'_>, id: InstallationId) -> Result<()> {
    if tx.execute("UPDATE installations SET suspended=1,permissions_valid=0,lifecycle_version=lifecycle_version+1 WHERE id=?1",[id.as_bytes()])? != 1 { return Err(Error::NotFound); }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Grant {
    pub installation: u64,
    pub account: u64,
    pub repo: u64,
    pub lifecycle_version: i64,
}

pub fn grant(conn: &Connection, tenant: TenantId, repo: RepoId) -> Result<Grant> {
    let (installation,account,repo,version):(String,i64,i64,i64)=conn.query_row("SELECT i.external_id,i.account_id,b.forge_repo_id,i.lifecycle_version FROM source_bindings b JOIN installations i ON i.id=b.installation_id AND i.tenant_id=b.tenant_id JOIN tenants t ON t.id=b.tenant_id AND t.active=1 WHERE b.repo_id=?1 AND b.tenant_id=?2 AND b.revoked=0 AND i.suspended=0 AND i.permissions_valid=1 AND i.provider='github'",params![repo.as_bytes(),tenant.as_bytes()],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).optional()?.ok_or(Error::NotFound)?;
    Ok(Grant {
        installation: installation
            .parse()
            .map_err(|_| Error::Corrupt("installation id"))?,
        account: account as u64,
        repo: repo as u64,
        lifecycle_version: version,
    })
}
