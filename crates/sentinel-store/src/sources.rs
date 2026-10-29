use crate::{Error, Result};
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use sentinel_auth::sealed::Key;
use sentinel_core::{
    AttemptId, InstallationId, RepoId, TenantId, UnixMillis, UserId, WorkerId,
    auth::{Permissions, Principal},
};
use sentinel_protocol::source::{Access, Binding, Credential};

use crate::registration::Authority;

pub(crate) fn context(tenant: TenantId, repo: RepoId, version: u64) -> [u8; 48] {
    let mut out = [0; 48];
    out[..8].copy_from_slice(b"source01");
    out[8..24].copy_from_slice(tenant.as_bytes());
    out[24..40].copy_from_slice(repo.as_bytes());
    out[40..].copy_from_slice(&version.to_be_bytes());
    out
}

pub struct Update<'a> {
    pub repo: RepoId,
    pub expected: u64,
    pub binding: &'a Binding,
    pub credential: &'a Credential,
    pub forge: Option<(InstallationId, u64)>,
}

pub fn bind(
    tx: &Transaction<'_>,
    authority: Authority,
    actor: Option<UserId>,
    update: Update<'_>,
    destinations: &[String],
    key: &Key,
    now: UnixMillis,
) -> Result<u64> {
    let tenant = match authority.principal() {
        Some(principal) => {
            let tenant = crate::auth::require_repo(tx, principal, update.repo, Permissions::READ)?;
            crate::auth::require_tenant_admin(tx, principal, tenant)?;
            tenant
        }
        None => crate::sources::repo_tenant(tx, update.repo)?,
    };
    let destination = sentinel_protocol::source::remote(&update.binding.remote)
        .ok_or(Error::InvalidInput("source remote"))?;
    if !destinations.iter().any(|d| d == destination) {
        return Err(Error::InvalidInput(
            "remote outside the deployment's source destinations",
        ));
    }
    if !update.binding.validate() {
        return Err(Error::InvalidInput("source binding"));
    }
    if !update.credential.valid_for(&update.binding.remote) {
        return Err(Error::InvalidInput("credential for this transport"));
    }
    if let Some((installation, repo_id)) = update.forge {
        if repo_id == 0
            || repo_id > i64::MAX as u64
            || !matches!(update.credential, Credential::Public)
            || !update.binding.remote.starts_with("https://github.com/")
        {
            return Err(Error::InvalidInput("forge association"));
        }
        let allowed: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM installations WHERE id=?1 AND tenant_id=?2 AND provider='github' AND suspended=0 AND permissions_valid=1 AND account_id IS NOT NULL)",params![installation.as_bytes(),tenant.as_bytes()], |r|r.get(0))?;
        if !allowed {
            return Err(Error::NotFound);
        }
    }
    let version = update
        .expected
        .checked_add(1)
        .filter(|v| *v <= i64::MAX as u64)
        .ok_or(Error::InvalidInput("source version"))?;
    let binding =
        serde_json::to_vec(update.binding).map_err(|_| Error::InvalidInput("source binding"))?;
    let plain = serde_json::to_vec(update.credential)
        .map_err(|_| Error::InvalidInput("source credential"))?;
    let sealed = key.seal(&context(tenant, update.repo, version), &plain);
    if binding.len() > 32768 || sealed.len() > 32768 {
        return Err(Error::InvalidInput("source size"));
    }
    let changed = if update.expected == 0 {
        tx.execute("INSERT INTO source_bindings(repo_id,tenant_id,version,binding,credential,installation_id,forge_repo_id,updated_ms)
            VALUES(?1,?2,?3,?4,?5,?6,?7,?8) ON CONFLICT(repo_id) DO NOTHING",
            params![update.repo.as_bytes(),tenant.as_bytes(),version as i64,binding,sealed,update.forge.as_ref().map(|f|f.0.as_bytes()),update.forge.map(|f|f.1 as i64),now.0])?
    } else {
        tx.execute("UPDATE source_bindings SET version=?3,binding=?4,credential=?5,installation_id=?6,forge_repo_id=?7,updated_ms=?8,revoked=0 WHERE repo_id=?1 AND tenant_id=?2 AND version=?9",
            params![update.repo.as_bytes(),tenant.as_bytes(),version as i64,binding,sealed,update.forge.as_ref().map(|f|f.0.as_bytes()),update.forge.map(|f|f.1 as i64),now.0,update.expected as i64])?
    };
    if changed != 1 {
        return Err(Error::Conflict);
    }
    tx.execute(
        "UPDATE poll_configs SET baseline_ms=NULL,updated_ms=?2 WHERE repo_id=?1",
        params![update.repo.as_bytes(), now.0],
    )?;
    tx.execute(
        "DELETE FROM poll_observations WHERE repo_id=?1",
        [update.repo.as_bytes()],
    )?;
    let recorded = actor.or_else(|| authority.actor());
    let recorded = recorded.map(|a| *a.as_bytes());
    tx.execute("INSERT INTO source_audit(tenant_id,repo_id,version,actor,action,at_ms) VALUES(?1,?2,?3,?4,'bind',?5)",params![tenant.as_bytes(),update.repo.as_bytes(),version as i64,recorded,now.0])?;
    Ok(version)
}

pub fn revoke(
    tx: &Transaction<'_>,
    authority: Authority,
    actor: Option<UserId>,
    repo: RepoId,
    expected: u64,
    now: UnixMillis,
) -> Result<()> {
    let tenant = match authority.principal() {
        Some(principal) => {
            let tenant = crate::auth::require_repo(tx, principal, repo, Permissions::READ)?;
            crate::auth::require_tenant_admin(tx, principal, tenant)?;
            tenant
        }
        None => repo_tenant(tx, repo)?,
    };
    if expected >= i64::MAX as u64 {
        return Err(Error::InvalidInput("source version"));
    }
    if tx.execute("UPDATE source_bindings SET revoked=1,version=version+1,credential=x'',updated_ms=?3 WHERE repo_id=?1 AND version=?2 AND revoked=0",params![repo.as_bytes(),expected as i64,now.0])? != 1 { return Err(Error::Conflict); }
    // A revoked binding's hook secret must not keep accepting events.
    tx.execute(
        "DELETE FROM source_intake_tokens WHERE repo_id = ?1",
        [repo.as_bytes()],
    )?;
    tx.execute(
        "DELETE FROM poll_configs WHERE repo_id = ?1",
        [repo.as_bytes()],
    )?;
    tx.execute(
        "DELETE FROM poll_observations WHERE repo_id = ?1",
        [repo.as_bytes()],
    )?;
    let recorded = actor.or_else(|| authority.actor());
    let recorded = recorded.map(|a| *a.as_bytes());
    tx.execute("INSERT INTO source_audit(tenant_id,repo_id,version,actor,action,at_ms) VALUES(?1,?2,?3,?4,'revoke',?5)",params![tenant.as_bytes(),repo.as_bytes(),(expected+1) as i64,recorded,now.0])?;
    Ok(())
}

pub fn repo_tenant(conn: &Connection, repo: RepoId) -> Result<TenantId> {
    let bytes: Option<[u8; 16]> = conn
        .prepare_cached(
            "SELECT r.tenant_id FROM repos r JOIN tenants t ON t.id = r.tenant_id AND t.active = 1 WHERE r.id = ?1",
        )?
        .query_row([repo.as_bytes()], |r| r.get(0))
        .optional()?;
    TenantId::from_bytes(bytes.ok_or(Error::NotFound)?).map_err(|_| Error::Corrupt("tenant_id"))
}

#[derive(Debug)]
pub struct Metadata {
    pub binding: Binding,
    pub version: u64,
    pub revoked: bool,
    pub forge: Option<(InstallationId, u64)>,
}

pub fn metadata(conn: &Connection, principal: Principal, repo: RepoId) -> Result<Metadata> {
    crate::auth::require_repo(conn, principal, repo, Permissions::READ)?;
    load_metadata(conn, repo)
}

pub fn metadata_trusted(conn: &Connection, repo: RepoId) -> Result<Metadata> {
    repo_tenant(conn, repo)?;
    load_metadata(conn, repo)
}

pub fn load_metadata(conn: &Connection, repo: RepoId) -> Result<Metadata> {
    type Row = (Vec<u8>, i64, bool, Option<[u8; 16]>, Option<i64>);
    let (bytes, version, revoked, installation, forge): Row = conn.query_row("SELECT binding,version,revoked,installation_id,forge_repo_id FROM source_bindings WHERE repo_id=?1",[repo.as_bytes()],|r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?))).optional()?.ok_or(Error::NotFound)?;
    Ok(Metadata {
        binding: serde_json::from_slice(&bytes).map_err(|_| Error::Corrupt("source binding"))?,
        version: version as u64,
        revoked,
        forge: match (installation, forge) {
            (Some(i), Some(r)) => Some((
                InstallationId::from_bytes(i).map_err(|_| Error::Corrupt("installation id"))?,
                r as u64,
            )),
            (None, None) => None,
            _ => return Err(Error::Corrupt("forge association")),
        },
    })
}

pub fn validate_source(
    conn: &Connection,
    repo: RepoId,
    source: &sentinel_pipeline::PinnedSource,
) -> Result<()> {
    match load_metadata(conn, repo) {
        Ok(m)
            if !m.revoked
                && m.binding.remote == source.repo
                && source.ref_name.as_ref().is_none_or(|r| m.binding.allows(r)) =>
        {
            Ok(())
        }
        Ok(_) => Err(Error::Forbidden),
        Err(Error::NotFound) => Ok(()),
        Err(e) => Err(e),
    }
}

// Manual runs carry no credential, so only an unauthenticated public https remote may be fetched.
pub fn manual_remote_allowed(remote: &str) -> bool {
    #[cfg(feature = "test-support")]
    if LOCAL_MANUAL_SOURCES.load(std::sync::atomic::Ordering::Relaxed) {
        return true;
    }
    sentinel_protocol::source::manual_destination_allowed(remote)
}

#[cfg(feature = "test-support")]
static LOCAL_MANUAL_SOURCES: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Switches the manual-destination policy off for the whole process. Only
/// built with the `test-support` feature, which dev-dependencies enable and
/// no shipped binary does.
#[cfg(feature = "test-support")]
#[doc(hidden)]
pub fn permit_any_manual_source_for_tests() {
    LOCAL_MANUAL_SOURCES.store(true, std::sync::atomic::Ordering::Relaxed);
}

pub fn validate_manual(
    conn: &Connection,
    repo: RepoId,
    source: &sentinel_pipeline::PinnedSource,
) -> Result<()> {
    match load_metadata(conn, repo) {
        Ok(_) => validate_source(conn, repo, source),
        Err(Error::NotFound) if manual_remote_allowed(&source.repo) => Ok(()),
        Err(Error::NotFound) => Err(Error::InvalidInput("manual source remote")),
        Err(e) => Err(e),
    }
}

pub fn attempt_repo(
    conn: &Connection,
    worker: WorkerId,
    attempt: AttemptId,
    now: UnixMillis,
) -> Result<(TenantId, RepoId)> {
    let (tenant,repo): ([u8;16],[u8;16]) = conn.query_row("SELECT r.tenant_id,r.id FROM attempts a JOIN jobs j ON j.id=a.job_id JOIN runs x ON x.id=j.run_id JOIN repos r ON r.id=x.repo_id JOIN tenants t ON t.id=r.tenant_id AND t.active=1 JOIN workers w ON w.id=a.worker_id AND w.revoked_ms IS NULL JOIN pools p ON p.id=w.pool_id AND p.active=1 LEFT JOIN pool_grants g ON g.pool_id=p.id AND g.tenant_id=t.id WHERE a.id=?1 AND a.worker_id=?2 AND a.released_ms IS NULL AND a.acked_ms IS NOT NULL AND a.lease_until_ms>?3 AND j.fence=a.fence AND j.cancel_requested=0 AND x.cancel_requested=0 AND j.state_code IN (2,3) AND (p.owner_tenant_id=t.id OR g.tenant_id IS NOT NULL)",params![attempt.as_bytes(),worker.as_bytes(),now.0],|r|Ok((r.get(0)?,r.get(1)?))).optional()?.ok_or(Error::NotFound)?;
    Ok((
        TenantId::from_bytes(tenant).map_err(|_| Error::Corrupt("tenant"))?,
        RepoId::from_bytes(repo).map_err(|_| Error::Corrupt("repo"))?,
    ))
}

pub fn issue(
    conn: &Connection,
    tenant: TenantId,
    repo: RepoId,
    key: &Key,
    now: UnixMillis,
) -> Result<Access> {
    // One statement: the terms, version and ciphertext come from one row image, so a concurrent rotation cannot mix them.
    type Row = (Vec<u8>, i64, bool, Option<[u8; 16]>, Vec<u8>);
    let (binding, version, revoked, installation, sealed): Row = conn
        .prepare_cached(
            "SELECT b.binding, b.version, b.revoked, b.installation_id, b.credential
             FROM source_bindings b JOIN tenants t ON t.id = b.tenant_id AND t.active = 1
             WHERE b.repo_id = ?1 AND b.tenant_id = ?2",
        )?
        .query_row(params![repo.as_bytes(), tenant.as_bytes()], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
        })
        .optional()?
        .ok_or(Error::NotFound)?;
    if revoked || installation.is_some() {
        return Err(Error::Forbidden);
    }
    let version = u64::try_from(version).map_err(|_| Error::Corrupt("source version"))?;
    let bytes = key
        .open(&context(tenant, repo, version), &sealed)
        .map_err(|_| Error::Corrupt("sealed source credential"))?;
    let access = Access {
        binding: serde_json::from_slice(&binding).map_err(|_| Error::Corrupt("source binding"))?,
        version,
        expires_ms: now.0.saturating_add(60_000),
        credential: serde_json::from_slice(&bytes)
            .map_err(|_| Error::Corrupt("source credential"))?,
    };
    if !access.validate(now.0) {
        return Err(Error::Corrupt("source access"));
    }
    Ok(access)
}
