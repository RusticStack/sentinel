//! Tenant-owned sealed secrets and explicit repository/job/step eligibility.
//! This module exposes metadata to clients; plaintext has no read API. Only
//! fenced preparation may open a sealed value for an authorized attempt.
use std::sync::Arc;

use rusqlite::{Connection, OptionalExtension, Transaction, params};
use sentinel_auth::sealed::{Key, secret_context};
use sentinel_core::{
    AttemptId, Fence, RepoId, SecretId, TenantId, UnixMillis, UserId, WorkerId,
    auth::{Permissions, Principal},
};
use sentinel_protocol::idempotency::{Fingerprint, IDEMPOTENCY_TTL_MS, IdempotencyKey};

use crate::{Error, Result, Store, auth, dispatch};

pub const MAX_VALUE: usize = 65_536;

#[derive(Clone, Copy)]
pub struct Idempotency<'a> {
    pub tenant: TenantId,
    pub principal: &'a str,
    pub route: &'a str,
    pub key: IdempotencyKey,
    /// A keyed MAC of the request (`Key::fingerprinter`), never an unkeyed
    /// digest of a value: this row is stored beside the ciphertext.
    pub fingerprint: Fingerprint,
}

/// Return a completed metadata-only response for an identical secret write.
/// The write and saved response share the same transaction, so there is no
/// durable in-flight state after a crash. A key reused for a different
/// request is [`Error::IdempotencyMismatch`], not a version conflict.
pub fn idempotency_replay(
    tx: &Transaction<'_>,
    idempotency: Idempotency<'_>,
    now: UnixMillis,
) -> Result<Option<Vec<u8>>> {
    let stored: Option<(Vec<u8>, i64, Vec<u8>)> = tx
        .prepare_cached(
            "SELECT fingerprint,created_ms,response_json FROM secret_idempotency
             WHERE tenant_id=?1 AND principal=?2 AND route=?3 AND key=?4",
        )?
        .query_row(
            params![
                idempotency.tenant.as_bytes(),
                idempotency.principal,
                idempotency.route,
                idempotency.key.as_str()
            ],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    let Some((bytes, created, response)) = stored else {
        return Ok(None);
    };
    if created < now.0.saturating_sub(IDEMPOTENCY_TTL_MS) {
        tx.execute(
            "DELETE FROM secret_idempotency WHERE tenant_id=?1 AND principal=?2 AND route=?3 AND key=?4",
            params![
                idempotency.tenant.as_bytes(),
                idempotency.principal,
                idempotency.route,
                idempotency.key.as_str()
            ],
        )?;
        return Ok(None);
    }
    let stored: [u8; 16] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| Error::Corrupt("secret_idempotency.fingerprint"))?;
    if stored != idempotency.fingerprint.0.to_le_bytes() {
        return Err(Error::IdempotencyMismatch);
    }
    Ok(Some(response))
}

/// Save only a bounded JSON result containing secret metadata, never values.
pub fn idempotency_save(
    tx: &Transaction<'_>,
    idempotency: Idempotency<'_>,
    response: &[u8],
    now: UnixMillis,
) -> Result<()> {
    if !(2..=65_536).contains(&response.len()) {
        return Err(Error::InvalidInput("secret response"));
    }
    tx.prepare_cached(
        "INSERT INTO secret_idempotency(tenant_id,principal,route,key,fingerprint,created_ms,response_json)
         VALUES(?1,?2,?3,?4,?5,?6,?7)
         ON CONFLICT(tenant_id,principal,route,key) DO UPDATE SET
           fingerprint=excluded.fingerprint,created_ms=excluded.created_ms,response_json=excluded.response_json",
    )?
    .execute(params![
        idempotency.tenant.as_bytes(),
        idempotency.principal,
        idempotency.route,
        idempotency.key.as_str(),
        idempotency.fingerprint.0.to_le_bytes(),
        now.0,
        response
    ])?;
    Ok(())
}

/// Bound retained secret-write retry records independently of ordinary run
/// idempotency records. The controller maintenance tick calls this in small
/// indexed batches.
pub fn purge_idempotency(store: &crate::Store, now: UnixMillis, limit: u32) -> Result<usize> {
    let cutoff = now.0 - IDEMPOTENCY_TTL_MS;
    store.writer().write(move |tx| {
        Ok(tx.execute(
            "DELETE FROM secret_idempotency WHERE (tenant_id,principal,route,key) IN (
               SELECT tenant_id,principal,route,key FROM secret_idempotency
               WHERE created_ms < ?1 ORDER BY created_ms LIMIT ?2)",
            params![cutoff, limit],
        )?)
    })
}

type MetadataRow = (
    [u8; 16],
    [u8; 16],
    Option<[u8; 16]>,
    String,
    i64,
    bool,
    i64,
    i64,
);

pub struct Update<'a> {
    pub scope: Scope,
    pub name: &'a str,
    pub expected: u64,
    pub value: &'a [u8],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scope {
    Tenant(TenantId),
    Repo(RepoId),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Metadata {
    pub id: SecretId,
    pub tenant: TenantId,
    pub repo: Option<RepoId>,
    pub name: String,
    pub version: u64,
    pub active: bool,
    pub created_ms: i64,
    pub updated_ms: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Binding {
    pub repo: RepoId,
    /// Empty means every job, but a job must still declare the secret.
    pub job: String,
    /// Empty means all steps of this job.
    pub step: String,
    pub name: String,
    pub secret: SecretId,
    pub override_tenant: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Resolved {
    pub secret: SecretId,
    pub version: u64,
    pub scope: Scope,
    pub name: String,
}

pub struct PreparedDelivery {
    pub fence: Fence,
    /// One bounded postcard encoding, ready for the link to chunk directly.
    pub encoded: sentinel_protocol::secrets::SecretBytes,
}

fn name_valid(name: &str) -> bool {
    let bytes = name.as_bytes();
    (1..=64).contains(&bytes.len())
        && !bytes[0].is_ascii_digit()
        && bytes
            .iter()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || *b == b'_')
}

fn selector_valid(value: &str) -> bool {
    value.is_empty() || sentinel_pipeline::schema::valid_id(value)
}

fn tenant_secret_admin(conn: &Connection, principal: Principal, tenant: TenantId) -> Result<()> {
    if !principal.permissions.contains(Permissions::TENANT_ADMIN)
        || principal.repo.is_some()
        || principal.tenant.is_some_and(|id| id != tenant)
    {
        return Err(Error::NotFound);
    }
    let allowed: bool = conn
        .prepare_cached(
            "SELECT EXISTS(SELECT 1 FROM memberships m JOIN users u ON u.id=m.user_id
             JOIN tenants t ON t.id=m.tenant_id WHERE m.tenant_id=?1 AND m.user_id=?2
             AND m.role=3 AND u.kind=0 AND u.active=1 AND t.active=1)",
        )?
        .query_row(params![tenant.as_bytes(), principal.user.as_bytes()], |r| {
            r.get(0)
        })?;
    if allowed {
        Ok(())
    } else {
        Err(Error::NotFound)
    }
}

fn scope_owner(
    conn: &Connection,
    principal: Principal,
    scope: Scope,
    write: bool,
) -> Result<(TenantId, Option<RepoId>)> {
    match scope {
        Scope::Repo(repo) => {
            let tenant = if write {
                auth::require_repo(conn, principal, repo, Permissions::WRITE_SECRETS)?
            } else {
                auth::require_repo(conn, principal, repo, Permissions::READ).or_else(|e| {
                    if matches!(e, Error::NotFound) {
                        auth::require_repo(conn, principal, repo, Permissions::WRITE_SECRETS)
                    } else {
                        Err(e)
                    }
                })?
            };
            Ok((tenant, Some(repo)))
        }
        Scope::Tenant(tenant) => {
            if write {
                tenant_secret_admin(conn, principal, tenant)?;
            } else {
                auth::require_tenant_member(conn, principal, tenant, false).or_else(|e| {
                    if matches!(e, Error::NotFound) {
                        tenant_secret_admin(conn, principal, tenant)
                    } else {
                        Err(e)
                    }
                })?;
            }
            Ok((tenant, None))
        }
    }
}

/// Check current store authority for an operation before returning a cached
/// idempotent response. A retry must never preserve access after a grant or
/// membership was removed.
pub fn authorize(conn: &Connection, principal: Principal, scope: Scope, write: bool) -> Result<()> {
    scope_owner(conn, principal, scope, write).map(|_| ())
}

fn metadata_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<MetadataRow> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
        row.get(6)?,
        row.get(7)?,
    ))
}
fn decode(row: MetadataRow) -> Result<Metadata> {
    Ok(Metadata {
        id: SecretId::from_bytes(row.0).map_err(|_| Error::Corrupt("secret id"))?,
        tenant: TenantId::from_bytes(row.1).map_err(|_| Error::Corrupt("secret tenant"))?,
        repo: row
            .2
            .map(RepoId::from_bytes)
            .transpose()
            .map_err(|_| Error::Corrupt("secret repo"))?,
        name: row.3,
        version: u64::try_from(row.4).map_err(|_| Error::Corrupt("secret version"))?,
        active: row.5,
        created_ms: row.6,
        updated_ms: row.7,
    })
}

struct Audit<'a> {
    repo: Option<RepoId>,
    actor: Option<UserId>,
    attempt: Option<AttemptId>,
    action: &'a str,
    result: &'a str,
}
fn audit(tx: &Transaction<'_>, meta: &Metadata, event: Audit<'_>, now: UnixMillis) -> Result<()> {
    tx.prepare_cached(
        "INSERT INTO secret_audit(tenant_id,repo_id,secret_id,version,actor,attempt_id,action,result,at_ms)
         VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",
    )?
    .execute(params![
        meta.tenant.as_bytes(),
        event.repo.as_ref().map(RepoId::as_bytes),
        meta.id.as_bytes(),
        meta.version as i64,
        event.actor.as_ref().map(UserId::as_bytes),
        event.attempt.as_ref().map(AttemptId::as_bytes),
        event.action,
        event.result,
        now.0
    ])?;
    Ok(())
}

/// Create or rotate using compare-and-set. `expected=0` creates; later writes
/// require the observed current version. Old versions remain sealed until
/// explicitly revoked for audit and history; each new attempt resolves current.
pub fn put(
    tx: &Transaction<'_>,
    principal: Principal,
    update: Update<'_>,
    key: &Key,
    now: UnixMillis,
) -> Result<Metadata> {
    let owner = scope_owner(tx, principal, update.scope, true)?;
    put_owned(tx, principal.user, owner, &update, key, now)
}

/// An atomic multi-name write (env-file import): authority is checked once
/// for the scope, then every entry is created or rotated in this
/// transaction. Any refusal rolls the whole import back with the caller's
/// transaction.
pub fn put_all<'a>(
    tx: &Transaction<'_>,
    principal: Principal,
    scope: Scope,
    entries: impl IntoIterator<Item = (&'a str, u64, &'a [u8])>,
    key: &Key,
    now: UnixMillis,
) -> Result<Vec<Metadata>> {
    let owner = scope_owner(tx, principal, scope, true)?;
    let entries = entries.into_iter();
    let mut out = Vec::with_capacity(entries.size_hint().0);
    for (name, expected, value) in entries {
        out.push(put_owned(
            tx,
            principal.user,
            owner,
            &Update {
                scope,
                name,
                expected,
                value,
            },
            key,
            now,
        )?);
    }
    Ok(out)
}

fn put_owned(
    tx: &Transaction<'_>,
    actor: UserId,
    (tenant, repo): (TenantId, Option<RepoId>),
    update: &Update<'_>,
    key: &Key,
    now: UnixMillis,
) -> Result<Metadata> {
    let Update {
        name,
        expected,
        value,
        ..
    } = *update;
    if !name_valid(name) || !(1..=MAX_VALUE).contains(&value.len()) || expected >= i64::MAX as u64 {
        return Err(Error::InvalidInput("secret name, value or version"));
    }
    let version = expected + 1;
    let (id, created_ms) = if expected == 0 {
        (SecretId::new(), now.0)
    } else {
        let current = lookup(tx, tenant, repo, name)
            .map(Some)
            .or_else(|e| match e {
                Error::NotFound => Ok(None),
                e => Err(e),
            })?
            .filter(|meta| meta.active && meta.version == expected)
            .ok_or(Error::Conflict)?;
        (current.id, current.created_ms)
    };
    let context = secret_context(
        tenant.as_bytes(),
        repo.as_ref().map(RepoId::as_bytes),
        name,
        version,
    );
    let sealed = key.seal(&context, value);
    if expected == 0 {
        let inserted = tx
            .prepare_cached(
                "INSERT INTO secrets(id,tenant_id,scope_repo_id,name,current_version,created_ms,updated_ms)
                 VALUES(?1,?2,?3,?4,?5,?6,?6) ON CONFLICT DO NOTHING",
            )?
            .execute(params![
                id.as_bytes(),
                tenant.as_bytes(),
                repo.as_ref().map(RepoId::as_bytes),
                name,
                version as i64,
                now.0
            ])?;
        if inserted == 0 {
            return Err(Error::Conflict);
        }
    } else if tx
        .prepare_cached(
            "UPDATE secrets SET current_version=?2,updated_ms=?3
             WHERE id=?1 AND current_version=?4 AND active=1",
        )?
        .execute(params![
            id.as_bytes(),
            version as i64,
            now.0,
            expected as i64
        ])?
        != 1
    {
        return Err(Error::Conflict);
    }
    tx.prepare_cached(
        "INSERT INTO secret_versions(secret_id,version,sealed,created_ms) VALUES(?1,?2,?3,?4)",
    )?
    .execute(params![id.as_bytes(), version as i64, sealed, now.0])?;
    let meta = Metadata {
        id,
        tenant,
        repo,
        name: name.to_owned(),
        version,
        active: true,
        created_ms,
        updated_ms: now.0,
    };
    audit(
        tx,
        &meta,
        Audit {
            repo,
            actor: Some(actor),
            attempt: None,
            action: if expected == 0 { "create" } else { "rotate" },
            result: "ok",
        },
        now,
    )?;
    Ok(meta)
}

/// Read only a bounded name/version/timestamp record; ciphertext is not
/// projected. A missing or unauthorized scope has the same result.
pub fn describe(
    conn: &Connection,
    principal: Principal,
    scope: Scope,
    name: &str,
) -> Result<Metadata> {
    let (tenant, repo) = scope_owner(conn, principal, scope, false)?;
    if !name_valid(name) {
        return Err(Error::InvalidInput("secret name"));
    }
    lookup(conn, tenant, repo, name)
}

/// One name in one scope. Each scope has its own statement so each is served
/// by its unique partial index (`secrets_tenant_name`, `secrets_repo_name`).
fn lookup(
    conn: &Connection,
    tenant: TenantId,
    repo: Option<RepoId>,
    name: &str,
) -> Result<Metadata> {
    let row = match repo {
        None => conn
            .prepare_cached(
                "SELECT id,tenant_id,scope_repo_id,name,current_version,active,created_ms,updated_ms
                 FROM secrets WHERE tenant_id=?1 AND scope_repo_id IS NULL AND name=?2",
            )?
            .query_row(params![tenant.as_bytes(), name], metadata_row)
            .optional()?,
        Some(repo) => conn
            .prepare_cached(
                "SELECT id,tenant_id,scope_repo_id,name,current_version,active,created_ms,updated_ms
                 FROM secrets WHERE scope_repo_id=?1 AND name=?2 AND tenant_id=?3",
            )?
            .query_row(
                params![repo.as_bytes(), name, tenant.as_bytes()],
                metadata_row,
            )
            .optional()?,
    };
    decode(row.ok_or(Error::NotFound)?)
}

/// Keyset pagination by name. No ciphertext or value-derived fingerprint is
/// read, even temporarily. At most 100 metadata records per call. A tenant
/// page and a repository page each walk only their own partial index, never
/// the other scope's names (P10S-11).
pub fn list(
    conn: &Connection,
    principal: Principal,
    scope: Scope,
    after: &str,
    limit: u16,
) -> Result<Vec<Metadata>> {
    let (tenant, repo) = scope_owner(conn, principal, scope, false)?;
    if !(1..=100).contains(&limit) || after.len() > 64 {
        return Err(Error::InvalidInput("secret page"));
    }
    let mut stmt = match repo {
        None => conn.prepare_cached(
            "SELECT id,tenant_id,scope_repo_id,name,current_version,active,created_ms,updated_ms
             FROM secrets WHERE tenant_id=?1 AND scope_repo_id IS NULL AND name>?2
             ORDER BY name LIMIT ?3",
        )?,
        Some(_) => conn.prepare_cached(
            "SELECT id,tenant_id,scope_repo_id,name,current_version,active,created_ms,updated_ms
             FROM secrets WHERE scope_repo_id=?1 AND name>?2 ORDER BY name LIMIT ?3",
        )?,
    };
    let owner: &[u8; 16] = match &repo {
        None => tenant.as_bytes(),
        Some(repo) => repo.as_bytes(),
    };
    stmt.query_map(params![owner, after, limit], metadata_row)?
        .map(|r| decode(r?))
        .collect()
}

/// Allow (or stop allowing) a tenant secret in exactly one owned
/// repository. Idempotent: setting the state it already has changes and
/// audits nothing. Removing the allow entry removes its bindings in the
/// same transaction, and resolution rechecks the allowlist anyway.
pub fn allow_repo(
    tx: &Transaction<'_>,
    principal: Principal,
    tenant: TenantId,
    name: &str,
    repo: RepoId,
    allow: bool,
    now: UnixMillis,
) -> Result<()> {
    tenant_secret_admin(tx, principal, tenant)?;
    if !name_valid(name) {
        return Err(Error::InvalidInput("secret name"));
    }
    let meta = lookup(tx, tenant, None, name)?;
    let owner: [u8; 16] = tx
        .prepare_cached("SELECT tenant_id FROM repos WHERE id=?1")?
        .query_row([repo.as_bytes()], |r| r.get(0))
        .optional()?
        .ok_or(Error::NotFound)?;
    let owner = TenantId::from_bytes(owner).map_err(|_| Error::Corrupt("repo owner"))?;
    if owner != tenant {
        return Err(Error::NotFound);
    }
    let changed = if allow {
        if !meta.active {
            return Err(Error::NotFound);
        }
        tx.prepare_cached(
            "INSERT INTO secret_repo_allow(secret_id,tenant_id,repo_id,granted_ms)
             VALUES(?1,?2,?3,?4) ON CONFLICT(secret_id,repo_id) DO NOTHING",
        )?
        .execute(params![
            meta.id.as_bytes(),
            tenant.as_bytes(),
            repo.as_bytes(),
            now.0
        ])?
    } else {
        let removed = tx
            .prepare_cached("DELETE FROM secret_repo_allow WHERE secret_id=?1 AND repo_id=?2")?
            .execute(params![meta.id.as_bytes(), repo.as_bytes()])?;
        tx.prepare_cached("DELETE FROM secret_bindings WHERE secret_id=?1 AND repo_id=?2")?
            .execute(params![meta.id.as_bytes(), repo.as_bytes()])?;
        removed
    };
    if changed == 0 {
        return Ok(());
    }
    audit(
        tx,
        &meta,
        Audit {
            repo: Some(repo),
            actor: Some(principal.user),
            attempt: None,
            action: if allow { "allow" } else { "deny" },
            result: "ok",
        },
        now,
    )
}

/// The repositories a tenant secret is allowed in: a keyset page by
/// repository ID, at most 100. Readable by a tenant member or its
/// administrator; names only, never a value.
pub fn list_allowed(
    conn: &Connection,
    principal: Principal,
    tenant: TenantId,
    name: &str,
    after: Option<RepoId>,
    limit: u16,
) -> Result<Vec<(RepoId, String)>> {
    scope_owner(conn, principal, Scope::Tenant(tenant), false)?;
    if !name_valid(name) || !(1..=100).contains(&limit) {
        return Err(Error::InvalidInput("secret allowlist page"));
    }
    let meta = lookup(conn, tenant, None, name)?;
    let after = after.map_or([0u8; 16], |repo| *repo.as_bytes());
    let mut stmt = conn.prepare_cached(
        "SELECT a.repo_id,r.name FROM secret_repo_allow a JOIN repos r ON r.id=a.repo_id
         WHERE a.secret_id=?1 AND a.repo_id>?2 ORDER BY a.repo_id LIMIT ?3",
    )?;
    stmt.query_map(params![meta.id.as_bytes(), after, limit], |r| {
        Ok((r.get::<_, [u8; 16]>(0)?, r.get::<_, String>(1)?))
    })?
    .map(|row| {
        let (id, name) = row?;
        Ok((
            RepoId::from_bytes(id).map_err(|_| Error::Corrupt("repo id"))?,
            name,
        ))
    })
    .collect()
}

/// Permanently disable a secret and every retained version. Its name is
/// reserved, so a concurrent or stale create cannot silently resurrect it.
pub fn delete(
    tx: &Transaction<'_>,
    principal: Principal,
    scope: Scope,
    name: &str,
    expected: u64,
    now: UnixMillis,
) -> Result<Metadata> {
    let (tenant, repo) = scope_owner(tx, principal, scope, true)?;
    let mut meta = lookup(tx, tenant, repo, name)?;
    if !meta.active || meta.version != expected {
        return Err(Error::Conflict);
    }
    tx.execute(
        "UPDATE secrets SET active=0,updated_ms=?2 WHERE id=?1 AND current_version=?3 AND active=1",
        params![meta.id.as_bytes(), now.0, expected as i64],
    )?;
    tx.execute(
        "UPDATE secret_versions SET revoked=1 WHERE secret_id=?1",
        [meta.id.as_bytes()],
    )?;
    audit(
        tx,
        &meta,
        Audit {
            repo,
            actor: Some(principal.user),
            attempt: None,
            action: "delete",
            result: "ok",
        },
        now,
    )?;
    meta.active = false;
    meta.updated_ms = now.0;
    Ok(meta)
}

/// Revoke one historical version without changing the current number. A
/// revoked current version makes resolution fail until a fresh rotation.
/// Idempotent: revoking an already revoked version changes and audits
/// nothing; a version that never existed is `NotFound`.
pub fn revoke_version(
    tx: &Transaction<'_>,
    principal: Principal,
    scope: Scope,
    name: &str,
    version: u64,
    now: UnixMillis,
) -> Result<()> {
    let (tenant, repo) = scope_owner(tx, principal, scope, true)?;
    if !name_valid(name) || version == 0 || version > i64::MAX as u64 {
        return Err(Error::InvalidInput("secret name or version"));
    }
    let mut meta = lookup(tx, tenant, repo, name)?;
    if !meta.active || version > meta.version {
        return Err(Error::NotFound);
    }
    if tx
        .prepare_cached(
            "UPDATE secret_versions SET revoked=1 WHERE secret_id=?1 AND version=?2 AND revoked=0",
        )?
        .execute(params![meta.id.as_bytes(), version as i64])?
        != 1
    {
        return Ok(());
    }
    meta.version = version;
    audit(
        tx,
        &meta,
        Audit {
            repo,
            actor: Some(principal.user),
            attempt: None,
            action: "revoke",
            result: "ok",
        },
        now,
    )
}

/// A repository secret writer can bind an existing repo secret or an
/// allowlisted tenant secret; broad tenant-secret administration stays with
/// the tenant administrator. Repo operators have no implicit write authority.
pub fn bind(
    tx: &Transaction<'_>,
    principal: Principal,
    binding: &Binding,
    now: UnixMillis,
) -> Result<()> {
    let tenant = auth::require_repo(tx, principal, binding.repo, Permissions::WRITE_SECRETS)?;
    bind_owned(tx, principal.user, tenant, binding, now)
}

/// [`bind`] by name: the source is the repository's own secret of that name,
/// or with `from_tenant` the tenant secret, which must be allowlisted for the
/// repository. A missing or foreign source is `NotFound`.
#[allow(clippy::too_many_arguments)]
pub fn bind_named(
    tx: &Transaction<'_>,
    principal: Principal,
    repo: RepoId,
    job: &str,
    step: &str,
    name: &str,
    from_tenant: bool,
    override_tenant: bool,
    now: UnixMillis,
) -> Result<Binding> {
    let tenant = auth::require_repo(tx, principal, repo, Permissions::WRITE_SECRETS)?;
    if !name_valid(name) {
        return Err(Error::InvalidInput("secret binding"));
    }
    let source = lookup(tx, tenant, (!from_tenant).then_some(repo), name)?;
    let binding = Binding {
        repo,
        job: job.to_owned(),
        step: step.to_owned(),
        name: name.to_owned(),
        secret: source.id,
        override_tenant,
    };
    bind_owned(tx, principal.user, tenant, &binding, now)?;
    Ok(binding)
}

fn bind_owned(
    tx: &Transaction<'_>,
    actor: UserId,
    tenant: TenantId,
    binding: &Binding,
    now: UnixMillis,
) -> Result<()> {
    if !name_valid(&binding.name)
        || !selector_valid(&binding.job)
        || !selector_valid(&binding.step)
        || (binding.job.is_empty() && !binding.step.is_empty())
    {
        return Err(Error::InvalidInput("secret binding"));
    }
    let row = tx
        .prepare_cached(
            "SELECT id,tenant_id,scope_repo_id,name,current_version,active,created_ms,updated_ms
             FROM secrets WHERE id=?1",
        )?
        .query_row([binding.secret.as_bytes()], metadata_row)
        .optional()?
        .ok_or(Error::NotFound)?;
    let meta = decode(row)?;
    if meta.tenant != tenant
        || !meta.active
        || meta.name != binding.name
        || meta.repo.is_some_and(|r| r != binding.repo)
    {
        return Err(Error::NotFound);
    }
    if meta.repo.is_none() {
        if !allowed_in(tx, meta.id, binding.repo)? || binding.override_tenant {
            return Err(Error::NotFound);
        }
        if tenant_name_exists_repo(tx, binding.repo, &binding.name)? {
            return Err(Error::Conflict);
        }
    } else if !binding.override_tenant
        && tenant_name_exists(tx, tenant, binding.repo, &binding.name)?
    {
        return Err(Error::Conflict);
    }
    tx.prepare_cached(
        "DELETE FROM secret_bindings WHERE repo_id=?1 AND job=?2 AND step=?3 AND name=?4",
    )?
    .execute(params![
        binding.repo.as_bytes(),
        binding.job,
        binding.step,
        binding.name
    ])?;
    tx.prepare_cached(
        "INSERT INTO secret_bindings(tenant_id,repo_id,job,step,name,secret_id,override_tenant,created_ms)
         VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
    )?
    .execute(params![
        tenant.as_bytes(),
        binding.repo.as_bytes(),
        binding.job,
        binding.step,
        binding.name,
        meta.id.as_bytes(),
        binding.override_tenant,
        now.0
    ])?;
    audit(
        tx,
        &meta,
        Audit {
            repo: Some(binding.repo),
            actor: Some(actor),
            attempt: None,
            action: "bind",
            result: "ok",
        },
        now,
    )
}

/// Remove one binding. Idempotent: removing a binding that does not exist
/// changes and audits nothing, so a retried unbind is not an error.
pub fn unbind(
    tx: &Transaction<'_>,
    principal: Principal,
    repo: RepoId,
    job: &str,
    step: &str,
    name: &str,
    now: UnixMillis,
) -> Result<()> {
    auth::require_repo(tx, principal, repo, Permissions::WRITE_SECRETS)?;
    if !name_valid(name) || !selector_valid(job) || !selector_valid(step) {
        return Err(Error::InvalidInput("secret binding"));
    }
    let Some(secret) = tx
        .prepare_cached(
            "SELECT secret_id FROM secret_bindings WHERE repo_id=?1 AND job=?2 AND step=?3 AND name=?4",
        )?
        .query_row(params![repo.as_bytes(), job, step, name], |r| {
            r.get::<_, [u8; 16]>(0)
        })
        .optional()?
    else {
        return Ok(());
    };
    let secret = SecretId::from_bytes(secret).map_err(|_| Error::Corrupt("secret id"))?;
    let meta = decode(
        tx.prepare_cached(
            "SELECT id,tenant_id,scope_repo_id,name,current_version,active,created_ms,updated_ms
             FROM secrets WHERE id=?1",
        )?
        .query_row([secret.as_bytes()], metadata_row)?,
    )?;
    tx.prepare_cached(
        "DELETE FROM secret_bindings WHERE repo_id=?1 AND job=?2 AND step=?3 AND name=?4",
    )?
    .execute(params![repo.as_bytes(), job, step, name])?;
    audit(
        tx,
        &meta,
        Audit {
            repo: Some(repo),
            actor: Some(principal.user),
            attempt: None,
            action: "unbind",
            result: "ok",
        },
        now,
    )
}

/// Metadata-only keyset page, scoped to one authorized repository.
pub fn list_bindings(
    conn: &Connection,
    principal: Principal,
    repo: RepoId,
    after: Option<(&str, &str, &str)>,
    limit: u16,
) -> Result<Vec<Binding>> {
    scope_owner(conn, principal, Scope::Repo(repo), false)?;
    if !(1..=100).contains(&limit)
        || after.is_some_and(|(j, s, n)| !selector_valid(j) || !selector_valid(s) || !name_valid(n))
    {
        return Err(Error::InvalidInput("binding page"));
    }
    let (job, step, name) = after.unwrap_or(("", "", ""));
    let mut stmt=conn.prepare_cached("SELECT job,step,name,secret_id,override_tenant FROM secret_bindings WHERE repo_id=?1 AND (job,step,name)>(?2,?3,?4) ORDER BY job,step,name LIMIT ?5")?;
    stmt.query_map(params![repo.as_bytes(), job, step, name, limit], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, [u8; 16]>(3)?,
            r.get::<_, bool>(4)?,
        ))
    })?
    .map(|r| {
        let (job, step, name, id, override_tenant) = r?;
        Ok(Binding {
            repo,
            job,
            step,
            name,
            secret: SecretId::from_bytes(id).map_err(|_| Error::Corrupt("secret id"))?,
            override_tenant,
        })
    })
    .collect()
}

fn allowed_in(conn: &Connection, secret: SecretId, repo: RepoId) -> Result<bool> {
    Ok(conn
        .prepare_cached(
            "SELECT EXISTS(SELECT 1 FROM secret_repo_allow WHERE secret_id=?1 AND repo_id=?2)",
        )?
        .query_row(params![secret.as_bytes(), repo.as_bytes()], |r| r.get(0))?)
}

fn tenant_name_exists(
    conn: &Connection,
    tenant: TenantId,
    repo: RepoId,
    name: &str,
) -> Result<bool> {
    Ok(conn
        .prepare_cached(
            "SELECT EXISTS(SELECT 1 FROM secrets s JOIN secret_repo_allow a ON a.secret_id=s.id AND a.repo_id=?2
             WHERE s.tenant_id=?1 AND s.scope_repo_id IS NULL AND s.name=?3 AND s.active=1)",
        )?
        .query_row(
            params![tenant.as_bytes(), repo.as_bytes(), name],
            |r| r.get(0),
        )?)
}

fn tenant_name_exists_repo(conn: &Connection, repo: RepoId, name: &str) -> Result<bool> {
    Ok(conn
        .prepare_cached(
            "SELECT EXISTS(SELECT 1 FROM secrets WHERE scope_repo_id=?1 AND name=?2 AND active=1)",
        )?
        .query_row(params![repo.as_bytes(), name], |r| r.get(0))?)
}

/// Why resolution refused a target, carried out of a failed preparation so
/// the refusal can be audited (P10S-6). IDs only; never a value.
struct Refused {
    secret: Option<SecretId>,
    version: u64,
    /// `denied`: a binding exists but policy refuses it (ambiguity, removed
    /// allowlist). `missing`: no binding, or its version or secret is gone.
    denied: bool,
}

impl Refused {
    fn error(&self) -> Error {
        if self.denied {
            Error::Conflict
        } else {
            Error::NotFound
        }
    }
}

/// Return the current version identity selected by exact step, job, then repo
/// binding. Only fenced preparation may turn this identity into attempt-bound plaintext.
pub fn resolve(
    conn: &Connection,
    repo: RepoId,
    job: &str,
    step: &str,
    name: &str,
) -> Result<Resolved> {
    resolve_detail(conn, repo, job, step, name)?.map_err(|refused| refused.error())
}

type BindingRow = ([u8; 16], [u8; 16], Option<[u8; 16]>, i64, bool, bool, bool);

fn resolve_detail(
    conn: &Connection,
    repo: RepoId,
    job: &str,
    step: &str,
    name: &str,
) -> Result<std::result::Result<Resolved, Refused>> {
    if !name_valid(name) || !selector_valid(job) || !selector_valid(step) || job.is_empty() {
        return Err(Error::InvalidInput("secret selector"));
    }
    let row: Option<BindingRow> = conn
        .prepare_cached(
            "SELECT s.id,s.tenant_id,s.scope_repo_id,s.current_version,s.active,b.override_tenant,
                    EXISTS(SELECT 1 FROM secret_versions v WHERE v.secret_id=s.id
                           AND v.version=s.current_version AND v.revoked=0)
             FROM secret_bindings b JOIN secrets s ON s.id=b.secret_id
             JOIN repos r ON r.id=b.repo_id AND r.tenant_id=b.tenant_id
             JOIN tenants t ON t.id=r.tenant_id AND t.active=1
             WHERE b.repo_id=?1 AND b.name=?2 AND (b.job=?3 OR b.job='') AND (b.step=?4 OR b.step='')
             ORDER BY (b.job=?3) DESC,(b.step=?4 AND b.step!='') DESC LIMIT 1",
        )?
        .query_row(params![repo.as_bytes(), name, job, step], |r| {
            Ok((
                r.get(0)?,
                r.get(1)?,
                r.get(2)?,
                r.get(3)?,
                r.get(4)?,
                r.get(5)?,
                r.get(6)?,
            ))
        })
        .optional()?;
    let Some(row) = row else {
        return Ok(Err(Refused {
            secret: None,
            version: 0,
            denied: false,
        }));
    };
    let id = SecretId::from_bytes(row.0).map_err(|_| Error::Corrupt("secret id"))?;
    let tenant = TenantId::from_bytes(row.1).map_err(|_| Error::Corrupt("secret tenant"))?;
    let version = row.3 as u64;
    let refused = |denied| {
        Ok(Err(Refused {
            secret: Some(id),
            version,
            denied,
        }))
    };
    let scope = if let Some(bytes) = row.2 {
        Scope::Repo(RepoId::from_bytes(bytes).map_err(|_| Error::Corrupt("secret repo"))?)
    } else {
        Scope::Tenant(tenant)
    };
    if !row.4 {
        return refused(false);
    }
    match scope {
        Scope::Tenant(_) => {
            if !allowed_in(conn, id, repo)? || tenant_name_exists_repo(conn, repo, name)? {
                return refused(true);
            }
        }
        Scope::Repo(_) => {
            if !row.5 && tenant_name_exists(conn, tenant, repo, name)? {
                return refused(true);
            }
        }
    }
    if !row.6 {
        return refused(false);
    }
    Ok(Ok(Resolved {
        secret: id,
        version,
        scope,
        name: name.to_owned(),
    }))
}

/// Record actual use only inside the same writer transaction as the
/// preparation decision. The caller holds the fenced delivery transaction.
pub fn audit_use(
    tx: &Transaction<'_>,
    attempt: AttemptId,
    step: &str,
    resolved: &Resolved,
    now: UnixMillis,
) -> Result<()> {
    let (tenant, repo, job): ([u8; 16], [u8; 16], String) = tx
        .prepare_cached(
            "SELECT a.tenant_id,r.repo_id,j.name FROM attempts a
             JOIN jobs j ON j.id=a.job_id AND j.tenant_id=a.tenant_id
             JOIN runs r ON r.id=j.run_id AND r.tenant_id=j.tenant_id WHERE a.id=?1",
        )?
        .query_row([attempt.as_bytes()], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?))
        })
        .optional()?
        .ok_or(Error::NotFound)?;
    let tenant = TenantId::from_bytes(tenant).map_err(|_| Error::Corrupt("attempt tenant"))?;
    let repo = RepoId::from_bytes(repo).map_err(|_| Error::Corrupt("attempt repo"))?;
    if resolve(tx, repo, &job, step, &resolved.name)? != *resolved {
        return Err(Error::Conflict);
    }
    record_use(tx, tenant, repo, attempt, step, resolved, now)
}

/// The use row for a target the caller resolved in this same transaction.
fn record_use(
    tx: &Transaction<'_>,
    tenant: TenantId,
    repo: RepoId,
    attempt: AttemptId,
    step: &str,
    resolved: &Resolved,
    now: UnixMillis,
) -> Result<()> {
    tx.prepare_cached(
        "INSERT INTO secret_audit(tenant_id,repo_id,secret_id,version,actor,attempt_id,step,action,result,at_ms)
         VALUES(?1,?2,?3,?4,NULL,?5,?6,'use','ok',?7)",
    )?
    .execute(params![
        tenant.as_bytes(),
        repo.as_bytes(),
        resolved.secret.as_bytes(),
        resolved.version as i64,
        attempt.as_bytes(),
        step,
        now.0
    ])?;
    Ok(())
}

/// A target an attempt was refused, recorded after its preparation rolled
/// back: tenant, repository, attempt, step, the name and whatever secret
/// ID and version were resolved. Never a value.
struct Refusal {
    tenant: TenantId,
    repo: RepoId,
    step: String,
    name: String,
    refused: Refused,
}

/// Resolve and open only the declared targets of the acknowledged attempt's
/// durable spec. The writer transaction serializes this fence/capability
/// check with revocation, binding changes, version rotation and the use audit.
///
/// A target refused by policy (no binding, an ambiguous name, a removed
/// allowlist entry, a revoked current version) fails the preparation. The
/// caller's transaction then rolls back; [`deliver`] instead commits one
/// `use` audit row with result `denied` or `missing` for the refused target.
pub fn prepare_delivery(
    tx: &Transaction<'_>,
    key: &Key,
    worker: WorkerId,
    attempt: AttemptId,
    now: UnixMillis,
) -> Result<PreparedDelivery> {
    prepare_recorded(tx, key, worker, attempt, now)?
}

/// Prepare an attempt's delivery in one writer transaction. A policy refusal
/// commits only its audit row: the preparation's own writes are rolled back
/// to a savepoint first, so no `use` row survives a refused attempt.
pub fn deliver(
    store: &Store,
    key: Arc<Key>,
    worker: WorkerId,
    attempt: AttemptId,
    now: UnixMillis,
) -> Result<PreparedDelivery> {
    store
        .writer()
        .write(move |tx| prepare_recorded(tx, &key, worker, attempt, now))?
}

fn prepare_recorded(
    tx: &Transaction<'_>,
    key: &Key,
    worker: WorkerId,
    attempt: AttemptId,
    now: UnixMillis,
) -> Result<Result<PreparedDelivery>> {
    tx.execute_batch("SAVEPOINT secret_delivery")?;
    let mut refusal = None;
    match prepare(tx, key, worker, attempt, now, &mut refusal) {
        Ok(prepared) => {
            tx.execute_batch("RELEASE secret_delivery")?;
            Ok(Ok(prepared))
        }
        Err(error) => {
            tx.execute_batch("ROLLBACK TO secret_delivery; RELEASE secret_delivery")?;
            if let Some(refusal) = refusal {
                tx.prepare_cached(
                    "INSERT INTO secret_audit(tenant_id,repo_id,secret_id,name,version,actor,attempt_id,step,action,result,at_ms)
                     VALUES(?1,?2,?3,?4,?5,NULL,?6,?7,'use',?8,?9)",
                )?
                .execute(params![
                    refusal.tenant.as_bytes(),
                    refusal.repo.as_bytes(),
                    refusal.refused.secret.as_ref().map(SecretId::as_bytes),
                    refusal.name,
                    refusal.refused.version as i64,
                    attempt.as_bytes(),
                    refusal.step,
                    if refusal.refused.denied {
                        "denied"
                    } else {
                        "missing"
                    },
                    now.0
                ])?;
            }
            Ok(Err(error))
        }
    }
}

/// A heap buffer wiped when dropped, for postcard output holding values.
struct Wiped(Vec<u8>);

impl Drop for Wiped {
    fn drop(&mut self) {
        self.0.fill(0);
        core::hint::black_box(&mut self.0);
    }
}

/// Encode into a buffer sized once, so no reallocation frees an unwiped
/// copy of already-serialized values (P10S-8).
fn encode_bundle(
    bundle: &sentinel_protocol::secrets::DeliveryBundle,
) -> Result<sentinel_protocol::secrets::SecretBytes> {
    let size = postcard::experimental::serialized_size(bundle)
        .map_err(|_| Error::Corrupt("secret delivery encoding"))?;
    if size > sentinel_protocol::secrets::MAX_DELIVERY_BYTES {
        return Err(Error::InvalidInput("secret delivery size"));
    }
    let mut buffer = Wiped(vec![0; size]);
    let written = postcard::to_slice(bundle, &mut buffer.0)
        .map_err(|_| Error::Corrupt("secret delivery encoding"))?
        .len();
    if written != size {
        return Err(Error::Corrupt("secret delivery encoding"));
    }
    Ok(sentinel_protocol::secrets::SecretBytes::new(
        std::mem::take(&mut buffer.0),
    ))
}

fn prepare(
    tx: &Transaction<'_>,
    key: &Key,
    worker: WorkerId,
    attempt: AttemptId,
    now: UnixMillis,
    refusal: &mut Option<Refusal>,
) -> Result<PreparedDelivery> {
    use sentinel_protocol::secrets::{DeliveryBundle, DeliveryTarget, DeliveryValue, TargetKind};

    if dispatch::spec_gate(tx, worker, attempt)? != dispatch::SpecGate::Ready {
        return Err(Error::NotFound);
    }
    let (tenant, run, job, job_index) = dispatch::attempt_scope(tx, worker, attempt)?;
    let fence: i64 = tx
        .prepare_cached(
            "SELECT a.fence FROM attempts a JOIN workers w ON w.id=a.worker_id
             WHERE a.id=?1 AND a.worker_id=?2 AND a.acked_ms IS NOT NULL
               AND a.released_ms IS NULL AND w.revoked_ms IS NULL",
        )?
        .query_row(params![attempt.as_bytes(), worker.as_bytes()], |row| {
            row.get(0)
        })
        .optional()?
        .ok_or(Error::NotFound)?;
    let (repo, job_name): ([u8; 16], String) = tx
        .prepare_cached(
            "SELECT r.repo_id,j.name FROM jobs j JOIN runs r ON r.id=j.run_id
             WHERE j.id=?1 AND j.tenant_id=?2 AND r.tenant_id=?2 AND r.id=?3",
        )?
        .query_row(
            params![job.as_bytes(), tenant.as_bytes(), run.as_bytes()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?
        .ok_or(Error::NotFound)?;
    let repo = RepoId::from_bytes(repo).map_err(|_| Error::Corrupt("attempt repo"))?;
    let bytes = dispatch::spec_bytes(tx, worker, attempt)?;
    let spec =
        sentinel_pipeline::RunSpec::decode(&bytes).map_err(|_| Error::Corrupt("run spec"))?;
    let compiled = spec
        .pipeline
        .jobs
        .get(job_index as usize)
        .filter(|compiled| compiled.name == job_name)
        .ok_or(Error::Corrupt("job spec index"))?;
    if compiled.spec.registry_auth.is_none()
        && !compiled
            .spec
            .steps
            .iter()
            .any(|step| !step.secrets.is_empty() || !step.secret_files.is_empty())
    {
        return Ok(PreparedDelivery {
            fence: Fence(fence as u64),
            encoded: encode_bundle(&DeliveryBundle::empty())?,
        });
    }
    let (protocol, capabilities): (i64, i64) = tx
        .prepare_cached(
            "SELECT protocol,capabilities FROM workers WHERE id=?1 AND revoked_ms IS NULL",
        )?
        .query_row([worker.as_bytes()], |row| Ok((row.get(0)?, row.get(1)?)))
        .optional()?
        .ok_or(Error::NotFound)?;
    if protocol < 10
        || capabilities as u64 & sentinel_protocol::negotiate::Capabilities::SECRET_DELIVERY.0 == 0
    {
        return Err(Error::Forbidden);
    }

    // Resolve one declared target; a policy refusal is remembered for the
    // audit and fails the preparation.
    let mut resolve_target = |step: &str, name: &str| -> Result<Resolved> {
        match resolve_detail(tx, repo, &job_name, step, name)? {
            Ok(resolved) => Ok(resolved),
            Err(refused) => {
                let error = refused.error();
                *refusal = Some(Refusal {
                    tenant,
                    repo,
                    step: step.to_owned(),
                    name: name.to_owned(),
                    refused,
                });
                Err(error)
            }
        }
    };

    let mut bundle = DeliveryBundle {
        values: Vec::with_capacity(compiled.spec.secrets.len().min(16)),
        targets: Vec::new(),
    };
    let mut value_indices: std::collections::HashMap<(SecretId, u64), u16> =
        std::collections::HashMap::with_capacity(compiled.spec.secrets.len().min(16));
    if let Some(name) = &compiled.spec.registry_auth {
        let resolved = resolve_target("", name)?;
        let identity = (resolved.secret, resolved.version);
        let value_index = match value_indices.get(&identity) {
            Some(index) => *index,
            None => {
                if bundle.values.len() >= sentinel_protocol::secrets::MAX_DELIVERY_VALUES {
                    return Err(Error::InvalidInput("secret delivery values"));
                }
                let value = open_value(tx, key, &resolved)?;
                let index = u16::try_from(bundle.values.len())
                    .map_err(|_| Error::InvalidInput("secret delivery values"))?;
                bundle.values.push(DeliveryValue::new(value));
                if !bundle.within_wire_limit() {
                    return Err(Error::InvalidInput("secret delivery size"));
                }
                value_indices.insert(identity, index);
                index
            }
        };
        record_use(tx, tenant, repo, attempt, "", &resolved, now)?;
        bundle.targets.push(DeliveryTarget {
            step: 0,
            name: name.clone(),
            value: value_index,
            target: TargetKind::RegistryAuth,
        });
        if !bundle.within_wire_limit() {
            return Err(Error::InvalidInput("secret delivery size"));
        }
    }
    for (step_index, step) in compiled.spec.steps.iter().enumerate() {
        let mut step_values: Vec<(String, u16)> = Vec::new();
        let mut target = |name: &str, kind: TargetKind| -> Result<()> {
            let cached = step_values.iter().find(|(existing, _)| existing == name);
            let value_index = if let Some((_, index)) = cached {
                *index
            } else {
                let resolved = resolve_target(&step.id, name)?;
                let identity = (resolved.secret, resolved.version);
                let value_index = match value_indices.get(&identity) {
                    Some(index) => *index,
                    None => {
                        if bundle.values.len() >= sentinel_protocol::secrets::MAX_DELIVERY_VALUES {
                            return Err(Error::InvalidInput("secret delivery values"));
                        }
                        let value = open_value(tx, key, &resolved)?;
                        let index = u16::try_from(bundle.values.len())
                            .map_err(|_| Error::InvalidInput("secret delivery values"))?;
                        bundle.values.push(DeliveryValue::new(value));
                        if !bundle.within_wire_limit() {
                            return Err(Error::InvalidInput("secret delivery size"));
                        }
                        value_indices.insert(identity, index);
                        index
                    }
                };
                record_use(tx, tenant, repo, attempt, &step.id, &resolved, now)?;
                step_values.push((name.to_owned(), value_index));
                value_index
            };
            if bundle.targets.len() >= sentinel_protocol::secrets::MAX_DELIVERY_TARGETS {
                return Err(Error::InvalidInput("secret delivery targets"));
            }
            bundle.targets.push(DeliveryTarget {
                step: step_index as u16,
                name: name.to_owned(),
                value: value_index,
                target: kind,
            });
            if !bundle.within_wire_limit() {
                return Err(Error::InvalidInput("secret delivery size"));
            }
            Ok(())
        };
        for name in &step.secrets {
            target(name, TargetKind::Environment)?;
        }
        for file in &step.secret_files {
            target(
                &file.name,
                TargetKind::File {
                    path: file.path.clone(),
                },
            )?;
        }
    }
    if !bundle.valid() {
        return Err(Error::Corrupt("secret delivery bundle"));
    }
    Ok(PreparedDelivery {
        fence: Fence(fence as u64),
        encoded: encode_bundle(&bundle)?,
    })
}

/// Open exactly one already-authorized immutable version. This stays private
/// to the store preparation path; client-facing metadata never exposes it.
type StoredSecretVersion = ([u8; 16], Option<[u8; 16]>, String, i64, bool, Vec<u8>, bool);

fn open_value(conn: &Connection, key: &Key, resolved: &Resolved) -> Result<Vec<u8>> {
    let row: Option<StoredSecretVersion> = conn
        .prepare_cached(
            "SELECT s.tenant_id,s.scope_repo_id,s.name,s.current_version,s.active,
                    v.sealed,v.revoked
             FROM secrets s JOIN secret_versions v ON v.secret_id=s.id
             WHERE s.id=?1 AND v.version=?2",
        )?
        .query_row(
            params![resolved.secret.as_bytes(), resolved.version as i64],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                ))
            },
        )
        .optional()?;
    let Some((tenant, repo, name, current, active, sealed, revoked)) = row else {
        return Err(Error::NotFound);
    };
    let tenant = TenantId::from_bytes(tenant).map_err(|_| Error::Corrupt("secret tenant"))?;
    let scope = match repo {
        Some(repo) => {
            Scope::Repo(RepoId::from_bytes(repo).map_err(|_| Error::Corrupt("secret repo"))?)
        }
        None => Scope::Tenant(tenant),
    };
    if !active
        || revoked
        || current != resolved.version as i64
        || name != resolved.name
        || scope != resolved.scope
    {
        return Err(Error::NotFound);
    }
    let scope_repo = match resolved.scope {
        Scope::Tenant(_) => None,
        Scope::Repo(repo) => Some(*repo.as_bytes()),
    };
    let context = secret_context(
        tenant.as_bytes(),
        scope_repo.as_ref(),
        &name,
        resolved.version,
    );
    let mut plaintext = key
        .open(&context, &sealed)
        .map_err(|_| Error::Corrupt("sealed secret"))?;
    if !(1..=MAX_VALUE).contains(&plaintext.len()) {
        plaintext.fill(0);
        core::hint::black_box(&mut plaintext);
        return Err(Error::Corrupt("secret value length"));
    }
    Ok(plaintext)
}
