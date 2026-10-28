//! The GitHub App registered through the manifest flow, and the one-time states that carry a
//! person from Sentinel to GitHub and back (migration 56).
//!
//! The App's private key, OAuth client secret and webhook secret are sealed with `master.key`;
//! nothing here ever returns them except [`load`], which the controller calls to put the App in
//! force. A state is stored as its digest, bound to the account, the session and (for an
//! installation) the tenant that minted it, spent at most once and dead after ten minutes.

use std::fmt;

use rusqlite::{Connection, OptionalExtension, Transaction, params};
use sentinel_auth::{sealed::Key, secret::Secret};
use sentinel_core::{InstallationId, SessionId, TenantId, UnixMillis, UserId, auth::Principal};

use crate::{
    Error, Result, Store,
    local_auth::{Event, audit},
};

/// Ten minutes: long enough to read GitHub's form and confirm it, short enough that a state
/// copied out of a browser history is useless soon after. GitHub's own code lives an hour.
pub const STATE_TTL_MS: i64 = 10 * 60 * 1000;
/// Live states one account may hold; minting more drops its oldest.
pub const MAX_STATES_PER_USER: i64 = 16;

const REFUSAL_FLOOD_ROWS: i64 = 5;
const REFUSAL_FLOOD_WINDOW_MS: i64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Purpose {
    /// Registering the App from a manifest (platform administration).
    Manifest = 1,
    /// Installing the App and binding the installation to one tenant.
    Install = 2,
}

impl Purpose {
    const fn name(self) -> &'static str {
        match self {
            Purpose::Manifest => "manifest",
            Purpose::Install => "installation",
        }
    }
}

/// Why a presented state was refused. The caller answers every case the same way; the reason
/// goes only to the audit log.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    Unknown,
    Foreign,
    Replayed,
    Expired,
}

impl Refusal {
    pub const fn as_str(self) -> &'static str {
        match self {
            Refusal::Unknown => "unknown",
            Refusal::Foreign => "foreign",
            Refusal::Replayed => "replayed",
            Refusal::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Spent {
    pub tenant: Option<TenantId>,
}

/// Mints a state for `purpose`, bound to this account and session (and tenant).
pub fn mint(
    tx: &Transaction<'_>,
    purpose: Purpose,
    user: UserId,
    session: SessionId,
    tenant: Option<TenantId>,
    now: UnixMillis,
) -> Result<(Secret, UnixMillis)> {
    if (purpose == Purpose::Install) != tenant.is_some() {
        return Err(Error::InvalidInput("state tenant"));
    }
    let secret = Secret::generate();
    let expires = UnixMillis(now.0 + STATE_TTL_MS);
    tx.prepare_cached(
        "INSERT INTO github_app_states(digest, purpose, user_id, session_id, tenant_id, created_ms, expires_ms)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
    )?
    .execute(params![
        secret.digest().0,
        purpose as u8,
        user.as_bytes(),
        session.as_bytes(),
        tenant.as_ref().map(TenantId::as_bytes),
        now.0,
        expires.0
    ])?;
    tx.prepare_cached(
        "DELETE FROM github_app_states WHERE user_id = ?1 AND digest IN (
             SELECT digest FROM github_app_states WHERE user_id = ?1
             ORDER BY created_ms DESC, digest LIMIT -1 OFFSET ?2)",
    )?
    .execute(params![user.as_bytes(), MAX_STATES_PER_USER])?;
    Ok((secret, expires))
}

/// purpose, user, session, tenant, expiry, spent.
type StateRow = (u8, [u8; 16], [u8; 16], Option<[u8; 16]>, i64, Option<i64>);

/// Spends a presented state once. `Ok(Err(_))` is a refusal the caller audits with
/// [`audit_refusal`] in the same transaction and answers uniformly.
pub fn spend(
    tx: &Transaction<'_>,
    purpose: Purpose,
    presented: &Secret,
    user: UserId,
    session: SessionId,
    now: UnixMillis,
) -> Result<std::result::Result<Spent, Refusal>> {
    let digest = presented.digest().0;
    let row: Option<StateRow> = tx
        .prepare_cached(
            "SELECT purpose, user_id, session_id, tenant_id, expires_ms, used_ms
             FROM github_app_states WHERE digest = ?1",
        )?
        .query_row([digest], |r| {
            Ok((
                r.get(0)?,
                r.get(1)?,
                r.get(2)?,
                r.get(3)?,
                r.get(4)?,
                r.get(5)?,
            ))
        })
        .optional()?;
    let Some((stored, owner, minted_in, tenant, expires, used)) = row else {
        return Ok(Err(Refusal::Unknown));
    };
    if stored != purpose as u8 || owner != *user.as_bytes() || minted_in != *session.as_bytes() {
        return Ok(Err(Refusal::Foreign));
    }
    if used.is_some() {
        return Ok(Err(Refusal::Replayed));
    }
    if expires <= now.0 {
        return Ok(Err(Refusal::Expired));
    }
    let spent = tx
        .prepare_cached(
            "UPDATE github_app_states SET used_ms = ?2 WHERE digest = ?1 AND used_ms IS NULL",
        )?
        .execute(params![digest, now.0])?;
    if spent != 1 {
        return Ok(Err(Refusal::Replayed));
    }
    let tenant = tenant
        .map(|t| TenantId::from_bytes(t).map_err(|_| Error::Corrupt("github_app_states.tenant_id")))
        .transpose()?;
    Ok(Ok(Spent { tenant }))
}

/// Audits a refused state, at most five rows per account in ten seconds so a client repeating
/// a bad state cannot grow the log without bound.
pub fn audit_refusal(
    tx: &Transaction<'_>,
    purpose: Purpose,
    refusal: Refusal,
    user: UserId,
    now: UnixMillis,
) -> Result<()> {
    let detail = format!("{} {}", purpose.name(), refusal.as_str());
    tx.prepare_cached(
        "INSERT INTO auth_audit(at_ms, event, actor_user_id, subject_user_id, host_local, detail)
         SELECT ?1, ?2, ?3, NULL, 0, ?4
         WHERE (SELECT COUNT(*) FROM auth_audit
                WHERE at_ms > ?5 AND event = ?2 AND actor_user_id = ?3) < ?6",
    )?
    .execute(params![
        now.0,
        Event::GithubAppStateRefused as u8,
        user.as_bytes(),
        detail,
        now.0 - REFUSAL_FLOOD_WINDOW_MS,
        REFUSAL_FLOOD_ROWS
    ])?;
    Ok(())
}

/// Deletes expired states, spent or not, oldest first.
pub fn purge(store: &Store, now: UnixMillis, limit: u32) -> Result<usize> {
    store.writer().write(move |tx| {
        Ok(tx
            .prepare_cached(
                "DELETE FROM github_app_states WHERE digest IN (
                     SELECT digest FROM github_app_states WHERE expires_ms <= ?1
                     ORDER BY expires_ms LIMIT ?2)",
            )?
            .execute(params![now.0, limit])?)
    })
}

/// The sealing context of one credential column, bound to the App id: a value moved to another
/// column or another App does not open.
pub fn context(column: &str, app_id: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(32 + column.len());
    out.extend_from_slice(b"sentinel github-app\0");
    out.extend_from_slice(column.as_bytes());
    out.push(0);
    out.extend_from_slice(&app_id.to_be_bytes());
    out
}

pub const KEY_COLUMN: &str = "sealed_key";
pub const CLIENT_SECRET_COLUMN: &str = "sealed_client_secret";
pub const WEBHOOK_SECRET_COLUMN: &str = "sealed_webhook_secret";

/// The App's public facts as GitHub reported them at conversion.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Public {
    pub app_id: u64,
    pub slug: String,
    pub name: String,
    pub owner: String,
    pub owner_id: u64,
    pub html_url: String,
    pub client_id: String,
}

/// The App's credentials, already sealed: only ciphertext reaches the writer thread.
pub struct SealedValues {
    pub key: Vec<u8>,
    pub client_secret: Vec<u8>,
    pub webhook_secret: Option<Vec<u8>>,
}

impl fmt::Debug for SealedValues {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SealedValues(..)")
    }
}

/// Seals the three credentials under contexts naming their column and the App id.
pub fn seal(
    key: &Key,
    app_id: u64,
    pem: &str,
    client_secret: &str,
    webhook_secret: Option<&str>,
) -> SealedValues {
    SealedValues {
        key: key.seal(&context(KEY_COLUMN, app_id), pem.as_bytes()),
        client_secret: key.seal(
            &context(CLIENT_SECRET_COLUMN, app_id),
            client_secret.as_bytes(),
        ),
        webhook_secret: webhook_secret
            .map(|s| key.seal(&context(WEBHOOK_SECRET_COLUMN, app_id), s.as_bytes())),
    }
}

/// Stores the App: `Conflict` when one is already stored. Audited as `github-app-created`
/// naming the App id and slug, which are public.
pub fn store(
    tx: &Transaction<'_>,
    app: &Public,
    sealed: &SealedValues,
    actor: UserId,
    now: UnixMillis,
) -> Result<()> {
    if app.app_id == 0 || app.app_id > i64::MAX as u64 || app.owner_id > i64::MAX as u64 {
        return Err(Error::InvalidInput("app id"));
    }
    let exists: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM github_app)", [], |r| r.get(0))?;
    if exists {
        return Err(Error::Conflict);
    }
    tx.prepare_cached(
        "INSERT INTO github_app(id, app_id, slug, name, owner, owner_id, html_url, client_id,
             sealed_key, sealed_client_secret, sealed_webhook_secret, created_by, created_ms)
         VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
    )?
    .execute(params![
        app.app_id as i64,
        app.slug,
        app.name,
        app.owner,
        app.owner_id as i64,
        app.html_url,
        app.client_id,
        sealed.key,
        sealed.client_secret,
        sealed.webhook_secret,
        actor.as_bytes(),
        now.0
    ])?;
    let detail = format!("app {} {}", app.app_id, app.slug);
    audit(
        tx,
        Event::GithubAppCreated,
        Some(actor),
        None,
        false,
        Some(&detail),
    )
}

/// The stored App's public facts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Facts {
    pub app_id: u64,
    pub slug: String,
    pub name: String,
    pub owner: String,
    pub html_url: String,
    pub client_id: String,
}

pub fn facts(conn: &Connection) -> Result<Option<Facts>> {
    Ok(conn
        .prepare_cached(
            "SELECT app_id, slug, name, owner, html_url, client_id FROM github_app WHERE id = 1",
        )?
        .query_row([], |r| {
            Ok(Facts {
                app_id: r.get::<_, i64>(0)? as u64,
                slug: r.get(1)?,
                name: r.get(2)?,
                owner: r.get(3)?,
                html_url: r.get(4)?,
                client_id: r.get(5)?,
            })
        })
        .optional()?)
}

/// The stored App with its credentials opened. Never printed; wiped on drop.
pub struct Credentials {
    pub facts: Facts,
    pub pem: String,
    pub client_secret: String,
    pub webhook_secret: Option<String>,
}

impl fmt::Debug for Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credentials")
            .field("facts", &self.facts)
            .finish_non_exhaustive()
    }
}

impl Drop for Credentials {
    fn drop(&mut self) {
        sentinel_auth::secret::wipe_string(&mut self.pem);
        sentinel_auth::secret::wipe_string(&mut self.client_secret);
        if let Some(secret) = &mut self.webhook_secret {
            sentinel_auth::secret::wipe_string(secret);
        }
    }
}

fn open_text(key: &Key, column: &'static str, app_id: u64, sealed: &[u8]) -> Result<String> {
    let plain = key
        .open(&context(column, app_id), sealed)
        .map_err(|_| Error::Corrupt(column))?;
    String::from_utf8(plain).map_err(|e| {
        let mut bytes = e.into_bytes();
        sentinel_auth::secret::wipe(&mut bytes);
        Error::Corrupt(column)
    })
}

type SealedRow = (Vec<u8>, Vec<u8>, Option<Vec<u8>>);

pub fn load(conn: &Connection, key: &Key) -> Result<Option<Credentials>> {
    let Some(facts) = facts(conn)? else {
        return Ok(None);
    };
    let (sealed_key, sealed_client, sealed_hook): SealedRow = conn.query_row(
        "SELECT sealed_key, sealed_client_secret, sealed_webhook_secret FROM github_app WHERE id = 1",
        [],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    )?;
    let id = facts.app_id;
    let pem = open_text(key, KEY_COLUMN, id, &sealed_key)?;
    let client_secret = open_text(key, CLIENT_SECRET_COLUMN, id, &sealed_client)?;
    let webhook_secret = sealed_hook
        .map(|sealed| open_text(key, WEBHOOK_SECRET_COLUMN, id, &sealed))
        .transpose()?;
    Ok(Some(Credentials {
        facts,
        pem,
        client_secret,
        webhook_secret,
    }))
}

/// The numeric GitHub account id linked to this account, if any.
pub fn linked_github_id(conn: &Connection, user: UserId) -> Result<Option<u64>> {
    let subject: Option<String> = conn
        .prepare_cached(
            "SELECT subject FROM external_identities WHERE provider = 'github' AND user_id = ?1",
        )?
        .query_row([user.as_bytes()], |r| r.get(0))
        .optional()?;
    Ok(subject.and_then(|s| s.parse().ok()))
}

/// Whether `tenant` is a personal namespace (`Some(true)`), an organization or absent.
pub fn tenant_is_personal(conn: &Connection, tenant: TenantId) -> Result<bool> {
    let kind: i64 = conn
        .prepare_cached("SELECT kind FROM tenants WHERE id = ?1 AND active = 1")?
        .query_row([tenant.as_bytes()], |r| r.get(0))
        .optional()?
        .ok_or(Error::NotFound)?;
    Ok(kind == 1)
}

/// An installation as GitHub reported it to the App just now.
pub struct Observed<'a> {
    pub external_id: u64,
    pub account_id: u64,
    pub login: &'a str,
    pub personal: bool,
    pub suspended: bool,
    pub permissions_valid: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Bound {
    Bound(InstallationId),
    /// Already bound to this tenant: nothing changed (GitHub's `setup_action=update`).
    Already(InstallationId),
}

/// Records the fresh snapshot and binds the installation to `tenant` through the existing
/// [`crate::registration::bind_installation`] rule. An organization's installation binds only
/// to an organization tenant (`Forbidden`); one bound to another tenant is `Conflict`.
pub fn bind(
    tx: &Transaction<'_>,
    principal: Principal,
    tenant: TenantId,
    observed: &Observed<'_>,
    now: UnixMillis,
) -> Result<Bound> {
    if !observed.personal && tenant_is_personal(tx, tenant)? {
        return Err(Error::Forbidden);
    }
    let external = observed.external_id.to_string();
    let existing: Option<(Option<[u8; 16]>, i64)> = tx
        .prepare_cached(
            "SELECT tenant_id, lifecycle_version FROM installations
             WHERE provider = 'github' AND external_id = ?1",
        )?
        .query_row([&external], |r| Ok((r.get(0)?, r.get(1)?)))
        .optional()?;
    if let Some((Some(bound), _)) = existing
        && bound != *tenant.as_bytes()
    {
        return Err(Error::Conflict);
    }
    let id = crate::sources_forge::refresh(
        tx,
        crate::sources_forge::Snapshot {
            external_id: observed.external_id,
            account_id: observed.account_id,
            login: observed.login,
            personal: observed.personal,
            suspended: observed.suspended,
            permissions_valid: observed.permissions_valid,
            expected: existing.map_or(0, |(_, version)| version as u64),
        },
        now,
    )?;
    if matches!(existing, Some((Some(_), _))) {
        crate::auth::require_tenant_admin(tx, principal, tenant)?;
        return Ok(Bound::Already(id));
    }
    crate::registration::bind_installation(tx, principal, id, tenant, now)?;
    Ok(Bound::Bound(id))
}
