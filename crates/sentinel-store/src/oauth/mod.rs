//! The OAuth 2.0 authorization server's durable state (O01–O06): clients,
//! grants, rotating refresh tokens, short-lived access tokens, authorization
//! codes and device requests. Migration 30 holds every table and trigger.
//!
//! A grant is one refresh-token family (a browser or device login) or one
//! service-account grant. Its scopes, narrowing, audience and absolute expiry
//! are fixed at issuance; only use and revocation move afterwards, and the
//! database refuses anything else. Every token is an opaque [`Secret`] stored
//! as its BLAKE3 digest, so validation is a primary-key probe and a database
//! snapshot yields nothing presentable.
//!
//! Access tokens are validated by [`authenticate_access`]: ONE statement, a
//! primary-key probe joined to the grant and the account, nothing written.
//! Authority is the intersection of the token's scopes, the grant's, and the
//! account's live state; repository and tenant decisions remain live checks
//! in [`crate::auth`], exactly as for sessions and API credentials.
//!
//! Refresh tokens rotate on every use ([`refresh`]). A lost response is
//! recovered once within [`ROTATION_GRACE_MS`]: presenting a just-rotated
//! token again supersedes its one unused successor and mints another, and
//! only while that successor is its only child. Every other reuse — a third
//! presentation, one after the successor was used, one after the window —
//! is a replay and revokes the whole grant.
//!
//! The authorization-code ([`code`]), device ([`device`]) and service-grant
//! ([`service`]) flows build on [`insert_grant`] and [`mint`] in this module.

pub mod code;
pub mod device;
pub mod service;

use std::collections::HashSet;

use rusqlite::{Connection, OptionalExtension, Transaction, params};
use sentinel_auth::{
    oauth::{self as forms, Kind},
    secret::{Digest, Secret},
};
use sentinel_core::{
    GrantId, RepoId, TenantId, UnixMillis, UserId,
    auth::{Audience, Permissions, Principal, Scopes},
};

use crate::{
    Error, Result, Store,
    auth::Authority,
    local_auth::{Event, audit},
};

const MINUTE_MS: i64 = 60 * 1000;
const DAY_MS: i64 = 24 * 60 * MINUTE_MS;

/// Life of an access token. Revocation is checked on every request anyway;
/// the short life bounds what a leaked token is worth.
pub const ACCESS_LIFETIME_MS: i64 = 10 * MINUTE_MS;
/// Idle life of a refresh token, capped by its grant's absolute expiry.
pub const REFRESH_IDLE_MS: i64 = 30 * DAY_MS;
/// Absolute ceiling on any grant. The database enforces it too.
pub const GRANT_MAX_MS: i64 = 90 * DAY_MS;
/// Absolute life of a browser or device login grant.
pub const LOGIN_GRANT_MS: i64 = GRANT_MAX_MS;
/// Life of an authorization code.
pub const CODE_LIFETIME_MS: i64 = 60 * 1000;
/// Life of a device authorization request.
pub const DEVICE_LIFETIME_MS: i64 = 10 * MINUTE_MS;
/// Initial device polling interval.
pub const DEVICE_INTERVAL_MS: i64 = 5 * 1000;
/// How much each `slow_down` adds to a device's polling interval.
pub const SLOW_DOWN_STEP_MS: i64 = 5 * 1000;
/// How long after a rotation the previous refresh token may recover a lost
/// response, once, if its successor was never used.
pub const ROTATION_GRACE_MS: i64 = 60 * 1000;
/// Default service-grant life; service grants have no idle expiry of their
/// own (the refresh token lives as long as the grant).
pub const SERVICE_DEFAULT_MS: i64 = 30 * DAY_MS;
/// Service-grant lifetime bounds.
pub const SERVICE_MIN_MS: i64 = 60 * MINUTE_MS;
pub const SERVICE_MAX_MS: i64 = GRANT_MAX_MS;
/// Unexpired pending device requests the deployment holds at once; beyond
/// it a new request is refused with `slow_down`.
pub const MAX_PENDING_DEVICE: usize = 1024;
/// How long a rotated refresh token is kept so that presenting it again is
/// recognized as a replay. Past it, the row is purged and a presentation is
/// merely unknown.
pub const ROTATED_RETENTION_MS: i64 = DAY_MS;

/// Stored `revoked_reason` codes.
pub mod reason {
    /// The holder logged out or presented a token to the revocation endpoint.
    pub const LOGOUT: u8 = 1;
    /// A rotated refresh token was presented again.
    pub const REFRESH_REPLAY: u8 = 2;
    /// A spent authorization code was presented again.
    pub const CODE_REPLAY: u8 = 3;
    /// The account was suspended or rejected, or its password changed or was reset.
    pub const ACCOUNT: u8 = 4;
    /// The account's membership of the grant's tenant was removed.
    pub const MEMBERSHIP: u8 = 5;
    /// The grant's tenant was suspended.
    pub const TENANT: u8 = 6;
    /// Revoked by the grant's owner or an administrator.
    pub const ADMIN: u8 = 7;
}

/// How a grant came to exist. Stored as its integer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum GrantKind {
    Code = 1,
    Device = 2,
    Service = 3,
}

impl GrantKind {
    pub const fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::Code),
            2 => Some(Self::Device),
            3 => Some(Self::Service),
            _ => None,
        }
    }
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Code => "authorization_code",
            Self::Device => "device",
            Self::Service => "service",
        }
    }
}

/// A registered, enabled client.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Client {
    pub id: String,
    /// Identifier safe to show in consent and grant listings. For CIMD this
    /// is the metadata URL; internal storage uses a fixed-size digest ID.
    pub display_id: String,
    pub name: String,
    pub first_party: bool,
    /// May redirect to `http://127.0.0.1:PORT<redirect_path>` / `[::1]`.
    pub loopback: bool,
    pub redirect_path: Option<String>,
    /// May use the device authorization flow.
    pub device: bool,
    /// Ceiling on every grant issued to this client.
    pub max_scopes: Scopes,
    /// OAuth resource this client may request.
    pub resource: Audience,
}

/// Terms of a client registered by [`register_client`].
#[derive(Clone, Copy, Debug)]
pub struct ClientSpec<'a> {
    pub id: &'a str,
    pub name: &'a str,
    pub first_party: bool,
    pub loopback: bool,
    pub redirect_path: Option<&'a str>,
    pub device: bool,
    pub max_scopes: Scopes,
}

/// Which public MCP client registration path supplied the client metadata.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum McpRegistrationKind {
    Dynamic,
    Metadata,
}

/// The bounded terms stored for one DCR or CIMD public client.
#[derive(Clone, Copy, Debug)]
pub struct McpClientSpec<'a> {
    pub id: &'a str,
    pub name: &'a str,
    pub max_scopes: Scopes,
    pub kind: McpRegistrationKind,
    pub metadata_url: Option<&'a str>,
}

/// Registration can be refused at the hard per-deployment client cap.
#[derive(Debug)]
pub enum McpRegistrationError {
    Capacity,
    Store(Error),
}

/// At most this many externally registered clients may be stored per deployment.
pub const MAX_MCP_CLIENTS: i64 = 512;

fn decode_scopes(bits: i64) -> Result<Scopes> {
    u32::try_from(bits)
        .ok()
        .and_then(Scopes::from_bits)
        .ok_or(Error::Corrupt("oauth scopes"))
}

fn tenant_of(bytes: Option<[u8; 16]>) -> Result<Option<TenantId>> {
    bytes
        .map(|b| TenantId::from_bytes(b).map_err(|_| Error::Corrupt("tenant_id")))
        .transpose()
}

fn repo_of(bytes: Option<[u8; 16]>) -> Result<Option<RepoId>> {
    bytes
        .map(|b| RepoId::from_bytes(b).map_err(|_| Error::Corrupt("repo_id")))
        .transpose()
}

fn user_of(bytes: [u8; 16]) -> Result<UserId> {
    UserId::from_bytes(bytes).map_err(|_| Error::Corrupt("user_id"))
}

fn grant_of(bytes: [u8; 16]) -> Result<GrantId> {
    GrantId::from_bytes(bytes).map_err(|_| Error::Corrupt("grant id"))
}

/// Trigger refusals (`RAISE(ABORT)`) and constraint violations on grant
/// issuance are authorization answers, not faults.
fn refused(error: rusqlite::Error) -> Error {
    match &error {
        rusqlite::Error::SqliteFailure(e, _)
            if e.code == rusqlite::ErrorCode::ConstraintViolation =>
        {
            Error::Forbidden
        }
        _ => Error::Sqlite(error),
    }
}

/// Look up an enabled client. Unknown and disabled clients are both `NotFound`.
pub fn client(conn: &Connection, client_id: &str) -> Result<Client> {
    if client_id.is_empty() || client_id.len() > 64 {
        return Err(Error::NotFound);
    }
    let row = conn
        .prepare_cached(
            "SELECT client_id, COALESCE(metadata_url, client_id), name, first_party,
                    loopback, redirect_path, device, max_scopes, resource
             FROM oauth_clients WHERE client_id = ?1 AND disabled_ms IS NULL",
        )?
        .query_row([client_id], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, bool>(3)?,
                r.get::<_, bool>(4)?,
                r.get::<_, Option<String>>(5)?,
                r.get::<_, bool>(6)?,
                r.get::<_, i64>(7)?,
                r.get::<_, u8>(8)?,
            ))
        })
        .optional()?
        .ok_or(Error::NotFound)?;
    Ok(Client {
        id: row.0,
        display_id: row.1,
        name: row.2,
        first_party: row.3,
        loopback: row.4,
        redirect_path: row.5,
        device: row.6,
        max_scopes: decode_scopes(row.7)?,
        resource: Audience::from_code(row.8).ok_or(Error::Corrupt("oauth_clients.resource"))?,
    })
}

/// Whether `uri` is a redirect this client may use: a loopback URI on the
/// client's path (any port), or an exact registered URI. No prefix, pattern
/// or normalization matching.
pub fn redirect_allowed(conn: &Connection, client: &Client, uri: &str) -> Result<bool> {
    if client.loopback
        && let Some(path) = client.redirect_path.as_deref()
        && forms::loopback_redirect(uri, path).is_some()
    {
        return Ok(true);
    }
    if uri.is_empty() || uri.len() > 512 {
        return Ok(false);
    }
    let listed: bool = conn
        .prepare_cached(
            "SELECT EXISTS(SELECT 1 FROM oauth_client_redirects WHERE client_id = ?1 AND uri = ?2)",
        )?
        .query_row(params![client.id, uri], |r| r.get(0))?;
    Ok(listed)
}

/// Register a client and its exact redirect URIs. Trusted: tests and
/// host-local administration only; no route exposes it.
pub fn register_client(store: &Store, spec: &ClientSpec<'_>, redirects: &[&str]) -> Result<()> {
    if spec.max_scopes.is_empty() || spec.name.chars().any(char::is_control) {
        return Err(Error::InvalidInput("client"));
    }
    let (id, name) = (spec.id.to_owned(), spec.name.to_owned());
    let path = spec.redirect_path.map(str::to_owned);
    let (first_party, loopback, device, max) = (
        spec.first_party,
        spec.loopback,
        spec.device,
        spec.max_scopes.bits(),
    );
    let redirects: Vec<String> = redirects.iter().map(|r| (*r).to_owned()).collect();
    let now = UnixMillis::now();
    store.writer().write(move |tx| {
        tx.execute(
            "INSERT INTO oauth_clients(client_id, name, first_party, loopback, redirect_path,
                device, max_scopes, created_ms) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![id, name, first_party, loopback, path, device, max, now.0],
        )?;
        for uri in &redirects {
            tx.execute(
                "INSERT INTO oauth_client_redirects(client_id, uri) VALUES (?1, ?2)",
                params![id, uri],
            )?;
        }
        Ok(())
    })
}

/// Register a bounded public MCP OAuth client. DCR creates a new row; CIMD
/// refreshes the metadata snapshot for its stable URL-derived ID. No user,
/// grant, tenant or repository is created by either path.
pub fn register_mcp_client(
    store: &Store,
    spec: &McpClientSpec<'_>,
    redirects: &[&str],
) -> std::result::Result<(), McpRegistrationError> {
    if spec.id.is_empty()
        || spec.id.len() > 64
        || spec.name.trim().is_empty()
        || spec.name.len() > 128
        || spec.name.chars().any(char::is_control)
        || spec.max_scopes.is_empty()
        || !Scopes::MCP.contains(spec.max_scopes)
        || redirects.is_empty()
        || redirects.len() > 16
        || redirects.iter().any(|uri| {
            uri.is_empty() || uri.len() > 512 || uri.bytes().any(|byte| byte.is_ascii_control())
        })
        || (spec.kind == McpRegistrationKind::Metadata) != spec.metadata_url.is_some()
        || spec.metadata_url.is_some_and(|url| url.len() > 2048)
    {
        return Err(McpRegistrationError::Store(Error::InvalidInput(
            "MCP client registration",
        )));
    }
    let mut unique = HashSet::with_capacity(redirects.len());
    if redirects.iter().any(|uri| !unique.insert(*uri)) {
        return Err(McpRegistrationError::Store(Error::InvalidInput(
            "MCP client redirects",
        )));
    }
    let id = spec.id.to_owned();
    let name = spec.name.to_owned();
    let max_scopes = spec.max_scopes.bits();
    let kind = match spec.kind {
        McpRegistrationKind::Dynamic => 1u8,
        McpRegistrationKind::Metadata => 2u8,
    };
    let metadata_url = spec.metadata_url.map(str::to_owned);
    let redirects: Vec<String> = redirects.iter().map(|uri| (*uri).to_owned()).collect();
    let now = UnixMillis::now();
    let inserted = store
        .writer()
        .write(move |tx| {
            let existing = tx
                .prepare_cached(
                    "SELECT registration_kind, metadata_url, disabled_ms FROM oauth_clients
                     WHERE client_id = ?1",
                )?
                .query_row([&id], |row| {
                    Ok((
                        row.get::<_, u8>(0)?,
                        row.get::<_, Option<String>>(1)?,
                        row.get::<_, Option<i64>>(2)?,
                    ))
                })
                .optional()?;
            if let Some((existing_kind, existing_url, disabled)) = existing {
                if kind != 2 || existing_kind != kind || existing_url != metadata_url {
                    return Err(Error::Conflict);
                }
                if disabled.is_some() {
                    return Err(Error::NotFound);
                }
                tx.execute(
                    "UPDATE oauth_clients SET name = ?2, max_scopes = ?3
                     WHERE client_id = ?1 AND disabled_ms IS NULL",
                    params![id, name, max_scopes],
                )?;
                tx.execute(
                    "DELETE FROM oauth_client_redirects WHERE client_id = ?1",
                    [&id],
                )?;
            } else {
                let count: i64 = tx.query_row(
                    "SELECT count(*) FROM oauth_clients WHERE registration_kind != 0",
                    [],
                    |row| row.get(0),
                )?;
                if count >= MAX_MCP_CLIENTS {
                    return Ok(false);
                }
                tx.execute(
                    "INSERT INTO oauth_clients(client_id, name, first_party, loopback,
                        redirect_path, device, max_scopes, created_ms, resource,
                        registration_kind, metadata_url)
                     VALUES (?1, ?2, 0, 0, NULL, 0, ?3, ?4, 2, ?5, ?6)",
                    params![id, name, max_scopes, now.0, kind, metadata_url],
                )?;
            }
            for uri in &redirects {
                tx.execute(
                    "INSERT INTO oauth_client_redirects(client_id, uri) VALUES (?1, ?2)",
                    params![id, uri],
                )?;
            }
            Ok(true)
        })
        .map_err(McpRegistrationError::Store)?;
    if inserted {
        Ok(())
    } else {
        Err(McpRegistrationError::Capacity)
    }
}

/// The terms of a new grant. The database re-checks the account, the
/// client's ceiling, platform/tenant-admin eligibility, service confinement
/// and repository ownership at insert.
#[derive(Clone, Copy, Debug)]
pub struct NewGrant<'a> {
    pub user: UserId,
    pub client_id: &'a str,
    pub kind: GrantKind,
    pub scopes: Scopes,
    pub tenant: Option<TenantId>,
    pub repo: Option<RepoId>,
    pub audience: Audience,
    /// Operator-facing label (service grants); `None` for logins.
    pub name: Option<&'a str>,
    /// Absolute lifetime, 1 ms ..= [`GRANT_MAX_MS`].
    pub lifetime_ms: i64,
    /// Who issued it when that is not `user` (service grants).
    pub created_by: Option<UserId>,
}

/// Insert a grant row. Callers authorize and audit; this validates shape and
/// lets the insert trigger refuse ineligible terms (`Forbidden`).
pub(crate) fn insert_grant(
    tx: &Transaction<'_>,
    g: &NewGrant<'_>,
    now: UnixMillis,
) -> Result<GrantId> {
    if g.scopes.is_empty() {
        return Err(Error::InvalidInput("scope"));
    }
    if g.repo.is_some() && g.tenant.is_none() {
        return Err(Error::InvalidInput("repository scope without its tenant"));
    }
    if !(1..=GRANT_MAX_MS).contains(&g.lifetime_ms) {
        return Err(Error::InvalidInput("grant lifetime"));
    }
    if g.name
        .is_some_and(|n| n.is_empty() || n.len() > 128 || n.chars().any(char::is_control))
    {
        return Err(Error::InvalidInput("grant name"));
    }
    let id = GrantId::new();
    tx.prepare_cached(
        "INSERT INTO oauth_grants(id, user_id, client_id, kind, scopes, tenant_id, repo_id,
            audience, name, created_by, created_ms, expires_ms, resource)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 1, ?8, ?9, ?10, ?11, ?12)",
    )?
    .execute(params![
        id.as_bytes(),
        g.user.as_bytes(),
        g.client_id,
        g.kind as u8,
        g.scopes.bits(),
        g.tenant.as_ref().map(TenantId::as_bytes),
        g.repo.as_ref().map(RepoId::as_bytes),
        g.name,
        g.created_by.as_ref().map(UserId::as_bytes),
        now.0,
        now.0.saturating_add(g.lifetime_ms),
        g.audience.code()
    ])
    .map_err(refused)?;
    Ok(id)
}

/// A freshly issued token pair. The secrets appear in text exactly once,
/// in the response that carries them.
#[derive(Debug)]
pub struct Minted {
    pub grant: GrantId,
    pub access: Secret,
    pub access_expires: UnixMillis,
    pub refresh: Secret,
    pub refresh_expires: UnixMillis,
    /// The access token's scopes (the grant's, or a narrowing of them).
    pub scopes: Scopes,
}

/// The facts of a grant the token paths need.
struct GrantTerms {
    id: GrantId,
    kind: GrantKind,
    scopes: Scopes,
    expires: i64,
}

fn live_terms(tx: &Transaction<'_>, grant: GrantId, now: UnixMillis) -> Result<GrantTerms> {
    let (kind, scopes, expires) = tx
        .prepare_cached(
            "SELECT kind, scopes, expires_ms FROM oauth_grants
             WHERE id = ?1 AND revoked_ms IS NULL AND expires_ms > ?2",
        )?
        .query_row(params![grant.as_bytes(), now.0], |r| {
            Ok((r.get::<_, u8>(0)?, r.get::<_, i64>(1)?, r.get::<_, i64>(2)?))
        })
        .optional()?
        .ok_or(Error::NotFound)?;
    Ok(GrantTerms {
        id: grant,
        kind: GrantKind::from_code(kind).ok_or(Error::Corrupt("oauth_grants.kind"))?,
        scopes: decode_scopes(scopes)?,
        expires,
    })
}

/// Write one refresh/access pair of `generation` for a live grant.
fn issue_pair(
    tx: &Transaction<'_>,
    grant: &GrantTerms,
    generation: i64,
    parent: Option<i64>,
    scopes: Scopes,
    now: UnixMillis,
) -> Result<Minted> {
    let access = Secret::generate();
    let refresh = Secret::generate();
    let access_expires = now.0.saturating_add(ACCESS_LIFETIME_MS).min(grant.expires);
    let refresh_expires = match grant.kind {
        GrantKind::Service => grant.expires,
        _ => now.0.saturating_add(REFRESH_IDLE_MS).min(grant.expires),
    };
    tx.prepare_cached(
        "INSERT INTO oauth_refresh_tokens(token_digest, grant_id, generation, parent,
            created_ms, idle_expires_ms) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
    )?
    .execute(params![
        refresh.digest().0,
        grant.id.as_bytes(),
        generation,
        parent,
        now.0,
        refresh_expires
    ])?;
    tx.prepare_cached(
        "INSERT INTO oauth_access_tokens(token_digest, grant_id, generation, scopes,
            created_ms, expires_ms) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
    )?
    .execute(params![
        access.digest().0,
        grant.id.as_bytes(),
        generation,
        scopes.bits(),
        now.0,
        access_expires
    ])?;
    Ok(Minted {
        grant: grant.id,
        access,
        access_expires: UnixMillis(access_expires),
        refresh,
        refresh_expires: UnixMillis(refresh_expires),
        scopes,
    })
}

/// The first token pair (generation 1) of a live grant, with `scopes` (the
/// grant's own, or a narrowing of them).
pub(crate) fn mint(
    tx: &Transaction<'_>,
    grant: GrantId,
    scopes: Scopes,
    now: UnixMillis,
) -> Result<Minted> {
    let terms = live_terms(tx, grant, now)?;
    if scopes.is_empty() || !terms.scopes.contains(scopes) {
        return Err(Error::InvalidInput("scope"));
    }
    issue_pair(tx, &terms, 1, None, scopes, now)
}

/// A validated access token. `principal` is already intersected with what
/// the account can still hold.
#[derive(Clone, Copy, Debug)]
pub struct Authenticated {
    pub grant: GrantId,
    pub principal: Principal,
    /// Token scopes ∩ grant scopes.
    pub scopes: Scopes,
    pub expires: UnixMillis,
}

/// Validate a presented access token for `audience`. ONE statement: a
/// primary-key probe on the token, the grant by its key, the account by its
/// key. Expiry, revocation, audience, the account's live state and a
/// service principal's home tenant are predicates of that statement; a
/// wrong audience is indistinguishable from an unknown token. Platform
/// administration is dropped unless the account still holds it.
pub fn authenticate_access(
    conn: &Connection,
    presented: &Secret,
    audience: Audience,
    now: UnixMillis,
) -> Result<Authenticated> {
    let digest = presented.digest();
    let row = conn
        .prepare_cached(AUTHENTICATE_ACCESS)?
        .query_row(params![digest.0, now.0, audience.code()], |r| {
            Ok((
                r.get::<_, [u8; 16]>(0)?,
                r.get::<_, [u8; 16]>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, Option<[u8; 16]>>(3)?,
                r.get::<_, Option<[u8; 16]>>(4)?,
                r.get::<_, i64>(5)?,
                r.get::<_, bool>(6)?,
            ))
        })
        .optional()?
        .ok_or(Error::NotFound)?;
    let mut scopes = decode_scopes(row.2)?;
    if !row.6 {
        // Demoted since issuance: the stored scope is a ceiling, not a grant.
        scopes = scopes.difference(Scopes::PLATFORM_ADMIN);
    }
    let permissions = scopes.ceiling();
    if permissions == Permissions::NONE {
        return Err(Error::NotFound);
    }
    Ok(Authenticated {
        grant: grant_of(row.0)?,
        principal: Principal::new(
            user_of(row.1)?,
            permissions,
            tenant_of(row.3)?,
            repo_of(row.4)?,
        ),
        scopes,
        expires: UnixMillis(row.5),
    })
}

const AUTHENTICATE_ACCESS: &str = "SELECT g.id, g.user_id, a.scopes & g.scopes, g.tenant_id,
        g.repo_id, a.expires_ms, u.super_admin
     FROM oauth_access_tokens a
     JOIN oauth_grants g ON g.id = a.grant_id
     JOIN users u ON u.id = g.user_id
     WHERE a.token_digest = ?1 AND a.expires_ms > ?2
     AND g.revoked_ms IS NULL AND g.expires_ms > ?2 AND g.audience = 1 AND g.resource = ?3
     AND u.active = 1 AND (u.kind = 0 OR u.service_tenant_id = g.tenant_id)";

/// Existing API clients may omit `resource`; an MCP grant never may.
pub(crate) fn resource_matches(granted: Audience, requested: Option<Audience>) -> bool {
    match requested {
        Some(requested) => granted == requested,
        None => granted == Audience::Api,
    }
}

/// Why a refresh produced no tokens.
#[derive(Debug)]
pub enum RefreshError {
    /// Unknown, expired or revoked token or grant, another client's token,
    /// or an inactive account. Nothing was written.
    Invalid,
    /// A rotated or superseded token was presented again. The grant is now
    /// revoked (reason 2) and the replay audited; report `invalid_grant`.
    Replay,
    /// The requested narrowing is empty or wider than the grant. Nothing was
    /// written; the presented token is still live.
    InvalidScope,
    Store(Error),
}

enum Refreshed {
    Minted(Minted),
    Invalid,
    Replay,
    InvalidScope,
}

/// Rotate a refresh token in one writer transaction; see the module docs.
/// `narrow` limits this access token's scopes; it never widens the grant.
pub fn refresh(
    store: &Store,
    client_id: &str,
    presented: &Secret,
    narrow: Option<Scopes>,
    resource: Option<Audience>,
    now: UnixMillis,
) -> std::result::Result<Minted, RefreshError> {
    let digest = presented.digest();
    let client_id = client_id.to_owned();
    let outcome = store
        .writer()
        .write(move |tx| rotate(tx, &client_id, digest, narrow, resource, now))
        .map_err(RefreshError::Store)?;
    match outcome {
        Refreshed::Minted(minted) => Ok(minted),
        Refreshed::Invalid => Err(RefreshError::Invalid),
        Refreshed::Replay => Err(RefreshError::Replay),
        Refreshed::InvalidScope => Err(RefreshError::InvalidScope),
    }
}

fn rotate(
    tx: &Transaction<'_>,
    client_id: &str,
    digest: Digest,
    narrow: Option<Scopes>,
    resource: Option<Audience>,
    now: UnixMillis,
) -> Result<Refreshed> {
    let row = tx
        .prepare_cached(
            "SELECT r.grant_id, r.generation, r.rotated_ms, r.superseded, r.idle_expires_ms,
                    g.client_id, g.kind, g.scopes, g.expires_ms, g.revoked_ms IS NULL,
                    g.user_id, u.active = 1 AND (u.kind = 0 OR u.service_tenant_id = g.tenant_id),
                    g.resource
             FROM oauth_refresh_tokens r
             JOIN oauth_grants g ON g.id = r.grant_id
             JOIN users u ON u.id = g.user_id
             WHERE r.token_digest = ?1",
        )?
        .query_row([digest.0], |r| {
            Ok((
                r.get::<_, [u8; 16]>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, Option<i64>>(2)?,
                r.get::<_, bool>(3)?,
                r.get::<_, i64>(4)?,
                r.get::<_, String>(5)?,
                r.get::<_, u8>(6)?,
                r.get::<_, i64>(7)?,
                r.get::<_, i64>(8)?,
                r.get::<_, bool>(9)?,
                r.get::<_, [u8; 16]>(10)?,
                r.get::<_, bool>(11)?,
                r.get::<_, u8>(12)?,
            ))
        })
        .optional()?;
    let Some((
        grant,
        generation,
        rotated,
        superseded,
        idle,
        client,
        kind,
        scopes,
        expires,
        live,
        user,
        account,
        grant_resource,
    )) = row
    else {
        return Ok(Refreshed::Invalid);
    };
    let grant_resource =
        Audience::from_code(grant_resource).ok_or(Error::Corrupt("oauth_grants.resource"))?;
    if !live
        || expires <= now.0
        || !account
        || client != client_id
        || !resource_matches(grant_resource, resource)
    {
        return Ok(Refreshed::Invalid);
    }
    let terms = GrantTerms {
        id: grant_of(grant)?,
        kind: GrantKind::from_code(kind).ok_or(Error::Corrupt("oauth_grants.kind"))?,
        scopes: decode_scopes(scopes)?,
        expires,
    };
    // Which presentation this is: the live token, a lost-response retry of
    // its parent, or a replay.
    let recovered_child = match rotated {
        None if !superseded => {
            if idle <= now.0 {
                return Ok(Refreshed::Invalid);
            }
            None
        }
        Some(at) if !superseded && now.0.saturating_sub(at) <= ROTATION_GRACE_MS => {
            // Recovery happens once: the presented token must have exactly
            // one child, never used and never superseded. A superseded
            // sibling means it was already recovered, so this is a replay.
            let children: Vec<(i64, Option<i64>, bool)> = tx
                .prepare_cached(RECOVERY_CHILDREN)?
                .query_map(params![grant, generation], |r| {
                    Ok((r.get(0)?, r.get(1)?, r.get(2)?))
                })?
                .take(2)
                .collect::<std::result::Result<_, _>>()?;
            match children.as_slice() {
                [(child, None, false)] => Some(*child),
                _ => return replay(tx, terms.id, user_of(user)?, now),
            }
        }
        _ => return replay(tx, terms.id, user_of(user)?, now),
    };
    let scopes = match narrow {
        None => terms.scopes,
        Some(n) if !n.is_empty() && terms.scopes.contains(n) => n,
        Some(_) => return Ok(Refreshed::InvalidScope),
    };
    match recovered_child {
        None => {
            tx.prepare_cached(
                "UPDATE oauth_refresh_tokens SET rotated_ms = ?2
                 WHERE token_digest = ?1 AND rotated_ms IS NULL",
            )?
            .execute(params![digest.0, now.0])?;
        }
        Some(child) => {
            tx.prepare_cached(
                "UPDATE oauth_refresh_tokens SET superseded = 1, rotated_ms = ?3
                 WHERE grant_id = ?1 AND generation = ?2",
            )?
            .execute(params![grant, child, now.0])?;
            tx.prepare_cached(
                "DELETE FROM oauth_access_tokens WHERE grant_id = ?1 AND generation = ?2",
            )?
            .execute(params![grant, child])?;
        }
    }
    let next: i64 = tx
        .prepare_cached("SELECT MAX(generation) + 1 FROM oauth_refresh_tokens WHERE grant_id = ?1")?
        .query_row([grant], |r| r.get(0))?;
    let minted = issue_pair(tx, &terms, next, Some(generation), scopes, now)?;
    tx.prepare_cached("UPDATE oauth_grants SET last_used_ms = ?2 WHERE id = ?1")?
        .execute(params![grant, now.0])?;
    Ok(Refreshed::Minted(minted))
}

/// Every child of one generation, superseded or not (see [`rotate`]).
const RECOVERY_CHILDREN: &str = "SELECT generation, rotated_ms, superseded
     FROM oauth_refresh_tokens WHERE grant_id = ?1 AND parent = ?2";

fn replay(
    tx: &Transaction<'_>,
    grant: GrantId,
    user: UserId,
    now: UnixMillis,
) -> Result<Refreshed> {
    revoke_row(tx, grant, reason::REFRESH_REPLAY, now)?;
    audit(tx, Event::OAuthRefreshReplay, None, Some(user), false, None)?;
    Ok(Refreshed::Replay)
}

/// Revoke one live grant row with `reason`. Returns whether it was live.
pub(crate) fn revoke_row(
    tx: &Transaction<'_>,
    grant: GrantId,
    reason: u8,
    now: UnixMillis,
) -> Result<bool> {
    let changed = tx
        .prepare_cached(
            "UPDATE oauth_grants SET revoked_ms = ?2, revoked_reason = ?3
             WHERE id = ?1 AND revoked_ms IS NULL",
        )?
        .execute(params![grant.as_bytes(), now.0, reason])?;
    Ok(changed == 1)
}

/// RFC 7009 revocation by the token's holder: a refresh or access token of
/// `client_id` revokes its whole grant (reason 1). An unknown, malformed,
/// already revoked or other client's token is not an error: the endpoint
/// answers 200 either way, so nothing here confirms what exists.
pub fn revoke_presented(
    store: &Store,
    client_id: &str,
    token_text: &str,
    now: UnixMillis,
) -> Result<()> {
    let (sql, digest) = if let Some(secret) = forms::parse(Kind::Refresh, token_text) {
        (
            "SELECT g.id, g.user_id, g.client_id FROM oauth_refresh_tokens t
             JOIN oauth_grants g ON g.id = t.grant_id WHERE t.token_digest = ?1",
            secret.digest(),
        )
    } else if let Some(secret) = forms::parse(Kind::Access, token_text) {
        (
            "SELECT g.id, g.user_id, g.client_id FROM oauth_access_tokens t
             JOIN oauth_grants g ON g.id = t.grant_id WHERE t.token_digest = ?1",
            secret.digest(),
        )
    } else {
        return Ok(());
    };
    let client_id = client_id.to_owned();
    store.writer().write(move |tx| {
        let row = tx
            .prepare_cached(sql)?
            .query_row([digest.0], |r| {
                Ok((
                    r.get::<_, [u8; 16]>(0)?,
                    r.get::<_, [u8; 16]>(1)?,
                    r.get::<_, String>(2)?,
                ))
            })
            .optional()?;
        let Some((grant, user, client)) = row else {
            return Ok(());
        };
        if client != client_id {
            return Ok(());
        }
        let user = user_of(user)?;
        if revoke_row(tx, grant_of(grant)?, reason::LOGOUT, now)? {
            audit(
                tx,
                Event::OAuthGrantRevoked,
                Some(user),
                Some(user),
                false,
                Some("logout"),
            )?;
        }
        Ok(())
    })
}

/// Revoke one grant by its handle (reason 7). The grant's owner, a platform
/// administrator, or — for a service principal's grant — an administrator of
/// its home tenant may; anyone else sees `NotFound`. Revoking a revoked
/// grant is `Ok`.
pub fn revoke_grant(
    tx: &Transaction<'_>,
    authority: Authority,
    grant: GrantId,
    now: UnixMillis,
) -> Result<()> {
    let (owner, service_tenant) = tx
        .prepare_cached(
            "SELECT g.user_id, u.service_tenant_id FROM oauth_grants g
             JOIN users u ON u.id = g.user_id WHERE g.id = ?1",
        )?
        .query_row([grant.as_bytes()], |r| {
            Ok((r.get::<_, [u8; 16]>(0)?, r.get::<_, Option<[u8; 16]>>(1)?))
        })
        .optional()?
        .ok_or(Error::NotFound)?;
    let owner = user_of(owner)?;
    if authority.actor() != Some(owner) && authority.require_platform(tx).is_err() {
        let tenant_admin = match (authority.principal(), tenant_of(service_tenant)?) {
            (Some(principal), Some(tenant)) => {
                crate::auth::require_tenant_admin(tx, principal, tenant).is_ok()
            }
            _ => false,
        };
        if !tenant_admin {
            return Err(Error::NotFound);
        }
    }
    if revoke_row(tx, grant, reason::ADMIN, now)? {
        audit(
            tx,
            Event::OAuthGrantRevoked,
            authority.actor(),
            Some(owner),
            authority.host_local(),
            None,
        )?;
    }
    Ok(())
}

/// Revoke every live grant of an account with `reason` (see [`reason`]).
/// Called beside session revocation on suspension, rejection, password
/// change and recovery; suspension and rejection also revoke the account's
/// API credentials, while a password change and recovery leave them live
/// (they do not depend on the password; see local-authentication.md).
pub fn revoke_all_for_user(
    tx: &Transaction<'_>,
    user: UserId,
    reason: u8,
    now: UnixMillis,
) -> Result<usize> {
    let revoked = tx
        .prepare_cached(
            "UPDATE oauth_grants SET revoked_ms = ?2, revoked_reason = ?3
             WHERE user_id = ?1 AND revoked_ms IS NULL",
        )?
        .execute(params![user.as_bytes(), now.0, reason])?;
    Ok(revoked)
}

/// Revoke every live grant narrowed to a suspended tenant (reason 6).
pub(crate) fn revoke_for_tenant(
    tx: &Transaction<'_>,
    tenant: TenantId,
    now: UnixMillis,
) -> Result<usize> {
    let revoked = tx
        .prepare_cached(
            "UPDATE oauth_grants SET revoked_ms = ?2, revoked_reason = ?3
             WHERE tenant_id = ?1 AND revoked_ms IS NULL",
        )?
        .execute(params![tenant.as_bytes(), now.0, reason::TENANT])?;
    Ok(revoked)
}

/// Revoke an account's live grants narrowed to a tenant it left (reason 5).
pub(crate) fn revoke_for_membership(
    tx: &Transaction<'_>,
    user: UserId,
    tenant: TenantId,
    now: UnixMillis,
) -> Result<usize> {
    let revoked = tx
        .prepare_cached(
            "UPDATE oauth_grants SET revoked_ms = ?3, revoked_reason = ?4
             WHERE user_id = ?1 AND tenant_id = ?2 AND revoked_ms IS NULL",
        )?
        .execute(params![
            user.as_bytes(),
            tenant.as_bytes(),
            now.0,
            reason::MEMBERSHIP
        ])?;
    Ok(revoked)
}

/// Metadata about one grant. Never carries a token or a digest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GrantRecord {
    pub id: GrantId,
    pub user: UserId,
    pub client_id: String,
    pub kind: GrantKind,
    pub scopes: Scopes,
    pub tenant: Option<TenantId>,
    pub repo: Option<RepoId>,
    pub name: Option<String>,
    pub created: UnixMillis,
    pub expires: UnixMillis,
    pub last_used: Option<UnixMillis>,
    pub revoked: bool,
}

/// Columns [`grant_record`] decodes, in order; for sibling modules' queries.
pub(crate) const GRANT_COLUMNS: &str = "id, user_id,
    COALESCE((SELECT metadata_url FROM oauth_clients
        WHERE oauth_clients.client_id = oauth_grants.client_id), oauth_grants.client_id),
    kind, scopes, tenant_id, repo_id,
    name, created_ms, expires_ms, last_used_ms, revoked_ms";

type RawGrant = (
    [u8; 16],
    [u8; 16],
    String,
    u8,
    i64,
    Option<[u8; 16]>,
    Option<[u8; 16]>,
    Option<String>,
    i64,
    i64,
    Option<i64>,
    Option<i64>,
);

pub(crate) fn raw_grant(r: &rusqlite::Row<'_>) -> rusqlite::Result<RawGrant> {
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
        r.get(9)?,
        r.get(10)?,
        r.get(11)?,
    ))
}

pub(crate) fn grant_record(row: RawGrant) -> Result<GrantRecord> {
    Ok(GrantRecord {
        id: grant_of(row.0)?,
        user: user_of(row.1)?,
        client_id: row.2,
        kind: GrantKind::from_code(row.3).ok_or(Error::Corrupt("oauth_grants.kind"))?,
        scopes: decode_scopes(row.4)?,
        tenant: tenant_of(row.5)?,
        repo: repo_of(row.6)?,
        name: row.7,
        created: UnixMillis(row.8),
        expires: UnixMillis(row.9),
        last_used: row.10.map(UnixMillis),
        revoked: row.11.is_some(),
    })
}

/// One account's grants, newest first, at most 100. The account itself or a
/// platform administrator may look; anyone else sees `NotFound`.
pub fn grants(
    conn: &Connection,
    authority: Authority,
    user: UserId,
    limit: u16,
) -> Result<Vec<GrantRecord>> {
    if !(1..=100).contains(&limit) {
        return Err(Error::InvalidInput("page size"));
    }
    if authority.actor() != Some(user) {
        authority
            .require_platform(conn)
            .map_err(|_| Error::NotFound)?;
    }
    let mut stmt = conn.prepare_cached(&format!(
        "SELECT {GRANT_COLUMNS} FROM oauth_grants WHERE user_id = ?1
         ORDER BY created_ms DESC, id LIMIT ?2"
    ))?;
    let rows = stmt.query_map(params![user.as_bytes(), limit], raw_grant)?;
    rows.map(|row| grant_record(row?)).collect()
}

/// Issue a grant and its first token pair without an authorization decision.
/// Tests and host-local provisioning only; no route reaches it. The insert
/// trigger still refuses ineligible terms (`Forbidden`).
pub fn issue_grant_trusted(store: &Store, g: NewGrant<'_>, now: UnixMillis) -> Result<Minted> {
    let client = g.client_id.to_owned();
    let name = g.name.map(str::to_owned);
    store.writer().write(move |tx| {
        let g = NewGrant {
            client_id: &client,
            name: name.as_deref(),
            ..g
        };
        let grant = insert_grant(tx, &g, now)?;
        let minted = mint(tx, grant, g.scopes, now)?;
        audit(
            tx,
            Event::OAuthGrantIssued,
            g.created_by,
            Some(g.user),
            true,
            Some(g.kind.as_str()),
        )?;
        Ok(minted)
    })
}

/// Delete OAuth rows that can no longer do anything, at most `limit` per
/// category per call, in one bounded writer transaction: expired codes,
/// device requests and access tokens; refresh tokens past their idle expiry
/// or rotated more than [`ROTATED_RETENTION_MS`] ago; and expired or revoked
/// grants with everything that references them. Maintenance only: every
/// validation already checks expiry and revocation itself.
pub fn purge_expired(store: &Store, now: UnixMillis, limit: u32) -> Result<usize> {
    store.writer().write(move |tx| {
        let mut removed = 0;
        removed += tx.execute(
            "DELETE FROM oauth_codes WHERE code_digest IN
             (SELECT code_digest FROM oauth_codes WHERE expires_ms <= ?1 LIMIT ?2)",
            params![now.0, limit],
        )?;
        removed += tx.execute(
            "DELETE FROM oauth_device_codes WHERE device_digest IN
             (SELECT device_digest FROM oauth_device_codes WHERE expires_ms <= ?1 LIMIT ?2)",
            params![now.0, limit],
        )?;
        removed += tx.execute(
            "DELETE FROM oauth_access_tokens WHERE token_digest IN
             (SELECT token_digest FROM oauth_access_tokens WHERE expires_ms <= ?1 LIMIT ?2)",
            params![now.0, limit],
        )?;
        removed += tx.execute(
            "DELETE FROM oauth_refresh_tokens WHERE token_digest IN
             (SELECT token_digest FROM oauth_refresh_tokens WHERE idle_expires_ms <= ?1 LIMIT ?2)",
            params![now.0, limit],
        )?;
        removed += tx.execute(
            "DELETE FROM oauth_refresh_tokens WHERE token_digest IN
             (SELECT token_digest FROM oauth_refresh_tokens
              WHERE rotated_ms IS NOT NULL AND rotated_ms <= ?1 LIMIT ?2)",
            params![now.0.saturating_sub(ROTATED_RETENTION_MS), limit],
        )?;
        let mut dead: Vec<[u8; 16]> = tx
            .prepare_cached(
                "SELECT id FROM oauth_grants WHERE expires_ms <= ?1
                 UNION ALL SELECT id FROM oauth_grants WHERE revoked_ms IS NOT NULL LIMIT ?2",
            )?
            .query_map(params![now.0, limit], |r| r.get(0))?
            .collect::<std::result::Result<_, _>>()?;
        // Expired and revoked overlap; each grant is deleted once.
        dead.sort_unstable();
        dead.dedup();
        for grant in dead {
            for sql in [
                "DELETE FROM oauth_access_tokens WHERE grant_id = ?1",
                "DELETE FROM oauth_refresh_tokens WHERE grant_id = ?1",
                "DELETE FROM oauth_codes WHERE grant_id = ?1",
                "DELETE FROM oauth_device_codes WHERE grant_id = ?1",
                "DELETE FROM oauth_grants WHERE id = ?1",
            ] {
                removed += tx.prepare_cached(sql)?.execute([grant])?;
            }
        }
        Ok(removed)
    })
}

#[cfg(test)]
mod tests {
    use rusqlite::Connection;

    fn plans(conn: &Connection, sql: &str) -> Vec<String> {
        let mut stmt = conn.prepare(&format!("EXPLAIN QUERY PLAN {sql}")).unwrap();
        let values = vec![rusqlite::types::Value::Null; stmt.parameter_count()];
        stmt.query_map(rusqlite::params_from_iter(values), |r| r.get(3))
            .unwrap()
            .map(|r| r.unwrap())
            .collect()
    }

    /// Access-token validation runs on every OAuth request: it must stay a
    /// primary-key probe plus two key joins, never a scan or a sort.
    #[test]
    fn access_token_validation_is_three_key_searches() {
        let mut conn = Connection::open_in_memory().unwrap();
        crate::migrate(&mut conn).unwrap();
        let plans = plans(&conn, super::AUTHENTICATE_ACCESS);
        assert_eq!(plans.len(), 3, "{plans:?}");
        assert!(plans.iter().all(|p| p.starts_with("SEARCH ")), "{plans:?}");
        assert!(plans.iter().all(|p| p.contains("PRIMARY KEY")), "{plans:?}");
        assert!(
            plans.iter().all(|p| !p.contains("TEMP B-TREE")),
            "{plans:?}"
        );
    }

    /// Revocation cascades and the replay lookup use indexes, not scans.
    #[test]
    fn revocation_and_rotation_lookups_are_index_searches() {
        let mut conn = Connection::open_in_memory().unwrap();
        crate::migrate(&mut conn).unwrap();
        for sql in [
            super::RECOVERY_CHILDREN,
            "SELECT MAX(generation) + 1 FROM oauth_refresh_tokens WHERE grant_id = ?1",
            "UPDATE oauth_grants SET revoked_ms = ?2 WHERE user_id = ?1 AND revoked_ms IS NULL",
            "UPDATE oauth_grants SET revoked_ms = ?2 WHERE tenant_id = ?1 AND revoked_ms IS NULL",
            "SELECT id FROM oauth_grants WHERE expires_ms <= ?1
             UNION ALL SELECT id FROM oauth_grants WHERE revoked_ms IS NOT NULL LIMIT ?2",
        ] {
            let plans = plans(&conn, sql);
            assert!(
                plans.iter().all(|p| !p.starts_with("SCAN ")),
                "{sql}: {plans:?}"
            );
        }
    }
}
