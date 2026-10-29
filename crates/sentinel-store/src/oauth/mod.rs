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
    GrantId, RepoId, SessionId, TenantId, UnixMillis, UserId,
    auth::{Audience, Permissions, Principal, Scopes},
};

use crate::{
    Error, Result, Store,
    auth::Authority,
    local_auth::{Event, audit},
};

const MINUTE_MS: i64 = 60 * 1000;
const DAY_MS: i64 = 24 * 60 * MINUTE_MS;

pub const ACCESS_LIFETIME_MS: i64 = 10 * MINUTE_MS;
pub const REFRESH_IDLE_MS: i64 = 30 * DAY_MS;
pub const GRANT_MAX_MS: i64 = 90 * DAY_MS;
pub const LOGIN_GRANT_MS: i64 = GRANT_MAX_MS;
pub const CODE_LIFETIME_MS: i64 = 60 * 1000;
pub const DEVICE_LIFETIME_MS: i64 = 10 * MINUTE_MS;
pub const DEVICE_INTERVAL_MS: i64 = 5 * 1000;
pub const SLOW_DOWN_STEP_MS: i64 = 5 * 1000;
pub const ROTATION_GRACE_MS: i64 = 60 * 1000;
pub const SERVICE_DEFAULT_MS: i64 = 30 * DAY_MS;
pub const SERVICE_MIN_MS: i64 = 60 * MINUTE_MS;
pub const SERVICE_MAX_MS: i64 = GRANT_MAX_MS;
pub const MAX_PENDING_DEVICE: usize = 1024;
pub const ROTATED_RETENTION_MS: i64 = DAY_MS;

pub mod reason {
    pub const LOGOUT: u8 = 1;
    pub const REFRESH_REPLAY: u8 = 2;
    pub const CODE_REPLAY: u8 = 3;
    pub const ACCOUNT: u8 = 4;
    pub const MEMBERSHIP: u8 = 5;
    pub const TENANT: u8 = 6;
    pub const ADMIN: u8 = 7;
}

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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Client {
    pub id: String,
    pub display_id: String,
    pub name: String,
    pub first_party: bool,
    pub loopback: bool,
    pub redirect_path: Option<String>,
    pub device: bool,
    pub max_scopes: Scopes,
    pub resource: Audience,
    pub registered: bool,
}

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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum McpRegistrationKind {
    Dynamic,
    Metadata,
}

#[derive(Clone, Copy, Debug)]
pub struct McpClientSpec<'a> {
    pub id: &'a str,
    pub name: &'a str,
    pub max_scopes: Scopes,
    pub kind: McpRegistrationKind,
    pub metadata_url: Option<&'a str>,
}

#[derive(Debug)]
pub enum McpRegistrationError {
    Capacity,
    Registrant,
    Store(Error),
}

pub const MAX_MCP_CLIENTS: i64 = 512;
pub const MAX_MCP_CLIENTS_PER_REGISTRANT: i64 = 16;
pub const UNUSED_CLIENT_TTL_MS: i64 = DAY_MS;
pub const EVICTABLE_CLIENT_AGE_MS: i64 = 15 * MINUTE_MS;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ClientRegistration {
    Off = 0,
    Metadata = 1,
    Open = 2,
}

impl ClientRegistration {
    pub const fn dynamic(self) -> bool {
        matches!(self, Self::Open)
    }
    pub const fn metadata(self) -> bool {
        matches!(self, Self::Metadata | Self::Open)
    }
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Metadata => "metadata",
            Self::Open => "open",
        }
    }
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "off" => Some(Self::Off),
            "metadata" => Some(Self::Metadata),
            "open" => Some(Self::Open),
            _ => None,
        }
    }
}

pub fn client_registration(conn: &Connection) -> Result<ClientRegistration> {
    let code: i64 = conn
        .prepare_cached("SELECT oauth_client_registration FROM deployment_policy WHERE id = 1")?
        .query_row([], |r| r.get(0))?;
    match code {
        0 => Ok(ClientRegistration::Off),
        1 => Ok(ClientRegistration::Metadata),
        2 => Ok(ClientRegistration::Open),
        _ => Err(Error::Corrupt(
            "deployment_policy.oauth_client_registration",
        )),
    }
}

pub fn set_client_registration(
    tx: &Transaction<'_>,
    authority: Authority,
    mode: ClientRegistration,
    now: UnixMillis,
) -> Result<()> {
    authority.require_privileged(tx)?;
    tx.execute(
        "UPDATE deployment_policy SET oauth_client_registration = ?1, updated_ms = ?2,
         updated_by = ?3 WHERE id = 1",
        params![
            mode as u8,
            now.0,
            authority.actor().as_ref().map(UserId::as_bytes)
        ],
    )?;
    let detail = format!("oauth_client_registration={}", mode.as_str());
    audit(
        tx,
        Event::PolicyChanged,
        authority.actor(),
        None,
        authority.host_local(),
        Some(&detail),
    )
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegisteredClient {
    pub id: String,
    pub metadata_url: Option<String>,
    pub name: String,
    pub kind: McpRegistrationKind,
    pub created: UnixMillis,
    pub disabled: Option<UnixMillis>,
    pub live_grants: u32,
}

pub fn registered_clients(conn: &Connection, now: UnixMillis) -> Result<Vec<RegisteredClient>> {
    let mut statement = conn.prepare_cached(
        "SELECT c.client_id, c.metadata_url, c.name, c.registration_kind, c.created_ms,
                c.disabled_ms,
                (SELECT count(*) FROM oauth_grants g WHERE g.client_id = c.client_id
                    AND g.revoked_ms IS NULL AND g.expires_ms > ?1)
         FROM oauth_clients c WHERE c.registration_kind != 0
         ORDER BY c.registration_kind, c.created_ms",
    )?;
    let rows = statement.query_map([now.0], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, Option<String>>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, u8>(3)?,
            r.get::<_, i64>(4)?,
            r.get::<_, Option<i64>>(5)?,
            r.get::<_, i64>(6)?,
        ))
    })?;
    let mut clients = Vec::new();
    for row in rows {
        let (id, metadata_url, name, kind, created, disabled, live) = row?;
        clients.push(RegisteredClient {
            id,
            metadata_url,
            name,
            kind: match kind {
                1 => McpRegistrationKind::Dynamic,
                2 => McpRegistrationKind::Metadata,
                _ => return Err(Error::Corrupt("oauth_clients.registration_kind")),
            },
            created: UnixMillis(created),
            disabled: disabled.map(UnixMillis),
            live_grants: u32::try_from(live).unwrap_or(u32::MAX),
        });
    }
    Ok(clients)
}

pub fn set_client_disabled(
    tx: &Transaction<'_>,
    authority: Authority,
    client: &str,
    disabled: bool,
    now: UnixMillis,
) -> Result<u32> {
    authority.require_privileged(tx)?;
    let (id, was_disabled): (String, bool) = tx
        .prepare_cached(
            "SELECT client_id, disabled_ms IS NOT NULL FROM oauth_clients
             WHERE registration_kind != 0 AND (client_id = ?1 OR metadata_url = ?1)",
        )?
        .query_row([client], |r| Ok((r.get(0)?, r.get(1)?)))
        .optional()?
        .ok_or(Error::NotFound)?;
    let mut revoked = 0;
    if disabled {
        tx.prepare_cached(
            "UPDATE oauth_clients SET disabled_ms = ?2 WHERE client_id = ?1 AND disabled_ms IS NULL",
        )?
        .execute(params![id, now.0])?;
        revoked = tx
            .prepare_cached(
                "UPDATE oauth_grants SET revoked_ms = ?2, revoked_reason = ?3
                 WHERE client_id = ?1 AND revoked_ms IS NULL",
            )?
            .execute(params![id, now.0, reason::ADMIN])?;
    } else if was_disabled {
        let enabled: i64 = tx
            .prepare_cached(
                "SELECT count(*) FROM oauth_clients
                 WHERE registration_kind != 0 AND disabled_ms IS NULL",
            )?
            .query_row([], |r| r.get(0))?;
        if enabled >= MAX_MCP_CLIENTS {
            return Err(Error::Conflict);
        }
        tx.prepare_cached("UPDATE oauth_clients SET disabled_ms = NULL WHERE client_id = ?1")?
            .execute([&id])?;
    }
    let mut detail = String::with_capacity(96);
    detail.push_str(if disabled {
        "oauth client disabled "
    } else {
        "oauth client enabled "
    });
    detail.push_str(&id);
    audit(
        tx,
        Event::PolicyChanged,
        authority.actor(),
        None,
        authority.host_local(),
        Some(&detail),
    )?;
    Ok(u32::try_from(revoked).unwrap_or(u32::MAX))
}

pub fn registrant_digest(key: u128) -> [u8; 16] {
    let digest = blake3::hash(&key.to_be_bytes());
    let mut out = [0; 16];
    out.copy_from_slice(&digest.as_bytes()[..16]);
    out
}

macro_rules! client_unused {
    () => {
        "NOT EXISTS(SELECT 1 FROM oauth_grants g WHERE g.client_id = c.client_id)
         AND NOT EXISTS(SELECT 1 FROM oauth_codes k WHERE k.client_id = c.client_id)"
    };
}

const EVICTION_CANDIDATE: &str = concat!(
    "SELECT c.client_id FROM oauth_clients c
     WHERE c.registration_kind != 0 AND c.disabled_ms IS NULL AND c.created_ms <= ?1 AND ",
    client_unused!(),
    " ORDER BY c.registration_kind, c.created_ms LIMIT 1"
);

/// Keeps a disabled CIMD row: presenting its document again would register it afresh.
const UNUSED_CLIENTS: &str = concat!(
    "SELECT c.client_id FROM oauth_clients c
     WHERE c.registration_kind != 0 AND c.created_ms <= ?1
       AND NOT (c.registration_kind = 2 AND c.disabled_ms IS NOT NULL) AND ",
    client_unused!(),
    " LIMIT ?2"
);

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

pub fn client(conn: &Connection, client_id: &str) -> Result<Client> {
    if client_id.is_empty() || client_id.len() > 64 {
        return Err(Error::NotFound);
    }
    let row = conn
        .prepare_cached(
            "SELECT client_id, COALESCE(metadata_url, client_id), name, first_party,
                    loopback, redirect_path, device, max_scopes, resource, registration_kind
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
                r.get::<_, u8>(9)?,
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
        registered: row.9 != 0,
    })
}

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
    let key = forms::loopback_redirect_key(uri);
    let listed: bool = conn
        .prepare_cached(
            "SELECT EXISTS(SELECT 1 FROM oauth_client_redirects WHERE client_id = ?1
             AND uri IN (?2, ?3))",
        )?
        .query_row(
            params![client.id, uri, key.as_deref().unwrap_or(uri)],
            |r| r.get(0),
        )?;
    Ok(listed)
}

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

pub fn register_mcp_client(
    store: &Store,
    spec: &McpClientSpec<'_>,
    redirects: &[&str],
) -> std::result::Result<(), McpRegistrationError> {
    register_mcp_client_from(store, spec, redirects, None, UnixMillis::now())
}

pub fn register_mcp_client_from(
    store: &Store,
    spec: &McpClientSpec<'_>,
    redirects: &[&str],
    registrant: Option<[u8; 16]>,
    now: UnixMillis,
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
    let mut stored: Vec<String> = Vec::with_capacity(redirects.len());
    for uri in redirects {
        let form = forms::loopback_redirect_key(uri).unwrap_or_else(|| (*uri).to_owned());
        if !stored.contains(&form) {
            stored.push(form);
        }
    }
    let id = spec.id.to_owned();
    let name = spec.name.to_owned();
    let max_scopes = spec.max_scopes.bits();
    let kind = match spec.kind {
        McpRegistrationKind::Dynamic => 1u8,
        McpRegistrationKind::Metadata => 2u8,
    };
    let metadata_url = spec.metadata_url.map(str::to_owned);
    let inserted = store
        .writer()
        .write(move |tx| {
            let reserved: bool = tx
                .prepare_cached(
                    "SELECT EXISTS(SELECT 1 FROM oauth_clients
                     WHERE registration_kind = 0 AND lower(name) = lower(?1))",
                )?
                .query_row([&name], |row| row.get(0))?;
            if reserved {
                return Err(Error::InvalidInput("client_name"));
            }
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
                if let Some(registrant) = registrant {
                    let held: i64 = tx
                        .prepare_cached(
                            "SELECT count(*) FROM oauth_clients
                             WHERE registrant = ?1 AND disabled_ms IS NULL",
                        )?
                        .query_row([registrant], |row| row.get(0))?;
                    if held >= MAX_MCP_CLIENTS_PER_REGISTRANT {
                        return Ok(Some(McpRegistrationError::Registrant));
                    }
                }
                let count: i64 = tx
                    .prepare_cached(
                        "SELECT count(*) FROM oauth_clients
                         WHERE registration_kind != 0 AND disabled_ms IS NULL",
                    )?
                    .query_row([], |row| row.get(0))?;
                if count >= MAX_MCP_CLIENTS {
                    let victim: Option<String> = tx
                        .prepare_cached(EVICTION_CANDIDATE)?
                        .query_row([now.0.saturating_sub(EVICTABLE_CLIENT_AGE_MS)], |row| {
                            row.get(0)
                        })
                        .optional()?;
                    let Some(victim) = victim else {
                        return Ok(Some(McpRegistrationError::Capacity));
                    };
                    delete_client(tx, &victim)?;
                }
                tx.execute(
                    "INSERT INTO oauth_clients(client_id, name, first_party, loopback,
                        redirect_path, device, max_scopes, created_ms, resource,
                        registration_kind, metadata_url, registrant)
                     VALUES (?1, ?2, 0, 0, NULL, 0, ?3, ?4, 2, ?5, ?6, ?7)",
                    params![id, name, max_scopes, now.0, kind, metadata_url, registrant],
                )?;
            }
            for uri in &stored {
                tx.execute(
                    "INSERT INTO oauth_client_redirects(client_id, uri) VALUES (?1, ?2)",
                    params![id, uri],
                )?;
            }
            Ok(None)
        })
        .map_err(McpRegistrationError::Store)?;
    match inserted {
        None => Ok(()),
        Some(refusal) => Err(refusal),
    }
}

fn delete_client(tx: &Transaction<'_>, client: &str) -> Result<()> {
    tx.prepare_cached("DELETE FROM oauth_client_redirects WHERE client_id = ?1")?
        .execute([client])?;
    tx.prepare_cached("DELETE FROM oauth_clients WHERE client_id = ?1 AND registration_kind != 0")?
        .execute([client])?;
    Ok(())
}

#[derive(Clone, Copy, Debug)]
pub struct NewGrant<'a> {
    pub user: UserId,
    pub client_id: &'a str,
    pub kind: GrantKind,
    pub scopes: Scopes,
    pub tenant: Option<TenantId>,
    pub repo: Option<RepoId>,
    pub audience: Audience,
    pub name: Option<&'a str>,
    pub lifetime_ms: i64,
    pub created_by: Option<UserId>,
    pub created_session: Option<SessionId>,
}

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
    if g.kind != GrantKind::Service && g.created_session.is_some() {
        return Err(Error::InvalidInput("grant session provenance"));
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
            audience, name, created_by, created_session, created_ms, expires_ms, resource)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 1, ?8, ?9, ?10, ?11, ?12, ?13)",
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
        g.created_session.as_ref().map(SessionId::as_bytes),
        now.0,
        now.0.saturating_add(g.lifetime_ms),
        g.audience.code()
    ])
    .map_err(refused)?;
    Ok(id)
}

#[derive(Debug)]
pub struct Minted {
    pub grant: GrantId,
    pub access: Secret,
    pub access_expires: UnixMillis,
    pub refresh: Secret,
    pub refresh_expires: UnixMillis,
    pub scopes: Scopes,
}

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

#[derive(Clone, Copy, Debug)]
pub struct Authenticated {
    pub grant: GrantId,
    pub principal: Principal,
    pub scopes: Scopes,
    pub expires: UnixMillis,
}

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

pub(crate) fn resource_matches(granted: Audience, requested: Option<Audience>) -> bool {
    match requested {
        Some(requested) => granted == requested,
        None => granted == Audience::Api,
    }
}

#[derive(Debug)]
pub enum RefreshError {
    Invalid,
    Replay,
    InvalidScope,
    Store(Error),
}

enum Refreshed {
    Minted(Minted),
    Invalid,
    Replay,
    InvalidScope,
}

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
    let recovered_child = match rotated {
        None if !superseded => {
            if idle <= now.0 {
                return Ok(Refreshed::Invalid);
            }
            None
        }
        Some(at) if !superseded && now.0.saturating_sub(at) <= ROTATION_GRACE_MS => {
            // Recovery happens once: a superseded sibling means it already happened.
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

/// Unknown or foreign tokens are not errors, so the response never confirms what exists.
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

/// Column order must match raw_grant and grant_record.
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

pub fn own_grant(conn: &Connection, user: UserId, grant: GrantId) -> Result<GrantRecord> {
    let row = conn
        .prepare_cached(&format!(
            "SELECT {GRANT_COLUMNS} FROM oauth_grants WHERE id = ?1 AND user_id = ?2"
        ))?
        .query_row(params![grant.as_bytes(), user.as_bytes()], raw_grant)
        .optional()?
        .ok_or(Error::NotFound)?;
    grant_record(row)
}

/// Revokes the live service grants one browser session minted, by the session's retained public ID.
/// Served by `oauth_grants_by_created_session`; the plan is asserted in `tests/oauth_service.rs`.
#[doc(hidden)]
pub const REVOKE_MINTED_BY_SESSION: &str =
    "UPDATE oauth_grants SET revoked_ms = ?3, revoked_reason = ?4
             WHERE revoked_ms IS NULL AND kind = 3
             AND created_by = ?1 AND created_session = ?2";

/// Revokes every live service grant a user minted from any session (logout-all).
#[doc(hidden)]
pub const REVOKE_MINTED_BY_USER: &str =
    "UPDATE oauth_grants SET revoked_ms = ?2, revoked_reason = ?3
             WHERE revoked_ms IS NULL AND kind = 3
             AND created_by = ?1 AND created_session IS NOT NULL";

/// Revokes the service grants a user minted without a session (`created_session IS NULL`: grants
/// from before migration 55, and grants minted by a non-session credential) inside a time window.
#[doc(hidden)]
pub const REVOKE_MINTED_LEGACY: &str =
    "UPDATE oauth_grants SET revoked_ms = ?3, revoked_reason = ?4
             WHERE expires_ms > ?3 AND revoked_ms IS NULL AND kind = 3
             AND created_by = ?1 AND created_session IS NULL
             AND created_ms >= ?2 AND created_ms <= ?3";

pub(crate) fn revoke_minted_for_session(
    tx: &Transaction<'_>,
    minter: UserId,
    session: SessionId,
    legacy_since: UnixMillis,
    now: UnixMillis,
) -> Result<usize> {
    let mut revoked = tx
        .prepare_cached(REVOKE_MINTED_BY_SESSION)?
        .execute(params![
            minter.as_bytes(),
            session.as_bytes(),
            now.0,
            reason::ACCOUNT
        ])?;
    revoked += revoke_legacy_minted_since(tx, minter, legacy_since, now)?;
    audit_minted_revocation(tx, minter, revoked)?;
    Ok(revoked)
}

pub(crate) fn revoke_all_minted(
    tx: &Transaction<'_>,
    minter: UserId,
    legacy_since: Option<UnixMillis>,
    now: UnixMillis,
) -> Result<usize> {
    let mut revoked = tx.prepare_cached(REVOKE_MINTED_BY_USER)?.execute(params![
        minter.as_bytes(),
        now.0,
        reason::ACCOUNT
    ])?;
    if let Some(since) = legacy_since {
        revoked += revoke_legacy_minted_since(tx, minter, since, now)?;
    }
    audit_minted_revocation(tx, minter, revoked)?;
    Ok(revoked)
}

fn revoke_legacy_minted_since(
    tx: &Transaction<'_>,
    minter: UserId,
    since: UnixMillis,
    now: UnixMillis,
) -> Result<usize> {
    Ok(tx.prepare_cached(REVOKE_MINTED_LEGACY)?.execute(params![
        minter.as_bytes(),
        since.0,
        now.0,
        reason::ACCOUNT
    ])?)
}

fn audit_minted_revocation(tx: &Transaction<'_>, minter: UserId, revoked: usize) -> Result<()> {
    if revoked > 0 {
        audit(
            tx,
            Event::OAuthGrantRevoked,
            None,
            Some(minter),
            false,
            Some(&format!(
                "{revoked} service grants minted in session window"
            )),
        )?;
    }
    Ok(())
}

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
        let unused: Vec<String> = tx
            .prepare_cached(UNUSED_CLIENTS)?
            .query_map(
                params![now.0.saturating_sub(UNUSED_CLIENT_TTL_MS), limit],
                |r| r.get(0),
            )?
            .collect::<std::result::Result<_, _>>()?;
        for client in &unused {
            delete_client(tx, client)?;
        }
        removed += unused.len();
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

    #[test]
    fn registration_reclamation_reads_only_registrations_and_key_searches() {
        let mut conn = Connection::open_in_memory().unwrap();
        crate::migrate(&mut conn).unwrap();
        for sql in [super::EVICTION_CANDIDATE, super::UNUSED_CLIENTS] {
            let plans = plans(&conn, sql);
            for plan in &plans {
                assert!(
                    !plan.starts_with("SCAN ")
                        || plan == "SCAN c USING INDEX oauth_clients_by_registration",
                    "{sql}: {plans:?}"
                );
                assert!(!plan.contains("TEMP B-TREE"), "{sql}: {plans:?}");
            }
            assert!(
                plans
                    .iter()
                    .any(|p| p.contains("SEARCH g USING COVERING INDEX oauth_grants_by_client")),
                "{plans:?}"
            );
            assert!(
                plans
                    .iter()
                    .any(|p| p.contains("SEARCH k USING COVERING INDEX oauth_codes_by_client")),
                "{plans:?}"
            );
        }
    }

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
            "UPDATE oauth_grants SET revoked_ms = ?2, revoked_reason = ?3
             WHERE client_id = ?1 AND revoked_ms IS NULL",
            super::REVOKE_MINTED_BY_SESSION,
            super::REVOKE_MINTED_BY_USER,
        ] {
            let plans = plans(&conn, sql);
            assert!(
                plans.iter().all(|p| !p.starts_with("SCAN ")),
                "{sql}: {plans:?}"
            );
        }
    }
}
