//! The device authorization flow's durable half (O03, RFC 8628): pending
//! requests, approval or denial by a signed-in account, and one-time
//! redemption.
//!
//! A request is one `oauth_device_codes` row keyed by the device code's
//! digest, with a unique user code. Migration 30 moves its status only
//! pending → approved | denied and approved → redeemed, lets the approver
//! narrow the scopes once, and writes every decision term once. Polling is a
//! single primary-key read; only the poll that finds an approved request
//! writes, and it issues the grant, its first token pair and the redemption
//! in one transaction, so a request yields tokens at most once.
//!
//! Admission applies as it does to browser login: the approver must be an
//! active account when deciding, and the grant's insert trigger re-checks it
//! at redemption. An approver suspended in between redeems nothing.

use rusqlite::{Connection, OptionalExtension, Transaction, params};
use sentinel_auth::{oauth as forms, secret::Secret};
use sentinel_core::{
    RepoId, TenantId, UnixMillis, UserId,
    auth::{Audience, Scopes},
};

use super::{
    DEVICE_INTERVAL_MS, DEVICE_LIFETIME_MS, GrantKind, LOGIN_GRANT_MS, MAX_PENDING_DEVICE, Minted,
    NewGrant, decode_scopes, insert_grant, mint, repo_of, tenant_of, user_of,
};
use crate::{
    Error, Result, Store,
    local_auth::{Event, audit},
};

/// Stored `oauth_device_codes.status` values.
const PENDING: u8 = 0;
const APPROVED: u8 = 1;
const DENIED: u8 = 2;
const REDEEMED: u8 = 3;

/// Fresh user codes tried when one collides with an existing row. A
/// collision needs one of the at most [`MAX_PENDING_DEVICE`] live codes (or
/// an unpurged expired one) out of 20^8; several in a row mean something
/// else is wrong.
const USER_CODE_ATTEMPTS: usize = 8;

/// A new pending request: the device code (for the polling client only)
/// and the canonical user code (8 characters, no dash).
#[derive(Debug)]
pub struct DeviceStart {
    pub device: Secret,
    pub user_code: String,
    pub expires: UnixMillis,
    pub interval_ms: i64,
}

/// Open a pending device request for a device-capable client.
///
/// `NotFound`: unknown or disabled client. `Forbidden`: the client may not
/// use the device flow. `InvalidInput("scope")`: empty or beyond the
/// client's ceiling. `QuotaExceeded`: the deployment already holds
/// [`MAX_PENDING_DEVICE`] unexpired pending requests (the endpoint answers
/// `429 slow_down`).
pub fn begin(
    store: &Store,
    client_id: &str,
    scopes: Scopes,
    audience: Audience,
    now: UnixMillis,
) -> Result<DeviceStart> {
    let client_id = client_id.to_owned();
    store.writer().write(move |tx| {
        let client = super::client(tx, &client_id)?;
        if !client.device {
            return Err(Error::Forbidden);
        }
        if scopes.is_empty() || !client.max_scopes.contains(scopes) {
            return Err(Error::InvalidInput("scope"));
        }
        // Counted through the partial index on pending rows, and never past
        // the cap: the cost is bounded whatever the table holds.
        let pending: i64 = tx
            .prepare_cached(
                "SELECT COUNT(*) FROM (SELECT 1 FROM oauth_device_codes
                 WHERE status = 0 AND expires_ms > ?1 LIMIT ?2)",
            )?
            .query_row(params![now.0, MAX_PENDING_DEVICE as i64], |r| r.get(0))?;
        if pending >= MAX_PENDING_DEVICE as i64 {
            return Err(Error::QuotaExceeded);
        }
        let device = Secret::generate();
        let digest = device.digest().0;
        let expires = now.0.saturating_add(DEVICE_LIFETIME_MS);
        let mut insert = tx.prepare_cached(
            "INSERT INTO oauth_device_codes(device_digest, user_code, client_id, scopes,
                audience, created_ms, expires_ms, resource)
             VALUES (?1, ?2, ?3, ?4, 1, ?5, ?6, ?7) ON CONFLICT(user_code) DO NOTHING",
        )?;
        for _ in 0..USER_CODE_ATTEMPTS {
            let user_code = forms::user_code();
            let inserted = insert.execute(params![
                digest,
                user_code,
                client_id,
                scopes.bits(),
                now.0,
                expires,
                audience.code()
            ])?;
            if inserted == 1 {
                return Ok(DeviceStart {
                    device,
                    user_code,
                    expires: UnixMillis(expires),
                    interval_ms: DEVICE_INTERVAL_MS,
                });
            }
        }
        Err(Error::Conflict)
    })
}

/// What the approval page shows for a pending user code.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceView {
    pub client_name: String,
    pub scopes: Scopes,
    pub expires: UnixMillis,
}

/// Look up a pending, unexpired request by its canonical user code (see
/// `sentinel_auth::oauth::normalize_user_code`). Anything else — unknown,
/// decided, redeemed, expired — is `NotFound`.
pub fn view(conn: &Connection, user_code: &str, now: UnixMillis) -> Result<DeviceView> {
    let (name, scopes, expires) = conn
        .prepare_cached(
            "SELECT c.name, d.scopes, d.expires_ms FROM oauth_device_codes d
             JOIN oauth_clients c ON c.client_id = d.client_id
             WHERE d.user_code = ?1 AND d.status = 0 AND d.expires_ms > ?2",
        )?
        .query_row(params![user_code, now.0], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, i64>(2)?,
            ))
        })
        .optional()?
        .ok_or(Error::NotFound)?;
    Ok(DeviceView {
        client_name: name,
        scopes: decode_scopes(scopes)?,
        expires: UnixMillis(expires),
    })
}

/// The signed-in account's answer.
#[derive(Clone, Copy, Debug)]
pub enum Decision {
    /// Approve with `scopes` (the request's, or a narrowing of them),
    /// optionally narrowed to one tenant the account is a member of and one
    /// repository of that tenant.
    Approve {
        scopes: Scopes,
        tenant: Option<TenantId>,
        repo: Option<RepoId>,
    },
    Deny,
}

/// Record `user`'s decision on a pending request, in one transaction.
///
/// `NotFound`: no pending, unexpired request has this user code (the page
/// counts it as a wrong code). `Forbidden`: the account is not an active
/// person, asks for `platform:admin` without being a super admin, or
/// narrows to a tenant it is not an active member of or a repository
/// outside that tenant. `InvalidInput("scope")`: empty or wider than asked.
pub fn decide(
    store: &Store,
    user_code: &str,
    user: UserId,
    d: Decision,
    now: UnixMillis,
) -> Result<()> {
    let user_code = user_code.to_owned();
    store
        .writer()
        .write(move |tx| decide_in(tx, &user_code, user, d, now))
}

fn decide_in(
    tx: &Transaction<'_>,
    user_code: &str,
    user: UserId,
    d: Decision,
    now: UnixMillis,
) -> Result<()> {
    let (digest, requested) = tx
        .prepare_cached(
            "SELECT device_digest, scopes FROM oauth_device_codes
             WHERE user_code = ?1 AND status = 0 AND expires_ms > ?2",
        )?
        .query_row(params![user_code, now.0], |r| {
            Ok((r.get::<_, [u8; 32]>(0)?, r.get::<_, i64>(1)?))
        })
        .optional()?
        .ok_or(Error::NotFound)?;
    // Only an active, admitted person decides: pending, rejected and
    // suspended accounts are inactive, service principals never sign in.
    let super_admin: bool = tx
        .prepare_cached("SELECT super_admin FROM users WHERE id = ?1 AND kind = 0 AND active = 1")?
        .query_row([user.as_bytes()], |r| r.get(0))
        .optional()?
        .ok_or(Error::Forbidden)?;
    let (status, scopes, tenant, repo, event) = match d {
        Decision::Deny => (DENIED, requested, None, None, Event::OAuthDeviceDenied),
        Decision::Approve {
            scopes,
            tenant,
            repo,
        } => {
            let requested = decode_scopes(requested)?;
            if scopes.is_empty() || !requested.contains(scopes) {
                return Err(Error::InvalidInput("scope"));
            }
            if scopes.contains(Scopes::PLATFORM_ADMIN) && !super_admin {
                return Err(Error::Forbidden);
            }
            match (tenant, repo) {
                (None, Some(_)) => return Err(Error::InvalidInput("repository without tenant")),
                (None, None) => {}
                (Some(tenant), repo) => {
                    let member: bool = tx
                        .prepare_cached(
                            "SELECT EXISTS(SELECT 1 FROM memberships m
                             JOIN tenants t ON t.id = m.tenant_id
                             WHERE m.tenant_id = ?1 AND m.user_id = ?2 AND t.active = 1)",
                        )?
                        .query_row(params![tenant.as_bytes(), user.as_bytes()], |r| r.get(0))?;
                    if !member {
                        return Err(Error::Forbidden);
                    }
                    if let Some(repo) = repo {
                        let owned: bool = tx
                            .prepare_cached(
                                "SELECT EXISTS(SELECT 1 FROM repos WHERE id = ?1 AND tenant_id = ?2)",
                            )?
                            .query_row(params![repo.as_bytes(), tenant.as_bytes()], |r| r.get(0))?;
                        if !owned {
                            return Err(Error::Forbidden);
                        }
                    }
                }
            }
            (
                APPROVED,
                i64::from(scopes.bits()),
                tenant,
                repo,
                Event::OAuthDeviceApproved,
            )
        }
    };
    tx.prepare_cached(
        "UPDATE oauth_device_codes SET status = ?2, scopes = ?3, user_id = ?4, tenant_id = ?5,
            repo_id = ?6, decided_ms = ?7 WHERE device_digest = ?1 AND status = 0",
    )?
    .execute(params![
        digest,
        status,
        scopes,
        user.as_bytes(),
        tenant.as_ref().map(TenantId::as_bytes),
        repo.as_ref().map(RepoId::as_bytes),
        now.0
    ])?;
    audit(tx, event, Some(user), Some(user), false, None)
}

/// What a poll finds.
#[derive(Debug)]
pub enum Poll {
    /// Not decided yet (`authorization_pending`).
    Pending,
    /// Denied, or approved by an account that can no longer hold a grant
    /// (`access_denied`).
    Denied,
    /// Undecided or unredeemed past its expiry (`expired_token`).
    Expired,
    /// The grant, issued now and never again.
    Issued(Minted),
}

/// Poll a request by its device code. A read unless the request is approved;
/// then one writer transaction issues the grant (kind device, the approved
/// terms, [`LOGIN_GRANT_MS`]), mints its first pair and marks the request
/// redeemed. `NotFound`: unknown device code, another client's, or already
/// redeemed (the endpoint answers `invalid_grant`).
pub fn poll(
    store: &Store,
    client_id: &str,
    device: &Secret,
    resource: Option<Audience>,
    now: UnixMillis,
) -> Result<Poll> {
    let digest = device.digest().0;
    let (status, expires) = store.read(|c| state(c, &digest, client_id))?;
    if let Some(answer) = classify(status, expires, now)? {
        return Ok(answer);
    }
    let client_id = client_id.to_owned();
    store
        .writer()
        .write(move |tx| redeem(tx, &digest, &client_id, resource, now))
}

/// Status and expiry of a device request of `client_id`.
fn state(conn: &Connection, digest: &[u8; 32], client_id: &str) -> Result<(u8, i64)> {
    conn.prepare_cached(
        "SELECT status, expires_ms FROM oauth_device_codes
         WHERE device_digest = ?1 AND client_id = ?2",
    )?
    .query_row(params![digest, client_id], |r| Ok((r.get(0)?, r.get(1)?)))
    .optional()?
    .ok_or(Error::NotFound)
}

/// The answer a status gives without writing; `None` for an approved,
/// unexpired request, which must be redeemed. A redeemed request is
/// `NotFound`, like an unknown one.
fn classify(status: u8, expires: i64, now: UnixMillis) -> Result<Option<Poll>> {
    Ok(match status {
        DENIED => Some(Poll::Denied),
        REDEEMED => return Err(Error::NotFound),
        PENDING | APPROVED if expires <= now.0 => Some(Poll::Expired),
        PENDING => Some(Poll::Pending),
        APPROVED => None,
        _ => return Err(Error::Corrupt("oauth_device_codes.status")),
    })
}

fn redeem(
    tx: &Transaction<'_>,
    digest: &[u8; 32],
    client_id: &str,
    requested_resource: Option<Audience>,
    now: UnixMillis,
) -> Result<Poll> {
    // Re-read in the writing transaction: a concurrent poll may have
    // redeemed it since the snapshot above.
    let row = tx
        .prepare_cached(
            "SELECT status, expires_ms, scopes, resource, user_id, tenant_id, repo_id
             FROM oauth_device_codes WHERE device_digest = ?1 AND client_id = ?2",
        )?
        .query_row(params![digest, client_id], |r| {
            Ok((
                r.get::<_, u8>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, u8>(3)?,
                r.get::<_, Option<[u8; 16]>>(4)?,
                r.get::<_, Option<[u8; 16]>>(5)?,
                r.get::<_, Option<[u8; 16]>>(6)?,
            ))
        })
        .optional()?
        .ok_or(Error::NotFound)?;
    let (status, expires, scopes, audience, user, tenant, repo) = row;
    if let Some(answer) = classify(status, expires, now)? {
        return Ok(answer);
    }
    let audience =
        Audience::from_code(audience).ok_or(Error::Corrupt("oauth_device_codes.resource"))?;
    if !super::resource_matches(audience, requested_resource) {
        return Ok(Poll::Denied);
    }
    let user = user_of(user.ok_or(Error::Corrupt("oauth_device_codes.user_id"))?)?;
    let scopes = decode_scopes(scopes)?;
    let grant = NewGrant {
        user,
        client_id,
        kind: GrantKind::Device,
        scopes,
        tenant: tenant_of(tenant)?,
        repo: repo_of(repo)?,
        audience,
        name: None,
        lifetime_ms: LOGIN_GRANT_MS,
        created_by: None,
    };
    const REDEEM: &str =
        "UPDATE oauth_device_codes SET status = 3, grant_id = ?2 WHERE device_digest = ?1";
    // The insert trigger re-checks the approver's admission, the platform
    // bit, the repository's tenant and the client: an approver suspended
    // since approving gets nothing, and the request is spent.
    let id = match insert_grant(tx, &grant, now) {
        Ok(id) => id,
        Err(Error::Forbidden) => {
            tx.prepare_cached(REDEEM)?
                .execute(params![digest, Option::<[u8; 16]>::None])?;
            return Ok(Poll::Denied);
        }
        Err(e) => return Err(e),
    };
    let minted = mint(tx, id, scopes, now)?;
    tx.prepare_cached(REDEEM)?
        .execute(params![digest, id.as_bytes()])?;
    audit(
        tx,
        Event::OAuthGrantIssued,
        Some(user),
        Some(user),
        false,
        Some(GrantKind::Device.as_str()),
    )?;
    Ok(Poll::Issued(minted))
}

#[cfg(test)]
mod tests {
    use rusqlite::Connection;

    /// The pending cap, the page's user-code lookup and the poll are index
    /// searches; none scans the table.
    #[test]
    fn device_lookups_are_index_searches() {
        let mut conn = Connection::open_in_memory().unwrap();
        crate::migrate(&mut conn).unwrap();
        for sql in [
            "SELECT COUNT(*) FROM (SELECT 1 FROM oauth_device_codes
             WHERE status = 0 AND expires_ms > ?1 LIMIT ?2)",
            "SELECT c.name, d.scopes, d.expires_ms FROM oauth_device_codes d
             JOIN oauth_clients c ON c.client_id = d.client_id
             WHERE d.user_code = ?1 AND d.status = 0 AND d.expires_ms > ?2",
            "SELECT status, expires_ms FROM oauth_device_codes
             WHERE device_digest = ?1 AND client_id = ?2",
        ] {
            let mut stmt = conn.prepare(&format!("EXPLAIN QUERY PLAN {sql}")).unwrap();
            let values = vec![rusqlite::types::Value::Null; stmt.parameter_count()];
            let plans: Vec<String> = stmt
                .query_map(rusqlite::params_from_iter(values), |r| r.get(3))
                .unwrap()
                .map(|r| r.unwrap())
                .collect();
            // Scanning the bounded subquery's own rows is fine; a table is not.
            assert!(
                plans
                    .iter()
                    .all(|p| p.starts_with("SEARCH ") || p.contains("subquery")),
                "{sql}: {plans:?}"
            );
        }
    }
}
