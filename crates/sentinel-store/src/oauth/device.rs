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

const PENDING: u8 = 0;
const APPROVED: u8 = 1;
const DENIED: u8 = 2;
const REDEEMED: u8 = 3;

const USER_CODE_ATTEMPTS: usize = 8;

#[derive(Debug)]
pub struct DeviceStart {
    pub device: Secret,
    pub user_code: String,
    pub expires: UnixMillis,
    pub interval_ms: i64,
}

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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceView {
    pub client_name: String,
    pub scopes: Scopes,
    pub expires: UnixMillis,
}

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

#[derive(Clone, Copy, Debug)]
pub enum Decision {
    Approve {
        scopes: Scopes,
        tenant: Option<TenantId>,
        repo: Option<RepoId>,
    },
    Deny,
}

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
    // Only an active person decides: service principals never sign in.
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

#[derive(Debug)]
pub enum Poll {
    Pending,
    Denied,
    Expired,
    Issued(Minted),
}

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

fn state(conn: &Connection, digest: &[u8; 32], client_id: &str) -> Result<(u8, i64)> {
    conn.prepare_cached(
        "SELECT status, expires_ms FROM oauth_device_codes
         WHERE device_digest = ?1 AND client_id = ?2",
    )?
    .query_row(params![digest, client_id], |r| Ok((r.get(0)?, r.get(1)?)))
    .optional()?
    .ok_or(Error::NotFound)
}

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
    // Re-read here: a concurrent poll may have redeemed the request.
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
    // The insert trigger refuses a suspended approver; the request is still spent.
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
            assert!(
                plans
                    .iter()
                    .all(|p| p.starts_with("SEARCH ") || p.contains("subquery")),
                "{sql}: {plans:?}"
            );
        }
    }
}
