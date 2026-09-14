//! Scoped, expiring API credentials.
//!
//! This is the authenticated entry point for the CLI and API before browser
//! OAuth exists (A03). It is not a development bypass: a credential produces
//! the same [`Principal`] a session does, and every tenant, repository and
//! administrative decision remains a live check in [`crate::auth`]. There is no
//! code path that skips authentication, and none that returns `Permissions::ALL`
//! because a request looked local.
//!
//! A credential is a 256-bit opaque secret stored only as its BLAKE3 digest,
//! carrying an explicit scope and a mandatory expiry. It is shown exactly once,
//! at issuance; a lost credential is replaced, never recovered.

use rusqlite::{Connection, OptionalExtension, Transaction, params};
use sentinel_auth::secret::Secret;
use sentinel_core::{
    RepoId, TenantId, TokenId, UnixMillis, UserId,
    auth::{Permissions, Principal},
};

use crate::{
    Error, Result, Store,
    auth::Authority,
    local_auth::{Event, audit},
};

const DAY_MS: i64 = 24 * 60 * 60 * 1000;

/// Hard ceiling on a credential's life. An unattended agent renews; it does not
/// hold a credential that outlives the decision to grant it.
pub const MAX_LIFETIME_MS: i64 = 90 * DAY_MS;
/// Used when the issuer does not state a lifetime. There is no unlimited value.
pub const DEFAULT_LIFETIME_MS: i64 = 30 * DAY_MS;
/// Minimum age of `last_used_ms` before a request pays a write to update it.
pub const USE_RECORD_INTERVAL_MS: i64 = 60 * 1000;

/// What a credential may do, decided once at issuance. Widening means issuing a
/// new credential: the stored row is immutable except for use and revocation.
#[derive(Clone, Copy, Debug)]
pub struct Grant<'a> {
    /// The account that acts. A credential never carries an identity of its own.
    pub user: UserId,
    /// Operator-facing label, so a credential can be recognized and revoked.
    pub name: &'a str,
    /// Upper bound on authority, intersected with live membership per query.
    pub permissions: Permissions,
    /// Optional narrowing. A service principal must be scoped to its home tenant.
    pub tenant: Option<TenantId>,
    /// Optional narrowing to one repository of `tenant`.
    pub repo: Option<RepoId>,
    pub lifetime_ms: i64,
}

impl<'a> Grant<'a> {
    /// A grant with the default lifetime and no tenant/repository narrowing.
    pub const fn new(user: UserId, name: &'a str, permissions: Permissions) -> Self {
        Self {
            user,
            name,
            permissions,
            tenant: None,
            repo: None,
            lifetime_ms: DEFAULT_LIFETIME_MS,
        }
    }
}

/// The one and only presentation of a new credential.
pub struct Granted {
    pub id: TokenId,
    pub secret: Secret,
    pub expires: UnixMillis,
}

/// A validated credential. `principal` is already intersected with what the
/// account can still hold; it is not the scope as written at issuance.
#[derive(Clone, Copy, Debug)]
pub struct Authenticated {
    pub token: TokenId,
    pub principal: Principal,
    pub expires: UnixMillis,
    last_used: Option<i64>,
}

impl Authenticated {
    /// True when this credential's recorded use is old enough to be worth one
    /// write. Recording use is operator visibility, not part of authentication.
    pub fn record_use_due(&self, now: UnixMillis) -> bool {
        self.last_used
            .is_none_or(|last| now.0.saturating_sub(last) >= USE_RECORD_INTERVAL_MS)
    }
}

fn check(grant: &Grant<'_>) -> Result<()> {
    if grant.name.is_empty() || grant.name.len() > 128 || grant.name.chars().any(char::is_control) {
        return Err(Error::InvalidInput("credential name"));
    }
    if grant.permissions == Permissions::NONE || !Permissions::ALL.contains(grant.permissions) {
        return Err(Error::InvalidInput("credential scope"));
    }
    if grant.repo.is_some() && grant.tenant.is_none() {
        return Err(Error::InvalidInput("repository scope without its tenant"));
    }
    if !(1..=MAX_LIFETIME_MS).contains(&grant.lifetime_ms) {
        return Err(Error::InvalidInput("credential lifetime"));
    }
    Ok(())
}

fn insert(tx: &Transaction<'_>, grant: &Grant<'_>, now: UnixMillis) -> Result<Granted> {
    check(grant)?;
    let id = TokenId::new();
    let secret = Secret::generate();
    let expires = UnixMillis(now.0.saturating_add(grant.lifetime_ms));
    tx.execute(
        "INSERT INTO api_tokens(token_digest, id, user_id, name, permissions,
            tenant_id, repo_id, created_ms, expires_ms)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            secret.digest().0,
            id.as_bytes(),
            grant.user.as_bytes(),
            grant.name,
            grant.permissions.bits(),
            grant.tenant.as_ref().map(TenantId::as_bytes),
            grant.repo.as_ref().map(RepoId::as_bytes),
            now.0,
            expires.0
        ],
    )?;
    Ok(Granted {
        id,
        secret,
        expires,
    })
}

/// Host-local provisioning: authorized by access to the database file, the same
/// authority that admits the first administrator. Used by `sentinel admin`, so
/// an operator can obtain a working credential before any login route exists.
pub fn provision(store: &Store, grant: Grant<'_>, now: UnixMillis) -> Result<Granted> {
    check(&grant)?;
    let owned = grant.name.to_owned();
    store.writer().write(move |tx| {
        let grant = Grant {
            name: &owned,
            ..grant
        };
        let granted = insert(tx, &grant, now)?;
        audit(
            tx,
            Event::TokenIssued,
            None,
            Some(grant.user),
            true,
            Some(&owned),
        )?;
        Ok(granted)
    })
}

/// Issue through the ordinary authorization layer: a platform admin may issue
/// for any account, a tenant admin for a service principal of that tenant, and
/// any account for itself — never wider than the issuer's own live authority.
pub fn issue(
    tx: &Transaction<'_>,
    principal: Principal,
    grant: Grant<'_>,
    now: UnixMillis,
) -> Result<Granted> {
    check(&grant)?;
    // Delegation can only narrow. This is checked before identity so that an
    // over-wide request fails the same way for every caller.
    if !principal.permissions.contains(grant.permissions) {
        return Err(Error::Forbidden);
    }
    let platform = crate::auth::require_platform_admin(tx, principal).is_ok();
    if !platform {
        if principal.user == grant.user {
            // Self-issued: a credential may not escape the scope the caller is
            // already acting under.
            if principal.tenant.is_some_and(|id| Some(id) != grant.tenant)
                || principal.repo.is_some_and(|id| Some(id) != grant.repo)
            {
                return Err(Error::Forbidden);
            }
        } else {
            let tenant = grant.tenant.ok_or(Error::Forbidden)?;
            crate::auth::require_tenant_admin(tx, principal, tenant)?;
            let service: bool = tx
                .prepare_cached(
                    "SELECT EXISTS(SELECT 1 FROM users
                     WHERE id = ?1 AND kind = 1 AND active = 1 AND service_tenant_id = ?2)",
                )?
                .query_row(params![grant.user.as_bytes(), tenant.as_bytes()], |r| {
                    r.get(0)
                })?;
            if !service {
                return Err(Error::Forbidden);
            }
        }
    }
    let granted = insert(tx, &grant, now)?;
    audit(
        tx,
        Event::TokenIssued,
        Some(principal.user),
        Some(grant.user),
        false,
        Some(grant.name),
    )?;
    Ok(granted)
}

/// Validate a presented credential. One primary-key probe; expiry, revocation,
/// the account's live state and a service principal's home tenant are all
/// predicates of the same statement.
///
/// The stored scope is a ceiling, not a grant: platform administration is
/// dropped unless the account still holds it, so demoting a super admin takes
/// effect on the next request without hunting down its credentials.
pub fn authenticate(
    conn: &Connection,
    presented: &Secret,
    now: UnixMillis,
) -> Result<Authenticated> {
    let digest = presented.digest();
    let row = conn
        .prepare_cached(
            "SELECT t.id, t.user_id, t.permissions, t.tenant_id, t.repo_id,
                    t.expires_ms, t.last_used_ms, u.super_admin
             FROM api_tokens t JOIN users u ON u.id = t.user_id
             WHERE t.token_digest = ?1 AND t.revoked_ms IS NULL AND t.expires_ms > ?2
             AND u.active = 1 AND (u.kind = 0 OR u.service_tenant_id = t.tenant_id)",
        )?
        .query_row(params![digest.0, now.0], |r| {
            Ok((
                r.get::<_, [u8; 16]>(0)?,
                r.get::<_, [u8; 16]>(1)?,
                r.get::<_, u8>(2)?,
                r.get::<_, Option<[u8; 16]>>(3)?,
                r.get::<_, Option<[u8; 16]>>(4)?,
                r.get::<_, i64>(5)?,
                r.get::<_, Option<i64>>(6)?,
                r.get::<_, bool>(7)?,
            ))
        })
        .optional()?
        .ok_or(Error::NotFound)?;

    let mut permissions = Permissions::NONE;
    for bit in [
        Permissions::READ,
        Permissions::RUN,
        Permissions::WRITE_SECRETS,
        Permissions::TENANT_ADMIN,
        Permissions::PLATFORM_ADMIN,
    ] {
        if row.2 & bit.bits() == bit.bits() && (bit != Permissions::PLATFORM_ADMIN || row.7) {
            permissions = permissions.union(bit);
        }
    }
    if permissions == Permissions::NONE {
        return Err(Error::NotFound);
    }
    let tenant = match row.3 {
        Some(bytes) => Some(TenantId::from_bytes(bytes).map_err(|_| Error::Corrupt("tenant_id"))?),
        None => None,
    };
    let repo = match row.4 {
        Some(bytes) => Some(RepoId::from_bytes(bytes).map_err(|_| Error::Corrupt("repo_id"))?),
        None => None,
    };
    Ok(Authenticated {
        token: TokenId::from_bytes(row.0).map_err(|_| Error::Corrupt("token id"))?,
        principal: Principal::new(
            UserId::from_bytes(row.1).map_err(|_| Error::Corrupt("user_id"))?,
            permissions,
            tenant,
            repo,
        ),
        expires: UnixMillis(row.5),
        last_used: row.6,
    })
}

/// Record that a credential was used. Call only when
/// [`Authenticated::record_use_due`] says so: this is one writer round trip.
pub fn record_use(store: &Store, token: TokenId, now: UnixMillis) -> Result<()> {
    store.writer().write(move |tx| {
        tx.execute(
            "UPDATE api_tokens SET last_used_ms = ?2 WHERE id = ?1 AND revoked_ms IS NULL",
            params![token.as_bytes(), now.0],
        )?;
        Ok(())
    })
}

/// Revoke one credential. Its owner or a platform admin may do so; both are
/// checked live, inside this transaction. Revocation is immediate and final.
pub fn revoke(
    tx: &Transaction<'_>,
    authority: Authority,
    token: TokenId,
    now: UnixMillis,
) -> Result<()> {
    let owner: [u8; 16] = tx
        .prepare_cached("SELECT user_id FROM api_tokens WHERE id = ?1")?
        .query_row([token.as_bytes()], |r| r.get(0))
        .optional()?
        .ok_or(Error::NotFound)?;
    let owner = UserId::from_bytes(owner).map_err(|_| Error::Corrupt("user_id"))?;
    if authority.actor() != Some(owner) {
        authority
            .require_platform(tx)
            .map_err(|_| Error::NotFound)?;
    }
    revoke_row(tx, token, now)?;
    audit(
        tx,
        Event::TokenRevoked,
        authority.actor(),
        Some(owner),
        authority.host_local(),
        None,
    )
}

/// Host-local revocation, for an operator who no longer has a working
/// credential or session to revoke one with.
pub fn revoke_host_local(store: &Store, token: TokenId, now: UnixMillis) -> Result<()> {
    store.writer().write(move |tx| {
        let owner: [u8; 16] = tx
            .prepare_cached("SELECT user_id FROM api_tokens WHERE id = ?1")?
            .query_row([token.as_bytes()], |r| r.get(0))
            .optional()?
            .ok_or(Error::NotFound)?;
        let owner = UserId::from_bytes(owner).map_err(|_| Error::Corrupt("user_id"))?;
        revoke_row(tx, token, now)?;
        audit(tx, Event::TokenRevoked, None, Some(owner), true, None)
    })
}

fn revoke_row(tx: &Transaction<'_>, token: TokenId, now: UnixMillis) -> Result<()> {
    tx.execute(
        "UPDATE api_tokens SET revoked_ms = ?2 WHERE id = ?1 AND revoked_ms IS NULL",
        params![token.as_bytes(), now.0],
    )?;
    Ok(())
}

/// Revoke every live credential of one account: suspension, and the caller's
/// "revoke everything" action.
pub fn revoke_all_for_user(tx: &Transaction<'_>, user: UserId, now: UnixMillis) -> Result<usize> {
    let revoked = tx.execute(
        "UPDATE api_tokens SET revoked_ms = ?2 WHERE user_id = ?1 AND revoked_ms IS NULL",
        params![user.as_bytes(), now.0],
    )?;
    Ok(revoked)
}

/// Metadata about one issued credential. Never carries the secret or its digest.
#[derive(Debug, PartialEq, Eq)]
pub struct Record {
    pub id: TokenId,
    pub user: UserId,
    pub name: String,
    pub permissions: Permissions,
    pub tenant: Option<TenantId>,
    pub repo: Option<RepoId>,
    pub created: UnixMillis,
    pub expires: UnixMillis,
    pub last_used: Option<UnixMillis>,
    pub revoked: bool,
}

/// List one account's credentials, newest first. The account itself or a
/// platform admin may look; nobody may list another account's credentials by
/// guessing its ID. At most 100 records.
pub fn list(
    conn: &Connection,
    authority: Authority,
    user: UserId,
    limit: u16,
) -> Result<Vec<Record>> {
    if !(1..=100).contains(&limit) {
        return Err(Error::InvalidInput("page size"));
    }
    if authority.actor() != Some(user) {
        authority
            .require_platform(conn)
            .map_err(|_| Error::NotFound)?;
    }
    let mut stmt = conn.prepare_cached(
        "SELECT id, user_id, name, permissions, tenant_id, repo_id, created_ms,
                expires_ms, last_used_ms, revoked_ms
         FROM api_tokens WHERE user_id = ?1 ORDER BY created_ms DESC, id LIMIT ?2",
    )?;
    let rows = stmt.query_map(params![user.as_bytes(), limit], |r| {
        Ok((
            r.get::<_, [u8; 16]>(0)?,
            r.get::<_, [u8; 16]>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, u8>(3)?,
            r.get::<_, Option<[u8; 16]>>(4)?,
            r.get::<_, Option<[u8; 16]>>(5)?,
            r.get::<_, i64>(6)?,
            r.get::<_, i64>(7)?,
            r.get::<_, Option<i64>>(8)?,
            r.get::<_, Option<i64>>(9)?,
        ))
    })?;
    rows.map(|row| {
        let row = row?;
        Ok(Record {
            id: TokenId::from_bytes(row.0).map_err(|_| Error::Corrupt("token id"))?,
            user: UserId::from_bytes(row.1).map_err(|_| Error::Corrupt("user_id"))?,
            name: row.2,
            permissions: Permissions::from_bits(row.3)
                .ok_or(Error::Corrupt("api_tokens.permissions"))?,
            tenant: match row.4 {
                Some(b) => Some(TenantId::from_bytes(b).map_err(|_| Error::Corrupt("tenant_id"))?),
                None => None,
            },
            repo: match row.5 {
                Some(b) => Some(RepoId::from_bytes(b).map_err(|_| Error::Corrupt("repo_id"))?),
                None => None,
            },
            created: UnixMillis(row.6),
            expires: UnixMillis(row.7),
            last_used: row.8.map(UnixMillis),
            revoked: row.9.is_some(),
        })
    })
    .collect()
}

/// Delete credentials that can no longer authenticate anybody, in bounded
/// batches. Maintenance only: expiry and revocation are already enforced by
/// the validation statement.
pub fn purge_expired(store: &Store, now: UnixMillis, limit: u32) -> Result<usize> {
    store.writer().write(move |tx| {
        let removed = tx.execute(
            "DELETE FROM api_tokens WHERE token_digest IN
             (SELECT token_digest FROM api_tokens
              WHERE expires_ms <= ?1 OR revoked_ms IS NOT NULL LIMIT ?2)",
            params![now.0, limit],
        )?;
        Ok(removed)
    })
}

#[cfg(test)]
mod tests {
    use rusqlite::Connection;

    /// Credential validation runs on every API request; it must stay a
    /// primary-key probe and one key join.
    #[test]
    fn credential_validation_is_an_index_search() {
        let mut conn = Connection::open_in_memory().unwrap();
        crate::migrate(&mut conn).unwrap();
        let sql = "EXPLAIN QUERY PLAN SELECT t.id, t.user_id, t.permissions, t.tenant_id,
                t.repo_id, t.expires_ms, t.last_used_ms, u.super_admin
             FROM api_tokens t JOIN users u ON u.id = t.user_id
             WHERE t.token_digest = ?1 AND t.revoked_ms IS NULL AND t.expires_ms > ?2
             AND u.active = 1 AND (u.kind = 0 OR u.service_tenant_id = t.tenant_id)";
        let mut stmt = conn.prepare(sql).unwrap();
        let values = vec![rusqlite::types::Value::Null; stmt.parameter_count()];
        let plans: Vec<String> = stmt
            .query_map(rusqlite::params_from_iter(values), |r| r.get(3))
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        assert!(plans.iter().all(|p| !p.starts_with("SCAN ")), "{plans:?}");
        assert!(
            plans.iter().all(|p| !p.contains("TEMP B-TREE")),
            "{plans:?}"
        );
        assert!(plans.iter().any(|p| p.contains("SEARCH")), "{plans:?}");
    }
}
