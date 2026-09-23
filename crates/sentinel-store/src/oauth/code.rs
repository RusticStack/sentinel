//! The authorization-code flow's durable half (O01): consent choices, code
//! issuance on approval, and the single-use, PKCE-bound exchange.
//!
//! Consent itself is stateless: nothing is written until the account
//! approves, and then only the code row. [`approve`] re-checks every term in
//! ONE statement inside the writer transaction (account, client ceiling and
//! redirect, platform eligibility, tenant membership, repository ownership).
//! [`exchange`] consumes the code in the same statement that reads it, so
//! every presentation after the first — successful or not — is a replay; a
//! replay of a code that produced a grant revokes that grant (reason 3).

use rusqlite::{Connection, OptionalExtension, Transaction, params};
use sentinel_auth::{
    oauth::{self as forms, pkce},
    secret::{Digest, Secret},
};
use sentinel_core::{
    GrantId, RepoId, TenantId, UnixMillis, UserId,
    auth::{Audience, Role, Scopes},
};

use super::{
    CODE_LIFETIME_MS, GrantKind, LOGIN_GRANT_MS, Minted, NewGrant, decode_scopes, grant_of,
    insert_grant, mint, reason, repo_of, revoke_row, tenant_of, user_of,
};
use crate::{
    Error, Result, Store,
    local_auth::{Event, audit},
};

/// At most this many tenants are offered on the consent page.
pub const MAX_CONSENT_CHOICES: u32 = 100;

/// A tenant the consenting account may narrow a grant to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConsentChoice {
    pub tenant: TenantId,
    pub slug: String,
    pub role: Role,
}

/// The consent page's tenant choices.
const CONSENT_CHOICES: &str = "SELECT m.tenant_id, t.slug, m.role FROM memberships m
     JOIN tenants t ON t.id = m.tenant_id
     WHERE m.user_id = ?1 AND t.active = 1
     ORDER BY t.slug LIMIT ?2";

/// The account's memberships of active tenants, by slug, at most
/// [`MAX_CONSENT_CHOICES`]. One index range on `memberships_by_user`; the
/// slug order is a sort over that one account's memberships, not a table.
pub fn consent_choices(conn: &Connection, user: UserId) -> Result<Vec<ConsentChoice>> {
    let mut stmt = conn.prepare_cached(CONSENT_CHOICES)?;
    let rows = stmt.query_map(params![user.as_bytes(), MAX_CONSENT_CHOICES], |r| {
        Ok((
            r.get::<_, [u8; 16]>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, u8>(2)?,
        ))
    })?;
    let mut out = Vec::new();
    for row in rows {
        let (tenant, slug, role) = row?;
        out.push(ConsentChoice {
            tenant: TenantId::from_bytes(tenant).map_err(|_| Error::Corrupt("tenant_id"))?,
            slug,
            role: match role {
                1 => Role::Reader,
                2 => Role::Operator,
                3 => Role::TenantAdmin,
                _ => return Err(Error::Corrupt("memberships.role")),
            },
        });
    }
    Ok(out)
}

/// Resolves a repository name for [`repo_named`]: only in an active tenant
/// the account is a member of, and only a repository it can see (a tenant
/// admin sees all of them, another member the ones granted to it).
const REPO_NAMED: &str = "SELECT r.id FROM repos r
     JOIN tenants t ON t.id = r.tenant_id AND t.active = 1
     JOIN memberships m ON m.tenant_id = r.tenant_id AND m.user_id = ?3
     WHERE r.tenant_id = ?1 AND r.name = ?2
     AND (m.role = 3 OR EXISTS(SELECT 1 FROM repo_grants g
         WHERE g.tenant_id = r.tenant_id AND g.user_id = m.user_id AND g.repo_id = r.id))";

/// The repository `name` of `tenant`, for narrowing `user`'s grant on the
/// consent page. `NotFound` alike when the tenant has no such repository,
/// when `user` is not a member of the tenant, and when `user` cannot see
/// the repository, so the page never reveals what another tenant holds.
/// Key probes on `UNIQUE(tenant_id, name)` and the membership key;
/// [`approve`] re-checks ownership anyway.
pub fn repo_named(conn: &Connection, user: UserId, tenant: TenantId, name: &str) -> Result<RepoId> {
    let bytes = conn
        .prepare_cached(REPO_NAMED)?
        .query_row(params![tenant.as_bytes(), name, user.as_bytes()], |r| {
            r.get::<_, [u8; 16]>(0)
        })
        .optional()?
        .ok_or(Error::NotFound)?;
    RepoId::from_bytes(bytes).map_err(|_| Error::Corrupt("repo_id"))
}

/// What the account approved on the consent page.
#[derive(Clone, Copy, Debug)]
pub struct Approval<'a> {
    pub client_id: &'a str,
    pub redirect_uri: &'a str,
    pub code_challenge: &'a str,
    pub user: UserId,
    pub scopes: Scopes,
    pub tenant: Option<TenantId>,
    pub repo: Option<RepoId>,
    pub audience: Audience,
}

/// Every eligibility fact of an approval, in one statement: the account
/// (active human, super admin), membership of an active tenant, repository
/// ownership, and the client's ceiling and redirect rules. No row means the
/// client is unknown or disabled, or the account does not exist.
const APPROVAL_TERMS: &str = "SELECT u.active = 1 AND u.kind = 0, u.super_admin,
        ?3 IS NULL OR EXISTS(SELECT 1 FROM memberships m JOIN tenants t ON t.id = m.tenant_id
            WHERE m.tenant_id = ?3 AND m.user_id = u.id AND t.active = 1),
        ?4 IS NULL OR EXISTS(SELECT 1 FROM repos WHERE id = ?4 AND tenant_id = ?3),
        c.max_scopes, c.loopback, c.redirect_path,
        EXISTS(SELECT 1 FROM oauth_client_redirects r WHERE r.client_id = c.client_id AND r.uri = ?5)
     FROM users u JOIN oauth_clients c ON c.client_id = ?2 AND c.disabled_ms IS NULL
     WHERE u.id = ?1";

/// Record an approved request and return its authorization code, valid for
/// [`CODE_LIFETIME_MS`]. Refusals: `NotFound` (unknown or disabled client,
/// unknown account), `Forbidden` (inactive or non-human account,
/// `platform:admin` without being a super admin, a tenant that is not an
/// active membership, a repository outside the tenant), `InvalidInput`
/// (empty or out-of-ceiling scopes, a redirect the client may not use, a
/// malformed challenge). Nothing is audited here; the exchange audits the
/// grant it issues.
pub fn approve(store: &Store, a: &Approval<'_>, now: UnixMillis) -> Result<Secret> {
    if !pkce::challenge_valid(a.code_challenge) {
        return Err(Error::InvalidInput("code_challenge"));
    }
    if a.redirect_uri.is_empty() || a.redirect_uri.len() > 512 {
        return Err(Error::InvalidInput("redirect_uri"));
    }
    if a.scopes.is_empty() {
        return Err(Error::InvalidInput("scope"));
    }
    if a.repo.is_some() && a.tenant.is_none() {
        return Err(Error::InvalidInput("repository scope without its tenant"));
    }
    // One owned buffer for the three strings the writer closure needs.
    let split = a.client_id.len();
    let challenge_at = split + a.redirect_uri.len();
    let mut text = String::with_capacity(challenge_at + pkce::CHALLENGE_LEN);
    text.push_str(a.client_id);
    text.push_str(a.redirect_uri);
    text.push_str(a.code_challenge);
    let (user, scopes, tenant, repo, audience) = (a.user, a.scopes, a.tenant, a.repo, a.audience);
    let code = Secret::generate();
    let digest = code.digest();
    store.writer().write(move |tx| {
        let (client_id, rest) = text.split_at(split);
        let (redirect_uri, challenge) = rest.split_at(challenge_at - split);
        let terms = tx
            .prepare_cached(APPROVAL_TERMS)?
            .query_row(
                params![
                    user.as_bytes(),
                    client_id,
                    tenant.as_ref().map(TenantId::as_bytes),
                    repo.as_ref().map(RepoId::as_bytes),
                    redirect_uri
                ],
                |r| {
                    let loopback = r.get::<_, bool>(5)?
                        && r.get_ref(6)?.as_str_or_null()?.is_some_and(|path| {
                            forms::loopback_redirect(redirect_uri, path).is_some()
                        });
                    Ok((
                        r.get::<_, bool>(0)?,
                        r.get::<_, bool>(1)?,
                        r.get::<_, bool>(2)?,
                        r.get::<_, bool>(3)?,
                        r.get::<_, i64>(4)?,
                        loopback || r.get::<_, bool>(7)?,
                    ))
                },
            )
            .optional()?
            .ok_or(Error::NotFound)?;
        let (human, super_admin, member, owned, ceiling, redirect) = terms;
        if !human || !member || !owned || (scopes.contains(Scopes::PLATFORM_ADMIN) && !super_admin)
        {
            return Err(Error::Forbidden);
        }
        if !decode_scopes(ceiling)?.contains(scopes) {
            return Err(Error::InvalidInput("scope"));
        }
        if !redirect {
            return Err(Error::InvalidInput("redirect_uri"));
        }
        tx.prepare_cached(
            "INSERT INTO oauth_codes(code_digest, client_id, redirect_uri, code_challenge,
                user_id, scopes, tenant_id, repo_id, audience, created_ms, expires_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        )?
        .execute(params![
            digest.0,
            client_id,
            redirect_uri,
            challenge,
            user.as_bytes(),
            scopes.bits(),
            tenant.as_ref().map(TenantId::as_bytes),
            repo.as_ref().map(RepoId::as_bytes),
            audience.code(),
            now.0,
            now.0.saturating_add(CODE_LIFETIME_MS)
        ])?;
        Ok(())
    })?;
    Ok(code)
}

/// Record that the account declined a client's request (audited as
/// `OAuthConsentDenied`; nothing else is written).
pub fn deny(store: &Store, client_id: &str, user: UserId) -> Result<()> {
    let client_id = client_id.to_owned();
    store.writer().write(move |tx| {
        audit(
            tx,
            Event::OAuthConsentDenied,
            Some(user),
            Some(user),
            false,
            Some(&client_id),
        )
    })
}

/// Why an exchange produced no tokens.
#[derive(Debug)]
pub enum CodeError {
    /// Unknown, expired, another client's, wrong redirect or wrong verifier,
    /// or the account can no longer hold a grant. A known code is spent.
    Invalid,
    /// A spent code was presented again; its grant (if it produced one) is
    /// revoked (reason 3) and the replay audited.
    Replay,
    Store(Error),
}

enum Exchanged {
    Minted(Minted),
    Invalid,
    Replay,
}

/// Exchange a code for the first token pair of a new grant (kind 1, life
/// [`LOGIN_GRANT_MS`]). The code is consumed by the lookup itself, so any
/// failure after it is found still spends it.
pub fn exchange(
    store: &Store,
    client_id: &str,
    code: &Secret,
    redirect_uri: &str,
    verifier: &str,
    now: UnixMillis,
) -> std::result::Result<Minted, CodeError> {
    let digest = code.digest();
    // A malformed verifier still spends the code; it can never match.
    let expected = pkce::verifier_valid(verifier).then(|| pkce::challenge(verifier));
    let split = client_id.len();
    let mut text = String::with_capacity(split + redirect_uri.len());
    text.push_str(client_id);
    text.push_str(redirect_uri);
    let outcome = store
        .writer()
        .write(move |tx| {
            let (client_id, redirect_uri) = text.split_at(split);
            redeem(
                tx,
                digest,
                client_id,
                redirect_uri,
                expected.as_deref(),
                now,
            )
        })
        .map_err(CodeError::Store)?;
    match outcome {
        Exchanged::Minted(minted) => Ok(minted),
        Exchanged::Invalid => Err(CodeError::Invalid),
        Exchanged::Replay => Err(CodeError::Replay),
    }
}

/// Consume-and-read in one statement: only the first presentation of a
/// code gets a row back.
const CONSUME: &str = "UPDATE oauth_codes SET consumed_ms = ?2
     WHERE code_digest = ?1 AND consumed_ms IS NULL
     RETURNING client_id = ?3 AND redirect_uri = ?4 AND expires_ms > ?2,
        code_challenge, user_id, scopes, tenant_id, repo_id, audience";

fn redeem(
    tx: &Transaction<'_>,
    digest: Digest,
    client_id: &str,
    redirect_uri: &str,
    expected: Option<&str>,
    now: UnixMillis,
) -> Result<Exchanged> {
    let row = tx
        .prepare_cached(CONSUME)?
        .query_row(params![digest.0, now.0, client_id, redirect_uri], |r| {
            let verified = expected.is_some_and(|expected| {
                r.get_ref(1)
                    .ok()
                    .and_then(|v| v.as_str().ok())
                    .is_some_and(|stored| constant_eq(expected.as_bytes(), stored.as_bytes()))
            });
            Ok((
                r.get::<_, bool>(0)? && verified,
                r.get::<_, [u8; 16]>(2)?,
                r.get::<_, i64>(3)?,
                r.get::<_, Option<[u8; 16]>>(4)?,
                r.get::<_, Option<[u8; 16]>>(5)?,
                r.get::<_, u8>(6)?,
            ))
        })
        .optional()?;
    let Some((valid, user, scopes, tenant, repo, audience)) = row else {
        return replayed(tx, digest, now);
    };
    if !valid {
        return Ok(Exchanged::Invalid);
    }
    let user = user_of(user)?;
    let scopes = decode_scopes(scopes)?;
    let grant = NewGrant {
        user,
        client_id,
        kind: GrantKind::Code,
        scopes,
        tenant: tenant_of(tenant)?,
        repo: repo_of(repo)?,
        audience: Audience::from_code(audience).ok_or(Error::Corrupt("oauth_codes.audience"))?,
        name: None,
        lifetime_ms: LOGIN_GRANT_MS,
        created_by: None,
    };
    // The account may have been suspended since approval: the grant
    // trigger refuses it, and the spent code stays spent.
    let grant = match insert_grant(tx, &grant, now) {
        Ok(grant) => grant,
        Err(Error::Forbidden) => return Ok(Exchanged::Invalid),
        Err(e) => return Err(e),
    };
    let minted = mint(tx, grant, scopes, now)?;
    tx.prepare_cached("UPDATE oauth_codes SET grant_id = ?2 WHERE code_digest = ?1")?
        .execute(params![digest.0, grant.as_bytes()])?;
    audit(
        tx,
        Event::OAuthGrantIssued,
        Some(user),
        Some(user),
        false,
        Some(GrantKind::Code.as_str()),
    )?;
    Ok(Exchanged::Minted(minted))
}

/// The code was not consumed by this presentation: unknown, or spent. A
/// spent code revokes the grant it produced and is audited.
fn replayed(tx: &Transaction<'_>, digest: Digest, now: UnixMillis) -> Result<Exchanged> {
    let row = tx
        .prepare_cached("SELECT user_id, grant_id FROM oauth_codes WHERE code_digest = ?1")?
        .query_row([digest.0], |r| {
            Ok((r.get::<_, [u8; 16]>(0)?, r.get::<_, Option<[u8; 16]>>(1)?))
        })
        .optional()?;
    let Some((user, grant)) = row else {
        return Ok(Exchanged::Invalid);
    };
    let grant: Option<GrantId> = grant.map(grant_of).transpose()?;
    if let Some(grant) = grant {
        revoke_row(tx, grant, reason::CODE_REPLAY, now)?;
    }
    audit(
        tx,
        Event::OAuthCodeReplay,
        None,
        Some(user_of(user)?),
        false,
        None,
    )?;
    Ok(Exchanged::Replay)
}

/// Equal length and bytes, in time independent of where they differ.
fn constant_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    core::hint::black_box(diff) == 0
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

    /// Approval, consumption and the consent/replay lookups are key searches,
    /// never table scans.
    #[test]
    fn code_statements_are_key_searches() {
        let mut conn = Connection::open_in_memory().unwrap();
        crate::migrate(&mut conn).unwrap();
        for sql in [
            super::APPROVAL_TERMS,
            super::CONSUME,
            "SELECT user_id, grant_id FROM oauth_codes WHERE code_digest = ?1",
            super::REPO_NAMED,
            // The statement that runs, ORDER BY and LIMIT included: its sort
            // is over one account's memberships, found by index search.
            super::CONSENT_CHOICES,
        ] {
            let plans = plans(&conn, sql);
            assert!(
                plans.iter().all(|p| !p.starts_with("SCAN ")),
                "{sql}: {plans:?}"
            );
        }
    }
}
