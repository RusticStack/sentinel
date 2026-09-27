//! External sign-in: pending authorization state, and what a verified provider
//! identity is allowed to do (A04).
//!
//! This module never talks to a provider and never decides whether a proof is
//! genuine — `sentinel-github` does that. What arrives here is already verified:
//! a configured provider key and an immutable provider subject. What leaves is
//! a session, or the honest answer that no account holds that identity.
//!
//! Authenticating somewhere else is not admission. An unknown identity is not
//! registered here, is not given a placeholder account, and does not become a
//! tenant: A05 owns invitations, approval and registration policy.

use rusqlite::{Connection, OptionalExtension, Transaction, params};
use sentinel_auth::secret::Secret;
use sentinel_core::{UnixMillis, UserId};

use crate::{
    Error, Result, Store,
    auth::Authority,
    local_auth::{Event, Issued, Policy, Session, audit},
};

/// Long enough for a person to sign in and approve, short enough that a pending
/// attempt is not a standing target.
pub const STATE_TTL_MS: i64 = 10 * 60 * 1000;

/// Longest destination recorded with a pending attempt (migration 37): room
/// for an OAuth authorization request's whole query, so a sign-in started on
/// the consent page returns to it with its parameters intact.
pub const MAX_REDIRECT_BYTES: usize = 2048;

/// Where to send the browser once sign-in completes. Same-site paths only: an
/// absolute URL here would turn a successful login into an open redirect.
fn destination(redirect_to: Option<&str>) -> Result<Option<String>> {
    let Some(path) = redirect_to else {
        return Ok(None);
    };
    let acceptable = path.starts_with('/')
        && !path.starts_with("//")
        && path.len() <= MAX_REDIRECT_BYTES
        && !path.contains('\\')
        && !path.chars().any(char::is_control);
    if !acceptable {
        return Err(Error::InvalidInput("redirect target"));
    }
    Ok(Some(path.to_owned()))
}

/// Begin an authorization round trip. The returned secret goes into the
/// `state` parameter *and* into the browser's `__Host-` sign-in cookie; the
/// callback must present both, so a stolen redirect URL is not enough.
pub fn begin(
    store: &Store,
    provider: &str,
    redirect_to: Option<&str>,
    now: UnixMillis,
    ttl_ms: i64,
) -> Result<Secret> {
    if provider.is_empty() || provider.len() > 64 {
        return Err(Error::InvalidInput("identity provider"));
    }
    if !(1..=STATE_TTL_MS).contains(&ttl_ms) {
        return Err(Error::InvalidInput("sign-in state lifetime"));
    }
    let destination = destination(redirect_to)?;
    let provider = provider.to_owned();
    let state = Secret::generate();
    let digest = state.digest();
    store.writer().write(move |tx| {
        tx.execute(
            "INSERT INTO sign_in_states(state_digest, provider, redirect_to, created_ms, expires_ms)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                digest.0,
                provider,
                destination,
                now.0,
                now.0.saturating_add(ttl_ms)
            ],
        )?;
        Ok(())
    })?;
    Ok(state)
}

/// Spend a pending attempt. Succeeds at most once per attempt: the same state
/// presented twice, after expiry, or for a different provider is `NotFound`.
/// Returns the validated same-site destination, when one was recorded.
pub fn consume(
    store: &Store,
    provider: &str,
    presented: &Secret,
    now: UnixMillis,
) -> Result<Option<String>> {
    let digest = presented.digest();
    let provider = provider.to_owned();
    store.writer().write(move |tx| {
        let destination: Option<String> = tx
            .prepare_cached(
                "UPDATE sign_in_states SET consumed_ms = ?3
                 WHERE state_digest = ?1 AND provider = ?2 AND consumed_ms IS NULL
                 AND expires_ms > ?3 RETURNING redirect_to",
            )?
            .query_row(params![digest.0, provider, now.0], |r| r.get(0))
            .optional()?
            .ok_or(Error::NotFound)?;
        Ok(destination)
    })
}

/// What a verified identity resolved to.
#[derive(Debug)]
pub enum Outcome {
    /// The identity is linked to an active account; a session was issued.
    SignedIn(Issued),
    /// Nothing is linked to this identity. Not an error and not a registration:
    /// A05 decides whether an invitation or approval can turn it into one.
    NoAccount,
}

/// Sign in with an already-verified provider identity: [`resolve`] then
/// [`finish`], with no previous session to end.
///
/// The subject is the provider's immutable account ID. A renamed login resolves
/// to the same account; a reused login handle resolves to nobody, because the
/// handle was never the key.
pub fn complete(
    store: &Store,
    provider: &str,
    subject: &str,
    policy: Policy,
    now: UnixMillis,
) -> Result<Outcome> {
    match resolve(store, provider, subject)? {
        Some(user) => finish(store, provider, user, None, policy, now),
        None => Ok(Outcome::NoAccount),
    }
}

/// The active account a verified provider identity is linked to, or `None`
/// (audited as a rejected login) when nothing is. Issues nothing: a browser
/// flow resolves on the provider's cross-site callback and issues the session
/// on the same-site hop that follows ([`finish`]).
pub fn resolve(store: &Store, provider: &str, subject: &str) -> Result<Option<UserId>> {
    let user = store
        .read(|conn| crate::auth::provisioning::resolve_verified_identity(conn, provider, subject));
    match user {
        Ok(user) => Ok(Some(user)),
        Err(Error::NotFound) => {
            let provider = provider.to_owned();
            store.writer().write(move |tx| {
                audit(tx, Event::LoginRejected, None, None, false, Some(&provider))
            })?;
            Ok(None)
        }
        Err(other) => Err(other),
    }
}

/// Issue the session of an account [`resolve`] returned, first revoking the
/// session the browser presented (`previous`, whoever it belongs to) in the
/// same transaction: the browser is switching to this sign-in, so the session
/// it held must not outlive the switch (P09S-10). The account could have been
/// suspended since it was resolved: the session insert trigger refuses it,
/// and that is the same honest answer as never having been linked.
pub fn finish(
    store: &Store,
    provider: &str,
    user: UserId,
    previous: Option<&Secret>,
    policy: Policy,
    now: UnixMillis,
) -> Result<Outcome> {
    let provider = provider.to_owned();
    let previous = previous.map(Secret::digest);
    let issued = store.writer().write(move |tx| {
        if let Some(digest) = previous {
            let ended: Option<[u8; 16]> = tx
                .prepare_cached(
                    "UPDATE sessions SET revoked_ms = ?2 WHERE token_digest = ?1
                     AND revoked_ms IS NULL RETURNING user_id",
                )?
                .query_row(params![digest.0, now.0], |r| r.get(0))
                .optional()?;
            if let Some(owner) = ended {
                let owner = UserId::from_bytes(owner).map_err(|_| Error::Corrupt("user_id"))?;
                audit(tx, Event::Logout, Some(owner), Some(owner), false, None)?;
            }
        }
        let issued = match crate::local_auth::issue_session(tx, user, policy, now) {
            Err(Error::Sqlite(rusqlite::Error::SqliteFailure(code, _)))
                if code.code == rusqlite::ErrorCode::ConstraintViolation =>
            {
                return Err(Error::NotFound);
            }
            other => other?,
        };
        audit(
            tx,
            Event::LoginAccepted,
            Some(user),
            Some(user),
            false,
            Some(&provider),
        )?;
        Ok(issued)
    });
    match issued {
        Ok(issued) => Ok(Outcome::SignedIn(issued)),
        Err(Error::NotFound) => Ok(Outcome::NoAccount),
        Err(other) => Err(other),
    }
}

/// Link a verified identity to the account of an authenticated session.
///
/// Linking changes who can authenticate as this account, so it needs the same
/// recent proof of presence as any other change to authentication: a stolen
/// cookie must not be able to attach an attacker's GitHub account. A provider
/// identity is linked to at most one account and is never silently moved —
/// relinking an already-claimed identity fails rather than taking it.
pub fn link(
    store: &Store,
    session: &Session,
    policy: Policy,
    provider: &str,
    subject: &str,
    now: UnixMillis,
) -> Result<()> {
    session.require_step_up(policy, now)?;
    let user = session.user;
    let (provider, subject) = (provider.to_owned(), subject.to_owned());
    store.writer().write(move |tx| {
        crate::auth::provisioning::link_verified_identity(tx, user, &provider, &subject, now)
            .map_err(|error| match error {
                // The unique key refuses a second claim on one identity.
                Error::Sqlite(rusqlite::Error::SqliteFailure(code, _))
                    if code.code == rusqlite::ErrorCode::ConstraintViolation =>
                {
                    Error::Conflict
                }
                other => other,
            })?;
        audit(
            tx,
            Event::IdentityLinked,
            Some(user),
            Some(user),
            false,
            Some(&provider),
        )
    })
}

/// Remove a link. The account itself or a platform admin may do so; the audit
/// record survives, so an unlink before a relink is visible.
pub fn unlink(
    tx: &Transaction<'_>,
    authority: Authority,
    user: UserId,
    provider: &str,
    now: UnixMillis,
) -> Result<()> {
    let _ = now;
    if authority.actor() != Some(user) {
        authority
            .require_platform(tx)
            .map_err(|_| Error::NotFound)?;
    }
    let removed = tx.execute(
        "DELETE FROM external_identities WHERE user_id = ?1 AND provider = ?2",
        params![user.as_bytes(), provider],
    )?;
    if removed == 0 {
        return Err(Error::NotFound);
    }
    audit(
        tx,
        Event::IdentityUnlinked,
        authority.actor(),
        Some(user),
        authority.host_local(),
        Some(provider),
    )
}

/// Host-local unlink, for an operator repairing a wrong link without a session.
pub fn unlink_host_local(
    store: &Store,
    user: UserId,
    provider: &str,
    now: UnixMillis,
) -> Result<()> {
    let _ = now;
    let provider = provider.to_owned();
    store.writer().write(move |tx| {
        let removed = tx.execute(
            "DELETE FROM external_identities WHERE user_id = ?1 AND provider = ?2",
            params![user.as_bytes(), provider],
        )?;
        if removed == 0 {
            return Err(Error::NotFound);
        }
        audit(
            tx,
            Event::IdentityUnlinked,
            None,
            Some(user),
            true,
            Some(&provider),
        )
    })
}

#[derive(Debug, PartialEq, Eq)]
pub struct Identity {
    pub provider: String,
    pub subject: String,
    pub linked: UnixMillis,
}

/// One account's linked identities. The account itself or a platform admin may
/// look; a subject is not a secret, but it is not public either.
pub fn identities(conn: &Connection, authority: Authority, user: UserId) -> Result<Vec<Identity>> {
    if authority.actor() != Some(user) {
        authority
            .require_platform(conn)
            .map_err(|_| Error::NotFound)?;
    }
    let mut stmt = conn.prepare_cached(
        "SELECT provider, subject, created_ms FROM external_identities
         WHERE user_id = ?1 ORDER BY provider",
    )?;
    let rows = stmt.query_map([user.as_bytes()], |r| {
        Ok(Identity {
            provider: r.get(0)?,
            subject: r.get(1)?,
            linked: UnixMillis(r.get(2)?),
        })
    })?;
    rows.map(|row| row.map_err(Error::from)).collect()
}

/// Delete spent and expired attempts in bounded batches. Maintenance only:
/// single use and expiry are already enforced by `consume`.
pub fn purge_expired(store: &Store, now: UnixMillis, limit: u32) -> Result<usize> {
    store.writer().write(move |tx| {
        let removed = tx.execute(
            "DELETE FROM sign_in_states WHERE state_digest IN
             (SELECT state_digest FROM sign_in_states
              WHERE expires_ms <= ?1 OR consumed_ms IS NOT NULL LIMIT ?2)",
            params![now.0, limit],
        )?;
        Ok(removed)
    })
}
