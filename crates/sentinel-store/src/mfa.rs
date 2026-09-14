//! Second factors and step-up (A06).
//!
//! A session proves who you are. Step-up proves you are *still there*, just
//! now, with something more than a cookie — before a change that would alter
//! who can authenticate at all: the registration policy, the super-admin set,
//! account suspension, or the second factor itself.
//!
//! The stamp is freshness, not authority: `Authority::require_privileged` still
//! checks platform administration live, in the same transaction as the change.
//!
//! Verification (Argon2 for a password proof) never runs inside the writer, and
//! the TOTP seed is sealed under a key outside the database, so a stolen
//! `metadata.sqlite` yields nothing that can mint codes.

use rusqlite::{Connection, OptionalExtension, params};
use sentinel_auth::{
    mfa::{self, RecoveryCode, Seed},
    password,
    sealed::Key,
    secret::Secret,
};
use sentinel_core::{UnixMillis, UserId};

use crate::{
    Error, Result, Store,
    local_auth::{Event, Policy, Session, audit},
};

/// Failed step-ups a session may accumulate before it is revoked. Small: a
/// six-digit code has three valid values per window, and a session that keeps
/// guessing is not the person it was issued to.
pub const MAX_STEP_UP_FAILURES: i64 = 5;

/// Context binding a sealed seed to the account it belongs to, so a seed row
/// copied onto another account cannot be opened.
fn context(user: UserId) -> Vec<u8> {
    let mut context = Vec::with_capacity(21);
    context.extend_from_slice(b"totp:");
    context.extend_from_slice(user.as_bytes());
    context
}

/// What an enrolling person needs, shown exactly once. The URI carries the
/// seed, so it is never logged, stored in the clear, or shown again.
pub struct Enrollment {
    pub provisioning_uri: String,
}

/// Begin enrolling a second factor for the session's own account.
///
/// Writes an unconfirmed registration. Until a code proves the app holds the
/// same seed, nothing about authentication changes — an abandoned enrollment
/// cannot lock anybody out.
pub fn begin_enrollment(
    store: &Store,
    key: &Key,
    session: &Session,
    issuer: &str,
    account: &str,
    now: UnixMillis,
) -> Result<Enrollment> {
    let user = session.user;
    let seed = Seed::generate();
    let provisioning_uri = seed
        .provisioning_uri(issuer, account)
        .map_err(|_| Error::InvalidInput("enrollment label"))?;
    let sealed = key.seal(&context(user), seed.as_bytes());
    store.writer().write(move |tx| {
        let confirmed: Option<Option<i64>> = tx
            .prepare_cached("SELECT confirmed_ms FROM mfa_totp WHERE user_id = ?1")?
            .query_row([user.as_bytes()], |r| r.get(0))
            .optional()?;
        match confirmed {
            // Replacing a confirmed factor goes through `disable` under
            // step-up, so a stolen session cannot quietly re-enroll its own.
            Some(Some(_)) => return Err(Error::Conflict),
            // An unconfirmed attempt is simply superseded.
            Some(None) => {
                tx.execute("DELETE FROM mfa_totp WHERE user_id = ?1", [user.as_bytes()])?;
            }
            None => {}
        }
        tx.execute(
            "INSERT INTO mfa_totp(user_id, sealed_seed, created_ms) VALUES (?1, ?2, ?3)",
            params![user.as_bytes(), sealed, now.0],
        )?;
        Ok(())
    })?;
    Ok(Enrollment { provisioning_uri })
}

/// Confirm enrollment with a code from the app, and issue the recovery codes.
///
/// Returns them once; only their digests are kept. Confirming also stamps the
/// session as stepped up, because proving a factor is exactly what step-up is.
pub fn confirm_enrollment(
    store: &Store,
    key: &Key,
    presented: &Secret,
    session: &Session,
    code: &str,
    now: UnixMillis,
) -> Result<Vec<RecoveryCode>> {
    let user = session.user;
    let sealed: Vec<u8> = store.read(|conn| {
        conn.prepare_cached(
            "SELECT sealed_seed FROM mfa_totp WHERE user_id = ?1 AND confirmed_ms IS NULL",
        )?
        .query_row([user.as_bytes()], |r| r.get(0))
        .optional()?
        .ok_or(Error::NotFound)
    })?;
    let seed = open_seed(key, user, &sealed)?;
    let step = mfa::check(&seed, code, unix_seconds(now)).ok_or(Error::Forbidden)?;

    let codes = mfa::recovery_codes();
    let digests: Vec<[u8; 32]> = codes.iter().map(|code| code.digest().0).collect();
    let digest = presented.digest();
    store.writer().write(move |tx| {
        let confirmed = tx.execute(
            "UPDATE mfa_totp SET confirmed_ms = ?2, last_step = ?3
             WHERE user_id = ?1 AND confirmed_ms IS NULL",
            params![user.as_bytes(), now.0, step as i64],
        )?;
        if confirmed == 0 {
            return Err(Error::Conflict);
        }
        replace_recovery_codes(tx, user, &digests, now)?;
        stamp(tx, digest.0, now)?;
        audit(tx, Event::MfaEnrolled, Some(user), Some(user), false, None)
    })?;
    Ok(codes)
}

fn open_seed(key: &Key, user: UserId, sealed: &[u8]) -> Result<Seed> {
    let bytes = key
        .open(&context(user), sealed)
        .map_err(|_| Error::Corrupt("mfa_totp.sealed_seed"))?;
    Seed::from_bytes(&bytes).map_err(|_| Error::Corrupt("mfa_totp.sealed_seed"))
}

fn replace_recovery_codes(
    tx: &rusqlite::Transaction<'_>,
    user: UserId,
    digests: &[[u8; 32]],
    now: UnixMillis,
) -> Result<()> {
    tx.execute(
        "DELETE FROM mfa_recovery_codes WHERE user_id = ?1",
        [user.as_bytes()],
    )?;
    let mut insert = tx.prepare_cached(
        "INSERT INTO mfa_recovery_codes(code_digest, user_id, created_ms) VALUES (?1, ?2, ?3)",
    )?;
    for digest in digests {
        insert.execute(params![digest, user.as_bytes(), now.0])?;
    }
    Ok(())
}

/// TOTP counts whole seconds; the rest of the store counts milliseconds.
fn unix_seconds(now: UnixMillis) -> u64 {
    now.0.max(0) as u64 / 1000
}

/// How a person proves they are still present.
pub enum Proof<'a> {
    /// A code from the enrolled authenticator app.
    Totp(&'a str),
    /// One of the recovery codes, spent on use.
    Recovery(&'a str),
    /// The account's own password. Accepted **only** when no second factor is
    /// enrolled: otherwise it would let the weaker proof stand in for the
    /// stronger one, which is the opposite of stepping up.
    Password(&'a [u8]),
}

/// Prove presence and stamp the session. Returns `false` for a wrong proof
/// rather than an error: the caller renders one response either way.
pub fn step_up(
    store: &Store,
    key: &Key,
    presented: &Secret,
    session: &Session,
    proof: Proof<'_>,
    now: UnixMillis,
) -> Result<bool> {
    let user = session.user;
    let digest = presented.digest();
    let accepted = match proof {
        Proof::Totp(code) => {
            let sealed: Option<Vec<u8>> = store.read(|conn| {
                conn.prepare_cached(
                    "SELECT sealed_seed FROM mfa_totp
                     WHERE user_id = ?1 AND confirmed_ms IS NOT NULL",
                )?
                .query_row([user.as_bytes()], |r| r.get(0))
                .optional()
                .map_err(Error::from)
            })?;
            let Some(sealed) = sealed else {
                return refuse(store, digest.0, user, now);
            };
            let seed = open_seed(key, user, &sealed)?;
            let Some(step) = mfa::check(&seed, code, unix_seconds(now)) else {
                return refuse(store, digest.0, user, now);
            };
            // RFC 6238 leaves one-use to the caller: a step already accepted is
            // refused, so a code seen over a shoulder is worthless.
            store.writer().write(move |tx| {
                let fresh = tx.execute(
                    "UPDATE mfa_totp SET last_step = ?2 WHERE user_id = ?1
                     AND (last_step IS NULL OR last_step < ?2)",
                    params![user.as_bytes(), step as i64],
                )?;
                Ok(fresh == 1)
            })?
        }
        Proof::Recovery(code) => {
            let Some(code_digest) = mfa::recovery_digest(code) else {
                return refuse(store, digest.0, user, now);
            };
            store.writer().write(move |tx| {
                let spent = tx.execute(
                    "UPDATE mfa_recovery_codes SET used_ms = ?3
                     WHERE code_digest = ?1 AND user_id = ?2 AND used_ms IS NULL",
                    params![code_digest.0, user.as_bytes(), now.0],
                )?;
                if spent == 1 {
                    audit(
                        tx,
                        Event::RecoveryCodeUsed,
                        Some(user),
                        Some(user),
                        false,
                        None,
                    )?;
                }
                Ok(spent == 1)
            })?
        }
        Proof::Password(password_bytes) => {
            // Only when there is no stronger factor to present.
            let stored: Option<(bool, Option<String>)> = store.read(|conn| {
                conn.prepare_cached(
                    "SELECT EXISTS(SELECT 1 FROM mfa_totp
                        WHERE user_id = ?1 AND confirmed_ms IS NOT NULL),
                        (SELECT phc FROM local_credentials WHERE user_id = ?1)",
                )?
                .query_row([user.as_bytes()], |r| Ok((r.get(0)?, r.get(1)?)))
                .optional()
                .map_err(Error::from)
            })?;
            match stored {
                Some((false, Some(phc))) => {
                    password::verify(&phc, password_bytes) == password::Verdict::Accepted
                }
                _ => {
                    password::spend_equal_work(password_bytes);
                    return refuse(store, digest.0, user, now);
                }
            }
        }
    };
    if !accepted {
        return refuse(store, digest.0, user, now);
    }
    store.writer().write(move |tx| {
        stamp(tx, digest.0, now)?;
        audit(tx, Event::SteppedUp, Some(user), Some(user), false, None)
    })?;
    Ok(true)
}

/// Record a failed proof against the session that presented it. Past the
/// limit the session is revoked outright: the cookie holder has shown they
/// cannot prove presence, so the cookie stops proving identity too.
fn refuse(store: &Store, digest: [u8; 32], user: UserId, now: UnixMillis) -> Result<bool> {
    store.writer().write(move |tx| {
        let failures: Option<i64> = tx
            .prepare_cached(
                "UPDATE sessions SET step_up_failures = step_up_failures + 1
                 WHERE token_digest = ?1 AND revoked_ms IS NULL RETURNING step_up_failures",
            )?
            .query_row([digest], |r| r.get(0))
            .optional()?;
        audit(tx, Event::StepUpFailed, Some(user), Some(user), false, None)?;
        if failures.is_some_and(|count| count >= MAX_STEP_UP_FAILURES) {
            tx.execute(
                "UPDATE sessions SET revoked_ms = ?2 WHERE token_digest = ?1 AND revoked_ms IS NULL",
                params![digest, now.0],
            )?;
            audit(
                tx,
                Event::SessionRevoked,
                None,
                Some(user),
                false,
                Some("step-up failures"),
            )?;
        }
        Ok(false)
    })
}

/// Stamp presence and forgive earlier failures: the proof just given is what
/// the counter was protecting.
fn stamp(tx: &rusqlite::Transaction<'_>, digest: [u8; 32], now: UnixMillis) -> Result<()> {
    tx.execute(
        "UPDATE sessions SET stepped_up_ms = ?2, step_up_failures = 0
         WHERE token_digest = ?1 AND revoked_ms IS NULL
         AND (stepped_up_ms IS NULL OR stepped_up_ms < ?2)",
        params![digest, now.0],
    )?;
    Ok(())
}

/// Whether an account has a confirmed second factor.
pub fn enrolled(conn: &Connection, user: UserId) -> Result<bool> {
    let enrolled: bool = conn
        .prepare_cached(
            "SELECT EXISTS(SELECT 1 FROM mfa_totp WHERE user_id = ?1 AND confirmed_ms IS NOT NULL)",
        )?
        .query_row([user.as_bytes()], |r| r.get(0))?;
    Ok(enrolled)
}

/// How many unspent recovery codes remain. Metadata: the codes themselves are
/// unrecoverable once shown.
pub fn recovery_codes_remaining(conn: &Connection, user: UserId) -> Result<usize> {
    let remaining: i64 = conn
        .prepare_cached(
            "SELECT COUNT(*) FROM mfa_recovery_codes WHERE user_id = ?1 AND used_ms IS NULL",
        )?
        .query_row([user.as_bytes()], |r| r.get(0))?;
    Ok(remaining.max(0) as usize)
}

/// Issue a fresh set of recovery codes, invalidating the previous set. Requires
/// a stepped-up session: the codes are a second factor in their own right.
pub fn reissue_recovery_codes(
    store: &Store,
    session: &Session,
    policy: Policy,
    now: UnixMillis,
) -> Result<Vec<RecoveryCode>> {
    session.require_step_up(policy, now)?;
    let user = session.user;
    let codes = mfa::recovery_codes();
    let digests: Vec<[u8; 32]> = codes.iter().map(|code| code.digest().0).collect();
    store.writer().write(move |tx| {
        if !enrolled(tx, user)? {
            return Err(Error::NotFound);
        }
        replace_recovery_codes(tx, user, &digests, now)?;
        audit(
            tx,
            Event::RecoveryCodesIssued,
            Some(user),
            Some(user),
            false,
            None,
        )
    })?;
    Ok(codes)
}

/// Remove the account's own second factor. Requires a stepped-up session, so a
/// stolen cookie alone cannot strip the protection it is meant to defeat.
pub fn disable(store: &Store, session: &Session, policy: Policy, now: UnixMillis) -> Result<()> {
    session.require_step_up(policy, now)?;
    let user = session.user;
    store.writer().write(move |tx| remove(tx, user, None, now))
}

/// Host-local removal, for an operator whose authenticator device is gone and
/// whose recovery codes are spent. Authorized by access to the database file,
/// like bootstrap and password recovery, and audited as host-local.
pub fn disable_host_local(store: &Store, user: UserId, now: UnixMillis) -> Result<()> {
    store
        .writer()
        .write(move |tx| remove(tx, user, Some(true), now))
}

fn remove(
    tx: &rusqlite::Transaction<'_>,
    user: UserId,
    host_local: Option<bool>,
    now: UnixMillis,
) -> Result<()> {
    let removed = tx.execute("DELETE FROM mfa_totp WHERE user_id = ?1", [user.as_bytes()])?;
    if removed == 0 {
        return Err(Error::NotFound);
    }
    tx.execute(
        "DELETE FROM mfa_recovery_codes WHERE user_id = ?1",
        [user.as_bytes()],
    )?;
    // Every session loses its step-up freshness: removing a factor must not
    // leave a window in which privileged changes are still available.
    tx.execute(
        "UPDATE sessions SET revoked_ms = ?2 WHERE user_id = ?1 AND revoked_ms IS NULL",
        params![user.as_bytes(), now.0],
    )?;
    audit(
        tx,
        Event::MfaDisabled,
        host_local.is_none().then_some(user),
        Some(user),
        host_local.unwrap_or(false),
        None,
    )
}
