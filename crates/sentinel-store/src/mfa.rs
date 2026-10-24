//! Argon2 and TOTP checks run outside the writer; the seed is sealed under a key outside the database.

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

pub const MAX_STEP_UP_FAILURES: i64 = 5;

pub const MAX_FACTOR_FAILURES: i64 = 10;
pub const FACTOR_LOCKOUT_MS: i64 = 15 * 60 * 1000;

pub(crate) fn context(user: UserId) -> Vec<u8> {
    let mut context = Vec::with_capacity(21);
    context.extend_from_slice(b"totp:");
    context.extend_from_slice(user.as_bytes());
    context
}

pub struct Enrollment {
    pub provisioning_uri: String,
}

pub fn begin_enrollment(
    store: &Store,
    key: &Key,
    session: &Session,
    issuer: &str,
    account: &str,
    now: UnixMillis,
) -> Result<Enrollment> {
    begin(store, key, session.user, issuer, account, now)
}

pub fn begin_enrollment_host_local(
    store: &Store,
    key: &Key,
    user: UserId,
    issuer: &str,
    account: &str,
    now: UnixMillis,
) -> Result<Enrollment> {
    begin(store, key, user, issuer, account, now)
}

fn begin(
    store: &Store,
    key: &Key,
    user: UserId,
    issuer: &str,
    account: &str,
    now: UnixMillis,
) -> Result<Enrollment> {
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
            Some(Some(_)) => return Err(Error::Conflict),
            Some(None) => {
                tx.execute("DELETE FROM mfa_totp WHERE user_id = ?1", [user.as_bytes()])?;
            }
            None => {}
        }
        tx.execute(
            "INSERT INTO mfa_totp(user_id, sealed_seed, created_ms) VALUES (?1, ?2, ?3)",
            params![user.as_bytes(), sealed, now.0],
        )
        .map_err(|error| match error {
            rusqlite::Error::SqliteFailure(code, _)
                if code.code == rusqlite::ErrorCode::ConstraintViolation =>
            {
                Error::NotFound
            }
            other => Error::from(other),
        })?;
        Ok(())
    })?;
    Ok(Enrollment { provisioning_uri })
}

pub fn confirm_enrollment(
    store: &Store,
    key: &Key,
    presented: &Secret,
    session: &Session,
    code: &str,
    now: UnixMillis,
) -> Result<Vec<RecoveryCode>> {
    confirm(
        store,
        key,
        session.user,
        Some(presented.digest().0),
        code,
        now,
    )
}

pub fn confirm_enrollment_host_local(
    store: &Store,
    key: &Key,
    user: UserId,
    code: &str,
    now: UnixMillis,
) -> Result<Vec<RecoveryCode>> {
    confirm(store, key, user, None, code, now)
}

fn confirm(
    store: &Store,
    key: &Key,
    user: UserId,
    stamp_session: Option<[u8; 32]>,
    code: &str,
    now: UnixMillis,
) -> Result<Vec<RecoveryCode>> {
    let sealed: Vec<u8> = store.read(|conn| {
        conn.prepare_cached(
            "SELECT sealed_seed FROM mfa_totp WHERE user_id = ?1 AND confirmed_ms IS NULL",
        )?
        .query_row([user.as_bytes()], |r| r.get(0))
        .optional()?
        .ok_or(Error::NotFound)
    })?;
    let seed = open_seed(key, user, &sealed)?;
    let Some(step) = mfa::check(&seed, code, unix_seconds(now)) else {
        if let Some(digest) = stamp_session {
            refuse(store, digest, user, now)?;
        }
        return Err(Error::Forbidden);
    };

    let codes = mfa::recovery_codes();
    let digests: Vec<[u8; 32]> = codes.iter().map(|code| code.digest().0).collect();
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
        let host_local = stamp_session.is_none();
        if let Some(digest) = stamp_session {
            stamp(tx, digest, now)?;
        }
        audit(
            tx,
            Event::MfaEnrolled,
            (!host_local).then_some(user),
            Some(user),
            host_local,
            None,
        )
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

fn unix_seconds(now: UnixMillis) -> u64 {
    now.0.max(0) as u64 / 1000
}

pub enum Proof<'a> {
    Totp(&'a str),
    Recovery(&'a str),
    /// Accepted only when no second factor is enrolled, so a weaker proof cannot stand in for a stronger one.
    Password(&'a [u8]),
}

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
            // A step already accepted is refused, so a code seen over a shoulder cannot be replayed.
            store.writer().write(move |tx| {
                let fresh = tx.execute(
                    "UPDATE mfa_totp SET last_step = ?2 WHERE user_id = ?1
                     AND (last_step IS NULL OR last_step < ?2) AND locked_until_ms <= ?3",
                    params![user.as_bytes(), step as i64, now.0],
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
                     WHERE code_digest = ?1 AND user_id = ?2 AND used_ms IS NULL
                     AND NOT EXISTS(SELECT 1 FROM mfa_totp
                         WHERE user_id = ?2 AND locked_until_ms > ?3)",
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
        tx.prepare_cached("UPDATE mfa_totp SET failures = 0 WHERE user_id = ?1 AND failures != 0")?
            .execute([user.as_bytes()])?;
        audit(tx, Event::SteppedUp, Some(user), Some(user), false, None)
    })?;
    Ok(true)
}

pub(crate) fn clear_factor_lockout(tx: &rusqlite::Transaction<'_>, user: UserId) -> Result<()> {
    tx.prepare_cached(
        "UPDATE mfa_totp SET failures = 0, locked_until_ms = 0
         WHERE user_id = ?1 AND (failures != 0 OR locked_until_ms != 0)",
    )?
    .execute([user.as_bytes()])?;
    Ok(())
}

fn refuse(store: &Store, digest: [u8; 32], user: UserId, now: UnixMillis) -> Result<bool> {
    refuse_counting(store, digest, user, now, true)
}

pub(crate) fn refuse_password(
    store: &Store,
    digest: [u8; 32],
    user: UserId,
    now: UnixMillis,
) -> Result<bool> {
    refuse_counting(store, digest, user, now, false)
}

fn refuse_counting(
    store: &Store,
    digest: [u8; 32],
    user: UserId,
    now: UnixMillis,
    count_factor: bool,
) -> Result<bool> {
    store.writer().write(move |tx| {
        let failures: Option<i64> = tx
            .prepare_cached(
                "UPDATE sessions SET step_up_failures = step_up_failures + 1
                 WHERE token_digest = ?1 AND revoked_ms IS NULL RETURNING step_up_failures",
            )?
            .query_row([digest], |r| r.get(0))
            .optional()?;
        audit(tx, Event::StepUpFailed, Some(user), Some(user), false, None)?;
        let until = now.0.saturating_add(FACTOR_LOCKOUT_MS);
        let locked_now: Option<bool> = tx
            .prepare_cached(
                "UPDATE mfa_totp SET
                 failures = CASE WHEN locked_until_ms > ?2 THEN failures
                     WHEN locked_until_ms != 0 THEN 1 ELSE failures + 1 END,
                 locked_until_ms = CASE WHEN locked_until_ms > ?2 THEN locked_until_ms
                     WHEN (CASE WHEN locked_until_ms != 0 THEN 1 ELSE failures + 1 END) >= ?3
                         THEN ?4
                     ELSE 0 END
                 WHERE user_id = ?1 AND confirmed_ms IS NOT NULL AND ?5
                 RETURNING locked_until_ms = ?4",
            )?
            .query_row(
                params![
                    user.as_bytes(),
                    now.0,
                    MAX_FACTOR_FAILURES,
                    until,
                    count_factor
                ],
                |r| r.get(0),
            )
            .optional()?;
        if locked_now == Some(true) {
            crate::local_auth::revoke_all(tx, user, now)?;
            audit(
                tx,
                Event::SessionRevoked,
                None,
                Some(user),
                false,
                Some("second factor locked"),
            )?;
            return Ok(false);
        }
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

fn stamp(tx: &rusqlite::Transaction<'_>, digest: [u8; 32], now: UnixMillis) -> Result<()> {
    tx.execute(
        "UPDATE sessions SET stepped_up_ms = ?2, step_up_failures = 0
         WHERE token_digest = ?1 AND revoked_ms IS NULL
         AND (stepped_up_ms IS NULL OR stepped_up_ms < ?2)",
        params![digest, now.0],
    )?;
    Ok(())
}

pub fn enrolled(conn: &Connection, user: UserId) -> Result<bool> {
    let enrolled: bool = conn
        .prepare_cached(
            "SELECT EXISTS(SELECT 1 FROM mfa_totp WHERE user_id = ?1 AND confirmed_ms IS NOT NULL)",
        )?
        .query_row([user.as_bytes()], |r| r.get(0))?;
    Ok(enrolled)
}

pub fn enrollment_pending(conn: &Connection, user: UserId) -> Result<bool> {
    let pending: bool = conn
        .prepare_cached(
            "SELECT EXISTS(SELECT 1 FROM mfa_totp WHERE user_id = ?1 AND confirmed_ms IS NULL)",
        )?
        .query_row([user.as_bytes()], |r| r.get(0))?;
    Ok(pending)
}

pub fn recovery_codes_remaining(conn: &Connection, user: UserId) -> Result<usize> {
    let remaining: i64 = conn
        .prepare_cached(
            "SELECT COUNT(*) FROM mfa_recovery_codes WHERE user_id = ?1 AND used_ms IS NULL",
        )?
        .query_row([user.as_bytes()], |r| r.get(0))?;
    Ok(remaining.max(0) as usize)
}

pub fn reissue_recovery_codes(
    store: &Store,
    session: &Session,
    policy: Policy,
    now: UnixMillis,
) -> Result<Vec<RecoveryCode>> {
    session.require_step_up(policy, now)?;
    reissue(store, session.user, false, now)
}

pub fn reissue_recovery_codes_host_local(
    store: &Store,
    user: UserId,
    now: UnixMillis,
) -> Result<Vec<RecoveryCode>> {
    reissue(store, user, true, now)
}

fn reissue(
    store: &Store,
    user: UserId,
    host_local: bool,
    now: UnixMillis,
) -> Result<Vec<RecoveryCode>> {
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
            (!host_local).then_some(user),
            Some(user),
            host_local,
            None,
        )
    })?;
    Ok(codes)
}

pub fn disable(store: &Store, session: &Session, policy: Policy, now: UnixMillis) -> Result<()> {
    session.require_step_up(policy, now)?;
    let user = session.user;
    store.writer().write(move |tx| remove(tx, user, None, now))
}

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
