//! Local login: host-local first-admin bootstrap, password credentials, opaque
//! sessions with idle/absolute expiry and revocation, and audited recovery.
//!
//! Ordering rule for every operation here: Argon2id verification costs ~19 MiB
//! and tens of milliseconds, so it runs on the caller's thread and never inside
//! the single durable writer. The writer transaction rechecks the credential it
//! verified against, so a password change or lockout that commits during that
//! window cannot be overtaken by an in-flight login.
//!
//! Authority is host-local where it says so: `bootstrap` and `recover` are
//! reachable only by a process that can already open this database file. No
//! route may expose them, and there is no unauthenticated network path to them.

use rusqlite::{Connection, OptionalExtension, Transaction, params};
use sentinel_auth::{
    password::{self, Verdict},
    secret::{Digest, Secret},
};
use sentinel_core::{
    UnixMillis, UserId,
    auth::{Permissions, Principal},
};

use crate::{Error, Result, Store};

/// Session lifetimes and login throttling. Absolute expiry bounds a stolen
/// cookie; idle expiry bounds an abandoned browser; the lockout bounds online
/// guessing without giving an attacker a way to lock an operator out forever.
#[derive(Clone, Copy, Debug)]
pub struct Policy {
    pub idle_ms: i64,
    pub absolute_ms: i64,
    /// Consecutive failures before the account stops accepting passwords.
    pub max_failures: i64,
    pub lockout_ms: i64,
    /// How much of the idle window must be spent before a request pays for a
    /// write to slide the deadline. Without it every request takes the writer.
    pub refresh_after_ms: i64,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            idle_ms: 8 * 60 * 60 * 1000,
            absolute_ms: 7 * 24 * 60 * 60 * 1000,
            max_failures: 10,
            lockout_ms: 15 * 60 * 1000,
            refresh_after_ms: 5 * 60 * 1000,
        }
    }
}

/// Audited authentication and account-administration events. The numbers are
/// persisted and stable. No record carries a password, digest or cookie value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Event {
    Bootstrap = 1,
    LoginAccepted = 2,
    LoginRejected = 3,
    LoginLocked = 4,
    Logout = 5,
    LogoutAll = 6,
    PasswordChanged = 7,
    PasswordRecovered = 8,
    SuperAdminGranted = 9,
    SuperAdminRevoked = 10,
    AccountActivated = 11,
    AccountDeactivated = 12,
}

impl Event {
    const fn from_code(code: i64) -> Option<Event> {
        Some(match code {
            1 => Event::Bootstrap,
            2 => Event::LoginAccepted,
            3 => Event::LoginRejected,
            4 => Event::LoginLocked,
            5 => Event::Logout,
            6 => Event::LogoutAll,
            7 => Event::PasswordChanged,
            8 => Event::PasswordRecovered,
            9 => Event::SuperAdminGranted,
            10 => Event::SuperAdminRevoked,
            11 => Event::AccountActivated,
            12 => Event::AccountDeactivated,
            _ => return None,
        })
    }
}

/// The credentials handed to the browser exactly once. `session` goes into the
/// `__Host-` cookie; `csrf` goes into the page, to be echoed in a header.
pub struct Issued {
    pub user: UserId,
    pub session: Secret,
    pub csrf: Secret,
    pub max_age_secs: u32,
}

/// Why a login did not produce a session. Callers render one response for every
/// non-accepted outcome; the distinction exists for audit, not for the user.
pub enum Login {
    Accepted(Issued),
    Rejected,
    Locked { until: UnixMillis },
}

/// A validated session. Not a capability: membership, grants and the account's
/// live state are still checked per query through [`crate::auth`].
#[derive(Clone, Copy, Debug)]
pub struct Session {
    pub user: UserId,
    pub super_admin: bool,
    pub csrf: Digest,
    pub idle_deadline: UnixMillis,
    pub absolute_deadline: UnixMillis,
}

impl Session {
    /// A browser session acts as its human, not above them: repository bits plus
    /// tenant administration, which `auth` still verifies against live
    /// membership per tenant. Platform administration is present only for an
    /// actual super admin; A06 adds step-up before privileged policy changes.
    pub fn principal(&self) -> Principal {
        let mut permissions = Permissions::REPOSITORY.union(Permissions::TENANT_ADMIN);
        if self.super_admin {
            permissions = permissions.union(Permissions::PLATFORM_ADMIN);
        }
        Principal::new(self.user, permissions, None, None)
    }
}

/// Canonical login name: 1-63 bytes of lower-case ASCII letters, digits, `.`,
/// `-` or `_`, starting alphanumeric. Case is rejected, never folded, so two
/// spellings can never resolve to one account.
pub fn username(value: &str) -> Result<&str> {
    let bytes = value.as_bytes();
    let acceptable = matches!(bytes.len(), 1..=63)
        && (bytes[0].is_ascii_lowercase() || bytes[0].is_ascii_digit())
        && bytes.iter().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'-' | b'_')
        });
    if acceptable {
        Ok(value)
    } else {
        Err(Error::InvalidInput("username"))
    }
}

/// Audit detail is bounded metadata (a login name, never a secret). Truncate on
/// a character boundary so a non-ASCII attempt cannot panic the writer.
fn bounded_detail(detail: &str) -> &str {
    match detail
        .char_indices()
        .take_while(|(at, _)| *at <= 128)
        .last()
    {
        Some((at, c)) if at + c.len_utf8() <= 128 => &detail[..at + c.len_utf8()],
        _ => "",
    }
}

fn audit(
    tx: &Transaction<'_>,
    event: Event,
    actor: Option<UserId>,
    subject: Option<UserId>,
    host_local: bool,
    detail: Option<&str>,
) -> Result<()> {
    tx.prepare_cached(
        "INSERT INTO auth_audit(at_ms, event, actor_user_id, subject_user_id, host_local, detail)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
    )?
    .execute(params![
        UnixMillis::now().0,
        event as u8,
        actor.as_ref().map(UserId::as_bytes),
        subject.as_ref().map(UserId::as_bytes),
        host_local,
        detail.map(bounded_detail)
    ])?;
    Ok(())
}

/// Host-local admission of the first super admin. Refuses once the latch is set
/// or any active super admin already exists: "first visitor wins" is not a
/// bootstrap. The user, its credential and the latch are one commit.
pub fn bootstrap(
    store: &Store,
    login_name: &str,
    display_name: &str,
    password_bytes: &[u8],
    now: UnixMillis,
) -> Result<UserId> {
    let login_name = username(login_name)?.to_owned();
    // Refuse an already-bootstrapped deployment without paying for a hash; the
    // transaction below is what actually decides.
    if store.read(bootstrap_complete)? {
        return Err(Error::Forbidden);
    }
    let phc = password::hash(password_bytes).map_err(|_| Error::InvalidInput("password"))?;
    let user = UserId::new();
    let display_name = display_name.to_owned();
    store.writer().write(move |tx| {
        if bootstrap_complete(tx)? {
            return Err(Error::Forbidden);
        }
        crate::auth::provisioning::insert_human(tx, user, &display_name, true, now)?;
        insert_credential(tx, user, &login_name, &phc, now)?;
        tx.execute(
            "INSERT INTO bootstrap(id, completed_ms, user_id) VALUES (1, ?1, ?2)",
            params![now.0, user.as_bytes()],
        )?;
        audit(
            tx,
            Event::Bootstrap,
            None,
            Some(user),
            true,
            Some(&login_name),
        )?;
        Ok(user)
    })
}

fn bootstrap_complete(conn: &Connection) -> Result<bool> {
    let complete: bool = conn
        .prepare_cached(
            "SELECT EXISTS(SELECT 1 FROM bootstrap)
             OR EXISTS(SELECT 1 FROM users WHERE kind = 0 AND super_admin = 1 AND active = 1)",
        )?
        .query_row([], |r| r.get(0))?;
    Ok(complete)
}

/// Whether the host-local bootstrap command is still available.
pub fn bootstrap_available(conn: &Connection) -> Result<bool> {
    bootstrap_complete(conn).map(|done| !done)
}

fn insert_credential(
    tx: &Transaction<'_>,
    user: UserId,
    login_name: &str,
    phc: &str,
    now: UnixMillis,
) -> Result<()> {
    tx.execute(
        "INSERT INTO local_credentials(user_id, username, phc, updated_ms) VALUES (?1, ?2, ?3, ?4)",
        params![user.as_bytes(), login_name, phc, now.0],
    )?;
    Ok(())
}

struct Candidate {
    user: UserId,
    phc: String,
    locked_until: i64,
}

/// One indexed lookup of everything verification needs. Returns `None` for an
/// unknown, service-owned or deactivated account alike.
fn candidate(conn: &Connection, login_name: &str) -> Result<Option<Candidate>> {
    let row = conn
        .prepare_cached(
            "SELECT c.user_id, c.phc, c.locked_until_ms FROM local_credentials c
             JOIN users u ON u.id = c.user_id
             WHERE c.username = ?1 AND u.kind = 0 AND u.active = 1",
        )?
        .query_row([login_name], |r| {
            Ok((
                r.get::<_, [u8; 16]>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, i64>(2)?,
            ))
        })
        .optional()?;
    let Some((id, phc, locked_until)) = row else {
        return Ok(None);
    };
    Ok(Some(Candidate {
        user: UserId::from_bytes(id).map_err(|_| Error::Corrupt("user_id"))?,
        phc,
        locked_until,
    }))
}

/// Verify a password and, on success, issue a fresh opaque session. An unknown
/// user costs the same work as a wrong password.
pub fn login(
    store: &Store,
    login_name: &str,
    password_bytes: &[u8],
    policy: Policy,
    now: UnixMillis,
) -> Result<Login> {
    // An attempt against an unknown or malformed name is still recorded, with no
    // subject: password spraying is visible in the audit trail, and the caller
    // cannot tell the outcomes apart from the response or from the time taken.
    let Ok(login_name) = username(login_name) else {
        password::spend_equal_work(password_bytes);
        store
            .writer()
            .write(move |tx| audit(tx, Event::LoginRejected, None, None, false, None))?;
        return Ok(Login::Rejected);
    };
    let Some(candidate) = store.read(|conn| candidate(conn, login_name))? else {
        password::spend_equal_work(password_bytes);
        let attempted = login_name.to_owned();
        store.writer().write(move |tx| {
            audit(
                tx,
                Event::LoginRejected,
                None,
                None,
                false,
                Some(&attempted),
            )
        })?;
        return Ok(Login::Rejected);
    };
    if candidate.locked_until > now.0 {
        password::spend_equal_work(password_bytes);
        let until = UnixMillis(candidate.locked_until);
        let user = candidate.user;
        store
            .writer()
            .write(move |tx| audit(tx, Event::LoginLocked, None, Some(user), false, None))?;
        return Ok(Login::Locked { until });
    }

    let verdict = password::verify(&candidate.phc, password_bytes);
    // Rehash outside the transaction too: a parameter upgrade must not add
    // tens of milliseconds of Argon2 to the writer's critical section.
    let upgraded = (verdict == Verdict::Accepted && password::needs_rehash(&candidate.phc))
        .then(|| password::hash(password_bytes).ok())
        .flatten();
    let user = candidate.user;
    let verified = candidate.phc;

    if verdict != Verdict::Accepted {
        store.writer().write(move |tx| {
            // Count the failure only against the record that was actually tested.
            let locked: Option<i64> = tx
                .prepare_cached(
                    "UPDATE local_credentials SET failures = failures + 1,
                     locked_until_ms = CASE WHEN failures + 1 >= ?3 THEN ?4 ELSE locked_until_ms END
                     WHERE user_id = ?1 AND phc = ?2 RETURNING locked_until_ms",
                )?
                .query_row(
                    params![
                        user.as_bytes(),
                        verified,
                        policy.max_failures,
                        now.0.saturating_add(policy.lockout_ms)
                    ],
                    |r| r.get(0),
                )
                .optional()?;
            let event = match locked {
                Some(until) if until > now.0 => Event::LoginLocked,
                _ => Event::LoginRejected,
            };
            audit(tx, event, None, Some(user), false, None)
        })?;
        return Ok(Login::Rejected);
    }

    let session = Secret::generate();
    let csrf = Secret::generate();
    let (token_digest, csrf_digest) = (session.digest(), csrf.digest());
    let issued = store.writer().write(move |tx| {
        let current: Option<(String, i64)> = tx
            .prepare_cached(
                "SELECT c.phc, c.locked_until_ms FROM local_credentials c
                 JOIN users u ON u.id = c.user_id
                 WHERE c.user_id = ?1 AND u.kind = 0 AND u.active = 1",
            )?
            .query_row([user.as_bytes()], |r| Ok((r.get(0)?, r.get(1)?)))
            .optional()?;
        // The credential changed, the account was suspended, or a concurrent
        // attempt locked it while this password was being hashed.
        match current {
            Some((phc, locked_until)) if phc == verified && locked_until <= now.0 => {}
            _ => return Err(Error::Conflict),
        }
        tx.execute(
            "UPDATE local_credentials SET failures = 0, locked_until_ms = 0,
             phc = COALESCE(?2, phc),
             updated_ms = CASE WHEN ?2 IS NULL THEN updated_ms ELSE ?3 END
             WHERE user_id = ?1",
            params![user.as_bytes(), upgraded, now.0],
        )?;
        insert_session(tx, user, token_digest, csrf_digest, policy, now)?;
        audit(
            tx,
            Event::LoginAccepted,
            Some(user),
            Some(user),
            false,
            None,
        )
    });
    match issued {
        Ok(()) => Ok(Login::Accepted(Issued {
            user,
            session,
            csrf,
            max_age_secs: (policy.idle_ms / 1000).clamp(0, i64::from(u32::MAX)) as u32,
        })),
        Err(Error::Conflict) => Ok(Login::Rejected),
        Err(error) => Err(error),
    }
}

fn insert_session(
    tx: &Transaction<'_>,
    user: UserId,
    token: Digest,
    csrf: Digest,
    policy: Policy,
    now: UnixMillis,
) -> Result<()> {
    let absolute = now.0.saturating_add(policy.absolute_ms);
    tx.execute(
        "INSERT INTO sessions(token_digest, user_id, csrf_digest, created_ms,
            idle_deadline_ms, absolute_deadline_ms) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            token.0,
            user.as_bytes(),
            csrf.0,
            now.0,
            now.0.saturating_add(policy.idle_ms).min(absolute),
            absolute
        ],
    )?;
    Ok(())
}

/// Validate a presented cookie value. One primary-key probe; expiry, revocation
/// and the account's live state are predicates of that same statement, so a
/// suspended user's cookie stops working without a sweep having to run first.
pub fn authenticate(conn: &Connection, presented: &Secret, now: UnixMillis) -> Result<Session> {
    let digest = presented.digest();
    let row = conn
        .prepare_cached(
            "SELECT s.user_id, s.csrf_digest, s.idle_deadline_ms, s.absolute_deadline_ms,
                    u.super_admin
             FROM sessions s JOIN users u ON u.id = s.user_id
             WHERE s.token_digest = ?1 AND s.revoked_ms IS NULL
             AND s.idle_deadline_ms > ?2 AND s.absolute_deadline_ms > ?2
             AND u.kind = 0 AND u.active = 1",
        )?
        .query_row(params![digest.0, now.0], |r| {
            Ok((
                r.get::<_, [u8; 16]>(0)?,
                r.get::<_, [u8; 32]>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, i64>(3)?,
                r.get::<_, bool>(4)?,
            ))
        })
        .optional()?
        .ok_or(Error::NotFound)?;
    Ok(Session {
        user: UserId::from_bytes(row.0).map_err(|_| Error::Corrupt("user_id"))?,
        super_admin: row.4,
        csrf: Digest(row.1),
        idle_deadline: UnixMillis(row.2),
        absolute_deadline: UnixMillis(row.3),
    })
}

/// True when this session has spent enough of its idle window to be worth one
/// write. A session already pinned to its absolute deadline never is.
pub fn refresh_due(session: &Session, policy: Policy, now: UnixMillis) -> bool {
    session.idle_deadline.0.saturating_sub(now.0) <= policy.idle_ms - policy.refresh_after_ms
        && session.idle_deadline < session.absolute_deadline
}

/// Slide the idle deadline, never past the absolute one, and never for a
/// revoked or already-expired session.
pub fn refresh(store: &Store, presented: &Secret, policy: Policy, now: UnixMillis) -> Result<()> {
    let digest = presented.digest();
    store.writer().write(move |tx| {
        tx.execute(
            "UPDATE sessions SET idle_deadline_ms = MIN(?2 + ?3, absolute_deadline_ms)
             WHERE token_digest = ?1 AND revoked_ms IS NULL AND idle_deadline_ms > ?2",
            params![digest.0, now.0, policy.idle_ms],
        )?;
        Ok(())
    })
}

/// Revoke one session. Idempotent, and safe to call for an unknown secret.
pub fn logout(store: &Store, presented: &Secret, now: UnixMillis) -> Result<()> {
    let digest = presented.digest();
    store.writer().write(move |tx| {
        let user: Option<[u8; 16]> = tx
            .prepare_cached(
                "UPDATE sessions SET revoked_ms = ?2 WHERE token_digest = ?1
                 AND revoked_ms IS NULL RETURNING user_id",
            )?
            .query_row(params![digest.0, now.0], |r| r.get(0))
            .optional()?;
        if let Some(user) = user {
            let user = UserId::from_bytes(user).map_err(|_| Error::Corrupt("user_id"))?;
            audit(tx, Event::Logout, Some(user), Some(user), false, None)?;
        }
        Ok(())
    })
}

/// Revoke every live session of one account: the caller's logout-all, and the
/// rotation a password change, role change or suspension must perform.
pub fn revoke_all(tx: &Transaction<'_>, user: UserId, now: UnixMillis) -> Result<usize> {
    let revoked = tx.execute(
        "UPDATE sessions SET revoked_ms = ?2 WHERE user_id = ?1 AND revoked_ms IS NULL",
        params![user.as_bytes(), now.0],
    )?;
    Ok(revoked)
}

/// Logout everywhere for the authenticated account, including this session.
pub fn logout_all(store: &Store, session: &Session, now: UnixMillis) -> Result<usize> {
    let user = session.user;
    store.writer().write(move |tx| {
        let revoked = revoke_all(tx, user, now)?;
        audit(tx, Event::LogoutAll, Some(user), Some(user), false, None)?;
        Ok(revoked)
    })
}

/// Self-service password change. Requires the current password, then rotates
/// every session: a password change must not leave old cookies working.
pub fn change_password(
    store: &Store,
    session: &Session,
    current: &[u8],
    new: &[u8],
    now: UnixMillis,
) -> Result<bool> {
    let user = session.user;
    let stored = store.read(|conn| {
        conn.prepare_cached("SELECT phc FROM local_credentials WHERE user_id = ?1")?
            .query_row([user.as_bytes()], |r| r.get::<_, String>(0))
            .optional()
            .map_err(Error::from)
    })?;
    let Some(stored) = stored else {
        password::spend_equal_work(current);
        return Err(Error::NotFound);
    };
    if password::verify(&stored, current) != Verdict::Accepted {
        return Ok(false);
    }
    let phc = password::hash(new).map_err(|_| Error::InvalidInput("password"))?;
    store.writer().write(move |tx| {
        let changed = tx.execute(
            "UPDATE local_credentials SET phc = ?2, updated_ms = ?3, failures = 0,
             locked_until_ms = 0 WHERE user_id = ?1 AND phc = ?4",
            params![user.as_bytes(), phc, now.0, stored],
        )?;
        if changed == 0 {
            return Err(Error::Conflict);
        }
        revoke_all(tx, user, now)?;
        audit(
            tx,
            Event::PasswordChanged,
            Some(user),
            Some(user),
            false,
            None,
        )?;
        Ok(true)
    })
}

/// Host-local recovery: reset a local password, clear the lockout and revoke
/// the account's sessions. Authorized by access to the database file itself, so
/// a locked-out operator is never permanently shut out, and every use is
/// recorded as host-local in the audit table.
pub fn recover(
    store: &Store,
    login_name: &str,
    password_bytes: &[u8],
    now: UnixMillis,
) -> Result<UserId> {
    let login_name = username(login_name)?.to_owned();
    let phc = password::hash(password_bytes).map_err(|_| Error::InvalidInput("password"))?;
    store.writer().write(move |tx| {
        let user: [u8; 16] = tx
            .prepare_cached(
                "UPDATE local_credentials SET phc = ?2, updated_ms = ?3, failures = 0,
                 locked_until_ms = 0 WHERE username = ?1 RETURNING user_id",
            )?
            .query_row(params![login_name, phc, now.0], |r| r.get(0))
            .optional()?
            .ok_or(Error::NotFound)?;
        let user = UserId::from_bytes(user).map_err(|_| Error::Corrupt("user_id"))?;
        revoke_all(tx, user, now)?;
        audit(
            tx,
            Event::PasswordRecovered,
            None,
            Some(user),
            true,
            Some(&login_name),
        )?;
        Ok(user)
    })
}

/// Provision a local credential for an existing human account. Trusted
/// administration, not a registration route: A05 owns invitations and approval.
pub fn provision_credential(
    tx: &Transaction<'_>,
    principal: Principal,
    target: UserId,
    login_name: &str,
    phc: &str,
    now: UnixMillis,
) -> Result<()> {
    crate::auth::require_platform_admin(tx, principal)?;
    insert_credential(tx, target, username(login_name)?, phc, now)
}

/// Grant or revoke platform administration. The database also refuses to empty
/// the super-admin set, so this cannot lock the deployment out even if a future
/// caller forgets the check.
pub fn set_super_admin(
    tx: &Transaction<'_>,
    principal: Principal,
    target: UserId,
    super_admin: bool,
    now: UnixMillis,
) -> Result<()> {
    crate::auth::require_platform_admin(tx, principal)?;
    let changed = tx.execute(
        "UPDATE users SET super_admin = ?2 WHERE id = ?1 AND kind = 0 AND super_admin != ?2",
        params![target.as_bytes(), super_admin],
    )?;
    if changed == 0 {
        return Err(Error::NotFound);
    }
    // A demoted admin's live sessions must stop carrying platform authority.
    revoke_all(tx, target, now)?;
    let event = if super_admin {
        Event::SuperAdminGranted
    } else {
        Event::SuperAdminRevoked
    };
    audit(tx, event, Some(principal.user), Some(target), false, None)
}

/// Activate or suspend an account. Deactivation revokes sessions in the same
/// transaction; it does not wait for their deadlines.
pub fn set_active(
    tx: &Transaction<'_>,
    principal: Principal,
    target: UserId,
    active: bool,
    now: UnixMillis,
) -> Result<()> {
    crate::auth::require_platform_admin(tx, principal)?;
    let changed = tx.execute(
        "UPDATE users SET active = ?2 WHERE id = ?1 AND active != ?2",
        params![target.as_bytes(), active],
    )?;
    if changed == 0 {
        return Err(Error::NotFound);
    }
    if !active {
        revoke_all(tx, target, now)?;
    }
    let event = if active {
        Event::AccountActivated
    } else {
        Event::AccountDeactivated
    };
    audit(tx, event, Some(principal.user), Some(target), false, None)
}

/// Delete sessions that can no longer authenticate anybody. Bounded per call so
/// maintenance cannot hold the writer while a large table is swept.
pub fn purge_expired(store: &Store, now: UnixMillis, limit: u32) -> Result<usize> {
    store.writer().write(move |tx| {
        let removed = tx.execute(
            "DELETE FROM sessions WHERE token_digest IN
             (SELECT token_digest FROM sessions
              WHERE absolute_deadline_ms <= ?1 OR idle_deadline_ms <= ?1 OR revoked_ms IS NOT NULL
              LIMIT ?2)",
            params![now.0, limit],
        )?;
        Ok(removed)
    })
}

#[derive(Debug, PartialEq, Eq)]
pub struct AuditRecord {
    pub seq: i64,
    pub at: UnixMillis,
    pub event: Event,
    pub actor: Option<UserId>,
    pub subject: Option<UserId>,
    pub host_local: bool,
    pub detail: Option<String>,
}

/// Most recent records first. At most 100 per call.
pub fn recent_audit(conn: &Connection, limit: u16) -> Result<Vec<AuditRecord>> {
    if !(1..=100).contains(&limit) {
        return Err(Error::InvalidInput("page size"));
    }
    let mut stmt = conn.prepare_cached(
        "SELECT seq, at_ms, event, actor_user_id, subject_user_id, host_local, detail
         FROM auth_audit ORDER BY seq DESC LIMIT ?1",
    )?;
    let rows = stmt.query_map([limit], |r| {
        Ok((
            r.get::<_, i64>(0)?,
            r.get::<_, i64>(1)?,
            r.get::<_, i64>(2)?,
            r.get::<_, Option<[u8; 16]>>(3)?,
            r.get::<_, Option<[u8; 16]>>(4)?,
            r.get::<_, bool>(5)?,
            r.get::<_, Option<String>>(6)?,
        ))
    })?;
    let id = |bytes: Option<[u8; 16]>| match bytes {
        Some(b) => UserId::from_bytes(b)
            .map(Some)
            .map_err(|_| Error::Corrupt("user_id")),
        None => Ok(None),
    };
    rows.map(|row| {
        let row = row?;
        Ok(AuditRecord {
            seq: row.0,
            at: UnixMillis(row.1),
            event: Event::from_code(row.2).ok_or(Error::Corrupt("auth_audit.event"))?,
            actor: id(row.3)?,
            subject: id(row.4)?,
            host_local: row.5,
            detail: row.6,
        })
    })
    .collect()
}

#[cfg(test)]
mod tests {
    use rusqlite::Connection;

    /// Session validation runs on every authenticated request. It must stay a
    /// primary-key probe plus one key join, never a scan or a temporary sort.
    #[test]
    fn session_validation_and_credential_lookup_are_index_searches() {
        let mut conn = Connection::open_in_memory().unwrap();
        crate::migrate(&mut conn).unwrap();
        for sql in [
            "EXPLAIN QUERY PLAN SELECT s.user_id, s.csrf_digest, s.idle_deadline_ms,
                s.absolute_deadline_ms, u.super_admin
             FROM sessions s JOIN users u ON u.id = s.user_id
             WHERE s.token_digest = ?1 AND s.revoked_ms IS NULL
             AND s.idle_deadline_ms > ?2 AND s.absolute_deadline_ms > ?2
             AND u.kind = 0 AND u.active = 1",
            "EXPLAIN QUERY PLAN SELECT c.user_id, c.phc, c.locked_until_ms
             FROM local_credentials c JOIN users u ON u.id = c.user_id
             WHERE c.username = ?1 AND u.kind = 0 AND u.active = 1",
        ] {
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
}
