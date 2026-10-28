//! Argon2id runs on the caller's thread, never inside the writer: the writer transaction rechecks the
//! verified credential, so a password change or lockout committed in between cannot be overtaken.

use rusqlite::{Connection, OptionalExtension, Transaction, params};
use sentinel_auth::{
    password::{self, Verdict},
    secret::{Digest, Secret},
};
use sentinel_core::{
    SessionId, UnixMillis, UserId,
    auth::{Permissions, Principal},
};

pub use crate::auth::Authority;

use crate::{Error, Result, Store};

#[derive(Clone, Copy, Debug)]
pub struct Policy {
    pub idle_ms: i64,
    pub absolute_ms: i64,
    pub max_failures: i64,
    pub lockout_ms: i64,
    pub refresh_after_ms: i64,
    pub step_up_ms: i64,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            idle_ms: 8 * 60 * 60 * 1000,
            absolute_ms: 7 * 24 * 60 * 60 * 1000,
            max_failures: 10,
            lockout_ms: 15 * 60 * 1000,
            refresh_after_ms: 5 * 60 * 1000,
            step_up_ms: 10 * 60 * 1000,
        }
    }
}

/// Persisted as these codes: never renumber or reuse one. No audit row carries a secret.
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
    TokenIssued = 13,
    TokenRevoked = 14,
    IdentityLinked = 15,
    IdentityUnlinked = 16,
    RegistrationAdmitted = 17,
    RegistrationPending = 18,
    RegistrationRefused = 19,
    AccountApproved = 20,
    AccountRejected = 21,
    InvitationCreated = 22,
    InvitationRedeemed = 23,
    InvitationRevoked = 24,
    PolicyChanged = 25,
    InstallationBound = 26,
    InstallationUnbound = 27,
    MfaEnrolled = 28,
    MfaDisabled = 29,
    SteppedUp = 30,
    StepUpFailed = 31,
    RecoveryCodeUsed = 32,
    RecoveryCodesIssued = 33,
    SessionRevoked = 34,
    TenantSuspended = 35,
    TenantReactivated = 36,
    MembershipSet = 37,
    MembershipRemoved = 38,
    GrantChanged = 39,
    PoolCreated = 40,
    PoolGranted = 41,
    PoolGrantRevoked = 42,
    NamespaceCreated = 43,
    WorkerEnrollmentIssued = 44,
    WorkerEnrollmentRefused = 45,
    WorkerEnrolled = 46,
    WorkerRevoked = 47,
    OAuthGrantIssued = 48,
    OAuthGrantRevoked = 49,
    OAuthRefreshReplay = 50,
    OAuthCodeReplay = 51,
    OAuthConsentDenied = 52,
    OAuthDeviceApproved = 53,
    OAuthDeviceDenied = 54,
    ServiceGrantIssued = 55,
    ServiceAccountCreated = 56,
    PlatformOverride = 57,
    MemberAdded = 58,
    EmailVerificationRequested = 59,
    EmailVerified = 60,
    MailAbandoned = 61,
    GithubMemberJoined = 70,
    GithubMemberRoleChanged = 71,
    GithubMemberRemoved = 72,
    TenantBackingChanged = 73,
    DomainAutoJoined = 74,
    MfaEnrollmentStarted = 75,
    WorkerUninstallRequested = 90,
    WorkerUninstalled = 91,
    WorkerBootstrapDownloaded = 92,
    WorkerEnrollmentRevoked = 93,
    WorkerPolicyChanged = 94,
    WorkerNodeKeyAuthorized = 95,
}

impl Event {
    pub const fn name(self) -> &'static str {
        match self {
            Event::Bootstrap => "bootstrap",
            Event::LoginAccepted => "login-accepted",
            Event::LoginRejected => "login-rejected",
            Event::LoginLocked => "login-locked",
            Event::Logout => "logout",
            Event::LogoutAll => "logout-all",
            Event::PasswordChanged => "password-changed",
            Event::PasswordRecovered => "password-recovered",
            Event::SuperAdminGranted => "super-admin-granted",
            Event::SuperAdminRevoked => "super-admin-revoked",
            Event::AccountActivated => "account-activated",
            Event::AccountDeactivated => "account-deactivated",
            Event::TokenIssued => "token-issued",
            Event::TokenRevoked => "token-revoked",
            Event::IdentityLinked => "identity-linked",
            Event::IdentityUnlinked => "identity-unlinked",
            Event::RegistrationAdmitted => "registration-admitted",
            Event::RegistrationPending => "registration-pending",
            Event::RegistrationRefused => "registration-refused",
            Event::AccountApproved => "account-approved",
            Event::AccountRejected => "account-rejected",
            Event::InvitationCreated => "invitation-created",
            Event::InvitationRedeemed => "invitation-redeemed",
            Event::InvitationRevoked => "invitation-revoked",
            Event::PolicyChanged => "policy-changed",
            Event::InstallationBound => "installation-bound",
            Event::InstallationUnbound => "installation-unbound",
            Event::MfaEnrolled => "mfa-enrolled",
            Event::MfaDisabled => "mfa-disabled",
            Event::SteppedUp => "stepped-up",
            Event::StepUpFailed => "step-up-failed",
            Event::RecoveryCodeUsed => "recovery-code-used",
            Event::RecoveryCodesIssued => "recovery-codes-issued",
            Event::SessionRevoked => "session-revoked",
            Event::TenantSuspended => "tenant-suspended",
            Event::TenantReactivated => "tenant-reactivated",
            Event::MembershipSet => "membership-set",
            Event::MembershipRemoved => "membership-removed",
            Event::GrantChanged => "grant-changed",
            Event::PoolCreated => "pool-created",
            Event::PoolGranted => "pool-granted",
            Event::PoolGrantRevoked => "pool-grant-revoked",
            Event::NamespaceCreated => "namespace-created",
            Event::WorkerEnrollmentIssued => "worker-enrollment-issued",
            Event::WorkerEnrollmentRefused => "worker-enrollment-refused",
            Event::WorkerEnrolled => "worker-enrolled",
            Event::WorkerRevoked => "worker-revoked",
            Event::OAuthGrantIssued => "oauth-grant-issued",
            Event::OAuthGrantRevoked => "oauth-grant-revoked",
            Event::OAuthRefreshReplay => "oauth-refresh-replay",
            Event::OAuthCodeReplay => "oauth-code-replay",
            Event::OAuthConsentDenied => "oauth-consent-denied",
            Event::OAuthDeviceApproved => "oauth-device-approved",
            Event::OAuthDeviceDenied => "oauth-device-denied",
            Event::ServiceGrantIssued => "service-grant-issued",
            Event::ServiceAccountCreated => "service-account-created",
            Event::PlatformOverride => "platform-override",
            Event::MemberAdded => "member-added",
            Event::EmailVerificationRequested => "email-verification-requested",
            Event::EmailVerified => "email-verified",
            Event::MailAbandoned => "mail-abandoned",
            Event::GithubMemberJoined => "github-member-joined",
            Event::GithubMemberRoleChanged => "github-member-role-changed",
            Event::GithubMemberRemoved => "github-member-removed",
            Event::TenantBackingChanged => "tenant-backing-changed",
            Event::DomainAutoJoined => "domain-auto-joined",
            Event::MfaEnrollmentStarted => "mfa-enrollment-started",
            Event::WorkerUninstallRequested => "worker-uninstall-requested",
            Event::WorkerUninstalled => "worker-uninstalled",
            Event::WorkerBootstrapDownloaded => "worker-bootstrap-downloaded",
            Event::WorkerEnrollmentRevoked => "worker-enrollment-revoked",
            Event::WorkerPolicyChanged => "worker-policy-changed",
            Event::WorkerNodeKeyAuthorized => "worker-node-key-authorized",
        }
    }

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
            13 => Event::TokenIssued,
            14 => Event::TokenRevoked,
            15 => Event::IdentityLinked,
            16 => Event::IdentityUnlinked,
            17 => Event::RegistrationAdmitted,
            18 => Event::RegistrationPending,
            19 => Event::RegistrationRefused,
            20 => Event::AccountApproved,
            21 => Event::AccountRejected,
            22 => Event::InvitationCreated,
            23 => Event::InvitationRedeemed,
            24 => Event::InvitationRevoked,
            25 => Event::PolicyChanged,
            26 => Event::InstallationBound,
            27 => Event::InstallationUnbound,
            28 => Event::MfaEnrolled,
            29 => Event::MfaDisabled,
            30 => Event::SteppedUp,
            31 => Event::StepUpFailed,
            32 => Event::RecoveryCodeUsed,
            33 => Event::RecoveryCodesIssued,
            34 => Event::SessionRevoked,
            35 => Event::TenantSuspended,
            36 => Event::TenantReactivated,
            37 => Event::MembershipSet,
            38 => Event::MembershipRemoved,
            39 => Event::GrantChanged,
            40 => Event::PoolCreated,
            41 => Event::PoolGranted,
            42 => Event::PoolGrantRevoked,
            43 => Event::NamespaceCreated,
            44 => Event::WorkerEnrollmentIssued,
            45 => Event::WorkerEnrollmentRefused,
            46 => Event::WorkerEnrolled,
            47 => Event::WorkerRevoked,
            48 => Event::OAuthGrantIssued,
            49 => Event::OAuthGrantRevoked,
            50 => Event::OAuthRefreshReplay,
            51 => Event::OAuthCodeReplay,
            52 => Event::OAuthConsentDenied,
            53 => Event::OAuthDeviceApproved,
            54 => Event::OAuthDeviceDenied,
            55 => Event::ServiceGrantIssued,
            56 => Event::ServiceAccountCreated,
            57 => Event::PlatformOverride,
            58 => Event::MemberAdded,
            59 => Event::EmailVerificationRequested,
            60 => Event::EmailVerified,
            61 => Event::MailAbandoned,
            70 => Event::GithubMemberJoined,
            71 => Event::GithubMemberRoleChanged,
            72 => Event::GithubMemberRemoved,
            73 => Event::TenantBackingChanged,
            74 => Event::DomainAutoJoined,
            75 => Event::MfaEnrollmentStarted,
            90 => Event::WorkerUninstallRequested,
            91 => Event::WorkerUninstalled,
            92 => Event::WorkerBootstrapDownloaded,
            93 => Event::WorkerEnrollmentRevoked,
            94 => Event::WorkerPolicyChanged,
            95 => Event::WorkerNodeKeyAuthorized,
            _ => return None,
        })
    }
}

#[derive(Debug)]
pub struct Issued {
    pub user: UserId,
    pub session: Secret,
    pub csrf: Secret,
    pub max_age_secs: u32,
}

pub enum Login {
    Accepted(Issued),
    Rejected,
    Locked { until: UnixMillis },
}

#[derive(Clone, Copy, Debug)]
pub struct Session {
    pub id: Option<SessionId>,
    pub user: UserId,
    pub super_admin: bool,
    pub csrf: Digest,
    pub idle_deadline: UnixMillis,
    pub absolute_deadline: UnixMillis,
    pub created: UnixMillis,
    pub stepped_up: Option<UnixMillis>,
}

impl Session {
    pub fn stepped_up_within(&self, policy: Policy, now: UnixMillis) -> bool {
        self.stepped_up
            .is_some_and(|at| at <= now && now.0.saturating_sub(at.0) < policy.step_up_ms)
    }

    pub fn signed_in_within(&self, policy: Policy, now: UnixMillis) -> bool {
        self.created <= now && now.0.saturating_sub(self.created.0) < policy.step_up_ms
    }

    pub fn require_step_up(&self, policy: Policy, now: UnixMillis) -> Result<()> {
        if self.stepped_up_within(policy, now) {
            Ok(())
        } else {
            Err(Error::StepUpRequired)
        }
    }

    pub fn principal(&self) -> Principal {
        let mut permissions = Permissions::REPOSITORY.union(Permissions::TENANT_ADMIN);
        if self.super_admin {
            permissions = permissions.union(Permissions::PLATFORM_ADMIN);
        }
        Principal::new(self.user, permissions, None, None)
    }
}

/// Case is rejected, never folded, so two spellings can never name one account.
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

pub(crate) fn audit(
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

const FLOOD_ROWS: i64 = 5;
const FLOOD_WINDOW_MS: i64 = 10_000;

fn audit_flood(
    tx: &Transaction<'_>,
    event: Event,
    subject: Option<UserId>,
    detail: Option<&str>,
) -> Result<()> {
    let now = UnixMillis::now().0;
    tx.prepare_cached(
        "INSERT INTO auth_audit(at_ms, event, actor_user_id, subject_user_id, host_local, detail)
         SELECT ?1, ?2, NULL, ?3, 0, ?4
         WHERE (SELECT COUNT(*) FROM auth_audit
                WHERE at_ms > ?5 AND event = ?2 AND subject_user_id IS ?3) < ?6",
    )?
    .execute(params![
        now,
        event as u8,
        subject.as_ref().map(UserId::as_bytes),
        detail.map(bounded_detail),
        now - FLOOD_WINDOW_MS,
        FLOOD_ROWS
    ])?;
    Ok(())
}

fn record_flood(
    store: &Store,
    event: Event,
    subject: Option<UserId>,
    detail: Option<String>,
) -> Result<()> {
    let room = store.read(|conn| {
        let rows: i64 = conn
            .prepare_cached(
                "SELECT COUNT(*) FROM auth_audit
                 WHERE at_ms > ?1 AND event = ?2 AND subject_user_id IS ?3",
            )?
            .query_row(
                params![
                    UnixMillis::now().0 - FLOOD_WINDOW_MS,
                    event as u8,
                    subject.as_ref().map(UserId::as_bytes)
                ],
                |r| r.get(0),
            )?;
        Ok(rows < FLOOD_ROWS)
    })?;
    if room {
        store
            .writer()
            .write(move |tx| audit_flood(tx, event, subject, detail.as_deref()))?;
    }
    Ok(())
}

pub fn bootstrap(
    store: &Store,
    login_name: &str,
    display_name: &str,
    password_bytes: &[u8],
    now: UnixMillis,
) -> Result<UserId> {
    let login_name = username(login_name)?.to_owned();
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
        tx.execute("DELETE FROM setup_token", [])?;
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

pub(crate) fn bootstrap_complete(conn: &Connection) -> Result<bool> {
    let complete: bool = conn
        .prepare_cached(
            "SELECT EXISTS(SELECT 1 FROM bootstrap)
             OR EXISTS(SELECT 1 FROM users WHERE kind = 0 AND super_admin = 1 AND active = 1)",
        )?
        .query_row([], |r| r.get(0))?;
    Ok(complete)
}

pub fn username_of(conn: &Connection, user: UserId) -> Result<Option<String>> {
    Ok(conn
        .prepare_cached("SELECT username FROM local_credentials WHERE user_id = ?1")?
        .query_row([user.as_bytes()], |r| r.get(0))
        .optional()?)
}

pub fn bootstrap_available(conn: &Connection) -> Result<bool> {
    bootstrap_complete(conn).map(|done| !done)
}

pub(crate) fn insert_credential(
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

fn candidate_by_email(conn: &Connection, email: &str) -> Result<Option<Candidate>> {
    let row = conn
        .prepare_cached(
            "SELECT c.user_id, c.phc, c.locked_until_ms FROM users u
             JOIN local_credentials c ON c.user_id = u.id
             WHERE u.email = ?1 AND u.email_verified_ms IS NOT NULL
               AND u.kind = 0 AND u.active = 1",
        )?
        .query_row([email], |r| {
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

pub fn login(
    store: &Store,
    login_name: &str,
    password_bytes: &[u8],
    policy: Policy,
    now: UnixMillis,
) -> Result<Login> {
    let (found, detail) = if login_name.contains('@') {
        let found = match crate::email::normalize(login_name) {
            Ok(email) => store.read(|conn| candidate_by_email(conn, &email))?,
            Err(_) => None,
        };
        (found, None)
    } else {
        match username(login_name) {
            Ok(name) => (
                store.read(|conn| candidate(conn, name))?,
                Some(name.to_owned()),
            ),
            Err(_) => (None, None),
        }
    };
    let Some(candidate) = found else {
        password::spend_equal_work(password_bytes);
        record_flood(store, Event::LoginRejected, None, detail)?;
        return Ok(Login::Rejected);
    };
    if candidate.locked_until > now.0 {
        password::spend_equal_work(password_bytes);
        let until = UnixMillis(candidate.locked_until);
        let user = candidate.user;
        record_flood(store, Event::LoginLocked, Some(user), None)?;
        return Ok(Login::Locked { until });
    }

    let verdict = password::verify(&candidate.phc, password_bytes);
    let upgraded = (verdict == Verdict::Accepted && password::needs_rehash(&candidate.phc))
        .then(|| password::hash(password_bytes).ok())
        .flatten();
    let user = candidate.user;
    let verified = candidate.phc;

    if verdict != Verdict::Accepted {
        store.writer().write(move |tx| {
            let locked: Option<i64> = tx
                .prepare_cached(
                    "UPDATE local_credentials SET
                     failures = CASE WHEN locked_until_ms != 0 AND locked_until_ms <= ?5
                         THEN 1 ELSE failures + 1 END,
                     locked_until_ms = CASE
                         WHEN (CASE WHEN locked_until_ms != 0 AND locked_until_ms <= ?5
                               THEN 1 ELSE failures + 1 END) >= ?3 THEN ?4
                         WHEN locked_until_ms <= ?5 THEN 0
                         ELSE locked_until_ms END
                     WHERE user_id = ?1 AND phc = ?2 RETURNING locked_until_ms",
                )?
                .query_row(
                    params![
                        user.as_bytes(),
                        verified,
                        policy.max_failures,
                        now.0.saturating_add(policy.lockout_ms),
                        now.0
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

    let issued = store.writer().write(move |tx| {
        let current: Option<(String, i64)> = tx
            .prepare_cached(
                "SELECT c.phc, c.locked_until_ms FROM local_credentials c
                 JOIN users u ON u.id = c.user_id
                 WHERE c.user_id = ?1 AND u.kind = 0 AND u.active = 1",
            )?
            .query_row([user.as_bytes()], |r| Ok((r.get(0)?, r.get(1)?)))
            .optional()?;
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
        let issued = issue_session(tx, user, policy, now)?;
        audit(
            tx,
            Event::LoginAccepted,
            Some(user),
            Some(user),
            false,
            None,
        )?;
        Ok(issued)
    });
    match issued {
        Ok(issued) => Ok(Login::Accepted(issued)),
        Err(Error::Conflict) => Ok(Login::Rejected),
        Err(error) => Err(error),
    }
}

pub fn issue_session(
    tx: &Transaction<'_>,
    user: UserId,
    policy: Policy,
    now: UnixMillis,
) -> Result<Issued> {
    let session = Secret::generate();
    let csrf = Secret::generate();
    let absolute = now.0.saturating_add(policy.absolute_ms);
    tx.execute(
        "INSERT INTO sessions(token_digest, user_id, csrf_digest, created_ms,
            idle_deadline_ms, absolute_deadline_ms, id) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            session.digest().0,
            user.as_bytes(),
            csrf.digest().0,
            now.0,
            now.0.saturating_add(policy.idle_ms).min(absolute),
            absolute,
            SessionId::new().as_bytes()
        ],
    )?;
    crate::github_members::enqueue_user(tx, user, now)?;
    crate::auto_join::apply(tx, user, now)?;
    Ok(Issued {
        user,
        session,
        csrf,
        max_age_secs: (policy.absolute_ms / 1000).clamp(0, i64::from(u32::MAX)) as u32,
    })
}

pub fn authenticate(conn: &Connection, presented: &Secret, now: UnixMillis) -> Result<Session> {
    let digest = presented.digest();
    let row = conn
        .prepare_cached(
            "SELECT s.user_id, s.csrf_digest, s.idle_deadline_ms, s.absolute_deadline_ms,
                    u.super_admin, s.id, s.stepped_up_ms, s.created_ms
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
                r.get::<_, Option<[u8; 16]>>(5)?,
                r.get::<_, Option<i64>>(6)?,
                r.get::<_, i64>(7)?,
            ))
        })
        .optional()?
        .ok_or(Error::NotFound)?;
    Ok(Session {
        id: match row.5 {
            Some(b) => Some(SessionId::from_bytes(b).map_err(|_| Error::Corrupt("session id"))?),
            None => None,
        },
        user: UserId::from_bytes(row.0).map_err(|_| Error::Corrupt("user_id"))?,
        super_admin: row.4,
        csrf: Digest(row.1),
        idle_deadline: UnixMillis(row.2),
        absolute_deadline: UnixMillis(row.3),
        created: UnixMillis(row.7),
        stepped_up: row.6.map(UnixMillis),
    })
}

pub fn refresh_due(session: &Session, policy: Policy, now: UnixMillis) -> bool {
    session.idle_deadline.0.saturating_sub(now.0) <= policy.idle_ms - policy.refresh_after_ms
        && session.idle_deadline < session.absolute_deadline
}

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

pub fn revoke_all(tx: &Transaction<'_>, user: UserId, now: UnixMillis) -> Result<usize> {
    let since: Option<i64> = tx
        .prepare_cached(
            "SELECT MIN(created_ms) FROM sessions WHERE user_id = ?1 AND revoked_ms IS NULL",
        )?
        .query_row(params![user.as_bytes()], |r| r.get(0))?;
    crate::oauth::revoke_all_minted(tx, user, since.map(UnixMillis), now)?;
    let revoked = tx.execute(
        "UPDATE sessions SET revoked_ms = ?2 WHERE user_id = ?1 AND revoked_ms IS NULL",
        params![user.as_bytes(), now.0],
    )?;
    Ok(revoked)
}

pub fn logout_all(store: &Store, session: &Session, now: UnixMillis) -> Result<usize> {
    let user = session.user;
    store.writer().write(move |tx| {
        let revoked = revoke_all(tx, user, now)?;
        audit(tx, Event::LogoutAll, Some(user), Some(user), false, None)?;
        Ok(revoked)
    })
}

pub fn change_password(
    store: &Store,
    presented: &Secret,
    session: &Session,
    policy: Policy,
    current: &[u8],
    new: &[u8],
    now: UnixMillis,
) -> Result<bool> {
    password::acceptable(new).map_err(|_| Error::InvalidInput("password"))?;
    let user = session.user;
    let (enrolled, stored) = store.read(|conn| {
        conn.prepare_cached(
            "SELECT EXISTS(SELECT 1 FROM mfa_totp
                WHERE user_id = ?1 AND confirmed_ms IS NOT NULL),
                (SELECT phc FROM local_credentials WHERE user_id = ?1)",
        )?
        .query_row([user.as_bytes()], |r| {
            Ok((r.get::<_, bool>(0)?, r.get::<_, Option<String>>(1)?))
        })
        .map_err(Error::from)
    })?;
    let Some(stored) = stored else {
        password::spend_equal_work(current);
        return Err(Error::NotFound);
    };
    if enrolled {
        session.require_step_up(policy, now)?;
    }
    if password::verify(&stored, current) != Verdict::Accepted {
        crate::mfa::refuse_password(store, presented.digest().0, user, now)?;
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
        crate::oauth::revoke_all_for_user(tx, user, crate::oauth::reason::ACCOUNT, now)?;
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
        crate::oauth::revoke_all_for_user(tx, user, crate::oauth::reason::ACCOUNT, now)?;
        crate::mfa::clear_factor_lockout(tx, user)?;
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

pub fn provision_credential(
    tx: &Transaction<'_>,
    authority: Authority,
    target: UserId,
    login_name: &str,
    phc: &str,
    now: UnixMillis,
) -> Result<()> {
    authority.require_privileged(tx)?;
    insert_credential(tx, target, username(login_name)?, phc, now)
}

pub fn set_super_admin(
    tx: &Transaction<'_>,
    authority: Authority,
    target: UserId,
    super_admin: bool,
    now: UnixMillis,
) -> Result<()> {
    authority.require_privileged(tx)?;
    let changed = tx.execute(
        "UPDATE users SET super_admin = ?2 WHERE id = ?1 AND kind = 0 AND super_admin != ?2",
        params![target.as_bytes(), super_admin],
    )?;
    if changed == 0 {
        return Err(Error::NotFound);
    }
    revoke_all(tx, target, now)?;
    let event = if super_admin {
        Event::SuperAdminGranted
    } else {
        Event::SuperAdminRevoked
    };
    audit(
        tx,
        event,
        authority.actor(),
        Some(target),
        authority.host_local(),
        None,
    )
}

pub fn set_active(
    tx: &Transaction<'_>,
    authority: Authority,
    target: UserId,
    active: bool,
    now: UnixMillis,
) -> Result<()> {
    authority.require_privileged(tx)?;
    let changed = tx.execute(
        "UPDATE users SET active = ?2 WHERE id = ?1 AND active != ?2",
        params![target.as_bytes(), active],
    )?;
    if changed == 0 {
        return Err(Error::NotFound);
    }
    if !active {
        revoke_all(tx, target, now)?;
        crate::tokens::revoke_all_for_user(tx, target, now)?;
        crate::oauth::revoke_all_for_user(tx, target, crate::oauth::reason::ACCOUNT, now)?;
    }
    let event = if active {
        Event::AccountActivated
    } else {
        Event::AccountDeactivated
    };
    audit(
        tx,
        event,
        authority.actor(),
        Some(target),
        authority.host_local(),
        None,
    )
}

#[derive(Debug, PartialEq, Eq)]
pub struct SessionRecord {
    pub id: Option<SessionId>,
    pub created: UnixMillis,
    pub idle_deadline: UnixMillis,
    pub absolute_deadline: UnixMillis,
    pub stepped_up: Option<UnixMillis>,
    pub revoked: bool,
}

fn may_administer(conn: &Connection, authority: Authority, user: UserId) -> Result<()> {
    if authority.actor() == Some(user) {
        return Ok(());
    }
    authority
        .require_platform(conn)
        .map_err(|_| Error::NotFound)
}

pub fn sessions(
    conn: &Connection,
    authority: Authority,
    user: UserId,
    limit: u16,
) -> Result<Vec<SessionRecord>> {
    if !(1..=100).contains(&limit) {
        return Err(Error::InvalidInput("page size"));
    }
    may_administer(conn, authority, user)?;
    let mut stmt = conn.prepare_cached(
        "SELECT id, created_ms, idle_deadline_ms, absolute_deadline_ms, stepped_up_ms, revoked_ms
         FROM sessions WHERE user_id = ?1 ORDER BY created_ms DESC, token_digest LIMIT ?2",
    )?;
    let rows = stmt.query_map(params![user.as_bytes(), limit], |r| {
        Ok((
            r.get::<_, Option<[u8; 16]>>(0)?,
            r.get::<_, i64>(1)?,
            r.get::<_, i64>(2)?,
            r.get::<_, i64>(3)?,
            r.get::<_, Option<i64>>(4)?,
            r.get::<_, Option<i64>>(5)?,
        ))
    })?;
    rows.map(|row| {
        let row = row?;
        Ok(SessionRecord {
            id: match row.0 {
                Some(b) => {
                    Some(SessionId::from_bytes(b).map_err(|_| Error::Corrupt("session id"))?)
                }
                None => None,
            },
            created: UnixMillis(row.1),
            idle_deadline: UnixMillis(row.2),
            absolute_deadline: UnixMillis(row.3),
            stepped_up: row.4.map(UnixMillis),
            revoked: row.5.is_some(),
        })
    })
    .collect()
}

pub fn revoke_session(
    tx: &Transaction<'_>,
    authority: Authority,
    user: UserId,
    session: SessionId,
    now: UnixMillis,
) -> Result<()> {
    may_administer(tx, authority, user)?;
    let created: i64 = tx
        .prepare_cached(
            "SELECT created_ms FROM sessions WHERE id = ?1 AND user_id = ?2 AND revoked_ms IS NULL",
        )?
        .query_row(params![session.as_bytes(), user.as_bytes()], |r| r.get(0))
        .optional()?
        .ok_or(Error::NotFound)?;
    let revoked = tx.execute(
        "UPDATE sessions SET revoked_ms = ?3 WHERE id = ?1 AND user_id = ?2 AND revoked_ms IS NULL",
        params![session.as_bytes(), user.as_bytes(), now.0],
    )?;
    if revoked == 0 {
        return Err(Error::NotFound);
    }
    audit(
        tx,
        Event::SessionRevoked,
        authority.actor(),
        Some(user),
        authority.host_local(),
        None,
    )?;
    crate::oauth::revoke_minted_for_session(tx, user, session, UnixMillis(created), now)?;
    Ok(())
}

pub fn revoke_all_host_local(store: &Store, user: UserId, now: UnixMillis) -> Result<usize> {
    store.writer().write(move |tx| {
        let revoked = revoke_all(tx, user, now)?;
        audit(tx, Event::LogoutAll, None, Some(user), true, None)?;
        Ok(revoked)
    })
}

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

pub fn recent_audit(conn: &Connection, limit: u16) -> Result<Vec<AuditRecord>> {
    audit_page(conn, None, limit)
}

pub fn audit_page(conn: &Connection, before: Option<i64>, limit: u16) -> Result<Vec<AuditRecord>> {
    if !(1..=100).contains(&limit) {
        return Err(Error::InvalidInput("page size"));
    }
    let mut stmt = conn.prepare_cached(
        "SELECT seq, at_ms, event, actor_user_id, subject_user_id, host_local, detail
         FROM auth_audit WHERE seq < ?1 ORDER BY seq DESC LIMIT ?2",
    )?;
    let rows = stmt.query_map(params![before.unwrap_or(i64::MAX), limit], |r| {
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
