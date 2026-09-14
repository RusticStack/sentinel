//! Admission (A05): who may obtain an account, who approves it, who may create
//! a namespace, and who may bind a forge installation to one.
//!
//! These are four separate decisions, and this module keeps them separate.
//! Authenticating — locally or at GitHub — is not admission. Being admitted is
//! not a tenant. Owning a tenant is not the right to bind somebody's GitHub
//! installation to it. Installing the App on GitHub is none of the above.
//!
//! A pending or rejected account is not `active`, which is the predicate every
//! authorization query in [`crate::auth`] already joins on. So a pending
//! account holds no session, no credential and no tenant data by construction,
//! rather than by each query remembering to ask.

use rusqlite::{Connection, OptionalExtension, Transaction, params};
use sentinel_auth::{password, secret::Secret};
use sentinel_core::{
    InstallationId, InvitationId, TenantId, UnixMillis, UserId,
    auth::{Namespace, Principal, Role},
};

use crate::{
    Error, Result, Store,
    local_auth::{Event, audit},
};

const DAY_MS: i64 = 24 * 60 * 60 * 1000;
/// An invitation is a standing admission right, so it expires by default in a
/// week and may never be open-ended.
pub const DEFAULT_INVITATION_MS: i64 = 7 * DAY_MS;
pub const MAX_INVITATION_MS: i64 = 30 * DAY_MS;

/// How a new account may come into existence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Registration {
    /// No new accounts, invitation or not. Existing accounts sign in normally:
    /// closing registration is not a lockout of the people already admitted.
    Closed = 0,
    /// Only with an unspent, unexpired invitation. The default.
    InviteOnly = 1,
    /// Anyone may apply; an application waits as pending until an admin acts.
    ApprovalRequired = 2,
}

/// Who may create a namespace.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum TenantCreation {
    /// Only a super admin, for organizations and personal namespaces alike.
    SuperAdminOnly = 0,
    /// An approved account may create its own personal namespace (one each,
    /// enforced by the schema). Organizations remain a platform decision.
    ApprovedUsers = 1,
}

/// Who may bind a forge installation to a tenant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum InstallationBinding {
    SuperAdminOnly = 0,
    /// A tenant admin may bind an installation to the tenant they administer.
    /// They still cannot bind one to a tenant they do not administer.
    TenantAdmins = 1,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeploymentPolicy {
    pub registration: Registration,
    pub tenant_creation: TenantCreation,
    pub installation_binding: InstallationBinding,
}

pub use crate::auth::Authority;

/// Read the deployment's admission policy. Cheap single-row read; callers that
/// need it inside a decision must read it in the same transaction as the write.
pub fn policy(conn: &Connection) -> Result<DeploymentPolicy> {
    let row = conn
        .prepare_cached(
            "SELECT registration, tenant_creation, installation_binding FROM deployment_policy",
        )?
        .query_row([], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, i64>(2)?,
            ))
        })?;
    Ok(DeploymentPolicy {
        registration: match row.0 {
            0 => Registration::Closed,
            1 => Registration::InviteOnly,
            2 => Registration::ApprovalRequired,
            _ => return Err(Error::Corrupt("deployment_policy.registration")),
        },
        tenant_creation: match row.1 {
            0 => TenantCreation::SuperAdminOnly,
            1 => TenantCreation::ApprovedUsers,
            _ => return Err(Error::Corrupt("deployment_policy.tenant_creation")),
        },
        installation_binding: match row.2 {
            0 => InstallationBinding::SuperAdminOnly,
            1 => InstallationBinding::TenantAdmins,
            _ => return Err(Error::Corrupt("deployment_policy.installation_binding")),
        },
    })
}

/// Change the deployment's admission policy. Platform administration with a
/// recent step-up, audited with the resulting values.
pub fn set_policy(
    tx: &Transaction<'_>,
    authority: Authority,
    policy: DeploymentPolicy,
    now: UnixMillis,
) -> Result<()> {
    authority.require_privileged(tx)?;
    tx.execute(
        "UPDATE deployment_policy SET registration = ?1, tenant_creation = ?2,
         installation_binding = ?3, updated_ms = ?4, updated_by = ?5 WHERE id = 1",
        params![
            policy.registration as u8,
            policy.tenant_creation as u8,
            policy.installation_binding as u8,
            now.0,
            authority.actor().as_ref().map(UserId::as_bytes)
        ],
    )?;
    let detail = format!(
        "registration={:?} tenants={:?} installations={:?}",
        policy.registration, policy.tenant_creation, policy.installation_binding
    );
    audit(
        tx,
        Event::PolicyChanged,
        authority.actor(),
        None,
        authority.host_local(),
        Some(&detail),
    )
}

/// The terms of an invitation, fixed when it is written.
#[derive(Clone, Copy, Debug)]
pub struct Terms<'a> {
    /// Join this tenant on acceptance, with `role`. Both or neither.
    pub tenant: Option<TenantId>,
    pub role: Option<Role>,
    /// Bind the invitation to one verified external identity, so only the
    /// person holding that provider account can redeem it.
    pub identity: Option<(&'a str, &'a str)>,
    pub lifetime_ms: i64,
}

impl Default for Terms<'_> {
    fn default() -> Self {
        Self {
            tenant: None,
            role: None,
            identity: None,
            lifetime_ms: DEFAULT_INVITATION_MS,
        }
    }
}

/// An invitation, presented exactly once. The link is delivered out of band;
/// there is no mandatory mail server, and no way to show the secret again.
pub struct Invitation {
    pub id: InvitationId,
    pub secret: Secret,
    pub expires: UnixMillis,
}

fn check_terms(terms: &Terms<'_>) -> Result<()> {
    if terms.tenant.is_some() != terms.role.is_some() {
        return Err(Error::InvalidInput("invitation membership"));
    }
    if let Some((provider, subject)) = terms.identity
        && (provider.is_empty() || provider.len() > 64 || subject.is_empty() || subject.len() > 255)
    {
        return Err(Error::InvalidInput("invitation identity"));
    }
    if !(1..=MAX_INVITATION_MS).contains(&terms.lifetime_ms) {
        return Err(Error::InvalidInput("invitation lifetime"));
    }
    Ok(())
}

/// Create an invitation. A platform admin may invite to any tenant or to none;
/// a tenant admin may invite only to the tenant they administer. Both are
/// checked live, in this transaction.
pub fn invite(
    tx: &Transaction<'_>,
    authority: Authority,
    terms: Terms<'_>,
    now: UnixMillis,
) -> Result<Invitation> {
    check_terms(&terms)?;
    if authority.require_platform(tx).is_err() {
        let principal = authority.principal().ok_or(Error::Forbidden)?;
        let tenant = terms.tenant.ok_or(Error::Forbidden)?;
        crate::auth::require_tenant_admin(tx, principal, tenant)?;
    }
    let id = InvitationId::new();
    let secret = Secret::generate();
    let expires = UnixMillis(now.0.saturating_add(terms.lifetime_ms));
    let (provider, subject) = match terms.identity {
        Some((provider, subject)) => (Some(provider), Some(subject)),
        None => (None, None),
    };
    tx.execute(
        "INSERT INTO invitations(token_digest, id, tenant_id, role, provider, subject,
            created_by, created_ms, expires_ms) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            secret.digest().0,
            id.as_bytes(),
            terms.tenant.as_ref().map(TenantId::as_bytes),
            terms.role.map(|role| role as u8),
            provider,
            subject,
            authority.actor().as_ref().map(UserId::as_bytes),
            now.0,
            expires.0
        ],
    )?;
    audit(
        tx,
        Event::InvitationCreated,
        authority.actor(),
        None,
        authority.host_local(),
        None,
    )?;
    Ok(Invitation {
        id,
        secret,
        expires,
    })
}

/// Revoke an unspent invitation. Platform admins, and the tenant admin of the
/// tenant it would grant membership of.
pub fn revoke_invitation(
    tx: &Transaction<'_>,
    authority: Authority,
    id: InvitationId,
    now: UnixMillis,
) -> Result<()> {
    let tenant: Option<[u8; 16]> = tx
        .prepare_cached("SELECT tenant_id FROM invitations WHERE id = ?1")?
        .query_row([id.as_bytes()], |r| r.get(0))
        .optional()?
        .ok_or(Error::NotFound)?;
    if authority.require_platform(tx).is_err() {
        let principal = authority.principal().ok_or(Error::NotFound)?;
        let tenant = tenant.ok_or(Error::NotFound)?;
        let tenant = TenantId::from_bytes(tenant).map_err(|_| Error::Corrupt("tenant_id"))?;
        crate::auth::require_tenant_admin(tx, principal, tenant).map_err(|_| Error::NotFound)?;
    }
    tx.execute(
        "UPDATE invitations SET revoked_ms = ?2 WHERE id = ?1 AND revoked_ms IS NULL",
        params![id.as_bytes(), now.0],
    )?;
    audit(
        tx,
        Event::InvitationRevoked,
        authority.actor(),
        None,
        authority.host_local(),
        None,
    )
}

/// Metadata about one invitation. Never carries the redeemable secret.
#[derive(Debug, PartialEq, Eq)]
pub struct InvitationRecord {
    pub id: InvitationId,
    pub tenant: Option<TenantId>,
    pub role: Option<Role>,
    pub identity: Option<(String, String)>,
    pub expires: UnixMillis,
    pub redeemed: bool,
    pub revoked: bool,
}

/// List invitations for one tenant, or deployment-wide ones for a platform
/// admin. Newest first, at most 100.
pub fn invitations(
    conn: &Connection,
    authority: Authority,
    tenant: Option<TenantId>,
    limit: u16,
) -> Result<Vec<InvitationRecord>> {
    if !(1..=100).contains(&limit) {
        return Err(Error::InvalidInput("page size"));
    }
    if authority.require_platform(conn).is_err() {
        let principal = authority.principal().ok_or(Error::NotFound)?;
        let tenant = tenant.ok_or(Error::NotFound)?;
        crate::auth::require_tenant_admin(conn, principal, tenant).map_err(|_| Error::NotFound)?;
    }
    let mut stmt = conn.prepare_cached(
        "SELECT id, tenant_id, role, provider, subject, expires_ms, redeemed_ms, revoked_ms
         FROM invitations WHERE (?1 IS NULL OR tenant_id = ?1)
         ORDER BY created_ms DESC, id LIMIT ?2",
    )?;
    let rows = stmt.query_map(
        params![tenant.as_ref().map(TenantId::as_bytes), limit],
        |r| {
            Ok((
                r.get::<_, [u8; 16]>(0)?,
                r.get::<_, Option<[u8; 16]>>(1)?,
                r.get::<_, Option<i64>>(2)?,
                r.get::<_, Option<String>>(3)?,
                r.get::<_, Option<String>>(4)?,
                r.get::<_, i64>(5)?,
                r.get::<_, Option<i64>>(6)?,
                r.get::<_, Option<i64>>(7)?,
            ))
        },
    )?;
    rows.map(|row| {
        let row = row?;
        Ok(InvitationRecord {
            id: InvitationId::from_bytes(row.0).map_err(|_| Error::Corrupt("invitation id"))?,
            tenant: match row.1 {
                Some(b) => Some(TenantId::from_bytes(b).map_err(|_| Error::Corrupt("tenant_id"))?),
                None => None,
            },
            role: match row.2 {
                Some(1) => Some(Role::Reader),
                Some(2) => Some(Role::Operator),
                Some(3) => Some(Role::TenantAdmin),
                Some(_) => return Err(Error::Corrupt("invitations.role")),
                None => None,
            },
            identity: row.3.zip(row.4),
            expires: UnixMillis(row.5),
            redeemed: row.6.is_some(),
            revoked: row.7.is_some(),
        })
    })
    .collect()
}

/// One unspent invitation's terms, as stored: tenant, role, and the verified
/// identity it is bound to, if any.
type Redeemable = (
    Option<[u8; 16]>,
    Option<i64>,
    Option<String>,
    Option<String>,
);

/// How someone proposes to authenticate once admitted.
pub enum Applicant<'a> {
    /// A local account: username plus a password, hashed before any write.
    Local {
        display_name: &'a str,
        username: &'a str,
        password: &'a [u8],
    },
    /// An already-verified external identity (A04 established the proof).
    External {
        display_name: &'a str,
        provider: &'a str,
        subject: &'a str,
    },
}

impl Applicant<'_> {
    fn display_name(&self) -> &str {
        match self {
            Applicant::Local { display_name, .. } | Applicant::External { display_name, .. } => {
                display_name
            }
        }
    }
}

/// Why an application produced no account. One response covers all of them at
/// the boundary; the distinction is for the operator's audit trail.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    RegistrationClosed,
    InvitationRequired,
    /// Unknown, expired, spent, revoked, or bound to a different identity.
    InvitationUnusable,
    /// That username or external identity already belongs to an account.
    AlreadyRegistered,
}

#[derive(Debug)]
pub enum Admission {
    /// The account exists and may sign in now.
    Admitted(UserId),
    /// The account exists, is not active, and holds nothing until an admin acts.
    Pending(UserId),
    Refused(Refusal),
}

/// Apply for an account.
///
/// Policy is read inside the writing transaction, so a policy change that
/// commits while an application is in flight decides it. Password hashing
/// happens before that transaction, never inside the writer.
pub fn register(
    store: &Store,
    applicant: Applicant<'_>,
    invitation: Option<&Secret>,
    now: UnixMillis,
) -> Result<Admission> {
    let display_name = applicant.display_name().to_owned();
    let (username, phc, provider, subject) = match applicant {
        Applicant::Local {
            username, password, ..
        } => {
            let username = crate::local_auth::username(username)?.to_owned();
            let phc = password::hash(password).map_err(|_| Error::InvalidInput("password"))?;
            (Some(username), Some(phc), None, None)
        }
        Applicant::External {
            provider, subject, ..
        } => (
            None,
            None,
            Some(provider.to_owned()),
            Some(subject.to_owned()),
        ),
    };
    let presented = invitation.map(Secret::digest);
    let outcome = store.writer().write(move |tx| {
        // Policy is read here, not before, so a change that commits while an
        // application is in flight is the one that decides it.
        let policy = policy(tx)?;
        if policy.registration == Registration::Closed {
            return refuse(tx, Refusal::RegistrationClosed);
        }

        // Redeem first: an invitation decides both admission and membership,
        // and spending it in this transaction means a lost race creates nothing.
        let redeemed = match presented {
            Some(digest) => {
                let row: Option<Redeemable> = tx
                    .prepare_cached(
                        "SELECT tenant_id, role, provider, subject FROM invitations
                         WHERE token_digest = ?1 AND redeemed_ms IS NULL AND revoked_ms IS NULL
                         AND expires_ms > ?2",
                    )?
                    .query_row(params![digest.0, now.0], |r| {
                        Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
                    })
                    .optional()?;
                let Some(row) = row else {
                    return refuse(tx, Refusal::InvitationUnusable);
                };
                // A bound invitation belongs to one verified identity.
                if row.2.is_some() && (row.2 != provider || row.3 != subject) {
                    return refuse(tx, Refusal::InvitationUnusable);
                }
                Some((digest, row.0, row.1))
            }
            None => {
                if policy.registration == Registration::InviteOnly {
                    return refuse(tx, Refusal::InvitationRequired);
                }
                None
            }
        };

        // Refuse a taken login before writing anything. The unique indexes are
        // still the decision under a race; that path rolls the whole attempt
        // back rather than leaving an account with no way to sign in.
        let taken: bool = match (&username, &provider, &subject) {
            (Some(username), _, _) => tx
                .prepare_cached(
                    "SELECT EXISTS(SELECT 1 FROM local_credentials WHERE username = ?1)",
                )?
                .query_row([username], |r| r.get(0))?,
            (_, Some(provider), Some(subject)) => tx
                .prepare_cached(
                    "SELECT EXISTS(SELECT 1 FROM external_identities
                     WHERE provider = ?1 AND subject = ?2)",
                )?
                .query_row(params![provider, subject], |r| r.get(0))?,
            _ => return Err(Error::InvalidInput("applicant")),
        };
        if taken {
            return refuse(tx, Refusal::AlreadyRegistered);
        }

        // An invitation is itself the approval; without one, an application
        // under `ApprovalRequired` waits.
        let approved = redeemed.is_some();
        let user = UserId::new();
        tx.execute(
            "INSERT INTO users(id, display_name, created_ms, status, active)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                user.as_bytes(),
                display_name,
                now.0,
                if approved { 1 } else { 0 },
                approved
            ],
        )?;
        let claimed = match (&username, &phc, &provider, &subject) {
            (Some(username), Some(phc), _, _) => {
                crate::local_auth::insert_credential(tx, user, username, phc, now)
            }
            (_, _, Some(provider), Some(subject)) => {
                crate::auth::provisioning::link_verified_identity(tx, user, provider, subject, now)
            }
            _ => Err(Error::InvalidInput("applicant")),
        };
        if let Err(Error::Sqlite(rusqlite::Error::SqliteFailure(code, _))) = &claimed
            && code.code == rusqlite::ErrorCode::ConstraintViolation
        {
            // Somebody claimed it between the check and this insert. Roll the
            // whole transaction back: no account, no spent invitation.
            return Err(Error::Conflict);
        }
        claimed?;

        if let Some((digest, tenant, role)) = redeemed {
            tx.execute(
                "UPDATE invitations SET redeemed_ms = ?2, redeemed_by = ?3 WHERE token_digest = ?1",
                params![digest.0, now.0, user.as_bytes()],
            )?;
            if let (Some(tenant), Some(role)) = (tenant, role) {
                tx.execute(
                    "INSERT INTO memberships(tenant_id, user_id, role) VALUES (?1, ?2, ?3)",
                    params![tenant, user.as_bytes(), role],
                )?;
            }
            audit(
                tx,
                Event::InvitationRedeemed,
                Some(user),
                Some(user),
                false,
                None,
            )?;
        }
        audit(
            tx,
            if approved {
                Event::RegistrationAdmitted
            } else {
                Event::RegistrationPending
            },
            None,
            Some(user),
            false,
            None,
        )?;
        Ok(if approved {
            Admission::Admitted(user)
        } else {
            Admission::Pending(user)
        })
    });
    match outcome {
        // The racing claim rolled its transaction back, so the refusal is
        // recorded on its own.
        Err(Error::Conflict) => store
            .writer()
            .write(move |tx| refuse(tx, Refusal::AlreadyRegistered)),
        other => other,
    }
}

/// Record why an application produced nothing. Every call site reaches this
/// before writing an account, so the audit line is the only effect.
fn refuse(tx: &Transaction<'_>, reason: Refusal) -> Result<Admission> {
    audit(
        tx,
        Event::RegistrationRefused,
        None,
        None,
        false,
        Some(&format!("{reason:?}")),
    )?;
    Ok(Admission::Refused(reason))
}

/// Approve a pending account: it becomes active and can sign in with whatever
/// credential it registered. Platform administration only, and audited.
pub fn approve(
    tx: &Transaction<'_>,
    authority: Authority,
    user: UserId,
    now: UnixMillis,
) -> Result<()> {
    let _ = now;
    authority.require_platform(tx)?;
    let changed = tx.execute(
        "UPDATE users SET status = 1, active = 1 WHERE id = ?1 AND kind = 0 AND status = 0",
        [user.as_bytes()],
    )?;
    if changed == 0 {
        return Err(Error::NotFound);
    }
    audit(
        tx,
        Event::AccountApproved,
        authority.actor(),
        Some(user),
        authority.host_local(),
        None,
    )
}

/// Reject an account. A rejected account is inactive and stays on record, so
/// its username and identity remain claimed and cannot be re-applied for.
pub fn reject(
    tx: &Transaction<'_>,
    authority: Authority,
    user: UserId,
    now: UnixMillis,
) -> Result<()> {
    authority.require_platform(tx)?;
    let changed = tx.execute(
        "UPDATE users SET active = 0, status = 2 WHERE id = ?1 AND kind = 0 AND status != 2",
        [user.as_bytes()],
    )?;
    if changed == 0 {
        return Err(Error::NotFound);
    }
    // An account that was approved before may hold live credentials.
    crate::local_auth::revoke_all(tx, user, now)?;
    crate::tokens::revoke_all_for_user(tx, user, now)?;
    audit(
        tx,
        Event::AccountRejected,
        authority.actor(),
        Some(user),
        authority.host_local(),
        None,
    )
}

#[derive(Debug, PartialEq, Eq)]
pub struct Application {
    pub user: UserId,
    pub display_name: String,
    pub applied: UnixMillis,
}

/// Pending applications, oldest first. Platform administration only.
pub fn pending(conn: &Connection, authority: Authority, limit: u16) -> Result<Vec<Application>> {
    if !(1..=100).contains(&limit) {
        return Err(Error::InvalidInput("page size"));
    }
    authority.require_platform(conn)?;
    let mut stmt = conn.prepare_cached(
        "SELECT id, display_name, created_ms FROM users
         WHERE kind = 0 AND status = 0 ORDER BY created_ms, id LIMIT ?1",
    )?;
    let rows = stmt.query_map([limit], |r| {
        Ok((
            r.get::<_, [u8; 16]>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, i64>(2)?,
        ))
    })?;
    rows.map(|row| {
        let row = row?;
        Ok(Application {
            user: UserId::from_bytes(row.0).map_err(|_| Error::Corrupt("user_id"))?,
            display_name: row.1,
            applied: UnixMillis(row.2),
        })
    })
    .collect()
}

/// Create a personal namespace for the caller, when policy allows it.
///
/// A separate decision from being admitted: under `SuperAdminOnly` an approved
/// account still cannot create one. The schema allows a person at most one, and
/// the owner's tenant-admin membership is created in the same transaction.
pub fn create_personal_namespace(
    tx: &Transaction<'_>,
    principal: Principal,
    tenant: TenantId,
    slug: Namespace<'_>,
    now: UnixMillis,
) -> Result<()> {
    let platform = crate::auth::require_platform_admin(tx, principal).is_ok();
    if !platform {
        if policy(tx)?.tenant_creation != TenantCreation::ApprovedUsers {
            return Err(Error::Forbidden);
        }
        // Scoped credentials act inside one tenant; creating another is outside
        // what they are acting under.
        if principal.tenant.is_some() || principal.repo.is_some() {
            return Err(Error::Forbidden);
        }
        let eligible: bool = tx
            .prepare_cached(
                "SELECT EXISTS(SELECT 1 FROM users
                 WHERE id = ?1 AND kind = 0 AND active = 1 AND status = 1)",
            )?
            .query_row([principal.user.as_bytes()], |r| r.get(0))?;
        if !eligible {
            return Err(Error::Forbidden);
        }
    }
    crate::auth::insert_namespace(
        tx,
        tenant,
        slug,
        crate::auth::NamespaceKind::Personal(principal.user),
        now,
    )
}

/// Record that a forge installation exists, without trusting it.
///
/// Trusted intake, called by webhook/App handling (G01–G02), not by a client. A
/// recorded installation is unbound and inactive: it grants nothing until an
/// authorized binding exists. Idempotent, because deliveries repeat.
pub fn record_installation(
    tx: &Transaction<'_>,
    provider: &str,
    external_id: &str,
    account_login: &str,
    now: UnixMillis,
) -> Result<InstallationId> {
    if provider.is_empty()
        || provider.len() > 64
        || external_id.is_empty()
        || external_id.len() > 64
    {
        return Err(Error::InvalidInput("installation identity"));
    }
    if account_login.is_empty() || account_login.len() > 128 {
        return Err(Error::InvalidInput("installation account"));
    }
    let id = InstallationId::new();
    tx.execute(
        "INSERT INTO installations(id, provider, external_id, account_login, first_seen_ms)
         VALUES (?1, ?2, ?3, ?4, ?5) ON CONFLICT(provider, external_id) DO NOTHING",
        params![id.as_bytes(), provider, external_id, account_login, now.0],
    )?;
    let stored: [u8; 16] = tx
        .prepare_cached("SELECT id FROM installations WHERE provider = ?1 AND external_id = ?2")?
        .query_row(params![provider, external_id], |r| r.get(0))?;
    InstallationId::from_bytes(stored).map_err(|_| Error::Corrupt("installation id"))
}

/// Bind an installation to a tenant: the decision that makes it usable.
///
/// Requires administration of *that* tenant (or platform administration), plus
/// the deployment's installation-binding policy. An installation already bound
/// elsewhere must be unbound first, so a repository's owner never changes
/// underneath running work.
pub fn bind_installation(
    tx: &Transaction<'_>,
    principal: Principal,
    installation: InstallationId,
    tenant: TenantId,
    now: UnixMillis,
) -> Result<()> {
    if crate::auth::require_platform_admin(tx, principal).is_err() {
        if policy(tx)?.installation_binding != InstallationBinding::TenantAdmins {
            return Err(Error::Forbidden);
        }
        crate::auth::require_tenant_admin(tx, principal, tenant)?;
    }
    let bound = tx.execute(
        "UPDATE installations SET tenant_id = ?2, bound_by = ?3, bound_ms = ?4
         WHERE id = ?1 AND tenant_id IS NULL",
        params![
            installation.as_bytes(),
            tenant.as_bytes(),
            principal.user.as_bytes(),
            now.0
        ],
    )?;
    if bound == 0 {
        // Absent, or already bound: both are "you cannot bind this".
        return Err(Error::Conflict);
    }
    audit(
        tx,
        Event::InstallationBound,
        Some(principal.user),
        None,
        false,
        None,
    )
}

/// Release a binding. Same authority as making it; the installation returns to
/// the known-but-inactive state rather than disappearing.
pub fn unbind_installation(
    tx: &Transaction<'_>,
    principal: Principal,
    installation: InstallationId,
    now: UnixMillis,
) -> Result<()> {
    let _ = now;
    let tenant: Option<[u8; 16]> = tx
        .prepare_cached("SELECT tenant_id FROM installations WHERE id = ?1")?
        .query_row([installation.as_bytes()], |r| r.get(0))
        .optional()?
        .ok_or(Error::NotFound)?;
    let tenant = tenant.ok_or(Error::NotFound)?;
    if crate::auth::require_platform_admin(tx, principal).is_err() {
        let tenant = TenantId::from_bytes(tenant).map_err(|_| Error::Corrupt("tenant_id"))?;
        crate::auth::require_tenant_admin(tx, principal, tenant).map_err(|_| Error::NotFound)?;
    }
    tx.execute(
        "UPDATE installations SET tenant_id = NULL, bound_by = NULL, bound_ms = NULL WHERE id = ?1",
        [installation.as_bytes()],
    )?;
    audit(
        tx,
        Event::InstallationUnbound,
        Some(principal.user),
        None,
        false,
        None,
    )
}

#[derive(Debug, PartialEq, Eq)]
pub struct InstallationRecord {
    pub id: InstallationId,
    pub provider: String,
    pub external_id: String,
    pub account_login: String,
    /// `None` means known but unbound: it authorizes nothing.
    pub tenant: Option<TenantId>,
}

/// The tenant an installation is bound to, if any. Trusted internal lookup for
/// intake: a webhook has no principal to authorize with, and an unbound
/// installation must resolve to nothing rather than to a guess.
pub fn installation_tenant(
    conn: &Connection,
    provider: &str,
    external_id: &str,
) -> Result<Option<TenantId>> {
    let bytes: Option<[u8; 16]> = conn
        .prepare_cached(
            "SELECT tenant_id FROM installations
             WHERE provider = ?1 AND external_id = ?2 AND suspended = 0",
        )?
        .query_row(params![provider, external_id], |r| r.get(0))
        .optional()?
        .ok_or(Error::NotFound)?;
    match bytes {
        Some(bytes) => Ok(Some(
            TenantId::from_bytes(bytes).map_err(|_| Error::Corrupt("tenant_id"))?,
        )),
        None => Ok(None),
    }
}

/// Installations visible to a platform admin: bound and unbound alike, because
/// the unbound ones are exactly what an operator needs to see.
pub fn installations(
    conn: &Connection,
    principal: Principal,
    limit: u16,
) -> Result<Vec<InstallationRecord>> {
    if !(1..=100).contains(&limit) {
        return Err(Error::InvalidInput("page size"));
    }
    crate::auth::require_platform_admin(conn, principal)?;
    let mut stmt = conn.prepare_cached(
        "SELECT id, provider, external_id, account_login, tenant_id FROM installations
         ORDER BY first_seen_ms, id LIMIT ?1",
    )?;
    let rows = stmt.query_map([limit], |r| {
        Ok((
            r.get::<_, [u8; 16]>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, String>(3)?,
            r.get::<_, Option<[u8; 16]>>(4)?,
        ))
    })?;
    rows.map(|row| {
        let row = row?;
        Ok(InstallationRecord {
            id: InstallationId::from_bytes(row.0).map_err(|_| Error::Corrupt("installation id"))?,
            provider: row.1,
            external_id: row.2,
            account_login: row.3,
            tenant: match row.4 {
                Some(b) => Some(TenantId::from_bytes(b).map_err(|_| Error::Corrupt("tenant_id"))?),
                None => None,
            },
        })
    })
    .collect()
}

/// Delete invitations that can no longer be redeemed, in bounded batches.
pub fn purge_expired_invitations(store: &Store, now: UnixMillis, limit: u32) -> Result<usize> {
    store.writer().write(move |tx| {
        let removed = tx.execute(
            "DELETE FROM invitations WHERE token_digest IN
             (SELECT token_digest FROM invitations
              WHERE expires_ms <= ?1 OR redeemed_ms IS NOT NULL OR revoked_ms IS NOT NULL
              LIMIT ?2)",
            params![now.0, limit],
        )?;
        Ok(removed)
    })
}
