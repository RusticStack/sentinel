//! Pending and rejected accounts are not `active`, the predicate every authorization query joins on, so they hold no session or tenant data.

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
pub const DEFAULT_INVITATION_MS: i64 = 7 * DAY_MS;
pub const MAX_INVITATION_MS: i64 = 30 * DAY_MS;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Registration {
    Closed = 0,
    InviteOnly = 1,
    ApprovalRequired = 2,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum TenantCreation {
    SuperAdminOnly = 0,
    ApprovedUsers = 1,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum InstallationBinding {
    SuperAdminOnly = 0,
    TenantAdmins = 1,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeploymentPolicy {
    pub registration: Registration,
    pub tenant_creation: TenantCreation,
    pub installation_binding: InstallationBinding,
}

pub use crate::auth::Authority;

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

#[derive(Clone, Copy, Debug)]
pub struct Terms<'a> {
    pub tenant: Option<TenantId>,
    pub role: Option<Role>,
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

pub fn invite(
    tx: &Transaction<'_>,
    authority: Authority,
    terms: Terms<'_>,
    now: UnixMillis,
) -> Result<Invitation> {
    invite_to(tx, authority, terms, None, now)
}

const EMAIL_INVITES_PER_HOUR: i64 = 50;

pub fn invite_by_email(
    tx: &Transaction<'_>,
    authority: Authority,
    terms: Terms<'_>,
    email: &str,
    key: Option<&sentinel_auth::sealed::Key>,
    now: UnixMillis,
) -> Result<Invited> {
    let email = crate::email::normalize(email)?;
    let invitation = invite_to(tx, authority, terms, Some(&email), now)?;
    let (Some(key), Some(url), Some(tenant)) = (key, crate::email::delivery_url(tx)?, terms.tenant)
    else {
        return Ok(Invited {
            invitation,
            queued: false,
        });
    };
    let slug: String = tx
        .prepare_cached("SELECT slug FROM tenants WHERE id = ?1")?
        .query_row([tenant.as_bytes()], |r| r.get(0))?;
    let (subject, body) = crate::email::invitation_message(&url, &invitation.secret, &slug);
    let queued = crate::email::enqueue(
        tx,
        key,
        &crate::email::Outgoing {
            kind: crate::email::Kind::Invitation,
            recipient: &email,
            subject: &subject,
            body: &body,
            ttl_ms: terms.lifetime_ms,
        },
        now,
    )?;
    Ok(Invited { invitation, queued })
}

pub struct Invited {
    pub invitation: Invitation,
    pub queued: bool,
}

fn invite_to(
    tx: &Transaction<'_>,
    authority: Authority,
    terms: Terms<'_>,
    email: Option<&str>,
    now: UnixMillis,
) -> Result<Invitation> {
    check_terms(&terms)?;
    if authority.require_platform(tx).is_err() {
        let principal = authority.principal().ok_or(Error::Forbidden)?;
        let tenant = terms.tenant.ok_or(Error::Forbidden)?;
        crate::auth::require_tenant_admin(tx, principal, tenant)?;
    }
    if email.is_some() {
        let tenant = terms
            .tenant
            .ok_or(Error::InvalidInput("invitation organization"))?;
        if terms.identity.is_some() {
            return Err(Error::InvalidInput("invitation identity"));
        }
        if tenant_is_github_backed(tx, tenant)? {
            return Err(Error::InvalidInput("organization backed by GitHub"));
        }
        let recent: i64 = tx
            .prepare_cached(
                "SELECT COUNT(*) FROM invitations
                 WHERE tenant_id = ?1 AND email IS NOT NULL AND created_ms > ?2",
            )?
            .query_row(params![tenant.as_bytes(), now.0 - 60 * 60 * 1000], |r| {
                r.get(0)
            })?;
        if recent >= EMAIL_INVITES_PER_HOUR {
            return Err(Error::Overloaded);
        }
    }
    if let Some(tenant) = terms.tenant {
        crate::github_members::require_app_managed(tx, tenant, None)?;
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
            created_by, created_ms, expires_ms, email)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            secret.digest().0,
            id.as_bytes(),
            terms.tenant.as_ref().map(TenantId::as_bytes),
            terms.role.map(|role| role as u8),
            provider,
            subject,
            authority.actor().as_ref().map(UserId::as_bytes),
            now.0,
            expires.0,
            email
        ],
    )?;
    audit(
        tx,
        Event::InvitationCreated,
        authority.actor(),
        None,
        authority.host_local(),
        email.map(|_| "email"),
    )?;
    Ok(Invitation {
        id,
        secret,
        expires,
    })
}

pub fn tenant_slug(conn: &Connection, tenant: TenantId) -> Result<Option<String>> {
    Ok(conn
        .prepare_cached("SELECT slug FROM tenants WHERE id = ?1")?
        .query_row([tenant.as_bytes()], |r| r.get(0))
        .optional()?)
}

pub fn revoke_tenant_invitation(
    tx: &Transaction<'_>,
    authority: Authority,
    tenant: TenantId,
    id: InvitationId,
    now: UnixMillis,
) -> Result<()> {
    let owner: Option<Option<[u8; 16]>> = tx
        .prepare_cached("SELECT tenant_id FROM invitations WHERE id = ?1")?
        .query_row([id.as_bytes()], |r| r.get(0))
        .optional()?;
    if owner.flatten().as_ref() != Some(tenant.as_bytes()) {
        return Err(Error::NotFound);
    }
    revoke_invitation(tx, authority, id, now)
}

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

#[derive(Debug, PartialEq, Eq)]
pub struct InvitationRecord {
    pub id: InvitationId,
    pub tenant: Option<TenantId>,
    pub role: Option<Role>,
    pub identity: Option<(String, String)>,
    pub expires: UnixMillis,
    pub redeemed: bool,
    pub revoked: bool,
    pub email: Option<String>,
}

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
        "SELECT id, tenant_id, role, provider, subject, expires_ms, redeemed_ms, revoked_ms, email
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
                r.get::<_, Option<String>>(8)?,
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
            role: decode_role(row.2)?,
            identity: row.3.zip(row.4),
            expires: UnixMillis(row.5),
            redeemed: row.6.is_some(),
            revoked: row.7.is_some(),
            email: row.8,
        })
    })
    .collect()
}

pub(crate) struct Usable {
    pub id: InvitationId,
    pub tenant: Option<TenantId>,
    pub role: Option<Role>,
    pub identity: Option<(String, String)>,
    pub email: Option<String>,
    /// Issued by the host-local CLI, so no tenant administrator stands behind it.
    pub host_local: bool,
}

pub(crate) enum Select {
    Digest([u8; 32]),
    Id(InvitationId),
}

macro_rules! usable_sql {
    ($selector:literal) => {
        concat!(
            "SELECT i.id, i.tenant_id, i.role, i.provider, i.subject, i.email, i.created_by IS NULL
             FROM invitations i
             LEFT JOIN users c ON c.id = i.created_by
             LEFT JOIN memberships cm
               ON cm.tenant_id = i.tenant_id AND cm.user_id = i.created_by
             WHERE ",
            $selector,
            " AND i.redeemed_ms IS NULL
             AND i.revoked_ms IS NULL AND i.expires_ms > ?2
             AND NOT EXISTS(SELECT 1 FROM tenants gt
                  WHERE gt.id = i.tenant_id AND gt.membership_source = 1)
             AND (i.created_by IS NULL OR
                  (c.active = 1 AND (c.super_admin = 1 OR cm.role = 3)))"
        )
    };
}

fn decode_role(code: Option<i64>) -> Result<Option<Role>> {
    Ok(match code {
        Some(1) => Some(Role::Reader),
        Some(2) => Some(Role::Operator),
        Some(3) => Some(Role::TenantAdmin),
        Some(_) => return Err(Error::Corrupt("invitations.role")),
        None => None,
    })
}

/// Usable only while the creator still holds the authority it delegated, so demoting or removing a creator voids their unspent invitations.
pub(crate) fn usable_invitation(
    conn: &Connection,
    by: Select,
    now: UnixMillis,
) -> Result<Option<Usable>> {
    #[allow(clippy::type_complexity)]
    let row: Option<(
        [u8; 16],
        Option<[u8; 16]>,
        Option<i64>,
        Option<String>,
        Option<String>,
        Option<String>,
        bool,
    )> = {
        let map = |r: &rusqlite::Row<'_>| {
            Ok((
                r.get(0)?,
                r.get(1)?,
                r.get(2)?,
                r.get(3)?,
                r.get(4)?,
                r.get(5)?,
                r.get(6)?,
            ))
        };
        match by {
            Select::Digest(digest) => conn
                .prepare_cached(usable_sql!("i.token_digest = ?1"))?
                .query_row(params![digest, now.0], map)
                .optional()?,
            Select::Id(id) => conn
                .prepare_cached(usable_sql!("i.id = ?1"))?
                .query_row(params![id.as_bytes(), now.0], map)
                .optional()?,
        }
    };
    let Some((id, tenant, role, provider, subject, email, host_local)) = row else {
        return Ok(None);
    };
    Ok(Some(Usable {
        id: InvitationId::from_bytes(id).map_err(|_| Error::Corrupt("invitation id"))?,
        tenant: tenant
            .map(|b| TenantId::from_bytes(b).map_err(|_| Error::Corrupt("tenant_id")))
            .transpose()?,
        role: decode_role(role)?,
        identity: provider.zip(subject),
        email,
        host_local,
    }))
}

pub fn tenant_is_github_backed(conn: &Connection, tenant: TenantId) -> Result<bool> {
    Ok(conn
        .prepare_cached(
            "SELECT EXISTS(SELECT 1 FROM installations WHERE tenant_id = ?1 AND provider = 'github')",
        )?
        .query_row([tenant.as_bytes()], |r| r.get(0))?)
}

fn tenant_is_open(conn: &Connection, tenant: TenantId) -> Result<bool> {
    let active: bool = conn
        .prepare_cached("SELECT EXISTS(SELECT 1 FROM tenants WHERE id = ?1 AND active = 1)")?
        .query_row([tenant.as_bytes()], |r| r.get(0))?;
    Ok(active && !tenant_is_github_backed(conn, tenant)?)
}

/// A platform administrator has no ambient tenant access, and joining one needs step-up and an audited
/// reason ([`crate::auth::Authority::require_tenant_access_change`]). A host-local invitation carries
/// neither, so it must not be a way around that: it stays unspent for the person it was meant for.
fn barred_platform_admin(conn: &Connection, invitation: &Usable, user: UserId) -> Result<bool> {
    if invitation.tenant.is_none() || !invitation.host_local {
        return Ok(false);
    }
    Ok(conn
        .prepare_cached(
            "SELECT EXISTS(SELECT 1 FROM users WHERE id = ?1 AND kind = 0 AND super_admin = 1)",
        )?
        .query_row([user.as_bytes()], |r| r.get(0))?)
}

pub(crate) fn redeem(
    tx: &Transaction<'_>,
    invitation: &Usable,
    user: UserId,
    now: UnixMillis,
) -> Result<Option<TenantId>> {
    if barred_platform_admin(tx, invitation, user)? {
        return Ok(None);
    }
    let spent = tx.execute(
        "UPDATE invitations SET redeemed_ms = ?2, redeemed_by = ?3
         WHERE id = ?1 AND redeemed_ms IS NULL AND revoked_ms IS NULL",
        params![invitation.id.as_bytes(), now.0, user.as_bytes()],
    )?;
    if spent != 1 {
        return Ok(None);
    }
    let joined = match (invitation.tenant, invitation.role) {
        (Some(tenant), Some(role)) => {
            tx.execute(
                "INSERT INTO memberships(tenant_id, user_id, role) VALUES (?1, ?2, ?3)
                 ON CONFLICT(tenant_id, user_id) DO NOTHING",
                params![tenant.as_bytes(), user.as_bytes(), role as u8],
            )?;
            Some(tenant)
        }
        _ => None,
    };
    audit(
        tx,
        Event::InvitationRedeemed,
        Some(user),
        Some(user),
        false,
        None,
    )?;
    Ok(joined)
}

pub(crate) fn redeem_verified(
    tx: &Transaction<'_>,
    id: InvitationId,
    user: UserId,
    email: &str,
    now: UnixMillis,
) -> Result<Option<TenantId>> {
    let Some(invitation) = usable_invitation(tx, Select::Id(id), now)? else {
        return Ok(None);
    };
    if invitation.email.as_deref() != Some(email) {
        return Ok(None);
    }
    if let Some(tenant) = invitation.tenant
        && !tenant_is_open(tx, tenant)?
    {
        return Ok(None);
    }
    let joined = redeem(tx, &invitation, user, now)?;
    if joined.is_some() {
        let admitted = tx.execute(
            "UPDATE users SET status = 1, active = 1 WHERE id = ?1 AND kind = 0 AND status = 0",
            [user.as_bytes()],
        )?;
        if admitted == 1 {
            audit(
                tx,
                Event::RegistrationAdmitted,
                None,
                Some(user),
                false,
                None,
            )?;
        }
    }
    Ok(joined)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Accepted {
    Joined(TenantId),
    Redeemed,
    AlreadyMember,
    VerificationSent,
    Unusable,
}

pub fn accept_invitation(
    store: &Store,
    user: UserId,
    secret: &Secret,
    key: Option<std::sync::Arc<sentinel_auth::sealed::Key>>,
    now: UnixMillis,
) -> Result<Accepted> {
    let digest = secret.digest();
    store.writer().write(move |tx| {
        let Some(invitation) = usable_invitation(tx, Select::Digest(digest.0), now)? else {
            return Ok(Accepted::Unusable);
        };
        let active: bool = tx
            .prepare_cached(
                "SELECT EXISTS(SELECT 1 FROM users WHERE id = ?1 AND kind = 0 AND active = 1)",
            )?
            .query_row([user.as_bytes()], |r| r.get(0))?;
        if !active || barred_platform_admin(tx, &invitation, user)? {
            return Ok(Accepted::Unusable);
        }
        if let Some((provider, subject)) = &invitation.identity {
            let linked: bool = tx
                .prepare_cached(
                    "SELECT EXISTS(SELECT 1 FROM external_identities
                     WHERE provider = ?1 AND subject = ?2 AND user_id = ?3)",
                )?
                .query_row(params![provider, subject, user.as_bytes()], |r| r.get(0))?;
            if !linked {
                return Ok(Accepted::Unusable);
            }
        }
        if let Some(tenant) = invitation.tenant {
            let member: bool = tx
                .prepare_cached(
                    "SELECT EXISTS(SELECT 1 FROM memberships WHERE tenant_id = ?1 AND user_id = ?2)",
                )?
                .query_row(params![tenant.as_bytes(), user.as_bytes()], |r| r.get(0))?;
            if member {
                return Ok(Accepted::AlreadyMember);
            }
            if invitation.email.is_some() && !tenant_is_open(tx, tenant)? {
                return Ok(Accepted::Unusable);
            }
        }
        let Some(address) = invitation.email.as_deref() else {
            return Ok(match redeem(tx, &invitation, user, now)? {
                Some(tenant) => Accepted::Joined(tenant),
                None => Accepted::Redeemed,
            });
        };
        let held: Option<(Option<String>, bool)> = tx
            .prepare_cached("SELECT email, email_verified_ms IS NOT NULL FROM users WHERE id = ?1")?
            .query_row([user.as_bytes()], |r| Ok((r.get(0)?, r.get(1)?)))
            .optional()?;
        match held {
            Some((Some(email), true)) if email == address => {
                Ok(match redeem(tx, &invitation, user, now)? {
                    Some(tenant) => Accepted::Joined(tenant),
                    None => Accepted::Redeemed,
                })
            }
            Some((Some(_), true)) => Ok(Accepted::Unusable),
            Some(_) => {
                // Every outcome answers alike, so the response reveals nothing about another account's address.
                crate::email::request(tx, key.as_deref(), user, address, Some(invitation.id), now)?;
                Ok(Accepted::VerificationSent)
            }
            None => Ok(Accepted::Unusable),
        }
    })
}

pub enum Applicant<'a> {
    Local {
        display_name: &'a str,
        username: &'a str,
        password: &'a [u8],
    },
    Email {
        display_name: &'a str,
        email: &'a str,
        password: &'a [u8],
    },
    External {
        display_name: &'a str,
        provider: &'a str,
        subject: &'a str,
    },
}

impl Applicant<'_> {
    fn display_name(&self) -> &str {
        match self {
            Applicant::Local { display_name, .. }
            | Applicant::Email { display_name, .. }
            | Applicant::External { display_name, .. } => display_name,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    RegistrationClosed,
    InvitationRequired,
    InvitationUnusable,
    AlreadyRegistered,
}

#[derive(Debug)]
pub enum Admission {
    Admitted(UserId),
    Pending(UserId),
    Refused(Refusal),
}

pub fn register(
    store: &Store,
    applicant: Applicant<'_>,
    invitation: Option<&Secret>,
    now: UnixMillis,
) -> Result<Admission> {
    register_with(store, applicant, invitation, None, now)
}

pub(crate) fn generated_username(user: UserId) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut name = String::with_capacity(17);
    name.push_str("user-");
    for byte in &user.as_bytes()[..6] {
        name.push(HEX[usize::from(byte >> 4)] as char);
        name.push(HEX[usize::from(byte & 15)] as char);
    }
    name
}

pub fn register_with(
    store: &Store,
    applicant: Applicant<'_>,
    invitation: Option<&Secret>,
    key: Option<std::sync::Arc<sentinel_auth::sealed::Key>>,
    now: UnixMillis,
) -> Result<Admission> {
    let display_name = applicant.display_name().to_owned();
    let (username, phc, provider, subject, email) = match applicant {
        Applicant::Local {
            username, password, ..
        } => {
            let username = crate::local_auth::username(username)?.to_owned();
            let phc = password::hash(password).map_err(|_| Error::InvalidInput("password"))?;
            (Some(username), Some(phc), None, None, None)
        }
        Applicant::Email {
            email, password, ..
        } => {
            let email = crate::email::normalize(email)?;
            let phc = password::hash(password).map_err(|_| Error::InvalidInput("password"))?;
            (None, Some(phc), None, None, Some(email))
        }
        Applicant::External {
            provider, subject, ..
        } => (
            None,
            None,
            Some(provider.to_owned()),
            Some(subject.to_owned()),
            None,
        ),
    };
    let presented = invitation.map(Secret::digest);
    let outcome = store.writer().write(move |tx| {
        // Read inside the writer so a policy change committed in flight decides this application.
        let policy = policy(tx)?;
        if policy.registration == Registration::Closed {
            return refuse(tx, Refusal::RegistrationClosed);
        }

        let (redeemed, deferred) = match presented {
            Some(digest) => {
                let Some(found) = usable_invitation(tx, Select::Digest(digest.0), now)? else {
                    return refuse(tx, Refusal::InvitationUnusable);
                };
                if let Some((bound_provider, bound_subject)) = &found.identity
                    && (provider.as_ref() != Some(bound_provider)
                        || subject.as_ref() != Some(bound_subject))
                {
                    return refuse(tx, Refusal::InvitationUnusable);
                }
                enum Addressed {
                    No,
                    ToApplicant,
                    ToSomeoneElse,
                }
                let addressed = match (found.email.as_deref(), email.as_deref()) {
                    (None, _) => Addressed::No,
                    (Some(to), Some(applied)) if to == applied => Addressed::ToApplicant,
                    _ => Addressed::ToSomeoneElse,
                };
                match addressed {
                    Addressed::No => (Some(found), None),
                    Addressed::ToApplicant => {
                        if let Some(tenant) = found.tenant
                            && !tenant_is_open(tx, tenant)?
                        {
                            return refuse(tx, Refusal::InvitationUnusable);
                        }
                        (None, Some(found.id))
                    }
                    Addressed::ToSomeoneElse => {
                        return refuse(tx, Refusal::InvitationUnusable);
                    }
                }
            }
            None => {
                if policy.registration == Registration::InviteOnly {
                    return refuse(tx, Refusal::InvitationRequired);
                }
                (None, None)
            }
        };

        let taken: bool = match (&username, &provider, &subject, &email) {
            (Some(username), _, _, _) => tx
                .prepare_cached(
                    "SELECT EXISTS(SELECT 1 FROM local_credentials WHERE username = ?1)",
                )?
                .query_row([username], |r| r.get(0))?,
            (_, Some(provider), Some(subject), _) => tx
                .prepare_cached(
                    "SELECT EXISTS(SELECT 1 FROM external_identities
                     WHERE provider = ?1 AND subject = ?2)",
                )?
                .query_row(params![provider, subject], |r| r.get(0))?,
            (_, _, _, Some(email)) => tx
                .prepare_cached(
                    "SELECT EXISTS(SELECT 1 FROM users
                     WHERE email = ?1 AND email_verified_ms IS NOT NULL)",
                )?
                .query_row([email], |r| r.get(0))?,
            _ => return Err(Error::InvalidInput("applicant")),
        };
        if taken {
            return refuse(tx, Refusal::AlreadyRegistered);
        }

        let approved = redeemed.is_some();
        let user = UserId::new();
        tx.execute(
            "INSERT INTO users(id, display_name, created_ms, status, active, email)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                user.as_bytes(),
                display_name,
                now.0,
                if approved { 1 } else { 0 },
                approved,
                email
            ],
        )?;
        let claimed = match (&username, &phc, &provider, &subject, &email) {
            (Some(username), Some(phc), _, _, _) => {
                crate::local_auth::insert_credential(tx, user, username, phc, now)
            }
            (_, Some(phc), _, _, Some(_)) => {
                crate::local_auth::insert_credential(tx, user, &generated_username(user), phc, now)
            }
            (_, _, Some(provider), Some(subject), _) => {
                crate::auth::provisioning::link_verified_identity(tx, user, provider, subject, now)
            }
            _ => Err(Error::InvalidInput("applicant")),
        };
        if let Err(Error::Sqlite(rusqlite::Error::SqliteFailure(code, _))) = &claimed
            && code.code == rusqlite::ErrorCode::ConstraintViolation
        {
            return Err(Error::Conflict);
        }
        claimed?;

        if let Some(found) = &redeemed {
            redeem(tx, found, user, now)?;
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
        if let Some(address) = &email {
            crate::email::request(tx, key.as_deref(), user, address, deferred, now)?;
        }
        Ok(if approved {
            Admission::Admitted(user)
        } else {
            Admission::Pending(user)
        })
    });
    match outcome {
        Err(Error::Conflict) => store
            .writer()
            .write(move |tx| refuse(tx, Refusal::AlreadyRegistered)),
        other => other,
    }
}

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

/// Rejecting an approved account is irreversible, so it needs the same step-up as deactivation.
pub fn reject(
    tx: &Transaction<'_>,
    authority: Authority,
    user: UserId,
    now: UnixMillis,
) -> Result<()> {
    authority.require_platform(tx)?;
    let status: Option<i64> = tx
        .prepare_cached("SELECT status FROM users WHERE id = ?1 AND kind = 0 AND status != 2")?
        .query_row([user.as_bytes()], |r| r.get(0))
        .optional()?;
    match status {
        None => return Err(Error::NotFound),
        Some(0) => {}
        Some(_) => authority.require_privileged(tx)?,
    }
    let changed = tx.execute(
        "UPDATE users SET active = 0, status = 2 WHERE id = ?1 AND kind = 0 AND status != 2",
        [user.as_bytes()],
    )?;
    if changed == 0 {
        return Err(Error::NotFound);
    }
    crate::local_auth::revoke_all(tx, user, now)?;
    crate::tokens::revoke_all_for_user(tx, user, now)?;
    crate::oauth::revoke_all_for_user(tx, user, crate::oauth::reason::ACCOUNT, now)?;
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
    crate::github_members::installation_released(
        tx,
        TenantId::from_bytes(tenant).map_err(|_| Error::Corrupt("tenant_id"))?,
        Some(principal.user),
        now,
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
    pub tenant: Option<TenantId>,
}

pub fn bind_installation_trusted(
    tx: &Transaction<'_>,
    installation: InstallationId,
    tenant: TenantId,
    now: UnixMillis,
) -> Result<()> {
    let known: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM installations i JOIN tenants t ON t.id = ?2 AND t.active = 1 WHERE i.id = ?1)",
        params![installation.as_bytes(), tenant.as_bytes()],
        |r| r.get(0),
    )?;
    if !known {
        return Err(Error::NotFound);
    }
    let bound = tx.execute(
        "UPDATE installations SET tenant_id = ?2, bound_by = NULL, bound_ms = ?3
         WHERE id = ?1 AND tenant_id IS NULL",
        params![installation.as_bytes(), tenant.as_bytes(), now.0],
    )?;
    if bound == 0 {
        return Err(Error::Conflict);
    }
    audit(tx, Event::InstallationBound, None, None, true, None)
}

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
