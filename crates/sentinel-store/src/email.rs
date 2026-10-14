//! Verified email identity and the durable mail outbox.
//!
//! An account may hold one email address. Holding is not proving: the address
//! is a claim until a single-use, expiring token delivered to that mailbox is
//! presented, and only a *verified* address is a login identifier, matches an
//! email-bound invitation, or excludes another account from verifying the same
//! address (first to verify wins; see migration 50). Changing the address never
//! carries the old verification over: the old one stays until the new one is
//! proved.
//!
//! Tokens are stored as digests, like every other secret. A message that has to
//! carry a link is a different matter: the link exists in readable form from the
//! moment it is minted until the mail lane has handed it to Resend. That
//! window is the outbox row, whose body is sealed with the deployment master
//! key and deleted as soon as the row settles. Without a Resend key (or without
//! a master key) nothing is queued and the link is minted on demand by the
//! host-local CLI, so a self-hosted operator is never locked out.
//!
//! Nothing here sends mail, and no request handler waits on the network: the
//! transaction that mints a token also writes the outbox row, and
//! `sentinel-mail`'s lane drains it.

use rusqlite::{Connection, OptionalExtension, Transaction, params};
use sentinel_auth::{
    sealed::Key,
    secret::{Secret, wipe_string},
    token,
};
use sentinel_core::{InvitationId, MailId, TenantId, UnixMillis, UserId};

use crate::{
    Error, Result, Store,
    local_auth::{Event, audit},
    registration::{self, Authority},
};

const HOUR_MS: i64 = 60 * 60 * 1000;
const DAY_MS: i64 = 24 * HOUR_MS;

/// How long a verification link works.
pub const VERIFICATION_TTL_MS: i64 = DAY_MS;
/// Links one account may be sent per [`RESEND_WINDOW_MS`]; the resend after
/// them is throttled whoever asks.
pub const RESENDS_PER_WINDOW: i64 = 5;
pub const RESEND_WINDOW_MS: i64 = HOUR_MS;
/// Messages one recipient may be queued per window, across every account and
/// every invitation: the ceiling on using this deployment to bury a mailbox.
pub const RECIPIENT_PER_WINDOW: i64 = 5;
/// Undelivered messages the outbox holds at once. Past it nothing more is
/// queued (the request still succeeds; the operator's CLI mints a link).
pub const MAX_PENDING: i64 = 2_000;
/// Delivery attempts before a message is given up on.
pub const MAX_ATTEMPTS: u32 = 8;
/// How long a settled outbox row and an expired token are kept.
pub const RETAIN_MS: i64 = 7 * DAY_MS;
/// The longest an address may be: RFC 5321's path limit.
pub const MAX_EMAIL_BYTES: usize = 254;
/// The longest local part (RFC 5321).
const MAX_LOCAL_BYTES: usize = 64;

/// The kinds of message the outbox carries. The numbers are stored.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Kind {
    Verification = 1,
    Invitation = 2,
}

impl Kind {
    pub const fn name(self) -> &'static str {
        match self {
            Kind::Verification => "verification",
            Kind::Invitation => "invitation",
        }
    }

    const fn from_code(code: i64) -> Option<Kind> {
        match code {
            1 => Some(Kind::Verification),
            2 => Some(Kind::Invitation),
            _ => None,
        }
    }
}

/// Characters RFC 5322 allows unquoted in a local part, besides the dot.
const fn atext(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(
            b,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'/'
                | b'='
                | b'?'
                | b'^'
                | b'_'
                | b'`'
                | b'{'
                | b'|'
                | b'}'
                | b'~'
        )
}

/// The canonical form of a mail domain: IDN labels in punycode (UTS 46 with
/// the STD3 rules), lower case, a registrable shape (two or more labels, none
/// empty or over 63 bytes, no label hyphen at an edge, a last label that is
/// not all digits so an IP literal is never a domain). The one place a domain
/// is compared: addresses and the operator's `SENTINEL_AUTO_JOIN_DOMAINS` both
/// go through it, so `Example.COM`, `example.com` and `EXAMPLE.com` are one
/// domain and `mail.example.com` is another.
pub fn normalize_domain(input: &str) -> Result<String> {
    let bad = || Error::InvalidInput("email domain");
    let text = input.trim();
    if text.is_empty()
        || text.len() > 512
        || text.starts_with('.')
        || text.ends_with('.')
        || text
            .chars()
            .any(|c| c.is_control() || c.is_whitespace() || c == '@')
    {
        return Err(bad());
    }
    let ascii = idna::domain_to_ascii_strict(text).map_err(|_| bad())?;
    let valid = ascii.len() <= 253
        && ascii.contains('.')
        && ascii.split('.').all(|label| {
            (1..=63).contains(&label.len())
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
        && !ascii
            .rsplit('.')
            .next()
            .is_some_and(|tld| tld.bytes().all(|b| b.is_ascii_digit()));
    if valid { Ok(ascii) } else { Err(bad()) }
}

/// The canonical form of an address: `local@domain` with the local part lower
/// cased (mail systems treat it case-insensitively, and so does this) and the
/// domain per [`normalize_domain`]. The local part is ASCII: an address that
/// needs an internationalized one is refused rather than mangled. At most
/// [`MAX_EMAIL_BYTES`]. Diagnostics never echo the input.
pub fn normalize(input: &str) -> Result<String> {
    let bad = || Error::InvalidInput("email address");
    let text = input.trim_matches([' ', '\t']);
    if text.is_empty() || text.len() > 512 {
        return Err(bad());
    }
    let (local, domain) = text.rsplit_once('@').ok_or_else(bad)?;
    let acceptable = (1..=MAX_LOCAL_BYTES).contains(&local.len())
        && !local.starts_with('.')
        && !local.ends_with('.')
        && !local.contains("..")
        && local.bytes().all(|b| b == b'.' || atext(b));
    if !acceptable {
        return Err(bad());
    }
    let domain = normalize_domain(domain).map_err(|_| bad())?;
    if local.len() + 1 + domain.len() > MAX_EMAIL_BYTES {
        return Err(bad());
    }
    let mut out = String::with_capacity(local.len() + 1 + domain.len());
    out.push_str(&local.to_ascii_lowercase());
    out.push('@');
    out.push_str(&domain);
    Ok(out)
}

/// The local part of an address already in canonical form.
pub fn local_part_of(normalized: &str) -> &str {
    normalized
        .rsplit_once('@')
        .map_or(normalized, |(local, _)| local)
}

/// The domain of an address already in canonical form.
pub fn domain_of(normalized: &str) -> &str {
    normalized
        .rsplit_once('@')
        .map_or(normalized, |(_, domain)| domain)
}

/// The public base URL links are built on, when this deployment delivers mail.
pub(crate) fn delivery_url(conn: &Connection) -> Result<Option<String>> {
    Ok(conn
        .prepare_cached("SELECT public_url FROM mail_settings WHERE id = 1 AND enabled = 1")?
        .query_row([], |r| r.get::<_, Option<String>>(0))
        .optional()?
        .flatten())
}

/// Whether this deployment delivers mail (a lane is running).
pub fn delivery_enabled(conn: &Connection) -> Result<bool> {
    Ok(delivery_url(conn)?.is_some())
}

/// The base URL the controller was last started with, whether or not it
/// delivers mail: what the host-local CLI builds a link on.
pub fn public_url(conn: &Connection) -> Result<Option<String>> {
    Ok(conn
        .prepare_cached("SELECT public_url FROM mail_settings WHERE id = 1")?
        .query_row([], |r| r.get::<_, Option<String>>(0))
        .optional()?
        .flatten())
}

/// Record, at controller start, whether mail is delivered and the base URL
/// links name (`public_url`; delivery needs one). Rows already queued stay
/// queued: a later start with the lane delivers them, and they expire on
/// their own.
pub fn set_delivery(
    store: &Store,
    enabled: bool,
    public_url: Option<&str>,
    now: UnixMillis,
) -> Result<()> {
    if enabled && public_url.is_none() {
        return Err(Error::InvalidInput("mail public url"));
    }
    let url = public_url.map(str::to_owned);
    store.writer().write(move |tx| {
        tx.execute(
            "UPDATE mail_settings SET enabled = ?1, public_url = ?2, updated_ms = ?3 WHERE id = 1",
            params![enabled, url, now.0],
        )?;
        Ok(())
    })
}

fn sealing_context(id: &MailId) -> [u8; 24] {
    let mut out = [0u8; 24];
    out[..8].copy_from_slice(b"mail/v1:");
    out[8..].copy_from_slice(id.as_bytes());
    out
}

/// One message to queue.
pub(crate) struct Outgoing<'a> {
    pub kind: Kind,
    pub recipient: &'a str,
    pub subject: &'a str,
    pub body: &'a str,
    /// How long the message is worth delivering.
    pub ttl_ms: i64,
}

/// Queue one message: sealed, bounded, and refused (`false`) rather than
/// piled up past the global or per-recipient ceilings.
pub(crate) fn enqueue(
    tx: &Transaction<'_>,
    key: &Key,
    message: &Outgoing<'_>,
    now: UnixMillis,
) -> Result<bool> {
    let Outgoing {
        kind,
        recipient,
        subject,
        body,
        ttl_ms,
    } = *message;
    let pending: i64 = tx
        .prepare_cached("SELECT COUNT(*) FROM mail_outbox WHERE state = 0")?
        .query_row([], |r| r.get(0))?;
    let recent: i64 = tx
        .prepare_cached(
            "SELECT COUNT(*) FROM mail_outbox WHERE recipient = ?1 AND created_ms > ?2",
        )?
        .query_row(params![recipient, now.0 - RESEND_WINDOW_MS], |r| r.get(0))?;
    if pending >= MAX_PENDING || recent >= RECIPIENT_PER_WINDOW {
        return Ok(false);
    }
    let id = MailId::new();
    let mut plain = String::with_capacity(subject.len() + 1 + body.len());
    plain.push_str(subject);
    plain.push('\n');
    plain.push_str(body);
    let sealed = key.seal(&sealing_context(&id), plain.as_bytes());
    wipe_string(&mut plain);
    tx.execute(
        "INSERT INTO mail_outbox(id, kind, recipient, body, state, attempts, next_attempt_ms,
            created_ms, expires_ms) VALUES (?1, ?2, ?3, ?4, 0, 0, ?5, ?5, ?6)",
        params![
            id.as_bytes(),
            kind as u8,
            recipient,
            sealed,
            now.0,
            now.0.saturating_add(ttl_ms)
        ],
    )?;
    Ok(true)
}

fn verification_message(url: &str, secret: &Secret) -> (&'static str, String) {
    let mut link = String::new();
    secret.expose(&mut link);
    let body = format!(
        "Someone, hopefully you, asked to use this address for a Sentinel account.\n\
         \n\
         To confirm it, open this link within 24 hours:\n\
         \n\
         {url}/verify-email#token={link}\n\
         \n\
         If this was not you, ignore this message: nothing changes until the link is opened.\n"
    );
    wipe_string(&mut link);
    ("Verify your Sentinel email address", body)
}

pub(crate) fn invitation_message(
    url: &str,
    secret: &Secret,
    tenant_slug: &str,
) -> (String, String) {
    let link = token::format(secret);
    let body = format!(
        "You have been invited to join {tenant_slug} on Sentinel.\n\
         \n\
         To accept, sign in (or register with this address) and open this link:\n\
         \n\
         {url}/invitations/accept#token={link}\n\
         \n\
         The link works once and expires. If you did not expect this invitation, ignore this message.\n"
    );
    (
        format!("You are invited to join {tenant_slug} on Sentinel"),
        body,
    )
}

/// What asking for a verification link did. Callers that must not reveal
/// whether an address is known answer the same for every variant but
/// [`Requested::Throttled`] on an authenticated route.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Requested {
    /// A link was minted and queued for delivery.
    Queued,
    /// A link was recorded but this deployment sends no mail (or holds no
    /// master key): the operator mints one with `sentinel admin account
    /// email-link`.
    Undelivered,
    /// The account (or the recipient) is over its resend allowance.
    Throttled,
    /// Nothing to do: another account already verified that address, the
    /// account already has it verified, or there is no such pending claim.
    Suppressed,
}

fn live_user(tx: &Connection, user: UserId) -> Result<bool> {
    Ok(tx
        .prepare_cached(
            "SELECT EXISTS(SELECT 1 FROM users WHERE id = ?1 AND kind = 0 AND status != 2)",
        )?
        .query_row([user.as_bytes()], |r| r.get(0))?)
}

fn verified_elsewhere(conn: &Connection, email: &str, user: UserId) -> Result<bool> {
    Ok(conn
        .prepare_cached(
            "SELECT EXISTS(SELECT 1 FROM users WHERE email = ?1 AND email_verified_ms IS NOT NULL
             AND id != ?2)",
        )?
        .query_row(params![email, user.as_bytes()], |r| r.get(0))?)
}

/// Record a fresh token for `email` (canonical) on `user`, voiding the
/// account's earlier unused ones, and return its secret.
fn mint(
    tx: &Transaction<'_>,
    user: UserId,
    email: &str,
    invitation: Option<InvitationId>,
    now: UnixMillis,
    host_local: bool,
) -> Result<Secret> {
    tx.execute(
        "UPDATE email_verifications SET used_ms = ?2 WHERE user_id = ?1 AND used_ms IS NULL",
        params![user.as_bytes(), now.0],
    )?;
    // An unverified claim follows the newest request; a verified address
    // stays until the new one is proved.
    tx.execute(
        "UPDATE users SET email = ?2 WHERE id = ?1 AND email_verified_ms IS NULL
         AND email IS NOT ?2",
        params![user.as_bytes(), email],
    )?;
    let secret = Secret::generate();
    tx.execute(
        "INSERT INTO email_verifications(token_digest, user_id, email, invitation, created_ms,
            expires_ms) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            secret.digest().0,
            user.as_bytes(),
            email,
            invitation.as_ref().map(InvitationId::as_bytes),
            now.0,
            now.0.saturating_add(VERIFICATION_TTL_MS)
        ],
    )?;
    audit(
        tx,
        Event::EmailVerificationRequested,
        (!host_local).then_some(user),
        Some(user),
        host_local,
        None,
    )?;
    Ok(secret)
}

/// Ask for a link proving `email` (any spelling; it is canonicalized) for
/// `user`, optionally carrying an email-bound invitation that the proof will
/// redeem. The per-account allowance is checked first and counts every link
/// minted in the window, delivered or not.
pub fn request(
    tx: &Transaction<'_>,
    key: Option<&Key>,
    user: UserId,
    email: &str,
    invitation: Option<InvitationId>,
    now: UnixMillis,
) -> Result<Requested> {
    let email = normalize(email)?;
    request_canonical(tx, key, user, &email, invitation, now)
}

fn request_canonical(
    tx: &Transaction<'_>,
    key: Option<&Key>,
    user: UserId,
    email: &str,
    invitation: Option<InvitationId>,
    now: UnixMillis,
) -> Result<Requested> {
    if !live_user(tx, user)? || verified_elsewhere(tx, email, user)? {
        return Ok(Requested::Suppressed);
    }
    let already: bool = tx
        .prepare_cached(
            "SELECT EXISTS(SELECT 1 FROM users WHERE id = ?1 AND email = ?2
             AND email_verified_ms IS NOT NULL)",
        )?
        .query_row(params![user.as_bytes(), email], |r| r.get(0))?;
    if already && invitation.is_none() {
        return Ok(Requested::Suppressed);
    }
    let minted: i64 = tx
        .prepare_cached(
            "SELECT COUNT(*) FROM email_verifications WHERE user_id = ?1 AND created_ms > ?2",
        )?
        .query_row(params![user.as_bytes(), now.0 - RESEND_WINDOW_MS], |r| {
            r.get(0)
        })?;
    if minted >= RESENDS_PER_WINDOW {
        return Ok(Requested::Throttled);
    }
    let secret = mint(tx, user, email, invitation, now, false)?;
    let (Some(key), Some(url)) = (key, delivery_url(tx)?) else {
        return Ok(Requested::Undelivered);
    };
    let (subject, body) = verification_message(&url, &secret);
    let queued = enqueue(
        tx,
        key,
        &Outgoing {
            kind: Kind::Verification,
            recipient: email,
            subject,
            body: &body,
            ttl_ms: VERIFICATION_TTL_MS,
        },
        now,
    )?;
    Ok(if queued {
        Requested::Queued
    } else {
        Requested::Throttled
    })
}

/// The address an account is still proving, and the invitation that proof
/// will redeem: the newest link's target unless that address is already the
/// account's verified one, else its unverified claim.
fn pending_for(conn: &Connection, user: UserId) -> Result<Option<(String, Option<InvitationId>)>> {
    let current: Option<(Option<String>, Option<i64>)> = conn
        .prepare_cached(
            "SELECT email, email_verified_ms FROM users WHERE id = ?1 AND kind = 0 AND status != 2",
        )?
        .query_row([user.as_bytes()], |r| Ok((r.get(0)?, r.get(1)?)))
        .optional()?;
    let Some((email, verified)) = current else {
        return Ok(None);
    };
    let latest: Option<(String, Option<[u8; 16]>)> = conn
        .prepare_cached(
            "SELECT email, invitation FROM email_verifications WHERE user_id = ?1
             ORDER BY created_ms DESC, token_digest LIMIT 1",
        )?
        .query_row([user.as_bytes()], |r| Ok((r.get(0)?, r.get(1)?)))
        .optional()?;
    let invitation = |bytes: Option<[u8; 16]>| match bytes {
        Some(bytes) => InvitationId::from_bytes(bytes)
            .map(Some)
            .map_err(|_| Error::Corrupt("invitation id")),
        None => Ok(None),
    };
    match latest {
        Some((target, inv))
            if !(verified.is_some() && email.as_deref() == Some(target.as_str())) =>
        {
            Ok(Some((target, invitation(inv)?)))
        }
        _ => Ok(match (email, verified) {
            (Some(email), None) => Some((email, None)),
            _ => None,
        }),
    }
}

/// Resend the link an authenticated account is waiting for.
pub fn resend(
    tx: &Transaction<'_>,
    key: Option<&Key>,
    user: UserId,
    now: UnixMillis,
) -> Result<Requested> {
    match pending_for(tx, user)? {
        Some((email, invitation)) => request_canonical(tx, key, user, &email, invitation, now),
        None => Ok(Requested::Suppressed),
    }
}

/// Resend for someone who names only an address (the "I never got it" form):
/// the newest account still claiming it unverified, if any. The caller answers
/// the same whatever this returns.
pub fn resend_for_address(
    tx: &Transaction<'_>,
    key: Option<&Key>,
    email: &str,
    now: UnixMillis,
) -> Result<Requested> {
    let email = normalize(email)?;
    let user: Option<[u8; 16]> = tx
        .prepare_cached(
            "SELECT id FROM users WHERE email = ?1 AND email_verified_ms IS NULL AND kind = 0
             AND status != 2 ORDER BY created_ms DESC, id LIMIT 1",
        )?
        .query_row([&email], |r| r.get(0))
        .optional()?;
    let Some(user) = user else {
        return Ok(Requested::Suppressed);
    };
    let user = UserId::from_bytes(user).map_err(|_| Error::Corrupt("user_id"))?;
    resend(tx, key, user, now)
}

/// A link minted for the operator to hand over.
pub struct IssuedLink {
    pub email: String,
    pub secret: Secret,
    pub expires: UnixMillis,
}

/// Host-local: mint a fresh verification token and return its secret, for an
/// operator whose deployment sends no mail. The token proves the address the
/// account is already proving, or `email` when the operator names one (which
/// becomes the account's unverified claim, or the pending replacement of a
/// verified address). Platform administration (the database file's
/// authority), audited as host-local; it voids the account's earlier links.
/// The secret is shown once; the link is
/// `<public_url>/verify-email#token=<secret>`. `Conflict` when another
/// account already verified the address.
pub fn issue_link(
    tx: &Transaction<'_>,
    authority: Authority,
    user: UserId,
    email: Option<&str>,
    now: UnixMillis,
) -> Result<IssuedLink> {
    authority.require_platform(tx)?;
    if !live_user(tx, user)? {
        return Err(Error::NotFound);
    }
    let (email, invitation) = match email {
        Some(address) => (normalize(address)?, None),
        None => pending_for(tx, user)?.ok_or(Error::NotFound)?,
    };
    if verified_elsewhere(tx, &email, user)? {
        return Err(Error::Conflict);
    }
    let secret = mint(tx, user, &email, invitation, now, true)?;
    Ok(IssuedLink {
        email,
        secret,
        expires: UnixMillis(now.0.saturating_add(VERIFICATION_TTL_MS)),
    })
}

/// Host-local: mark an account's current address verified without a link (the
/// operator vouches for it). Platform administration, audited with the
/// host-local marker.
pub fn verify_host_local(
    tx: &Transaction<'_>,
    authority: Authority,
    user: UserId,
    now: UnixMillis,
) -> Result<()> {
    authority.require_platform(tx)?;
    let email: Option<String> = tx
        .prepare_cached(
            "SELECT email FROM users WHERE id = ?1 AND kind = 0 AND status != 2
             AND email_verified_ms IS NULL",
        )?
        .query_row([user.as_bytes()], |r| r.get(0))
        .optional()?
        .flatten();
    let email = email.ok_or(Error::NotFound)?;
    if verified_elsewhere(tx, &email, user)? {
        return Err(Error::Conflict);
    }
    claim_verified(tx, user, &email, now)?;
    audit(
        tx,
        Event::EmailVerified,
        authority.actor(),
        Some(user),
        authority.host_local(),
        None,
    )?;
    crate::auto_join::apply(tx, user, now)?;
    Ok(())
}

/// Make `email` the account's verified address and clear every other
/// account's unverified claim to it. The caller checked nobody else holds it
/// verified.
pub(crate) fn claim_verified(
    tx: &Transaction<'_>,
    user: UserId,
    email: &str,
    now: UnixMillis,
) -> Result<()> {
    tx.execute(
        "UPDATE users SET email = NULL WHERE email = ?1 AND id != ?2
         AND email_verified_ms IS NULL",
        params![email, user.as_bytes()],
    )?;
    tx.execute(
        "UPDATE users SET email = ?2, email_verified_ms = ?3 WHERE id = ?1",
        params![user.as_bytes(), email, now.0],
    )?;
    Ok(())
}

/// What presenting a verification token did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Confirmation {
    /// The address is verified; `joined` is the tenant an email-bound
    /// invitation carried by the token granted membership of.
    Verified {
        user: UserId,
        joined: Option<TenantId>,
    },
    /// Unknown, expired, spent or voided token, or the address is verified by
    /// another account. One answer for all; a presented token is spent either way.
    Refused,
}

/// Present a verification token. Single-use and race-safe: the token is spent,
/// the address verified and any invitation it carries redeemed in one
/// transaction, so a lost race changes nothing it should not.
pub fn confirm(store: &Store, secret: &Secret, now: UnixMillis) -> Result<Confirmation> {
    let digest = secret.digest();
    store.writer().write(move |tx| {
        let row: Option<([u8; 16], String, Option<[u8; 16]>)> = tx
            .prepare_cached(
                "SELECT user_id, email, invitation FROM email_verifications
                 WHERE token_digest = ?1 AND used_ms IS NULL AND expires_ms > ?2",
            )?
            .query_row(params![digest.0, now.0], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?))
            })
            .optional()?;
        let Some((user, email, invitation)) = row else {
            return Ok(Confirmation::Refused);
        };
        let user = UserId::from_bytes(user).map_err(|_| Error::Corrupt("user_id"))?;
        let spent = tx.execute(
            "UPDATE email_verifications SET used_ms = ?2 WHERE token_digest = ?1 AND used_ms IS NULL",
            params![digest.0, now.0],
        )?;
        if spent != 1 || !live_user(tx, user)? || verified_elsewhere(tx, &email, user)? {
            return Ok(Confirmation::Refused);
        }
        claim_verified(tx, user, &email, now)?;
        audit(
            tx,
            Event::EmailVerified,
            Some(user),
            Some(user),
            false,
            None,
        )?;
        let joined = match invitation {
            Some(bytes) => {
                let id = InvitationId::from_bytes(bytes)
                    .map_err(|_| Error::Corrupt("invitation id"))?;
                registration::redeem_verified(tx, id, user, &email, now)?
            }
            None => None,
        };
        // After the invitation: an account it just admitted is eligible.
        crate::auto_join::apply(tx, user, now)?;
        Ok(Confirmation::Verified { user, joined })
    })
}

/// The account an operator means by an address: the one that verified it, else
/// the newest still claiming it. For the host-local CLI, which names accounts.
pub fn user_by_address(conn: &Connection, address: &str) -> Result<Option<UserId>> {
    let address = normalize(address)?;
    let row: Option<[u8; 16]> = conn
        .prepare_cached(
            "SELECT id FROM users WHERE email = ?1 AND kind = 0 AND status != 2
             ORDER BY email_verified_ms IS NULL, created_ms DESC, id LIMIT 1",
        )?
        .query_row([&address], |r| r.get(0))
        .optional()?;
    row.map(|bytes| UserId::from_bytes(bytes).map_err(|_| Error::Corrupt("user_id")))
        .transpose()
}

/// An account's address and whether it is verified.
pub fn account_email(conn: &Connection, user: UserId) -> Result<Option<(String, bool)>> {
    Ok(conn
        .prepare_cached("SELECT email, email_verified_ms IS NOT NULL FROM users WHERE id = ?1")?
        .query_row([user.as_bytes()], |r| {
            Ok((r.get::<_, Option<String>>(0)?, r.get::<_, bool>(1)?))
        })
        .optional()?
        .and_then(|(email, verified)| email.map(|email| (email, verified))))
}

/// One message the lane should deliver.
#[derive(Clone, Debug)]
pub struct Pending {
    pub id: MailId,
    pub kind: Kind,
    pub recipient: String,
    pub attempts: u32,
    pub expires_ms: i64,
    sealed: Vec<u8>,
}

/// A message opened for sending.
pub struct Message {
    pub subject: String,
    pub body: String,
}

impl Pending {
    /// Open the sealed body. `None` when it cannot be opened (the key was
    /// retired, or the row was altered): the lane gives the message up.
    pub fn open(&self, key: &Key) -> Option<Message> {
        let plain = key.open(&sealing_context(&self.id), &self.sealed).ok()?;
        let text = String::from_utf8(plain).ok()?;
        let (subject, body) = text.split_once('\n')?;
        Some(Message {
            subject: subject.to_owned(),
            body: body.to_owned(),
        })
    }
}

/// Messages due for delivery, oldest first.
pub fn due(conn: &Connection, now: UnixMillis, limit: u16) -> Result<Vec<Pending>> {
    let mut stmt = conn.prepare_cached(
        "SELECT id, kind, recipient, body, attempts, expires_ms FROM mail_outbox
         WHERE state = 0 AND next_attempt_ms <= ?1 ORDER BY next_attempt_ms, id LIMIT ?2",
    )?;
    let rows = stmt.query_map(params![now.0, limit], |r| {
        Ok((
            r.get::<_, [u8; 16]>(0)?,
            r.get::<_, i64>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, Vec<u8>>(3)?,
            r.get::<_, i64>(4)?,
            r.get::<_, i64>(5)?,
        ))
    })?;
    rows.map(|row| {
        let (id, kind, recipient, sealed, attempts, expires_ms) = row?;
        Ok(Pending {
            id: MailId::from_bytes(id).map_err(|_| Error::Corrupt("mail id"))?,
            kind: Kind::from_code(kind).ok_or(Error::Corrupt("mail_outbox.kind"))?,
            recipient,
            attempts: u32::try_from(attempts).unwrap_or(u32::MAX),
            expires_ms,
            sealed,
        })
    })
    .collect()
}

/// When the earliest pending message becomes due, in wall-clock milliseconds
/// (`None` when nothing is pending): one read of the head of the due index.
pub fn next_due_ms(conn: &Connection) -> Result<Option<i64>> {
    Ok(conn
        .prepare_cached(
            "SELECT next_attempt_ms FROM mail_outbox WHERE state = 0
             ORDER BY next_attempt_ms LIMIT 1",
        )?
        .query_row([], |r| r.get(0))
        .optional()?)
}

/// Milliseconds to wait after failed attempt number `attempts` (1-based): one
/// minute for the first, doubling, capped at fifteen minutes.
pub fn backoff_ms(attempts: u32) -> i64 {
    (30_000i64 << attempts.min(10)).min(15 * 60 * 1000)
}

/// Resend accepted the message: settle it and drop the sealed body.
pub fn delivered(tx: &Transaction<'_>, id: MailId, now: UnixMillis) -> Result<()> {
    let changed = tx.execute(
        "UPDATE mail_outbox SET state = 1, body = NULL, settled_ms = ?2 WHERE id = ?1 AND state = 0",
        params![id.as_bytes(), now.0],
    )?;
    if changed == 1 {
        Ok(())
    } else {
        Err(Error::Conflict)
    }
}

/// What a failed attempt did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Retry {
    Scheduled { attempts: u32, next_attempt_ms: i64 },
    GaveUp,
}

/// A bounded, control-free reason for the audit row and the outbox.
fn brief(reason: &str) -> String {
    let mut text: String = reason
        .chars()
        .filter(|c| !c.is_control())
        .take(100)
        .collect();
    if text.trim().is_empty() {
        text = "failed".into();
    }
    text
}

/// The longest a service's `Retry-After` is honored: past it the back-off
/// schedule decides.
pub const MAX_RETRY_AFTER_MS: i64 = 60 * 60 * 1000;

/// A transient failure: due again after the back-off (or `retry_after_ms`,
/// when the service asked for longer, bounded by [`MAX_RETRY_AFTER_MS`]), or
/// given up once the attempt budget or the message's own expiry is spent.
pub fn retry(
    tx: &Transaction<'_>,
    id: MailId,
    now: UnixMillis,
    reason: &str,
    retry_after_ms: i64,
) -> Result<Retry> {
    let row: Option<(i64, i64, i64)> = tx
        .prepare_cached(
            "SELECT attempts, expires_ms, kind FROM mail_outbox WHERE id = ?1 AND state = 0",
        )?
        .query_row([id.as_bytes()], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .optional()?;
    let (attempts, expires_ms, kind) = row.ok_or(Error::Conflict)?;
    let next = u32::try_from(attempts.saturating_add(1)).unwrap_or(u32::MAX);
    let wait_ms = backoff_ms(next).max(retry_after_ms.clamp(0, MAX_RETRY_AFTER_MS));
    let next_attempt_ms = now.0.saturating_add(wait_ms);
    if next >= MAX_ATTEMPTS || next_attempt_ms >= expires_ms {
        give_up_row(tx, id, kind, "attempts", reason, now)?;
        return Ok(Retry::GaveUp);
    }
    tx.execute(
        "UPDATE mail_outbox SET attempts = ?2, next_attempt_ms = ?3 WHERE id = ?1 AND state = 0",
        params![id.as_bytes(), next, next_attempt_ms],
    )?;
    Ok(Retry::Scheduled {
        attempts: next,
        next_attempt_ms,
    })
}

/// A permanent failure (Resend refused the message, the body cannot be
/// opened): settle it as given up with `reason`, audited.
pub fn give_up(tx: &Transaction<'_>, id: MailId, reason: &str, now: UnixMillis) -> Result<()> {
    let kind: i64 = tx
        .prepare_cached("SELECT kind FROM mail_outbox WHERE id = ?1 AND state = 0")?
        .query_row([id.as_bytes()], |r| r.get(0))
        .optional()?
        .ok_or(Error::Conflict)?;
    give_up_row(tx, id, kind, "refused", reason, now)
}

fn give_up_row(
    tx: &Transaction<'_>,
    id: MailId,
    kind: i64,
    why: &str,
    detail: &str,
    now: UnixMillis,
) -> Result<()> {
    tx.execute(
        "UPDATE mail_outbox SET state = 2, body = NULL, settled_ms = ?2, reason = ?3
         WHERE id = ?1 AND state = 0",
        params![id.as_bytes(), now.0, why],
    )?;
    let kind = Kind::from_code(kind).map_or("message", Kind::name);
    audit(
        tx,
        Event::MailAbandoned,
        None,
        None,
        false,
        Some(&format!("{kind} {why}: {}", brief(detail))),
    )
}

/// Bounded maintenance: expire undelivered messages past their life, delete
/// settled rows and spent or expired tokens a week old. At most `limit` rows
/// of each kind; returns how many were touched.
pub fn purge(store: &Store, now: UnixMillis, limit: u32) -> Result<usize> {
    store.writer().write(move |tx| {
        let expired: Vec<([u8; 16], i64)> = {
            let mut stmt = tx.prepare_cached(
                "SELECT id, kind FROM mail_outbox WHERE state = 0 AND expires_ms <= ?1 LIMIT ?2",
            )?;
            stmt.query_map(params![now.0, limit], |r| Ok((r.get(0)?, r.get(1)?)))?
                .collect::<std::result::Result<_, _>>()?
        };
        let mut touched = expired.len();
        for (id, kind) in expired {
            let id = MailId::from_bytes(id).map_err(|_| Error::Corrupt("mail id"))?;
            give_up_row(
                tx,
                id,
                kind,
                "expired",
                "not delivered before it expired",
                now,
            )?;
        }
        let horizon = now.0.saturating_sub(RETAIN_MS);
        touched += tx.execute(
            "DELETE FROM mail_outbox WHERE id IN (
                SELECT id FROM mail_outbox WHERE state != 0 AND settled_ms <= ?1 LIMIT ?2)",
            params![horizon, limit],
        )?;
        touched += tx.execute(
            "DELETE FROM email_verifications WHERE token_digest IN (
                SELECT token_digest FROM email_verifications WHERE expires_ms <= ?1 LIMIT ?2)",
            params![horizon, limit],
        )?;
        Ok(touched)
    })
}

/// Outbox counts for diagnostics: pending, delivered, given up.
pub fn counts(conn: &Connection) -> Result<(i64, i64, i64)> {
    let count = |state: i64| -> Result<i64> {
        Ok(conn
            .prepare_cached("SELECT COUNT(*) FROM mail_outbox WHERE state = ?1")?
            .query_row([state], |r| r.get(0))?)
    };
    Ok((count(0)?, count(1)?, count(2)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addresses_are_canonicalized_and_hostile_ones_refused() {
        assert_eq!(
            normalize("  Alice.Smith+ci@Example.COM ").unwrap(),
            "alice.smith+ci@example.com"
        );
        // An IDN domain is compared in punycode, whichever way it is written.
        assert_eq!(
            normalize("a@BÜCHER.example").unwrap(),
            normalize("a@xn--bcher-kva.example").unwrap()
        );
        assert_eq!(
            normalize("a@xn--bcher-kva.example").unwrap(),
            "a@xn--bcher-kva.example"
        );
        for bad in [
            "",
            "plain",
            "@example.com",
            "a@",
            "a@localhost",
            "a@127.0.0.1",
            "a@[::1]",
            "a b@example.com",
            "a@exa mple.com",
            ".a@example.com",
            "a.@example.com",
            "a..b@example.com",
            "\"a\"@example.com",
            "a<b@example.com",
            "a@example.com.",
            "a@-example.com",
            "ä@example.com",
            "a@exa_mple.com",
            "a\r\nBcc: x@example.com@example.com",
        ] {
            assert!(normalize(bad).is_err(), "{bad:?}");
        }
        let long_local = "a".repeat(65);
        assert!(normalize(&format!("{long_local}@example.com")).is_err());
        let long_domain = format!("{}.example.com", "a".repeat(64));
        assert!(normalize(&format!("a@{long_domain}")).is_err());
    }

    #[test]
    fn a_domain_matches_exactly_never_by_suffix() {
        let a = normalize_domain("Example.COM").unwrap();
        assert_eq!(a, "example.com");
        assert_ne!(a, normalize_domain("mail.example.com").unwrap());
        assert_ne!(a, normalize_domain("notexample.com").unwrap());
        assert!(normalize_domain("com").is_err());
        assert!(normalize_domain("a@example.com").is_err());
    }

    #[test]
    fn backoff_doubles_to_a_ceiling() {
        assert_eq!(backoff_ms(1), 60_000);
        assert_eq!(backoff_ms(2), 120_000);
        assert_eq!(backoff_ms(20), 15 * 60 * 1000);
    }
}
