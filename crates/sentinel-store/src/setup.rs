//! First-run setup: the wizard's one-time token and the single transaction
//! that turns an empty deployment into one with an administrator.
//!
//! "First visitor wins" is not a bootstrap, so the web path is gated by a
//! credential only somebody with the host can read. At start, while no super
//! admin exists, the controller [`issue`]s a setup token — 256 random bits,
//! stored only as its digest, expiring after [`TOKEN_TTL_MS`] — and shows it
//! once on the host (a `0600` file in the data directory and a console line).
//! [`complete`] needs it, and in one commit creates the administrator with a
//! verified address, records the registration policy and instance settings,
//! creates the optional namespaces, closes the existing `bootstrap` latch,
//! deletes the token and issues the administrator's session. There is no
//! second latch: `sentinel admin bootstrap` writes the same `bootstrap` row
//! and deletes the token too, so whichever comes second is refused.
//!
//! Brute force is bounded twice: the API admits a client only a few attempts
//! ([`crate`] callers' budgets), and here [`FAILURES_BEFORE_LOCK`] wrong
//! tokens lock setup for [`LOCK_MS`] for everyone, the right token included.
//! The lock can delay setup, never complete it, and `admin bootstrap` is
//! unaffected.
//!
//! Every refusal of a token (wrong, expired, locked, absent) is one
//! [`Error::Forbidden`]; setup after the latch closed is [`Error::NotFound`],
//! which the status route already told the client.

use rusqlite::{Connection, OptionalExtension, Transaction, params};
use sentinel_auth::{
    password,
    secret::{Digest, Secret, digest_eq},
};
use sentinel_core::{TenantId, UnixMillis, UserId};

use crate::{
    Error, Result, Store,
    auth::Authority,
    local_auth::{self, Event, Issued, Policy, audit},
    registration::{self, DeploymentPolicy, Registration, TenantCreation},
};

/// How long an issued token stays good: long enough to read it on the host
/// and fill in the wizard, short enough that a forgotten one is not a
/// standing credential. A controller start or `admin setup-token` issues a
/// new one and voids the old.
pub const TOKEN_TTL_MS: i64 = 60 * 60 * 1000;
/// Wrong tokens, all clients together, before setup locks.
pub const FAILURES_BEFORE_LOCK: i64 = 5;
/// How long a locked setup refuses every attempt.
pub const LOCK_MS: i64 = 5 * 60 * 1000;

/// Whether the first-run wizard is available: no super admin has been
/// admitted, by the wizard or by `sentinel admin bootstrap`. The answer is
/// the bootstrap latch itself, read the way the latch is read everywhere.
pub fn is_open(conn: &Connection) -> Result<bool> {
    local_auth::bootstrap_available(conn)
}

/// Mint a setup token, replacing any earlier one, and return it for the one
/// place that may show it. `None` when setup is already closed (and any stale
/// token row is removed). Only the digest is stored.
pub fn issue(store: &Store, now: UnixMillis) -> Result<Option<Secret>> {
    store.writer().write(move |tx| {
        if local_auth::bootstrap_complete(tx)? {
            tx.execute("DELETE FROM setup_token", [])?;
            return Ok(None);
        }
        let token = Secret::generate();
        tx.execute(
            "INSERT OR REPLACE INTO setup_token(id, digest, created_ms, expires_ms)
             VALUES (1, ?1, ?2, ?3)",
            params![token.digest().0, now.0, now.0.saturating_add(TOKEN_TTL_MS)],
        )?;
        Ok(Some(token))
    })
}

/// What the wizard decided. Strings are borrowed from the request; nothing
/// here is a secret except `password` and `token`.
pub struct Setup<'a> {
    pub token: &'a Secret,
    /// The administrator's address. The setup token proves the operator, so
    /// it is stored verified.
    pub email: &'a str,
    pub display_name: &'a str,
    pub password: &'a [u8],
    pub registration: Registration,
    pub tenant_creation: TenantCreation,
    pub instance_name: &'a str,
    /// The operator's statement of the instance's base URL, shown to
    /// administrators; links keep using the configured `public_url`.
    pub base_url: Option<&'a str>,
    /// The administrator's personal namespace, if they want one now.
    pub personal_namespace: Option<&'a str>,
    /// A first organization the administrator administers.
    pub organization: Option<&'a str>,
}

/// Judge a presented token without using it, for the wizard's side steps (the
/// SMTP test). A wrong token counts against the same lock as [`complete`];
/// the refusals are the same.
pub fn verify(store: &Store, token: &Secret, now: UnixMillis) -> Result<()> {
    let presented = token.digest();
    match store.read(move |c| judge(c, &presented, now))? {
        Verdict::Good => Ok(()),
        Verdict::Wrong => {
            fail(store, now)?;
            Err(Error::Forbidden)
        }
        Verdict::Refused | Verdict::Locked => Err(Error::Forbidden),
    }
}

/// What setup created.
pub struct Completed {
    pub user: UserId,
    pub issued: Issued,
    pub personal: Option<TenantId>,
    pub organization: Option<TenantId>,
}

/// Judge `presented` against the stored token. `Ok(())` only for the live,
/// unlocked, matching token; `Forbidden` for anything else, `NotFound` when
/// setup is closed. Never writes.
fn judge(conn: &Connection, presented: &Digest, now: UnixMillis) -> Result<Verdict> {
    if local_auth::bootstrap_complete(conn)? {
        return Err(Error::NotFound);
    }
    let row: Option<(Vec<u8>, i64, i64)> = conn
        .prepare_cached("SELECT digest, expires_ms, locked_until_ms FROM setup_token WHERE id = 1")?
        .query_row([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .optional()?;
    let Some((digest, expires, locked_until)) = row else {
        return Ok(Verdict::Refused);
    };
    if now.0 < locked_until {
        return Ok(Verdict::Locked);
    }
    let Ok(stored) = <[u8; 32]>::try_from(digest.as_slice()) else {
        return Err(Error::Corrupt("setup_token.digest"));
    };
    // Constant time over the digests, and the expiry judged after it so a
    // wrong and an expired token cost the same.
    let matches = digest_eq(&Digest(stored), presented);
    if !matches {
        return Ok(Verdict::Wrong);
    }
    Ok(if now.0 >= expires {
        Verdict::Refused
    } else {
        Verdict::Good
    })
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Verdict {
    Good,
    /// Present but not the token.
    Wrong,
    /// Expired or no token has been issued.
    Refused,
    Locked,
}

/// Count a wrong token against the lock. One cheap write, only for a token
/// that was actually wrong; a locked setup refuses before this is reached.
fn fail(store: &Store, now: UnixMillis) -> Result<()> {
    store.writer().write(move |tx| {
        tx.execute(
            "UPDATE setup_token SET
                 locked_until_ms = CASE WHEN failures + 1 >= ?1 THEN ?2 ELSE locked_until_ms END,
                 failures = CASE WHEN failures + 1 >= ?1 THEN 0 ELSE failures + 1 END
             WHERE id = 1",
            params![FAILURES_BEFORE_LOCK, now.0.saturating_add(LOCK_MS)],
        )?;
        Ok(())
    })
}

fn bounded_label(value: &str, max: usize, what: &'static str) -> Result<()> {
    let trimmed = value.trim();
    if trimmed.is_empty() || value.chars().count() > max || value.chars().any(char::is_control) {
        return Err(Error::InvalidInput(what));
    }
    Ok(())
}

/// Validate the free-form fields before any token is judged or hash paid.
fn validate(setup: &Setup<'_>) -> Result<String> {
    let email = crate::email::normalize(setup.email)?;
    bounded_label(setup.display_name, 128, "display name")?;
    bounded_label(setup.instance_name, 64, "instance name")?;
    password::acceptable(setup.password).map_err(|_| Error::InvalidInput("password"))?;
    if let Some(url) = setup.base_url {
        let ok = url.len() <= 255
            && (url.starts_with("https://") || url.starts_with("http://"))
            && url.bytes().all(|b| b.is_ascii_graphic());
        if !ok {
            return Err(Error::InvalidInput("base url"));
        }
    }
    // Both names are held to the organization rules: nothing the product
    // routes on, and not one character.
    for name in [setup.personal_namespace, setup.organization]
        .into_iter()
        .flatten()
    {
        crate::organizations::slug(name)?;
    }
    if setup.personal_namespace.is_some() && setup.personal_namespace == setup.organization {
        return Err(Error::InvalidInput("namespace"));
    }
    Ok(email)
}

/// Run first-run setup: one commit, or nothing.
///
/// Order: the free fields are validated and the token judged on a reader
/// (a wrong token costs one counted write, never a password hash), then the
/// password is hashed outside the writer, then the writer re-judges the token
/// and the latch inside the transaction that creates everything. A setup
/// that lost a race to another setup or to `admin bootstrap` finds the latch
/// closed there and creates nothing.
///
/// # Errors
/// [`Error::InvalidInput`] for a bad field, [`Error::Forbidden`] for a token
/// that is wrong, expired, absent or locked out, [`Error::NotFound`] once
/// setup is closed, [`Error::Conflict`] when the address or a namespace name
/// is already taken.
pub fn complete(
    store: &Store,
    setup: &Setup<'_>,
    sessions: Policy,
    now: UnixMillis,
) -> Result<Completed> {
    let email = validate(setup)?;
    let presented = setup.token.digest();
    match store.read(move |c| judge(c, &presented, now))? {
        Verdict::Good => {}
        Verdict::Wrong => {
            fail(store, now)?;
            return Err(Error::Forbidden);
        }
        Verdict::Refused | Verdict::Locked => return Err(Error::Forbidden),
    }
    let phc = password::hash(setup.password).map_err(|_| Error::InvalidInput("password"))?;
    let display_name = setup.display_name.trim().to_owned();
    let instance_name = setup.instance_name.trim().to_owned();
    let base_url = setup.base_url.map(str::to_owned);
    let personal = setup.personal_namespace.map(str::to_owned);
    let organization = setup.organization.map(str::to_owned);
    let (registration, tenant_creation) = (setup.registration, setup.tenant_creation);
    store.writer().write(move |tx| {
        // The deciding judgement: same checks, same transaction as the writes.
        if judge(tx, &presented, now)? != Verdict::Good {
            return Err(Error::Forbidden);
        }
        let user = UserId::new();
        crate::auth::provisioning::insert_human(tx, user, &display_name, true, now)?;
        crate::local_auth::insert_credential(
            tx,
            user,
            &registration::generated_username(user),
            &phc,
            now,
        )?;
        let held: bool = tx
            .prepare_cached(
                "SELECT EXISTS(SELECT 1 FROM users WHERE email = ?1 AND email_verified_ms IS NOT NULL)",
            )?
            .query_row([&email], |r| r.get(0))?;
        if held {
            return Err(Error::Conflict);
        }
        // Claimed and proved in one step: the token is the operator's proof.
        crate::email::claim_verified(tx, user, &email, now)?;
        tx.execute(
            "INSERT INTO bootstrap(id, completed_ms, user_id) VALUES (1, ?1, ?2)",
            params![now.0, user.as_bytes()],
        )?;
        tx.execute("DELETE FROM setup_token", [])?;

        // The policy the person chose, audited as the host-local decision it
        // is (the setup token is host access); installation binding keeps the
        // deployment's current value.
        let current = registration::policy(tx)?;
        registration::set_policy(
            tx,
            Authority::HostLocal,
            DeploymentPolicy {
                registration,
                tenant_creation,
                ..current
            },
            now,
        )?;
        tx.execute(
            "INSERT INTO instance_settings(id, name, base_url, updated_ms) VALUES (1, ?1, ?2, ?3)",
            params![instance_name, base_url, now.0],
        )?;
        audit(
            tx,
            Event::Bootstrap,
            None,
            Some(user),
            true,
            Some("first-run setup"),
        )?;

        let personal = match &personal {
            Some(name) => {
                let tenant = TenantId::new();
                let slug = crate::organizations::slug(name)?;
                taken_is_conflict(crate::auth::insert_namespace(
                    tx,
                    tenant,
                    slug,
                    crate::auth::NamespaceKind::Personal(user),
                    now,
                ))?;
                audit(
                    tx,
                    Event::NamespaceCreated,
                    Some(user),
                    None,
                    true,
                    Some(slug.as_str()),
                )?;
                Some(tenant)
            }
            None => None,
        };
        let organization = match &organization {
            Some(name) => {
                let tenant = TenantId::new();
                let slug = crate::organizations::slug(name)?;
                taken_is_conflict(crate::tenancy::create_organization(
                    tx,
                    Authority::HostLocal,
                    tenant,
                    slug,
                    now,
                ))?;
                tx.execute(
                    "INSERT INTO memberships(tenant_id, user_id, role) VALUES (?1, ?2, 3)",
                    params![tenant.as_bytes(), user.as_bytes()],
                )?;
                audit(
                    tx,
                    Event::MembershipSet,
                    None,
                    Some(user),
                    true,
                    Some("admin"),
                )?;
                Some(tenant)
            }
            None => None,
        };
        let issued = local_auth::issue_session(tx, user, sessions, now)?;
        Ok(Completed {
            user,
            issued,
            personal,
            organization,
        })
    })
}

/// A namespace name another tenant holds is `Conflict`, the unique index
/// being the decision under any race.
fn taken_is_conflict(result: Result<()>) -> Result<()> {
    match result {
        Err(Error::Sqlite(rusqlite::Error::SqliteFailure(code, _)))
            if code.code == rusqlite::ErrorCode::ConstraintViolation =>
        {
            Err(Error::Conflict)
        }
        other => other,
    }
}

/// The instance name and base URL the wizard recorded, once it has run.
pub fn instance(conn: &Connection) -> Result<Option<(String, Option<String>)>> {
    Ok(conn
        .prepare_cached("SELECT name, base_url FROM instance_settings WHERE id = 1")?
        .query_row([], |r| Ok((r.get(0)?, r.get(1)?)))
        .optional()?)
}

/// Remove an expired or stale token row once setup has closed or the token
/// has expired, so the table never holds a dead credential. Maintenance.
pub fn purge(store: &Store, now: UnixMillis) -> Result<usize> {
    store.writer().write(move |tx: &Transaction<'_>| {
        Ok(tx.execute(
            "DELETE FROM setup_token
             WHERE expires_ms <= ?1 OR EXISTS(SELECT 1 FROM bootstrap)",
            [now.0],
        )?)
    })
}
