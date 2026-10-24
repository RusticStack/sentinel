//! Setup is gated by a token only a host operator can read; the first visitor never becomes administrator.

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

pub const TOKEN_TTL_MS: i64 = 60 * 60 * 1000;
pub const TOKEN_FILE: &str = "setup-token";
pub const FAILURES_BEFORE_LOCK: i64 = 5;
pub const LOCK_MS: i64 = 5 * 60 * 1000;

pub fn is_open(conn: &Connection) -> Result<bool> {
    local_auth::bootstrap_available(conn)
}

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

pub struct Setup<'a> {
    pub token: &'a Secret,
    pub email: &'a str,
    pub display_name: &'a str,
    pub password: &'a [u8],
    pub registration: Registration,
    pub tenant_creation: TenantCreation,
    pub instance_name: &'a str,
    pub base_url: Option<&'a str>,
    pub personal_namespace: Option<&'a str>,
    pub organization: Option<&'a str>,
}

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

pub struct Completed {
    pub user: UserId,
    pub issued: Issued,
    pub personal: Option<TenantId>,
    pub organization: Option<TenantId>,
}

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
    // Constant time over digests; expiry is judged after, so wrong and expired cost the same.
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
    Wrong,
    Refused,
    Locked,
}

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

// The token is judged again inside the writer, so a setup that loses a race creates nothing.
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
        crate::email::claim_verified(tx, user, &email, now)?;
        tx.execute(
            "INSERT INTO bootstrap(id, completed_ms, user_id) VALUES (1, ?1, ?2)",
            params![now.0, user.as_bytes()],
        )?;
        tx.execute("DELETE FROM setup_token", [])?;

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

pub fn instance(conn: &Connection) -> Result<Option<(String, Option<String>)>> {
    Ok(conn
        .prepare_cached("SELECT name, base_url FROM instance_settings WHERE id = 1")?
        .query_row([], |r| Ok((r.get(0)?, r.get(1)?)))
        .optional()?)
}

pub fn purge(store: &Store, now: UnixMillis, _limit: u32) -> Result<usize> {
    store.writer().write(move |tx: &Transaction<'_>| {
        Ok(tx.execute(
            "DELETE FROM setup_token
             WHERE expires_ms <= ?1 OR EXISTS(SELECT 1 FROM bootstrap)",
            [now.0],
        )?)
    })
}

pub fn token_live(conn: &Connection, now: UnixMillis) -> Result<bool> {
    if !is_open(conn)? {
        return Ok(false);
    }
    Ok(conn
        .prepare_cached("SELECT EXISTS(SELECT 1 FROM setup_token WHERE expires_ms > ?1)")?
        .query_row([now.0], |r| r.get(0))?)
}
