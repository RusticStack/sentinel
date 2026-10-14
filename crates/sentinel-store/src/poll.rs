//! The cursor advances in the same transaction as its delivery, so a crash never skips or replays a change.

use rusqlite::{Connection, OptionalExtension, Transaction, params};
use sentinel_core::{DeliveryId, RepoId, TenantId, UnixMillis, UserId};
use sentinel_protocol::source::{self, ref_matches, valid_ref_pattern};

use crate::{Error, Result, intake, registration::Authority, sources};

pub const PROVIDER: &str = "poll";
pub const MIN_INTERVAL_MS: i64 = 10_000;
pub const MAX_INTERVAL_MS: i64 = 24 * 60 * 60 * 1_000;
pub const MAX_REFS: usize = source::MAX_REFS;

pub struct Spec {
    pub interval_ms: i64,
    pub refs: Vec<String>,
}

pub struct Config {
    pub repo: RepoId,
    pub tenant: TenantId,
    pub interval_ms: i64,
    pub refs: Vec<String>,
    pub next_poll_ms: i64,
    pub failures: i64,
    pub last_error: Option<String>,
    pub baselined: bool,
}

pub struct Tip {
    pub name: String,
    pub oid: String,
    pub peeled: Option<String>,
}

pub struct Observation {
    pub ref_name: String,
    pub oid: String,
    pub peeled: Option<String>,
    pub delivery: Option<DeliveryId>,
    pub observed_ms: UnixMillis,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Admitted {
    pub baseline: usize,
    pub created: usize,
    pub moved: usize,
    pub deleted: usize,
    pub deferred: usize,
}

pub fn configure(
    tx: &Transaction,
    authority: Authority,
    actor: Option<UserId>,
    repo: RepoId,
    spec: &Spec,
    now: UnixMillis,
) -> Result<()> {
    let tenant = tenant_admin_of(tx, authority, repo)?;
    if sources::load_metadata(tx, repo)?.revoked {
        return Err(Error::NotFound);
    }
    if !(MIN_INTERVAL_MS..=MAX_INTERVAL_MS).contains(&spec.interval_ms)
        || spec.refs.is_empty()
        || spec.refs.len() > MAX_REFS
        || !spec.refs.iter().all(|r| valid_ref_pattern(r))
    {
        return Err(Error::InvalidInput("poll spec"));
    }
    let refs = serde_json::to_string(&spec.refs).map_err(|_| Error::InvalidInput("poll refs"))?;
    tx.execute(
        "INSERT INTO poll_configs(repo_id,tenant_id,interval_ms,refs,next_poll_ms,failures,baseline_ms,updated_ms)
         VALUES(?1,?2,?3,?4,?5,0,NULL,?6)
         ON CONFLICT(repo_id) DO UPDATE SET interval_ms=?3,refs=?4,next_poll_ms=?5,failures=0,last_error=NULL,baseline_ms=NULL,updated_ms=?6",
        params![repo.as_bytes(), tenant.as_bytes(), spec.interval_ms, refs, now.0, now.0],
    )?;
    tx.execute(
        "DELETE FROM poll_observations WHERE repo_id=?1",
        [repo.as_bytes()],
    )?;
    audit(
        tx,
        tenant,
        repo,
        actor.or_else(|| authority.actor()),
        "poll",
        now,
    )?;
    Ok(())
}

pub fn disable(
    tx: &Transaction,
    authority: Authority,
    actor: Option<UserId>,
    repo: RepoId,
    now: UnixMillis,
) -> Result<()> {
    let tenant = tenant_admin_of(tx, authority, repo)?;
    if tx.execute(
        "DELETE FROM poll_configs WHERE repo_id=?1",
        [repo.as_bytes()],
    )? != 1
    {
        return Err(Error::NotFound);
    }
    tx.execute(
        "DELETE FROM poll_observations WHERE repo_id=?1",
        [repo.as_bytes()],
    )?;
    audit(
        tx,
        tenant,
        repo,
        actor.or_else(|| authority.actor()),
        "poll-disabled",
        now,
    )?;
    Ok(())
}

pub fn drop_config(tx: &Transaction, repo: RepoId) -> Result<()> {
    tx.execute(
        "DELETE FROM poll_configs WHERE repo_id=?1",
        [repo.as_bytes()],
    )?;
    tx.execute(
        "DELETE FROM poll_observations WHERE repo_id=?1",
        [repo.as_bytes()],
    )?;
    Ok(())
}

pub fn due(conn: &Connection, now: UnixMillis, limit: u16) -> Result<Vec<Config>> {
    let mut q = conn.prepare_cached(
        "SELECT repo_id,tenant_id,interval_ms,refs,next_poll_ms,failures,last_error,baseline_ms FROM poll_configs WHERE next_poll_ms<=?1 ORDER BY next_poll_ms LIMIT ?2",
    )?;
    let rows = q
        .query_map(params![now.0, limit], |r| {
            Ok((
                r.get::<_, [u8; 16]>(0)?,
                r.get::<_, [u8; 16]>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, i64>(4)?,
                r.get::<_, i64>(5)?,
                r.get::<_, Option<String>>(6)?,
                r.get::<_, Option<i64>>(7)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    rows.iter().map(config_row).collect()
}

pub fn of_repo(conn: &Connection, repo: RepoId) -> Result<Option<Config>> {
    let row: Option<ConfigRow> = conn
        .prepare_cached(
            "SELECT repo_id,tenant_id,interval_ms,refs,next_poll_ms,failures,last_error,baseline_ms FROM poll_configs WHERE repo_id=?1",
        )?
        .query_row([repo.as_bytes()], |r| {
            Ok((
                r.get::<_, [u8; 16]>(0)?,
                r.get::<_, [u8; 16]>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, i64>(4)?,
                r.get::<_, i64>(5)?,
                r.get::<_, Option<String>>(6)?,
                r.get::<_, Option<i64>>(7)?,
            ))
        })
        .optional()?;
    row.map(|r| config_row(&r)).transpose()
}

type ConfigRow = (
    [u8; 16],
    [u8; 16],
    i64,
    String,
    i64,
    i64,
    Option<String>,
    Option<i64>,
);

fn config_row(row: &ConfigRow) -> Result<Config> {
    Ok(Config {
        repo: RepoId::from_bytes(row.0).map_err(|_| Error::Corrupt("poll repo"))?,
        tenant: TenantId::from_bytes(row.1).map_err(|_| Error::Corrupt("poll tenant"))?,
        interval_ms: row.2,
        refs: serde_json::from_str(&row.3).map_err(|_| Error::Corrupt("poll refs"))?,
        next_poll_ms: row.4,
        failures: row.5,
        last_error: row.6.clone(),
        baselined: row.7.is_some(),
    })
}

pub fn schedule(
    tx: &Transaction,
    repo: RepoId,
    next_poll_ms: i64,
    failures: i64,
    last_error: Option<&str>,
    now: UnixMillis,
) -> Result<()> {
    tx.execute(
        "UPDATE poll_configs SET next_poll_ms=?2,failures=?3,last_error=?4,updated_ms=?5 WHERE repo_id=?1",
        params![repo.as_bytes(), next_poll_ms, failures, last_error, now.0],
    )?;
    Ok(())
}

pub fn observations(conn: &Connection, repo: RepoId) -> Result<Vec<Observation>> {
    let mut q = conn.prepare_cached(
        "SELECT ref_name,oid,peeled,delivery_id,observed_ms FROM poll_observations WHERE repo_id=?1 ORDER BY ref_name",
    )?;
    q.query_map([repo.as_bytes()], |r| {
        Ok(Observation {
            ref_name: r.get(0)?,
            oid: r.get(1)?,
            peeled: r.get(2)?,
            delivery: r
                .get::<_, Option<[u8; 16]>>(3)?
                .map(DeliveryId::from_bytes)
                .transpose()
                .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(3, 0))?,
            observed_ms: UnixMillis(r.get(4)?),
        })
    })?
    .collect::<rusqlite::Result<Vec<_>>>()
    .map_err(Into::into)
}

pub fn admit(
    tx: &Transaction,
    repo: RepoId,
    tips: &[Tip],
    now: UnixMillis,
) -> Result<Option<Admitted>> {
    let Some((tenant, baseline, refs)) = tx
        .prepare_cached("SELECT tenant_id,baseline_ms,refs FROM poll_configs WHERE repo_id=?1")?
        .query_row([repo.as_bytes()], |r| {
            Ok((
                r.get::<_, [u8; 16]>(0)?,
                r.get::<_, Option<i64>>(1)?,
                r.get::<_, String>(2)?,
            ))
        })
        .optional()?
    else {
        return Ok(None);
    };
    let tenant = TenantId::from_bytes(tenant).map_err(|_| Error::Corrupt("poll tenant"))?;
    let selection: Vec<String> =
        serde_json::from_str(&refs).map_err(|_| Error::Corrupt("poll refs"))?;
    let tips: Vec<&Tip> = tips
        .iter()
        .filter(|t| selection.iter().any(|p| ref_matches(p, &t.name)))
        .collect();
    let mut out = Admitted::default();

    if baseline.is_none() {
        // Initial discovery admits nothing, so enabling polling never replays history.
        for &tip in &tips {
            if !valid_tip(tip) {
                continue;
            }
            observe(tx, repo, tenant, tip, None, now)?;
            out.baseline += 1;
        }
        tx.execute(
            "UPDATE poll_configs SET baseline_ms=?2,updated_ms=?2 WHERE repo_id=?1",
            params![repo.as_bytes(), now.0],
        )?;
        return Ok(Some(out));
    }

    // A ref still advertised, however badly, is never a deletion.
    let mut present = std::collections::HashSet::with_capacity(tips.len());
    let mut processed = std::collections::HashSet::with_capacity(tips.len());
    for &tip in &tips {
        present.insert(tip.name.as_str());
        if !valid_tip(tip) || !processed.insert(tip.name.as_str()) {
            continue;
        }
        let previous: Option<(String, Cursor)> = tx
            .prepare_cached(
                "SELECT oid,delivery_id,observed_ms FROM poll_observations
                 WHERE repo_id=?1 AND ref_name=?2",
            )?
            .query_row(params![repo.as_bytes(), tip.name.as_str()], |r| {
                Ok((r.get(0)?, Cursor(r.get(1)?, r.get(2)?)))
            })
            .optional()?;
        let (old, cursor, kind) = match previous {
            Some((oid, _)) if oid == tip.oid => continue,
            Some((oid, cursor)) => (oid, cursor, &mut out.moved),
            None => (
                "0".repeat(tip.oid.len()),
                Cursor(None, now.0),
                &mut out.created,
            ),
        };
        let external = external_id(&tip.name, &old, &tip.oid, &cursor);
        match intake::accept(
            tx,
            repo,
            &intake::NewDelivery {
                provider: PROVIDER,
                external_id: &external,
                event: "ref_update",
                ref_name: &tip.name,
                old_sha: &old,
                new_sha: &tip.oid,
            },
            None,
            now,
        ) {
            Ok(intake::Accepted::Fresh(id)) | Ok(intake::Accepted::Duplicate(id)) => {
                *kind += 1;
                observe(tx, repo, tenant, tip, Some(id), now)?;
            }
            Err(Error::Overloaded) => out.deferred += 1,
            Err(e) => return Err(e),
        }
    }

    let mut q = tx.prepare_cached(
        "SELECT ref_name,oid,delivery_id,observed_ms FROM poll_observations WHERE repo_id=?1",
    )?;
    let cursors: Vec<(String, String, Cursor)> = q
        .query_map([repo.as_bytes()], |r| {
            Ok((r.get(0)?, r.get(1)?, Cursor(r.get(2)?, r.get(3)?)))
        })?
        .collect::<rusqlite::Result<_>>()?;
    for (name, old, cursor) in cursors {
        if present.contains(name.as_str()) {
            continue;
        }
        let new = "0".repeat(old.len());
        let external = external_id(&name, &old, &new, &cursor);
        match intake::accept(
            tx,
            repo,
            &intake::NewDelivery {
                provider: PROVIDER,
                external_id: &external,
                event: "ref_update",
                ref_name: &name,
                old_sha: &old,
                new_sha: &new,
            },
            None,
            now,
        ) {
            Ok(intake::Accepted::Fresh(_)) | Ok(intake::Accepted::Duplicate(_)) => {
                out.deleted += 1;
                tx.execute(
                    "DELETE FROM poll_observations WHERE repo_id=?1 AND ref_name=?2",
                    params![repo.as_bytes(), name],
                )?;
            }
            Err(Error::Overloaded) => out.deferred += 1,
            Err(e) => return Err(e),
        }
    }
    Ok(Some(out))
}

fn valid_tip(tip: &Tip) -> bool {
    sentinel_protocol::intake::valid_ref(&tip.name)
        && sentinel_protocol::intake::valid_sha(&tip.oid)
        && !sentinel_protocol::intake::is_zero_sha(&tip.oid)
        && tip
            .peeled
            .as_deref()
            .is_none_or(sentinel_protocol::intake::valid_sha)
}

struct Cursor(Option<[u8; 16]>, i64);

fn external_id(reference: &str, old: &str, new: &str, cursor: &Cursor) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(reference.as_bytes());
    hasher.update(b"\0");
    hasher.update(old.as_bytes());
    hasher.update(b"\0");
    hasher.update(new.as_bytes());
    hasher.update(b"\0");
    hasher.update(cursor.0.as_ref().map_or(&[][..], |d| &d[..]));
    hasher.update(b"\0");
    hasher.update(&cursor.1.to_le_bytes());
    format!("poll:{}", hasher.finalize().to_hex())
}

fn observe(
    tx: &Transaction,
    repo: RepoId,
    tenant: TenantId,
    tip: &Tip,
    delivery: Option<DeliveryId>,
    now: UnixMillis,
) -> Result<()> {
    tx.execute(
        "INSERT INTO poll_observations(repo_id,tenant_id,ref_name,oid,peeled,delivery_id,observed_ms) VALUES(?1,?2,?3,?4,?5,?6,?7)
         ON CONFLICT(repo_id,ref_name) DO UPDATE SET oid=?4,peeled=?5,delivery_id=?6,observed_ms=?7",
        params![
            repo.as_bytes(),
            tenant.as_bytes(),
            tip.name.as_str(),
            tip.oid.as_str(),
            tip.peeled.as_deref(),
            delivery.map(|d| *d.as_bytes()),
            now.0
        ],
    )?;
    Ok(())
}

fn audit(
    tx: &Transaction,
    tenant: TenantId,
    repo: RepoId,
    actor: Option<UserId>,
    action: &str,
    now: UnixMillis,
) -> Result<()> {
    let recorded = actor.map(|a| *a.as_bytes());
    tx.execute(
        "INSERT INTO source_audit(tenant_id,repo_id,version,actor,action,at_ms) VALUES(?1,?2,0,?3,?4,?5)",
        params![tenant.as_bytes(), repo.as_bytes(), recorded, action, now.0],
    )?;
    Ok(())
}

fn tenant_admin_of(tx: &Transaction, authority: Authority, repo: RepoId) -> Result<TenantId> {
    match authority.principal() {
        Some(principal) => {
            let tenant = crate::auth::require_repo(
                tx,
                principal,
                repo,
                sentinel_core::auth::Permissions::READ,
            )?;
            crate::auth::require_tenant_admin(tx, principal, tenant)?;
            Ok(tenant)
        }
        None => sources::repo_tenant(tx, repo),
    }
}

pub fn selected(config: &Config, reference: &str) -> bool {
    config.refs.iter().any(|p| ref_matches(p, reference))
}
