//! Opt-in bounded ref polling (G07): durable schedules and observation
//! cursors.
//!
//! A repository's poll configuration is tenant-owned and requires a live
//! source binding; it records which ref patterns to watch and when the next
//! poll is due. `admit` compares one remote advertisement to the durable
//! cursor and inserts a normal intake delivery for every transition — the
//! cursor advances only when the delivery it produced commits in the same
//! transaction, so a crash can never skip a change or replay one twice.

use rusqlite::{Connection, OptionalExtension, Transaction, params};
use sentinel_core::{DeliveryId, RepoId, TenantId, UnixMillis, UserId};
use sentinel_protocol::source::{self, ref_matches, valid_ref_pattern};

use crate::{Error, Result, intake, registration::Authority, sources};

/// Provider key a polled transition carries through the delivery table.
pub const PROVIDER: &str = "poll";
pub const MIN_INTERVAL_MS: i64 = 10_000;
pub const MAX_INTERVAL_MS: i64 = 24 * 60 * 60 * 1_000;
pub const MAX_REFS: usize = source::MAX_REFS;

/// What one repository polls for: an interval and the ref patterns it
/// watches. Patterns follow the binding's selector rules exactly.
pub struct Spec {
    pub interval_ms: i64,
    pub refs: Vec<String>,
}

/// A repository's durable poll configuration and schedule.
pub struct Config {
    pub repo: RepoId,
    pub tenant: TenantId,
    pub interval_ms: i64,
    pub refs: Vec<String>,
    pub next_poll_ms: i64,
    pub failures: i64,
    pub last_error: Option<String>,
    /// `true` once the first successful poll has recorded the baseline;
    /// transitions are admitted only after it exists.
    pub baselined: bool,
}

/// One remote tip, as `git ls-remote` advertised it.
pub struct Tip {
    pub name: String,
    pub oid: String,
    /// Peeled commit id for an annotated tag.
    pub peeled: Option<String>,
}

/// The durable cursor for one watched ref.
pub struct Observation {
    pub ref_name: String,
    pub oid: String,
    pub peeled: Option<String>,
    pub delivery: Option<DeliveryId>,
    pub observed_ms: UnixMillis,
}

/// What one `admit` call produced.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Admitted {
    /// The first successful poll only establishes the baseline.
    pub baseline: usize,
    pub created: usize,
    pub moved: usize,
    pub deleted: usize,
    /// Transitions deferred because the delivery queue was full; their
    /// cursors were not advanced and the next poll retries them.
    pub deferred: usize,
}

/// Install or replace a repository's poll configuration. Requires a live
/// source binding (there is no remote or credential to poll without one)
/// and the same authority a binding change does. Replacing the spec rebuilds
/// the baseline from scratch so a changed selection can never fabricate
/// deletions against stale cursors.
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

/// Stop polling a repository: configuration and cursors go together so a
/// later re-enable starts from a clean baseline rather than a stale one.
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

/// Drop a repo's poll state without authority: the binding the config
/// depended on is gone, so the schedule can never succeed again.
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

/// The repositories whose polls have come due, soonest first.
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

/// One repository's poll configuration, for admin and inspection.
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

/// Reschedule one repository's poll and record its failure state. A missing
/// row means the configuration was disabled mid-flight; that is not an
/// error for the lane.
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

/// The durable observation cursor for one repository.
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

/// Admit one remote advertisement against the durable cursor. Only tips the
/// repository's selected patterns cover become observable state — the
/// selection is enforced here, not just by the caller. Returns `None` when
/// the configuration vanished between the poll and this transaction.
///
/// Every transition becomes an ordinary `poll`-provider `ref_update`
/// delivery through `intake::accept`, and the cursor update commits in the
/// same transaction: a crash mid-flight replays the advertisement, whose
/// deterministic delivery ids make the retry a no-op where the delivery
/// already landed.
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
    // The selection is enforced here too, not just by the lane: nothing the
    // caller passed can become observable state outside it.
    let tips: Vec<&Tip> = tips
        .iter()
        .filter(|t| selection.iter().any(|p| ref_matches(p, &t.name)))
        .collect();
    let mut out = Admitted::default();

    if baseline.is_none() {
        // Initial discovery: record what the remote looks like and admit
        // nothing, so enabling polling never replays history.
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

    // `present` is every advertised name, valid or not: a ref the remote
    // still advertises — however badly — is not a deletion.
    let mut present = std::collections::HashSet::with_capacity(tips.len());
    let mut processed = std::collections::HashSet::with_capacity(tips.len());
    for &tip in &tips {
        present.insert(tip.name.as_str());
        if !valid_tip(tip) || !processed.insert(tip.name.as_str()) {
            continue;
        }
        let previous: Option<(String, Option<[u8; 16]>)> = tx
            .prepare_cached(
                "SELECT oid,delivery_id FROM poll_observations WHERE repo_id=?1 AND ref_name=?2",
            )?
            .query_row(params![repo.as_bytes(), tip.name.as_str()], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .optional()?;
        let (old, kind) = match &previous {
            Some((oid, _)) if oid == &tip.oid => continue,
            Some((oid, _)) => (oid.clone(), &mut out.moved),
            None => ("0".repeat(tip.oid.len()), &mut out.created),
        };
        let external = external_id(&tip.name, &old, &tip.oid);
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

    // A watched ref the remote no longer advertises is a deletion. The
    // cursor is dropped only once the deletion delivery lands.
    let mut q = tx.prepare_cached("SELECT ref_name,oid FROM poll_observations WHERE repo_id=?1")?;
    let cursors: Vec<(String, String)> = q
        .query_map([repo.as_bytes()], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect::<rusqlite::Result<_>>()?;
    for (name, old) in cursors {
        if present.contains(name.as_str()) {
            continue;
        }
        let new = "0".repeat(old.len());
        let external = external_id(&name, &old, &new);
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

/// A tip must be shape-valid to ever become a delivery; a remote answering
/// outside the ref contract is skipped rather than wedging the schedule.
fn valid_tip(tip: &Tip) -> bool {
    sentinel_protocol::intake::valid_ref(&tip.name)
        && sentinel_protocol::intake::valid_sha(&tip.oid)
        && !sentinel_protocol::intake::is_zero_sha(&tip.oid)
        && tip
            .peeled
            .as_deref()
            .is_none_or(sentinel_protocol::intake::valid_sha)
}

/// `poll:` plus the transition's digest: the same observed change always
/// maps to the same delivery, so a retried admission is a no-op.
fn external_id(reference: &str, old: &str, new: &str) -> String {
    let digest = blake3::hash(format!("{reference}\0{old}\0{new}").as_bytes());
    format!("poll:{}", digest.to_hex())
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

/// Unused by the lane's own writes but part of the shared filter surface:
/// does this configuration's selection cover `reference`?
pub fn selected(config: &Config, reference: &str) -> bool {
    config.refs.iter().any(|p| ref_matches(p, reference))
}
