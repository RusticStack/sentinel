//! Durable UTC schedules: the row is the schedule, and an occurrence's instant is its identity.
//!
//! Nothing here holds a timer. A pass reads the schedules whose `next_at_ms` is due, claims the
//! occurrence it finds in one transaction and advances the cursor past it, so a controller that
//! restarts, a second controller computing the same instant, or a clock step across it inserts one
//! occurrence row — the table's key is (schedule, instant) — and fires one run. Every occurrence that
//! is not dispatched is still a row: skipped because the previous run was going, missed while the
//! controller was down, or suspended with its tenant.

use rusqlite::{Connection, OptionalExtension, Transaction, params};
use sentinel_core::{RepoId, RunId, TenantId, UnixMillis};
use sentinel_pipeline::cron::{self, Cron};
use sentinel_protocol::intake::valid_ref;

use crate::{
    Error, Result, auth::Authority, codec::TERMINAL_BASE, provenance::Provenance, sources,
};

/// One cron expression is bounded by the parser's own limit; the row repeats it.
pub const MAX_CRON_BYTES: usize = cron::MAX_CRON_BYTES;
/// A claim older than this is the residue of a controller that died between claiming an occurrence
/// and recording what became of it, so the next pass claims it again rather than losing it.
pub const CLAIM_TTL_MS: i64 = 120_000;
/// Schedules one pass claims. The rest stay due and are claimed by the next pass.
pub const MAX_PER_PASS: u32 = 64;
/// Instants one pass records for a single schedule. Beyond it the row still records the gap, and
/// says how many instants it covers is at least this many.
pub const MAX_MISSED_RECORDED: usize = 4096;
/// Settled occurrence rows are kept this long, then purged like any other retained record. A cursor
/// only moves forward, so the dedup key it protects is never older than the gap in front of it.
pub const OCCURRENCE_RETENTION_MS: i64 = 90 * 24 * 60 * 60 * 1_000;

/// What happens when an occurrence comes due and the run its schedule created before it has not
/// finished. `Skip` is the default and leaves that run untouched; `Cancel` gives the newer
/// occurrence the fleet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Overlap {
    Skip = 0,
    Cancel = 1,
}

impl Overlap {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Skip => "skip",
            Self::Cancel => "cancel",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "skip" => Some(Self::Skip),
            "cancel" => Some(Self::Cancel),
            _ => None,
        }
    }
}

/// What became of an occurrence. `Claimed` is transient: a pass that dies holding it leaves the row
/// for `CLAIM_TTL_MS`, after which it is claimed again.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Claimed = 1,
    Dispatched = 2,
    /// The previous run was still going and the schedule's policy is `Overlap::Skip`.
    Overlap = 3,
    /// The controller was not running, or not passing, when it came due.
    Missed = 4,
    /// The tenant was suspended when it came due.
    Suspended = 5,
    /// The occurrence was claimed and could not be dispatched: its reason names why.
    Failed = 6,
}

pub struct Spec {
    pub cron: String,
    pub ref_name: String,
    pub overlap: Overlap,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Schedule {
    pub tenant: TenantId,
    pub repo: RepoId,
    pub cron: String,
    pub ref_name: String,
    pub overlap: Overlap,
    pub enabled: bool,
    /// The first occurrence this schedule has not settled yet.
    pub next_at_ms: i64,
    pub last_at_ms: Option<i64>,
    pub last_run_id: Option<RunId>,
    pub updated_ms: i64,
}

/// One occurrence a pass took ownership of, and the instants older than it the pass recorded as
/// missed in the same write.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Claim {
    pub schedule: Schedule,
    pub at_ms: i64,
    pub skipped: i64,
}

/// Whether a schedule's last run is still going: any job of it in a state below terminal.
fn run_live(tx: &Transaction<'_>, tenant: TenantId, run: Option<RunId>) -> Result<bool> {
    let Some(run) = run else {
        return Ok(false);
    };
    let live: i64 = tx
        .prepare_cached(
            "SELECT EXISTS(SELECT 1 FROM jobs WHERE run_id = ?1 AND tenant_id = ?2 AND state_code < ?3)",
        )?
        .query_row(
            params![run.as_bytes(), tenant.as_bytes(), TERMINAL_BASE],
            |r| r.get(0),
        )?;
    Ok(live != 0)
}

fn suspended(tx: &Transaction<'_>, tenant: TenantId) -> Result<bool> {
    let active: Option<i64> = tx
        .prepare_cached("SELECT active FROM tenants WHERE id = ?1")?
        .query_row([tenant.as_bytes()], |r| r.get(0))
        .optional()?;
    Ok(active != Some(1))
}

fn tenant_admin_of(tx: &Transaction<'_>, authority: Authority, repo: RepoId) -> Result<TenantId> {
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

/// Store (or replace) the repository's schedule. The cursor restarts from the next occurrence after
/// `now`, so an edit neither replays the past nor fires an instant the old expression alone named.
pub fn configure(
    tx: &Transaction<'_>,
    authority: Authority,
    actor: Option<sentinel_core::UserId>,
    repo: RepoId,
    spec: &Spec,
    now: UnixMillis,
) -> Result<i64> {
    let tenant = tenant_admin_of(tx, authority, repo)?;
    let metadata = sources::load_metadata(tx, repo)?;
    if metadata.revoked {
        return Err(Error::NotFound);
    }
    if spec.cron.is_empty() || spec.cron.len() > MAX_CRON_BYTES {
        return Err(Error::InvalidInput("schedule cron"));
    }
    // A schedule reads a ref its binding already allows: it can never widen what the repository may
    // fetch, and a ref the binding does not name is refused here rather than every pass.
    if !valid_ref(&spec.ref_name)
        || !metadata
            .binding
            .allowed_refs
            .iter()
            .any(|p| sentinel_protocol::source::ref_matches(p, &spec.ref_name))
    {
        return Err(Error::InvalidInput("schedule ref"));
    }
    let cron = Cron::parse(&spec.cron).map_err(|_| Error::InvalidInput("schedule cron"))?;
    let next = cron
        .next_after(now.0)
        .ok_or(Error::InvalidInput("schedule cron"))?;
    tx.execute(
        "INSERT INTO schedules(repo_id, tenant_id, cron, ref_name, overlap, enabled, next_at_ms, updated_ms)
         VALUES(?1, ?2, ?3, ?4, ?5, 1, ?6, ?7)
         ON CONFLICT(repo_id) DO UPDATE SET cron = ?3, ref_name = ?4, overlap = ?5, enabled = 1,
             next_at_ms = ?6, updated_ms = ?7",
        params![
            repo.as_bytes(),
            tenant.as_bytes(),
            spec.cron,
            spec.ref_name,
            spec.overlap as i64,
            next,
            now.0
        ],
    )?;
    crate::intake::audit(tx, tenant, repo, actor, "schedule-configured", now)?;
    Ok(next)
}

/// Stop firing this repository's schedule. The row stays so its history and cursor stay readable.
pub fn disable(
    tx: &Transaction<'_>,
    authority: Authority,
    actor: Option<sentinel_core::UserId>,
    repo: RepoId,
    now: UnixMillis,
) -> Result<()> {
    let tenant = tenant_admin_of(tx, authority, repo)?;
    let changed = tx.execute(
        "UPDATE schedules SET enabled = 0, updated_ms = ?2 WHERE repo_id = ?1",
        params![repo.as_bytes(), now.0],
    )?;
    if changed != 1 {
        return Err(Error::NotFound);
    }
    crate::intake::audit(tx, tenant, repo, actor, "schedule-disabled", now)?;
    Ok(())
}

/// The columns `of_repo` and `all` decode, in one place so the two cannot drift.
const COLUMNS: &str =
    "tenant_id, cron, ref_name, overlap, enabled, next_at_ms, last_at_ms, last_run_id, updated_ms";

type Row = (
    [u8; 16],
    String,
    String,
    i64,
    i64,
    i64,
    Option<i64>,
    Option<[u8; 16]>,
    i64,
);

fn decode(repo: RepoId, row: Row) -> Result<Schedule> {
    let (tenant, cron, ref_name, overlap, enabled, next_at_ms, last_at_ms, last_run_id, updated_ms) =
        row;
    let overlap = match overlap {
        0 => Overlap::Skip,
        1 => Overlap::Cancel,
        _ => return Err(Error::Corrupt("schedule overlap")),
    };
    let run = match last_run_id {
        Some(bytes) => Some(RunId::from_bytes(bytes).map_err(|_| Error::Corrupt("run_id"))?),
        None => None,
    };
    Ok(Schedule {
        tenant: TenantId::from_bytes(tenant).map_err(|_| Error::Corrupt("tenant_id"))?,
        repo,
        cron,
        ref_name,
        overlap,
        enabled: enabled != 0,
        next_at_ms,
        last_at_ms,
        last_run_id: run,
        updated_ms,
    })
}

pub fn of_repo(conn: &Connection, repo: RepoId) -> Result<Option<Schedule>> {
    let row = conn
        .prepare_cached(&format!(
            "SELECT {COLUMNS} FROM schedules WHERE repo_id = ?1"
        ))?
        .query_row([repo.as_bytes()], |r| {
            Ok((
                r.get::<_, [u8; 16]>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, i64>(3)?,
                r.get::<_, i64>(4)?,
                r.get::<_, i64>(5)?,
                r.get::<_, Option<i64>>(6)?,
                r.get::<_, Option<[u8; 16]>>(7)?,
                r.get::<_, i64>(8)?,
            ))
        })
        .optional()?;
    row.map(|row| decode(repo, row)).transpose()
}

/// Every schedule, oldest cursor first, for the operator's listing.
pub fn all(conn: &Connection) -> Result<Vec<Schedule>> {
    let mut query = conn.prepare_cached(&format!(
        "SELECT repo_id, {COLUMNS} FROM schedules ORDER BY next_at_ms"
    ))?;
    let rows = query
        .query_map([], |r| {
            Ok((
                r.get::<_, [u8; 16]>(0)?,
                (
                    r.get::<_, [u8; 16]>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, i64>(4)?,
                    r.get::<_, i64>(5)?,
                    r.get::<_, i64>(6)?,
                    r.get::<_, Option<i64>>(7)?,
                    r.get::<_, Option<[u8; 16]>>(8)?,
                    r.get::<_, i64>(9)?,
                ),
            ))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let mut out = Vec::with_capacity(rows.len());
    for (bytes, row) in rows {
        let repo = RepoId::from_bytes(bytes).map_err(|_| Error::Corrupt("repo_id"))?;
        out.push(decode(repo, row)?);
    }
    Ok(out)
}

/// One pass: claim every occurrence that is due, and re-claim the ones a dead controller left
/// claimed. Occurrences that are not dispatched are recorded here, in the same transaction that
/// moves the cursor past them, so no later pass can fire them again.
pub fn claim(tx: &Transaction<'_>, now: UnixMillis, limit: u32) -> Result<Vec<Claim>> {
    let mut claims = reclaim(tx, now)?;
    let due: Vec<[u8; 16]> = tx
        .prepare_cached(
            "SELECT repo_id FROM schedules WHERE enabled = 1 AND next_at_ms <= ?1
             ORDER BY next_at_ms LIMIT ?2",
        )?
        .query_map(params![now.0, i64::from(limit)], |r| r.get(0))?
        .collect::<std::result::Result<_, _>>()?;
    for bytes in due {
        let repo = RepoId::from_bytes(bytes).map_err(|_| Error::Corrupt("repo_id"))?;
        let Some(schedule) = of_repo(tx, repo)? else {
            continue;
        };
        if claims.len() as u32 >= limit {
            break;
        }
        advance(tx, &schedule, now, &mut claims)?;
    }
    Ok(claims)
}

/// Occurrences a pass left claimed and never settled: the controller died mid-resolution.
fn reclaim(tx: &Transaction<'_>, now: UnixMillis) -> Result<Vec<Claim>> {
    let stale: Vec<([u8; 16], i64, [u8; 16], i64)> = tx
        .prepare_cached(
            "SELECT o.schedule_id, o.at_ms, o.tenant_id, o.skipped FROM schedule_occurrences o
             JOIN schedules s ON s.repo_id = o.schedule_id
             WHERE o.state = 1 AND o.claimed_ms <= ?1 AND s.enabled = 1",
        )?
        .query_map([now.0 - CLAIM_TTL_MS], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
        })?
        .collect::<std::result::Result<_, _>>()?;
    let mut claims = Vec::with_capacity(stale.len());
    for (repo, at_ms, tenant, skipped) in stale {
        let repo = RepoId::from_bytes(repo).map_err(|_| Error::Corrupt("repo_id"))?;
        let tenant = TenantId::from_bytes(tenant).map_err(|_| Error::Corrupt("tenant_id"))?;
        let Some(schedule) = of_repo(tx, repo)? else {
            continue;
        };
        if suspended(tx, tenant)? {
            settle(tx, repo, at_ms, State::Suspended, None, now)?;
            continue;
        }
        if schedule.overlap == Overlap::Skip && run_live(tx, tenant, schedule.last_run_id)? {
            settle(tx, repo, at_ms, State::Overlap, None, now)?;
            continue;
        }
        let changed = tx.execute(
            "UPDATE schedule_occurrences SET claimed_ms = ?3
             WHERE schedule_id = ?1 AND at_ms = ?2 AND state = 1",
            params![repo.as_bytes(), at_ms, now.0],
        )?;
        if changed == 1 {
            claims.push(Claim {
                schedule,
                at_ms,
                skipped,
            });
        }
    }
    Ok(claims)
}

/// A schedule is due: record what the last occurrence of the gap becomes, and claim it.
fn advance(
    tx: &Transaction<'_>,
    schedule: &Schedule,
    now: UnixMillis,
    claims: &mut Vec<Claim>,
) -> Result<()> {
    let cron = Cron::parse(&schedule.cron).map_err(|_| Error::Corrupt("schedule cron"))?;
    let Some(latest) = cron.prev_at_or_before(now.0) else {
        // An expression with no occurrence at all cannot be stored (`configure` refuses it), so the
        // row was written by something else: stop firing it rather than spin on it every pass.
        tx.execute(
            "UPDATE schedules SET enabled = 0, updated_ms = ?2 WHERE repo_id = ?1",
            params![schedule.repo.as_bytes(), now.0],
        )?;
        return Ok(());
    };
    if latest < schedule.next_at_ms {
        return Ok(());
    }
    // Everything due before the newest instant is missed: one pass fires one occurrence, so a
    // controller that was down for an hour runs the pipeline once, not once per minute.
    let (older, truncated) = cron.span(schedule.next_at_ms - 1, latest - 1, MAX_MISSED_RECORDED);
    let skipped = older.len() as i64;
    let first = older.first().copied();
    let next = cron.next_after(latest);
    if suspended(tx, schedule.tenant)? {
        record(
            tx,
            schedule,
            latest,
            State::Suspended,
            first,
            skipped,
            None,
            truncated,
            now,
        )?;
    } else if schedule.overlap == Overlap::Skip
        && run_live(tx, schedule.tenant, schedule.last_run_id)?
    {
        record(
            tx,
            schedule,
            latest,
            State::Overlap,
            first,
            skipped,
            None,
            truncated,
            now,
        )?;
    } else {
        if let Some(previous) = schedule.last_run_id
            && schedule.overlap == Overlap::Cancel
        {
            crate::dispatch::cancel_run(tx, schedule.tenant, previous, now)?;
        }
        if record(
            tx,
            schedule,
            latest,
            State::Claimed,
            first,
            skipped,
            None,
            truncated,
            now,
        )? {
            claims.push(Claim {
                schedule: schedule.clone(),
                at_ms: latest,
                skipped,
            });
        }
    }
    // Monotone: a second controller's later pass cannot move the cursor back.
    tx.execute(
        "UPDATE schedules SET next_at_ms = MAX(next_at_ms, ?1), updated_ms = ?2 WHERE repo_id = ?3",
        params![next.unwrap_or(i64::MAX), now.0, schedule.repo.as_bytes()],
    )?;
    Ok(())
}

/// Record one occurrence, and the instants of the gap ahead of it in the same row. Returns whether
/// this pass inserted it: a row already there is the same occurrence recorded by another pass.
#[allow(clippy::too_many_arguments)]
fn record(
    tx: &Transaction<'_>,
    schedule: &Schedule,
    at_ms: i64,
    state: State,
    first_missed: Option<i64>,
    skipped: i64,
    reason: Option<&str>,
    truncated: bool,
    now: UnixMillis,
) -> Result<bool> {
    if let Some(first) = first_missed {
        tx.execute(
            "INSERT OR IGNORE INTO schedule_occurrences
                (schedule_id, at_ms, tenant_id, state, claimed_ms, settled_ms, skipped, reason)
             VALUES(?1, ?2, ?3, ?4, ?5, ?5, ?6, ?7)",
            params![
                schedule.repo.as_bytes(),
                first,
                schedule.tenant.as_bytes(),
                State::Missed as i64,
                now.0,
                skipped,
                if truncated {
                    Some("gap_over_scan")
                } else {
                    reason
                }
            ],
        )?;
    }
    // The gap row above owns the count of instants this pass did not fire, so this row states only
    // its own instant.
    let changed = tx.execute(
        "INSERT OR IGNORE INTO schedule_occurrences
            (schedule_id, at_ms, tenant_id, state, claimed_ms, settled_ms, reason)
         VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            schedule.repo.as_bytes(),
            at_ms,
            schedule.tenant.as_bytes(),
            state as i64,
            (state == State::Claimed).then_some(now.0),
            (state != State::Claimed).then_some(now.0),
            reason
        ],
    )?;
    Ok(changed == 1)
}

/// Finish a claimed occurrence without a run: what it became, and why when a reason exists.
pub fn settle(
    tx: &Transaction<'_>,
    repo: RepoId,
    at_ms: i64,
    state: State,
    reason: Option<&str>,
    now: UnixMillis,
) -> Result<()> {
    debug_assert!(state != State::Claimed && state != State::Dispatched);
    tx.execute(
        "UPDATE schedule_occurrences SET state = ?3, settled_ms = ?4, reason = ?5
         WHERE schedule_id = ?1 AND at_ms = ?2 AND state = 1",
        params![
            repo.as_bytes(),
            at_ms,
            state as i64,
            now.0,
            reason.map(|r| r.chars().take(64).collect::<String>())
        ],
    )?;
    Ok(())
}

/// Turn a claimed occurrence into a run of the pipeline pinned at `spec`'s revision, in the same
/// transaction that records the occurrence, so a crash leaves neither a run without its occurrence
/// nor an occurrence that claims a run it never created.
pub fn dispatch(
    tx: &Transaction<'_>,
    claim: &Claim,
    spec: &sentinel_pipeline::RunSpec,
    images: &[(String, String)],
    provenance: &Provenance,
    now: UnixMillis,
) -> Result<RunId> {
    let changed = tx.execute(
        "UPDATE schedule_occurrences SET settled_ms = ?3
         WHERE schedule_id = ?1 AND at_ms = ?2 AND state = 1",
        params![claim.schedule.repo.as_bytes(), claim.at_ms, now.0],
    )?;
    if changed != 1 {
        return Err(Error::Conflict);
    }
    let (tenant, repo) = (claim.schedule.tenant, claim.schedule.repo);
    let run = RunId::new();
    let jobs = crate::runs::create_run(tx, tenant, repo, run, spec, now)?;
    for (job, (digest, platform)) in jobs.iter().zip(images) {
        crate::runs::resolve_image(tx, tenant, *job, digest, platform)?;
    }
    crate::provenance::insert(tx, provenance, run, now)?;
    crate::runs::apply_concurrency(tx, tenant, run, now)?;
    crate::dispatch::release_dependents(tx, tenant, run, now)?;
    crate::checks::record_run(tx, tenant, run, now)?;
    let changed = tx.execute(
        "UPDATE schedule_occurrences SET state = 2, run_id = ?3
         WHERE schedule_id = ?1 AND at_ms = ?2 AND state = 1",
        params![repo.as_bytes(), claim.at_ms, run.as_bytes()],
    )?;
    if changed != 1 {
        return Err(Error::Conflict);
    }
    tx.execute(
        "UPDATE schedules SET last_at_ms = ?2, last_run_id = ?3, updated_ms = ?4 WHERE repo_id = ?1",
        params![repo.as_bytes(), claim.at_ms, run.as_bytes(), now.0],
    )?;
    Ok(run)
}

/// Settled occurrence rows older than `before`, a bounded batch at a time.
pub fn purge(store: &crate::Store, before: UnixMillis, limit: u32) -> Result<usize> {
    store
        .writer()
        .write(move |tx| purge_settled(tx, before, limit))
}

pub fn purge_settled(tx: &Transaction<'_>, before: UnixMillis, limit: u32) -> Result<usize> {
    Ok(tx.execute(
        "DELETE FROM schedule_occurrences WHERE (schedule_id, at_ms) IN (
            SELECT schedule_id, at_ms FROM schedule_occurrences
             WHERE settled_ms IS NOT NULL AND settled_ms <= ?1 ORDER BY settled_ms LIMIT ?2)",
        params![before.0, i64::from(limit)],
    )?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overlap_names_round_trip() {
        for overlap in [Overlap::Skip, Overlap::Cancel] {
            assert_eq!(Overlap::parse(overlap.as_str()), Some(overlap));
        }
        assert_eq!(Overlap::parse("queue"), None);
        assert_eq!(Overlap::Skip as i64, 0, "skip is the stored default");
    }
}
