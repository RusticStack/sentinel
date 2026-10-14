//! Authenticated GitHub control events. Receipt, revocation and rerequest commit
//! together; network refreshes never run on the writer.
use crate::{Error, Result, checks, intake, runs, sources_forge};
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use sentinel_core::{InstallationId, JobState, RepoId, RunId, UnixMillis};

#[derive(Clone, Debug)]
pub enum Event {
    Rerequest {
        installation: u64,
        repository: u64,
        head: String,
        check: Option<(i64, String)>,
        suite: i64,
    },
    Installation {
        installation: u64,
        disable: bool,
    },
    Repositories {
        installation: u64,
        removed: Vec<u64>,
    },
    Repository {
        installation: u64,
        repository: u64,
    },
    /// Organization membership or access changed ([`crate::github_members`]):
    /// `user` is the numeric GitHub account id concerned, `None` for the whole
    /// organization; `removed` is a signed `member_removed`.
    Members {
        installation: u64,
        user: Option<u64>,
        removed: bool,
    },
}

/// Only the signature-verified adapter calls this. Positive events enqueue a
/// fresh API snapshot; webhook bodies never confer grants.
pub fn accept(
    tx: &Transaction<'_>,
    delivery: &str,
    digest: &[u8; 32],
    event: &Event,
    now: UnixMillis,
) -> Result<(String, bool)> {
    if !sentinel_protocol::intake::valid_delivery_id(delivery) {
        return Err(Error::InvalidInput("delivery"));
    }
    let old: Option<(Vec<u8>, String)> = tx
        .query_row(
            "SELECT digest,outcome FROM github_events WHERE delivery=?1",
            [delivery],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    if let Some((old, outcome)) = old {
        return if old == digest {
            Ok((outcome, true))
        } else {
            Err(Error::Conflict)
        };
    }
    let installation = match event {
        Event::Rerequest { installation, .. }
        | Event::Installation { installation, .. }
        | Event::Repositories { installation, .. }
        | Event::Repository { installation, .. }
        | Event::Members { installation, .. } => *installation,
    };
    let installed: Option<[u8; 16]> = tx
        .query_row(
            "SELECT id FROM installations WHERE provider='github' AND external_id=?1",
            [installation.to_string()],
            |r| r.get(0),
        )
        .optional()?;
    let outcome = if let Some(id) = installed {
        let id = InstallationId::from_bytes(id).map_err(|_| Error::Corrupt("installation"))?;
        match event {
            Event::Rerequest {
                repository,
                head,
                check,
                suite,
                ..
            } => rerequest(
                tx,
                installation,
                *repository,
                head,
                check.as_ref(),
                *suite,
                now,
            )?,
            Event::Installation { disable, .. } => {
                sources_forge::remove(tx, id)?;
                schedule(tx, id.as_bytes(), 0, now)?;
                if *disable {
                    "installation_disabled"
                } else {
                    "refresh_pending"
                }
                .into()
            }
            Event::Repositories { removed, .. } => {
                for repo in removed {
                    let repo =
                        i64::try_from(*repo).map_err(|_| Error::InvalidInput("repository"))?;
                    tx.execute("UPDATE source_bindings SET revoked=1,credential=x'',version=version+1 WHERE installation_id=?1 AND forge_repo_id=?2 AND revoked=0",params![id.as_bytes(),repo])?;
                }
                tx.execute(
                    "UPDATE installations SET lifecycle_version=lifecycle_version+1 WHERE id=?1",
                    [id.as_bytes()],
                )?;
                schedule(tx, id.as_bytes(), 0, now)?;
                seed_repos(tx, id, now)?;
                "repository_access_changed".into()
            }
            Event::Repository { repository, .. } => {
                let repository =
                    i64::try_from(*repository).map_err(|_| Error::InvalidInput("repository"))?;
                // Approved remotes never silently follow a rename or transfer.
                tx.execute("UPDATE source_bindings SET revoked=1,credential=x'',version=version+1 WHERE installation_id=?1 AND forge_repo_id=?2 AND revoked=0",params![id.as_bytes(),repository])?;
                "repository_rebind_required".into()
            }
            Event::Members { user, removed, .. } => members(tx, id, *user, *removed, now)?,
        }
    } else {
        "unbound_installation".into()
    };
    tx.execute(
        "INSERT INTO github_events(delivery,digest,outcome,created_ms) VALUES(?1,?2,?3,?4)",
        params![delivery, digest, outcome, now.0],
    )?;
    Ok((outcome, false))
}

/// A membership event for a bound installation. Only a tenant that is
/// GitHub-backed by *this* installation is touched; everything positive is a
/// hint that schedules a check, and a signed removal also revokes at once.
fn members(
    tx: &Transaction<'_>,
    installation: InstallationId,
    user: Option<u64>,
    removed: bool,
    now: UnixMillis,
) -> Result<String> {
    let tenant: Option<[u8; 16]> = tx
        .query_row(
            "SELECT i.tenant_id FROM installations i JOIN tenants t ON t.id = i.tenant_id
             WHERE i.id = ?1 AND i.account_personal = 0 AND t.membership_source = 1",
            [installation.as_bytes()],
            |r| r.get(0),
        )
        .optional()?;
    let Some(tenant) = tenant else {
        return Ok("not_github_backed".into());
    };
    let tenant =
        sentinel_core::TenantId::from_bytes(tenant).map_err(|_| Error::Corrupt("tenant"))?;
    match user {
        Some(user) if removed => {
            let revoked = crate::github_members::member_removed(tx, tenant, user, now)?;
            Ok(if revoked {
                "member_removed"
            } else {
                "member_removed_no_access"
            }
            .into())
        }
        user => {
            crate::github_members::hint(tx, tenant, user, now)?;
            Ok("membership_check_pending".into())
        }
    }
}

/// Receipts younger than this are kept whatever retention an operator asks
/// for: a receipt is what makes a replayed control event (a signed
/// `repository` rename that revokes a binding, say) a recorded no-op, and
/// GitHub redelivers for days, not weeks.
pub const MIN_RECEIPT_RETENTION_MS: i64 = 30 * 24 * 60 * 60 * 1000;

/// Delete control-event receipts older than `before` (and never younger than
/// [`MIN_RECEIPT_RETENTION_MS`] before `now`), oldest first, at most `limit`
/// rows. Receipts are the only unbounded table control events write.
pub fn purge_receipts(
    tx: &Transaction<'_>,
    before: UnixMillis,
    now: UnixMillis,
    limit: u32,
) -> Result<usize> {
    let before = before.0.min(now.0.saturating_sub(MIN_RECEIPT_RETENTION_MS));
    Ok(tx.execute(
        "DELETE FROM github_events WHERE delivery IN (
            SELECT delivery FROM github_events WHERE created_ms <= ?1
            ORDER BY created_ms LIMIT ?2)",
        params![before, limit],
    )?)
}

fn rerequest(
    tx: &Transaction<'_>,
    installation: u64,
    repository: u64,
    head: &str,
    check: Option<&(i64, String)>,
    suite: i64,
    now: UnixMillis,
) -> Result<String> {
    let repository = i64::try_from(repository).map_err(|_| Error::InvalidInput("repository"))?;
    let (tenant, repo) = match intake::github_target(tx, &installation.to_string(), repository) {
        Ok(target) => target,
        Err(Error::NotFound) => return Ok("unbound_repository".into()),
        Err(e) => return Err(e),
    };
    match sources_forge::grant(tx, tenant, repo) {
        Ok(_) => {}
        Err(Error::NotFound) => return Ok("access_removed".into()),
        Err(e) => return Err(e),
    }
    let mut stmt=tx.prepare_cached("SELECT DISTINCT run_id FROM check_publications WHERE repo_id=?1 AND head_sha=?2 AND run_id IS NOT NULL AND ((?3 IS NOT NULL AND check_run_id=?3 AND (external_id=?4 OR (create_seq IS NOT NULL AND ?4=external_id||':'||create_seq))) OR (?3 IS NULL AND (check_suite_id=?5 OR check_suite_id IS NULL))) LIMIT 65")?;
    let ids = stmt
        .query_map(
            params![
                repo.as_bytes(),
                head,
                check.map(|c| c.0),
                check.map(|c| c.1.as_str()),
                suite
            ],
            |r| r.get::<_, [u8; 16]>(0),
        )?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    if ids.len() > 64 {
        return Ok("rerequest_limit".into());
    }
    if ids.is_empty() {
        return Ok("unknown_check".into());
    }
    let mut reran = false;
    for id in ids {
        let run = RunId::from_bytes(id).map_err(|_| Error::Corrupt("run"))?;
        let stale:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM run_provenance p JOIN run_provenance newer ON newer.repo_id=p.repo_id AND newer.trigger=p.trigger AND newer.ref_name IS p.ref_name AND newer.pr_number IS p.pr_number AND newer.created_ms>p.created_ms WHERE p.run_id=?1)",[run.as_bytes()],|r|r.get(0))?;
        if stale {
            continue;
        }
        let jobs = runs::run_jobs(tx, tenant, run)?;
        if jobs.is_empty()
            || jobs
                .iter()
                .any(|(_, s)| !matches!(s, JobState::Terminal(_)))
        {
            continue;
        }
        let spec = runs::get_run_spec(tx, tenant, run)?;
        crate::sources::validate_source(tx, repo, &spec.source)?;
        if jobs.len() != spec.pipeline.jobs.len() {
            return Err(Error::Corrupt("run jobs"));
        }
        // A full immutable DAG rerun preserves attempts, fences and image pins.
        // Each reset is compare-and-set on the terminal state just read, so a
        // job that moved in between is never overwritten.
        // The reset jobs queue on the deadline clock their queue timeout is
        // decided against, not the caller's wall-clock `now`.
        let queued = UnixMillis::steady();
        for ((job, seen), compiled) in jobs.iter().zip(&spec.pipeline.jobs) {
            let ready = compiled.needs.is_empty() && compiled.spec.condition.is_none();
            let state = if ready {
                JobState::Queued
            } else {
                JobState::Blocked
            };
            let reset = tx.execute("UPDATE jobs SET state_code=?1,cancel_requested=0,failure_class=NULL,queued_ms=?2,leased_ms=NULL,preparing_ms=NULL,running_ms=NULL,finalizing_ms=NULL,terminal_ms=NULL WHERE id=?3 AND state_code=?4",params![crate::codec::encode_state(state),if ready{Some(queued.0)}else{None},job.as_bytes(),crate::codec::encode_state(*seen)])?;
            if reset != 1 {
                // The single writer read these states in this very
                // transaction: a miss means the row is not what it was.
                return Err(Error::Corrupt("run job state"));
            }
        }
        // The rerequest starts the cancelled run over: its run-level flag
        // goes with the jobs' (docs/checks.md), or the run could never
        // fetch its source again.
        tx.execute(
            "UPDATE runs SET cancel_requested=0 WHERE id=?1 AND tenant_id=?2",
            params![run.as_bytes(), tenant.as_bytes()],
        )?;
        // Jobs with an `if` were blocked above; decide them against the
        // event the run already carries.
        crate::dispatch::release_dependents(tx, tenant, run, now)?;
        checks::record_run(tx, tenant, run, now)?;
        reran = true;
    }
    Ok(if reran {
        "rerequested"
    } else {
        "active_or_superseded"
    }
    .into())
}

pub fn schedule(tx: &Transaction<'_>, id: &[u8; 16], kind: i64, now: UnixMillis) -> Result<()> {
    tx.execute("INSERT INTO github_refresh(id,kind,next_ms) VALUES(?1,?2,?3) ON CONFLICT(id) DO UPDATE SET seq=seq+1,next_ms=excluded.next_ms,attempts=0",params![id,kind,now.0])?;
    Ok(())
}
pub fn seed(tx: &Transaction<'_>, now: UnixMillis) -> Result<()> {
    tx.execute("INSERT OR IGNORE INTO github_refresh(id,kind,next_ms) SELECT id,0,?1 FROM installations WHERE provider='github'",[now.0])?;
    tx.execute("INSERT OR IGNORE INTO github_refresh(id,kind,next_ms) SELECT repo_id,1,?1 FROM source_bindings WHERE installation_id IS NOT NULL AND revoked=0",[now.0])?;
    Ok(())
}
fn seed_repos(tx: &Transaction<'_>, id: InstallationId, now: UnixMillis) -> Result<()> {
    tx.execute("INSERT INTO github_refresh(id,kind,next_ms) SELECT repo_id,1,?2 FROM source_bindings WHERE installation_id=?1 AND revoked=0 ON CONFLICT(id) DO UPDATE SET seq=seq+1,next_ms=excluded.next_ms,attempts=0",params![id.as_bytes(),now.0])?;
    Ok(())
}
#[derive(Clone, Copy, Debug)]
pub struct Refresh {
    pub id: [u8; 16],
    pub kind: i64,
    pub seq: i64,
    pub attempts: u32,
}
pub fn due(conn: &Connection, now: UnixMillis) -> Result<Option<Refresh>> {
    Ok(conn.query_row("SELECT id,kind,seq,attempts FROM github_refresh WHERE next_ms<=?1 ORDER BY next_ms,id LIMIT 1",[now.0],|r|Ok(Refresh{id:r.get(0)?,kind:r.get(1)?,seq:r.get(2)?,attempts:r.get(3)?})).optional()?)
}
/// Failed passes after which a row is quarantined: it waits an hour between
/// attempts instead of the five-minute back-off ceiling.
pub const QUARANTINE_AFTER: u32 = 12;
const QUARANTINE_MS: i64 = 60 * 60 * 1000;

/// Park the row under the sequence fence. `retry` counts a failed pass and
/// backs off (doubling to five minutes, then an hour once the row has failed
/// [`QUARANTINE_AFTER`] times); otherwise the attempts reset and the row owes
/// the next periodic pass. Every outcome moves `next_ms` into the future: a
/// row is never left due, so a poison row cannot spin the lane.
pub fn settled(tx: &Transaction<'_>, work: &Refresh, now: UnixMillis, retry: bool) -> Result<()> {
    let attempts = if retry {
        work.attempts.saturating_add(1)
    } else {
        0
    };
    let delay = if !retry {
        300_000
    } else if attempts >= QUARANTINE_AFTER {
        QUARANTINE_MS
    } else {
        checks::backoff_ms(attempts)
    };
    tx.execute(
        "UPDATE github_refresh SET attempts=?3,next_ms=?4 WHERE id=?1 AND seq=?2",
        params![work.id, work.seq, attempts, now.0.saturating_add(delay)],
    )?;
    Ok(())
}

/// What a kind-0 refresh needs before the network call: the installation's
/// external id and the lifecycle version the snapshot must be applied
/// against, read at pick time so a newer webhook lands first.
pub struct InstallTarget {
    pub external: u64,
    pub expected: u64,
}

pub fn install_target(conn: &Connection, id: &[u8; 16]) -> Result<Option<InstallTarget>> {
    let row:Option<(String,i64)>=conn.query_row("SELECT external_id,lifecycle_version FROM installations WHERE id=?1 AND provider='github'",[id],|r|Ok((r.get(0)?,r.get(1)?))).optional()?;
    row.map(|(external, version)| {
        Ok(InstallTarget {
            external: external
                .parse()
                .map_err(|_| Error::Corrupt("installation id"))?,
            expected: u64::try_from(version).map_err(|_| Error::Corrupt("lifecycle version"))?,
        })
    })
    .transpose()
}

/// What a kind-1 refresh needs before the network call: the binding under the
/// repository, the installation it trusts and the identity GitHub must still
/// report for the binding to stay valid.
pub struct RepoTarget {
    pub repo: RepoId,
    pub forge_repo: u64,
    pub remote: String,
    /// The installation row id, for scheduling a kind-0 pass when the
    /// installation itself answers "access refused".
    pub installation: [u8; 16],
    pub installation_external: u64,
    pub account: u64,
    /// The binding's version when it was read: a revocation computed from this
    /// read applies only while the binding still has it.
    pub version: i64,
}

pub fn repo_target(conn: &Connection, id: &[u8; 16]) -> Result<Option<RepoTarget>> {
    type Row = ([u8; 16], i64, Vec<u8>, [u8; 16], String, i64, i64);
    let row:Option<Row>=conn.query_row("SELECT b.repo_id,b.forge_repo_id,b.binding,i.id,i.external_id,i.account_id,b.version FROM source_bindings b JOIN installations i ON i.id=b.installation_id WHERE b.repo_id=?1 AND b.revoked=0",[id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?))).optional()?;
    row.map(
        |(repo, forge, binding, installation, external, account, version)| {
            let binding: sentinel_protocol::source::Binding =
                serde_json::from_slice(&binding).map_err(|_| Error::Corrupt("source binding"))?;
            Ok(RepoTarget {
                repo: RepoId::from_bytes(repo).map_err(|_| Error::Corrupt("repo_id"))?,
                forge_repo: u64::try_from(forge).map_err(|_| Error::Corrupt("forge repo"))?,
                remote: binding.remote,
                installation,
                installation_external: external
                    .parse()
                    .map_err(|_| Error::Corrupt("installation id"))?,
                account: u64::try_from(account).map_err(|_| Error::Corrupt("account"))?,
                version,
            })
        },
    )
    .transpose()
}

/// The repositories one installation's bindings name, with the approved
/// remote each must still match, and the version each binding had when read:
/// (repo, forge repository id, remote, version). Read this *before* asking
/// GitHub for the repository list, so a binding created in between is never
/// judged against a list that predates it.
pub fn bound_repositories(
    conn: &Connection,
    installation: &[u8; 16],
) -> Result<Vec<(RepoId, u64, String, i64)>> {
    let mut stmt=conn.prepare_cached("SELECT repo_id,forge_repo_id,binding,version FROM source_bindings WHERE installation_id=?1 AND revoked=0")?;
    let rows = stmt.query_map([installation], |r| {
        Ok((
            r.get::<_, [u8; 16]>(0)?,
            r.get::<_, i64>(1)?,
            r.get::<_, Vec<u8>>(2)?,
            r.get::<_, i64>(3)?,
        ))
    })?;
    let mut out = Vec::new();
    for row in rows {
        let (repo, forge, binding, version) = row?;
        let binding: sentinel_protocol::source::Binding =
            serde_json::from_slice(&binding).map_err(|_| Error::Corrupt("source binding"))?;
        out.push((
            RepoId::from_bytes(repo).map_err(|_| Error::Corrupt("repo_id"))?,
            u64::try_from(forge).map_err(|_| Error::Corrupt("forge repo"))?,
            binding.remote,
            version,
        ));
    }
    Ok(out)
}

/// One binding revoked: the row stays, its credential is destroyed and the
/// version moves so a sealed copy can never be re-opened for new work. The
/// revocation is fenced on the `version` the verdict was computed from: a
/// binding that was changed or re-created since keeps its new state, and the
/// next periodic pass judges it afresh.
fn revoke_binding(tx: &Transaction<'_>, repo: RepoId, version: i64) -> Result<()> {
    tx.execute("UPDATE source_bindings SET revoked=1,credential=x'',version=version+1 WHERE repo_id=?1 AND version=?2 AND revoked=0",params![repo.as_bytes(),version])?;
    Ok(())
}

/// Apply an authenticated installation snapshot, then revoke every binding
/// the reconcile lane proved GitHub no longer grants or names differently.
/// `sources_forge::refresh` fences the snapshot on the lifecycle version read
/// at pick time; `Conflict` means a newer event landed — the caller retries
/// the whole pass rather than writing a stale truth.
pub fn apply_installation(
    tx: &Transaction<'_>,
    work: &Refresh,
    snapshot: sources_forge::Snapshot<'_>,
    revoked: &[(RepoId, i64)],
    now: UnixMillis,
) -> Result<()> {
    sources_forge::refresh(tx, snapshot, now)?;
    for (repo, version) in revoked {
        revoke_binding(tx, *repo, *version)?;
    }
    settled(tx, work, now, false)
}

/// The installation is confirmed gone — the API answered 404, the one answer
/// that revokes. Disable issuance and revoke every binding that trusted it;
/// a reinstalled App is a new installation identity, never this one.
pub fn installation_gone(tx: &Transaction<'_>, work: &Refresh, id: &[u8; 16]) -> Result<()> {
    let id = InstallationId::from_bytes(*id).map_err(|_| Error::Corrupt("installation"))?;
    sources_forge::remove(tx, id)?;
    tx.execute("UPDATE source_bindings SET revoked=1,credential=x'',version=version+1 WHERE installation_id=?1 AND revoked=0",[id.as_bytes()])?;
    finished(tx, work)
}

/// Settle a repository check: revoke the binding when GitHub disowned,
/// renamed or archived it, then park the row for the next periodic pass.
pub fn apply_repository(
    tx: &Transaction<'_>,
    work: &Refresh,
    repo: RepoId,
    version: i64,
    revoke: bool,
    now: UnixMillis,
) -> Result<()> {
    if revoke {
        revoke_binding(tx, repo, version)?;
    }
    settled(tx, work, now, false)
}

/// Drop a refresh row whose target no longer exists. Guarded by `seq` like
/// [`settled`]: a rescheduled row is never deleted under a stale pass.
pub fn finished(tx: &Transaction<'_>, work: &Refresh) -> Result<()> {
    tx.execute(
        "DELETE FROM github_refresh WHERE id=?1 AND seq=?2",
        params![work.id, work.seq],
    )?;
    Ok(())
}
