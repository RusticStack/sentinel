//! Read models for status (W08): a run with its jobs, and recent runs of a
//! repository. Controller row operations — authorization is the caller's,
//! through `auth::require_repo` on the run's repository.

use rusqlite::{Connection, OptionalExtension, params};
use sentinel_core::{
    AttemptId, AttemptTimestamps, FailureClass, JobId, JobState, RepoId, RunId, RunState, TenantId,
    UnixMillis, aggregate,
};

use crate::{
    Error, Result,
    codec::{decode_failure, decode_state},
    dispatch::LogState,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JobStatus {
    pub id: JobId,
    pub name: String,
    pub state: JobState,
    pub failure_class: Option<FailureClass>,
    pub cancel_requested: bool,
    pub timestamps: AttemptTimestamps,
    /// The newest attempt, if any was ever leased.
    pub attempt: Option<AttemptId>,
    /// Whether that attempt's log end marker is durable — `None` until an
    /// attempt exists.
    pub log_state: Option<LogState>,
    pub fence: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunStatus {
    pub id: RunId,
    pub tenant: TenantId,
    pub repo: RepoId,
    pub sha: String,
    pub created: UnixMillis,
    pub cancel_requested: bool,
    pub state: RunState,
    /// What triggered the run (`push`, `tag`, `pull_request`, `manual`);
    /// `None` only for a run created without provenance.
    pub trigger: Option<String>,
    /// In compiled order.
    pub jobs: Vec<JobStatus>,
}

/// The job verdict visible from one attempt. An older attempt must not
/// inherit the mutable state of a later rerun.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AttemptJobStatus {
    pub current: bool,
    pub state: Option<JobState>,
    pub failure_class: Option<FailureClass>,
}

/// Read the job state only when `attempt` still owns the job. This is an
/// indexed join over the requested attempt and does not build the run-wide
/// status vector for a failure lookup.
///
/// Only a lease advances the fence, so fence equality alone would let an
/// attempt keep "owning" a job that was requeued under it. A requeued job no
/// longer belongs to its last attempt: a rerun (or a push re-trigger)
/// clears `leased_ms`, which only the next lease sets again — so a later
/// cancel or queue timeout of the requeued job is not the old attempt's
/// verdict either. A lapsed or declined offer (`dispatch::give_back`) clears
/// it too, so a job canceled or timed out in the queue after a lapse is not
/// the lapsed attempt's verdict.
pub fn attempt_job_status(
    conn: &Connection,
    tenant: TenantId,
    attempt: AttemptId,
) -> Result<AttemptJobStatus> {
    let (attempt_fence, job_fence, state, failure, leased): (i64, i64, i64, Option<i64>, bool) =
        conn.prepare_cached(
            "SELECT a.fence, j.fence, j.state_code, j.failure_class, j.leased_ms IS NOT NULL
             FROM attempts a JOIN jobs j ON j.id = a.job_id
             WHERE a.id = ?1 AND a.tenant_id = ?2",
        )?
        .query_row(params![attempt.as_bytes(), tenant.as_bytes()], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
            ))
        })
        .optional()?
        .ok_or(Error::NotFound)?;
    let current = attempt_fence == job_fence
        && leased
        && decode_state(state).ok_or(Error::Corrupt("state_code"))? != JobState::Queued;
    Ok(AttemptJobStatus {
        current,
        state: current
            .then(|| decode_state(state).ok_or(Error::Corrupt("state_code")))
            .transpose()?,
        failure_class: if current {
            failure
                .map(|value| decode_failure(value).ok_or(Error::Corrupt("failure_class")))
                .transpose()?
        } else {
            None
        },
    })
}

/// The run and every job of it, in one read snapshot.
pub fn run(conn: &Connection, tenant: TenantId, run: RunId) -> Result<RunStatus> {
    let head: Option<([u8; 16], String, i64, i64)> = conn
        .prepare_cached(
            "SELECT repo_id, source_sha, created_ms, cancel_requested FROM runs
             WHERE id = ?1 AND tenant_id = ?2",
        )?
        .query_row(params![run.as_bytes(), tenant.as_bytes()], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
        })
        .optional()?;
    let Some((repo, sha, created, cancel)) = head else {
        return Err(Error::NotFound);
    };
    let mut stmt = conn.prepare_cached(
        "SELECT j.id, j.name, j.state_code, j.failure_class, j.cancel_requested, j.fence,
                j.queued_ms, j.leased_ms, j.preparing_ms, j.running_ms, j.finalizing_ms, j.terminal_ms,
                a.id, a.log_state
         FROM jobs j
         LEFT JOIN attempts a ON a.id = (
            SELECT a2.id FROM attempts a2 WHERE a2.job_id = j.id ORDER BY a2.fence DESC LIMIT 1)
         WHERE j.run_id = ?1 AND j.tenant_id = ?2 ORDER BY j.spec_index",
    )?;
    let rows = stmt.query_map(params![run.as_bytes(), tenant.as_bytes()], |r| {
        let ms = |i: usize| -> rusqlite::Result<Option<UnixMillis>> {
            Ok(r.get::<_, Option<i64>>(i)?.map(UnixMillis))
        };
        Ok((
            r.get::<_, [u8; 16]>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, i64>(2)?,
            r.get::<_, Option<i64>>(3)?,
            r.get::<_, i64>(4)?,
            r.get::<_, i64>(5)?,
            AttemptTimestamps {
                queued: ms(6)?,
                leased: ms(7)?,
                preparing: ms(8)?,
                running: ms(9)?,
                finalizing: ms(10)?,
                terminal: ms(11)?,
            },
            r.get::<_, Option<[u8; 16]>>(12)?,
            r.get::<_, Option<i64>>(13)?,
        ))
    })?;
    let mut jobs = Vec::new();
    for row in rows {
        let (id, name, code, class, cancel, fence, timestamps, attempt, log_state) = row?;
        jobs.push(JobStatus {
            id: JobId::from_bytes(id).map_err(|_| Error::Corrupt("job_id"))?,
            name,
            state: decode_state(code).ok_or(Error::Corrupt("state_code"))?,
            failure_class: match class {
                None => None,
                Some(c) => Some(decode_failure(c).ok_or(Error::Corrupt("failure_class"))?),
            },
            cancel_requested: cancel != 0,
            timestamps,
            attempt: attempt
                .map(|a| AttemptId::from_bytes(a).map_err(|_| Error::Corrupt("attempt_id")))
                .transpose()?,
            log_state: log_state.map(LogState::from_code).transpose()?,
            fence: fence as u64,
        });
    }
    let state = aggregate(jobs.iter().map(|j| j.state));
    Ok(RunStatus {
        id: run,
        tenant,
        repo: RepoId::from_bytes(repo).map_err(|_| Error::Corrupt("repo_id"))?,
        sha,
        created: UnixMillis(created),
        cancel_requested: cancel != 0,
        state,
        trigger: crate::provenance::trigger_of(conn, run)?,
        jobs,
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunSummary {
    pub id: RunId,
    pub sha: String,
    pub created: UnixMillis,
    pub state: RunState,
    /// From the run's provenance: `push`, `tag`, `pull_request`, `manual`;
    /// `None` only for a run created without provenance.
    pub trigger: Option<String>,
    /// The ref the run was created for (a pull request's base branch).
    pub ref_name: Option<String>,
    pub pr_number: Option<u64>,
}

/// What [`filtered_runs`] narrows a repository's runs to. Each is a range on
/// its own index (migration 45), so a filtered page costs what an
/// unfiltered one does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RunFilter<'a> {
    /// Exactly this ref (`refs/heads/main`, `refs/tags/v1`).
    Ref(&'a str),
    /// Runs of this pull request.
    Pr(u64),
    /// Runs whose pinned commit starts with this lowercase hex prefix,
    /// 7 to 64 characters: long enough that the matching range stays a
    /// handful of rows.
    Sha(&'a str),
}

/// The newest runs of a repository, newest first, at most `limit`.
pub fn recent_runs(
    conn: &Connection,
    tenant: TenantId,
    repo: RepoId,
    limit: u16,
) -> Result<Vec<RunSummary>> {
    runs_page(conn, tenant, repo, None, limit).map(|page| page.runs)
}

/// One page of a repository's runs, newest first.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunPage {
    pub runs: Vec<RunSummary>,
    /// The cursor for the next page — the last listed run — when more runs
    /// exist past this page; `None` on the last page.
    pub next: Option<RunId>,
}

/// Keyset pagination over `runs_by_repo`, newest first: at most `limit`
/// runs strictly older than `before` in `(created_ms, id)` order, so pages
/// stay stable when runs share a millisecond and when new runs arrive
/// between requests. `before` must be a run of this repository, else
/// `NotFound` (a foreign run's timestamp is not revealed). One row past
/// the page is read to tell whether a next page exists, so the last page
/// never needs an empty follow-up request.
pub fn runs_page(
    conn: &Connection,
    tenant: TenantId,
    repo: RepoId,
    before: Option<RunId>,
    limit: u16,
) -> Result<RunPage> {
    if !(1..=500).contains(&limit) {
        return Err(Error::InvalidInput("page size"));
    }
    // The cursor as a key: (created_ms, id). Without one, a key above every
    // real run keeps one statement (and one plan) for both cases.
    let (cursor_ms, cursor_id): (i64, [u8; 16]) = match before {
        None => (i64::MAX, [0xff; 16]),
        Some(run) => {
            let created: i64 = conn
                .prepare_cached(
                    "SELECT created_ms FROM runs WHERE id = ?1 AND tenant_id = ?2 AND repo_id = ?3",
                )?
                .query_row(
                    params![run.as_bytes(), tenant.as_bytes(), repo.as_bytes()],
                    |r| r.get(0),
                )
                .optional()?
                .ok_or(Error::NotFound)?;
            (created, *run.as_bytes())
        }
    };
    let fetch = i64::from(limit) + 1;
    let mut stmt = conn.prepare_cached(PAGE_SQL)?;
    let rows = stmt.query_map(
        params![
            tenant.as_bytes(),
            repo.as_bytes(),
            cursor_ms,
            &cursor_id[..],
            fetch
        ],
        summary_row,
    )?;
    let mut out = Vec::with_capacity(usize::from(limit).min(64));
    for row in rows {
        out.push(row?);
    }
    let more = out.len() > usize::from(limit);
    out.truncate(usize::from(limit));
    // One grouped read for every listed run's job states — the `IN`
    // subquery is the same page, materialized once — rather than a
    // `run_state` query per row.
    let mut states: std::collections::HashMap<[u8; 16], Vec<JobState>> =
        std::collections::HashMap::with_capacity(out.len());
    if !out.is_empty() {
        let mut jobs = conn.prepare_cached(PAGE_JOBS_SQL)?;
        let rows = jobs.query_map(
            params![
                tenant.as_bytes(),
                repo.as_bytes(),
                cursor_ms,
                &cursor_id[..],
                i64::from(limit)
            ],
            |r| Ok((r.get::<_, [u8; 16]>(0)?, r.get::<_, i64>(1)?)),
        )?;
        for row in rows {
            let (run, code) = row?;
            states
                .entry(run)
                .or_default()
                .push(decode_state(code).ok_or(Error::Corrupt("state_code"))?);
        }
    }
    let runs = out
        .into_iter()
        .map(|row| {
            let state = aggregate(states.get(&row.id).into_iter().flatten().copied());
            row.into_summary(state)
        })
        .collect::<Result<Vec<_>>>()?;
    let next = if more {
        runs.last().map(|r| r.id)
    } else {
        None
    };
    Ok(RunPage { runs, next })
}

/// One listed run as its statement reads it, before its jobs are folded
/// into a state. Column order: id, sha, created, trigger, ref, PR.
struct SummaryRow {
    id: [u8; 16],
    sha: String,
    created: i64,
    trigger: Option<String>,
    ref_name: Option<String>,
    pr_number: Option<i64>,
}

fn summary_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<SummaryRow> {
    Ok(SummaryRow {
        id: r.get(0)?,
        sha: r.get(1)?,
        created: r.get(2)?,
        trigger: r.get(3)?,
        ref_name: r.get(4)?,
        pr_number: r.get(5)?,
    })
}

impl SummaryRow {
    fn into_summary(self, state: RunState) -> Result<RunSummary> {
        Ok(RunSummary {
            id: RunId::from_bytes(self.id).map_err(|_| Error::Corrupt("run_id"))?,
            sha: self.sha,
            created: UnixMillis(self.created),
            state,
            trigger: self.trigger,
            ref_name: self.ref_name,
            pr_number: self
                .pr_number
                .map(|n| u64::try_from(n).map_err(|_| Error::Corrupt("pr_number")))
                .transpose()?,
        })
    }
}

/// A page of runs: a range on `runs_by_repo`, whose trailing primary key
/// makes the index `(tenant_id, repo_id, created_ms, id)`; each listed run's
/// provenance is one primary-key probe.
pub const PAGE_SQL: &str =
    "SELECT r.id, r.source_sha, r.created_ms, p.trigger, p.ref_name, p.pr_number
     FROM runs r LEFT JOIN run_provenance p ON p.run_id = r.id
     WHERE r.tenant_id = ?1 AND r.repo_id = ?2 AND (r.created_ms, r.id) < (?3, ?4)
     ORDER BY r.created_ms DESC, r.id DESC LIMIT ?5";

/// Runs of one ref, newest first: a range on `provenance_by_ref`.
pub const REF_PAGE_SQL: &str =
    "SELECT p.run_id, r.source_sha, r.created_ms, p.trigger, p.ref_name, p.pr_number
     FROM run_provenance p JOIN runs r ON r.id = p.run_id
     WHERE p.tenant_id = ?1 AND p.repo_id = ?2 AND p.ref_name = ?3
       AND (p.created_ms, p.run_id) < (?4, ?5)
     ORDER BY p.created_ms DESC, p.run_id DESC LIMIT ?6";

/// Runs of one pull request, newest first: a range on `provenance_by_pr`.
pub const PR_PAGE_SQL: &str =
    "SELECT p.run_id, r.source_sha, r.created_ms, p.trigger, p.ref_name, p.pr_number
     FROM run_provenance p JOIN runs r ON r.id = p.run_id
     WHERE p.tenant_id = ?1 AND p.repo_id = ?2 AND p.pr_number = ?3
       AND (p.created_ms, p.run_id) < (?4, ?5)
     ORDER BY p.created_ms DESC, p.run_id DESC LIMIT ?6";

/// Runs of commits starting with a prefix: a range on `runs_by_sha`
/// (`[prefix, prefix + "g")`, as hex digits sort below `g`), then ordered.
/// A 7-digit prefix matches one commit in all but enormous histories, so the
/// ordering works on that commit's runs, not the repository's.
pub const SHA_PAGE_SQL: &str =
    "SELECT r.id, r.source_sha, r.created_ms, p.trigger, p.ref_name, p.pr_number
     FROM runs r INDEXED BY runs_by_sha LEFT JOIN run_provenance p ON p.run_id = r.id
     WHERE r.tenant_id = ?1 AND r.repo_id = ?2 AND r.source_sha >= ?3 AND r.source_sha < ?4
       AND (r.created_ms, r.id) < (?5, ?6)
     ORDER BY r.created_ms DESC, r.id DESC LIMIT ?7";

/// One page of a repository's runs narrowed by `filter`, newest first, with
/// the same keyset contract as [`runs_page`]: `before` must be a run of this
/// repository (it need not match the filter), and `next` is `None` on the
/// last page. Ref and PR pages are ordered by the provenance row's creation
/// time, written with the run.
pub fn filtered_runs(
    conn: &Connection,
    tenant: TenantId,
    repo: RepoId,
    filter: RunFilter<'_>,
    before: Option<RunId>,
    limit: u16,
) -> Result<RunPage> {
    if !(1..=500).contains(&limit) {
        return Err(Error::InvalidInput("page size"));
    }
    let by_provenance = !matches!(filter, RunFilter::Sha(_));
    let (cursor_ms, cursor_id): (i64, [u8; 16]) = match before {
        None => (i64::MAX, [0xff; 16]),
        Some(run) => {
            let sql = if by_provenance {
                "SELECT created_ms FROM run_provenance
                 WHERE run_id = ?1 AND tenant_id = ?2 AND repo_id = ?3"
            } else {
                "SELECT created_ms FROM runs WHERE id = ?1 AND tenant_id = ?2 AND repo_id = ?3"
            };
            let created: i64 = conn
                .prepare_cached(sql)?
                .query_row(
                    params![run.as_bytes(), tenant.as_bytes(), repo.as_bytes()],
                    |r| r.get(0),
                )
                .optional()?
                .ok_or(Error::NotFound)?;
            (created, *run.as_bytes())
        }
    };
    let fetch = i64::from(limit) + 1;
    let mut out: Vec<SummaryRow> = Vec::with_capacity(usize::from(limit).min(64));
    match filter {
        RunFilter::Ref(name) => {
            if name.is_empty() || name.len() > 1024 {
                return Err(Error::InvalidInput("ref"));
            }
            let mut stmt = conn.prepare_cached(REF_PAGE_SQL)?;
            let rows = stmt.query_map(
                params![
                    tenant.as_bytes(),
                    repo.as_bytes(),
                    name,
                    cursor_ms,
                    &cursor_id[..],
                    fetch
                ],
                summary_row,
            )?;
            for row in rows {
                out.push(row?);
            }
        }
        RunFilter::Pr(number) => {
            let number = i64::try_from(number)
                .ok()
                .filter(|n| *n > 0)
                .ok_or(Error::InvalidInput("pull request number"))?;
            let mut stmt = conn.prepare_cached(PR_PAGE_SQL)?;
            let rows = stmt.query_map(
                params![
                    tenant.as_bytes(),
                    repo.as_bytes(),
                    number,
                    cursor_ms,
                    &cursor_id[..],
                    fetch
                ],
                summary_row,
            )?;
            for row in rows {
                out.push(row?);
            }
        }
        RunFilter::Sha(prefix) => {
            if !(7..=64).contains(&prefix.len())
                || !prefix
                    .bytes()
                    .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
            {
                return Err(Error::InvalidInput("commit prefix"));
            }
            let mut upper = String::with_capacity(prefix.len() + 1);
            upper.push_str(prefix);
            upper.push('g');
            let mut stmt = conn.prepare_cached(SHA_PAGE_SQL)?;
            let rows = stmt.query_map(
                params![
                    tenant.as_bytes(),
                    repo.as_bytes(),
                    prefix,
                    upper,
                    cursor_ms,
                    &cursor_id[..],
                    fetch
                ],
                summary_row,
            )?;
            for row in rows {
                out.push(row?);
            }
        }
    }
    let more = out.len() > usize::from(limit);
    out.truncate(usize::from(limit));
    // Each listed run's job states: one `jobs_by_run` range per run, at
    // most `limit` of them, on one cached statement and one reused buffer.
    let mut jobs = conn.prepare_cached("SELECT state_code FROM jobs WHERE run_id = ?1")?;
    let mut codes = Vec::new();
    let mut runs = Vec::with_capacity(out.len());
    for row in out {
        codes.clear();
        let mut rows = jobs.query([&row.id[..]])?;
        while let Some(job) = rows.next()? {
            codes.push(decode_state(job.get(0)?).ok_or(Error::Corrupt("state_code"))?);
        }
        let state = aggregate(codes.iter().copied());
        runs.push(row.into_summary(state)?);
    }
    let next = if more {
        runs.last().map(|r| r.id)
    } else {
        None
    };
    Ok(RunPage { runs, next })
}

/// The job states of the same page.
pub const PAGE_JOBS_SQL: &str = "SELECT run_id, state_code FROM jobs WHERE run_id IN (
     SELECT id FROM runs
     WHERE tenant_id = ?1 AND repo_id = ?2 AND (created_ms, id) < (?3, ?4)
     ORDER BY created_ms DESC, id DESC LIMIT ?5)";

/// A run's change version for long polls: 64-bit FNV-1a over the run's
/// cancel flag and, for every job in id order (the order `jobs_by_run` already
/// delivers, so no sort), its id, state code, fence, cancel flag and newest
/// attempt's log state. Any state change a
/// status reader can see changes it (with FNV's collision odds). Computed
/// straight off the rows — no allocation — so a parked poll can re-check
/// cheaply after every commit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RunVersion {
    pub version: u64,
    /// Every job is terminal: nothing about the run will change by itself.
    pub finished: bool,
}

const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

#[inline]
fn fnv(mut hash: u64, bytes: &[u8]) -> u64 {
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

/// The per-job rows [`run_version`] hashes. `jobs` is `WITHOUT ROWID`, so
/// `jobs_by_run(run_id)` entries carry the primary key and deliver `id`
/// order for one run: a parked poll's re-check never builds a sort.
pub const VERSION_JOBS_SQL: &str = "SELECT j.id, j.state_code, j.fence, j.cancel_requested,
        (SELECT a.log_state FROM attempts a WHERE a.job_id = j.id
         ORDER BY a.fence DESC LIMIT 1)
     FROM jobs j WHERE j.run_id = ?1 AND j.tenant_id = ?2 ORDER BY j.id";

/// See [`RunVersion`]. `NotFound` for a run outside `tenant`.
pub fn run_version(conn: &Connection, tenant: TenantId, run: RunId) -> Result<RunVersion> {
    let cancel: i64 = conn
        .prepare_cached("SELECT cancel_requested FROM runs WHERE id = ?1 AND tenant_id = ?2")?
        .query_row(params![run.as_bytes(), tenant.as_bytes()], |r| r.get(0))
        .optional()?
        .ok_or(Error::NotFound)?;
    let mut hash = fnv(FNV_OFFSET, &cancel.to_le_bytes());
    let mut finished = true;
    let mut any = false;
    let mut stmt = conn.prepare_cached(VERSION_JOBS_SQL)?;
    let mut rows = stmt.query(params![run.as_bytes(), tenant.as_bytes()])?;
    while let Some(row) = rows.next()? {
        let id: [u8; 16] = row.get(0)?;
        let code: i64 = row.get(1)?;
        let fence: i64 = row.get(2)?;
        let job_cancel: i64 = row.get(3)?;
        // Absent (no attempt yet) hashes apart from every stored code.
        let log_state: i64 = row.get::<_, Option<i64>>(4)?.unwrap_or(-1);
        hash = fnv(hash, &id);
        hash = fnv(hash, &code.to_le_bytes());
        hash = fnv(hash, &fence.to_le_bytes());
        hash = fnv(hash, &job_cancel.to_le_bytes());
        hash = fnv(hash, &log_state.to_le_bytes());
        any = true;
        finished &= matches!(
            decode_state(code).ok_or(Error::Corrupt("state_code"))?,
            JobState::Terminal(_)
        );
    }
    Ok(RunVersion {
        version: hash,
        finished: finished && any,
    })
}
