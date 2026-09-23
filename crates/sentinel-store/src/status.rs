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
        |r| {
            Ok((
                r.get::<_, [u8; 16]>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, i64>(2)?,
            ))
        },
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
        .map(|(id, sha, created)| {
            Ok(RunSummary {
                id: RunId::from_bytes(id).map_err(|_| Error::Corrupt("run_id"))?,
                sha,
                created: UnixMillis(created),
                state: aggregate(states.get(&id).into_iter().flatten().copied()),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let next = if more {
        runs.last().map(|r| r.id)
    } else {
        None
    };
    Ok(RunPage { runs, next })
}

/// A page of runs: a range on `runs_by_repo`, whose trailing primary key
/// makes the index `(tenant_id, repo_id, created_ms, id)`.
pub const PAGE_SQL: &str = "SELECT id, source_sha, created_ms FROM runs
     WHERE tenant_id = ?1 AND repo_id = ?2 AND (created_ms, id) < (?3, ?4)
     ORDER BY created_ms DESC, id DESC LIMIT ?5";

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
