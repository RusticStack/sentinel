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
                (SELECT a.id FROM attempts a WHERE a.job_id = j.id ORDER BY a.fence DESC LIMIT 1)
         FROM jobs j WHERE j.run_id = ?1 AND j.tenant_id = ?2 ORDER BY j.spec_index",
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
        ))
    })?;
    let mut jobs = Vec::new();
    for row in rows {
        let (id, name, code, class, cancel, fence, timestamps, attempt) = row?;
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
    if !(1..=500).contains(&limit) {
        return Err(Error::InvalidInput("page size"));
    }
    let mut stmt = conn.prepare_cached(
        "SELECT id, source_sha, created_ms FROM runs WHERE tenant_id = ?1 AND repo_id = ?2
         ORDER BY created_ms DESC, id DESC LIMIT ?3",
    )?;
    let rows = stmt.query_map(
        params![tenant.as_bytes(), repo.as_bytes(), i64::from(limit)],
        |r| {
            Ok((
                r.get::<_, [u8; 16]>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, i64>(2)?,
            ))
        },
    )?;
    let mut out = Vec::new();
    for row in rows {
        let (id, sha, created) = row?;
        let id = RunId::from_bytes(id).map_err(|_| Error::Corrupt("run_id"))?;
        let state = crate::jobs::run_state(conn, tenant, id)?;
        out.push(RunSummary {
            id,
            sha,
            created: UnixMillis(created),
            state,
        });
    }
    Ok(out)
}
