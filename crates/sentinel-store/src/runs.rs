//! Run creation, spec retrieval and reruns.
//!
//! A run is created in one transaction with its immutable spec and one job
//! row per compiled job. Jobs with no dependencies start `Queued`; the rest
//! start `Blocked` and are released by the scheduler from the spec's
//! dependency indices. A rerun is a new attempt of an existing job under the
//! same spec; a new dispatch is a new run with its own spec.
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use sentinel_core::{
    Actor, Event, JobControl, JobId, JobState, RepoId, RunId, TenantId, UnixMillis,
};
use sentinel_pipeline::run::{RunSpec, SPEC_FORMAT};

use crate::{
    Error, Result,
    codec::{decode_state, encode_state},
    jobs,
};

/// Default queue priority; lower runs first. Scheduling policy (fairness,
/// aging) adjusts this later without touching the spec.
pub const DEFAULT_PRIORITY: u8 = 5;

/// Insert the run, its spec and its jobs. Returns job IDs in compiled order.
pub fn create_run(
    tx: &Transaction<'_>,
    tenant: TenantId,
    repo: RepoId,
    run: RunId,
    spec: &RunSpec,
    now: UnixMillis,
) -> Result<Vec<JobId>> {
    jobs::insert_run(tx, tenant, repo, run, &spec.source.sha, now)?;
    let bytes = spec.encode().map_err(Error::Spec)?;
    tx.execute(
        "INSERT INTO run_specs(run_id, tenant_id, digest, format, spec) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            run.as_bytes(),
            tenant.as_bytes(),
            spec.pipeline.digest.to_le_bytes(),
            SPEC_FORMAT as i64,
            bytes
        ],
    )?;
    let mut ids = Vec::with_capacity(spec.pipeline.jobs.len());
    let mut mark_index = tx.prepare_cached(
        "UPDATE jobs SET spec_index = ?1, cpu_millis = ?3, memory_bytes = ?4 WHERE id = ?2",
    )?;
    for (index, job) in spec.pipeline.jobs.iter().enumerate() {
        let id = JobId::new();
        jobs::insert_job(
            tx,
            tenant,
            run,
            id,
            &job.name,
            DEFAULT_PRIORITY,
            index as i64,
        )?;
        mark_index.execute(params![
            index as i64,
            id.as_bytes(),
            i64::from(job.spec.resources.cpu_millis),
            i64::try_from(job.spec.resources.memory_bytes)
                .map_err(|_| Error::InvalidInput("memory_bytes"))?
        ])?;
        if let Some(digest) = sentinel_pipeline::run::ImageRef::parse(&job.spec.image)
            .ok()
            .and_then(|image| image.digest)
        {
            tx.execute(
                "UPDATE jobs SET image_digest = ?1 WHERE id = ?2",
                params![digest, id.as_bytes()],
            )?;
        }
        if job.needs.is_empty() {
            jobs::transition(
                tx,
                tenant,
                id,
                Actor::Controller,
                Event::DependenciesSatisfied,
                now,
            )?;
        }
        ids.push(id);
    }
    Ok(ids)
}

/// The image a job will actually run: digest and platform, both durable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedImage {
    pub digest: String,
    pub platform: String,
}

/// Record what the image reference resolved to, once. A spec pinned by digest
/// pre-fills the digest, so resolution must agree with it; the platform is
/// always the resolver's to state. Refuses to change either afterwards, and
/// refuses malformed values before touching the row.
pub fn resolve_image(
    tx: &Transaction<'_>,
    tenant: TenantId,
    job: JobId,
    digest: &str,
    platform: &str,
) -> Result<()> {
    sentinel_pipeline::run::ImageRef::parse(&format!("x@{digest}"))
        .map_err(|_| Error::InvalidInput("image digest"))?;
    if !(5..=64).contains(&platform.len())
        || !platform
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'/' || b == b'-')
        || !platform.contains('/')
    {
        return Err(Error::InvalidInput("image platform"));
    }
    let current: Option<(Option<String>, Option<String>)> = tx
        .prepare_cached(
            "SELECT image_digest, image_platform FROM jobs WHERE id = ?1 AND tenant_id = ?2",
        )?
        .query_row(params![job.as_bytes(), tenant.as_bytes()], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .optional()?;
    let Some((stored_digest, stored_platform)) = current else {
        return Err(Error::NotFound);
    };
    if stored_platform.is_some() || stored_digest.as_deref().is_some_and(|d| d != digest) {
        return Err(Error::Conflict);
    }
    tx.execute(
        "UPDATE jobs SET image_digest = ?3, image_platform = ?4 WHERE id = ?1 AND tenant_id = ?2",
        params![job.as_bytes(), tenant.as_bytes(), digest, platform],
    )?;
    Ok(())
}

/// What a job will run, or `Unresolved` if admission must still wait.
pub fn resolved_image(conn: &Connection, tenant: TenantId, job: JobId) -> Result<ResolvedImage> {
    let row: Option<(Option<String>, Option<String>)> = conn
        .prepare_cached(
            "SELECT image_digest, image_platform FROM jobs WHERE id = ?1 AND tenant_id = ?2",
        )?
        .query_row(params![job.as_bytes(), tenant.as_bytes()], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .optional()?;
    match row {
        None => Err(Error::NotFound),
        Some((Some(digest), Some(platform))) => Ok(ResolvedImage { digest, platform }),
        Some(_) => Err(Error::Unresolved),
    }
}

/// The spec exactly as written at creation.
pub fn get_run_spec(conn: &Connection, tenant: TenantId, run: RunId) -> Result<RunSpec> {
    let (format, bytes): (i64, Vec<u8>) = conn
        .query_row(
            "SELECT format, spec FROM run_specs WHERE run_id = ?1 AND tenant_id = ?2",
            params![run.as_bytes(), tenant.as_bytes()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?
        .ok_or(Error::NotFound)?;
    if format != SPEC_FORMAT as i64 {
        return Err(Error::Corrupt("run_specs.format"));
    }
    RunSpec::decode(&bytes).map_err(|_| Error::Corrupt("run_specs.spec"))
}

/// Job IDs of a run in compiled order, with their current state.
pub fn run_jobs(conn: &Connection, tenant: TenantId, run: RunId) -> Result<Vec<(JobId, JobState)>> {
    let mut stmt = conn.prepare_cached(
        "SELECT id, state_code FROM jobs WHERE run_id = ?1 AND tenant_id = ?2 ORDER BY spec_index",
    )?;
    let rows = stmt.query_map(params![run.as_bytes(), tenant.as_bytes()], |r| {
        Ok((r.get::<_, [u8; 16]>(0)?, r.get::<_, i64>(1)?))
    })?;
    let mut out = Vec::new();
    for row in rows {
        let (id, code) = row?;
        out.push((
            JobId::from_bytes(id).map_err(|_| Error::Corrupt("job_id"))?,
            decode_state(code).ok_or(Error::Corrupt("state_code"))?,
        ));
    }
    Ok(out)
}

/// Rerun a finished job: back to `Queued` under the same spec with attempt
/// history cleared. The fence is untouched; the next lease advances it, so
/// a late completion from the previous attempt still carries a stale fence.
pub fn rerun_job(
    tx: &Transaction<'_>,
    tenant: TenantId,
    job: JobId,
    now: UnixMillis,
) -> Result<JobState> {
    let row = jobs::get_job(tx, tenant, job)?;
    let mut control = JobControl {
        state: row.state,
        fence: row.fence,
        cancel_requested: row.cancel_requested,
    };
    let next = control.apply(Actor::Controller, Event::Rerun)?;
    let changed = tx.execute(
        "UPDATE jobs SET state_code = ?1, failure_class = NULL, queued_ms = ?2,
            leased_ms = NULL, preparing_ms = NULL, running_ms = NULL, finalizing_ms = NULL, terminal_ms = NULL
         WHERE id = ?3 AND tenant_id = ?4 AND state_code = ?5 AND fence = ?6",
        params![
            encode_state(next),
            now.0,
            job.as_bytes(),
            tenant.as_bytes(),
            encode_state(row.state),
            row.fence.0 as i64,
        ],
    )?;
    if changed != 1 {
        return Err(Error::Conflict);
    }
    Ok(next)
}
