use rusqlite::{Connection, OptionalExtension, Transaction, params};
use sentinel_core::{
    Actor, Event, JobControl, JobId, JobState, RepoId, RunId, TenantId, UnixMillis,
};
use sentinel_pipeline::{
    expr::{Context, DependencySummary, HashFilesError, Lookup, Phase, Value},
    run::{RunSpec, SPEC_FORMAT, SPEC_FORMAT_READ_MIN},
};

use crate::{
    Error, Result,
    codec::{TERMINAL_BASE, decode_state, encode_state},
    dispatch, jobs,
    provenance::{self, EventFacts},
};

pub const DEFAULT_PRIORITY: u8 = 5;

pub fn create_run(
    tx: &Transaction<'_>,
    tenant: TenantId,
    repo: RepoId,
    run: RunId,
    spec: &RunSpec,
    now: UnixMillis,
) -> Result<Vec<JobId>> {
    crate::sources::validate_source(tx, repo, &spec.source)?;
    jobs::insert_run(tx, tenant, repo, run, &spec.source.sha, now)?;
    let bytes = spec.encode().map_err(Error::Spec)?;
    tx.execute(
        "INSERT INTO run_specs(run_id, tenant_id, digest, format, spec) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            run.as_bytes(),
            tenant.as_bytes(),
            spec.pipeline.digest.to_le_bytes(),
            i64::from(spec.format()),
            bytes
        ],
    )?;
    let mut ids = Vec::with_capacity(spec.pipeline.jobs.len());
    let group = create_group(tx, tenant, repo, run, spec)?;
    let mut mark_index = tx.prepare_cached(
        "UPDATE jobs SET spec_index = ?1, cpu_millis = ?3, memory_bytes = ?4, timeout_ms = ?5,
                disk_bytes = ?6, arch = ?7, labels = ?8, concurrency_group = ?9,
                requires_secret_delivery = ?10, runtime = ?11
         WHERE id = ?2",
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
                .map_err(|_| Error::InvalidInput("memory_bytes"))?,
            i64::try_from(job.spec.timeout_secs)
                .map_err(|_| Error::InvalidInput("timeout"))?
                .saturating_mul(1000),
            i64::try_from(job.spec.resources.disk_bytes)
                .map_err(|_| Error::InvalidInput("disk_bytes"))?,
            job_arch(job.spec.runs_on.arch),
            dispatch::encode_labels(&job.spec.runs_on.labels)?,
            group,
            job.spec.requires_secret_delivery(),
            dispatch::job_runtime(&job.spec.runs_on),
        ])?;
        if let Ok(image) = sentinel_pipeline::run::ImageRef::parse(&job.spec.image) {
            let name = dispatch::prefetch_name(&image.name).then_some(image.name.as_str());
            if image.digest.is_some() || name.is_some() {
                tx.execute(
                    "UPDATE jobs SET image_digest = COALESCE(?1, image_digest), image_name = ?2
                     WHERE id = ?3",
                    params![image.digest, name, id.as_bytes()],
                )?;
            }
        }
        // A job with an `if` starts blocked: its condition reads the run's event, recorded after this transaction.
        if job.needs.is_empty() && job.spec.condition.is_none() {
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
    if let (Some(group), Some(concurrency)) = (group.as_deref(), spec.pipeline.concurrency.as_ref())
        && concurrency.cancel_in_progress
    {
        supersede(tx, tenant, repo, run, group, now)?;
    }
    Ok(ids)
}

fn job_arch(arch: Option<sentinel_pipeline::schema::Arch>) -> Option<&'static str> {
    match arch {
        Some(sentinel_pipeline::schema::Arch::Amd64) => Some("x86_64"),
        Some(sentinel_pipeline::schema::Arch::Arm64) => Some("aarch64"),
        None => None,
    }
}

const MAX_GROUP_BYTES: usize = 256;

struct RunContext {
    repo: RepoId,
    repo_name: String,
    run: RunId,
    sha: String,
    event: Option<EventFacts>,
}

impl Context for RunContext {
    fn phase(&self) -> Phase {
        Phase::Dispatch
    }

    fn lookup(&self, path: &[String]) -> Lookup {
        let key: Vec<&str> = path.iter().map(String::as_str).collect();
        match key.as_slice() {
            ["event", "sha"] => Lookup::Value(Value::Str(self.sha.clone())),
            ["event", _] => match &self.event {
                None => Lookup::Unresolved,
                Some(event) => Lookup::Value(match key[1] {
                    "name" => Value::Str(event.name.clone()),
                    "ref" => Value::Str(event.ref_name.clone()),
                    "key" => Value::Str(event.key.clone()),
                    "base_ref" => match &event.base_ref {
                        Some(base) => Value::Str(base.clone()),
                        None => Value::Null,
                    },
                    "pr_number" => match event.pr_number {
                        Some(number) => Value::Int(number as i64),
                        None => Value::Null,
                    },
                    _ => return Lookup::Unresolved,
                }),
            },
            ["repo", "id"] => Lookup::Value(Value::Str(self.repo.to_string())),
            ["repo", "name"] => Lookup::Value(Value::Str(self.repo_name.clone())),
            ["run", "id"] => Lookup::Value(Value::Str(self.run.to_string())),
            _ => Lookup::Unresolved,
        }
    }

    fn dependency_summary(&self) -> Option<DependencySummary> {
        None
    }

    fn cancelled(&self) -> Option<bool> {
        Some(false)
    }

    fn hash_files(&self, _patterns: &[&str]) -> std::result::Result<String, HashFilesError> {
        Err(HashFilesError::UnsupportedPlatform)
    }
}

fn render_group(
    conn: &Connection,
    tenant: TenantId,
    repo: RepoId,
    run: RunId,
    spec: &RunSpec,
    event: Option<EventFacts>,
) -> Result<Option<String>> {
    let Some(concurrency) = spec.pipeline.concurrency.as_ref() else {
        return Ok(None);
    };
    let repo_name: String = conn
        .prepare_cached("SELECT name FROM repos WHERE id = ?1 AND tenant_id = ?2")?
        .query_row(params![repo.as_bytes(), tenant.as_bytes()], |r| r.get(0))
        .optional()?
        .ok_or(Error::NotFound)?;
    let context = RunContext {
        repo,
        repo_name,
        run,
        sha: spec.source.sha.clone(),
        event,
    };
    Ok(concurrency.group.render(&context, MAX_GROUP_BYTES).ok())
}

fn create_group(
    conn: &Connection,
    tenant: TenantId,
    repo: RepoId,
    run: RunId,
    spec: &RunSpec,
) -> Result<Option<String>> {
    if spec.pipeline.concurrency.is_none() {
        return Ok(None);
    }
    match provenance::of_run(conn, run)? {
        Some(_) => {
            let event = provenance::event_facts(conn, run)?;
            render_group(conn, tenant, repo, run, spec, Some(event))
        }
        None => render_group(conn, tenant, repo, run, spec, None),
    }
}

pub fn apply_concurrency(
    tx: &Transaction<'_>,
    tenant: TenantId,
    run: RunId,
    now: UnixMillis,
) -> Result<()> {
    let spec = get_run_spec(tx, tenant, run)?;
    let Some(concurrency) = spec.pipeline.concurrency.as_ref() else {
        return Ok(());
    };
    let repo: [u8; 16] = tx
        .prepare_cached("SELECT repo_id FROM runs WHERE id = ?1 AND tenant_id = ?2")?
        .query_row(params![run.as_bytes(), tenant.as_bytes()], |r| r.get(0))
        .optional()?
        .ok_or(Error::NotFound)?;
    let repo = RepoId::from_bytes(repo).map_err(|_| Error::Corrupt("repo_id"))?;
    let event = provenance::event_facts(tx, run)?;
    let Some(group) = render_group(tx, tenant, repo, run, &spec, Some(event))? else {
        return Ok(());
    };
    tx.prepare_cached(
        "UPDATE jobs SET concurrency_group = ?1 WHERE run_id = ?2 AND tenant_id = ?3
           AND (concurrency_group IS NULL OR concurrency_group <> ?1)",
    )?
    .execute(params![group, run.as_bytes(), tenant.as_bytes()])?;
    if concurrency.cancel_in_progress {
        supersede(tx, tenant, repo, run, &group, now)?;
    }
    Ok(())
}

// `<=`, not `<`: runs created in the same millisecond must still supersede one another.
fn supersede(
    tx: &Transaction<'_>,
    tenant: TenantId,
    repo: RepoId,
    run: RunId,
    group: &str,
    now: UnixMillis,
) -> Result<usize> {
    let live: Vec<[u8; 16]> = tx
        .prepare_cached(
            "SELECT DISTINCT r.id FROM runs r JOIN jobs j ON j.run_id = r.id
             WHERE r.tenant_id = ?1 AND r.repo_id = ?2 AND r.id <> ?3
               AND r.created_ms <= (SELECT created_ms FROM runs WHERE id = ?3)
               AND j.concurrency_group = ?4 AND j.state_code < ?5",
        )?
        .query_map(
            params![
                tenant.as_bytes(),
                repo.as_bytes(),
                run.as_bytes(),
                group,
                TERMINAL_BASE
            ],
            |r| r.get::<_, [u8; 16]>(0),
        )?
        .collect::<std::result::Result<_, _>>()?;
    let mut cancelled = 0;
    for old in live {
        let old = RunId::from_bytes(old).map_err(|_| Error::Corrupt("run_id"))?;
        cancelled += dispatch::cancel_run(tx, tenant, old, now)?;
    }
    Ok(cancelled)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedImage {
    pub digest: String,
    pub platform: String,
}

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

pub fn pinned_images(spec: &RunSpec) -> Result<Vec<(String, String)>> {
    let mut out = Vec::with_capacity(spec.pipeline.jobs.len());
    for job in &spec.pipeline.jobs {
        let image = sentinel_pipeline::ImageRef::parse(&job.spec.image)
            .map_err(|_| Error::InvalidInput("image reference"))?;
        let digest = image.digest.ok_or(Error::Unresolved)?;
        let platform = match job.spec.runs_on.arch {
            Some(sentinel_pipeline::schema::Arch::Arm64) => "linux/arm64".to_owned(),
            _ => "linux/amd64".to_owned(),
        };
        out.push((digest, platform));
    }
    Ok(out)
}

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

pub fn get_run_spec(conn: &Connection, tenant: TenantId, run: RunId) -> Result<RunSpec> {
    let (format, bytes): (i64, Vec<u8>) = conn
        .query_row(
            "SELECT format, spec FROM run_specs WHERE run_id = ?1 AND tenant_id = ?2",
            params![run.as_bytes(), tenant.as_bytes()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?
        .ok_or(Error::NotFound)?;
    if !(SPEC_FORMAT_READ_MIN as i64..=SPEC_FORMAT as i64).contains(&format) {
        return Err(Error::Corrupt("run_specs.format"));
    }
    RunSpec::decode(&bytes).map_err(|_| Error::Corrupt("run_specs.spec"))
}

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

// The fence is kept: the next lease advances it, so a late completion from the old attempt stays stale.
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
    reset_terminal_job(tx, tenant, job, &row, next, now, false)?;
    crate::checks::record_job(tx, tenant, job, now)?;
    revive_skipped_dependents(tx, tenant, job, now)?;
    Ok(next)
}

/// Reset one observed terminal job without rewriting its attempt history.
pub(crate) fn reset_terminal_job(
    tx: &Transaction<'_>,
    tenant: TenantId,
    job: JobId,
    observed: &jobs::JobRow,
    next: JobState,
    now: UnixMillis,
    clear_cancel: bool,
) -> Result<()> {
    if !matches!(observed.state, JobState::Terminal(_))
        || !matches!(next, JobState::Queued | JobState::Blocked)
    {
        return Err(Error::InvalidInput("terminal job reset"));
    }
    let changed = tx.execute(
        "UPDATE jobs SET state_code = ?1, failure_class = NULL, queued_ms = ?2,
            leased_ms = NULL, preparing_ms = NULL, running_ms = NULL, finalizing_ms = NULL,
            terminal_ms = NULL, cancel_requested = ?3
         WHERE id = ?4 AND tenant_id = ?5 AND state_code = ?6 AND fence = ?7
           AND cancel_requested = ?8",
        params![
            encode_state(next),
            (next == JobState::Queued).then_some(now.0),
            !clear_cancel && observed.cancel_requested,
            job.as_bytes(),
            tenant.as_bytes(),
            encode_state(observed.state),
            observed.fence.0 as i64,
            observed.cancel_requested,
        ],
    )?;
    if changed != 1 {
        return Err(Error::Conflict);
    }
    Ok(())
}

fn revive_skipped_dependents(
    tx: &Transaction<'_>,
    tenant: TenantId,
    job: JobId,
    now: UnixMillis,
) -> Result<()> {
    let run: [u8; 16] = tx
        .prepare_cached("SELECT run_id FROM jobs WHERE id = ?1 AND tenant_id = ?2")?
        .query_row(params![job.as_bytes(), tenant.as_bytes()], |r| r.get(0))?;
    let run = RunId::from_bytes(run).map_err(|_| Error::Corrupt("run_id"))?;
    tx.prepare_cached(
        "UPDATE runs SET cancel_requested = 0
         WHERE id = ?1 AND tenant_id = ?2 AND cancel_requested = 1",
    )?
    .execute(params![run.as_bytes(), tenant.as_bytes()])?;
    let states = run_jobs(tx, tenant, run)?;
    let Some(origin) = states.iter().position(|(id, _)| *id == job) else {
        return Err(Error::Corrupt("run jobs"));
    };
    let skipped = JobState::Terminal(sentinel_core::Outcome::Skipped);
    if !states[origin + 1..].iter().any(|(_, s)| *s == skipped) {
        return Ok(());
    }
    let spec = get_run_spec(tx, tenant, run)?;
    let mut reached = vec![false; states.len()];
    reached[origin] = true;
    let mut revive = tx.prepare_cached(
        "UPDATE jobs SET state_code = ?1, failure_class = NULL, queued_ms = NULL,
            leased_ms = NULL, preparing_ms = NULL, running_ms = NULL, finalizing_ms = NULL,
            terminal_ms = NULL
         WHERE id = ?2 AND tenant_id = ?3 AND state_code = ?4 AND cancel_requested = 0",
    )?;
    for index in origin + 1..states.len() {
        if states[index].1 != skipped {
            continue;
        }
        let compiled = spec
            .pipeline
            .jobs
            .get(index)
            .ok_or(Error::Corrupt("run_specs.spec"))?;
        if !compiled
            .needs
            .iter()
            .any(|need| reached.get(usize::from(*need)).copied().unwrap_or(false))
        {
            continue;
        }
        let changed = revive.execute(params![
            encode_state(JobState::Blocked),
            states[index].0.as_bytes(),
            tenant.as_bytes(),
            encode_state(skipped),
        ])?;
        if changed == 1 {
            reached[index] = true;
            crate::checks::record_job(tx, tenant, states[index].0, now)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use rusqlite::Connection;
    use sentinel_core::Outcome;

    use super::*;

    const SHA: &str = "0123456789abcdef0123456789abcdef01234567";

    fn terminal_job(cancel_requested: bool) -> (Connection, TenantId, JobId) {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("PRAGMA foreign_keys=ON").unwrap();
        crate::migrate(&mut conn).unwrap();
        let (tenant, repo, run, job) = (TenantId::new(), RepoId::new(), RunId::new(), JobId::new());
        let tx = conn.transaction().unwrap();
        jobs::insert_tenant(&tx, tenant, "acme", UnixMillis(1)).unwrap();
        jobs::insert_repo(&tx, tenant, repo, "app", UnixMillis(1)).unwrap();
        jobs::insert_run(&tx, tenant, repo, run, SHA, UnixMillis(1)).unwrap();
        jobs::insert_job(&tx, tenant, run, job, "build", 5, 1).unwrap();
        tx.execute(
            "UPDATE jobs SET state_code=?1, fence=7, cancel_requested=?2 WHERE id=?3",
            params![
                encode_state(JobState::Terminal(Outcome::Canceled)),
                cancel_requested,
                job.as_bytes()
            ],
        )
        .unwrap();
        tx.commit().unwrap();
        (conn, tenant, job)
    }

    #[test]
    fn a_terminal_reset_rejects_a_stale_fence_snapshot() {
        let (mut conn, tenant, job) = terminal_job(false);
        let observed = jobs::get_job(&conn, tenant, job).unwrap();
        let tx = conn.transaction().unwrap();
        tx.execute("UPDATE jobs SET fence=8 WHERE id=?1", [job.as_bytes()])
            .unwrap();
        assert!(matches!(
            reset_terminal_job(
                &tx,
                tenant,
                job,
                &observed,
                JobState::Queued,
                UnixMillis(2),
                false,
            ),
            Err(Error::Conflict)
        ));
    }

    #[test]
    fn a_terminal_reset_rejects_a_stale_cancel_snapshot() {
        let (mut conn, tenant, job) = terminal_job(true);
        let observed = jobs::get_job(&conn, tenant, job).unwrap();
        let tx = conn.transaction().unwrap();
        tx.execute(
            "UPDATE jobs SET cancel_requested=0 WHERE id=?1",
            [job.as_bytes()],
        )
        .unwrap();
        assert!(matches!(
            reset_terminal_job(
                &tx,
                tenant,
                job,
                &observed,
                JobState::Queued,
                UnixMillis(2),
                true,
            ),
            Err(Error::Conflict)
        ));
    }
}
