//! History views over a repository's recent runs: duration percentiles per job, a two-attempt phase comparison and
//! the attempts a cross-run log search walks. Every read is keyed: the newest runs by `runs_by_repo`, a run's jobs by
//! `jobs_by_run` (or `(run_id, name)`), a job's newest attempt by `(job_id, fence)`, so the work is the window, never a
//! table scan ([API](../../../docs/api.md)). The caller authorizes the repository first.

use std::collections::HashMap;

use rusqlite::{Connection, OptionalExtension, params};
use sentinel_core::{AttemptId, JobId, RepoId, RunId, TenantId};
use sentinel_protocol::summary::AttemptSummary;

use crate::{Error, Result};

/// Runs a duration window may cover: the same ceiling as a run page.
pub const MAX_WINDOW_RUNS: u16 = 500;
pub const DEFAULT_WINDOW_RUNS: u16 = 100;
/// Distinct job names one answer reports; a repository that renames jobs often has more over a long window.
pub const MAX_JOB_NAMES: usize = 128;
/// Runs a cross-run log search may cover in all, across its continuation requests.
pub const MAX_SEARCH_RUNS: u16 = 100;
pub const DEFAULT_SEARCH_RUNS: u16 = 20;

pub const PHASE_COUNT: usize = 7;
pub const PHASE_NAMES: [&str; PHASE_COUNT] = [
    "checkout",
    "checkout_fetch",
    "checkout_materialize",
    "image_pull",
    "container_start",
    "steps",
    "finalize",
];
const CHECKOUT: usize = 0;
const IMAGE_PULL: usize = 3;
const CONTAINER_START: usize = 4;
const STEPS: usize = 5;
const FINALIZE: usize = 6;

pub type Phases = [Option<u64>; PHASE_COUNT];

pub fn phases(summary: &AttemptSummary) -> Phases {
    [
        summary.checkout_ns,
        summary.checkout_fetch_ns,
        summary.checkout_materialize_ns,
        summary.image_pull_ns,
        summary.container_start_ns,
        summary.steps_ns,
        summary.finalize_ns,
    ]
}

/// The attempt's duration: the longer of checkout and image pull (they run side by side), then container start, the
/// steps and finalization. Absent unless every one of those was measured, so an attempt that never reached its steps
/// has no duration instead of a short one.
pub fn total_ns(phases: &Phases) -> Option<u64> {
    phases[CHECKOUT]
        .max(phases[IMAGE_PULL])?
        .checked_add(phases[CONTAINER_START]?)?
        .checked_add(phases[STEPS]?)?
        .checked_add(phases[FINALIZE]?)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Percentiles {
    pub count: u32,
    pub p50_ns: u64,
    pub p95_ns: u64,
}

/// Nearest rank: the smallest value with at least `p` percent of the samples at or below it. `values` is sorted by the call.
fn percentiles(values: &mut [u64]) -> Option<Percentiles> {
    if values.is_empty() {
        return None;
    }
    values.sort_unstable();
    let at = |p: usize| values[(values.len() * p).div_ceil(100).max(1) - 1];
    Some(Percentiles {
        count: u32::try_from(values.len()).unwrap_or(u32::MAX),
        p50_ns: at(50),
        p95_ns: at(95),
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sample {
    pub run: RunId,
    pub attempt: AttemptId,
    pub fence: u64,
    pub created_ms: i64,
    pub phases: Phases,
    pub total_ns: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JobDurations {
    pub job: String,
    /// Attempts with a stored, readable summary: the newest one of this job in each run of the window.
    pub attempts: u32,
    pub total: Option<Percentiles>,
    pub phases: [Option<Percentiles>; PHASE_COUNT],
    /// Newest run first; only when the request named the job.
    pub samples: Vec<Sample>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Durations {
    /// Runs asked for, after the ceiling.
    pub requested: u16,
    /// Runs the window actually holds, with their oldest and newest creation time.
    pub runs: u32,
    pub oldest_ms: Option<i64>,
    pub newest_ms: Option<i64>,
    pub jobs: Vec<JobDurations>,
    /// Distinct job names past `MAX_JOB_NAMES` were left out.
    pub truncated: bool,
    /// Stored summaries that did not decode: left out of every figure.
    pub unreadable: u32,
}

pub const WINDOW_SQL: &str = "SELECT COUNT(*), MIN(created_ms), MAX(created_ms) FROM (
        SELECT created_ms FROM runs WHERE tenant_id = ?1 AND repo_id = ?2
        ORDER BY created_ms DESC, id DESC LIMIT ?3)";

pub const DURATIONS_SQL: &str = "SELECT j.name, a.id, a.fence, r.created_ms, r.id, a.summary
    FROM (SELECT id, created_ms FROM runs WHERE tenant_id = ?1 AND repo_id = ?2
          ORDER BY created_ms DESC, id DESC LIMIT ?3) r
    JOIN jobs j ON j.run_id = r.id
    JOIN attempts a ON a.id = (SELECT a2.id FROM attempts a2
        WHERE a2.job_id = j.id AND a2.summary IS NOT NULL ORDER BY a2.fence DESC LIMIT 1)";

pub const JOB_DURATIONS_SQL: &str = "SELECT j.name, a.id, a.fence, r.created_ms, r.id, a.summary
    FROM (SELECT id, created_ms FROM runs WHERE tenant_id = ?1 AND repo_id = ?2
          ORDER BY created_ms DESC, id DESC LIMIT ?3) r
    JOIN jobs j ON j.run_id = r.id AND j.name = ?4
    JOIN attempts a ON a.id = (SELECT a2.id FROM attempts a2
        WHERE a2.job_id = j.id AND a2.summary IS NOT NULL ORDER BY a2.fence DESC LIMIT 1)";

#[derive(Default)]
struct Acc {
    attempts: u32,
    totals: Vec<u64>,
    phases: [Vec<u64>; PHASE_COUNT],
    samples: Vec<Sample>,
}

/// Duration percentiles per job over the newest `runs` runs of the repository (1 to `MAX_WINDOW_RUNS`; more is served
/// as the ceiling). Each run contributes the newest attempt of each job that has a stored summary; `job` narrows the
/// answer to one name and adds its samples.
pub fn durations(
    conn: &Connection,
    tenant: TenantId,
    repo: RepoId,
    runs: u16,
    job: Option<&str>,
) -> Result<Durations> {
    let requested = runs.clamp(1, MAX_WINDOW_RUNS);
    let (count, oldest, newest): (i64, Option<i64>, Option<i64>) =
        conn.prepare_cached(WINDOW_SQL)?.query_row(
            params![tenant.as_bytes(), repo.as_bytes(), i64::from(requested)],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )?;
    let mut by_job: HashMap<String, Acc> = HashMap::new();
    let (mut truncated, mut unreadable) = (false, 0u32);
    let mut stmt = conn.prepare_cached(if job.is_some() {
        JOB_DURATIONS_SQL
    } else {
        DURATIONS_SQL
    })?;
    let mut rows = match job {
        Some(name) => stmt.query(params![
            tenant.as_bytes(),
            repo.as_bytes(),
            i64::from(requested),
            name
        ])?,
        None => stmt.query(params![
            tenant.as_bytes(),
            repo.as_bytes(),
            i64::from(requested)
        ])?,
    };
    while let Some(row) = rows.next()? {
        let blob = row
            .get_ref(5)?
            .as_blob()
            .map_err(|_| Error::Corrupt("attempt summary"))?;
        let Ok(summary) = AttemptSummary::decode(blob) else {
            unreadable += 1;
            continue;
        };
        let name = row
            .get_ref(0)?
            .as_str()
            .map_err(|_| Error::Corrupt("job name"))?;
        if !by_job.contains_key(name) && by_job.len() >= MAX_JOB_NAMES {
            truncated = true;
            continue;
        }
        let acc = match by_job.get_mut(name) {
            Some(acc) => acc,
            None => by_job.entry(name.to_owned()).or_default(),
        };
        let measured = phases(&summary);
        let total = total_ns(&measured);
        acc.attempts += 1;
        acc.totals.extend(total);
        for (values, phase) in acc.phases.iter_mut().zip(measured) {
            values.extend(phase);
        }
        if job.is_some() {
            acc.samples.push(Sample {
                run: RunId::from_bytes(row.get(4)?).map_err(|_| Error::Corrupt("run_id"))?,
                attempt: AttemptId::from_bytes(row.get(1)?)
                    .map_err(|_| Error::Corrupt("attempt_id"))?,
                fence: u64::try_from(row.get::<_, i64>(2)?).map_err(|_| Error::Corrupt("fence"))?,
                created_ms: row.get(3)?,
                phases: measured,
                total_ns: total,
            });
        }
    }
    let mut jobs: Vec<JobDurations> = by_job
        .into_iter()
        .map(|(job, mut acc)| {
            acc.samples
                .sort_unstable_by(|a, b| (b.created_ms, b.run).cmp(&(a.created_ms, a.run)));
            JobDurations {
                job,
                attempts: acc.attempts,
                total: percentiles(&mut acc.totals),
                phases: acc.phases.each_mut().map(|values| percentiles(values)),
                samples: acc.samples,
            }
        })
        .collect();
    jobs.sort_unstable_by(|a, b| a.job.cmp(&b.job));
    Ok(Durations {
        requested,
        runs: u32::try_from(count).unwrap_or(0),
        oldest_ms: oldest,
        newest_ms: newest,
        jobs,
        truncated,
        unreadable,
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Side {
    pub attempt: AttemptId,
    pub run: RunId,
    pub fence: u64,
    pub created_ms: i64,
    /// `None` until the attempt reported its summary.
    pub phases: Option<Phases>,
    pub total_ns: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Comparison {
    pub job: String,
    pub base: Side,
    pub head: Side,
}

/// Head minus base, in nanoseconds, only where both attempts measured the phase.
pub fn delta(base: Option<u64>, head: Option<u64>) -> Option<i64> {
    let (base, head) = (i128::from(base?), i128::from(head?));
    Some(i64::try_from(head - base).unwrap_or(if head > base { i64::MAX } else { i64::MIN }))
}

pub const SIDE_SQL: &str = "SELECT j.name, j.run_id, a.fence, r.created_ms, a.summary
    FROM attempts a JOIN jobs j ON j.id = a.job_id JOIN runs r ON r.id = j.run_id
    WHERE a.id = ?1 AND r.tenant_id = ?2 AND r.repo_id = ?3";

/// Two attempts of one job in this repository, side by side. An attempt of another repository or tenant is
/// `NotFound`, as if it did not exist; attempts of jobs with different names are `InvalidInput`.
pub fn compare(
    conn: &Connection,
    tenant: TenantId,
    repo: RepoId,
    base: AttemptId,
    head: AttemptId,
) -> Result<Comparison> {
    let mut stmt = conn.prepare_cached(SIDE_SQL)?;
    let mut side = |attempt: AttemptId| -> Result<(String, Side)> {
        let (name, run, fence, created_ms, summary): (String, [u8; 16], i64, i64, Option<Vec<u8>>) =
            stmt.query_row(
                params![attempt.as_bytes(), tenant.as_bytes(), repo.as_bytes()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )
            .optional()?
            .ok_or(Error::NotFound)?;
        let measured = summary
            .map(|bytes| {
                AttemptSummary::decode(&bytes)
                    .map(|s| phases(&s))
                    .map_err(|_| Error::Corrupt("attempt summary"))
            })
            .transpose()?;
        Ok((
            name,
            Side {
                attempt,
                run: RunId::from_bytes(run).map_err(|_| Error::Corrupt("run_id"))?,
                fence: u64::try_from(fence).map_err(|_| Error::Corrupt("fence"))?,
                created_ms,
                total_ns: measured.as_ref().and_then(total_ns),
                phases: measured,
            },
        ))
    };
    let (base_job, base) = side(base)?;
    let (head_job, head) = side(head)?;
    if base_job != head_job {
        return Err(Error::InvalidInput("attempts of different jobs"));
    }
    Ok(Comparison {
        job: base_job,
        base,
        head,
    })
}

pub const SEARCH_RUNS_SQL: &str = "SELECT id FROM runs WHERE tenant_id = ?1 AND repo_id = ?2
        AND (created_ms, id) <= (?3, ?4) ORDER BY created_ms DESC, id DESC LIMIT ?5";

/// The newest `runs` runs of the repository, newest first; from `from` (a run of this repository, included) when given.
pub fn search_runs(
    conn: &Connection,
    tenant: TenantId,
    repo: RepoId,
    from: Option<RunId>,
    runs: u16,
) -> Result<Vec<RunId>> {
    let (created, id): (i64, [u8; 16]) = match from {
        None => (i64::MAX, [0xff; 16]),
        Some(run) => (
            conn.prepare_cached(
                "SELECT created_ms FROM runs WHERE id = ?1 AND tenant_id = ?2 AND repo_id = ?3",
            )?
            .query_row(
                params![run.as_bytes(), tenant.as_bytes(), repo.as_bytes()],
                |r| r.get(0),
            )
            .optional()?
            .ok_or(Error::NotFound)?,
            *run.as_bytes(),
        ),
    };
    let mut stmt = conn.prepare_cached(SEARCH_RUNS_SQL)?;
    let rows = stmt.query_map(
        params![
            tenant.as_bytes(),
            repo.as_bytes(),
            created,
            &id[..],
            i64::from(runs.clamp(1, MAX_SEARCH_RUNS))
        ],
        |r| r.get::<_, [u8; 16]>(0),
    )?;
    rows.map(|row| RunId::from_bytes(row?).map_err(|_| Error::Corrupt("run_id")))
        .collect()
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogTarget {
    pub job: JobId,
    pub name: String,
    pub spec_index: i64,
    pub attempt: AttemptId,
    /// When retention removed the attempt's log.
    pub expired_ms: Option<i64>,
}

pub const TARGETS_SQL: &str = "SELECT j.id, j.name, j.spec_index, a.id, a.log_expired_ms
    FROM jobs j JOIN attempts a ON a.id = (SELECT a2.id FROM attempts a2
        WHERE a2.job_id = j.id ORDER BY a2.fence DESC LIMIT 1)
    WHERE j.run_id = ?1 AND j.tenant_id = ?2 AND j.spec_index > ?3 ORDER BY j.spec_index";

pub const TARGET_SQL: &str = "SELECT j.id, j.name, j.spec_index, a.id, a.log_expired_ms
    FROM attempts a JOIN jobs j ON j.id = a.job_id
    WHERE a.id = ?1 AND j.run_id = ?2 AND a.tenant_id = ?3";

fn target(r: &rusqlite::Row<'_>) -> Result<LogTarget> {
    Ok(LogTarget {
        job: JobId::from_bytes(r.get(0)?).map_err(|_| Error::Corrupt("job_id"))?,
        name: r.get(1)?,
        spec_index: r.get(2)?,
        attempt: AttemptId::from_bytes(r.get(3)?).map_err(|_| Error::Corrupt("attempt_id"))?,
        expired_ms: r.get(4)?,
    })
}

/// The newest attempt of each job of `run`, in pipeline order, with the jobs up to and including `after` left out.
pub fn log_targets(
    conn: &Connection,
    tenant: TenantId,
    run: RunId,
    after: Option<i64>,
) -> Result<Vec<LogTarget>> {
    let mut stmt = conn.prepare_cached(TARGETS_SQL)?;
    let mut rows = stmt.query(params![
        run.as_bytes(),
        tenant.as_bytes(),
        after.unwrap_or(-1)
    ])?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        out.push(target(row)?);
    }
    Ok(out)
}

/// One named attempt of `run`, which a continuation resumes in; `NotFound` for an attempt of another run.
pub fn log_target(
    conn: &Connection,
    tenant: TenantId,
    run: RunId,
    attempt: AttemptId,
) -> Result<LogTarget> {
    let mut stmt = conn.prepare_cached(TARGET_SQL)?;
    let mut rows = stmt.query(params![
        attempt.as_bytes(),
        run.as_bytes(),
        tenant.as_bytes()
    ])?;
    match rows.next()? {
        Some(row) => target(row),
        None => Err(Error::NotFound),
    }
}
