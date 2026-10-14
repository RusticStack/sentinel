//! Rows hold coalesced desired state; the seq guard keeps a publisher that read an older generation from overwriting a newer one.

use rusqlite::{Connection, OptionalExtension, Transaction, params};
use sentinel_core::{CheckId, DeliveryId, JobId, RepoId, RunId, TenantId, UnixMillis};

use crate::{Error, Result};

pub const AGGREGATE_SCOPE: &str = "aggregate";
pub const AGGREGATE_NAME: &str = "sentinel / ci";
pub const JOB_PREFIX: &str = "sentinel / ";
pub const EXTERNAL_PREFIX: &str = "sentinel:";

pub const MAX_ATTEMPTS: u32 = 8;
pub const MAX_TERMINAL_ATTEMPTS: u32 = 40;
const BASE_BACKOFF_MS: i64 = 1_000;
const MAX_BACKOFF_MS: i64 = 5 * 60 * 1000;
const TERMINAL_MAX_BACKOFF_MS: i64 = 15 * 60 * 1000;
pub const MAX_DEFER_MS: i64 = 60 * 60 * 1000;
pub const REARM_WINDOW_MS: i64 = 7 * 24 * 60 * 60 * 1000;
pub const REARM_LIMIT: u32 = 1_000;

macro_rules! columns {
    () => {
        "id, tenant_id, repo_id, run_id, delivery_id, scope, name, head_sha,
    external_id, status, conclusion, title, summary, check_run_id, seq, published_seq, state, reason,
    check_suite_id, create_started_ms, create_seq"
    };
}
const COLUMNS: &str = columns!();

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Pending,
    Published,
    Refused,
}

impl State {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Published => "published",
            Self::Refused => "refused",
        }
    }

    const fn decode(code: i64) -> Option<Self> {
        Some(match code {
            0 => Self::Pending,
            1 => Self::Published,
            2 => Self::Refused,
            _ => return None,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    Queued,
    InProgress,
    Completed,
}

impl Status {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::InProgress => "in_progress",
            Self::Completed => "completed",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        Some(match text {
            "queued" => Self::Queued,
            "in_progress" => Self::InProgress,
            "completed" => Self::Completed,
            _ => return None,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Conclusion {
    Success,
    Failure,
    Neutral,
    Cancelled,
    TimedOut,
    Skipped,
}

impl Conclusion {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Failure => "failure",
            Self::Neutral => "neutral",
            Self::Cancelled => "cancelled",
            Self::TimedOut => "timed_out",
            Self::Skipped => "skipped",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        Some(match text {
            "success" => Self::Success,
            "failure" => Self::Failure,
            "neutral" => Self::Neutral,
            "cancelled" => Self::Cancelled,
            "timed_out" => Self::TimedOut,
            "skipped" => Self::Skipped,
            _ => return None,
        })
    }

    fn of_reason(reason: &str) -> Option<Conclusion> {
        Some(match reason {
            "ref_deleted" | "duplicate" | "superseded" => return None,
            "no_trigger" | "fork_pr" | "merge_unavailable" => Conclusion::Neutral,
            _ => Conclusion::Failure,
        })
    }

    const fn of_outcome(outcome: sentinel_core::Outcome) -> Conclusion {
        use sentinel_core::Outcome;
        match outcome {
            Outcome::Passed => Self::Success,
            Outcome::Failed | Outcome::InfraFailed => Self::Failure,
            Outcome::TimedOut => Self::TimedOut,
            Outcome::Canceled => Self::Cancelled,
            Outcome::Skipped => Self::Skipped,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Publication {
    pub id: CheckId,
    pub tenant: TenantId,
    pub repo: RepoId,
    pub run: Option<RunId>,
    pub delivery: Option<DeliveryId>,
    pub scope: String,
    pub name: String,
    pub head_sha: String,
    pub external_id: String,
    pub status: Status,
    pub conclusion: Option<Conclusion>,
    pub title: String,
    pub summary: String,
    pub check_run_id: Option<i64>,
    pub check_suite_id: Option<i64>,
    pub create_started_ms: Option<i64>,
    pub create_seq: Option<i64>,
    pub seq: i64,
    pub published_seq: i64,
    pub state: State,
    pub reason: Option<String>,
}

pub fn create_identity(external_id: &str, seq: i64) -> String {
    format!("{external_id}:{seq}")
}

impl Publication {
    pub fn created_identity(&self) -> String {
        match self.create_seq {
            Some(seq) => create_identity(&self.external_id, seq),
            None => self.external_id.clone(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Retry {
    Scheduled { attempts: u32, next_attempt_ms: i64 },
    Exhausted,
}

pub fn backoff_ms(attempts: u32) -> i64 {
    BASE_BACKOFF_MS
        .saturating_mul(1i64 << attempts.min(20))
        .min(MAX_BACKOFF_MS)
}

fn terminal_backoff_ms(attempts: u32) -> i64 {
    BASE_BACKOFF_MS
        .saturating_mul(1i64 << attempts.min(20))
        .min(TERMINAL_MAX_BACKOFF_MS)
}

fn job_content(
    state: sentinel_core::JobState,
    class: Option<sentinel_core::FailureClass>,
    job: &str,
) -> (Status, Option<Conclusion>, &'static str, String) {
    use sentinel_core::JobState as S;
    match state {
        S::Blocked | S::Queued => (
            Status::Queued,
            None,
            "Queued",
            format!("job {job}: waiting for a worker"),
        ),
        S::Leased | S::Preparing | S::Running | S::Finalizing => (
            Status::InProgress,
            None,
            "Running",
            format!("job {job}: running"),
        ),
        S::Terminal(outcome) => {
            use sentinel_core::Outcome as O;
            let class = class
                .map(sentinel_core::FailureClass::as_str)
                .unwrap_or("-");
            let (title, why) = match (outcome, class) {
                (O::Passed, _) => ("Passed", "passed".to_owned()),
                (O::Skipped, _) => ("Skipped", "a dependency did not pass".to_owned()),
                (O::Canceled, _) => ("Cancelled", "cancellation was requested".to_owned()),
                (O::TimedOut, "queue_timeout") => {
                    ("Timed out", "waited too long for a worker".to_owned())
                }
                (O::TimedOut, _) => ("Timed out", "exceeded its time budget".to_owned()),
                (O::Failed, "command_failed") => ("Failed", "a command exited non-zero".to_owned()),
                (O::Failed, "command_signaled") => {
                    ("Failed", "a command was killed by a signal".to_owned())
                }
                (O::Failed, "out_of_memory") => {
                    ("Failed", "the container ran out of memory".to_owned())
                }
                (O::Failed, _) => ("Failed", "failed".to_owned()),
                (O::InfraFailed, _) => (
                    "Infrastructure failure",
                    format!("sentinel could not run it ({class})"),
                ),
            };
            (
                Status::Completed,
                Some(Conclusion::of_outcome(outcome)),
                title,
                format!("job {job}: {why}"),
            )
        }
    }
}

fn aggregate_content(
    states: impl Iterator<Item = sentinel_core::JobState>,
) -> Result<(Status, Option<Conclusion>, &'static str, String)> {
    use sentinel_core::{JobState, Outcome as O};
    let (mut total, mut passed, mut failed, mut skipped, mut cancelled) = (0usize, 0, 0, 0, 0);
    let state = sentinel_core::aggregate(states.inspect(|state| {
        total += 1;
        if let JobState::Terminal(outcome) = state {
            match outcome {
                O::Passed => passed += 1,
                O::Failed | O::InfraFailed => failed += 1,
                O::Skipped => skipped += 1,
                O::Canceled => cancelled += 1,
                O::TimedOut => {}
            }
        }
    }));
    if total == 0 {
        return Err(Error::Corrupt("run has no jobs"));
    }
    let summary = format!(
        "{passed}/{total} jobs passed · {failed} failed · {skipped} skipped · {cancelled} cancelled",
    );
    Ok(match state {
        sentinel_core::RunState::Pending => (
            Status::Queued,
            None,
            "Queued",
            format!("{total} jobs waiting for a worker"),
        ),
        sentinel_core::RunState::Active => (Status::InProgress, None, "Running", summary),
        sentinel_core::RunState::Terminal(outcome) => {
            let title = match outcome {
                O::Passed => "Passed",
                O::Skipped => "Skipped",
                O::Canceled => "Cancelled",
                O::TimedOut => "Timed out",
                O::Failed => "Failed",
                O::InfraFailed => "Infrastructure failure",
            };
            (
                Status::Completed,
                Some(Conclusion::of_outcome(outcome)),
                title,
                summary,
            )
        }
    })
}

struct RunFacts {
    repo: RepoId,
    head_sha: String,
}

fn run_facts(conn: &Connection, tenant: TenantId, run: RunId) -> Result<Option<RunFacts>> {
    let row: Option<(String, [u8; 16], i64, Option<String>)> = conn
        .prepare_cached(
            "SELECT COALESCE(p.head_sha, r.source_sha), r.repo_id, (b.installation_id IS NOT NULL), p.trigger
             FROM runs r
             LEFT JOIN source_bindings b ON b.repo_id = r.repo_id AND b.revoked = 0
             LEFT JOIN run_provenance p ON p.run_id = r.id
             WHERE r.id = ?1 AND r.tenant_id = ?2",
        )?
        .query_row(params![run.as_bytes(), tenant.as_bytes()], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
        })
        .optional()?;
    let Some((head_sha, repo, forge, trigger)) = row else {
        return Ok(None);
    };
    // A manual run's inline pipeline is diagnostic and must never satisfy the required aggregate.
    let event_driven = matches!(trigger.as_deref(), Some("push" | "tag" | "pull_request"));
    if forge == 0 || !event_driven {
        return Ok(None);
    }
    Ok(Some(RunFacts {
        repo: RepoId::from_bytes(repo).map_err(|_| Error::Corrupt("repo_id"))?,
        head_sha,
    }))
}

struct Draft<'a> {
    tenant: TenantId,
    repo: RepoId,
    run: Option<RunId>,
    delivery: Option<DeliveryId>,
    scope: &'a str,
    name: &'a str,
    head_sha: &'a str,
    external: String,
    status: Status,
    conclusion: Option<Conclusion>,
    title: &'static str,
    summary: String,
}

/// A generation after a delivered completed one drops the stale run handle: GitHub keeps a completed run completed.
fn upsert(tx: &Transaction<'_>, draft: Draft<'_>, now: UnixMillis) -> Result<()> {
    let id = CheckId::new();
    tx.prepare_cached(
        "INSERT INTO check_publications(id, tenant_id, repo_id, run_id, delivery_id, scope, name,
            head_sha, external_id, status, conclusion, title, summary, seq, state, created_ms, updated_ms)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, 1, 0, ?14, ?14)
         ON CONFLICT(run_id, scope) WHERE run_id IS NOT NULL DO UPDATE SET
            status = excluded.status, conclusion = excluded.conclusion,
            title = excluded.title, summary = excluded.summary,
            check_run_id = CASE WHEN check_publications.status = 'completed'
                AND check_publications.state = 1
                AND check_publications.published_seq = check_publications.seq
                THEN NULL ELSE check_publications.check_run_id END,
            create_started_ms = CASE WHEN check_publications.status = 'completed'
                AND check_publications.state = 1
                AND check_publications.published_seq = check_publications.seq
                THEN NULL ELSE check_publications.create_started_ms END,
            create_seq = CASE WHEN check_publications.status = 'completed'
                AND check_publications.state = 1
                AND check_publications.published_seq = check_publications.seq
                THEN NULL ELSE check_publications.create_seq END,
            seq = check_publications.seq + 1, state = 0, reason = NULL, attempts = 0,
            next_attempt_ms = NULL, settled_ms = NULL, updated_ms = excluded.updated_ms
         WHERE check_publications.state = 2
            OR check_publications.status IS NOT excluded.status
            OR check_publications.conclusion IS NOT excluded.conclusion
            OR check_publications.title IS NOT excluded.title
            OR check_publications.summary IS NOT excluded.summary",
    )?
    .execute(params![
            id.as_bytes(),
            draft.tenant.as_bytes(),
            draft.repo.as_bytes(),
            draft.run.map(|r| r.as_bytes().to_vec()),
            draft.delivery.map(|d| d.as_bytes().to_vec()),
            draft.scope,
            draft.name,
            draft.head_sha,
            draft.external,
            draft.status.as_str(),
            draft.conclusion.map(Conclusion::as_str),
            draft.title,
            draft.summary,
            now.0
        ],
    )?;
    Ok(())
}

fn external_id(run: RunId, scope: &str) -> String {
    format!("{EXTERNAL_PREFIX}{run}:{scope}")
}

pub fn record_run(
    tx: &Transaction<'_>,
    tenant: TenantId,
    run: RunId,
    now: UnixMillis,
) -> Result<usize> {
    let Some(facts) = run_facts(tx, tenant, run)? else {
        return Ok(0);
    };
    let rows: Vec<([u8; 16], String)> = tx
        .prepare_cached(
            "SELECT id, name FROM jobs WHERE run_id = ?1 AND tenant_id = ?2 ORDER BY spec_index",
        )?
        .query_map(params![run.as_bytes(), tenant.as_bytes()], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })?
        .collect::<std::result::Result<_, _>>()?;
    let mut written = 0;
    for (job, job_name) in &rows {
        let job = JobId::from_bytes(*job).map_err(|_| Error::Corrupt("job_id"))?;
        let (status, conclusion, title, summary) =
            job_content(sentinel_core::JobState::Queued, None, job_name);
        let scope = job.to_string();
        upsert(
            tx,
            Draft {
                tenant,
                repo: facts.repo,
                run: Some(run),
                delivery: None,
                scope: &scope,
                name: &qualified_name(job_name),
                head_sha: &facts.head_sha,
                external: external_id(run, &scope),
                status,
                conclusion,
                title,
                summary,
            },
            now,
        )?;
        written += 1;
    }
    written += record_aggregate(tx, tenant, run, &facts, now)?;
    Ok(written)
}

pub fn qualified_name(job: &str) -> String {
    let mut name = String::with_capacity(JOB_PREFIX.len() + job.len());
    name.push_str(JOB_PREFIX);
    name.push_str(job);
    name
}

fn record_aggregate(
    tx: &Transaction<'_>,
    tenant: TenantId,
    run: RunId,
    facts: &RunFacts,
    now: UnixMillis,
) -> Result<usize> {
    let mut stmt =
        tx.prepare_cached("SELECT state_code FROM jobs WHERE run_id = ?1 AND tenant_id = ?2")?;
    let mut rows = stmt.query(params![run.as_bytes(), tenant.as_bytes()])?;
    let mut fault = None;
    let content =
        aggregate_content(std::iter::from_fn(|| match rows.next() {
            Ok(Some(row)) => match row.get::<_, i64>(0).map_err(Error::from).and_then(|code| {
                crate::codec::decode_state(code).ok_or(Error::Corrupt("state_code"))
            }) {
                Ok(state) => Some(state),
                Err(e) => {
                    fault = Some(e);
                    None
                }
            },
            Ok(None) => None,
            Err(e) => {
                fault = Some(Error::from(e));
                None
            }
        }));
    if let Some(e) = fault {
        return Err(e);
    }
    let (status, conclusion, title, summary) = content?;
    upsert(
        tx,
        Draft {
            tenant,
            repo: facts.repo,
            run: Some(run),
            delivery: None,
            scope: AGGREGATE_SCOPE,
            name: AGGREGATE_NAME,
            head_sha: &facts.head_sha,
            external: external_id(run, AGGREGATE_SCOPE),
            status,
            conclusion,
            title,
            summary,
        },
        now,
    )?;
    Ok(1)
}

pub fn record_job(
    tx: &Transaction<'_>,
    tenant: TenantId,
    job: JobId,
    now: UnixMillis,
) -> Result<()> {
    let row: Option<([u8; 16], String, i64, Option<i64>)> = tx
        .prepare_cached(
            "SELECT run_id, name, state_code, failure_class FROM jobs
             WHERE id = ?1 AND tenant_id = ?2",
        )?
        .query_row(params![job.as_bytes(), tenant.as_bytes()], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
        })
        .optional()?;
    let Some((run, name, code, class)) = row else {
        return Err(Error::Corrupt("job"));
    };
    let run = RunId::from_bytes(run).map_err(|_| Error::Corrupt("run_id"))?;
    let Some(facts) = run_facts(tx, tenant, run)? else {
        return Ok(());
    };
    let state = crate::codec::decode_state(code).ok_or(Error::Corrupt("state_code"))?;
    let class = match class {
        None => None,
        Some(code) => {
            Some(crate::codec::decode_failure(code).ok_or(Error::Corrupt("failure_class"))?)
        }
    };
    let (status, conclusion, title, summary) = job_content(state, class, &name);
    let scope = job.to_string();
    upsert(
        tx,
        Draft {
            tenant,
            repo: facts.repo,
            run: Some(run),
            delivery: None,
            scope: &scope,
            name: &qualified_name(&name),
            head_sha: &facts.head_sha,
            external: external_id(run, &scope),
            status,
            conclusion,
            title,
            summary,
        },
        now,
    )?;
    record_aggregate(tx, tenant, run, &facts, now)?;
    Ok(())
}

pub fn record_delivery(
    tx: &Transaction<'_>,
    delivery: DeliveryId,
    reason: &str,
    now: UnixMillis,
) -> Result<()> {
    type Row = (
        [u8; 16],
        [u8; 16],
        String,
        Option<String>,
        Option<i64>,
        Option<i64>,
    );
    let Some(conclusion) = Conclusion::of_reason(reason) else {
        return Ok(());
    };
    let row: Option<Row> = tx
        .prepare_cached(
            "SELECT d.tenant_id, d.repo_id, COALESCE(p.head_sha, d.new_sha), d.ref_name,
                    (b.installation_id IS NOT NULL), b.revoked
             FROM webhook_deliveries d
             LEFT JOIN pr_deliveries p ON p.delivery_id = d.id
             LEFT JOIN source_bindings b ON b.repo_id = d.repo_id
             WHERE d.id = ?1",
        )?
        .query_row([delivery.as_bytes()], |r| {
            Ok((
                r.get(0)?,
                r.get(1)?,
                r.get(2)?,
                r.get(3)?,
                r.get(4)?,
                r.get(5)?,
            ))
        })
        .optional()?;
    let Some((tenant, repo, new_sha, ref_name, forge, revoked)) = row else {
        return Ok(());
    };
    if forge != Some(1) || revoked == Some(1) {
        return Ok(());
    }
    if ref_name
        .as_deref()
        .is_some_and(|r| r.starts_with("refs/tags/"))
    {
        return Ok(());
    }
    let tenant = TenantId::from_bytes(tenant).map_err(|_| Error::Corrupt("tenant_id"))?;
    let repo = RepoId::from_bytes(repo).map_err(|_| Error::Corrupt("repo_id"))?;
    let (title, why) = match reason {
        "no_trigger" => ("Not run", "the pipeline does not declare this event"),
        "fork_pr" => ("Not executed", "fork pull requests are not executed yet"),
        "merge_unavailable" => (
            "Not run",
            "GitHub did not compute a tested merge for this pull request",
        ),
        "binding_revoked" => ("Not run", "the source binding was revoked"),
        "tenant_suspended" => ("Not run", "the repository's tenant is suspended"),
        "access_removed" => (
            "Not run",
            "the GitHub App installation no longer grants access",
        ),
        "destination_refused" => (
            "Not run",
            "the deployment no longer approves this source's destination",
        ),
        "ref_not_allowed" => ("Not run", "the binding does not allow this ref"),
        "no_pipeline" => (
            "Not run",
            "the bound pipeline path is missing at this revision",
        ),
        "pipeline_invalid" => ("Not run", "the pipeline did not compile"),
        "image_unpinned" => ("Not run", "a job image is not pinned by digest"),
        "source_unavailable" => ("Not run", "no usable source credential exists"),
        "no_forge_association" => ("Not run", "the pull request has no forge association"),
        "pr_metadata" => ("Not run", "the pull request metadata is incomplete"),
        "resolution_attempts" => ("Not run", "source resolution failed repeatedly"),
        _ => ("Not run", "the event did not produce a run"),
    };
    let summary = match ref_name.as_deref() {
        Some(reference) => format!("{why} ({reason}): {reference}"),
        None => format!("{why} ({reason})"),
    };
    upsert(
        tx,
        Draft {
            tenant,
            repo,
            run: None,
            delivery: Some(delivery),
            scope: AGGREGATE_SCOPE,
            name: AGGREGATE_NAME,
            head_sha: &new_sha,
            external: format!("{EXTERNAL_PREFIX}dlv:{delivery}"),
            status: Status::Completed,
            conclusion: Some(conclusion),
            title,
            summary,
        },
        now,
    )
}

pub fn due(conn: &Connection, now: UnixMillis, limit: u16) -> Result<Vec<Publication>> {
    let mut stmt = conn.prepare_cached(concat!(
        "SELECT ",
        columns!(),
        " FROM check_publications
         WHERE state = 0 AND published_seq < seq
           AND (next_attempt_ms IS NULL OR next_attempt_ms <= ?1)
         ORDER BY created_ms, id LIMIT ?2"
    ))?;
    let rows = stmt.query_map(params![now.0, limit], decode_row)?;
    rows.map(|row| decode(row?)).collect()
}

pub fn next_due_ms(conn: &Connection) -> Result<Option<i64>> {
    Ok(conn
        .prepare_cached(
            "SELECT COALESCE(next_attempt_ms, 0) FROM check_publications
             WHERE state = 0 AND published_seq < seq
             ORDER BY next_attempt_ms LIMIT 1",
        )?
        .query_row([], |r| r.get(0))
        .optional()?)
}

pub fn get(conn: &Connection, id: CheckId) -> Result<Option<Publication>> {
    let row = conn
        .prepare_cached(&format!(
            "SELECT {COLUMNS} FROM check_publications WHERE id = ?1"
        ))?
        .query_row([id.as_bytes()], decode_row)
        .optional()?;
    row.map(decode).transpose()
}

pub fn of_run(conn: &Connection, tenant: TenantId, run: RunId) -> Result<Vec<Publication>> {
    let mut stmt = conn.prepare_cached(&format!(
        "SELECT {COLUMNS} FROM check_publications
         WHERE tenant_id = ?1 AND run_id = ?2 ORDER BY scope"
    ))?;
    let rows = stmt.query_map(params![tenant.as_bytes(), run.as_bytes()], decode_row)?;
    rows.map(|row| decode(row?)).collect()
}

pub fn of_delivery(conn: &Connection, delivery: DeliveryId) -> Result<Option<Publication>> {
    let row = conn
        .prepare_cached(&format!(
            "SELECT {COLUMNS} FROM check_publications WHERE delivery_id = ?1"
        ))?
        .query_row([delivery.as_bytes()], decode_row)
        .optional()?;
    row.map(decode).transpose()
}

type Fields = (
    [u8; 16],
    [u8; 16],
    [u8; 16],
    Option<[u8; 16]>,
    Option<[u8; 16]>,
    String,
    String,
    String,
    String,
    String,
    Option<String>,
    String,
    String,
    Option<i64>,
    i64,
    i64,
    i64,
    Option<String>,
    Option<i64>,
    Option<i64>,
    Option<i64>,
);

fn decode_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<Fields> {
    Ok((
        r.get(0)?,
        r.get(1)?,
        r.get(2)?,
        r.get(3)?,
        r.get(4)?,
        r.get(5)?,
        r.get(6)?,
        r.get(7)?,
        r.get(8)?,
        r.get(9)?,
        r.get(10)?,
        r.get(11)?,
        r.get(12)?,
        r.get(13)?,
        r.get(14)?,
        r.get(15)?,
        r.get(16)?,
        r.get(17)?,
        r.get(18)?,
        r.get(19)?,
        r.get(20)?,
    ))
}

fn decode(row: Fields) -> Result<Publication> {
    let (
        id,
        tenant,
        repo,
        run,
        delivery,
        scope,
        name,
        head_sha,
        external_id,
        status,
        conclusion,
        title,
        summary,
        check_run_id,
        seq,
        published_seq,
        state,
        reason,
        check_suite_id,
        create_started_ms,
        create_seq,
    ) = row;
    Ok(Publication {
        id: CheckId::from_bytes(id).map_err(|_| Error::Corrupt("check id"))?,
        tenant: TenantId::from_bytes(tenant).map_err(|_| Error::Corrupt("tenant_id"))?,
        repo: RepoId::from_bytes(repo).map_err(|_| Error::Corrupt("repo_id"))?,
        run: run
            .map(|b| RunId::from_bytes(b).map_err(|_| Error::Corrupt("run_id")))
            .transpose()?,
        delivery: delivery
            .map(|b| DeliveryId::from_bytes(b).map_err(|_| Error::Corrupt("delivery_id")))
            .transpose()?,
        scope,
        name,
        head_sha,
        external_id,
        status: Status::parse(&status).ok_or(Error::Corrupt("check status"))?,
        conclusion: match conclusion.as_deref() {
            None => None,
            Some(text) => Some(Conclusion::parse(text).ok_or(Error::Corrupt("check conclusion"))?),
        },
        title,
        summary,
        check_run_id,
        check_suite_id,
        create_started_ms,
        create_seq,
        seq,
        published_seq,
        state: State::decode(state).ok_or(Error::Corrupt("check state"))?,
        reason,
    })
}

/// Durably marked before a create request, so a retry adopts by external_id instead of creating a second run.
pub fn create_started(tx: &Transaction<'_>, id: CheckId, seq: i64, now: UnixMillis) -> Result<()> {
    let changed = tx.execute(
        "UPDATE check_publications SET create_started_ms = ?3, create_seq = ?2, updated_ms = ?3
         WHERE id = ?1 AND seq = ?2",
        params![id.as_bytes(), seq, now.0],
    )?;
    if changed != 1 {
        return Err(Error::Conflict);
    }
    Ok(())
}

pub fn published(
    tx: &Transaction<'_>,
    id: CheckId,
    seq: i64,
    check_run_id: i64,
    check_suite_id: Option<i64>,
    now: UnixMillis,
) -> Result<bool> {
    tx.execute(
        "UPDATE check_publications SET check_run_id = ?2,
            check_suite_id = COALESCE(?4, check_suite_id), updated_ms = ?3 WHERE id = ?1",
        params![id.as_bytes(), check_run_id, now.0, check_suite_id],
    )?;
    let changed = tx.execute(
        "UPDATE check_publications SET published_seq = ?2, state = 1, reason = NULL,
            next_attempt_ms = NULL, settled_ms = ?3, updated_ms = ?3
         WHERE id = ?1 AND seq = ?2",
        params![id.as_bytes(), seq, now.0],
    )?;
    Ok(changed == 1)
}

pub fn retry(
    tx: &Transaction<'_>,
    id: CheckId,
    seq: i64,
    now: UnixMillis,
    delay_ms: i64,
) -> Result<Retry> {
    let (attempts, status): (i64, String) = tx
        .prepare_cached(
            "SELECT attempts, status FROM check_publications WHERE id = ?1 AND seq = ?2",
        )?
        .query_row(params![id.as_bytes(), seq], |r| Ok((r.get(0)?, r.get(1)?)))
        .optional()?
        .ok_or(Error::Conflict)?;
    let terminal = status == Status::Completed.as_str();
    let (budget, ceiling) = if terminal {
        (MAX_TERMINAL_ATTEMPTS, TERMINAL_MAX_BACKOFF_MS)
    } else {
        (MAX_ATTEMPTS, MAX_BACKOFF_MS)
    };
    let next = u32::try_from(attempts.saturating_add(1)).unwrap_or(u32::MAX);
    if next >= budget {
        refused(tx, id, seq, "attempts", now)?;
        return Ok(Retry::Exhausted);
    }
    let base = if terminal {
        terminal_backoff_ms(next)
    } else {
        backoff_ms(next)
    };
    let wait = base.max(delay_ms.clamp(0, ceiling));
    let next_attempt_ms = now.0.saturating_add(wait);
    let changed = tx.execute(
        "UPDATE check_publications SET attempts = ?3, next_attempt_ms = ?4, updated_ms = ?5
         WHERE id = ?1 AND seq = ?2",
        params![id.as_bytes(), seq, next as i64, next_attempt_ms, now.0],
    )?;
    if changed != 1 {
        return Err(Error::Conflict);
    }
    Ok(Retry::Scheduled {
        attempts: next,
        next_attempt_ms,
    })
}

pub fn defer(
    tx: &Transaction<'_>,
    id: CheckId,
    seq: i64,
    now: UnixMillis,
    until_ms: i64,
) -> Result<bool> {
    let until = until_ms.min(now.0.saturating_add(MAX_DEFER_MS));
    let changed = tx.execute(
        "UPDATE check_publications SET next_attempt_ms = ?3, updated_ms = ?4
         WHERE id = ?1 AND seq = ?2 AND state = 0",
        params![id.as_bytes(), seq, until, now.0],
    )?;
    Ok(changed == 1)
}

pub fn rearm_exhausted(tx: &Transaction<'_>, now: UnixMillis, limit: u32) -> Result<usize> {
    Ok(tx.execute(
        "UPDATE check_publications SET state = 0, reason = NULL, attempts = 0,
            next_attempt_ms = NULL, settled_ms = NULL, updated_ms = ?1
         WHERE id IN (
            SELECT id FROM check_publications
            WHERE state = 2 AND reason = 'attempts' AND status = 'completed'
              AND settled_ms >= ?2
            ORDER BY settled_ms DESC LIMIT ?3)",
        params![now.0, now.0.saturating_sub(REARM_WINDOW_MS), limit],
    )?)
}

pub fn refused(
    tx: &Transaction<'_>,
    id: CheckId,
    seq: i64,
    reason: &str,
    now: UnixMillis,
) -> Result<()> {
    let mut reason: String = reason
        .chars()
        .filter(|c| !c.is_control())
        .take(120)
        .collect::<String>()
        .trim()
        .to_owned();
    if reason.is_empty() {
        reason.push_str("refused");
    }
    let changed = tx.execute(
        "UPDATE check_publications SET state = 2, reason = ?3, next_attempt_ms = NULL,
            settled_ms = ?4, updated_ms = ?4
         WHERE id = ?1 AND seq = ?2",
        params![id.as_bytes(), seq, reason, now.0],
    )?;
    if changed != 1 {
        return Err(Error::Conflict);
    }
    Ok(())
}
