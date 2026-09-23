//! The GitHub Checks outbox (G04).
//!
//! One durable row per check: the stable required aggregate `sentinel / ci`
//! and one `sentinel / <job>` per compiled job, plus a completed aggregate for
//! an event that was understood but could not run. The row holds the *desired*
//! state, coalesced: a job that moves queued → running → passed bumps `seq`
//! three times, and a publisher that read an older generation can never
//! overwrite the newer one because its guarded write names the sequence it
//! read.
//!
//! Nothing here depends on GitHub: the row is provider-independent, generic
//! Git runs create no rows, and dispatch never waits on a publication.

use rusqlite::{Connection, OptionalExtension, Transaction, params};
use sentinel_core::{CheckId, DeliveryId, JobId, RepoId, RunId, TenantId, UnixMillis};

use crate::{Error, Result};

/// The stable required check's scope and name. Job scopes are job IDs.
pub const AGGREGATE_SCOPE: &str = "aggregate";
pub const AGGREGATE_NAME: &str = "sentinel / ci";
/// Per-job check names; the aggregate above is the required one.
pub const JOB_PREFIX: &str = "sentinel / ";
/// External IDs let a rerequest (G05) find the run a check belongs to.
pub const EXTERNAL_PREFIX: &str = "sentinel:";

pub const MAX_ATTEMPTS: u32 = 8;
const BASE_BACKOFF_MS: i64 = 1_000;
const MAX_BACKOFF_MS: i64 = 5 * 60 * 1000;

const COLUMNS: &str = "id, tenant_id, repo_id, run_id, delivery_id, scope, name, head_sha,
    external_id, status, conclusion, title, summary, check_run_id, seq, published_seq, state, reason,
    check_suite_id, create_started_ms, create_seq";

/// A check's desired status.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    /// The newest generation still has to be delivered.
    Pending,
    /// The newest generation was delivered.
    Published,
    /// One generation was refused permanently; `reason` says why.
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

/// A check's desired status.
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

/// A completed check's conclusion, in GitHub's vocabulary (the publisher
/// validates the text against its own enum before sending).
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

    /// The conclusion a settled event gets. `None` means nothing is published:
    /// the event was a duplicate, superseded, or a deletion with no commit.
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

/// One publication as a publisher reads it.
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
    /// The check suite the run landed in, recorded from the forge's answer;
    /// a `check_suite` rerequest resolves runs through it (G05).
    pub check_suite_id: Option<i64>,
    /// When a create was last attempted, set durably before the request. Its
    /// presence means an earlier create may have landed: a later attempt must
    /// adopt by `external_id` instead of blindly creating another check run.
    pub create_started_ms: Option<i64>,
    /// The generation whose create is outstanding or produced the current
    /// handle: it names the run on GitHub ([`Publication::create_identity`]).
    /// `None` on a row created before migration 33, whose run carries the
    /// bare `external_id`.
    pub create_seq: Option<i64>,
    pub seq: i64,
    pub published_seq: i64,
    /// Where the outbox stands: due, delivered, or refused with `reason`.
    pub state: State,
    pub reason: Option<String>,
}

/// The `external_id` a create for generation `seq` sends: the row's stable
/// id plus the generation, so every create names exactly one GitHub run and
/// a lost answer can be adopted by exact match whatever status the run was
/// created with. `parse_control` and rerequest matching accept it (it keeps
/// the `sentinel:` prefix and stays well under 128 bytes).
pub fn create_identity(external_id: &str, seq: i64) -> String {
    format!("{external_id}:{seq}")
}

impl Publication {
    /// The identity the run behind this row was (or is being) created with:
    /// what an update keeps sending and what an adoption lookup matches.
    pub fn created_identity(&self) -> String {
        match self.create_seq {
            Some(seq) => create_identity(&self.external_id, seq),
            None => self.external_id.clone(),
        }
    }
}

/// What a retry did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Retry {
    Scheduled {
        attempts: u32,
        next_attempt_ms: i64,
    },
    /// The attempt budget is spent; the row is refused with that reason.
    Exhausted,
}

/// Milliseconds to wait before attempt `attempts` (1-based): doubling from one
/// second, capped at five minutes.
pub fn backoff_ms(attempts: u32) -> i64 {
    BASE_BACKOFF_MS
        .saturating_mul(1i64 << attempts.min(20))
        .min(MAX_BACKOFF_MS)
}

/// What one job's state means to a forge.
fn job_content(
    state: sentinel_core::JobState,
    class: Option<sentinel_core::FailureClass>,
    job: &str,
) -> (Status, Option<Conclusion>, String, String) {
    use sentinel_core::JobState as S;
    match state {
        S::Blocked | S::Queued => (
            Status::Queued,
            None,
            "Queued".into(),
            format!("job {job}: waiting for a worker"),
        ),
        S::Leased | S::Preparing | S::Running | S::Finalizing => (
            Status::InProgress,
            None,
            "Running".into(),
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
                title.to_owned(),
                format!("job {job}: {why}"),
            )
        }
    }
}

/// What the run as a whole means to a forge.
fn aggregate_content(
    jobs: &[(sentinel_core::JobState, Option<sentinel_core::FailureClass>)],
) -> Result<(Status, Option<Conclusion>, String, String)> {
    use sentinel_core::Outcome as O;
    if jobs.is_empty() {
        return Err(Error::Corrupt("run has no jobs"));
    }
    let state = sentinel_core::aggregate(jobs.iter().map(|(state, _)| *state));
    let count = |wanted: O| {
        jobs.iter()
            .filter(
                |(state, _)| matches!(state, sentinel_core::JobState::Terminal(o) if *o == wanted),
            )
            .count()
    };
    let total = jobs.len();
    let summary = format!(
        "{}/{} jobs passed · {} failed · {} skipped · {} cancelled",
        count(O::Passed),
        total,
        count(O::Failed) + count(O::InfraFailed),
        count(O::Skipped),
        count(O::Canceled),
    );
    Ok(match state {
        sentinel_core::RunState::Pending => (
            Status::Queued,
            None,
            "Queued".into(),
            format!("{total} jobs waiting for a worker"),
        ),
        sentinel_core::RunState::Active => (Status::InProgress, None, "Running".into(), summary),
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
                title.to_owned(),
                summary,
            )
        }
    })
}

/// The registry facts a publication needs: which repository it belongs to,
/// what the checked-out revision is, and whether a forge is associated at all.
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
    // Only event-driven runs publish: a manual run's inline pipeline is a
    // diagnostic and never satisfies the repository's required aggregate, so
    // it creates no rows at all. Generic repositories have no forge to tell.
    let event_driven = matches!(trigger.as_deref(), Some("push" | "tag" | "pull_request"));
    if forge == 0 || !event_driven {
        return Ok(None);
    }
    Ok(Some(RunFacts {
        repo: RepoId::from_bytes(repo).map_err(|_| Error::Corrupt("repo_id"))?,
        head_sha,
    }))
}

/// One desired check state to coalesce into the outbox.
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
    title: String,
    summary: String,
}

/// One statement: create the row or coalesce the newest desired state into it.
/// A new generation resets the cursor to pending and clears any previous
/// refusal or retry schedule. A generation that follows a `completed` one
/// also drops the check-run handle: the remote run is terminal and GitHub
/// silently keeps a completed run completed, so new work needs a fresh run —
/// and the create mark goes with it, so that fresh run is created under its
/// own identity instead of adopting the terminal one.
fn upsert(tx: &Transaction<'_>, draft: Draft<'_>, now: UnixMillis) -> Result<()> {
    let id = CheckId::new();
    tx.execute(
        "INSERT INTO check_publications(id, tenant_id, repo_id, run_id, delivery_id, scope, name,
            head_sha, external_id, status, conclusion, title, summary, seq, state, created_ms, updated_ms)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, 1, 0, ?14, ?14)
         ON CONFLICT(run_id, scope) WHERE run_id IS NOT NULL DO UPDATE SET
            status = excluded.status, conclusion = excluded.conclusion,
            title = excluded.title, summary = excluded.summary,
            check_run_id = CASE WHEN check_publications.status = 'completed'
                THEN NULL ELSE check_publications.check_run_id END,
            create_started_ms = CASE WHEN check_publications.status = 'completed'
                THEN NULL ELSE check_publications.create_started_ms END,
            create_seq = CASE WHEN check_publications.status = 'completed'
                THEN NULL ELSE check_publications.create_seq END,
             seq = check_publications.seq + 1, state = 0, reason = NULL, attempts = 0,
            next_attempt_ms = NULL, settled_ms = NULL, updated_ms = excluded.updated_ms",
        params![
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

/// Record the initial checks for a newly created run: every compiled job as
/// `queued` and, unless the run is manual, the stable aggregate. Manual runs
/// are namespaced so they can never satisfy the required aggregate.
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
        upsert(
            tx,
            Draft {
                tenant,
                repo: facts.repo,
                run: Some(run),
                delivery: None,
                scope: &job.to_string(),
                name: &qualified_name(job_name),
                head_sha: &facts.head_sha,
                external: external_id(run, &job.to_string()),
                status,
                conclusion,
                title,
                summary,
            },
            now,
        )?;
        written += 1;
    }
    written += record_aggregate(tx, tenant, run, now)?;
    Ok(written)
}

/// The name of one job's check: `sentinel / <job>`.
pub fn qualified_name(job: &str) -> String {
    let mut name = String::with_capacity(JOB_PREFIX.len() + job.len());
    name.push_str(JOB_PREFIX);
    name.push_str(job);
    name
}

/// Recompute the stable aggregate from the run's job rows and coalesce it.
fn record_aggregate(
    tx: &Transaction<'_>,
    tenant: TenantId,
    run: RunId,
    now: UnixMillis,
) -> Result<usize> {
    let Some(facts) = run_facts(tx, tenant, run)? else {
        return Ok(0);
    };
    let rows: Vec<(i64, Option<i64>)> = tx
        .prepare_cached(
            "SELECT state_code, failure_class FROM jobs WHERE run_id = ?1 AND tenant_id = ?2",
        )?
        .query_map(params![run.as_bytes(), tenant.as_bytes()], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })?
        .collect::<std::result::Result<_, _>>()?;
    let mut jobs = Vec::with_capacity(rows.len());
    for (code, class) in rows {
        let state = crate::codec::decode_state(code).ok_or(Error::Corrupt("state_code"))?;
        let class = match class {
            None => None,
            Some(code) => {
                Some(crate::codec::decode_failure(code).ok_or(Error::Corrupt("failure_class"))?)
            }
        };
        jobs.push((state, class));
    }
    let content = aggregate_content(&jobs)?;
    let (status, conclusion, title, summary) = content;
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

/// Record one job's newest state and refresh the aggregate. This is called
/// from the state machine's single transition point, so no way of ending a job
/// can skip it.
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
    // A generic repository gets no rows at all, and a revoked binding stops
    // new rows: this is the single place the association is read.
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
    upsert(
        tx,
        Draft {
            tenant,
            repo: facts.repo,
            run: Some(run),
            delivery: None,
            scope: &job.to_string(),
            name: &qualified_name(&name),
            head_sha: &facts.head_sha,
            external: external_id(run, &job.to_string()),
            status,
            conclusion,
            title,
            summary,
        },
        now,
    )?;
    record_aggregate(tx, tenant, run, now)?;
    Ok(())
}

/// Record one completed check for an event that was understood but produced no
/// run, so a required aggregate never stays pending.
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
    // A pull-request delivery's check belongs on its head: the pull-request
    // view reads checks on the head commit, not the tested merge.
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
    // A tag's revision is a tag object, not a commit a check can attach to;
    // a dispatched tag run publishes from the peeled commit instead.
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
            title: title.to_owned(),
            summary,
        },
        now,
    )
}

/// Publications whose newest generation has not been delivered yet and whose
/// next attempt is due, oldest first.
pub fn due(conn: &Connection, now: UnixMillis, limit: u16) -> Result<Vec<Publication>> {
    let mut stmt = conn.prepare_cached(&format!(
        "SELECT {COLUMNS} FROM check_publications
         WHERE state = 0 AND published_seq < seq
           AND (next_attempt_ms IS NULL OR next_attempt_ms <= ?1)
         ORDER BY created_ms, id LIMIT ?2"
    ))?;
    let rows = stmt.query_map(params![now.0, limit], decode_row)?;
    rows.map(|row| decode(row?)).collect()
}

/// One publication by ID, whatever its state.
pub fn get(conn: &Connection, id: CheckId) -> Result<Option<Publication>> {
    let row = conn
        .prepare_cached(&format!(
            "SELECT {COLUMNS} FROM check_publications WHERE id = ?1"
        ))?
        .query_row([id.as_bytes()], decode_row)
        .optional()?;
    row.map(decode).transpose()
}

/// One run's publications, in scope order, for tests and operators.
pub fn of_run(conn: &Connection, tenant: TenantId, run: RunId) -> Result<Vec<Publication>> {
    let mut stmt = conn.prepare_cached(&format!(
        "SELECT {COLUMNS} FROM check_publications
         WHERE tenant_id = ?1 AND run_id = ?2 ORDER BY scope"
    ))?;
    let rows = stmt.query_map(params![tenant.as_bytes(), run.as_bytes()], decode_row)?;
    rows.map(|row| decode(row?)).collect()
}

/// One delivery's publication, if it has one.
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

/// Mark, durably and before the request, that a create was attempted for this
/// generation. A crash between GitHub accepting the create and the handle
/// being recorded then still reconciles through the `external_id` lookup
/// rather than creating a second check run. The mark records the generation
/// the create is for, which is the identity the request carries
/// ([`create_identity`]). It sticks across generations until the row's run
/// goes terminal: once a create may have landed, every later create looks
/// first. `Conflict` means the generation moved — re-read and start over.
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

/// Record the run's numeric handle and, when the generation is still the one
/// the publisher read, mark it current. The handle is recorded either way: a
/// create that raced a newer generation must not be repeated, or GitHub would
/// grow a second check run for the same check. The suite the run landed in is
/// recorded the same way so a `check_suite` rerequest can resolve it.
///
/// Returns whether the *current* generation was marked (the stale-write
/// protection). `false` is not an error: the newer generation stays pending
/// and the next attempt updates the run whose handle was just recorded.
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

/// Make an attempt that failed transiently due again under the shared budget.
pub fn retry(
    tx: &Transaction<'_>,
    id: CheckId,
    seq: i64,
    now: UnixMillis,
    delay_ms: i64,
) -> Result<Retry> {
    let attempts: i64 = tx
        .prepare_cached("SELECT attempts FROM check_publications WHERE id = ?1 AND seq = ?2")?
        .query_row(params![id.as_bytes(), seq], |r| r.get(0))
        .optional()?
        .ok_or(Error::Conflict)?;
    let next = u32::try_from(attempts.saturating_add(1)).unwrap_or(u32::MAX);
    if next >= MAX_ATTEMPTS {
        refused(tx, id, seq, "attempts", now)?;
        return Ok(Retry::Exhausted);
    }
    let wait = backoff_ms(next).max(delay_ms.clamp(0, MAX_BACKOFF_MS));
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

/// Give up on one generation: the row records why, and a later generation (a
/// state change) starts fresh.
pub fn refused(
    tx: &Transaction<'_>,
    id: CheckId,
    seq: i64,
    reason: &str,
    now: UnixMillis,
) -> Result<()> {
    let reason: String = reason
        .chars()
        .filter(|c| !c.is_control())
        .take(120)
        .collect();
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
