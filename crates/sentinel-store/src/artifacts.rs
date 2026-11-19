//! A captured row commits with its manifest version, so an artifact is never half-published.

use rusqlite::{Connection, OptionalExtension, Transaction, params};
use sentinel_core::{ArtifactId, AttemptId, JobId, RepoId, RunId, TenantId, UnixMillis, UserId};

use crate::{
    Error, Result,
    objects::{self, Objects},
};

/// A name a native job's declared artifact may carry; GitHub's `upload-artifact` names are longer,
/// so the two other origins allow more.
const MAX_JOB_NAME: usize = 64;
pub const MAX_NAME: usize = 128;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum State {
    Captured = 0,
    Absent = 1,
    Failed = 2,
}

impl State {
    fn code(self) -> i64 {
        self as i64
    }
    fn from_code(code: i64) -> Result<State> {
        match code {
            0 => Ok(State::Captured),
            1 => Ok(State::Absent),
            2 => Ok(State::Failed),
            _ => Err(Error::Corrupt("artifact state")),
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            State::Captured => "captured",
            State::Absent => "absent",
            State::Failed => "failed",
        }
    }
}

/// Who produced an artifact row. Only a native job's own artifact can satisfy a declared required
/// one: finalization decides coverage from the attempt's rows, and the other two origins carry no
/// attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Origin {
    /// A declared artifact of a native job, captured at finalization.
    Job = 0,
    /// Files an authorized client attached to a run through an upload session.
    Run = 1,
    /// What a runner-mode job's `upload-artifact` produced, under its GitHub run and job.
    Runner = 2,
}

impl Origin {
    fn from_code(code: i64) -> Result<Origin> {
        match code {
            0 => Ok(Origin::Job),
            1 => Ok(Origin::Run),
            2 => Ok(Origin::Runner),
            _ => Err(Error::Corrupt("artifact origin")),
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Origin::Job => "job",
            Origin::Run => "run",
            Origin::Runner => "runner",
        }
    }
}

/// A run-level artifact's uploader. `display_name` is the account's name while it is still a member
/// of the owning tenant and `None` once it is not, as run provenance reports its actor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Uploader {
    pub user: UserId,
    pub display_name: Option<String>,
}

#[derive(Clone, Debug)]
pub struct Row {
    pub id: ArtifactId,
    pub origin: Origin,
    pub run: Option<RunId>,
    pub job: Option<JobId>,
    pub job_name: Option<String>,
    pub attempt: Option<AttemptId>,
    pub uploader: Option<Uploader>,
    /// The repository a runner-mode artifact belongs to; a job or run-level row names its run.
    pub repo: Option<RepoId>,
    pub github_run: Option<u64>,
    pub github_job: Option<u64>,
    pub name: String,
    pub state: State,
    pub manifest_version: Option<u64>,
    pub entries: u64,
    pub bytes: u64,
    pub class: String,
    pub charged_bytes: u64,
    pub retain_until_ms: UnixMillis,
    pub pinned_ms: Option<UnixMillis>,
    pub created_ms: UnixMillis,
    /// Why a failed artifact is missing (a controller's refusal), on the row an operator reads; absent otherwise.
    pub failure: Option<String>,
}

impl Row {
    /// The name this row's manifest is stored under. Its producer decides the namespace, so a
    /// run-level or runner-mode artifact never collides with a job's `{job}/{name}`.
    pub fn manifest(&self) -> Result<String> {
        manifest_of(
            self.job.as_ref().map(|job| *job.as_bytes()),
            self.run.as_ref().map(|run| *run.as_bytes()),
            self.repo.as_ref().map(|repo| *repo.as_bytes()),
            (self.github_run, self.github_job),
            &self.name,
        )
    }
    /// What an archive of this row is named for: the job that declared it, else its origin.
    pub fn owner_label(&self) -> &str {
        match &self.job_name {
            Some(name) => name,
            None => self.origin.as_str(),
        }
    }
}

pub fn manifest_name(job: JobId, name: &str) -> String {
    format!("{job}/{name}")
}

/// The manifest a run-level artifact lives under; its own namespace, so it cannot stand in for a
/// declared artifact's.
#[doc(hidden)]
pub fn run_manifest_name(run: RunId, name: &str) -> String {
    format!("run/{run}/{name}")
}

/// The manifest a runner-mode artifact lives under, under the GitHub run and job that produced it.
#[doc(hidden)]
pub fn runner_manifest_name(repo: RepoId, github_run: u64, github_job: u64, name: &str) -> String {
    format!("runner/{repo}/{github_run}/{github_job}/{name}")
}

/// The manifest name of a row read without its origin (the sweep), from the identity it carries.
fn manifest_of(
    job: Option<[u8; 16]>,
    run: Option<[u8; 16]>,
    repo: Option<[u8; 16]>,
    github: (Option<u64>, Option<u64>),
    name: &str,
) -> Result<String> {
    match (job, run, repo, github) {
        (Some(job), _, _, _) => Ok(manifest_name(
            JobId::from_bytes(job).map_err(|_| Error::Corrupt("job id"))?,
            name,
        )),
        (None, Some(run), _, _) => Ok(run_manifest_name(
            RunId::from_bytes(run).map_err(|_| Error::Corrupt("run id"))?,
            name,
        )),
        (None, None, Some(repo), (Some(run), Some(job))) => Ok(runner_manifest_name(
            RepoId::from_bytes(repo).map_err(|_| Error::Corrupt("repo id"))?,
            run,
            job,
            name,
        )),
        _ => Err(Error::Corrupt("artifact identity")),
    }
}

/// The class a new artifact row takes and what its bytes are charged: its bytes times the class's
/// quota weight, the figure its repository's quota counts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Charge {
    pub class: String,
    pub charged: u64,
}

/// The class (`None`: the deployment's default) and the charge a row of `bytes` would take. A caller
/// that must check the quota it will owe resolves it once and hands it to `record_upload` or
/// `record_runner`.
pub fn charge(tx: &Transaction<'_>, class: Option<&str>, bytes: u64) -> Result<Charge> {
    let (class, weight): (String, i64) = tx
        .prepare_cached(
            "SELECT c.name, c.weight FROM artifact_classes c WHERE c.name = COALESCE(
                 ?1, (SELECT default_class FROM storage_defaults WHERE id = 1), 'standard')",
        )?
        .query_row([class], |r| Ok((r.get(0)?, r.get(1)?)))
        .optional()?
        .ok_or(Error::InvalidInput("artifact class"))?;
    Ok(Charge {
        class,
        charged: bytes.saturating_mul(weight as u64),
    })
}

/// Who a row belongs to, before it is stored.
enum Identity {
    Job {
        run: RunId,
        job: JobId,
        attempt: AttemptId,
    },
    Run {
        run: RunId,
        uploader: UserId,
    },
    Runner {
        repo: RepoId,
        run: u64,
        job: u64,
    },
}

#[allow(clippy::too_many_arguments)]
pub fn record(
    tx: &Transaction<'_>,
    tenant: TenantId,
    run: RunId,
    job: JobId,
    attempt: AttemptId,
    name: &str,
    state: State,
    manifest_version: Option<u64>,
    entries: u64,
    bytes: u64,
    retain_until: UnixMillis,
    now: UnixMillis,
) -> Result<ArtifactId> {
    record_class(
        tx,
        tenant,
        run,
        job,
        attempt,
        name,
        None,
        state,
        manifest_version,
        entries,
        bytes,
        retain_until,
        now,
    )
}

/// A failed artifact with the controller's reason, for a publication the tenant's hard threshold refused: the
/// row is what tells an operator why the artifact is missing, so the refusal is recorded where it is read.
#[allow(clippy::too_many_arguments)]
pub fn record_refused(
    tx: &Transaction<'_>,
    tenant: TenantId,
    run: RunId,
    job: JobId,
    attempt: AttemptId,
    name: &str,
    class: Option<&str>,
    failure: &str,
    retain_until: UnixMillis,
    now: UnixMillis,
) -> Result<ArtifactId> {
    if failure.is_empty() || failure.len() > MAX_FAILURE_BYTES {
        return Err(Error::InvalidInput("artifact failure"));
    }
    let charge = charge(tx, class, 0)?;
    insert(
        tx,
        tenant,
        Identity::Job { run, job, attempt },
        name,
        &charge,
        State::Failed,
        None,
        0,
        0,
        retain_until,
        now,
        Some(failure),
    )
}

/// The bound the `artifacts.failure` column keeps and the trigger that follows it repeats.
pub const MAX_FAILURE_BYTES: usize = 512;

/// [`record`], under the artifact's declared class: `None` takes the deployment's default class.
// UNIQUE(attempt_id, name) turns a redelivered insert into a conflict, not a duplicate.
#[allow(clippy::too_many_arguments)]
pub fn record_class(
    tx: &Transaction<'_>,
    tenant: TenantId,
    run: RunId,
    job: JobId,
    attempt: AttemptId,
    name: &str,
    class: Option<&str>,
    state: State,
    manifest_version: Option<u64>,
    entries: u64,
    bytes: u64,
    retain_until: UnixMillis,
    now: UnixMillis,
) -> Result<ArtifactId> {
    let charge = charge(tx, class, bytes)?;
    insert(
        tx,
        tenant,
        Identity::Job { run, job, attempt },
        name,
        &charge,
        state,
        manifest_version,
        entries,
        bytes,
        retain_until,
        now,
        None,
    )
}

/// A row for files an authorized client attached to a run: it names its run and its uploader and
/// carries no attempt, so it never stands in for a declared artifact of the run's jobs.
#[allow(clippy::too_many_arguments)]
pub fn record_upload(
    tx: &Transaction<'_>,
    tenant: TenantId,
    run: RunId,
    name: &str,
    charge: &Charge,
    manifest_version: u64,
    entries: u64,
    bytes: u64,
    retain_until: UnixMillis,
    uploader: UserId,
    now: UnixMillis,
) -> Result<ArtifactId> {
    insert(
        tx,
        tenant,
        Identity::Run { run, uploader },
        name,
        charge,
        State::Captured,
        Some(manifest_version),
        entries,
        bytes,
        retain_until,
        now,
        None,
    )
}

/// A row for what a runner-mode job's `upload-artifact` produced: it names the repository and the
/// GitHub run and job, and no Sentinel job or attempt.
#[allow(clippy::too_many_arguments)]
pub fn record_runner(
    tx: &Transaction<'_>,
    tenant: TenantId,
    repo: RepoId,
    run: u64,
    job: u64,
    name: &str,
    charge: &Charge,
    manifest_version: u64,
    entries: u64,
    bytes: u64,
    retain_until: UnixMillis,
    now: UnixMillis,
) -> Result<ArtifactId> {
    insert(
        tx,
        tenant,
        Identity::Runner { repo, run, job },
        name,
        charge,
        State::Captured,
        Some(manifest_version),
        entries,
        bytes,
        retain_until,
        now,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
fn insert(
    tx: &Transaction<'_>,
    tenant: TenantId,
    identity: Identity,
    name: &str,
    charge: &Charge,
    state: State,
    manifest_version: Option<u64>,
    entries: u64,
    bytes: u64,
    retain_until: UnixMillis,
    now: UnixMillis,
    failure: Option<&str>,
) -> Result<ArtifactId> {
    let limit = match identity {
        Identity::Job { .. } => MAX_JOB_NAME,
        Identity::Run { .. } | Identity::Runner { .. } => MAX_NAME,
    };
    if name.is_empty() || name.len() > limit || name.bytes().any(|b| b < 32 || b == 127) {
        return Err(Error::InvalidInput("artifact name"));
    }
    if (state == State::Captured) != manifest_version.is_some() {
        return Err(Error::InvalidInput("artifact manifest"));
    }
    let (origin, run, job, attempt, uploader, repo, github) = match identity {
        Identity::Job { run, job, attempt } => (
            Origin::Job,
            Some(run),
            Some(job),
            Some(attempt),
            None,
            None,
            (None, None),
        ),
        Identity::Run { run, uploader } => (
            Origin::Run,
            Some(run),
            None,
            None,
            Some(uploader),
            None,
            (None, None),
        ),
        Identity::Runner { repo, run, job } => (
            Origin::Runner,
            None,
            None,
            None,
            None,
            Some(repo),
            (
                Some(i64::try_from(run).map_err(|_| Error::InvalidInput("github run"))?),
                Some(i64::try_from(job).map_err(|_| Error::InvalidInput("github job"))?),
            ),
        ),
    };
    let id = ArtifactId::new();
    tx.execute(
        "INSERT INTO artifacts(id, tenant_id, origin_code, run_id, job_id, attempt_id, uploader_id,
             repo_id, github_run_id, github_job_id, name, class, charged_bytes, state_code,
             manifest_version, entries, bytes, retain_until_ms, created_ms, failure)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18,
             ?19, ?20)",
        params![
            id.as_bytes().as_slice(),
            tenant.as_bytes().as_slice(),
            origin as i64,
            run.map(|r| r.as_bytes().to_vec()),
            job.map(|j| j.as_bytes().to_vec()),
            attempt.map(|a| a.as_bytes().to_vec()),
            uploader.map(|u| u.as_bytes().to_vec()),
            repo.map(|p| p.as_bytes().to_vec()),
            github.0,
            github.1,
            name,
            charge.class,
            charge.charged as i64,
            state.code(),
            manifest_version.map(|v| v as i64),
            entries as i64,
            bytes as i64,
            retain_until.0,
            now.0,
            failure,
        ],
    )?;
    Ok(id)
}

/// Whether a run already has an artifact of this name attached to it, so a repeated attach is a
/// conflict before its manifest is written.
pub fn run_upload_exists(conn: &Connection, run: RunId, name: &str) -> Result<bool> {
    Ok(conn
        .prepare_cached(
            "SELECT EXISTS(SELECT 1 FROM artifacts
             WHERE run_id = ?1 AND name = ?2 AND origin_code = 1)",
        )?
        .query_row(params![run.as_bytes().as_slice(), name], |r| {
            r.get::<_, bool>(0)
        })?)
}

/// Whether this GitHub job already has an artifact of this name, so a repeated upload is a
/// conflict before its manifest is written.
pub fn runner_exists(
    conn: &Connection,
    tenant: TenantId,
    repo: RepoId,
    github_run: u64,
    github_job: u64,
    name: &str,
) -> Result<bool> {
    Ok(conn
        .prepare_cached(
            "SELECT EXISTS(SELECT 1 FROM artifacts
             WHERE tenant_id = ?1 AND repo_id = ?2 AND github_run_id = ?3 AND github_job_id = ?4
               AND name = ?5 AND origin_code = 2)",
        )?
        .query_row(
            params![
                tenant.as_bytes().as_slice(),
                repo.as_bytes().as_slice(),
                i64::try_from(github_run).map_err(|_| Error::InvalidInput("github run"))?,
                i64::try_from(github_job).map_err(|_| Error::InvalidInput("github job"))?,
                name
            ],
            |r| r.get::<_, bool>(0),
        )?)
}

pub fn exists(conn: &Connection, attempt: AttemptId, name: &str) -> Result<bool> {
    Ok(conn
        .prepare_cached(
            "SELECT EXISTS(SELECT 1 FROM artifacts WHERE attempt_id = ?1 AND name = ?2)",
        )?
        .query_row(params![attempt.as_bytes().as_slice(), name], |r| {
            r.get::<_, bool>(0)
        })?)
}

pub fn for_attempt(conn: &Connection, attempt: AttemptId) -> Result<Vec<(String, State)>> {
    let rows = conn
        .prepare_cached("SELECT name, state_code FROM artifacts WHERE attempt_id = ?1")?
        .query_map([attempt.as_bytes().as_slice()], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    rows.into_iter()
        .map(|(name, code)| Ok((name, State::from_code(code)?)))
        .collect()
}

pub fn captured_for_attempt(
    conn: &Connection,
    tenant: TenantId,
    attempt: AttemptId,
    limit: usize,
) -> Result<Vec<(String, u64)>> {
    let rows = conn
        .prepare_cached(
            "SELECT name, manifest_version FROM artifacts
             WHERE attempt_id = ?1 AND tenant_id = ?2 AND state_code = 0
             ORDER BY name LIMIT ?3",
        )?
        .query_map(
            params![
                attempt.as_bytes().as_slice(),
                tenant.as_bytes().as_slice(),
                limit.min(i64::MAX as usize) as i64
            ],
            |r| Ok((r.get::<_, String>(0)?, r.get::<_, Option<i64>>(1)?)),
        )?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    rows.into_iter()
        .map(|(name, version)| {
            let version = version.ok_or(Error::Corrupt("artifact manifest"))?;
            Ok((name, version as u64))
        })
        .collect()
}

/// What a run's artifacts come to: its jobs' captured artifacts and the files a client attached to
/// it, which is what its budget counts. A runner-mode artifact belongs to a GitHub run, not a
/// Sentinel one, and is bounded by the class and the quotas alone.
pub fn run_bytes(conn: &Connection, tenant: TenantId, run: RunId) -> Result<u64> {
    Ok(conn
        .prepare_cached(
            "SELECT COALESCE(SUM(bytes), 0) FROM artifacts
             WHERE tenant_id = ?1 AND run_id = ?2 AND state_code = 0",
        )?
        .query_row(
            params![tenant.as_bytes().as_slice(), run.as_bytes().as_slice()],
            |r| r.get::<_, i64>(0),
        )? as u64)
}

/// One row's columns as the statements below read them, so the index of each lives in one place.
type Raw = (
    Vec<u8>,
    i64,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Option<String>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Option<String>,
    Option<Vec<u8>>,
    Option<i64>,
    Option<i64>,
    String,
    i64,
    Option<i64>,
    i64,
    i64,
    String,
    i64,
    i64,
    Option<i64>,
    i64,
    Option<String>,
);

fn raw(r: &rusqlite::Row<'_>) -> rusqlite::Result<Raw> {
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
        r.get(21)?,
    ))
}

fn uuid<const N: usize>(bytes: &[u8], what: &'static str) -> Result<[u8; N]> {
    <[u8; N]>::try_from(bytes).map_err(|_| Error::Corrupt(what))
}

fn decode(row: Raw) -> Result<Row> {
    let (
        id,
        origin,
        run,
        job,
        job_name,
        attempt,
        uploader,
        uploader_name,
        repo,
        github_run,
        github_job,
        name,
        state,
        version,
        entries,
        bytes,
        class,
        charged,
        retain,
        pinned,
        created,
        failure,
    ) = row;
    Ok(Row {
        id: ArtifactId::from_bytes(uuid(&id, "artifact id")?)
            .map_err(|_| Error::Corrupt("artifact id"))?,
        origin: Origin::from_code(origin)?,
        run: run
            .map(|bytes| {
                RunId::from_bytes(uuid(&bytes, "run id")?).map_err(|_| Error::Corrupt("run id"))
            })
            .transpose()?,
        job: job
            .map(|bytes| {
                JobId::from_bytes(uuid(&bytes, "job id")?).map_err(|_| Error::Corrupt("job id"))
            })
            .transpose()?,
        job_name,
        attempt: attempt
            .map(|bytes| {
                AttemptId::from_bytes(uuid(&bytes, "attempt id")?)
                    .map_err(|_| Error::Corrupt("attempt id"))
            })
            .transpose()?,
        uploader: uploader
            .map(|bytes| {
                UserId::from_bytes(uuid(&bytes, "uploader id")?)
                    .map_err(|_| Error::Corrupt("uploader id"))
            })
            .transpose()?
            .map(|user| Uploader {
                user,
                display_name: uploader_name,
            }),
        repo: repo
            .map(|bytes| {
                RepoId::from_bytes(uuid(&bytes, "repo id")?).map_err(|_| Error::Corrupt("repo id"))
            })
            .transpose()?,
        github_run: github_run.and_then(|id| u64::try_from(id).ok()),
        github_job: github_job.and_then(|id| u64::try_from(id).ok()),
        name,
        state: State::from_code(state)?,
        manifest_version: version.map(|v| v as u64),
        entries: entries as u64,
        bytes: bytes as u64,
        class,
        charged_bytes: charged as u64,
        retain_until_ms: UnixMillis(retain),
        pinned_ms: pinned.map(UnixMillis),
        created_ms: UnixMillis(created),
        failure,
    })
}

/// Every artifact of a run in one read: its jobs' declared artifacts in job order and then the
/// files attached to the run itself.
pub fn for_run(conn: &Connection, tenant: TenantId, run: RunId) -> Result<Vec<Row>> {
    let mut stmt = conn.prepare_cached(
        "SELECT a.id, a.origin_code, a.run_id, a.job_id, j.name, a.attempt_id, a.uploader_id,
                u.display_name, a.repo_id, a.github_run_id, a.github_job_id, a.name, a.state_code,
                a.manifest_version, a.entries, a.bytes, a.class, a.charged_bytes,
                a.retain_until_ms, a.pinned_ms, a.created_ms, a.failure
         FROM artifacts a
         LEFT JOIN jobs j ON j.id = a.job_id
         LEFT JOIN memberships m ON m.tenant_id = a.tenant_id AND m.user_id = a.uploader_id
         LEFT JOIN users u ON u.id = m.user_id
         WHERE a.tenant_id = ?1 AND a.run_id = ?2
         ORDER BY COALESCE(j.created_seq, 9223372036854775807), a.created_ms, a.name",
    )?;
    let rows = stmt.query_map(
        params![tenant.as_bytes().as_slice(), run.as_bytes().as_slice()],
        raw,
    )?;
    rows.map(|row| decode(row?)).collect()
}

/// A foreign or absent id answers NotFound, so a tenant cannot probe for another tenant's records.
pub fn get(conn: &Connection, tenant: TenantId, run: RunId, id: ArtifactId) -> Result<Row> {
    conn.prepare_cached(
        "SELECT a.id, a.origin_code, a.run_id, a.job_id, j.name, a.attempt_id, a.uploader_id,
                u.display_name, a.repo_id, a.github_run_id, a.github_job_id, a.name, a.state_code,
                a.manifest_version, a.entries, a.bytes, a.class, a.charged_bytes,
                a.retain_until_ms, a.pinned_ms, a.created_ms, a.failure
         FROM artifacts a
         LEFT JOIN jobs j ON j.id = a.job_id
         LEFT JOIN memberships m ON m.tenant_id = a.tenant_id AND m.user_id = a.uploader_id
         LEFT JOIN users u ON u.id = m.user_id
         WHERE a.tenant_id = ?1 AND a.run_id = ?2 AND a.id = ?3",
    )?
    .query_row(
        params![
            tenant.as_bytes().as_slice(),
            run.as_bytes().as_slice(),
            id.as_bytes().as_slice()
        ],
        raw,
    )
    .optional()?
    .ok_or(Error::NotFound)
    .and_then(decode)
}

/// Every artifact one GitHub run's jobs produced, in job order, for the repository it ran in.
pub fn for_runner_run(
    conn: &Connection,
    tenant: TenantId,
    repo: RepoId,
    github_run: u64,
) -> Result<Vec<Row>> {
    let mut stmt = conn.prepare_cached(
        "SELECT a.id, a.origin_code, a.run_id, a.job_id, j.name, a.attempt_id, a.uploader_id,
                u.display_name, a.repo_id, a.github_run_id, a.github_job_id, a.name, a.state_code,
                a.manifest_version, a.entries, a.bytes, a.class, a.charged_bytes,
                a.retain_until_ms, a.pinned_ms, a.created_ms, a.failure
         FROM artifacts a INDEXED BY artifacts_runner
         LEFT JOIN jobs j ON j.id = a.job_id
         LEFT JOIN memberships m ON m.tenant_id = a.tenant_id AND m.user_id = a.uploader_id
         LEFT JOIN users u ON u.id = m.user_id
         WHERE a.tenant_id = ?1 AND a.repo_id = ?2 AND a.github_run_id = ?3 AND a.origin_code = 2
         ORDER BY a.github_job_id, a.created_ms, a.name",
    )?;
    let rows = stmt.query_map(
        params![
            tenant.as_bytes().as_slice(),
            repo.as_bytes().as_slice(),
            i64::try_from(github_run).map_err(|_| Error::InvalidInput("github run"))?
        ],
        raw,
    )?;
    rows.map(|row| decode(row?)).collect()
}

/// One artifact of a GitHub run, by id. A foreign or absent id, or one of another GitHub run, is
/// the same NotFound.
pub fn runner_get(
    conn: &Connection,
    tenant: TenantId,
    repo: RepoId,
    github_run: u64,
    id: ArtifactId,
) -> Result<Row> {
    conn.prepare_cached(
        "SELECT a.id, a.origin_code, a.run_id, a.job_id, j.name, a.attempt_id, a.uploader_id,
                u.display_name, a.repo_id, a.github_run_id, a.github_job_id, a.name, a.state_code,
                a.manifest_version, a.entries, a.bytes, a.class, a.charged_bytes,
                a.retain_until_ms, a.pinned_ms, a.created_ms, a.failure
         FROM artifacts a INDEXED BY artifacts_runner
         LEFT JOIN jobs j ON j.id = a.job_id
         LEFT JOIN memberships m ON m.tenant_id = a.tenant_id AND m.user_id = a.uploader_id
         LEFT JOIN users u ON u.id = m.user_id
         WHERE a.tenant_id = ?1 AND a.repo_id = ?2 AND a.github_run_id = ?3 AND a.id = ?4
           AND a.origin_code = 2",
    )?
    .query_row(
        params![
            tenant.as_bytes().as_slice(),
            repo.as_bytes().as_slice(),
            i64::try_from(github_run).map_err(|_| Error::InvalidInput("github run"))?,
            id.as_bytes().as_slice()
        ],
        raw,
    )
    .optional()?
    .ok_or(Error::NotFound)
    .and_then(decode)
}

/// A record a short-lived link names, resolved from its tenant and id alone because the token carries no run. A
/// suspended tenant and a foreign or absent id are the same `NotFound`, so redemption reveals neither.
pub fn for_link(conn: &Connection, tenant: TenantId, id: ArtifactId) -> Result<Row> {
    conn.prepare_cached(
        "SELECT a.id, a.origin_code, a.run_id, a.job_id, j.name, a.attempt_id, a.uploader_id,
                u.display_name, a.repo_id, a.github_run_id, a.github_job_id, a.name, a.state_code,
                a.manifest_version, a.entries, a.bytes, a.class, a.charged_bytes,
                a.retain_until_ms, a.pinned_ms, a.created_ms, a.failure
         FROM artifacts a
         LEFT JOIN jobs j ON j.id = a.job_id
         JOIN tenants t ON t.id = a.tenant_id AND t.active = 1
         LEFT JOIN memberships m ON m.tenant_id = a.tenant_id AND m.user_id = a.uploader_id
         LEFT JOIN users u ON u.id = m.user_id
         WHERE a.tenant_id = ?1 AND a.id = ?2",
    )?
    .query_row(
        params![tenant.as_bytes().as_slice(), id.as_bytes().as_slice()],
        raw,
    )
    .optional()?
    .ok_or(Error::NotFound)
    .and_then(decode)
}

pub fn captured(
    conn: &Connection,
    tenant: TenantId,
    run: RunId,
    job_name: &str,
    name: &str,
) -> Result<Row> {
    conn.prepare_cached(
        "SELECT a.id, a.origin_code, a.run_id, a.job_id, j.name, a.attempt_id, a.uploader_id,
                u.display_name, a.repo_id, a.github_run_id, a.github_job_id, a.name, a.state_code,
                a.manifest_version, a.entries, a.bytes, a.class, a.charged_bytes,
                a.retain_until_ms, a.pinned_ms, a.created_ms, a.failure
         FROM artifacts a
         JOIN jobs j ON j.id = a.job_id
         LEFT JOIN memberships m ON m.tenant_id = a.tenant_id AND m.user_id = a.uploader_id
         LEFT JOIN users u ON u.id = m.user_id
         WHERE a.tenant_id = ?1 AND a.run_id = ?2 AND j.name = ?3 AND a.name = ?4
           AND a.state_code = 0
         ORDER BY a.created_ms DESC",
    )?
    .query_row(
        params![
            tenant.as_bytes().as_slice(),
            run.as_bytes().as_slice(),
            job_name,
            name
        ],
        raw,
    )
    .optional()?
    .ok_or(Error::NotFound)
    .and_then(decode)
}

pub fn sweep_expired(
    tx: &Transaction<'_>,
    objects: &Objects,
    now: UnixMillis,
    limit: i64,
) -> Result<Vec<objects::Doomed>> {
    Ok(sweep_expired_counted(tx, objects, now, limit)?.0)
}

/// Like [`sweep_expired`], and also how many artifacts it deleted: a count equal to `limit` means more may be due.
pub fn sweep_expired_counted(
    tx: &Transaction<'_>,
    objects: &Objects,
    now: UnixMillis,
    limit: i64,
) -> Result<(Vec<objects::Doomed>, usize)> {
    type Due = (
        Vec<u8>,
        Vec<u8>,
        Option<Vec<u8>>,
        Option<Vec<u8>>,
        Option<Vec<u8>>,
        Option<i64>,
        Option<i64>,
        String,
        Option<i64>,
    );
    let due: Vec<Due> = tx
        .prepare(
            "SELECT id, tenant_id, run_id, job_id, repo_id, github_run_id, github_job_id, name,
                    manifest_version
             FROM artifacts WHERE retain_until_ms <= ?1 AND pinned_ms IS NULL LIMIT ?2",
        )?
        .query_map(params![now.0, limit], |r| {
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
            ))
        })?
        .collect::<std::result::Result<_, _>>()?;
    let expired = due.len();
    let mut paths = Vec::new();
    for (id, tenant, run, job, repo, github_run, github_job, name, version) in due {
        // A row's manifest is retired under the name its origin stored it, and only a captured row
        // names one.
        if let Some(version) = version {
            let manifest = manifest_of(
                job.as_deref()
                    .map(|bytes| uuid(bytes, "job id"))
                    .transpose()?,
                run.as_deref()
                    .map(|bytes| uuid(bytes, "run id"))
                    .transpose()?,
                repo.as_deref()
                    .map(|bytes| uuid(bytes, "repo id"))
                    .transpose()?,
                (
                    github_run.and_then(|id| u64::try_from(id).ok()),
                    github_job.and_then(|id| u64::try_from(id).ok()),
                ),
                &name,
            )?;
            if let Some(path) = objects.retire_manifest(
                tx,
                objects::tenant_from(tenant)?,
                objects::Kind::Artifact,
                &manifest,
                version as u64,
            )? {
                paths.push(path);
            }
        }
        tx.execute(
            "DELETE FROM artifacts WHERE id = ?1",
            params![id.as_slice()],
        )?;
    }
    Ok((paths, expired))
}
