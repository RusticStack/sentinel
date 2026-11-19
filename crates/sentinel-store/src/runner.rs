//! Runner mode: the tenant's switch, what an installation snapshot states runner mode needs, and
//! the GitHub job each `workflow_job` delivery describes. A queued job is demand recorded durably;
//! placing it on a pool and registering a runner for it are the provisioning work that follows.

use rusqlite::{Connection, OptionalExtension, Transaction, params};
use sentinel_core::{
    DeliveryId, Labelled, RepoId, RunnerClass, RunnerPermissions, TenantId, UnixMillis,
};

use crate::{
    Error, Result,
    auth::Authority,
    intake::{self, Accepted, Delivery},
    local_auth::{Event, audit},
};

/// The GitHub event this module accepts. It carries no ref: the job names its own commit.
pub const EVENT: &str = "workflow_job";

/// The activities that mean something here. Anything else is acknowledged and not stored.
pub const QUEUED: &str = "queued";
pub const IN_PROGRESS: &str = "in_progress";
pub const COMPLETED: &str = "completed";

pub fn action_known(action: &str) -> bool {
    matches!(action, QUEUED | IN_PROGRESS | COMPLETED)
}

/// A `workflow_job` delivery's terms, before they are stored.
pub struct NewRunner<'a> {
    pub authentication: intake::Authentication,
    pub provider: &'a str,
    pub external_id: &'a str,
    pub action: &'a str,
    pub job: u64,
    pub run: u64,
    pub labels: &'a str,
    pub runner: Option<&'a str>,
    pub conclusion: Option<&'a str>,
}

fn printable(text: &str, max: usize) -> bool {
    !text.is_empty() && text.len() <= max && !text.bytes().any(|b| b < 32 || b == 127)
}

fn check(delivery: &NewRunner<'_>) -> Result<()> {
    let invalid = !printable(delivery.provider, 32)
        || !printable(delivery.action, 32)
        || !sentinel_protocol::intake::valid_delivery_id(delivery.external_id)
        || delivery.job == 0
        || delivery.job > i64::MAX as u64
        || delivery.run == 0
        || delivery.run > i64::MAX as u64
        || delivery.labels.len() > 512
        || delivery.labels.bytes().any(|b| b < 32 || b == 127)
        || delivery.runner.is_some_and(|r| !printable(r, 128))
        || delivery.conclusion.is_some_and(|c| !printable(c, 32));
    if invalid {
        return Err(Error::InvalidInput("runner job"));
    }
    Ok(())
}

/// Accept one `workflow_job` delivery: deduplicated on its delivery id, refused as a conflict
/// when that id arrives with different terms, and stored with the job facts beside it.
pub fn accept(
    tx: &Transaction<'_>,
    repo: RepoId,
    delivery: &NewRunner<'_>,
    now: UnixMillis,
) -> Result<Accepted> {
    check(delivery)?;
    let tenant = crate::sources::repo_tenant(tx, repo)?;
    let metadata = crate::sources::load_metadata(tx, repo).map_err(|e| match e {
        Error::NotFound => Error::Forbidden,
        other => other,
    })?;
    if metadata.revoked {
        return Err(Error::Forbidden);
    }
    if let Some((id, existing)) = find(tx, tenant, repo, delivery.provider, delivery.external_id)? {
        let same = existing.as_ref().is_some_and(|row| {
            row.action == delivery.action
                && row.job == delivery.job
                && row.run == delivery.run
                && row.labels == delivery.labels
                && row.runner.as_deref() == delivery.runner
                && row.conclusion.as_deref() == delivery.conclusion
        });
        return if same {
            Ok(Accepted::Duplicate(id))
        } else {
            Err(Error::Conflict)
        };
    }
    let pending: i64 = tx
        .prepare_cached(
            "SELECT count(*) FROM webhook_deliveries WHERE repo_id = ?1 AND state IN (0, 1)",
        )?
        .query_row([repo.as_bytes()], |r| r.get(0))?;
    if pending >= intake::MAX_PENDING_PER_REPO {
        return Err(Error::Overloaded);
    }
    let id = DeliveryId::new();
    tx.execute(
        "INSERT INTO webhook_deliveries(id, tenant_id, repo_id, provider, external_id,
            event, ref_name, old_sha, new_sha, state, received_ms, authentication)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL, NULL, NULL, 0, ?7, ?8)",
        params![
            id.as_bytes(),
            tenant.as_bytes(),
            repo.as_bytes(),
            delivery.provider,
            delivery.external_id,
            EVENT,
            now.0,
            delivery.authentication as i64
        ],
    )?;
    tx.execute(
        "INSERT INTO runner_deliveries(delivery_id, tenant_id, repo_id, action, job_id, run_id,
            labels, runner, conclusion)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            id.as_bytes(),
            tenant.as_bytes(),
            repo.as_bytes(),
            delivery.action,
            delivery.job as i64,
            delivery.run as i64,
            delivery.labels,
            delivery.runner,
            delivery.conclusion
        ],
    )?;
    Ok(Accepted::Fresh(id))
}

/// A stored delivery's identity beside the terms it stated, if it stated any.
type LookupRow = (
    [u8; 16],
    Option<String>,
    Option<i64>,
    Option<i64>,
    Option<String>,
    Option<String>,
    Option<String>,
);

/// The stored runner delivery with this identity, if there is one.
fn find(
    conn: &Connection,
    tenant: TenantId,
    repo: RepoId,
    provider: &str,
    external_id: &str,
) -> Result<Option<(DeliveryId, Option<Terms>)>> {
    let row: Option<LookupRow> = conn
        .prepare_cached(
            "SELECT d.id, r.action, r.job_id, r.run_id, r.labels, r.runner, r.conclusion
             FROM webhook_deliveries d
             LEFT JOIN runner_deliveries r ON r.delivery_id = d.id
             WHERE d.tenant_id = ?1 AND d.repo_id = ?2 AND d.provider = ?3 AND d.external_id = ?4",
        )?
        .query_row(
            params![tenant.as_bytes(), repo.as_bytes(), provider, external_id],
            |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                    r.get(6)?,
                ))
            },
        )
        .optional()?;
    let Some((id, action, job, run, labels, runner, conclusion)) = row else {
        return Ok(None);
    };
    let id = DeliveryId::from_bytes(id).map_err(|_| Error::Corrupt("delivery id"))?;
    let terms = match (action, job, run, labels) {
        (Some(action), Some(job), Some(run), Some(labels)) => Some(Terms {
            action,
            job: u64::try_from(job).map_err(|_| Error::Corrupt("runner job"))?,
            run: u64::try_from(run).map_err(|_| Error::Corrupt("runner run"))?,
            labels,
            runner,
            conclusion,
        }),
        // The identity was used by another event class: this delivery is a conflict, never a duplicate.
        _ => None,
    };
    Ok(Some((id, terms)))
}

/// What one delivery said about its job.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Terms {
    pub action: String,
    pub job: u64,
    pub run: u64,
    pub labels: String,
    pub runner: Option<String>,
    pub conclusion: Option<String>,
}

impl Terms {
    /// The class the delivery's label set names; the caller decides what an unserved one means.
    pub fn class(&self) -> Labelled {
        RunnerClass::of_labels(self.labels.split(','))
    }
}

type TermsRow = (String, i64, i64, String, Option<String>, Option<String>);

pub fn terms_for(conn: &Connection, delivery: DeliveryId) -> Result<Option<Terms>> {
    let row: Option<TermsRow> = conn
        .prepare_cached(
            "SELECT action, job_id, run_id, labels, runner, conclusion
             FROM runner_deliveries WHERE delivery_id = ?1",
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
    row.map(|(action, job, run, labels, runner, conclusion)| {
        Ok(Terms {
            action,
            job: u64::try_from(job).map_err(|_| Error::Corrupt("runner job"))?,
            run: u64::try_from(run).map_err(|_| Error::Corrupt("runner run"))?,
            labels,
            runner,
            conclusion,
        })
    })
    .transpose()
}

/// The tenant's switch and what the installation its repository is bound through grants.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Access {
    pub enabled: bool,
    pub permissions: RunnerPermissions,
    /// The installation's account is a personal namespace, which asks for
    /// repository administration write instead of the organization grant.
    pub personal: bool,
}

/// `NotFound` when the repository is bound through no live installation at all.
pub fn access(conn: &Connection, tenant: TenantId, repo: RepoId) -> Result<Access> {
    let row: Option<(i64, i64, i64)> = conn
        .prepare_cached(
            "SELECT t.runner_mode, i.runner_permissions, i.account_personal
             FROM source_bindings b
             JOIN installations i ON i.id = b.installation_id AND i.tenant_id = b.tenant_id
                 AND i.suspended = 0 AND i.permissions_valid = 1
             JOIN tenants t ON t.id = b.tenant_id AND t.active = 1
             WHERE b.repo_id = ?1 AND b.tenant_id = ?2 AND b.revoked = 0",
        )?
        .query_row(params![repo.as_bytes(), tenant.as_bytes()], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?))
        })
        .optional()?;
    let Some((enabled, permissions, personal)) = row else {
        return Err(Error::NotFound);
    };
    let bits = u8::try_from(permissions).map_err(|_| Error::Corrupt("runner permissions"))?;
    Ok(Access {
        enabled: enabled == 1,
        permissions: RunnerPermissions::from_bits(bits)
            .ok_or(Error::Corrupt("runner permissions"))?,
        personal: personal == 1,
    })
}

/// Record what one delivery says about its job and mark the delivery as having produced it, in
/// the caller's transaction. A job is kept under GitHub's job id, so a duplicated or reordered
/// delivery can neither create a second one nor move its state backwards.
pub fn record(
    tx: &Transaction<'_>,
    delivery: &Delivery,
    terms: &Terms,
    class: RunnerClass,
    now: UnixMillis,
) -> Result<()> {
    let (tenant, repo) = (delivery.tenant, delivery.repo);
    let state = match terms.action.as_str() {
        QUEUED => 0,
        IN_PROGRESS => 1,
        COMPLETED => 2,
        _ => return Err(Error::InvalidInput("runner job")),
    };
    let (job, run) = (terms.job as i64, terms.run as i64);
    // The first delivery of a job decides its class and run; later ones only move its state
    // forward and add what only they know.
    let changed = if state == 0 {
        tx.execute(
            "INSERT INTO runner_jobs(tenant_id, repo_id, job_id, run_id, class, state_code,
                runner, conclusion, queued_ms, started_ms, completed_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, 0, NULL, NULL, ?6, NULL, NULL)
             ON CONFLICT(tenant_id, repo_id, job_id) DO NOTHING",
            params![
                tenant.as_bytes(),
                repo.as_bytes(),
                job,
                run,
                class.to_string(),
                delivery.received.0
            ],
        )?
    } else if state == 1 {
        tx.execute(
            "INSERT INTO runner_jobs(tenant_id, repo_id, job_id, run_id, class, state_code,
                runner, conclusion, queued_ms, started_ms, completed_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, 1, ?6, NULL, ?7, ?7, NULL)
             ON CONFLICT(tenant_id, repo_id, job_id) DO UPDATE SET
                state_code = 1, runner = COALESCE(excluded.runner, runner_jobs.runner),
                started_ms = ?7
             WHERE runner_jobs.state_code = 0",
            params![
                tenant.as_bytes(),
                repo.as_bytes(),
                job,
                run,
                class.to_string(),
                terms.runner,
                now.0
            ],
        )?
    } else {
        tx.execute(
            "INSERT INTO runner_jobs(tenant_id, repo_id, job_id, run_id, class, state_code,
                runner, conclusion, queued_ms, started_ms, completed_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, 2, ?6, ?7, ?8, NULL, ?8)
             ON CONFLICT(tenant_id, repo_id, job_id) DO UPDATE SET
                state_code = 2, conclusion = excluded.conclusion,
                runner = COALESCE(excluded.runner, runner_jobs.runner),
                completed_ms = ?8
             WHERE runner_jobs.state_code < 2",
            params![
                tenant.as_bytes(),
                repo.as_bytes(),
                job,
                run,
                class.to_string(),
                terms.runner,
                terms.conclusion,
                now.0
            ],
        )?
    };
    // Zero means the job was already at or past this activity: the delivery is still settled.
    let _ = changed;
    // The runner GitHub assigned is the name the lease was registered under, so this delivery is
    // what binds a job to the runner Sentinel started — and `completed` is what ends its lease.
    match terms.action.as_str() {
        IN_PROGRESS => {
            if let Some(runner) = terms.runner.as_deref() {
                crate::runner_provision::bind(tx, tenant, repo, runner, terms.job, now)?;
            }
        }
        COMPLETED => {
            let reason = match terms.conclusion.as_deref() {
                Some("cancelled") => crate::runner_provision::CANCELLED,
                _ => crate::runner_provision::JOB_COMPLETED,
            };
            crate::runner_provision::complete(tx, tenant, repo, terms.job, reason, now)?;
        }
        _ => {}
    }
    intake::settle_runner(tx, delivery.id, now)
}

/// Settle a delivery runner mode refuses, with its reason in the repository's audit trail, in
/// the caller's transaction. The delivery is never retried: the refusal is a decision.
pub fn refuse(
    tx: &Transaction<'_>,
    delivery: &Delivery,
    reason: &'static str,
    now: UnixMillis,
) -> Result<()> {
    intake::settle(tx, delivery.id, intake::Resolution::Failed(reason), now)?;
    intake::audit(tx, delivery.tenant, delivery.repo, None, reason, now)
}

/// The tenant's switch, as a reader sees it.
pub fn mode(conn: &Connection, tenant: TenantId) -> Result<bool> {
    let enabled: i64 = conn
        .prepare_cached("SELECT runner_mode FROM tenants WHERE id = ?1 AND active = 1")?
        .query_row([tenant.as_bytes()], |r| r.get(0))
        .optional()?
        .ok_or(Error::NotFound)?;
    Ok(enabled == 1)
}

/// The runner-mode permissions this tenant's installations do not grant, named as GitHub's App
/// settings name them and in one fixed order; empty when every one of them is granted. The
/// tenant's live installations are judged, not only those a repository happens to be bound
/// through: an administrator turns the switch before binding everything, and a later binding
/// must not be the first place a missing permission is noticed.
pub fn missing(conn: &Connection, tenant: TenantId) -> Result<Vec<&'static str>> {
    let mut stmt = conn.prepare_cached(
        "SELECT i.account_personal, i.runner_permissions FROM installations i
         WHERE i.tenant_id = ?1 AND i.suspended = 0",
    )?;
    let rows = stmt.query_map([tenant.as_bytes()], |r| {
        Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?))
    })?;
    let mut missing: Vec<&'static str> = Vec::new();
    for row in rows {
        let (personal, bits) = row?;
        let bits = u8::try_from(bits).map_err(|_| Error::Corrupt("runner permissions"))?;
        let granted =
            RunnerPermissions::from_bits(bits).ok_or(Error::Corrupt("runner permissions"))?;
        for name in granted.missing(personal == 1) {
            if !missing.contains(name) {
                missing.push(name);
            }
        }
    }
    missing.sort_unstable();
    Ok(missing)
}

/// What turning the switch asked for did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Switch {
    /// The tenant now reads what was asked for, and the change is audited.
    Set,
    /// It already read that; nothing changed and nothing was written.
    Unchanged,
    /// Refused: the installations the tenant's repositories are bound through do not grant
    /// these, named as GitHub's App settings name them.
    Missing(Vec<&'static str>),
    /// Refused: the tenant has no live GitHub installation to register a runner through.
    NoInstallation,
}

/// Turn runner mode on or off. Enabling is refused while the installations the tenant's
/// repositories are bound through do not grant what runner mode needs; disabling never is.
pub fn set_mode(
    tx: &Transaction<'_>,
    authority: Authority,
    tenant: TenantId,
    enabled: bool,
) -> Result<Switch> {
    if let Some(principal) = authority.principal() {
        crate::auth::require_tenant_admin(tx, principal, tenant)?;
    }
    let current = mode(tx, tenant)?;
    if enabled && !current {
        if !has_installation(tx, tenant)? {
            return Ok(Switch::NoInstallation);
        }
        let missing = missing(tx, tenant)?;
        if !missing.is_empty() {
            return Ok(Switch::Missing(missing));
        }
    }
    if current == enabled {
        return Ok(Switch::Unchanged);
    }
    let changed = tx.execute(
        "UPDATE tenants SET runner_mode = ?2 WHERE id = ?1 AND active = 1 AND runner_mode = ?3",
        params![tenant.as_bytes(), enabled, current],
    )?;
    if changed != 1 {
        return Err(Error::Conflict);
    }
    audit(
        tx,
        Event::RunnerModeChanged,
        authority.actor(),
        None,
        authority.host_local(),
        Some(if enabled { "enabled" } else { "disabled" }),
    )?;
    Ok(Switch::Set)
}

fn has_installation(conn: &Connection, tenant: TenantId) -> Result<bool> {
    Ok(conn
        .prepare_cached(
            "SELECT EXISTS(SELECT 1 FROM installations WHERE tenant_id = ?1 AND suspended = 0)",
        )?
        .query_row([tenant.as_bytes()], |r| r.get(0))?)
}

/// How far a GitHub job has got, which only ever moves forward.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JobState {
    Queued,
    InProgress,
    Completed,
}

impl JobState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Queued => QUEUED,
            Self::InProgress => IN_PROGRESS,
            Self::Completed => COMPLETED,
        }
    }
}

/// One GitHub job as the intake recorded it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunnerJob {
    pub job: u64,
    pub run: u64,
    pub class: String,
    pub state: JobState,
    pub runner: Option<String>,
    pub conclusion: Option<String>,
    pub queued: UnixMillis,
    pub started: Option<UnixMillis>,
    pub completed: Option<UnixMillis>,
}

type JobRow = (
    i64,
    i64,
    String,
    i64,
    Option<String>,
    Option<String>,
    i64,
    Option<i64>,
    Option<i64>,
);

pub fn job(
    conn: &Connection,
    tenant: TenantId,
    repo: RepoId,
    job: u64,
) -> Result<Option<RunnerJob>> {
    let row: Option<JobRow> = conn
        .prepare_cached(
            "SELECT job_id, run_id, class, state_code, runner, conclusion, queued_ms,
                    started_ms, completed_ms
             FROM runner_jobs WHERE tenant_id = ?1 AND repo_id = ?2 AND job_id = ?3",
        )?
        .query_row(
            params![tenant.as_bytes(), repo.as_bytes(), job as i64],
            |r| {
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
            },
        )
        .optional()?;
    let Some((job, run, class, state, runner, conclusion, queued, started, completed)) = row else {
        return Ok(None);
    };
    let state = match state {
        0 => JobState::Queued,
        1 => JobState::InProgress,
        2 => JobState::Completed,
        _ => return Err(Error::Corrupt("runner job state")),
    };
    Ok(Some(RunnerJob {
        job: u64::try_from(job).map_err(|_| Error::Corrupt("runner job"))?,
        run: u64::try_from(run).map_err(|_| Error::Corrupt("runner run"))?,
        class,
        state,
        runner,
        conclusion,
        queued: UnixMillis(queued),
        started: started.map(UnixMillis),
        completed: completed.map(UnixMillis),
    }))
}
