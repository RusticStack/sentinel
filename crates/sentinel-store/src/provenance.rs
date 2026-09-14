//! Why a run exists: one immutable row per run, written in the same
//! transaction as the run itself (G03).
//!
//! A manual dispatch names its pipeline inline and has no delivery; an event
//! names the delivery that produced it, the ref transition, and — for a pull
//! request — the head, base and tested-merge revisions. `pipeline_sha` is the
//! revision the pipeline file was read from, which is not necessarily the
//! revision that will be checked out. Nothing here is inferred from a ref:
//! the values are what the authorizing adapter supplied, and a generic Git
//! event can never claim PR metadata.

use rusqlite::{Connection, OptionalExtension, Transaction, params};
use sentinel_core::{DeliveryId, RepoId, RunId, TenantId, UnixMillis};

use crate::{Error, Result};

/// The terms of one run's provenance. Owned: the dispatch transaction moves
/// them onto the writer thread.
pub struct Provenance {
    pub tenant: TenantId,
    pub repo: RepoId,
    /// `push`, `tag`, `pull_request` or `manual`.
    pub trigger: String,
    /// The delivery that produced this run; `None` for manual dispatch.
    pub delivery: Option<DeliveryId>,
    /// The provider that authenticated the event; `None` for manual dispatch.
    pub provider: Option<String>,
    /// The full ref the event concerns (the base branch for a pull request).
    pub ref_name: Option<String>,
    /// The observed ref transition, when the event was one.
    pub old_sha: Option<String>,
    pub new_sha: Option<String>,
    /// Pull-request provenance: the head tip, the base tip and the tested
    /// merge commit GitHub computed, when there was one.
    pub head_sha: Option<String>,
    pub base_sha: Option<String>,
    pub merge_sha: Option<String>,
    pub pipeline_sha: String,
    /// The bound pipeline path; `None` when the pipeline was submitted inline.
    pub pipeline_path: Option<String>,
    /// The compiled content digest.
    pub pipeline_digest: [u8; 16],
    /// The pull request number, when the run came from one.
    pub pr_number: Option<u64>,
}

impl Provenance {
    fn check(&self) -> Result<()> {
        let bounded = |value: &Option<String>, max: usize| {
            value
                .as_ref()
                .is_none_or(|v| !v.is_empty() && v.len() <= max)
        };
        if self.trigger.is_empty()
            || self.trigger.len() > 32
            || self.pipeline_sha.is_empty()
            || self.pipeline_sha.len() > 64
            || (self.delivery.is_none()) != (self.provider.is_none())
            || !bounded(&self.provider, 32)
            || !bounded(&self.ref_name, 1024)
            || !bounded(&self.pipeline_path, 1024)
            || self
                .pr_number
                .is_some_and(|n| n == 0 || n > i64::MAX as u64)
            || [
                &self.old_sha,
                &self.new_sha,
                &self.head_sha,
                &self.base_sha,
                &self.merge_sha,
            ]
            .into_iter()
            .any(|sha| !bounded(sha, 64))
        {
            return Err(Error::InvalidInput("run provenance"));
        }
        Ok(())
    }
}

/// Insert one run's provenance. The store refuses a rewrite or a delete.
pub fn insert(
    tx: &Transaction<'_>,
    provenance: &Provenance,
    run: RunId,
    now: UnixMillis,
) -> Result<()> {
    provenance.check()?;
    tx.execute(
        "INSERT INTO run_provenance(run_id, tenant_id, repo_id, trigger, delivery_id, provider,
            ref_name, old_sha, new_sha, head_sha, base_sha, merge_sha, pipeline_sha,
            pipeline_path, pipeline_digest, pr_number, created_ms)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)",
        params![
            run.as_bytes(),
            provenance.tenant.as_bytes(),
            provenance.repo.as_bytes(),
            provenance.trigger,
            provenance.delivery.as_ref().map(DeliveryId::as_bytes),
            provenance.provider,
            provenance.ref_name,
            provenance.old_sha,
            provenance.new_sha,
            provenance.head_sha,
            provenance.base_sha,
            provenance.merge_sha,
            provenance.pipeline_sha,
            provenance.pipeline_path,
            provenance.pipeline_digest.as_slice(),
            provenance.pr_number.map(|n| n as i64),
            now.0
        ],
    )?;
    Ok(())
}

/// A run's provenance as read back.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunProvenance {
    pub run: RunId,
    pub tenant: TenantId,
    pub repo: RepoId,
    pub trigger: String,
    pub delivery: Option<DeliveryId>,
    pub provider: Option<String>,
    pub ref_name: Option<String>,
    pub old_sha: Option<String>,
    pub new_sha: Option<String>,
    pub head_sha: Option<String>,
    pub base_sha: Option<String>,
    pub merge_sha: Option<String>,
    pub pipeline_sha: String,
    pub pipeline_path: Option<String>,
    pub pipeline_digest: [u8; 16],
    pub pr_number: Option<u64>,
    pub created: UnixMillis,
}

/// The event facts expressions and the worker context see, derived from
/// provenance. `event.key` is a short, stable key: the branch or tag name,
/// `pr-<n>`, or `manual`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EventFacts {
    pub name: String,
    pub ref_name: String,
    pub base_ref: Option<String>,
    pub pr_number: Option<u64>,
    pub key: String,
}

impl EventFacts {
    fn of(trigger: &str, ref_name: Option<&str>, pr_number: Option<u64>) -> EventFacts {
        let ref_name = ref_name.unwrap_or_default().to_owned();
        let short = ref_name
            .strip_prefix("refs/heads/")
            .or_else(|| ref_name.strip_prefix("refs/tags/"))
            .map(str::to_owned);
        match trigger {
            "pull_request" => {
                let number = pr_number;
                EventFacts {
                    name: trigger.to_owned(),
                    // The merge ref is what was tested; keep the base ref in
                    // `base_ref` where a pipeline can filter on it.
                    ref_name: number
                        .map(|n| format!("refs/pull/{n}/merge"))
                        .unwrap_or_else(|| "refs/pull/unknown/merge".to_owned()),
                    base_ref: short,
                    pr_number: number,
                    key: number
                        .map(|n| format!("pr-{n}"))
                        .unwrap_or_else(|| "pr".to_owned()),
                }
            }
            other => EventFacts {
                name: other.to_owned(),
                ref_name,
                base_ref: None,
                pr_number: None,
                key: short.unwrap_or_else(|| other.to_owned()),
            },
        }
    }
}

/// One run's event facts. A run without provenance (created by a raw store
/// primitive, or before this contract) is the manual mode: the only path that
/// did not record one.
pub fn event_facts(conn: &Connection, run: RunId) -> Result<EventFacts> {
    let row: Option<(String, Option<String>, Option<i64>)> = conn
        .prepare_cached(
            "SELECT trigger, ref_name, pr_number FROM run_provenance WHERE run_id = ?1",
        )?
        .query_row([run.as_bytes()], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .optional()?;
    Ok(match row {
        Some((trigger, ref_name, number)) => EventFacts::of(
            &trigger,
            ref_name.as_deref(),
            number.and_then(|n| u64::try_from(n).ok()),
        ),
        None => EventFacts::of("manual", None, None),
    })
}

/// One run's provenance; `None` for a run created before this contract
/// (or by a path that does not record it).
pub fn of_run(conn: &Connection, run: RunId) -> Result<Option<RunProvenance>> {
    type Row = (
        [u8; 16],
        [u8; 16],
        String,
        Option<[u8; 16]>,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        String,
        Option<String>,
        Vec<u8>,
        Option<i64>,
        i64,
    );
    let row: Option<Row> = conn
        .prepare_cached(
            "SELECT tenant_id, repo_id, trigger, delivery_id, provider, ref_name, old_sha,
                    new_sha, head_sha, base_sha, merge_sha, pipeline_sha, pipeline_path,
                    pipeline_digest, pr_number, created_ms
             FROM run_provenance WHERE run_id = ?1",
        )?
        .query_row([run.as_bytes()], |r| {
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
            ))
        })
        .optional()?;
    let Some((
        tenant,
        repo,
        trigger,
        delivery,
        provider,
        ref_name,
        old_sha,
        new_sha,
        head_sha,
        base_sha,
        merge_sha,
        pipeline_sha,
        pipeline_path,
        digest,
        pr_number,
        created,
    )) = row
    else {
        return Ok(None);
    };
    let digest: [u8; 16] = digest
        .try_into()
        .map_err(|_| Error::Corrupt("pipeline_digest"))?;
    Ok(Some(RunProvenance {
        run,
        tenant: TenantId::from_bytes(tenant).map_err(|_| Error::Corrupt("tenant_id"))?,
        repo: RepoId::from_bytes(repo).map_err(|_| Error::Corrupt("repo_id"))?,
        trigger,
        delivery: match delivery {
            Some(bytes) => {
                Some(DeliveryId::from_bytes(bytes).map_err(|_| Error::Corrupt("delivery_id"))?)
            }
            None => None,
        },
        provider,
        ref_name,
        old_sha,
        new_sha,
        head_sha,
        base_sha,
        merge_sha,
        pipeline_sha,
        pipeline_path,
        pipeline_digest: digest,
        pr_number: pr_number.and_then(|n| u64::try_from(n).ok()),
        created: UnixMillis(created),
    }))
}

/// The event kind of a run, for the status views. `None` means the run has no
/// provenance row (created before G03).
pub fn trigger_of(conn: &Connection, run: RunId) -> Result<Option<String>> {
    Ok(conn
        .prepare_cached("SELECT trigger FROM run_provenance WHERE run_id = ?1")?
        .query_row([run.as_bytes()], |r| r.get::<_, String>(0))
        .optional()?)
}
