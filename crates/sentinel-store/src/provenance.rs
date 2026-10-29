//! Values are what the authorizing adapter supplied, never inferred from a ref, so a generic Git event cannot claim PR metadata.

use rusqlite::{Connection, OptionalExtension, Transaction, params};
use sentinel_core::{DeliveryId, RepoId, RunId, TenantId, UnixMillis, UserId};

use crate::{Error, Result};

pub struct Provenance {
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

pub fn insert(
    tx: &Transaction<'_>,
    provenance: &Provenance,
    run: RunId,
    now: UnixMillis,
) -> Result<()> {
    insert_with_actor(tx, provenance, run, now, None)
}

/// A manual run also records the Sentinel user (or service account) who started it. A webhook run has no
/// such principal: the provider's sender is text its author chose, so it is not stored as one.
pub fn insert_with_actor(
    tx: &Transaction<'_>,
    provenance: &Provenance,
    run: RunId,
    now: UnixMillis,
    actor: Option<UserId>,
) -> Result<()> {
    provenance.check()?;
    tx.execute(
        "INSERT INTO run_provenance(run_id, tenant_id, repo_id, trigger, delivery_id, provider,
            ref_name, old_sha, new_sha, head_sha, base_sha, merge_sha, pipeline_sha,
            pipeline_path, pipeline_digest, pr_number, created_ms, actor_user_id)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18)",
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
            now.0,
            actor.as_ref().map(UserId::as_bytes)
        ],
    )?;
    Ok(())
}

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

pub fn cache_trust(
    conn: &Connection,
    run: RunId,
    repo: sentinel_core::RepoId,
) -> Result<sentinel_protocol::cache::Trust> {
    use sentinel_protocol::cache::Trust;
    let row: Option<(String, bool, Option<String>)> = conn
        .prepare_cached(
            "SELECT trigger, delivery_id IS NOT NULL, ref_name FROM run_provenance
             WHERE run_id = ?1",
        )?
        .query_row([run.as_bytes()], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .optional()?;
    let Some((trigger, verified, ref_name)) = row else {
        return Ok(Trust::Unprotected);
    };
    let exact = match (&*trigger, verified, ref_name) {
        ("push" | "tag", true, Some(reference)) => {
            match crate::sources::load_metadata(conn, repo) {
                Ok(meta) => {
                    !meta.revoked
                        && meta
                            .binding
                            .allowed_refs
                            .iter()
                            .any(|pattern| !pattern.contains('*') && *pattern == reference)
                }
                Err(crate::Error::NotFound) => false,
                Err(e) => return Err(e),
            }
        }
        _ => false,
    };
    Ok(Trust::derive(&trigger, verified, exact))
}

/// A run may receive secrets only when its provenance names a stored delivery that was authenticated at intake (a
/// verified webhook signature or the repository's hook secret). The fact is read from the delivery row, which only the
/// ingest adapter writes, never from the trigger text the run's provenance carries. A manual run (no delivery), a polled
/// transition (observed, never authenticated) and a run without provenance fail closed.
pub fn may_receive_secrets(conn: &Connection, run: RunId) -> Result<bool> {
    Ok(conn
        .prepare_cached(
            "SELECT p.trigger != 'manual' AND d.authentication IN (1, 2)
             FROM run_provenance p JOIN webhook_deliveries d ON d.id = p.delivery_id
             WHERE p.run_id = ?1",
        )?
        .query_row([run.as_bytes()], |r| r.get(0))
        .optional()?
        .unwrap_or(false))
}

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

pub fn trigger_of(conn: &Connection, run: RunId) -> Result<Option<String>> {
    Ok(conn
        .prepare_cached("SELECT trigger FROM run_provenance WHERE run_id = ?1")?
        .query_row([run.as_bytes()], |r| r.get::<_, String>(0))
        .optional()?)
}
