//! Logs are never refused for quota, since refusing one would hide a failure.
//! Expiry deletes a log's files only after its row commits, so a crash leaves files the directory sweep reclaims.

use std::collections::HashMap;

use rusqlite::{Connection, OptionalExtension, Transaction, params};
use sentinel_core::{ArtifactId, AttemptId, JobId, RepoId, RunId, TenantId, UnixMillis};

use crate::{Error, Result, auth::Authority};

const DAY_MS: i64 = 24 * 3_600_000;

pub const MIN_RETENTION_MS: i64 = 3_600_000;
pub const MAX_RETENTION_MS: i64 = 366 * DAY_MS;

/// Below this share of its quota a tenant is warned and nothing is refused; at the hard one the caches go first
/// and an artifact that would pass it is refused. Both are percentages of the effective quota, so one policy
/// serves every quota size.
pub const DEFAULT_SOFT_PERCENT: u8 = 80;
pub const DEFAULT_HARD_PERCENT: u8 = 100;

/// The per-tenant default a deployment that states no `tenant_quota_bytes` gives every organization, and
/// the personal namespace's own default: a twentieth of the data file system for a tenant, a fifth of that
/// for one person's namespace, each clamped so a small disk still gets a workable limit and a large one
/// still bounds a single tenant. On the reference host's measured 1,080,795,422,720-byte file system a
/// twentieth is 50.3 GiB and a hundredth 10.1 GiB, so both land on these ceilings there
/// ([retention](../../../docs/retention.md#the-default-limit)).
pub const DEFAULT_TENANT_QUOTA_BYTES: u64 = 50 << 30;
pub const MIN_TENANT_QUOTA_BYTES: u64 = 8 << 30;
pub const DEFAULT_PERSONAL_QUOTA_BYTES: u64 = 10 << 30;
pub const MIN_PERSONAL_QUOTA_BYTES: u64 = 2 << 30;

/// The defaults a data file system of `total` bytes sizes: a tenant's and a personal namespace's. One
/// function so the controller, the upgrade preflight and the tests agree on the arithmetic the page states.
pub const fn sized_quota(total: u64) -> (u64, u64) {
    let tenant = total / 20;
    let tenant = if tenant < MIN_TENANT_QUOTA_BYTES {
        MIN_TENANT_QUOTA_BYTES
    } else if tenant > DEFAULT_TENANT_QUOTA_BYTES {
        DEFAULT_TENANT_QUOTA_BYTES
    } else {
        tenant
    };
    let personal = total / 100;
    let personal = if personal < MIN_PERSONAL_QUOTA_BYTES {
        MIN_PERSONAL_QUOTA_BYTES
    } else if personal > DEFAULT_PERSONAL_QUOTA_BYTES {
        DEFAULT_PERSONAL_QUOTA_BYTES
    } else {
        personal
    };
    (tenant, personal)
}

/// The deployment's default quota for one tenant, by what kind of namespace it is: a personal namespace
/// answers to `personal_quota_bytes`, every other to `tenant_quota_bytes`. A tenant's own quota wins over
/// either, and a repository's narrows it, as before.
pub const fn default_quota(d: &Deployment, personal: bool) -> u64 {
    if personal {
        d.personal_quota_bytes
    } else {
        d.tenant_quota_bytes
    }
}

/// A tenant's position against its own thresholds. `Soft` refuses nothing: it is what the API and the
/// `sentinel_storage_tenants` metric report so an operator sees a tenant filling up before it is full.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Ok,
    Soft,
    Hard,
}

impl State {
    pub const fn as_str(self) -> &'static str {
        match self {
            State::Ok => "ok",
            State::Soft => "soft",
            State::Hard => "hard",
        }
    }
}

/// The first byte count at or above which `percent` of `quota` is reached, rounded up so that the number a
/// report shows and the comparison `check_tenant` makes are the same boundary. An unlimited tenant (quota 0)
/// has no threshold and answers 0.
pub fn limit_bytes(quota: u64, percent: u8) -> u64 {
    if quota == 0 {
        return 0;
    }
    let scaled = u128::from(quota) * u128::from(percent);
    u64::try_from(scaled.div_ceil(100)).unwrap_or(u64::MAX)
}

pub fn state(used: u64, quota: u64, soft_percent: u8, hard_percent: u8) -> State {
    if quota == 0 {
        return State::Ok;
    }
    if used >= limit_bytes(quota, hard_percent) {
        State::Hard
    } else if used >= limit_bytes(quota, soft_percent) {
        State::Soft
    } else {
        State::Ok
    }
}

/// A tenant's own thresholds narrowed to the deployment's, soft never above hard: a tenant may tighten what
/// the deployment allows and never widen it, and lowering a deployment threshold tightens every tenant with it.
pub(crate) const fn thresholds(d: &Deployment, soft: Option<u8>, hard: Option<u8>) -> (u8, u8) {
    let hard = match hard {
        Some(own) if own < d.hard_percent => own,
        _ => d.hard_percent,
    };
    let soft = match soft {
        Some(own) if own < d.soft_percent => own,
        _ => d.soft_percent,
    };
    (if soft < hard { soft } else { hard }, hard)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Deployment {
    pub quota_bytes: u64,
    /// The default an organization's tenant inherits when it states no quota of its own; 0 is an explicit
    /// unlimited, which only a platform administrator can state.
    pub tenant_quota_bytes: u64,
    /// The same for a personal namespace, whose owner is one person and whose evidence is one person's.
    pub personal_quota_bytes: u64,
    pub log_retention_ms: i64,
    pub artifact_retention_ms: i64,
    pub run_artifact_bytes: u64,
    pub soft_percent: u8,
    pub hard_percent: u8,
}

impl Default for Deployment {
    fn default() -> Self {
        Deployment {
            quota_bytes: 0,
            tenant_quota_bytes: DEFAULT_TENANT_QUOTA_BYTES,
            personal_quota_bytes: DEFAULT_PERSONAL_QUOTA_BYTES,
            log_retention_ms: 14 * DAY_MS,
            artifact_retention_ms: 90 * DAY_MS,
            run_artifact_bytes: sentinel_protocol::limits::MAX_RUN_ARTIFACT_BYTES,
            soft_percent: DEFAULT_SOFT_PERCENT,
            hard_percent: DEFAULT_HARD_PERCENT,
        }
    }
}

/// An artifact class's longest retention and how heavily its bytes count against the repository quota.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Class {
    pub name: String,
    pub max_age_ms: i64,
    pub weight: u32,
}

/// The deployment's artifact class map and the class an undeclared artifact takes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Classes {
    pub default_class: String,
    pub classes: Vec<Class>,
}

pub const CLASS_NAME_MAX: usize = 32;
pub const CLASS_WEIGHT_MAX: u32 = 100;

impl Default for Classes {
    fn default() -> Self {
        let class = |name: &str, days: i64, weight: u32| Class {
            name: name.to_owned(),
            max_age_ms: days * DAY_MS,
            weight,
        };
        Classes {
            default_class: "standard".to_owned(),
            classes: vec![
                class("debug", 7, 1),
                class("standard", 30, 1),
                class("evidence", 90, 1),
                class("release", 90, 2),
            ],
        }
    }
}

/// The one name rule: a pipeline's `artifacts[].class` and a class row are the same shape.
fn valid_class_name(name: &str) -> bool {
    name.len() <= CLASS_NAME_MAX && sentinel_pipeline::schema::valid_class_name(name)
}

impl Classes {
    /// Bounds a class map the way the other storage limits are: a name, an age within the
    /// deployment's artifact retention, a weight, and a default that names a defined class.
    pub fn validate(&self, d: &Deployment) -> Result<()> {
        if self.classes.is_empty() || !valid_class_name(&self.default_class) {
            return Err(Error::InvalidInput("artifact class"));
        }
        for class in &self.classes {
            if !valid_class_name(&class.name)
                || !(MIN_RETENTION_MS..=d.artifact_retention_ms).contains(&class.max_age_ms)
                || !(1..=CLASS_WEIGHT_MAX).contains(&class.weight)
            {
                return Err(Error::InvalidInput("artifact class"));
            }
        }
        if !self.classes.iter().any(|c| c.name == self.default_class) {
            return Err(Error::InvalidInput("default artifact class"));
        }
        Ok(())
    }
}

/// Writes the deployment's class map and default, and returns the classes whose age or weight
/// changed (or which are new), so the caller re-applies exactly those rows.
pub fn install_classes(
    tx: &Transaction<'_>,
    d: &Deployment,
    classes: &Classes,
) -> Result<Vec<String>> {
    classes.validate(d)?;
    let mut known: Vec<(String, i64, i64)> = tx
        .prepare_cached("SELECT name, max_age_ms, weight FROM artifact_classes")?
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
        .collect::<std::result::Result<_, _>>()?;
    let mut changed = Vec::new();
    for class in &classes.classes {
        let kept = known.iter().position(|(name, _, _)| *name == class.name);
        let weight = i64::from(class.weight);
        match kept {
            Some(at) => {
                let (_, age, prior) = known.remove(at);
                if age != class.max_age_ms || prior != weight {
                    changed.push(class.name.clone());
                }
            }
            None => changed.push(class.name.clone()),
        }
        tx.prepare_cached(
            "INSERT INTO artifact_classes(name, max_age_ms, weight) VALUES (?1, ?2, ?3)
             ON CONFLICT(name) DO UPDATE SET max_age_ms = excluded.max_age_ms,
                 weight = excluded.weight",
        )?
        .execute(params![class.name, class.max_age_ms, weight])?;
    }
    for (name, _, _) in known {
        tx.prepare_cached("DELETE FROM artifact_classes WHERE name = ?1")?
            .execute([name])?;
    }
    tx.prepare_cached("UPDATE storage_defaults SET default_class = ?1 WHERE id = 1")?
        .execute([&classes.default_class])?;
    Ok(changed)
}

/// The names the deployment defines, for a caller that refuses a pipeline naming another.
pub fn artifact_classes(conn: &Connection) -> Result<Vec<String>> {
    Ok(conn
        .prepare_cached("SELECT name FROM artifact_classes ORDER BY name")?
        .query_map([], |r| r.get(0))?
        .collect::<std::result::Result<_, _>>()?)
}

/// The first class a pipeline declares that the deployment does not define, if any. `defined` is
/// [`artifact_classes`]; the loader accepts any well-formed name and the deployment decides which exist.
pub fn unknown_class<'a>(
    defined: &[String],
    declared: impl Iterator<Item = &'a str>,
) -> Option<&'a str> {
    declared
        .into_iter()
        .find(|name| !defined.iter().any(|known| known == name))
}

/// The default class and the weight and maximum age of every defined class.
pub fn classes(conn: &Connection) -> Result<Classes> {
    let default_class = conn
        .prepare_cached("SELECT default_class FROM storage_defaults WHERE id = 1")?
        .query_row([], |r| r.get(0))
        .optional()?
        .unwrap_or_else(|| Classes::default().default_class);
    let classes = conn
        .prepare_cached("SELECT name, max_age_ms, weight FROM artifact_classes ORDER BY name")?
        .query_map([], |r| {
            Ok(Class {
                name: r.get(0)?,
                max_age_ms: r.get(1)?,
                weight: r.get::<_, i64>(2)?.max(0) as u32,
            })
        })?
        .collect::<std::result::Result<_, _>>()?;
    Ok(Classes {
        default_class,
        classes,
    })
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Policy {
    pub quota_bytes: Option<u64>,
    pub log_retention_ms: Option<i64>,
    pub artifact_retention_ms: Option<i64>,
    /// The tenant's thresholds; a repository row never carries them, because a threshold is the tenant's.
    pub soft_percent: Option<u8>,
    pub hard_percent: Option<u8>,
}

impl Policy {
    fn is_empty(&self) -> bool {
        *self == Policy::default()
    }
    /// Whether a quota of 0 may be written on this row: an explicit unlimited is a tenant's, and only a
    /// platform administrator reaches a tenant row, so it is refused on a repository's, which a tenant
    /// administrator sets and which narrows its tenant's quota rather than lifting it.
    fn validate(&self, unlimited: bool) -> Result<()> {
        match self.quota_bytes {
            Some(0) if !unlimited => return Err(Error::InvalidInput("quota")),
            Some(q) if q > i64::MAX as u64 => return Err(Error::InvalidInput("quota")),
            _ => {}
        }
        let percent = |p: Option<u8>| p.is_none_or(|v| (1..=100).contains(&v));
        if !percent(self.soft_percent) || !percent(self.hard_percent) {
            return Err(Error::InvalidInput("threshold"));
        }
        if matches!((self.soft_percent, self.hard_percent), (Some(soft), Some(hard)) if hard < soft)
        {
            return Err(Error::InvalidInput("threshold"));
        }
        for ms in [self.log_retention_ms, self.artifact_retention_ms]
            .into_iter()
            .flatten()
        {
            if !(MIN_RETENTION_MS..=MAX_RETENTION_MS).contains(&ms) {
                return Err(Error::InvalidInput("retention"));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Effective {
    pub tenant_quota_bytes: u64,
    pub repo_quota_bytes: u64,
    pub log_retention_ms: i64,
    pub artifact_retention_ms: i64,
    pub soft_percent: u8,
    pub hard_percent: u8,
}

fn blob_repo(repo: Option<RepoId>) -> Vec<u8> {
    repo.map_or_else(Vec::new, |r| r.as_bytes().to_vec())
}

pub fn policy(conn: &Connection, tenant: TenantId, repo: Option<RepoId>) -> Result<Policy> {
    Ok(conn
        .prepare_cached(
            "SELECT quota_bytes, log_retention_ms, artifact_retention_ms, soft_percent, hard_percent
             FROM storage_policies WHERE tenant_id = ?1 AND repo_id = ?2",
        )?
        .query_row(
            params![tenant.as_bytes().as_slice(), blob_repo(repo)],
            |r| {
                Ok(Policy {
                    quota_bytes: r.get::<_, Option<i64>>(0)?.map(|q| q as u64),
                    log_retention_ms: r.get(1)?,
                    artifact_retention_ms: r.get(2)?,
                    soft_percent: r.get::<_, Option<i64>>(3)?.map(|p| p as u8),
                    hard_percent: r.get::<_, Option<i64>>(4)?.map(|p| p as u8),
                })
            },
        )
        .optional()?
        .unwrap_or_default())
}

/// A tenant's own policy row and whether its namespace is personal, in one keyed statement: the default a
/// tenant that states no quota inherits is the personal one or the deployment's per-tenant one.
fn tenant_policy(conn: &Connection, tenant: TenantId) -> Result<(Policy, bool)> {
    Ok(conn
        .prepare_cached(
            "SELECT p.quota_bytes, p.log_retention_ms, p.artifact_retention_ms, p.soft_percent,
                    p.hard_percent, t.kind = 1
             FROM (SELECT ?1 AS id) one
             LEFT JOIN tenants t ON t.id = one.id
             LEFT JOIN storage_policies p ON p.tenant_id = one.id AND p.repo_id = X''",
        )?
        .query_row([tenant.as_bytes().as_slice()], |r| {
            Ok((
                Policy {
                    quota_bytes: r.get::<_, Option<i64>>(0)?.map(|q| q as u64),
                    log_retention_ms: r.get(1)?,
                    artifact_retention_ms: r.get(2)?,
                    soft_percent: r.get::<_, Option<i64>>(3)?.map(|p| p as u8),
                    hard_percent: r.get::<_, Option<i64>>(4)?.map(|p| p as u8),
                },
                r.get::<_, Option<bool>>(5)?.unwrap_or(false),
            ))
        })?)
}

pub fn effective(
    conn: &Connection,
    d: &Deployment,
    tenant: TenantId,
    repo: Option<RepoId>,
) -> Result<Effective> {
    let (own, personal) = tenant_policy(conn, tenant)?;
    let tenant_logs = own.log_retention_ms.unwrap_or(d.log_retention_ms);
    let tenant_artifacts = own.artifact_retention_ms.unwrap_or(d.artifact_retention_ms);
    let (soft_percent, hard_percent) = thresholds(d, own.soft_percent, own.hard_percent);
    let mut out = Effective {
        tenant_quota_bytes: own
            .quota_bytes
            .unwrap_or_else(|| default_quota(d, personal)),
        repo_quota_bytes: 0,
        log_retention_ms: tenant_logs,
        artifact_retention_ms: tenant_artifacts,
        soft_percent,
        hard_percent,
    };
    if repo.is_some() {
        let narrow = policy(conn, tenant, repo)?;
        out.repo_quota_bytes = narrow.quota_bytes.unwrap_or(0);
        out.log_retention_ms = narrow
            .log_retention_ms
            .map_or(tenant_logs, |ms| ms.min(tenant_logs));
        out.artifact_retention_ms = narrow
            .artifact_retention_ms
            .map_or(tenant_artifacts, |ms| ms.min(tenant_artifacts));
    }
    Ok(out)
}

pub fn set(
    tx: &Transaction<'_>,
    authority: &Authority,
    d: &Deployment,
    tenant: TenantId,
    repo: Option<RepoId>,
    policy: Policy,
    now: UnixMillis,
) -> Result<Reapply> {
    // Who may write first, then what: a tenant administrator who states unlimited on a repository row is
    // refused as unauthorized (a tenant row is refused for them too), and the value is judged for the
    // writer who is allowed to state it.
    match (repo, authority) {
        (None, _) => authority.require_platform(tx)?,
        (Some(_), Authority::HostLocal) => {}
        (
            Some(_),
            Authority::Credential { principal, .. } | Authority::Session { principal, .. },
        ) => crate::auth::require_tenant_admin(tx, *principal, tenant)?,
    }
    policy.validate(repo.is_none())?;
    let tenant_known: bool = tx
        .prepare_cached("SELECT EXISTS(SELECT 1 FROM tenants WHERE id = ?1)")?
        .query_row([tenant.as_bytes().as_slice()], |r| r.get(0))?;
    if !tenant_known {
        return Err(Error::NotFound);
    }
    if let Some(repo) = repo {
        let owned: bool = tx
            .prepare_cached("SELECT EXISTS(SELECT 1 FROM repos WHERE id = ?1 AND tenant_id = ?2)")?
            .query_row(
                params![repo.as_bytes().as_slice(), tenant.as_bytes().as_slice()],
                |r| r.get(0),
            )?;
        if !owned {
            return Err(Error::NotFound);
        }
        let limit = effective(tx, d, tenant, None)?;
        if policy
            .log_retention_ms
            .is_some_and(|ms| ms > limit.log_retention_ms)
            || policy
                .artifact_retention_ms
                .is_some_and(|ms| ms > limit.artifact_retention_ms)
        {
            return Err(Error::InvalidInput("retention above the tenant's"));
        }
        if limit.tenant_quota_bytes > 0
            && policy
                .quota_bytes
                .is_some_and(|q| q > limit.tenant_quota_bytes)
        {
            return Err(Error::InvalidInput("quota above the tenant's"));
        }
        if policy.soft_percent.is_some() || policy.hard_percent.is_some() {
            return Err(Error::InvalidInput("a threshold is the tenant's"));
        }
    } else if policy.soft_percent.is_some_and(|p| p > d.soft_percent)
        || policy.hard_percent.is_some_and(|p| p > d.hard_percent)
    {
        return Err(Error::InvalidInput("threshold above the deployment's"));
    }
    if policy.is_empty() {
        tx.prepare_cached("DELETE FROM storage_policies WHERE tenant_id = ?1 AND repo_id = ?2")?
            .execute(params![tenant.as_bytes().as_slice(), blob_repo(repo)])?;
    } else {
        tx.prepare_cached(
            "INSERT INTO storage_policies(tenant_id, repo_id, quota_bytes, log_retention_ms,
                 artifact_retention_ms, soft_percent, hard_percent, updated_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(tenant_id, repo_id) DO UPDATE SET
                 quota_bytes = excluded.quota_bytes,
                 log_retention_ms = excluded.log_retention_ms,
                 artifact_retention_ms = excluded.artifact_retention_ms,
                 soft_percent = excluded.soft_percent,
                 hard_percent = excluded.hard_percent,
                 updated_ms = excluded.updated_ms",
        )?
        .execute(params![
            tenant.as_bytes().as_slice(),
            blob_repo(repo),
            policy.quota_bytes.map(|q| q as i64),
            policy.log_retention_ms,
            policy.artifact_retention_ms,
            policy.soft_percent.map(i64::from),
            policy.hard_percent.map(i64::from),
            now.0,
        ])?;
    }
    reapply_step(tx, d, tenant, repo, Reapply::default(), REAPPLY_BATCH)
}

fn effective_sql(col: &str, repo: &str) -> String {
    format!(
        "(SELECT MIN(COALESCE(rp.{col}, tp), tp) FROM
            (SELECT COALESCE((SELECT {col} FROM storage_policies
                WHERE tenant_id = ?1 AND repo_id = X''), ?2) AS tp)
          LEFT JOIN storage_policies rp ON rp.tenant_id = ?1 AND rp.repo_id = {repo})"
    )
}

pub const REAPPLY_BATCH: i64 = 512;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[must_use = "the rows past the first batch are re-applied by finish_reapply"]
pub struct Reapply {
    phase: u8,
    after: [u8; 16],
}

impl Reapply {
    pub fn done(&self) -> bool {
        self.phase >= 2
    }
}

pub fn reapply_step(
    tx: &Transaction<'_>,
    d: &Deployment,
    tenant: TenantId,
    repo: Option<RepoId>,
    at: Reapply,
    batch: i64,
) -> Result<Reapply> {
    if batch < 1 {
        return Err(Error::InvalidInput("batch"));
    }
    if at.done() {
        return Ok(at);
    }
    let logs_phase = at.phase == 0;
    let (retention, expires) = if logs_phase {
        (d.log_retention_ms, "log_retention_ms")
    } else {
        (d.artifact_retention_ms, "artifact_retention_ms")
    };
    let t = tenant.as_bytes().as_slice();
    let r: Option<[u8; 16]> = repo.map(|r| *r.as_bytes());
    let (bound_sql, update) = reapply_sql(logs_phase, repo.is_some(), expires, batch);
    let bound: Option<[u8; 16]> = tx
        .prepare_cached(&bound_sql)?
        .query_row(
            params![
                t,
                retention,
                r.as_ref().map(|r| r.as_slice()),
                at.after.as_slice()
            ],
            |row| row.get(0),
        )
        .optional()?;
    let upper = bound.unwrap_or([0xff; 16]);
    tx.prepare_cached(&update)?.execute(params![
        t,
        retention,
        r.as_ref().map(|r| r.as_slice()),
        at.after.as_slice(),
        upper.as_slice()
    ])?;
    Ok(match (bound, logs_phase) {
        (Some(after), _) => Reapply { after, ..at },
        (None, true) => Reapply {
            phase: 1,
            after: [0; 16],
        },
        (None, false) => Reapply {
            phase: 2,
            after: [0; 16],
        },
    })
}

/// The two statements of one reapply step: the cursor bound and the update.
///
/// INDEXED BY pins the tenant's keyed index: without it the planner may walk every tenant's rows.
/// Both statements read at most one batch of the tenant's rows from the cursor: the bound stops at
/// `OFFSET batch - 1` and the update is confined to `(after, bound]`. A repository filter is a
/// per-row primary-key probe inside that range, never a set built from the repository's runs.
/// Public only so the query-plan tests in `tests/retention.rs` assert on the statements that run.
#[doc(hidden)]
pub fn reapply_sql(logs_phase: bool, scoped: bool, expires: &str, batch: i64) -> (String, String) {
    let (table, index, filter) = if logs_phase {
        (
            "attempts",
            "attempts_log_reapply",
            "tenant_id = ?1 AND log_expires_ms IS NOT NULL AND log_expired_ms IS NULL",
        )
    } else {
        (
            "artifacts",
            "artifacts_reapply",
            "tenant_id = ?1 AND pinned_ms IS NULL",
        )
    };
    let scope = match (scoped, logs_phase) {
        (false, _) => "",
        (true, true) => " AND repo_id = ?3",
        // A runner-mode artifact carries its repository itself; a job or run-level one names its
        // run. Both are matched here so a repository's policy re-stamps every artifact of it.
        (true, false) => {
            " AND COALESCE(artifacts.repo_id,
                 (SELECT repo_id FROM runs WHERE id = artifacts.run_id AND tenant_id = ?1)) = ?3"
        }
    };
    let bound = format!(
        "SELECT id FROM {table} INDEXED BY {index} WHERE id > ?4 AND {filter}
         ORDER BY id LIMIT 1 OFFSET {}",
        batch - 1
    );
    let update = if logs_phase {
        format!(
            "UPDATE attempts INDEXED BY {index} SET log_expires_ms = released_ms + {}
             WHERE id > ?4 AND id <= ?5 AND {filter}{scope}",
            effective_sql(expires, "COALESCE(attempts.repo_id, X'')"),
        )
    } else {
        format!(
            "UPDATE artifacts INDEXED BY {index}
             SET retain_until_ms = MIN(retain_until_ms, created_ms + MIN(
                 COALESCE((SELECT max_age_ms FROM artifact_classes
                     WHERE name = artifacts.class), 9223372036854775807),
                 {}))
             WHERE id > ?4 AND id <= ?5 AND {filter}{scope}",
            effective_sql(
                expires,
                "COALESCE(artifacts.repo_id, (SELECT repo_id FROM runs WHERE id = artifacts.run_id))"
            ),
        )
    };
    (bound, update)
}

pub fn finish_reapply(
    store: &crate::Store,
    d: &Deployment,
    tenant: TenantId,
    repo: Option<RepoId>,
    mut at: Reapply,
) -> Result<()> {
    let d = *d;
    while !at.done() {
        at = store
            .writer()
            .write(move |tx| reapply_step(tx, &d, tenant, repo, at, REAPPLY_BATCH))?;
    }
    Ok(())
}

/// Where a class re-application had reached: the last row id of the class, or done.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[must_use = "the rows past the first batch are re-applied by finish_class_reapply"]
pub struct ClassReapply {
    after: [u8; 16],
    done: bool,
}

impl ClassReapply {
    pub fn done(&self) -> bool {
        self.done
    }
}

/// The two statements of one class re-application step: the cursor bound and the update.
///
/// INDEXED BY pins the class's own index, so a changed class reads only its rows and never walks
/// another class's: the bound stops at `OFFSET batch - 1` and the update is confined to
/// `(after, bound]`. The effective retention is resolved per row from its tenant and repository;
/// a pinned artifact keeps its deadline. Public only so the query-plan tests can assert on it.
#[doc(hidden)]
pub fn class_reapply_sql(batch: i64) -> (String, String) {
    let bound = format!(
        "SELECT id FROM artifacts INDEXED BY artifacts_class_reapply
         WHERE id > ?2 AND class = ?1 AND pinned_ms IS NULL
         ORDER BY id LIMIT 1 OFFSET {}",
        batch - 1
    );
    let update = "UPDATE artifacts INDEXED BY artifacts_class_reapply
         SET charged_bytes = bytes * ?2,
             retain_until_ms = MIN(retain_until_ms, created_ms + MIN(?3,
                 COALESCE((SELECT MIN(COALESCE(rp.artifact_retention_ms, tp.ms), tp.ms) FROM
                    (SELECT COALESCE(
                        (SELECT artifact_retention_ms FROM storage_policies
                         WHERE tenant_id = artifacts.tenant_id AND repo_id = X''), ?4) AS ms) tp
                    LEFT JOIN storage_policies rp ON rp.tenant_id = artifacts.tenant_id
                        AND rp.repo_id = COALESCE(artifacts.repo_id,
                            (SELECT repo_id FROM runs WHERE id = artifacts.run_id))),
                 9223372036854775807)))
         WHERE class = ?1 AND id > ?5 AND id <= ?6 AND pinned_ms IS NULL"
        .to_owned();
    (bound, update)
}

pub fn class_reapply_step(
    tx: &Transaction<'_>,
    class: &Class,
    d: &Deployment,
    at: ClassReapply,
    batch: i64,
) -> Result<ClassReapply> {
    if batch < 1 {
        return Err(Error::InvalidInput("batch"));
    }
    if at.done {
        return Ok(at);
    }
    let (bound_sql, update) = class_reapply_sql(batch);
    let bound: Option<[u8; 16]> = tx
        .prepare_cached(&bound_sql)?
        .query_row(params![class.name, at.after.as_slice()], |row| row.get(0))
        .optional()?;
    let upper = bound.unwrap_or([0xff; 16]);
    tx.prepare_cached(&update)?.execute(params![
        class.name,
        i64::from(class.weight),
        class.max_age_ms,
        d.artifact_retention_ms,
        at.after.as_slice(),
        upper.as_slice()
    ])?;
    Ok(match bound {
        Some(after) => ClassReapply { after, done: false },
        None => ClassReapply {
            after: [0; 16],
            done: true,
        },
    })
}

/// Re-applies one class's retention ceiling and weight to every artifact of it, in bounded batches.
pub fn finish_class_reapply(store: &crate::Store, d: &Deployment, class: &Class) -> Result<()> {
    let d = *d;
    let class = class.clone();
    let mut at = ClassReapply::default();
    while !at.done() {
        let step = class.clone();
        at = store
            .writer()
            .write(move |tx| class_reapply_step(tx, &step, &d, at, REAPPLY_BATCH))?;
    }
    Ok(())
}

/// A tenant administrator pins an artifact: it is kept until unpinned, and its bytes stay counted.
/// Pinning an artifact already pinned keeps the first pin's time.
pub fn pin(
    tx: &Transaction<'_>,
    authority: &Authority,
    tenant: TenantId,
    run: RunId,
    artifact: ArtifactId,
    now: UnixMillis,
) -> Result<UnixMillis> {
    require_artifact_admin(tx, authority, tenant)?;
    let pinned: Option<i64> = tx
        .prepare_cached(
            "UPDATE artifacts SET pinned_ms = COALESCE(pinned_ms, ?4)
             WHERE tenant_id = ?1 AND run_id = ?2 AND id = ?3
             RETURNING pinned_ms",
        )?
        .query_row(
            params![
                tenant.as_bytes().as_slice(),
                run.as_bytes().as_slice(),
                artifact.as_bytes().as_slice(),
                now.0
            ],
            |r| r.get(0),
        )
        .optional()?
        .flatten();
    pinned.map(UnixMillis).ok_or(Error::NotFound)
}

/// Unpinning restores the deadline the artifact already carries: the sweep collects it at the
/// next pass when that deadline has passed.
pub fn unpin(
    tx: &Transaction<'_>,
    authority: &Authority,
    tenant: TenantId,
    run: RunId,
    artifact: ArtifactId,
) -> Result<()> {
    require_artifact_admin(tx, authority, tenant)?;
    let changed = tx
        .prepare_cached(
            "UPDATE artifacts SET pinned_ms = NULL
             WHERE tenant_id = ?1 AND run_id = ?2 AND id = ?3 AND pinned_ms IS NOT NULL",
        )?
        .execute(params![
            tenant.as_bytes().as_slice(),
            run.as_bytes().as_slice(),
            artifact.as_bytes().as_slice()
        ])?;
    if changed == 1 {
        return Ok(());
    }
    let known: bool = tx
        .prepare_cached(
            "SELECT EXISTS(SELECT 1 FROM artifacts WHERE tenant_id = ?1 AND run_id = ?2 AND id = ?3)",
        )?
        .query_row(
            params![
                tenant.as_bytes().as_slice(),
                run.as_bytes().as_slice(),
                artifact.as_bytes().as_slice()
            ],
            |r| r.get(0),
        )?;
    if known { Ok(()) } else { Err(Error::NotFound) }
}

/// Retention is evidence, so pinning it is the tenant administrator's decision, never an operator's.
fn require_artifact_admin(
    tx: &Transaction<'_>,
    authority: &Authority,
    tenant: TenantId,
) -> Result<()> {
    match authority {
        Authority::HostLocal => Ok(()),
        Authority::Credential { principal, .. } | Authority::Session { principal, .. } => {
            crate::auth::require_tenant_admin(tx, *principal, tenant)
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Usage {
    pub object_bytes: u64,
    pub log_bytes: u64,
    /// The runner-mode caches the tenant's workers reported; counted by the quota, never stored here.
    pub actions_cache_bytes: u64,
}

impl Usage {
    /// What the controller stores for the tenant: its objects and its logs.
    pub fn total(&self) -> u64 {
        self.object_bytes.saturating_add(self.log_bytes)
    }

    /// What the tenant's quota counts, the figure [`standing`] reports: the stored bytes plus the reported
    /// runner-mode caches, so an upload is refused at the same line the storage page draws.
    pub fn counted(&self) -> u64 {
        self.total().saturating_add(self.actions_cache_bytes)
    }
}

pub fn tenant_usage(conn: &Connection, tenant: TenantId) -> Result<Usage> {
    Ok(conn
        .prepare_cached(
            "SELECT bytes, log_bytes, actions_cache_bytes FROM tenant_usage WHERE tenant_id = ?1",
        )?
        .query_row([tenant.as_bytes().as_slice()], |r| {
            Ok(Usage {
                object_bytes: r.get::<_, i64>(0)?.max(0) as u64,
                log_bytes: r.get::<_, i64>(1)?.max(0) as u64,
                actions_cache_bytes: r.get::<_, i64>(2)?.max(0) as u64,
            })
        })
        .optional()?
        .unwrap_or_default())
}

pub fn deployment_usage(conn: &Connection) -> Result<u64> {
    let total: i64 = conn
        .prepare_cached("SELECT COALESCE(SUM(bytes + log_bytes), 0) FROM tenant_usage")?
        .query_row([], |r| r.get(0))?;
    Ok(total.max(0) as u64)
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RepoUsage {
    pub artifact_bytes: u64,
    pub log_bytes: u64,
}

impl RepoUsage {
    pub fn total(&self) -> u64 {
        self.artifact_bytes.saturating_add(self.log_bytes)
    }
}

pub fn repo_usage(conn: &Connection, tenant: TenantId, repo: RepoId) -> Result<RepoUsage> {
    Ok(conn
        .prepare_cached(
            "SELECT artifact_bytes, log_bytes FROM repo_usage
             WHERE tenant_id = ?1 AND repo_id = ?2",
        )?
        .query_row(
            params![tenant.as_bytes().as_slice(), repo.as_bytes().as_slice()],
            |r| {
                Ok(RepoUsage {
                    artifact_bytes: r.get::<_, i64>(0)?.max(0) as u64,
                    log_bytes: r.get::<_, i64>(1)?.max(0) as u64,
                })
            },
        )
        .optional()?
        .unwrap_or_default())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RepoStorage {
    pub repo: RepoId,
    pub name: String,
    pub usage: RepoUsage,
    pub policy: Policy,
}

/// The tenant's repository ids alone, for a pass that acts on the tenant's share of a shared store (the
/// remote cache's eviction at the hard threshold).
pub fn repo_ids(conn: &Connection, tenant: TenantId) -> Result<Vec<RepoId>> {
    let mut stmt = conn.prepare_cached("SELECT id FROM repos WHERE tenant_id = ?1")?;
    let rows = stmt.query_map([tenant.as_bytes().as_slice()], |r| r.get::<_, [u8; 16]>(0))?;
    rows.map(|row| RepoId::from_bytes(row?).map_err(|_| Error::Corrupt("repo_id")))
        .collect()
}

pub fn repos(conn: &Connection, tenant: TenantId) -> Result<Vec<RepoStorage>> {
    let mut stmt = conn.prepare_cached(
        "SELECT r.id, r.name, COALESCE(u.artifact_bytes, 0), COALESCE(u.log_bytes, 0),
                p.quota_bytes, p.log_retention_ms, p.artifact_retention_ms, p.soft_percent,
                p.hard_percent
         FROM repos r
         LEFT JOIN repo_usage u ON u.tenant_id = r.tenant_id AND u.repo_id = r.id
         LEFT JOIN storage_policies p ON p.tenant_id = r.tenant_id AND p.repo_id = r.id
         WHERE r.tenant_id = ?1 ORDER BY r.name",
    )?;
    let rows = stmt.query_map([tenant.as_bytes().as_slice()], |r| {
        Ok((
            r.get::<_, [u8; 16]>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, i64>(2)?,
            r.get::<_, i64>(3)?,
            r.get::<_, Option<i64>>(4)?,
            r.get::<_, Option<i64>>(5)?,
            r.get::<_, Option<i64>>(6)?,
            r.get::<_, Option<i64>>(7)?,
            r.get::<_, Option<i64>>(8)?,
        ))
    })?;
    let mut out = Vec::new();
    for row in rows {
        let (id, name, artifacts, logs, quota, log_ms, art_ms, soft, hard) = row?;
        out.push(RepoStorage {
            repo: RepoId::from_bytes(id).map_err(|_| Error::Corrupt("repo_id"))?,
            name,
            usage: RepoUsage {
                artifact_bytes: artifacts.max(0) as u64,
                log_bytes: logs.max(0) as u64,
            },
            policy: Policy {
                quota_bytes: quota.map(|q| q as u64),
                log_retention_ms: log_ms,
                artifact_retention_ms: art_ms,
                soft_percent: soft.map(|p| p as u8),
                hard_percent: hard.map(|p| p as u8),
            },
        });
    }
    Ok(out)
}

pub fn check_tenant(
    conn: &Connection,
    d: &Deployment,
    tenant: TenantId,
    owed: u64,
    extra: u64,
) -> Result<()> {
    let e = effective(conn, d, tenant, None)?;
    let limit = limit_bytes(e.tenant_quota_bytes, e.hard_percent);
    if limit > 0 && owed.saturating_add(extra) > limit {
        return Err(Error::QuotaExceeded);
    }
    if d.quota_bytes > 0 && deployment_usage(conn)?.saturating_add(extra) > d.quota_bytes {
        return Err(Error::QuotaExceeded);
    }
    Ok(())
}

/// A tenant's counted bytes against its own thresholds, in one keyed read: what a refusal names and what the
/// storage page and the metric report. The bytes counted are the quota's (`artifacts + uploads + logs` plus the
/// runner-mode caches a worker reported against the tenant's repositories), the same numbers `check_tenant`
/// enforces, so a report and a refusal can never disagree about where the line is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Standing {
    pub used: u64,
    pub quota_bytes: u64,
    pub soft_bytes: u64,
    pub hard_bytes: u64,
    pub soft_percent: u8,
    pub hard_percent: u8,
    pub state: State,
}

const STANDING: &str = "SELECT COALESCE(u.bytes, 0) + COALESCE(u.log_bytes, 0)
            + COALESCE(u.actions_cache_bytes, 0),
        p.quota_bytes, p.soft_percent, p.hard_percent, t.kind = 1
    FROM (SELECT ?1 AS id) one
    LEFT JOIN tenants t ON t.id = one.id
    LEFT JOIN tenant_usage u ON u.tenant_id = one.id
    LEFT JOIN storage_policies p ON p.tenant_id = one.id AND p.repo_id = X''";

pub fn standing(conn: &Connection, d: &Deployment, tenant: TenantId) -> Result<Standing> {
    let (used, quota, soft, hard, personal) =
        conn.prepare_cached(STANDING)?
            .query_row([tenant.as_bytes().as_slice()], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, Option<i64>>(1)?,
                    r.get::<_, Option<i64>>(2)?,
                    r.get::<_, Option<i64>>(3)?,
                    r.get::<_, Option<bool>>(4)?.unwrap_or(false),
                ))
            })?;
    let (soft_percent, hard_percent) = thresholds(
        d,
        soft.map(|p| p.clamp(1, 100) as u8),
        hard.map(|p| p.clamp(1, 100) as u8),
    );
    let quota_bytes = quota.map_or_else(|| default_quota(d, personal), |q| q.max(0) as u64);
    Ok(Standing {
        used: used.max(0) as u64,
        quota_bytes,
        soft_bytes: limit_bytes(quota_bytes, soft_percent),
        hard_bytes: limit_bytes(quota_bytes, hard_percent),
        soft_percent,
        hard_percent,
        state: state(used.max(0) as u64, quota_bytes, soft_percent, hard_percent),
    })
}

const STATES: &str = "SELECT COALESCE(u.bytes, 0) + COALESCE(u.log_bytes, 0)
            + COALESCE(u.actions_cache_bytes, 0),
        p.quota_bytes, p.soft_percent, p.hard_percent, t.kind = 1
    FROM tenants t
    LEFT JOIN tenant_usage u ON u.tenant_id = t.id
    LEFT JOIN storage_policies p ON p.tenant_id = t.id AND p.repo_id = X''";

/// How many tenants stand in each state, `[ok, soft, hard]`, for the metric that names no tenant. Every tenant
/// is one keyed row here: a tenant with no usage row is `ok`, and one with no policy row inherits the
/// deployment's thresholds.
pub fn states(conn: &Connection, d: &Deployment) -> Result<[u64; 3]> {
    let mut stmt = conn.prepare_cached(STATES)?;
    let rows = stmt.query_map([], |r| {
        Ok((
            r.get::<_, i64>(0)?,
            r.get::<_, Option<i64>>(1)?,
            r.get::<_, Option<i64>>(2)?,
            r.get::<_, Option<i64>>(3)?,
            r.get::<_, Option<bool>>(4)?.unwrap_or(false),
        ))
    })?;
    let mut out = [0u64; 3];
    for row in rows {
        let (used, quota, soft, hard, personal) = row?;
        let (soft_percent, hard_percent) = thresholds(
            d,
            soft.map(|p| p.clamp(1, 100) as u8),
            hard.map(|p| p.clamp(1, 100) as u8),
        );
        let quota_bytes = quota.map_or_else(|| default_quota(d, personal), |q| q.max(0) as u64);
        out[state(used.max(0) as u64, quota_bytes, soft_percent, hard_percent) as usize] += 1;
    }
    Ok(out)
}

pub fn check_repo(
    conn: &Connection,
    d: &Deployment,
    tenant: TenantId,
    repo: RepoId,
    extra: u64,
) -> Result<()> {
    let quota = effective(conn, d, tenant, Some(repo))?.repo_quota_bytes;
    if quota > 0
        && repo_usage(conn, tenant, repo)?
            .total()
            .saturating_add(extra)
            > quota
    {
        return Err(Error::QuotaExceeded);
    }
    Ok(())
}

pub fn check_run_repo(
    conn: &Connection,
    d: &Deployment,
    tenant: TenantId,
    run: RunId,
    extra: u64,
) -> Result<()> {
    let repo: Option<[u8; 16]> = conn
        .prepare_cached("SELECT repo_id FROM runs WHERE id = ?1 AND tenant_id = ?2")?
        .query_row(
            params![run.as_bytes().as_slice(), tenant.as_bytes().as_slice()],
            |r| r.get(0),
        )
        .optional()?
        .flatten();
    match repo.map(RepoId::from_bytes) {
        Some(Ok(repo)) => check_repo(conn, d, tenant, repo, extra),
        Some(Err(_)) => Err(Error::Corrupt("repo_id")),
        None => Ok(()),
    }
}

pub fn install(tx: &Transaction<'_>, d: &Deployment) -> Result<()> {
    let fits = |v: u64| i64::try_from(v).map_err(|_| Error::InvalidInput("storage limit"));
    if d.log_retention_ms <= 0 || d.artifact_retention_ms <= 0 || d.run_artifact_bytes == 0 {
        return Err(Error::InvalidInput("storage limit"));
    }
    tx.prepare_cached(
        "INSERT INTO storage_defaults(id, quota_bytes, tenant_quota_bytes, personal_quota_bytes,
             log_retention_ms, artifact_retention_ms, run_artifact_bytes, soft_percent, hard_percent,
             installed_ms)
         VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
         ON CONFLICT(id) DO UPDATE SET quota_bytes = excluded.quota_bytes,
             tenant_quota_bytes = excluded.tenant_quota_bytes,
             personal_quota_bytes = excluded.personal_quota_bytes,
             log_retention_ms = excluded.log_retention_ms,
             artifact_retention_ms = excluded.artifact_retention_ms,
             run_artifact_bytes = excluded.run_artifact_bytes,
             soft_percent = excluded.soft_percent,
             hard_percent = excluded.hard_percent,
             installed_ms = excluded.installed_ms",
    )?
    .execute(params![
        fits(d.quota_bytes)?,
        fits(d.tenant_quota_bytes)?,
        fits(d.personal_quota_bytes)?,
        d.log_retention_ms,
        d.artifact_retention_ms,
        fits(d.run_artifact_bytes)?,
        i64::from(d.soft_percent),
        i64::from(d.hard_percent),
        UnixMillis::now().0,
    ])?;
    Ok(())
}

pub fn installed(conn: &Connection) -> Result<Deployment> {
    Ok(conn
        .prepare_cached(
            "SELECT quota_bytes, tenant_quota_bytes, personal_quota_bytes, log_retention_ms,
                    artifact_retention_ms, run_artifact_bytes, soft_percent, hard_percent
             FROM storage_defaults WHERE id = 1",
        )?
        .query_row([], |r| {
            Ok(Deployment {
                quota_bytes: r.get::<_, i64>(0)?.max(0) as u64,
                tenant_quota_bytes: r.get::<_, i64>(1)?.max(0) as u64,
                personal_quota_bytes: r.get::<_, i64>(2)?.max(0) as u64,
                log_retention_ms: r.get(3)?,
                artifact_retention_ms: r.get(4)?,
                run_artifact_bytes: r.get::<_, i64>(5)?.max(1) as u64,
                soft_percent: r.get::<_, i64>(6)?.clamp(1, 100) as u8,
                hard_percent: r.get::<_, i64>(7)?.clamp(1, 100) as u8,
            })
        })
        .optional()?
        .unwrap_or_default())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Unstamped {
    pub attempt: AttemptId,
    pub run: RunId,
    pub job: JobId,
    pub tenant: TenantId,
    pub repo: Option<RepoId>,
    pub released_ms: i64,
}

fn id<T>(
    bytes: [u8; 16],
    f: fn([u8; 16]) -> std::result::Result<T, sentinel_core::InvalidId>,
    what: &'static str,
) -> Result<T> {
    f(bytes).map_err(|_| Error::Corrupt(what))
}

fn unstamped_row(
    attempt: [u8; 16],
    run: [u8; 16],
    job: [u8; 16],
    tenant: [u8; 16],
    repo: Option<[u8; 16]>,
    released_ms: i64,
) -> Result<Unstamped> {
    Ok(Unstamped {
        attempt: id(attempt, AttemptId::from_bytes, "attempt_id")?,
        run: id(run, RunId::from_bytes, "run_id")?,
        job: id(job, JobId::from_bytes, "job_id")?,
        tenant: id(tenant, TenantId::from_bytes, "tenant_id")?,
        repo: repo
            .map(|r| id(r, RepoId::from_bytes, "repo_id"))
            .transpose()?,
        released_ms,
    })
}

pub fn unstamped(conn: &Connection, limit: u32) -> Result<Vec<Unstamped>> {
    let mut stmt = conn.prepare_cached(
        "SELECT a.id, j.run_id, a.job_id, a.tenant_id, a.repo_id, a.released_ms
         FROM attempts a INDEXED BY attempts_log_unstamped
         JOIN jobs j ON j.id = a.job_id
         WHERE a.released_ms IS NOT NULL AND a.log_expires_ms IS NULL
         ORDER BY a.released_ms LIMIT ?1",
    )?;
    let rows = stmt.query_map([i64::from(limit)], |r| {
        Ok((
            r.get::<_, [u8; 16]>(0)?,
            r.get::<_, [u8; 16]>(1)?,
            r.get::<_, [u8; 16]>(2)?,
            r.get::<_, [u8; 16]>(3)?,
            r.get::<_, Option<[u8; 16]>>(4)?,
            r.get::<_, i64>(5)?,
        ))
    })?;
    let mut out = Vec::new();
    for row in rows {
        let (attempt, run, job, tenant, repo, released_ms) = row?;
        // One damaged row must not stop the rows behind it: it is counted and named, and the batch goes on.
        match unstamped_row(attempt, run, job, tenant, repo, released_ms) {
            Ok(row) => out.push(row),
            Err(Error::Corrupt(_)) => crate::skipped::note_blob("attempts", &attempt),
            Err(e) => return Err(e),
        }
    }
    Ok(out)
}

pub fn stamp(tx: &Transaction<'_>, d: &Deployment, logs: &[(Unstamped, u64)]) -> Result<u32> {
    let mut retention: HashMap<(TenantId, Option<RepoId>), i64> = HashMap::new();
    let mut stamped = 0u32;
    for (row, bytes) in logs {
        let key = (row.tenant, row.repo);
        let ms = match retention.get(&key) {
            Some(ms) => *ms,
            None => {
                let ms = effective(tx, d, row.tenant, row.repo)?.log_retention_ms;
                retention.insert(key, ms);
                ms
            }
        };
        stamped += tx
            .prepare_cached(
                "UPDATE attempts SET log_bytes = ?2, log_expires_ms = ?3
                 WHERE id = ?1 AND log_expires_ms IS NULL",
            )?
            .execute(params![
                row.attempt.as_bytes().as_slice(),
                i64::try_from(*bytes).unwrap_or(i64::MAX),
                row.released_ms.saturating_add(ms),
            ])? as u32;
    }
    Ok(stamped)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Expiring {
    pub attempt: AttemptId,
    pub run: RunId,
    pub job: JobId,
}

fn expiring_row(attempt: [u8; 16], run: [u8; 16], job: [u8; 16]) -> Result<Expiring> {
    Ok(Expiring {
        attempt: id(attempt, AttemptId::from_bytes, "attempt_id")?,
        run: id(run, RunId::from_bytes, "run_id")?,
        job: id(job, JobId::from_bytes, "job_id")?,
    })
}

pub fn expiring(conn: &Connection, now: UnixMillis, limit: u32) -> Result<Vec<Expiring>> {
    let mut stmt = conn.prepare_cached(
        "SELECT a.id, j.run_id, a.job_id
         FROM attempts a INDEXED BY attempts_log_expiry
         JOIN jobs j ON j.id = a.job_id
         WHERE a.log_expires_ms IS NOT NULL AND a.log_expired_ms IS NULL
           AND a.log_expires_ms <= ?1
         ORDER BY a.log_expires_ms LIMIT ?2",
    )?;
    let rows = stmt.query_map(params![now.0, i64::from(limit)], |r| {
        Ok((
            r.get::<_, [u8; 16]>(0)?,
            r.get::<_, [u8; 16]>(1)?,
            r.get::<_, [u8; 16]>(2)?,
        ))
    })?;
    let mut out = Vec::new();
    for row in rows {
        let (attempt, run, job) = row?;
        match expiring_row(attempt, run, job) {
            Ok(row) => out.push(row),
            Err(Error::Corrupt(_)) => crate::skipped::note_blob("attempts", &attempt),
            Err(e) => return Err(e),
        }
    }
    Ok(out)
}

pub fn expire(tx: &Transaction<'_>, logs: &[Expiring], now: UnixMillis) -> Result<Vec<Expiring>> {
    let mut out = Vec::with_capacity(logs.len());
    for log in logs {
        let changed = tx
            .prepare_cached(
                "UPDATE attempts SET log_expired_ms = ?2, log_bytes = 0
                 WHERE id = ?1 AND log_expired_ms IS NULL
                   AND log_expires_ms IS NOT NULL AND log_expires_ms <= ?2",
            )?
            .execute(params![log.attempt.as_bytes().as_slice(), now.0])?;
        if changed == 1 {
            out.push(*log);
        }
    }
    Ok(out)
}

pub fn log_gone(conn: &Connection, attempt: AttemptId) -> Result<bool> {
    let expired: Option<bool> = conn
        .prepare_cached("SELECT log_expired_ms IS NOT NULL FROM attempts WHERE id = ?1")?
        .query_row([attempt.as_bytes().as_slice()], |r| r.get(0))
        .optional()?;
    Ok(expired.unwrap_or(true))
}

pub fn log_expired(conn: &Connection, attempt: AttemptId) -> Result<Option<UnixMillis>> {
    Ok(conn
        .prepare_cached("SELECT log_expired_ms FROM attempts WHERE id = ?1")?
        .query_row([attempt.as_bytes().as_slice()], |r| {
            r.get::<_, Option<i64>>(0)
        })
        .optional()?
        .flatten()
        .map(UnixMillis))
}

pub const ABORTED_UPLOAD_KEEP_MS: i64 = 7 * DAY_MS;

/// Committed sessions stay: they authorize reads of the object they produced.
pub fn purge_aborted_uploads(tx: &Transaction<'_>, now: UnixMillis, limit: u32) -> Result<u32> {
    let ids: Vec<Vec<u8>> = tx
        .prepare_cached(
            "SELECT id FROM uploads INDEXED BY uploads_aborted
             WHERE state_code = 2 AND expires_ms < ?1 LIMIT ?2",
        )?
        .query_map(
            params![now.0 - ABORTED_UPLOAD_KEEP_MS, i64::from(limit)],
            |r| r.get(0),
        )?
        .collect::<std::result::Result<_, _>>()?;
    let mut purged = 0u32;
    for id in ids {
        purged += tx
            .prepare_cached("DELETE FROM uploads WHERE id = ?1 AND state_code = 2")?
            .execute([id])? as u32;
    }
    Ok(purged)
}
