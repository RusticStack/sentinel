//! Per-class storage accounting: what a tenant stores, split by what holds it.
//!
//! `artifacts`, `uploads` and `logs` are kept by the triggers of migration 65 (and the log triggers of 46) in the same
//! transaction that writes the underlying row, so a class total is never behind a committed fact and a crash cannot
//! leave it wrong. `remote_cache` and `worker_cache` are reported: the first by the controller's reclamation pass, the
//! second by the triggers that follow a worker's availability report. `actions_cache` has no writer until runner mode.
//! `recount` derives every database-held class from the facts alone, for the audit that proves the totals.

use std::collections::HashMap;

use rusqlite::{Connection, OptionalExtension, Transaction, params};
use sentinel_core::{ArtifactId, RepoId, TenantId, UnixMillis};

use crate::{Error, Result, Store};

pub const DAY_MS: i64 = 86_400_000;
/// Snapshots a tenant keeps; the same number is in the `storage_class_snapshots_bound` trigger.
pub const SNAPSHOT_DAYS: usize = 90;
const REPORT_BATCH: usize = 256;

pub const CLASS_NAMES: [&str; 6] = [
    "artifacts",
    "uploads",
    "logs",
    "remote_cache",
    "actions_cache",
    "worker_cache",
];

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Classes {
    pub artifacts: u64,
    pub uploads: u64,
    pub logs: u64,
    pub remote_cache: u64,
    pub actions_cache: u64,
    pub worker_cache: u64,
}

impl Classes {
    /// What the tenant quota counts: the classes held in the object store and the log directory.
    pub fn stored(&self) -> u64 {
        self.artifacts
            .saturating_add(self.uploads)
            .saturating_add(self.logs)
    }

    /// Each class under its metric label, in `CLASS_NAMES` order.
    pub fn by_name(&self) -> [(&'static str, u64); 6] {
        [
            (CLASS_NAMES[0], self.artifacts),
            (CLASS_NAMES[1], self.uploads),
            (CLASS_NAMES[2], self.logs),
            (CLASS_NAMES[3], self.remote_cache),
            (CLASS_NAMES[4], self.actions_cache),
            (CLASS_NAMES[5], self.worker_cache),
        ]
    }
}

fn clamp(value: i64) -> u64 {
    value.max(0) as u64
}

fn classes_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<Classes> {
    Ok(Classes {
        artifacts: clamp(r.get(0)?),
        uploads: clamp(r.get(1)?),
        logs: clamp(r.get(2)?),
        remote_cache: clamp(r.get(3)?),
        actions_cache: clamp(r.get(4)?),
        worker_cache: clamp(r.get(5)?),
    })
}

const TENANT: &str =
    "SELECT artifact_bytes, upload_bytes, log_bytes, remote_cache_bytes, actions_cache_bytes,
        worker_cache_bytes FROM tenant_usage WHERE tenant_id = ?1";
const DEPLOYMENT: &str = "SELECT COALESCE(SUM(artifact_bytes), 0), COALESCE(SUM(upload_bytes), 0),
        COALESCE(SUM(MAX(log_bytes, 0)), 0), COALESCE(SUM(remote_cache_bytes), 0),
        COALESCE(SUM(actions_cache_bytes), 0), COALESCE(SUM(worker_cache_bytes), 0) FROM tenant_usage";
const ARTIFACTS_RECOUNT: &str = "SELECT COALESCE(SUM(o.len), 0) FROM objects o WHERE o.tenant_id = ?1
        AND EXISTS(SELECT 1 FROM manifest_refs r WHERE r.tenant_id = o.tenant_id AND r.digest = o.digest)";
const UNREFERENCED_RECOUNT: &str = "SELECT COALESCE(SUM(o.len), 0) FROM objects o WHERE o.tenant_id = ?1
        AND NOT EXISTS(SELECT 1 FROM manifest_refs r WHERE r.tenant_id = o.tenant_id AND r.digest = o.digest)";
const OPEN_UPLOADS_RECOUNT: &str =
    "SELECT COALESCE(SUM(declared_len), 0) FROM uploads INDEXED BY uploads_open
        WHERE tenant_id = ?1 AND state_code = 0";
/// A log is counted from its stamp until its expiry: `log_bytes` is zero outside that window, which the partial index names.
const LOGS_RECOUNT: &str =
    "SELECT COALESCE(SUM(log_bytes), 0) FROM attempts INDEXED BY attempts_log_reapply
        WHERE tenant_id = ?1 AND log_expires_ms IS NOT NULL AND log_expired_ms IS NULL";
const WORKER_CACHE_RECOUNT: &str = "SELECT COALESCE(SUM(MAX(w.cache_bytes, 0)), 0) FROM pools p
        JOIN workers w ON w.pool_id = p.id AND w.revoked_ms IS NULL
        WHERE p.owner_tenant_id = ?1 AND p.kind = 0";
const REPORTED: &str =
    "SELECT remote_cache_bytes, actions_cache_bytes FROM tenant_usage WHERE tenant_id = ?1";
const REPO_TENANT: &str = "SELECT tenant_id FROM repos WHERE id = ?1";
const REMOTE_SET: &str = "INSERT INTO tenant_usage(tenant_id, remote_cache_bytes) VALUES(?1, ?2)
        ON CONFLICT(tenant_id) DO UPDATE SET remote_cache_bytes = excluded.remote_cache_bytes";
const REMOTE_HOLDERS: &str = "SELECT tenant_id FROM tenant_usage INDEXED BY tenant_usage_remote
        WHERE remote_cache_bytes != 0 AND tenant_id > ?1 ORDER BY tenant_id LIMIT ?2";
const REMOTE_CLEAR: &str = "UPDATE tenant_usage SET remote_cache_bytes = 0 WHERE tenant_id = ?1";
const SNAPSHOT_KEYS: &str =
    "SELECT tenant_id FROM tenant_usage WHERE tenant_id > ?1 ORDER BY tenant_id LIMIT ?2";
const SNAPSHOT_INSERT: &str = "INSERT OR IGNORE INTO storage_class_snapshots(tenant_id, day, taken_ms,
        artifact_bytes, upload_bytes, log_bytes, remote_cache_bytes, actions_cache_bytes, worker_cache_bytes)
        SELECT tenant_id, ?2, ?3, artifact_bytes, upload_bytes, MAX(log_bytes, 0), remote_cache_bytes,
            actions_cache_bytes, worker_cache_bytes FROM tenant_usage WHERE tenant_id = ?1";
const SNAPSHOTS: &str =
    "SELECT day, taken_ms, artifact_bytes, upload_bytes, log_bytes, remote_cache_bytes,
        actions_cache_bytes, worker_cache_bytes FROM storage_class_snapshots
        WHERE tenant_id = ?1 ORDER BY day DESC LIMIT ?2";

/// Every statement this module adds, named, so a test can assert each one is answered by a key and not a table scan.
pub const STATEMENTS: &[(&str, &str)] = &[
    ("tenant", TENANT),
    ("reported", REPORTED),
    ("artifacts_recount", ARTIFACTS_RECOUNT),
    ("unreferenced_recount", UNREFERENCED_RECOUNT),
    ("open_uploads_recount", OPEN_UPLOADS_RECOUNT),
    ("logs_recount", LOGS_RECOUNT),
    ("worker_cache_recount", WORKER_CACHE_RECOUNT),
    ("repo_tenant", REPO_TENANT),
    ("remote_set", REMOTE_SET),
    ("remote_holders", REMOTE_HOLDERS),
    ("remote_clear", REMOTE_CLEAR),
    ("snapshot_keys", SNAPSHOT_KEYS),
    ("snapshot_insert", SNAPSHOT_INSERT),
    ("snapshots", SNAPSHOTS),
];

/// The reads the storage page adds beyond the class totals, each with the index that answers it: the two expiry
/// figures are range reads over a partial index, and the heaviest-first list walks the tenant's own artifacts. A
/// plan test asserts every one of them names its index and none scans a table.
pub const PAGE_READS: &[(&str, &str, &str)] = &[
    ("largest", LARGEST, "artifacts_by_run"),
    (
        "expiring_artifacts",
        EXPIRING_ARTIFACTS,
        "artifacts_retention",
    ),
    ("expiring_totals", EXPIRING_TOTALS, "artifacts_retention"),
    ("expiring_logs", EXPIRING_LOGS, "attempts_log_expiry"),
];

/// The tenant's classes as the triggers and reports keep them; a tenant that never stored anything has none.
pub fn tenant(conn: &Connection, tenant: TenantId) -> Result<Classes> {
    Ok(conn
        .prepare_cached(TENANT)?
        .query_row([tenant.as_bytes().as_slice()], classes_row)
        .optional()?
        .unwrap_or_default())
}

/// Every tenant together. One row per tenant is read, as `retention::deployment_usage` does.
pub fn deployment(conn: &Connection) -> Result<Classes> {
    Ok(conn
        .prepare_cached(DEPLOYMENT)?
        .query_row([], classes_row)?)
}

/// The audit: each database-held class summed from the rows that make it, walking the tenant's objects, open sessions,
/// stamped logs and dedicated-pool workers. The reported classes that no row holds (`remote_cache`, `actions_cache`)
/// are returned as stored. Never on a request path.
pub fn recount(conn: &Connection, tenant: TenantId) -> Result<Classes> {
    let id = tenant.as_bytes().as_slice();
    let sum = |sql: &str| -> Result<u64> {
        Ok(clamp(
            conn.prepare_cached(sql)?.query_row([id], |r| r.get(0))?,
        ))
    };
    let reported = conn
        .prepare_cached(REPORTED)?
        .query_row([id], |r| Ok((clamp(r.get(0)?), clamp(r.get(1)?))))
        .optional()?
        .unwrap_or_default();
    Ok(Classes {
        artifacts: sum(ARTIFACTS_RECOUNT)?,
        uploads: sum(UNREFERENCED_RECOUNT)?.saturating_add(sum(OPEN_UPLOADS_RECOUNT)?),
        logs: sum(LOGS_RECOUNT)?,
        remote_cache: reported.0,
        actions_cache: reported.1,
        worker_cache: sum(WORKER_CACHE_RECOUNT)?,
    })
}

/// Publishes what a complete walk of the remote cache store found, per repository: each tenant's bundles become its
/// `remote_cache` class, and a tenant that held bytes and no longer does goes to zero. A repository no row names is
/// not attributed. Batched like the other passes (one writer transaction per 256 tenants) and idempotent, so a crash
/// midway only leaves some tenants on the previous pass's figure. Call it only with a complete walk: a partial one
/// would report a smaller total than the store holds.
pub fn report_remote_cache(store: &Store, repos: &[(RepoId, u64)]) -> Result<()> {
    let mut totals: HashMap<[u8; 16], u64> = HashMap::new();
    for chunk in repos.chunks(REPORT_BATCH) {
        store.read(|c| {
            let mut stmt = c.prepare_cached(REPO_TENANT)?;
            for (repo, bytes) in chunk {
                let owner = stmt
                    .query_row([repo.as_bytes().as_slice()], |r| r.get::<_, [u8; 16]>(0))
                    .optional()?;
                if let Some(owner) = owner {
                    let held = totals.entry(owner).or_insert(0);
                    *held = held.saturating_add(*bytes);
                }
            }
            Ok(())
        })?;
    }
    let set: Vec<([u8; 16], i64)> = totals
        .iter()
        .map(|(tenant, bytes)| (*tenant, i64::try_from(*bytes).unwrap_or(i64::MAX)))
        .collect();
    for chunk in set.chunks(REPORT_BATCH) {
        let chunk = chunk.to_vec();
        store.writer().write(move |tx| {
            let mut stmt = tx.prepare_cached(REMOTE_SET)?;
            for (tenant, bytes) in &chunk {
                stmt.execute(params![tenant.as_slice(), bytes])?;
            }
            Ok(())
        })?;
    }
    let mut after = [0u8; 16];
    loop {
        let page: Vec<[u8; 16]> = store.read(|c| {
            let rows = c
                .prepare_cached(REMOTE_HOLDERS)?
                .query_map(params![after.as_slice(), REPORT_BATCH as i64], |r| {
                    r.get::<_, [u8; 16]>(0)
                })?
                .collect::<std::result::Result<_, _>>()?;
            Ok(rows)
        })?;
        let Some(last) = page.last().copied() else {
            return Ok(());
        };
        let gone: Vec<[u8; 16]> = page
            .iter()
            .filter(|tenant| !totals.contains_key(*tenant))
            .copied()
            .collect();
        if !gone.is_empty() {
            store.writer().write(move |tx| {
                let mut stmt = tx.prepare_cached(REMOTE_CLEAR)?;
                for tenant in &gone {
                    stmt.execute([tenant.as_slice()])?;
                }
                Ok(())
            })?;
        }
        if page.len() < REPORT_BATCH {
            return Ok(());
        }
        after = last;
    }
}

/// The UTC day a millisecond belongs to; the snapshot key.
pub fn day_of(at: UnixMillis) -> i64 {
    at.0.div_euclid(DAY_MS)
}

/// One batch of the day's snapshot: the next `limit` tenants after `after` (in key order) that have usage rows each
/// get their row for `day` unless they already have it, so a pass that is repeated or resumed after a restart adds
/// nothing twice. Returns the tenants seen and the last key; a batch of `limit` means more may follow, from that key.
/// A tenant's oldest rows beyond the newest ninety leave in the same statement (trigger), so the bound holds for any writer.
pub fn snapshot_day(
    tx: &Transaction<'_>,
    day: i64,
    taken: UnixMillis,
    after: Option<[u8; 16]>,
    limit: u32,
) -> Result<(u32, Option<[u8; 16]>)> {
    let after = after.unwrap_or([0u8; 16]);
    let keys: Vec<[u8; 16]> = tx
        .prepare_cached(SNAPSHOT_KEYS)?
        .query_map(params![after.as_slice(), i64::from(limit)], |r| r.get(0))?
        .collect::<std::result::Result<_, _>>()?;
    let mut stmt = tx.prepare_cached(SNAPSHOT_INSERT)?;
    for key in &keys {
        stmt.execute(params![key.as_slice(), day, taken.0])?;
    }
    Ok((keys.len() as u32, keys.last().copied()))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Snapshot {
    pub day: i64,
    pub taken_ms: i64,
    pub classes: Classes,
}

/// A tenant's snapshots, newest first, at most `limit`.
pub fn snapshots(conn: &Connection, tenant: TenantId, limit: usize) -> Result<Vec<Snapshot>> {
    let mut stmt = conn.prepare_cached(SNAPSHOTS)?;
    let rows = stmt.query_map(params![tenant.as_bytes().as_slice(), limit as i64], |r| {
        Ok(Snapshot {
            day: r.get(0)?,
            taken_ms: r.get(1)?,
            classes: Classes {
                artifacts: clamp(r.get(2)?),
                uploads: clamp(r.get(3)?),
                logs: clamp(r.get(4)?),
                remote_cache: clamp(r.get(5)?),
                actions_cache: clamp(r.get(6)?),
                worker_cache: clamp(r.get(7)?),
            },
        })
    })?;
    Ok(rows.collect::<std::result::Result<_, _>>()?)
}

/// One artifact as the storage page lists it: the bytes it holds against the quota and when they go.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Item {
    pub artifact: ArtifactId,
    pub name: String,
    pub class: String,
    pub repo: Option<String>,
    pub bytes: u64,
    pub expires: UnixMillis,
    pub pinned: bool,
}

/// The heaviest artifacts a tenant holds, heaviest first. Bounded by `limit`: SQLite sorts the tenant's own rows for
/// the order and keeps the head of it, which is the one sort this page's reads cannot avoid without an index of its
/// own (the metadata schema is frozen here), so the walk is the tenant's artifacts and nothing else.
const LARGEST: &str = "SELECT a.id, a.name, a.class, a.bytes, a.retain_until_ms, a.pinned_ms,
        (SELECT p.name FROM repos p WHERE p.id = COALESCE(a.repo_id,
            (SELECT r.repo_id FROM runs r WHERE r.id = a.run_id)))
     FROM artifacts a INDEXED BY artifacts_by_run
     WHERE a.tenant_id = ?1 AND a.state_code = 0
     ORDER BY a.bytes DESC LIMIT ?2";

/// The artifacts that expire from `now` to `until` (not the pinned ones, which the sweep keeps), soonest first.
const EXPIRING_ARTIFACTS: &str =
    "SELECT a.id, a.name, a.class, a.bytes, a.retain_until_ms, a.pinned_ms,
        (SELECT p.name FROM repos p WHERE p.id = COALESCE(a.repo_id,
            (SELECT r.repo_id FROM runs r WHERE r.id = a.run_id)))
     FROM artifacts a INDEXED BY artifacts_retention
     WHERE a.retain_until_ms <= ?2 AND a.pinned_ms IS NULL AND a.state_code = 0
       AND a.tenant_id = ?1
     ORDER BY a.retain_until_ms LIMIT ?3";

/// The tenant's expiring artifact bytes and log bytes in one row each; the same window as the list above.
const EXPIRING_TOTALS: &str = "SELECT COALESCE(SUM(bytes), 0), COUNT(*)
     FROM artifacts a INDEXED BY artifacts_retention
     WHERE a.retain_until_ms <= ?2 AND a.pinned_ms IS NULL AND a.state_code = 0
       AND a.tenant_id = ?1";

/// A tenant's stamped, unexpired logs due by `until`. The partial index is on the deadline alone, so the walk is the
/// logs due in the window for every tenant and the tenant's are the rows kept — bounded by the window, never by the
/// tenant's whole log history.
const EXPIRING_LOGS: &str = "SELECT COALESCE(SUM(log_bytes), 0), COUNT(*)
     FROM attempts INDEXED BY attempts_log_expiry
     WHERE log_expires_ms <= ?2 AND tenant_id = ?1 AND log_expired_ms IS NULL";

type ItemRow = (
    [u8; 16],
    String,
    String,
    i64,
    i64,
    Option<i64>,
    Option<String>,
);

fn item(r: &rusqlite::Row<'_>) -> rusqlite::Result<ItemRow> {
    Ok((
        r.get(0)?,
        r.get(1)?,
        r.get(2)?,
        r.get(3)?,
        r.get(4)?,
        r.get(5)?,
        r.get(6)?,
    ))
}

fn item_of((id, name, class, bytes, expires, pinned, repo): ItemRow) -> Result<Item> {
    Ok(Item {
        artifact: ArtifactId::from_bytes(id).map_err(|_| Error::Corrupt("artifact_id"))?,
        name,
        class,
        repo,
        bytes: clamp(bytes),
        expires: UnixMillis(expires),
        pinned: pinned.is_some(),
    })
}

fn items(rows: impl Iterator<Item = rusqlite::Result<ItemRow>>) -> Result<Vec<Item>> {
    let mut out = Vec::new();
    for row in rows {
        out.push(item_of(row?)?);
    }
    Ok(out)
}

pub fn largest(conn: &Connection, tenant: TenantId, limit: usize) -> Result<Vec<Item>> {
    let mut stmt = conn.prepare_cached(LARGEST)?;
    let rows = stmt.query_map(params![tenant.as_bytes().as_slice(), limit as i64], item)?;
    items(rows)
}

/// What a tenant loses inside a window, and the soonest artifacts in it when a list is asked for.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Expiry {
    pub artifacts: u64,
    pub artifact_bytes: u64,
    pub logs: u64,
    pub log_bytes: u64,
    pub items: Vec<Item>,
}

pub fn expiring(
    conn: &Connection,
    tenant: TenantId,
    until: UnixMillis,
    limit: usize,
) -> Result<Expiry> {
    let id = tenant.as_bytes().as_slice();
    let totals = |sql: &str| -> Result<(u64, u64)> {
        let (bytes, count) = conn
            .prepare_cached(sql)?
            .query_row(params![id, until.0], |r| {
                Ok((clamp(r.get(0)?), clamp(r.get(1)?)))
            })?;
        Ok((bytes, count))
    };
    let (artifact_bytes, artifacts) = totals(EXPIRING_TOTALS)?;
    let (log_bytes, logs) = totals(EXPIRING_LOGS)?;
    let soonest = if limit == 0 {
        Vec::new()
    } else {
        let mut stmt = conn.prepare_cached(EXPIRING_ARTIFACTS)?;
        let rows = stmt.query_map(params![id, until.0, limit as i64], item)?;
        items(rows)?
    };
    Ok(Expiry {
        artifacts,
        artifact_bytes,
        logs,
        log_bytes,
        items: soonest,
    })
}
