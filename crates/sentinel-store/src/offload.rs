use rusqlite::{Connection, OptionalExtension, Transaction, params};
use sentinel_core::{AttemptId, JobId, RunId, TenantId, UnixMillis};

use crate::{Error, Result, objects::Digest};

fn tenant(bytes: Vec<u8>) -> Result<TenantId> {
    TenantId::from_bytes(
        <[u8; 16]>::try_from(bytes.as_slice()).map_err(|_| Error::Corrupt("tenant_id"))?,
    )
    .map_err(|_| Error::Corrupt("tenant_id"))
}

fn digest(bytes: Vec<u8>) -> Result<Digest> {
    Ok(Digest::from_bytes(
        <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| Error::Corrupt("object digest"))?,
    ))
}

fn id16<T>(
    bytes: Vec<u8>,
    f: fn([u8; 16]) -> std::result::Result<T, sentinel_core::InvalidId>,
    what: &'static str,
) -> Result<T> {
    f(<[u8; 16]>::try_from(bytes.as_slice()).map_err(|_| Error::Corrupt(what))?)
        .map_err(|_| Error::Corrupt(what))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ObjectRef {
    pub tenant: TenantId,
    pub digest: Digest,
    pub len: u64,
}

fn object_rows(conn: &Connection, sql: &str, limit: u32) -> Result<Vec<ObjectRef>> {
    let mut stmt = conn.prepare_cached(sql)?;
    let rows = stmt.query_map([i64::from(limit)], |r| {
        Ok((
            r.get::<_, Vec<u8>>(0)?,
            r.get::<_, Vec<u8>>(1)?,
            r.get::<_, i64>(2)?,
        ))
    })?;
    let mut out = Vec::new();
    for row in rows {
        let (t, d, len) = row?;
        out.push(ObjectRef {
            tenant: tenant(t)?,
            digest: digest(d)?,
            len: len.max(0) as u64,
        });
    }
    Ok(out)
}

pub fn unreplicated(conn: &Connection, limit: u32) -> Result<Vec<ObjectRef>> {
    object_rows(
        conn,
        "SELECT tenant_id, digest, len FROM objects INDEXED BY objects_unreplicated
         WHERE remote_ms IS NULL ORDER BY created_ms LIMIT ?1",
        limit,
    )
}

pub fn replicated(tx: &Transaction<'_>, object: &ObjectRef, now: UnixMillis) -> Result<bool> {
    Ok(tx
        .prepare_cached(
            "UPDATE objects SET remote_ms = ?3
             WHERE tenant_id = ?1 AND digest = ?2 AND remote_ms IS NULL",
        )?
        .execute(params![
            object.tenant.as_bytes().as_slice(),
            object.digest.as_bytes().as_slice(),
            now.0
        ])?
        == 1)
}

pub fn evictable(conn: &Connection, limit: u32) -> Result<Vec<ObjectRef>> {
    object_rows(
        conn,
        "SELECT tenant_id, digest, len FROM objects INDEXED BY objects_evictable
         WHERE remote_ms IS NOT NULL AND evicted_ms IS NULL ORDER BY created_ms LIMIT ?1",
        limit,
    )
}

/// Their files are removed only after this commit.
pub fn evicted(
    tx: &Transaction<'_>,
    objects: &[(TenantId, Digest)],
    now: UnixMillis,
) -> Result<u32> {
    let mut n = 0;
    for (t, d) in objects {
        n += tx
            .prepare_cached(
                "UPDATE objects SET evicted_ms = ?3
                 WHERE tenant_id = ?1 AND digest = ?2 AND remote_ms IS NOT NULL AND evicted_ms IS NULL",
            )?
            .execute(params![t.as_bytes().as_slice(), d.as_bytes().as_slice(), now.0])? as u32;
    }
    Ok(n)
}

pub fn local_again(tx: &Transaction<'_>, objects: &[(TenantId, Digest)]) -> Result<u32> {
    let mut n = 0;
    for (t, d) in objects {
        n +=
            tx.prepare_cached(
                "UPDATE objects SET evicted_ms = NULL
                 WHERE tenant_id = ?1 AND digest = ?2 AND evicted_ms IS NOT NULL",
            )?
            .execute(params![t.as_bytes().as_slice(), d.as_bytes().as_slice()])? as u32;
    }
    Ok(n)
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Totals {
    pub local_bytes: u64,
    pub unreplicated_bytes: u64,
    pub oldest_unreplicated_ms: Option<i64>,
    pub unreplicated_logs: u64,
}

pub fn totals(conn: &Connection) -> Result<Totals> {
    let (local, backlog): (i64, i64) = conn
        .prepare_cached("SELECT local_bytes, unreplicated_bytes FROM object_totals WHERE id = 1")?
        .query_row([], |r| Ok((r.get(0)?, r.get(1)?)))
        .optional()?
        .unwrap_or((0, 0));
    let oldest: Option<i64> = conn
        .prepare_cached(
            "SELECT created_ms FROM objects INDEXED BY objects_unreplicated
             WHERE remote_ms IS NULL ORDER BY created_ms LIMIT 1",
        )?
        .query_row([], |r| r.get(0))
        .optional()?;
    let logs: i64 = conn
        .prepare_cached(
            "SELECT COUNT(*) FROM attempts INDEXED BY attempts_log_unreplicated
             WHERE log_expires_ms IS NOT NULL AND log_expired_ms IS NULL AND log_remote_ms IS NULL",
        )?
        .query_row([], |r| r.get(0))?;
    Ok(Totals {
        local_bytes: local.max(0) as u64,
        unreplicated_bytes: backlog.max(0) as u64,
        oldest_unreplicated_ms: oldest,
        unreplicated_logs: logs.max(0) as u64,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LogRef {
    pub attempt: AttemptId,
    pub run: RunId,
    pub job: JobId,
    pub released_ms: i64,
}

pub fn unreplicated_logs(
    conn: &Connection,
    settled_before: UnixMillis,
    limit: u32,
) -> Result<Vec<LogRef>> {
    let mut stmt = conn.prepare_cached(
        "SELECT a.id, j.run_id, a.job_id, a.released_ms
         FROM attempts a INDEXED BY attempts_log_unreplicated JOIN jobs j ON j.id = a.job_id
         WHERE a.log_expires_ms IS NOT NULL AND a.log_expired_ms IS NULL
           AND a.log_remote_ms IS NULL AND a.released_ms <= ?1
         ORDER BY a.released_ms LIMIT ?2",
    )?;
    let rows = stmt.query_map(params![settled_before.0, i64::from(limit)], |r| {
        Ok((
            r.get::<_, Vec<u8>>(0)?,
            r.get::<_, Vec<u8>>(1)?,
            r.get::<_, Vec<u8>>(2)?,
            r.get::<_, i64>(3)?,
        ))
    })?;
    let mut out = Vec::new();
    for row in rows {
        let (a, r, j, released_ms) = row?;
        out.push(LogRef {
            attempt: id16(a, AttemptId::from_bytes, "attempt_id")?,
            run: id16(r, RunId::from_bytes, "run_id")?,
            job: id16(j, JobId::from_bytes, "job_id")?,
            released_ms,
        });
    }
    Ok(out)
}

pub fn log_replicated(tx: &Transaction<'_>, attempt: AttemptId, now: UnixMillis) -> Result<bool> {
    Ok(tx
        .prepare_cached(
            "UPDATE attempts SET log_remote_ms = ?2
             WHERE id = ?1 AND log_remote_ms IS NULL AND log_expired_ms IS NULL",
        )?
        .execute(params![attempt.as_bytes().as_slice(), now.0])?
        == 1)
}

pub fn log_prefix(run: RunId, job: JobId, attempt: AttemptId) -> String {
    format!("logs/{run}/{job}/{attempt}/")
}

pub fn upload(conn: &Connection, key: &str) -> Result<Option<(String, u64)>> {
    Ok(conn
        .prepare_cached("SELECT upload_id, part_bytes FROM s3_uploads WHERE key = ?1")?
        .query_row([key], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)? as u64))
        })
        .optional()?)
}

pub fn record_upload(
    tx: &Transaction<'_>,
    key: &str,
    upload_id: &str,
    part_bytes: u64,
    now: UnixMillis,
) -> Result<()> {
    tx.prepare_cached(
        "INSERT INTO s3_uploads(key, upload_id, part_bytes, created_ms) VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(key) DO UPDATE SET upload_id = excluded.upload_id,
             part_bytes = excluded.part_bytes, created_ms = excluded.created_ms",
    )?
    .execute(params![key, upload_id, part_bytes as i64, now.0])?;
    Ok(())
}

pub fn forget_upload(tx: &Transaction<'_>, key: &str) -> Result<()> {
    tx.prepare_cached("DELETE FROM s3_uploads WHERE key = ?1")?
        .execute([key])?;
    Ok(())
}

pub fn recorded_uploads(conn: &Connection) -> Result<Vec<(String, String, i64)>> {
    let mut stmt = conn.prepare_cached("SELECT key, upload_id, created_ms FROM s3_uploads")?;
    let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
    Ok(rows.collect::<std::result::Result<_, _>>()?)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Delete {
    Object {
        id: i64,
        tenant: TenantId,
        digest: Digest,
    },
    Log {
        id: i64,
        run: RunId,
        job: JobId,
        attempt: AttemptId,
    },
}

impl Delete {
    pub fn id(&self) -> i64 {
        match self {
            Delete::Object { id, .. } | Delete::Log { id, .. } => *id,
        }
    }
}

pub fn deletes(conn: &Connection, limit: u32) -> Result<Vec<Delete>> {
    let mut stmt = conn.prepare_cached(
        "SELECT id, kind, tenant_id, digest, run_id, job_id, attempt_id
         FROM s3_deletes ORDER BY id LIMIT ?1",
    )?;
    let rows = stmt.query_map([i64::from(limit)], |r| {
        Ok((
            r.get::<_, i64>(0)?,
            r.get::<_, i64>(1)?,
            r.get::<_, Option<Vec<u8>>>(2)?,
            r.get::<_, Option<Vec<u8>>>(3)?,
            r.get::<_, Option<Vec<u8>>>(4)?,
            r.get::<_, Option<Vec<u8>>>(5)?,
            r.get::<_, Option<Vec<u8>>>(6)?,
        ))
    })?;
    let mut out = Vec::new();
    for row in rows {
        let (id, kind, t, d, run, job, attempt) = row?;
        out.push(match (kind, t, d, run, job, attempt) {
            (0, Some(t), Some(d), _, _, _) => Delete::Object {
                id,
                tenant: tenant(t)?,
                digest: digest(d)?,
            },
            (1, _, _, Some(r), Some(j), Some(a)) => Delete::Log {
                id,
                run: id16(r, RunId::from_bytes, "run_id")?,
                job: id16(j, JobId::from_bytes, "job_id")?,
                attempt: id16(a, AttemptId::from_bytes, "attempt_id")?,
            },
            _ => return Err(Error::Corrupt("s3 delete")),
        });
    }
    Ok(out)
}

pub fn queue_object_delete(
    tx: &Transaction<'_>,
    tenant: TenantId,
    digest: &Digest,
    now: UnixMillis,
) -> Result<()> {
    tx.prepare_cached(
        "INSERT INTO s3_deletes(kind, tenant_id, digest, queued_ms) VALUES (0, ?1, ?2, ?3)",
    )?
    .execute(params![
        tenant.as_bytes().as_slice(),
        digest.as_bytes().as_slice(),
        now.0
    ])?;
    Ok(())
}

/// A live row for the digest owns the S3 copy, so the queued delete is dropped.
/// The check and the drop share the caller's transaction, so no commit lands between them.
pub fn keep_if_live(
    tx: &Transaction<'_>,
    id: i64,
    tenant: TenantId,
    digest: &Digest,
) -> Result<bool> {
    let live: bool = tx
        .prepare_cached(
            "SELECT EXISTS(SELECT 1 FROM objects WHERE tenant_id = ?1 AND digest = ?2)",
        )?
        .query_row(
            params![tenant.as_bytes().as_slice(), digest.as_bytes().as_slice()],
            |r| r.get(0),
        )?;
    if live {
        delete_done(tx, id)?;
    }
    Ok(live)
}

pub fn delete_done(tx: &Transaction<'_>, id: i64) -> Result<()> {
    tx.prepare_cached("DELETE FROM s3_deletes WHERE id = ?1")?
        .execute([id])?;
    Ok(())
}
