//! A captured row commits with its manifest version, so an artifact is never half-published.

use rusqlite::{Connection, OptionalExtension, Transaction, params};
use sentinel_core::{ArtifactId, AttemptId, JobId, RunId, TenantId, UnixMillis};

use crate::{
    Error, Result,
    objects::{self, Objects},
};

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

#[derive(Clone, Debug)]
pub struct Row {
    pub id: ArtifactId,
    pub job: JobId,
    pub job_name: String,
    pub attempt: AttemptId,
    pub name: String,
    pub state: State,
    pub manifest_version: Option<u64>,
    pub entries: u64,
    pub bytes: u64,
    pub retain_until_ms: UnixMillis,
    pub created_ms: UnixMillis,
}

pub fn manifest_name(job: JobId, name: &str) -> String {
    format!("{job}/{name}")
}

// UNIQUE(attempt_id, name) turns a redelivered insert into a conflict, not a duplicate.
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
    if name.is_empty() || name.len() > 64 {
        return Err(Error::InvalidInput("artifact name"));
    }
    if (state == State::Captured) != manifest_version.is_some() {
        return Err(Error::InvalidInput("artifact manifest"));
    }
    let id = ArtifactId::new();
    tx.execute(
        "INSERT INTO artifacts(id, tenant_id, run_id, job_id, attempt_id, name,
             state_code, manifest_version, entries, bytes, retain_until_ms, created_ms)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
        params![
            id.as_bytes().as_slice(),
            tenant.as_bytes().as_slice(),
            run.as_bytes().as_slice(),
            job.as_bytes().as_slice(),
            attempt.as_bytes().as_slice(),
            name,
            state.code(),
            manifest_version.map(|v| v as i64),
            entries as i64,
            bytes as i64,
            retain_until.0,
            now.0,
        ],
    )?;
    Ok(id)
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

pub fn for_run(conn: &Connection, tenant: TenantId, run: RunId) -> Result<Vec<Row>> {
    let mut stmt = conn.prepare_cached(
        "SELECT a.id, a.job_id, j.name, a.attempt_id, a.name, a.state_code,
                a.manifest_version, a.entries, a.bytes, a.retain_until_ms, a.created_ms
         FROM artifacts a JOIN jobs j ON j.id = a.job_id
         WHERE a.tenant_id = ?1 AND a.run_id = ?2
         ORDER BY j.created_seq, a.created_ms, a.name",
    )?;
    let rows = stmt.query_map(
        params![tenant.as_bytes().as_slice(), run.as_bytes().as_slice()],
        |r| {
            Ok((
                r.get::<_, Vec<u8>>(0)?,
                r.get::<_, Vec<u8>>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, Vec<u8>>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, i64>(5)?,
                r.get::<_, Option<i64>>(6)?,
                r.get::<_, i64>(7)?,
                r.get::<_, i64>(8)?,
                r.get::<_, i64>(9)?,
                r.get::<_, i64>(10)?,
            ))
        },
    )?;
    let mut out = Vec::new();
    for row in rows {
        let (id, job, job_name, attempt, name, state, version, entries, bytes, retain, created) =
            row?;
        out.push(Row {
            id: ArtifactId::from_bytes(
                <[u8; 16]>::try_from(id.as_slice()).map_err(|_| Error::Corrupt("artifact id"))?,
            )
            .map_err(|_| Error::Corrupt("artifact id"))?,
            job: JobId::from_bytes(
                <[u8; 16]>::try_from(job.as_slice()).map_err(|_| Error::Corrupt("job id"))?,
            )
            .map_err(|_| Error::Corrupt("job id"))?,
            job_name,
            attempt: AttemptId::from_bytes(
                <[u8; 16]>::try_from(attempt.as_slice())
                    .map_err(|_| Error::Corrupt("attempt id"))?,
            )
            .map_err(|_| Error::Corrupt("attempt id"))?,
            name,
            state: State::from_code(state)?,
            manifest_version: version.map(|v| v as u64),
            entries: entries as u64,
            bytes: bytes as u64,
            retain_until_ms: UnixMillis(retain),
            created_ms: UnixMillis(created),
        });
    }
    Ok(out)
}

/// A foreign or absent id answers NotFound, so a tenant cannot probe for another tenant's records.
pub fn get(conn: &Connection, tenant: TenantId, run: RunId, id: ArtifactId) -> Result<Row> {
    let row = conn
        .prepare_cached(
            "SELECT a.id, a.job_id, j.name, a.attempt_id, a.name, a.state_code,
                    a.manifest_version, a.entries, a.bytes, a.retain_until_ms, a.created_ms
             FROM artifacts a JOIN jobs j ON j.id = a.job_id
             WHERE a.tenant_id = ?1 AND a.run_id = ?2 AND a.id = ?3",
        )?
        .query_row(
            params![
                tenant.as_bytes().as_slice(),
                run.as_bytes().as_slice(),
                id.as_bytes().as_slice()
            ],
            |r| {
                Ok((
                    r.get::<_, Vec<u8>>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, Vec<u8>>(3)?,
                    r.get::<_, String>(4)?,
                    r.get::<_, i64>(5)?,
                    r.get::<_, Option<i64>>(6)?,
                    r.get::<_, i64>(7)?,
                    r.get::<_, i64>(8)?,
                    r.get::<_, i64>(9)?,
                    r.get::<_, i64>(10)?,
                ))
            },
        )
        .optional()?
        .ok_or(Error::NotFound)?;
    let (job, job_name, attempt, name, state, version, entries, bytes, retain, created) = row;
    Ok(Row {
        id,
        job: JobId::from_bytes(
            <[u8; 16]>::try_from(job.as_slice()).map_err(|_| Error::Corrupt("job id"))?,
        )
        .map_err(|_| Error::Corrupt("job id"))?,
        job_name,
        attempt: AttemptId::from_bytes(
            <[u8; 16]>::try_from(attempt.as_slice()).map_err(|_| Error::Corrupt("attempt id"))?,
        )
        .map_err(|_| Error::Corrupt("attempt id"))?,
        name,
        state: State::from_code(state)?,
        manifest_version: version.map(|v| v as u64),
        entries: entries as u64,
        bytes: bytes as u64,
        retain_until_ms: UnixMillis(retain),
        created_ms: UnixMillis(created),
    })
}

pub fn captured(
    conn: &Connection,
    tenant: TenantId,
    run: RunId,
    job_name: &str,
    name: &str,
) -> Result<Row> {
    let row = conn
        .prepare_cached(
            "SELECT a.id, a.job_id, j.name, a.attempt_id, a.name, a.state_code,
                    a.manifest_version, a.entries, a.bytes, a.retain_until_ms, a.created_ms
             FROM artifacts a JOIN jobs j ON j.id = a.job_id
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
            |r| {
                Ok((
                    r.get::<_, Vec<u8>>(0)?,
                    r.get::<_, Vec<u8>>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, Vec<u8>>(3)?,
                    r.get::<_, String>(4)?,
                    r.get::<_, i64>(5)?,
                    r.get::<_, Option<i64>>(6)?,
                    r.get::<_, i64>(7)?,
                    r.get::<_, i64>(8)?,
                    r.get::<_, i64>(9)?,
                    r.get::<_, i64>(10)?,
                ))
            },
        )
        .optional()?
        .ok_or(Error::NotFound)?;
    let (id, job, job_name, attempt, name, state, version, entries, bytes, retain, created) = row;
    Ok(Row {
        id: ArtifactId::from_bytes(
            <[u8; 16]>::try_from(id.as_slice()).map_err(|_| Error::Corrupt("artifact id"))?,
        )
        .map_err(|_| Error::Corrupt("artifact id"))?,
        job: JobId::from_bytes(
            <[u8; 16]>::try_from(job.as_slice()).map_err(|_| Error::Corrupt("job id"))?,
        )
        .map_err(|_| Error::Corrupt("job id"))?,
        job_name,
        attempt: AttemptId::from_bytes(
            <[u8; 16]>::try_from(attempt.as_slice()).map_err(|_| Error::Corrupt("attempt id"))?,
        )
        .map_err(|_| Error::Corrupt("attempt id"))?,
        name,
        state: State::from_code(state)?,
        manifest_version: version.map(|v| v as u64),
        entries: entries as u64,
        bytes: bytes as u64,
        retain_until_ms: UnixMillis(retain),
        created_ms: UnixMillis(created),
    })
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
    type Due = (Vec<u8>, Vec<u8>, Vec<u8>, String, Option<i64>);
    let due: Vec<Due> = tx
        .prepare(
            "SELECT id, tenant_id, job_id, name, manifest_version
             FROM artifacts WHERE retain_until_ms <= ?1 LIMIT ?2",
        )?
        .query_map(params![now.0, limit], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
        })?
        .collect::<std::result::Result<_, _>>()?;
    let expired = due.len();
    let mut paths = Vec::new();
    for (id, tenant, job, name, version) in due {
        if let Some(version) = version {
            let tenant = objects::tenant_from(tenant)?;
            let job = JobId::from_bytes(
                <[u8; 16]>::try_from(job.as_slice()).map_err(|_| Error::Corrupt("job id"))?,
            )
            .map_err(|_| Error::Corrupt("job id"))?;
            if let Some(path) = objects.retire_manifest(
                tx,
                tenant,
                objects::Kind::Artifact,
                &manifest_name(job, &name),
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
