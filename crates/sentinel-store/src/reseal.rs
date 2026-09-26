//! Every sealed column in one place: whether any exists (a controller must
//! not start without its key when one does), whether the loaded key opens
//! them, and moving them to the active key so retired keys can be dropped.
//!
//! Sealed values live in `secret_versions.sealed` (revoked versions
//! included), `mfa_totp.sealed_seed` and `source_bindings.credential`. Each
//! row's context is derived from its own columns, exactly as the writer that
//! sealed it derived it.

use std::sync::Arc;

use rusqlite::{Connection, OptionalExtension, params};
use sentinel_auth::sealed::{Key, key_id, secret_context};
use sentinel_core::{RepoId, TenantId, UserId};

use crate::{Error, Result, Store};

/// Rows each writer transaction reseals: bounded writer hold time.
pub const BATCH: u32 = 256;

/// Whether any sealed value is stored. Three indexed `EXISTS` probes.
pub fn sealed_rows_exist(conn: &Connection) -> Result<bool> {
    Ok(conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM secret_versions) OR EXISTS(SELECT 1 FROM mfa_totp)
             OR EXISTS(SELECT 1 FROM source_bindings)",
        [],
        |r| r.get(0),
    )?)
}

/// Open the newest row of each sealed table with `key`: a key file that
/// does not match the restored database fails here, at start, instead of at
/// first use. Bounded: at most one row per table.
pub fn verify_key(conn: &Connection, key: &Key) -> Result<()> {
    let secret: Option<Row> = conn
        .query_row(
            "SELECT v.secret_id,v.version,v.sealed,s.tenant_id,s.scope_repo_id,s.name
             FROM secret_versions v JOIN secrets s ON s.id=v.secret_id
             ORDER BY v.created_ms DESC LIMIT 1",
            [],
            secret_row,
        )
        .optional()?;
    if let Some(row) = secret {
        opens(key, &secret_row_context(&row)?, &row.2, "secret_versions")?;
    }
    let seed: Option<([u8; 16], Vec<u8>)> = conn
        .query_row(
            "SELECT user_id,sealed_seed FROM mfa_totp ORDER BY created_ms DESC LIMIT 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    if let Some((user, sealed)) = seed {
        let user = UserId::from_bytes(user).map_err(|_| Error::Corrupt("mfa_totp.user_id"))?;
        opens(key, &crate::mfa::context(user), &sealed, "mfa_totp")?;
    }
    let source: Option<([u8; 16], [u8; 16], i64, Vec<u8>)> = conn
        .query_row(
            "SELECT repo_id,tenant_id,version,credential FROM source_bindings
             ORDER BY updated_ms DESC LIMIT 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .optional()?;
    if let Some(row) = source {
        let context = source_context(row.0, row.1, row.2)?;
        opens(key, &context, &row.3, "source_bindings")?;
    }
    Ok(())
}

fn opens(key: &Key, context: &[u8], sealed: &[u8], what: &'static str) -> Result<()> {
    let mut plain = key
        .open(context, sealed)
        .map_err(|_| Error::Corrupt(what))?;
    plain.fill(0);
    core::hint::black_box(&mut plain);
    Ok(())
}

/// How many stored values name a key other than `key`'s active one. Zero
/// is the precondition for retiring every other key. A full scan: offline
/// administration only.
pub fn stale(conn: &Connection, key: &Key) -> Result<u64> {
    let active = key.active_id().to_be_bytes();
    let count = |sql: &str| -> Result<u64> {
        Ok(conn.query_row(sql, [active.as_slice()], |r| r.get::<_, i64>(0))? as u64)
    };
    Ok(count(
        "SELECT count(*) FROM secret_versions
         WHERE substr(sealed,1,1)!=x'02' OR substr(sealed,2,4)!=?1",
    )? + count(
        "SELECT count(*) FROM mfa_totp
         WHERE substr(sealed_seed,1,1)!=x'02' OR substr(sealed_seed,2,4)!=?1",
    )? + count(
        "SELECT count(*) FROM source_bindings
         WHERE substr(credential,1,1)!=x'02' OR substr(credential,2,4)!=?1",
    )?)
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Progress {
    /// Rows looked at.
    pub examined: u64,
    /// Rows rewritten under the active key.
    pub resealed: u64,
}

/// Move every sealed value to the active key, [`BATCH`] rows per writer
/// transaction. Offline (the caller holds the database ownership lock).
/// Resumable: a crash between batches leaves some rows on the old key and
/// some on the new; running again skips the rows already moved without
/// decrypting them. A row that does not open is `Corrupt` and stops the run,
/// since retiring its key would lose it.
pub fn reseal_all(store: &Store, key: Arc<Key>) -> Result<Progress> {
    let mut progress = Progress::default();
    let mut after = ([0u8; 16], 0i64);
    loop {
        let key = Arc::clone(&key);
        let (step, next) = store
            .writer()
            .write(move |tx| reseal_secrets(tx, &key, after))?;
        progress.examined += step.examined;
        progress.resealed += step.resealed;
        match next {
            Some(cursor) => after = cursor,
            None => break,
        }
    }
    let mut after = [0u8; 16];
    loop {
        let key = Arc::clone(&key);
        let (step, next) = store
            .writer()
            .write(move |tx| reseal_seeds(tx, &key, after))?;
        progress.examined += step.examined;
        progress.resealed += step.resealed;
        match next {
            Some(cursor) => after = cursor,
            None => break,
        }
    }
    let mut after = [0u8; 16];
    loop {
        let key = Arc::clone(&key);
        let (step, next) = store
            .writer()
            .write(move |tx| reseal_sources(tx, &key, after))?;
        progress.examined += step.examined;
        progress.resealed += step.resealed;
        match next {
            Some(cursor) => after = cursor,
            None => break,
        }
    }
    Ok(progress)
}

type Row = ([u8; 16], i64, Vec<u8>, [u8; 16], Option<[u8; 16]>, String);

fn secret_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<Row> {
    Ok((
        r.get(0)?,
        r.get(1)?,
        r.get(2)?,
        r.get(3)?,
        r.get(4)?,
        r.get(5)?,
    ))
}

fn secret_row_context(row: &Row) -> Result<Vec<u8>> {
    let version = u64::try_from(row.1).map_err(|_| Error::Corrupt("secret version"))?;
    Ok(secret_context(&row.3, row.4.as_ref(), &row.5, version))
}

fn source_context(repo: [u8; 16], tenant: [u8; 16], version: i64) -> Result<[u8; 48]> {
    let repo = RepoId::from_bytes(repo).map_err(|_| Error::Corrupt("source repo"))?;
    let tenant = TenantId::from_bytes(tenant).map_err(|_| Error::Corrupt("source tenant"))?;
    let version = u64::try_from(version).map_err(|_| Error::Corrupt("source version"))?;
    Ok(crate::sources::context(tenant, repo, version))
}

/// Whether a stored value already uses the active key (no decryption).
fn current(key: &Key, sealed: &[u8]) -> bool {
    sealed.first() == Some(&2) && key_id(sealed) == Some(key.active_id())
}

type Step<C> = (Progress, Option<C>);

fn reseal_secrets(
    tx: &rusqlite::Transaction<'_>,
    key: &Key,
    after: ([u8; 16], i64),
) -> Result<Step<([u8; 16], i64)>> {
    let rows = tx
        .prepare_cached(
            "SELECT v.secret_id,v.version,v.sealed,s.tenant_id,s.scope_repo_id,s.name
             FROM secret_versions v JOIN secrets s ON s.id=v.secret_id
             WHERE (v.secret_id,v.version)>(?1,?2) ORDER BY v.secret_id,v.version LIMIT ?3",
        )?
        .query_map(params![after.0, after.1, BATCH], secret_row)?
        .collect::<rusqlite::Result<Vec<Row>>>()?;
    let mut step = Progress::default();
    for row in &rows {
        step.examined += 1;
        if current(key, &row.2) {
            continue;
        }
        let fresh = key
            .reseal(&secret_row_context(row)?, &row.2)
            .map_err(|_| Error::Corrupt("sealed secret"))?;
        if let Some(fresh) = fresh {
            tx.prepare_cached(
                "UPDATE secret_versions SET sealed=?3 WHERE secret_id=?1 AND version=?2 AND sealed=?4",
            )?
            .execute(params![row.0, row.1, fresh, row.2])?;
            step.resealed += 1;
        }
    }
    let next = (rows.len() == BATCH as usize).then(|| {
        let last = rows.last().expect("a full batch");
        (last.0, last.1)
    });
    Ok((step, next))
}

fn reseal_seeds(
    tx: &rusqlite::Transaction<'_>,
    key: &Key,
    after: [u8; 16],
) -> Result<Step<[u8; 16]>> {
    let rows = tx
        .prepare_cached(
            "SELECT user_id,sealed_seed FROM mfa_totp WHERE user_id>?1 ORDER BY user_id LIMIT ?2",
        )?
        .query_map(params![after, BATCH], |r| {
            Ok((r.get::<_, [u8; 16]>(0)?, r.get::<_, Vec<u8>>(1)?))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let mut step = Progress::default();
    for (user, sealed) in &rows {
        step.examined += 1;
        if current(key, sealed) {
            continue;
        }
        let id = UserId::from_bytes(*user).map_err(|_| Error::Corrupt("mfa_totp.user_id"))?;
        let fresh = key
            .reseal(&crate::mfa::context(id), sealed)
            .map_err(|_| Error::Corrupt("mfa_totp.sealed_seed"))?;
        if let Some(fresh) = fresh {
            tx.prepare_cached(
                "UPDATE mfa_totp SET sealed_seed=?2 WHERE user_id=?1 AND sealed_seed=?3",
            )?
            .execute(params![user, fresh, sealed])?;
            step.resealed += 1;
        }
    }
    let next = (rows.len() == BATCH as usize).then(|| rows.last().expect("a full batch").0);
    Ok((step, next))
}

fn reseal_sources(
    tx: &rusqlite::Transaction<'_>,
    key: &Key,
    after: [u8; 16],
) -> Result<Step<[u8; 16]>> {
    type SourceRow = ([u8; 16], [u8; 16], i64, Vec<u8>);
    let rows = tx
        .prepare_cached(
            "SELECT repo_id,tenant_id,version,credential FROM source_bindings
             WHERE repo_id>?1 ORDER BY repo_id LIMIT ?2",
        )?
        .query_map(params![after, BATCH], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
        })?
        .collect::<rusqlite::Result<Vec<SourceRow>>>()?;
    let mut step = Progress::default();
    for (repo, tenant, version, sealed) in &rows {
        step.examined += 1;
        if current(key, sealed) {
            continue;
        }
        let fresh = key
            .reseal(&source_context(*repo, *tenant, *version)?, sealed)
            .map_err(|_| Error::Corrupt("source_bindings.credential"))?;
        if let Some(fresh) = fresh {
            tx.prepare_cached(
                "UPDATE source_bindings SET credential=?2 WHERE repo_id=?1 AND credential=?3",
            )?
            .execute(params![repo, fresh, sealed])?;
            step.resealed += 1;
        }
    }
    let next = (rows.len() == BATCH as usize).then(|| rows.last().expect("a full batch").0);
    Ok((step, next))
}
