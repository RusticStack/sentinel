//! Each migration runs in its own transaction, so a failure leaves the last committed version, never half of one.

use std::path::{Path, PathBuf};

use rusqlite::{Connection, OpenFlags, OptionalExtension};

use crate::{Durability, Error, Result, Store, schema};

pub const SNAPSHOTS_KEPT: usize = 2;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Inspection {
    pub fresh: bool,
    pub database: u32,
    pub binary: u32,
    pub pending: Vec<u32>,
    pub newer: bool,
    pub needs: Option<u32>,
    pub integrity: String,
    pub bytes: u64,
}

impl Inspection {
    pub fn openable(&self) -> bool {
        !self.newer || self.needs.is_some_and(|n| n <= self.binary)
    }
}

fn size(path: &Path) -> u64 {
    let mut wal = path.as_os_str().to_owned();
    wal.push("-wal");
    [path.to_path_buf(), PathBuf::from(wal)]
        .iter()
        .filter_map(|p| std::fs::metadata(p).ok())
        .map(|m| m.len())
        .sum()
}

pub fn inspect(path: &Path) -> Result<Inspection> {
    let binary = schema::LATEST;
    if !path.exists() {
        return Ok(Inspection {
            fresh: true,
            binary,
            pending: schema::MIGRATIONS.iter().map(|m| m.0).collect(),
            integrity: "ok".into(),
            ..Inspection::default()
        });
    }
    let conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    let has_table: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = 'schema_migrations')",
        [],
        |r| r.get(0),
    )?;
    let database: u32 = if has_table {
        conn.query_row(
            "SELECT COALESCE(MAX(version), 0) FROM schema_migrations",
            [],
            |r| r.get(0),
        )?
    } else {
        0
    };
    let newer = database > binary;
    let needs = if newer {
        conn.query_row(
            "SELECT MAX(COALESCE(readable_by, version)) FROM schema_migrations WHERE version > ?1",
            [binary],
            |r| r.get::<_, Option<u32>>(0),
        )
        .optional()
        .ok()
        .flatten()
        .flatten()
    } else {
        None
    };
    let integrity: String = conn.query_row("PRAGMA quick_check", [], |r| r.get(0))?;
    Ok(Inspection {
        fresh: false,
        database,
        binary,
        pending: schema::MIGRATIONS
            .iter()
            .map(|m| m.0)
            .filter(|v| *v > database)
            .collect(),
        newer,
        needs,
        integrity,
        bytes: size(path),
    })
}

pub fn snapshot_path(database: &Path, version: u32) -> PathBuf {
    let mut name = database.as_os_str().to_owned();
    name.push(format!(".v{version:03}"));
    PathBuf::from(name)
}

pub fn snapshots(database: &Path) -> Vec<(u32, PathBuf)> {
    let (Some(dir), Some(name)) = (database.parent(), database.file_name()) else {
        return Vec::new();
    };
    let prefix = format!("{}.v", name.to_string_lossy());
    let mut found: Vec<(u32, PathBuf)> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            let n = e.file_name().to_string_lossy().into_owned();
            let v = n.strip_prefix(&prefix)?.parse().ok()?;
            Some((v, e.path()))
        })
        .collect();
    found.sort();
    found
}

pub fn open_upgrading(path: &Path, durability: Durability) -> Result<(Store, Option<PathBuf>)> {
    let inspection = inspect(path)?;
    let mut snapshot = None;
    if !inspection.fresh && !inspection.newer && !inspection.pending.is_empty() {
        let dest = snapshot_path(path, inspection.database);
        // Renamed into place only once durable: a copy cut short by a crash or full disk is never mistaken for complete.
        let mut partial = dest.clone().into_os_string();
        partial.push(".partial");
        let partial = PathBuf::from(partial);
        for stale in [&partial, &dest] {
            if stale.exists() {
                std::fs::remove_file(stale)?;
            }
        }
        let partial_str = partial
            .to_str()
            .ok_or(Error::InvalidInput("database path must be UTF-8"))?
            .to_owned();
        let conn = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        conn.busy_timeout(std::time::Duration::from_secs(10))?;
        conn.execute("VACUUM INTO ?1", [partial_str])?;
        drop(conn);
        std::fs::File::open(&partial)?.sync_all()?;
        std::fs::rename(&partial, &dest)?;
        if let Some(dir) = dest.parent()
            && let Ok(dir) = std::fs::File::open(dir)
        {
            // A directory handle syncs on Unix; elsewhere it is best effort.
            let _ = dir.sync_all();
        }
        let all = snapshots(path);
        for (_, old) in all.iter().take(all.len().saturating_sub(SNAPSHOTS_KEPT)) {
            let _ = std::fs::remove_file(old);
        }
        snapshot = Some(dest);
    }
    match Store::open(path, durability) {
        Ok(store) => Ok((store, snapshot)),
        Err(Error::Sqlite(e)) if !inspection.pending.is_empty() => {
            let reached = inspect(path)
                .map(|i| i.database)
                .unwrap_or(inspection.database);
            Err(Error::MigrationFailed {
                from: inspection.database,
                reached,
                snapshot: snapshot.map(|p| p.display().to_string()),
                cause: e.to_string(),
            })
        }
        Err(e) => Err(e),
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkerVersion {
    pub name: String,
    pub protocol: u16,
    pub software: Option<String>,
    pub last_seen_ms: Option<i64>,
    pub refused: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Preflight {
    pub inspection: Inspection,
    pub free_bytes: Option<u64>,
    pub needed_bytes: u64,
    pub sealed_values: bool,
    pub key_present: bool,
    pub workers: Vec<WorkerVersion>,
    pub blocking: Vec<String>,
}

pub fn preflight(data_dir: &Path) -> Result<Preflight> {
    use sentinel_protocol::negotiate::{SUPPORTED_MAX, SUPPORTED_MIN};
    let path = data_dir.join(crate::METADATA_FILE);
    let inspection = inspect(&path)?;
    let free_bytes = crate::space::free_bytes(data_dir).ok();
    let needed_bytes = inspection.bytes.saturating_mul(2);
    let mut sealed_values = false;
    let mut workers = Vec::new();
    if !inspection.fresh {
        let conn = Connection::open_with_flags(
            &path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        sealed_values = crate::reseal::sealed_rows_exist(&conn).unwrap_or(false);
        let with_software = conn.prepare("SELECT software FROM workers LIMIT 0").is_ok();
        let sql = if with_software {
            "SELECT name, protocol, software, last_seen_ms FROM workers WHERE revoked_ms IS NULL ORDER BY name"
        } else {
            "SELECT name, protocol, NULL, last_seen_ms FROM workers WHERE revoked_ms IS NULL ORDER BY name"
        };
        if let Ok(mut stmt) = conn.prepare(sql) {
            let rows = stmt.query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, i64>(1)?,
                    r.get::<_, Option<String>>(2)?,
                    r.get::<_, Option<i64>>(3)?,
                ))
            })?;
            for row in rows {
                let (name, protocol, software, last_seen_ms) = row?;
                let protocol = u16::try_from(protocol).unwrap_or(0);
                workers.push(WorkerVersion {
                    name,
                    protocol,
                    software,
                    last_seen_ms,
                    refused: !(SUPPORTED_MIN.0..=SUPPORTED_MAX.0).contains(&protocol),
                });
            }
        }
    }
    let key_present = data_dir.join(crate::MASTER_KEY_FILE).is_file();
    let mut blocking = Vec::new();
    if !inspection.openable() {
        blocking.push(format!(
            "the database is at schema {}, newer than this build's {}, and needs schema {} to run: use that release or restore a backup",
            inspection.database,
            inspection.binary,
            inspection.needs.unwrap_or(inspection.database)
        ));
    }
    if inspection.integrity != "ok" {
        blocking.push(format!(
            "the database fails its integrity check: {}",
            inspection.integrity
        ));
    }
    if !inspection.pending.is_empty()
        && !inspection.fresh
        && free_bytes.is_some_and(|free| free < needed_bytes)
    {
        blocking.push(format!(
            "{needed_bytes} bytes free are needed for the pre-migration copy and the migration; {} are",
            free_bytes.unwrap_or(0)
        ));
    }
    if sealed_values && !key_present {
        blocking
            .push("sealed values exist but master.key is missing from the data directory".into());
    }
    Ok(Preflight {
        inspection,
        free_bytes,
        needed_bytes,
        sealed_values,
        key_present,
        workers,
        blocking,
    })
}
