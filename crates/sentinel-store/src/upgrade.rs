//! Upgrades (R05): what a database needs before this build opens it, and the
//! snapshot taken before any migration runs.
//!
//! Migrations are forward-only and each runs in its own transaction
//! ([`crate::migrate`]): a failure leaves the database at the last version
//! that committed, never half-way through one. Before the first pending
//! migration, [`open_upgrading`] copies the database aside
//! (`metadata.sqlite.v047` for a database at schema 47), so a failed or
//! regretted upgrade rolls back by restoring that file and starting the
//! previous release. The newest [`SNAPSHOTS_KEPT`] are kept.

use std::path::{Path, PathBuf};

use rusqlite::{Connection, OpenFlags, OptionalExtension};

use crate::{Durability, Error, Result, Store, schema};

/// Pre-migration snapshots kept beside the database.
pub const SNAPSHOTS_KEPT: usize = 2;

/// What [`inspect`] found, without changing anything.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Inspection {
    /// No database at the path yet: a fresh installation.
    pub fresh: bool,
    /// The database's schema.
    pub database: u32,
    /// The newest schema this build knows.
    pub binary: u32,
    /// Migrations this build would apply, in order.
    pub pending: Vec<u32>,
    /// The database is newer than this build.
    pub newer: bool,
    /// For a newer database: the schema its unknown migrations need; this
    /// build runs on it only when that is at most `binary`.
    pub needs: Option<u32>,
    /// SQLite's `PRAGMA quick_check`.
    pub integrity: String,
    /// The database's size on disk (main file and write-ahead log).
    pub bytes: u64,
}

impl Inspection {
    /// Whether this build can open the database at all.
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

/// Look at the database at `path` read-only: its schema against this
/// build's, what would migrate, and its integrity. Nothing is written.
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

/// The pre-migration snapshot of a database at schema `version`.
pub fn snapshot_path(database: &Path, version: u32) -> PathBuf {
    let mut name = database.as_os_str().to_owned();
    name.push(format!(".v{version:03}"));
    PathBuf::from(name)
}

/// Pre-migration snapshots beside `database`, oldest first.
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

/// Open the store, copying the database aside first when this build will
/// migrate it. Returns the store and the snapshot it took, if any.
///
/// A migration that fails leaves the database at the last version that
/// committed; the error then names the snapshot to roll back to
/// ([`Error::MigrationFailed`]).
pub fn open_upgrading(path: &Path, durability: Durability) -> Result<(Store, Option<PathBuf>)> {
    let inspection = inspect(path)?;
    let mut snapshot = None;
    if !inspection.fresh && !inspection.newer && !inspection.pending.is_empty() {
        let dest = snapshot_path(path, inspection.database);
        if dest.exists() {
            std::fs::remove_file(&dest)?;
        }
        let dest_str = dest
            .to_str()
            .ok_or(Error::InvalidInput("database path must be UTF-8"))?
            .to_owned();
        let conn = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        conn.busy_timeout(std::time::Duration::from_secs(10))?;
        conn.execute("VACUUM INTO ?1", [dest_str])?;
        drop(conn);
        std::fs::File::open(&dest)?.sync_all()?;
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

/// One enrolled worker, as a skew check sees it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkerVersion {
    pub name: String,
    pub protocol: u16,
    pub software: Option<String>,
    pub last_seen_ms: Option<i64>,
    /// Outside the protocol range this build accepts: it would be refused
    /// at its next hello until upgraded.
    pub refused: bool,
}

/// Everything `sentinel admin upgrade check` reports: the database against
/// this build, the room the upgrade needs, the key, and the workers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Preflight {
    pub inspection: Inspection,
    pub free_bytes: Option<u64>,
    /// The pre-migration copy plus growth: twice the database.
    pub needed_bytes: u64,
    pub sealed_values: bool,
    pub key_present: bool,
    pub workers: Vec<WorkerVersion>,
    /// What would stop this build from starting, in words.
    pub blocking: Vec<String>,
}

/// Check a stopped controller's data directory against this build without
/// changing anything.
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
