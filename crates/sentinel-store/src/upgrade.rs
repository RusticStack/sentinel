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

/// A table whose stored rows a pending migration writes, drops or rebuilds, with the rows it holds now.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rewrite {
    pub table: String,
    pub rows: u64,
}

/// One pending migration: what applying it does to the rows a populated database already holds. Shape
/// alone (a new table, an index, a column, a trigger) rewrites nothing and lists no table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Step {
    pub version: u32,
    pub rewrites: Vec<Rewrite>,
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
    /// The file the upgrade writes the pre-migration copy to before it migrates: the rollback point,
    /// absent when it has nothing to migrate or the database is newer than the binary.
    pub copy: Option<PathBuf>,
    /// One entry per pending migration, in order.
    pub steps: Vec<Step>,
}

/// The text of the migration with comments and the contents of string literals blanked, so a keyword
/// search sees statements rather than prose and a `;` inside either does not end one.
fn plain(sql: &str) -> String {
    let mut text = sql.as_bytes().to_vec();
    let len = text.len();
    let mut i = 0;
    while i < len {
        match text[i] {
            b'-' if text.get(i + 1) == Some(&b'-') => {
                while i < len && text[i] != b'\n' {
                    text[i] = b' ';
                    i += 1;
                }
            }
            b'/' if text.get(i + 1) == Some(&b'*') => {
                let end = sql[i..].find("*/").map_or(len, |at| i + at + 2);
                text[i..end].fill(b' ');
                i = end;
            }
            b'\'' => {
                // A doubled quote closes and reopens the literal, so the body stays blanked either way.
                text[i] = b' ';
                i += 1;
                while i < len {
                    let closing = text[i] == b'\'';
                    text[i] = b' ';
                    i += 1;
                    if closing {
                        break;
                    }
                }
            }
            _ => i += 1,
        }
    }
    String::from_utf8(text).expect("only ASCII bytes are blanked")
}

/// The tables whose rows a migration's own statements insert, update, delete or drop, in the order it
/// names them and without duplicates. Statements inside a trigger it creates are skipped: they run when
/// a later write fires them, not when the migration applies.
fn rewritten(sql: &str) -> Vec<String> {
    fn words(statement: &str) -> Vec<&str> {
        statement
            .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .filter(|word| !word.is_empty())
            .collect()
    }
    fn named<'a>(words: &[&'a str], ahead: &str) -> Option<&'a str> {
        let at = words
            .iter()
            .position(|word| word.eq_ignore_ascii_case(ahead))?;
        words.get(at + 1).copied()
    }
    let plain = plain(sql);
    let bytes = plain.as_bytes();
    let mut tables: Vec<String> = Vec::new();
    let (mut start, mut i, mut body) = (0, 0, false);
    while i < bytes.len() {
        if bytes[i] != b';' {
            i += 1;
            continue;
        }
        let words = words(&plain[start..i]);
        start = i + 1;
        i += 1;
        // A trigger's body runs later: it closes on the `END;` statement that ends it, and a nested
        // `CASE … END` never stands alone as one.
        if body {
            body = !(words.len() == 1 && words[0].eq_ignore_ascii_case("END"));
            continue;
        }
        let Some(head) = words.first() else {
            continue;
        };
        if head.eq_ignore_ascii_case("CREATE")
            && words
                .iter()
                .any(|word| word.eq_ignore_ascii_case("TRIGGER"))
        {
            body = true;
            continue;
        }
        let table = if head.eq_ignore_ascii_case("INSERT") || head.eq_ignore_ascii_case("REPLACE") {
            named(&words, "INTO")
        } else if head.eq_ignore_ascii_case("UPDATE") {
            // `UPDATE OR REPLACE t` names its table after the conflict clause.
            match words.get(1) {
                Some(word) if word.eq_ignore_ascii_case("OR") => words.get(3).copied(),
                _ => words.get(1).copied(),
            }
        } else if head.eq_ignore_ascii_case("DELETE") {
            named(&words, "FROM")
        } else if head.eq_ignore_ascii_case("DROP") {
            // `DROP TABLE [IF EXISTS] t`; a dropped trigger or index destroys no rows.
            words
                .iter()
                .position(|word| word.eq_ignore_ascii_case("TABLE"))
                .and_then(|at| {
                    words[at + 1..].iter().copied().find(|word| {
                        !word.eq_ignore_ascii_case("IF") && !word.eq_ignore_ascii_case("EXISTS")
                    })
                })
        } else {
            None
        };
        if let Some(table) = table
            && !tables.iter().any(|seen| seen == table)
        {
            tables.push(table.to_owned());
        }
    }
    tables
}

fn step(conn: &Connection, version: u32) -> Step {
    let mut rewrites: Vec<Rewrite> = Vec::new();
    let mut query = String::with_capacity(48);
    for table in rewritten(schema::MIGRATIONS[version as usize - 1].1) {
        query.clear();
        query.push_str("SELECT COUNT(*) FROM \"");
        query.push_str(&table);
        query.push('"');
        // A table the migration creates is not counted: it holds nothing to rewrite yet.
        if let Ok(rows) = conn.query_row(&query, [], |r| r.get::<_, i64>(0)) {
            rewrites.push(Rewrite {
                table,
                rows: rows.max(0) as u64,
            });
        }
    }
    Step { version, rewrites }
}

pub fn preflight(data_dir: &Path) -> Result<Preflight> {
    use sentinel_protocol::negotiate::{SUPPORTED_MAX, SUPPORTED_MIN};
    let path = data_dir.join(crate::METADATA_FILE);
    let inspection = inspect(&path)?;
    let free_bytes = crate::space::free_bytes(data_dir).ok();
    let needed_bytes = inspection.bytes.saturating_mul(2);
    let mut sealed_values = false;
    let mut workers = Vec::new();
    let mut steps = Vec::new();
    if !inspection.fresh {
        let conn = Connection::open_with_flags(
            &path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        sealed_values = crate::reseal::sealed_rows_exist(&conn).unwrap_or(false);
        steps = inspection.pending.iter().map(|&v| step(&conn, v)).collect();
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
    // The copy is what an upgrade writes before its first migration, so it is the only rollback for a
    // release older than the result (docs/upgrades.md).
    let copy = (!inspection.fresh && !inspection.newer && !inspection.pending.is_empty())
        .then(|| snapshot_path(&path, inspection.database));
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
        copy,
        steps,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_rewrite_names_only_the_tables_its_own_statements_write() {
        // A trigger body runs when a later write fires it, not when the migration applies.
        assert_eq!(
            rewritten(
                "CREATE TABLE fresh(id INTEGER);
                 CREATE TRIGGER later AFTER INSERT ON fresh BEGIN
                     UPDATE elsewhere SET x = 1;
                     DELETE FROM gone;
                 END;
                 INSERT INTO kept VALUES (1);"
            ),
            ["kept"]
        );
        assert_eq!(
            rewritten(
                "-- UPDATE commented_out SET x = 1;
                 /* DELETE FROM also_commented; */
                 INSERT OR IGNORE INTO answers(id) VALUES (1);
                 UPDATE OR REPLACE scored SET x = 1;
                 DELETE FROM retired;
                 DROP TABLE IF EXISTS rebuilt;
                 DROP TRIGGER stale_trigger;
                 DROP INDEX stale_index;
                 ALTER TABLE shaped ADD COLUMN extra INTEGER NOT NULL DEFAULT 0;
                 CREATE INDEX named ON answers(id);"
            ),
            ["answers", "scored", "retired", "rebuilt"]
        );
        // A semicolon or a doubled quote inside a literal does not end a statement.
        assert_eq!(
            rewritten("INSERT INTO texts(body) VALUES ('a;b''c'); UPDATE texts SET body = '';"),
            ["texts"]
        );
    }

    #[test]
    fn the_pending_migrations_report_the_tables_they_rewrite() {
        let sql = |version: u32| schema::MIGRATIONS[version as usize - 1].1;
        // Runner-mode provisioning adds tables, indexes and triggers only.
        assert!(rewritten(sql(schema::LATEST)).is_empty());
        // The OAuth scope rebuild copies every row into a `_v73` table and drops the original.
        let oauth = rewritten(sql(73));
        for table in ["oauth_clients", "oauth_grants", "oauth_access_tokens"] {
            assert!(
                oauth.iter().any(|seen| seen == table),
                "migration 73 rewrites {table}: {oauth:?}"
            );
        }
        assert!(oauth.iter().any(|seen| seen.ends_with("_v73")), "{oauth:?}");
        // The artifact rebuild is the one that visits stored rows; a trigger's own writes are not its.
        assert_eq!(rewritten(sql(72)), ["artifacts_v71", "artifacts"]);
    }
}
