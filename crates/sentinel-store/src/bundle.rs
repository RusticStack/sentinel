//! The sanitized diagnostic bundle (R06): what a support request needs about
//! a deployment and nothing it must not carry.
//!
//! In it: versions and schema, SQLite's quick check, row counts by state,
//! each worker's operator-given name, protocol, software, age and drain,
//! queue age, check publication backlog, and the last day's audit events as
//! counts by event code. Never in it: user names, email addresses, tenant
//! or repository names, IP addresses, credentials or their digests, secret
//! names, log contents, pipeline text or URLs. Tenants and repositories are
//! counted, not named.

use rusqlite::Connection;
use serde_json::{Value, json};

use crate::Result;

pub const FORMAT: &str = "sentinel.diagnostics-bundle/1";

fn count(conn: &Connection, sql: &str) -> i64 {
    conn.query_row(sql, [], |r| r.get(0)).unwrap_or(-1)
}

/// The database half of the bundle: everything a stopped controller's data
/// directory can tell. `integrity` runs `PRAGMA quick_check`, a full read
/// of the database — seconds for a large one; ask for it knowingly.
pub fn collect(conn: &Connection, now_ms: i64, integrity: bool) -> Result<Value> {
    let schema: i64 = count(
        conn,
        "SELECT COALESCE(MAX(version), 0) FROM schema_migrations",
    );
    let by_state = |table: &str, column: &str| -> Value {
        let sql =
            format!("SELECT {column}, COUNT(*) FROM {table} GROUP BY {column} ORDER BY {column}");
        let mut out = serde_json::Map::new();
        if let Ok(mut stmt) = conn.prepare(&sql)
            && let Ok(rows) = stmt.query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?)))
        {
            for (state, n) in rows.flatten() {
                out.insert(state.to_string(), json!(n));
            }
        }
        Value::Object(out)
    };
    let mut workers = Vec::new();
    let with_software = conn.prepare("SELECT software FROM workers LIMIT 0").is_ok();
    let sql = format!(
        "SELECT name, arch, protocol, {}, enrolled_ms, last_seen_ms, drain_ms IS NOT NULL
         FROM workers WHERE revoked_ms IS NULL ORDER BY name LIMIT 1000",
        if with_software { "software" } else { "NULL" }
    );
    if let Ok(mut stmt) = conn.prepare(&sql)
        && let Ok(rows) = stmt.query_map([], |r| {
            Ok(json!({
                "name": r.get::<_, String>(0)?,
                "arch": r.get::<_, String>(1)?,
                "protocol": r.get::<_, i64>(2)?,
                "software": r.get::<_, Option<String>>(3)?,
                "enrolled_ms": r.get::<_, i64>(4)?,
                "last_seen_ms": r.get::<_, Option<i64>>(5)?,
                "draining": r.get::<_, bool>(6)?,
            }))
        })
    {
        workers.extend(rows.flatten());
    }
    let mut events = serde_json::Map::new();
    for (kind, sql) in [
        (
            "auth",
            "SELECT event, COUNT(*) FROM auth_audit WHERE at_ms >= ?1 GROUP BY event",
        ),
        (
            "operation",
            "SELECT action, COUNT(*) FROM operation_audit WHERE at_ms >= ?1 GROUP BY action",
        ),
    ] {
        if let Ok(mut stmt) = conn.prepare(sql)
            && let Ok(rows) = stmt.query_map([now_ms - 86_400_000], |r| {
                Ok((r.get::<_, rusqlite::types::Value>(0)?, r.get::<_, i64>(1)?))
            })
        {
            for (event, n) in rows.flatten() {
                let code = match event {
                    rusqlite::types::Value::Integer(i) => i,
                    _ => continue,
                };
                events.insert(format!("{kind}.{code}"), json!(n));
            }
        }
    }
    let oldest_queued: Option<i64> = conn
        .query_row(
            "SELECT MIN(queued_ms) FROM jobs WHERE state_code = 1",
            [],
            |r| r.get(0),
        )
        .unwrap_or(None);
    Ok(json!({
        "format": FORMAT,
        "generated_ms": now_ms,
        "schema": schema,
        "integrity": if integrity {
            conn.query_row("PRAGMA quick_check", [], |r| r.get::<_, String>(0)).unwrap_or_else(|e| e.to_string())
        } else {
            "not checked".into()
        },
        "counts": {
            "tenants": count(conn, "SELECT COUNT(*) FROM tenants"),
            "tenants_suspended": count(conn, "SELECT COUNT(*) FROM tenants WHERE active = 0"),
            "repos": count(conn, "SELECT COUNT(*) FROM repos"),
            "users": count(conn, "SELECT COUNT(*) FROM users"),
            "runs": count(conn, "SELECT COUNT(*) FROM runs"),
            "jobs_by_state": by_state("jobs", "state_code"),
            "attempts": count(conn, "SELECT COUNT(*) FROM attempts"),
            "attempts_held": count(conn, "SELECT COUNT(*) FROM attempts WHERE released_ms IS NULL"),
            "objects": count(conn, "SELECT COUNT(*) FROM objects"),
            "manifests": count(conn, "SELECT COUNT(*) FROM manifests"),
            "artifacts_by_state": by_state("artifacts", "state_code"),
            "uploads_open": count(conn, "SELECT COUNT(*) FROM uploads WHERE state_code = 0"),
            "check_publications_by_state": by_state("check_publications", "state"),
            "webhook_deliveries": count(conn, "SELECT COUNT(*) FROM webhook_deliveries"),
            "secrets": count(conn, "SELECT COUNT(*) FROM secrets"),
            "sessions": count(conn, "SELECT COUNT(*) FROM sessions"),
            "api_tokens": count(conn, "SELECT COUNT(*) FROM api_tokens"),
        },
        "queue": {
            "oldest_queued_age_ms": oldest_queued.map(|q| (now_ms - q).max(0)),
        },
        "workers": workers,
        "events_last_day": events,
    }))
}

/// The bundle of a stopped controller's data directory, opened read-only
/// (it never migrates): [`collect`] plus the disk and the binary's own
/// versions. `sentinel admin diagnostics` prints it.
pub fn collect_offline(data_dir: &std::path::Path, now_ms: i64, integrity: bool) -> Result<Value> {
    use rusqlite::OpenFlags;
    let path = data_dir.join(crate::METADATA_FILE);
    let conn = Connection::open_with_flags(
        &path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    let mut bundle = collect(&conn, now_ms, integrity)?;
    let size = |p: std::path::PathBuf| std::fs::metadata(p).map(|m| m.len()).ok();
    bundle["runtime"] = json!({
        "version": env!("CARGO_PKG_VERSION"),
        "schema_binary": crate::schema::LATEST,
        "os": std::env::consts::OS,
        "arch": std::env::consts::ARCH,
        "offline": true,
        "storage": {
            "metadata_bytes": size(path.clone()),
            "wal_bytes": size(data_dir.join(format!("{}-wal", crate::METADATA_FILE))),
            "free_bytes": crate::space::free_bytes(data_dir).ok(),
            "master_key_present": data_dir.join(crate::MASTER_KEY_FILE).is_file(),
        },
    });
    Ok(bundle)
}
