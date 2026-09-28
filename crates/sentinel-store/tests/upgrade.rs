//! R05: upgrades — a copy of the database before any migration, a failed
//! migration leaving the database at its last good version with the copy
//! named for the rollback, declared rollback compatibility letting an older
//! build run on a newer database only when every unknown migration says so,
//! and the preflight an operator runs before upgrading.
use rusqlite::{Connection, params};
use sentinel_core::{RepoId, RunId, TenantId, UnixMillis};
use sentinel_store::{Durability, Error, Store, jobs, schema, upgrade, workers};

const NOW: UnixMillis = UnixMillis(1_000_000_000);

/// A database at `version`, built the way that release built it.
fn database_at(path: &std::path::Path, version: u32) -> Connection {
    let mut conn = Connection::open(path).unwrap();
    conn.execute_batch(
        "PRAGMA foreign_keys=ON; CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY, applied_ms INTEGER NOT NULL);",
    )
    .unwrap();
    for &(v, sql) in &schema::MIGRATIONS[..version as usize] {
        let tx = conn.transaction().unwrap();
        tx.execute_batch(sql).unwrap();
        if v >= schema::READABLE_BY_SINCE {
            tx.execute(
                "INSERT INTO schema_migrations VALUES (?1, 1, ?2)",
                params![v, schema::readable_by(v)],
            )
            .unwrap();
        } else {
            tx.execute("INSERT INTO schema_migrations VALUES (?1, 1)", [v])
                .unwrap();
        }
        tx.commit().unwrap();
    }
    conn
}

fn version(path: &std::path::Path) -> u32 {
    Connection::open(path)
        .unwrap()
        .query_row("SELECT MAX(version) FROM schema_migrations", [], |r| {
            r.get(0)
        })
        .unwrap()
}

#[test]
fn an_upgrade_keeps_a_copy_of_the_database_from_before_it() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("metadata.sqlite");
    let from = schema::LATEST - 3;
    let conn = database_at(&path, from);
    drop(conn);
    let before = upgrade::inspect(&path).unwrap();
    assert_eq!(before.database, from);
    assert_eq!(before.pending, vec![from + 1, from + 2, from + 3]);
    assert_eq!(before.integrity, "ok");
    assert!(before.openable());

    let (store, snapshot) = upgrade::open_upgrading(&path, Durability::Full).unwrap();
    let snapshot = snapshot.expect("a pending migration takes a copy");
    assert_eq!(snapshot, upgrade::snapshot_path(&path, from));
    assert_eq!(
        version(&snapshot),
        from,
        "the copy is the database from before"
    );
    drop(store);
    assert_eq!(version(&path), schema::LATEST);
    // From schema 48 on each migration records who can still read it.
    let readable: Vec<(u32, u32)> = Connection::open(&path)
        .unwrap()
        .prepare("SELECT version, readable_by FROM schema_migrations WHERE version >= 44 ORDER BY version")
        .unwrap()
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert!(readable.contains(&(45, 44)), "{readable:?}");
    assert!(readable.contains(&(46, 46)), "{readable:?}");
    assert!(readable.contains(&(48, 47)), "{readable:?}");
    // Nothing pending: no copy.
    let (_, again) = upgrade::open_upgrading(&path, Durability::Full).unwrap();
    assert!(again.is_none());
    // Only the newest two copies are kept: a second deployment with two
    // older copies beside it keeps the newer of those and its own.
    let other = dir.path().join("other");
    std::fs::create_dir_all(&other).unwrap();
    let path = other.join("metadata.sqlite");
    drop(database_at(&path, from));
    std::fs::write(upgrade::snapshot_path(&path, 1), b"old").unwrap();
    std::fs::write(upgrade::snapshot_path(&path, 2), b"old").unwrap();
    drop(upgrade::open_upgrading(&path, Durability::Full).unwrap());
    let kept: Vec<u32> = upgrade::snapshots(&path)
        .into_iter()
        .map(|(v, _)| v)
        .collect();
    assert_eq!(kept, vec![2, from]);
}

#[test]
fn a_failed_migration_stays_at_its_last_good_version_and_names_the_rollback() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("metadata.sqlite");
    let mut conn = database_at(&path, 3);
    // Ownership migration 4 refuses: a run another tenant owns.
    let (a, b, repo, run) = (
        TenantId::new(),
        TenantId::new(),
        RepoId::new(),
        RunId::new(),
    );
    let tx = conn.transaction().unwrap();
    jobs::insert_tenant(&tx, a, "legacy", NOW).unwrap();
    jobs::insert_tenant(&tx, b, "other", NOW).unwrap();
    jobs::insert_repo(&tx, a, repo, "app", NOW).unwrap();
    jobs::insert_run(&tx, a, repo, run, "sha", NOW).unwrap();
    tx.execute(
        "UPDATE runs SET tenant_id=?1 WHERE id=?2",
        params![b.as_bytes(), run.as_bytes()],
    )
    .unwrap();
    tx.commit().unwrap();
    drop(conn);
    match upgrade::open_upgrading(&path, Durability::Full) {
        Err(Error::MigrationFailed {
            from,
            reached,
            snapshot,
            ..
        }) => {
            assert_eq!((from, reached), (3, 3));
            let snapshot = std::path::PathBuf::from(snapshot.expect("a copy was taken"));
            assert_eq!(version(&snapshot), 3);
            let message = Error::MigrationFailed {
                from,
                reached,
                snapshot: Some(snapshot.display().to_string()),
                cause: "x".into(),
            }
            .to_string();
            assert!(
                message.contains("roll back") && message.contains("previous release"),
                "{message}"
            );
        }
        Err(other) => panic!("expected MigrationFailed, got {other:?}"),
        Ok(_) => panic!("the migration should have failed"),
    }
    assert_eq!(version(&path), 3, "left at the last version that committed");
}

#[test]
fn an_older_build_runs_on_a_newer_database_only_when_every_unknown_migration_allows_it() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("metadata.sqlite");
    drop(Store::open(&path, Durability::Full).unwrap());
    let future = schema::LATEST + 1;
    // A newer release's additive migration, readable by this build.
    Connection::open(&path)
        .unwrap()
        .execute(
            "INSERT INTO schema_migrations VALUES (?1, 1, ?2)",
            params![future, schema::LATEST],
        )
        .unwrap();
    let seen = upgrade::inspect(&path).unwrap();
    assert!(seen.newer && seen.openable(), "{seen:?}");
    assert_eq!(seen.needs, Some(schema::LATEST));
    let (store, snapshot) = upgrade::open_upgrading(&path, Durability::Full).unwrap();
    assert!(snapshot.is_none(), "nothing migrates backwards");
    drop(store);
    assert_eq!(version(&path), future, "left as the newer release made it");
    // One that needs itself: refused, and the preflight says why.
    Connection::open(&path)
        .unwrap()
        .execute(
            "INSERT INTO schema_migrations VALUES (?1, 1, ?1)",
            [future + 1],
        )
        .unwrap();
    assert!(matches!(
        Store::open(&path, Durability::Full),
        Err(Error::Corrupt(_))
    ));
    let report = upgrade::preflight(dir.path()).unwrap();
    assert!(!report.inspection.openable());
    assert_eq!(report.blocking.len(), 1, "{:?}", report.blocking);
}

#[test]
fn the_preflight_reports_skew_room_and_the_key_without_changing_anything() {
    let dir = tempfile::tempdir().unwrap();
    let fresh = upgrade::preflight(dir.path()).unwrap();
    assert!(fresh.inspection.fresh && fresh.blocking.is_empty());
    let path = dir.path().join("metadata.sqlite");
    drop(database_at(&path, schema::LATEST - 1));
    let before = std::fs::read(&path).unwrap();
    let report = upgrade::preflight(dir.path()).unwrap();
    assert_eq!(report.inspection.pending, vec![schema::LATEST]);
    assert!(!report.sealed_values && !report.key_present);
    assert!(report.blocking.is_empty(), "{:?}", report.blocking);
    assert_eq!(report.needed_bytes, report.inspection.bytes * 2);
    assert_eq!(std::fs::read(&path).unwrap(), before, "nothing written");
    assert_eq!(version(&path), schema::LATEST - 1);
}

#[test]
fn a_worker_software_label_is_printable_and_bounded() {
    assert_eq!(
        workers::software_label("sentinel-worker 0.1.0").as_deref(),
        Some("sentinel-worker 0.1.0")
    );
    assert_eq!(
        workers::software_label("a\u{0}b\nc\u{1b}[31m").as_deref(),
        Some("abc[31m")
    );
    assert_eq!(workers::software_label("\u{7}\t").as_deref(), None);
    assert_eq!(
        workers::software_label(&"x".repeat(500)).map(|s| s.len()),
        Some(128)
    );
}

/// R06: the offline diagnostic bundle of a stopped controller counts rows
/// without naming tenants or repositories, and never writes.
#[test]
fn the_offline_diagnostic_bundle_counts_without_naming() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("metadata.sqlite");
    let store = Store::open(&path, Durability::Full).unwrap();
    let (tenant, repo, run) = (TenantId::new(), RepoId::new(), RunId::new());
    store
        .writer()
        .write(move |tx| {
            jobs::insert_tenant(tx, tenant, "secret-tenant", NOW)?;
            jobs::insert_repo(tx, tenant, repo, "secret-repo", NOW)?;
            jobs::insert_run(tx, tenant, repo, run, "sha", NOW)?;
            Ok(())
        })
        .unwrap();
    drop(store);
    let before = std::fs::read(&path).unwrap();
    let bundle = sentinel_store::bundle::collect_offline(dir.path(), NOW.0, true).unwrap();
    assert_eq!(bundle["format"], sentinel_store::bundle::FORMAT);
    assert_eq!(bundle["integrity"], "ok");
    assert_eq!(bundle["schema"], schema::LATEST);
    assert_eq!(bundle["counts"]["tenants"], 1);
    assert_eq!(bundle["counts"]["repos"], 1);
    assert_eq!(bundle["counts"]["runs"], 1);
    for (name, n) in bundle["counts"].as_object().unwrap() {
        if let Some(n) = n.as_i64() {
            assert!(n >= 0, "{name} = {n}");
        }
    }
    assert_eq!(bundle["runtime"]["offline"], true);
    let flat = bundle.to_string();
    assert!(
        !flat.contains("secret-tenant") && !flat.contains("secret-repo"),
        "{flat}"
    );
    assert_eq!(std::fs::read(&path).unwrap(), before, "read-only");
}

/// R07: a controller killed in the middle of a migration — the transaction
/// open, the schema changed, nothing committed — leaves the database at the
/// version before it, intact, and the next start migrates it. A copy cut
/// short by the same kill is never listed as a snapshot and is replaced.
#[test]
fn a_process_killed_mid_migration_leaves_the_last_committed_version() {
    const CHILD: &str = "SENTINEL_R07_MIGRATION_CHILD";
    if let Ok(path) = std::env::var(CHILD) {
        // The child: apply the last migration inside a transaction and die
        // before it commits, as a kill or a power cut would.
        let mut conn = Connection::open(&path).unwrap();
        conn.pragma_update(None, "journal_mode", "WAL").unwrap();
        let (v, sql) = schema::MIGRATIONS[schema::LATEST as usize - 1];
        let tx = conn.transaction().unwrap();
        tx.execute_batch(sql).unwrap();
        tx.execute(
            "INSERT INTO schema_migrations VALUES (?1, 1, ?2)",
            params![v, schema::readable_by(v)],
        )
        .unwrap();
        std::process::abort();
    }
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("metadata.sqlite");
    let from = schema::LATEST - 1;
    let mut conn = database_at(&path, from);
    conn.pragma_update(None, "journal_mode", "WAL").unwrap();
    let tx = conn.transaction().unwrap();
    jobs::insert_tenant(&tx, TenantId::new(), "kept", NOW).unwrap();
    tx.commit().unwrap();
    drop(conn);

    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "a_process_killed_mid_migration_leaves_the_last_committed_version",
            "--nocapture",
        ])
        .env(CHILD, &path)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .unwrap();
    assert!(!status.success(), "the child died mid-migration");

    let after = upgrade::inspect(&path).unwrap();
    assert_eq!(after.database, from, "nothing of the migration committed");
    assert_eq!(after.integrity, "ok");
    assert_eq!(after.pending, vec![schema::LATEST]);
    // The same kill during the copy: a truncated temporary file.
    let snapshot = upgrade::snapshot_path(&path, from);
    let mut partial = snapshot.clone().into_os_string();
    partial.push(".partial");
    std::fs::write(&partial, b"SQLite format 3\0cut short").unwrap();
    assert!(
        upgrade::snapshots(&path).is_empty(),
        "a partial copy is not a snapshot"
    );

    let (store, taken) = upgrade::open_upgrading(&path, Durability::Full).unwrap();
    assert_eq!(taken.as_deref(), Some(snapshot.as_path()));
    assert!(!std::path::Path::new(&partial).exists());
    assert_eq!(version(&snapshot), from);
    let tenants: i64 = store
        .read(|c| Ok(c.query_row("SELECT COUNT(*) FROM tenants", [], |r| r.get(0))?))
        .unwrap();
    assert_eq!(tenants, 1, "the committed row survived");
    drop(store);
    assert_eq!(version(&path), schema::LATEST);
}
