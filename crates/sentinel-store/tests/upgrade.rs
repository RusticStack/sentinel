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
