use rusqlite::{Connection, params};
use sentinel_core::{
    GrantId, RepoId, RunId, TenantId, UnixMillis, UserId,
    auth::{Permissions as P, Principal, Role},
};
use sentinel_store::{
    Durability, Error, Store, ai,
    auth::{self, Authority, provisioning},
    jobs, schema, upgrade, workers,
};

const NOW: UnixMillis = UnixMillis(1_000_000_000);

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
    assert!(readable.contains(&(49, 48)), "{readable:?}");
    assert!(readable.contains(&(50, 50)), "{readable:?}");
    assert!(readable.contains(&(52, 51)), "{readable:?}");
    assert!(readable.contains(&(53, 51)), "{readable:?}");
    assert!(readable.contains(&(57, 56)), "{readable:?}");
    assert!(readable.contains(&(67, 66)), "{readable:?}");
    assert!(readable.contains(&(68, 68)), "{readable:?}");
    assert!(readable.contains(&(69, 69)), "{readable:?}");
    let (_, again) = upgrade::open_upgrading(&path, Durability::Full).unwrap();
    assert!(again.is_none());
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
fn session_grant_provenance_migration_preserves_legacy_rows() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("metadata.sqlite");
    let mut conn = database_at(&path, 54);
    let user = UserId::new();
    let grant = GrantId::new();
    let tx = conn.transaction().unwrap();
    provisioning::insert_human(&tx, user, "Root", true, NOW).unwrap();
    tx.execute(
        "INSERT INTO oauth_grants(id, user_id, client_id, kind, scopes, audience, created_ms, expires_ms)
         VALUES (?1, ?2, 'sentinel-cli', 1, 1, 1, ?3, ?4)",
        params![grant.as_bytes(), user.as_bytes(), NOW.0, NOW.0 + 1_000],
    )
    .unwrap();
    tx.commit().unwrap();
    drop(conn);

    let (store, _) = upgrade::open_upgrading(&path, Durability::Full).unwrap();
    let provenance = store
        .read(|c| {
            c.query_row(
                "SELECT created_session FROM oauth_grants WHERE id = ?1",
                [grant.as_bytes()],
                |row| row.get::<_, Option<[u8; 16]>>(0),
            )
            .map_err(Error::from)
        })
        .unwrap();
    assert_eq!(provenance, None);
}

/// Part 22 Y01: the migration adds a policy nobody has set, so an upgraded deployment is
/// exactly as off as a fresh one, and a tenant administrator cannot switch it on by themselves.
#[test]
fn an_upgraded_deployment_has_ai_off_and_no_tenant_opted_in() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("metadata.sqlite");
    let mut conn = database_at(&path, schema::LATEST - 1);
    let (tenant, admin) = (TenantId::new(), UserId::new());
    let tx = conn.transaction().unwrap();
    jobs::insert_tenant(&tx, tenant, "acme", NOW).unwrap();
    provisioning::insert_human(&tx, admin, "Ada", true, NOW).unwrap();
    auth::set_membership(
        &tx,
        Principal::new(admin, P::ALL, None, None),
        tenant,
        admin,
        Role::TenantAdmin,
    )
    .unwrap();
    tx.commit().unwrap();
    drop(conn);

    let (store, _) = upgrade::open_upgrading(&path, Durability::Full).unwrap();
    assert_eq!(
        store.read(ai::deployment).unwrap(),
        ai::Deployment::default(),
        "an upgrade allowed AI"
    );
    let rows: i64 = store
        .read(|c| Ok(c.query_row("SELECT COUNT(*) FROM tenant_ai", [], |r| r.get(0))?))
        .unwrap();
    assert_eq!(rows, 0, "the upgrade opted a tenant in");
    assert_eq!(store.read(|c| ai::tenant(c, tenant)).unwrap(), None);
    for provider in ai::Provider::ALL {
        assert_eq!(
            store.read(|c| ai::admit(c, tenant, provider)).unwrap(),
            None,
            "{}",
            provider.as_str()
        );
    }
    let authority = Authority::Credential {
        principal: Principal::new(admin, P::REPOSITORY.union(P::TENANT_ADMIN), None, None),
        stepped_up: true,
    };
    let refused = store.writer().write(move |tx| {
        ai::set_tenant(
            tx,
            authority,
            tenant,
            ai::Tenant {
                enabled: true,
                data_policy: ai::DataPolicy::ProviderTerms,
            },
            NOW,
        )
    });
    assert!(
        matches!(refused, Err(Error::Forbidden)),
        "a tenant enabled AI on a deployment that never allowed it: {refused:?}"
    );
}

#[test]
fn a_failed_migration_stays_at_its_last_good_version_and_names_the_rollback() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("metadata.sqlite");
    let mut conn = database_at(&path, 3);
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

#[test]
fn a_process_killed_mid_migration_leaves_the_last_committed_version() {
    const CHILD: &str = "SENTINEL_R07_MIGRATION_CHILD";
    if let Ok(path) = std::env::var(CHILD) {
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

/// Releases an operator may be upgrading from: every schema named as a `READABLE_BY` target (the
/// oldest release that may keep running on a later database) and the two releases before the
/// current schema.
fn upgrade_sources() -> Vec<u32> {
    let mut sources: Vec<u32> = schema::READABLE_BY.iter().map(|&(_, by)| by).collect();
    sources.extend([schema::LATEST - 2, schema::LATEST - 1]);
    sources.sort_unstable();
    sources.dedup();
    sources
}

#[test]
fn every_readable_by_release_upgrades_and_runs_on_the_databases_the_matrix_expects() {
    // docs/upgrades.md (tests/compat_doc.rs compares it with the code): a database at schema N
    // runs on release R only when no migration in (R, N] declares a readable_by above R. Rows
    // are R, columns are N = 53, 55, 58, 64, 65, 66, 67, 68, LATEST.
    let readable = |db: &Connection, release: u32, newest: u32| -> bool {
        let needs: u32 = db
            .query_row(
                "SELECT COALESCE(MAX(readable_by), 0) FROM schema_migrations WHERE version > ?1 AND version <= ?2",
                [release, newest],
                |r| r.get(0),
            )
            .unwrap();
        needs <= release
    };
    assert_eq!(
        schema::LATEST,
        69,
        "extend the matrix in docs/upgrades.md for the new migration"
    );
    let sources = upgrade_sources();
    assert_eq!(sources, vec![44, 47, 48, 51, 56, 57, 63, 64, 66, 67, 68]);
    for from in sources {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("metadata.sqlite");
        drop(database_at(&path, from));
        let (store, snapshot) = upgrade::open_upgrading(&path, Durability::Full).unwrap();
        let snapshot = snapshot.expect("a pending migration takes a copy");
        assert_eq!(
            version(&snapshot),
            from,
            "the copy is release {from}'s database"
        );
        drop(store);
        assert_eq!(version(&path), schema::LATEST, "from {from}");
        let db = Connection::open(&path).unwrap();
        let ok: Vec<bool> = [53, 55, 58, 64, 65, 66, 67, 68, 69]
            .iter()
            .map(|&newest| from >= newest || readable(&db, from, newest))
            .collect();
        // 44, 47 and 48 cannot run on schema 53 (migrations 46, 49 and 50 need 46, 48 and 50); 51 can
        // (52 and 53 are readable by 51) but not on 55 (54 needs 54); 56 and 57 are the targets of
        // migrations 57 and 58, so 57 runs on a database at 58 and 56 does not (58 needs 57); nothing
        // runs on 64 or 65 below migration 63's own schema (59 to 63 are readable by nothing older);
        // 63 runs on 64 (readable by 63) but not on 65 (readable by 64), and 64 runs on both, being
        // where the storage-class migration says an older binary is safe. Migration 66 is readable by
        // nothing older — an older controller settles a merge-group delivery it re-reads as
        // failed:unsupported_event — so 63, 64 and 65 all stop at 65. Migration 67 (the AI policy)
        // is readable by 66, so 66 runs on a database at 67 while 65 does not. Migration 68
        // (artifact classes) is readable by nothing older, so 67 stops at 67, and migration 69
        // (runner mode) is readable by nothing either: an older controller re-reads a queued
        // workflow_job delivery as failed:unsupported_event and completes a check runner mode never
        // publishes, and it knows neither the tenant's switch nor the installation's permissions.
        let expected = match from {
            44 | 47 | 48 => [
                false, false, false, false, false, false, false, false, false,
            ],
            51 => [true, false, false, false, false, false, false, false, false],
            56 => [true, true, false, false, false, false, false, false, false],
            57 => [true, true, true, false, false, false, false, false, false],
            63 => [true, true, true, true, false, false, false, false, false],
            64 | 65 => [true, true, true, true, true, false, false, false, false],
            66 => [true, true, true, true, true, true, true, false, false],
            67 => [true, true, true, true, true, true, true, false, false],
            68 => [true, true, true, true, true, true, true, true, false],
            _ => unreachable!(),
        };
        assert_eq!(
            ok, expected,
            "release {from} on schemas 53, 55, 58, 64, 65, 66, 67, 68, 69"
        );
    }
}

fn schema_objects(db: &Connection) -> Vec<(String, String)> {
    let mut stmt = db
        .prepare(
            "SELECT type, name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name",
        )
        .unwrap();
    stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
        .map(|r| r.unwrap())
        .collect()
}

/// Migration 67 gives every artifact a class, a charge weight and a pin column; the upgraded
/// database has to equal a fresh one, and an artifact stored before it keeps its deadline.
#[test]
fn a_database_upgraded_from_066_equals_a_fresh_one() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("metadata.sqlite");
    let (tenant, repo, run, job, attempt, artifact) = (
        TenantId::new(),
        RepoId::new(),
        RunId::new(),
        sentinel_core::JobId::new(),
        sentinel_core::AttemptId::new(),
        sentinel_core::ArtifactId::new(),
    );
    {
        let conn = database_at(&path, 66);
        let (t, r, ru, j, a, ar) = (
            tenant.as_bytes().as_slice(),
            repo.as_bytes().as_slice(),
            run.as_bytes().as_slice(),
            job.as_bytes().as_slice(),
            attempt.as_bytes().as_slice(),
            artifact.as_bytes().as_slice(),
        );
        let worker = [0x11u8; 16];
        let sha = "0".repeat(40);
        conn.execute_batch("PRAGMA foreign_keys=ON;").unwrap();
        conn.execute(
            "INSERT INTO tenants(id, slug, created_ms) VALUES(?1, 'acme', 1)",
            [t],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO repos(id, tenant_id, name, created_ms) VALUES(?1, ?2, 'app', 1)",
            params![r, t],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO runs(id, tenant_id, repo_id, source_sha, created_ms)
             VALUES(?1, ?2, ?3, ?4, 1)",
            params![ru, t, r, sha],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO jobs(id, tenant_id, run_id, name, state_code, priority, created_seq)
             VALUES(?1, ?2, ?3, 'build', 5, 0, 0)",
            params![j, t, ru],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO attempts(id, tenant_id, job_id, fence, worker_id, lease_until_ms)
             VALUES(?1, ?2, ?3, 1, ?4, 1)",
            params![a, t, j, worker.as_slice()],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO artifacts(id, tenant_id, run_id, job_id, attempt_id, name, state_code,
                 manifest_version, entries, bytes, retain_until_ms, created_ms)
             VALUES(?1, ?2, ?3, ?4, ?5, 'out', 1, NULL, 0, 0, 5000000000, 1)",
            params![ar, t, ru, j, a],
        )
        .unwrap();
        assert_eq!(version(&path), 66);
    }
    let (store, copy) = upgrade::open_upgrading(&path, Durability::Full).unwrap();
    assert!(copy.is_some(), "a pending migration takes a copy first");
    let (class, charged, pinned, retain): (String, i64, Option<i64>, i64) = store
        .read(|c| {
            Ok(c.query_row(
                "SELECT class, charged_bytes, pinned_ms, retain_until_ms FROM artifacts",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )?)
        })
        .unwrap();
    assert_eq!(class, "standard", "an artifact stored before the migration");
    assert_eq!(
        charged, 0,
        "the charge is its bytes times the default class's weight"
    );
    assert_eq!(pinned, None);
    assert_eq!(retain, 5_000_000_000, "an upgrade re-stamps nothing");
    let classes: Vec<(String, i64, i64)> = store
        .read(|c| {
            let mut stmt =
                c.prepare("SELECT name, max_age_ms, weight FROM artifact_classes ORDER BY name")?;
            let rows = stmt
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
                .collect::<Result<_, _>>()?;
            Ok(rows)
        })
        .unwrap();
    assert_eq!(
        classes,
        [
            ("debug".to_owned(), 7 * 86_400_000, 1),
            ("evidence".to_owned(), 90 * 86_400_000, 1),
            ("release".to_owned(), 90 * 86_400_000, 2),
            ("standard".to_owned(), 30 * 86_400_000, 1),
        ]
    );
    let upgraded = store.read(|c| Ok(schema_objects(c))).unwrap();
    drop(store);
    let fresh = tempfile::tempdir().unwrap();
    let fresh_store = Store::open(fresh.path().join("metadata.sqlite"), Durability::Full).unwrap();
    assert_eq!(version(&path), schema::LATEST);
    assert_eq!(
        upgraded,
        fresh_store.read(|c| Ok(schema_objects(c))).unwrap(),
        "the upgraded database has the schema a fresh one has"
    );
}
