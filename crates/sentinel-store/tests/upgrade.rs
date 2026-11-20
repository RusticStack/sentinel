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
    let refused = match Store::open(&path, Durability::Full) {
        Err(error) => error,
        Ok(_) => panic!("a database that needs a newer schema is refused"),
    };
    let Error::SchemaNewer {
        database,
        binary,
        needs,
    } = &refused
    else {
        panic!("expected a schema refusal, got {refused:?}");
    };
    assert_eq!(
        (*database, *binary, *needs),
        (future + 1, schema::LATEST, future + 1),
        "the refusal names the schema, the binary and what the database needs"
    );
    let message = refused.to_string();
    assert!(
        message.contains(&format!("at schema {}", future + 1))
            && message.contains(&format!("reads {}", schema::LATEST))
            && message.contains("restore the copy"),
        "{message}"
    );
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

/// A populated database at schema 72: a tenant, its sealed secret, an OAuth client with every child
/// row, and two enrolled workers, one of them at a protocol this build does not serve. The copy is
/// what the operator inspects before the upgrade and rolls back to after it.
fn populated_at_72(path: &std::path::Path) -> [u8; 32] {
    let (tenant, user, access) = (TenantId::new(), UserId::new(), [0x0b_u8; 32]);
    drop(database_at(path, 72));
    let mut conn = Connection::open(path).unwrap();
    conn.execute(
        "INSERT INTO tenants(id, slug, created_ms) VALUES(?1, 'acme', 1)",
        [tenant.as_bytes().as_slice()],
    )
    .unwrap();
    let secret = [0x01_u8; 16];
    conn.execute(
        "INSERT INTO secrets(id, tenant_id, name, current_version, created_ms, updated_ms)
         VALUES(?1, ?2, 'TOKEN', 1, 1, 1)",
        params![secret.as_slice(), tenant.as_bytes().as_slice()],
    )
    .unwrap();
    let mut sealed = vec![0x02_u8; 64];
    sealed[0] = 0x02;
    conn.execute(
        "INSERT INTO secret_versions(secret_id, version, sealed, created_ms)
         VALUES(?1, 1, ?2, 1)",
        params![secret.as_slice(), sealed],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO oauth_clients(client_id, name, first_party, loopback, redirect_path,
             device, max_scopes, created_ms)
         VALUES('legacy-cli', 'Legacy', 0, 1, '/cb', 1, 1023, 1)",
        [],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO oauth_client_redirects(client_id, uri)
         VALUES('legacy-cli', 'https://legacy.example/cb')",
        [],
    )
    .unwrap();
    let tx = conn.transaction().unwrap();
    provisioning::insert_human(&tx, user, "Root", true, NOW).unwrap();
    tx.commit().unwrap();
    conn.execute(
        "INSERT INTO oauth_grants(id, user_id, client_id, kind, scopes, audience, created_ms,
             expires_ms, resource)
         VALUES(?1, ?2, 'legacy-cli', 1, 1023, 1, 1, 2, 1)",
        params![[0x0c_u8; 16].as_slice(), user.as_bytes().as_slice()],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO oauth_access_tokens(token_digest, grant_id, generation, scopes,
             created_ms, expires_ms)
         VALUES(?1, ?2, 1, 1023, 1, 2)",
        params![access.as_slice(), [0x0c_u8; 16].as_slice()],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO pools(id, name, kind, created_ms) VALUES(?1, 'builders', 1, 1)",
        [[0x0f_u8; 16].as_slice()],
    )
    .unwrap();
    for (name, protocol, software, fingerprint) in [
        ("old", 13, Some("sentinel-worker 0.1.0"), 0x21_u8),
        ("next", 14, None, 0x22_u8),
    ] {
        conn.execute(
            "INSERT INTO workers(id, pool_id, fingerprint, name, arch, capabilities, protocol,
                 enrolled_ms, software)
             VALUES(?1, ?2, ?3, ?4, 'x86_64', 15, ?5, 1, ?6)",
            params![
                [fingerprint; 16].as_slice(),
                [0x0f_u8; 16].as_slice(),
                [fingerprint; 32].as_slice(),
                name,
                protocol,
                software
            ],
        )
        .unwrap();
    }
    let _ = tenant;
    access
}

#[test]
fn the_preflight_on_a_populated_database_names_the_copy_and_the_rows_it_rewrites() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("metadata.sqlite");
    let access = populated_at_72(&path);
    let before = std::fs::read(&path).unwrap();
    let stored = {
        let conn = Connection::open(&path).unwrap();
        let rows = |table: &str| -> u64 {
            conn.query_row(&format!("SELECT count(*) FROM {table}"), [], |r| {
                r.get::<_, i64>(0)
            })
            .unwrap() as u64
        };
        [
            "oauth_clients",
            "oauth_client_redirects",
            "oauth_grants",
            "oauth_access_tokens",
        ]
        .map(|table| (table, rows(table)))
    };

    let report = upgrade::preflight(dir.path()).unwrap();
    assert_eq!(report.inspection.pending, vec![73, 74, 75, 76, 77, 78]);
    assert!(report.inspection.openable() && report.inspection.integrity == "ok");
    assert_eq!(
        report.copy.as_deref(),
        Some(upgrade::snapshot_path(&path, 72).as_path()),
        "the copy the upgrade writes is the rollback point, named before it exists"
    );
    assert_eq!(report.needed_bytes, report.inspection.bytes * 2);

    // What the upgrade does to the rows already stored: migration 73 rebuilds every OAuth table, and
    // migrations 74 to 77 add runner-mode, guided-migration, fork-policy and AI-request shape
    // without visiting a row.
    assert_eq!(
        report
            .steps
            .iter()
            .map(|step| step.version)
            .collect::<Vec<_>>(),
        vec![73, 74, 75, 76, 77, 78]
    );
    let rewrites = |step: usize| -> Vec<(String, u64)> {
        report.steps[step]
            .rewrites
            .iter()
            .map(|rewrite| (rewrite.table.clone(), rewrite.rows))
            .collect()
    };
    let (oauth, runner, migration, fork) = (rewrites(0), rewrites(1), rewrites(2), rewrites(3));
    let switch = rewrites(4);
    for (table, rows) in stored {
        assert!(rows > 0, "{table} is populated");
        assert!(
            oauth.contains(&(table.to_owned(), rows)),
            "migration 73 rewrites {table}'s {rows} rows: {oauth:?}"
        );
    }
    assert!(
        runner.is_empty(),
        "migration 74 only adds shape: {runner:?}"
    );
    assert!(
        migration.is_empty(),
        "migration 75 only adds shape: {migration:?}"
    );
    assert!(fork.is_empty(), "migration 76 only adds shape: {fork:?}");
    assert!(
        switch.is_empty(),
        "migration 77 only adds shape: {switch:?}"
    );

    // Every enrolled worker is listed with what it announces, and the one this build cannot serve is
    // marked rather than silently dropped.
    let workers: Vec<(&str, u16, Option<&str>, bool)> = report
        .workers
        .iter()
        .map(|w| {
            (
                w.name.as_str(),
                w.protocol,
                w.software.as_deref(),
                w.refused,
            )
        })
        .collect();
    assert_eq!(
        workers,
        vec![
            ("next", 14, None, true),
            ("old", 13, Some("sentinel-worker 0.1.0"), false)
        ]
    );

    // A populated database with sealed values needs its key before it needs anything else.
    assert!(report.sealed_values && !report.key_present);
    assert_eq!(report.blocking.len(), 1, "{:?}", report.blocking);
    assert!(
        report.blocking[0].contains("master.key"),
        "{:?}",
        report.blocking
    );
    let key = dir.path().join(sentinel_store::MASTER_KEY_FILE);
    std::fs::write(&key, [0x33_u8; 32]).unwrap();
    let report = upgrade::preflight(dir.path()).unwrap();
    assert!(
        report.key_present && report.blocking.is_empty(),
        "{:?}",
        report.blocking
    );
    assert_eq!(std::fs::read(&path).unwrap(), before, "nothing written");
    assert_eq!(version(&path), 72);

    // The upgrade takes the copy the preflight named, and everything it rewrote arrives intact.
    let (store, copy) = upgrade::open_upgrading(&path, Durability::Full).unwrap();
    assert_eq!(copy, Some(upgrade::snapshot_path(&path, 72)));
    assert_eq!(version(&path), schema::LATEST);
    let survivors: (i64, Vec<u8>, i64) = store
        .read(|c| {
            Ok((
                c.query_row("SELECT count(*) FROM oauth_clients", [], |r| r.get(0))?,
                c.query_row("SELECT token_digest FROM oauth_access_tokens", [], |r| {
                    r.get(0)
                })?,
                c.query_row("SELECT scopes FROM oauth_grants", [], |r| r.get(0))?,
            ))
        })
        .unwrap();
    assert_eq!(survivors, (2, access.to_vec(), 1023));
    drop(store);
    let copy = upgrade::snapshot_path(&path, 72);
    assert_eq!(version(&copy), 72);
    let copied: i64 = Connection::open(&copy)
        .unwrap()
        .query_row("SELECT count(*) FROM oauth_access_tokens", [], |r| r.get(0))
        .unwrap();
    assert_eq!(
        copied, 1,
        "the copy is the database as it was before the upgrade"
    );
}

#[test]
fn the_copy_restores_the_database_the_matrix_says_no_release_can_read_after_the_upgrade() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("metadata.sqlite");
    let tenant = TenantId::new();
    {
        let conn = database_at(&path, 70);
        conn.execute(
            "INSERT INTO tenants(id, slug, created_ms) VALUES(?1, 'acme', 1)",
            [tenant.as_bytes().as_slice()],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO oauth_clients(client_id, name, first_party, loopback, redirect_path,
                 device, max_scopes, created_ms)
             VALUES('legacy-cli', 'Legacy', 0, 1, '/cb', 1, 1023, 1)",
            [],
        )
        .unwrap();
    }
    let report = upgrade::preflight(dir.path()).unwrap();
    assert_eq!(
        report.inspection.pending,
        vec![71, 72, 73, 74, 75, 76, 77, 78]
    );
    assert_eq!(
        report.copy.as_deref(),
        Some(upgrade::snapshot_path(&path, 70).as_path())
    );
    assert_eq!(
        report.steps.iter().map(|s| s.version).collect::<Vec<_>>(),
        vec![71, 72, 73, 74, 75, 76, 77, 78]
    );
    assert!(report.blocking.is_empty(), "{:?}", report.blocking);

    let (store, copy) = upgrade::open_upgrading(&path, Durability::Full).unwrap();
    let copy = copy.expect("a pending migration takes the copy");
    // What was written after the upgrade is what a restore loses.
    store
        .writer()
        .write(move |tx| jobs::insert_tenant(tx, TenantId::new(), "after", NOW))
        .unwrap();
    drop(store);
    assert_eq!(version(&path), schema::LATEST);

    // The matrix: no release older than the current schema runs on the result, because migration 74 is
    // readable by nothing below itself, so the copy (or a backup) is the only rollback.
    let needs = |db: &std::path::Path, release: u32| -> u32 {
        Connection::open(db)
            .unwrap()
            .query_row(
                "SELECT COALESCE(MAX(readable_by), 0) FROM schema_migrations
                 WHERE version > ?1 AND version <= ?2",
                params![release, schema::LATEST],
                |r| r.get(0),
            )
            .unwrap()
    };
    assert_eq!(
        schema::readable_by(77),
        76,
        "migration 77 is readable by the release before it"
    );
    assert_eq!(
        schema::readable_by(schema::LATEST),
        schema::LATEST,
        "the newest migration is readable by nothing older, so the copy is the only rollback"
    );
    for release in [69, schema::LATEST - 2] {
        assert!(
            needs(&path, release) > release,
            "release {release} cannot run on the upgraded database"
        );
    }
    // Restoring the copy is that rollback path, and release 69 runs on it as the matrix says.
    std::fs::copy(&copy, &path).unwrap();
    for suffix in ["-wal", "-shm"] {
        let mut stale = path.clone().into_os_string();
        stale.push(suffix);
        let stale = std::path::PathBuf::from(stale);
        if stale.exists() {
            std::fs::remove_file(stale).unwrap();
        }
    }
    assert_eq!(version(&path), 70, "the copy is the old schema");
    let restored = Connection::open(&path).unwrap();
    let slugs: Vec<String> = restored
        .prepare("SELECT slug FROM tenants ORDER BY slug")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(slugs, ["acme"], "the restore drops what the upgrade wrote");
    assert_eq!(
        needs(&path, 69),
        69,
        "migration 70 is readable by 69, so release 69 runs on the restored copy"
    );
    let clients: Vec<String> = restored
        .prepare("SELECT client_id FROM oauth_clients ORDER BY client_id")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(clients, ["legacy-cli", "sentinel-cli"]);
    drop(restored);
    // A second preflight over the restored copy reports the same upgrade, not a migration half done.
    let again = upgrade::preflight(dir.path()).unwrap();
    assert_eq!(
        again.inspection.pending,
        vec![71, 72, 73, 74, 75, 76, 77, 78]
    );
    assert_eq!(
        again.steps.iter().map(|s| s.version).collect::<Vec<_>>(),
        vec![71, 72, 73, 74, 75, 76, 77, 78]
    );
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
    // are R, columns are N = 53, 55, 58, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, LATEST.
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
        78,
        "extend the matrix in docs/upgrades.md for the new migration"
    );
    let sources = upgrade_sources();
    assert_eq!(
        sources,
        vec![44, 47, 48, 51, 56, 57, 63, 64, 66, 69, 76, 77]
    );
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
        let ok: Vec<bool> = [53, 55, 58, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75]
            .iter()
            .map(|&newest| from >= newest || readable(&db, from, newest))
            .collect();
        // Schema 75 is readable by nothing below itself (fork provenance is what placement reads),
        // and every release here is below it.
        // The columns are fixed up to 75, and the newest migration is checked from the schema itself,
        // so this table does not have to grow a column every time one is added: nothing below LATEST
        // may run on a database at LATEST.
        // Migration 77 only adds a tenant switch no older statement reads, so it is declared
        // readable by the release before it; migration 78 adds the AI request rows and the
        // delegations they name and is readable by nothing older, so no release here runs on a
        // database at LATEST.
        assert!(
            !readable(&db, from, schema::LATEST),
            "release {from} runs on a database at {LATEST}",
            LATEST = schema::LATEST
        );
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
        // Migration 70 (the storage thresholds) is readable by 69: no schema-69 statement reads or
        // writes the new columns, its `storage_defaults` insert takes their defaults and a tenant
        // policy it writes leaves them NULL, which inherits; while an older controller runs on the
        // result it enforces the bare quota instead of the tenant's narrowed hard threshold.
        // Migration 72 (run-level and runner-mode artifacts) rebuilds the artifact table with a
        // nullable job and attempt and two origins an older controller cannot explain, so 70 and 71
        // stop at 70. Migration 73 (the OAuth scope bound) changes a constraint and rewrites the
        // CLI's seeded cap, so 72 stops at 72. Migration 74 (runner-mode leases) is readable by
        // nothing older either: a schema-73 controller records demand it can never place and can
        // neither deliver a JIT configuration nor de-register the runners this one registered.
        // Migration 75 (the migration switch and the write permissions of each installation
        // snapshot) is readable by nothing older either: a schema-74 controller records no
        // snapshot's migration permissions, so the bits the new write gate reads go stale where a
        // permission is withdrawn on GitHub, and it holds no switch to turn off.
        let expected = match from {
            44 | 47 | 48 => [
                false, false, false, false, false, false, false, false, false, false, false, false,
                false, false, false,
            ],
            51 => [
                true, false, false, false, false, false, false, false, false, false, false, false,
                false, false, false,
            ],
            56 => [
                true, true, false, false, false, false, false, false, false, false, false, false,
                false, false, false,
            ],
            57 => [
                true, true, true, false, false, false, false, false, false, false, false, false,
                false, false, false,
            ],
            63 => [
                true, true, true, true, false, false, false, false, false, false, false, false,
                false, false, false,
            ],
            64 | 65 => [
                true, true, true, true, true, false, false, false, false, false, false, false,
                false, false, false,
            ],
            66 | 67 => [
                true, true, true, true, true, true, true, false, false, false, false, false, false,
                false, false,
            ],
            68 => [
                true, true, true, true, true, true, true, true, false, false, false, false, false,
                false, false,
            ],
            69 | 70 => [
                true, true, true, true, true, true, true, true, true, true, false, false, false,
                false, false,
            ],
            71 => [
                true, true, true, true, true, true, true, true, true, true, true, false, false,
                false, false,
            ],
            73 => [
                true, true, true, true, true, true, true, true, true, true, true, true, true,
                false, false,
            ],
            // The newest releases in the list run on every column they are listed against.
            75..=77 => [
                true, true, true, true, true, true, true, true, true, true, true, true, true, true,
                true,
            ],
            _ => unreachable!(),
        };
        assert_eq!(
            ok,
            expected,
            "release {from} on the schemas the matrix lists below {LATEST}",
            LATEST = schema::LATEST
        );
    }
}

/// Every object SQLite holds, so two databases can be compared as schemas rather than by whatever a test
/// happened to look for. `schema_migrations` is skipped: whatever opens the database first (the store, or a
/// fixture with its own literal) writes its text, so it is not the migrations' to compare.
fn schema_sql(db: &Connection) -> Vec<(String, String, String)> {
    let mut stmt = db
        .prepare(
            "SELECT type, name, COALESCE(sql, '') FROM sqlite_master
             WHERE name != 'schema_migrations' ORDER BY type, name",
        )
        .unwrap();
    stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .unwrap()
        .map(|r| r.unwrap())
        .collect()
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

/// Migration 68 gives every artifact a class, a charge weight and a pin column; the upgraded
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

#[test]
fn a_database_upgraded_from_066_has_the_thresholds_a_fresh_one_has() {
    let dir = tempfile::tempdir().unwrap();
    let upgraded = dir.path().join("upgraded.sqlite");
    let tenant = TenantId::new();
    let id = tenant.as_bytes().to_vec();
    let seed = database_at(&upgraded, 66);
    seed.execute(
        "INSERT INTO tenants(id, slug, created_ms) VALUES (?1, 'acme', 1)",
        params![id.as_slice()],
    )
    .unwrap();
    seed.execute(
        "INSERT INTO tenant_usage(tenant_id, bytes) VALUES (?1, 500)",
        params![id.as_slice()],
    )
    .unwrap();
    seed.execute(
        "INSERT INTO storage_policies(tenant_id, repo_id, quota_bytes, updated_ms)
         VALUES (?1, X'', 1000, 1)",
        params![id.as_slice()],
    )
    .unwrap();
    drop(seed);

    let (store, copy) = upgrade::open_upgrading(&upgraded, Durability::Full).unwrap();
    assert!(copy.is_some(), "a pending migration takes a copy first");
    // The row the tenant already had keeps its quota and inherits both thresholds; the deployment's
    // defaults are the ones the migration wrote.
    let (d, policy, effective) = store
        .read(|c| {
            let d = sentinel_store::retention::installed(c)?;
            Ok((
                d,
                sentinel_store::retention::policy(c, tenant, None)?,
                sentinel_store::retention::effective(c, &d, tenant, None)?,
            ))
        })
        .unwrap();
    assert_eq!((d.soft_percent, d.hard_percent), (80, 100));
    assert_eq!(policy.quota_bytes, Some(1000));
    assert_eq!((policy.soft_percent, policy.hard_percent), (None, None));
    assert_eq!((effective.soft_percent, effective.hard_percent), (80, 100));
    let standing = store
        .read(|c| sentinel_store::retention::standing(c, &d, tenant))
        .unwrap();
    assert_eq!(standing.used, 500);
    assert_eq!((standing.soft_bytes, standing.hard_bytes), (800, 1000));
    let upgraded_schema = store.read(|c| Ok(schema_sql(c))).unwrap();
    drop(store);

    let fresh = dir.path().join("fresh.sqlite");
    drop(Store::open(&fresh, Durability::Full).unwrap());
    let fresh_schema = schema_sql(&Connection::open(&fresh).unwrap());
    let differing: Vec<_> = upgraded_schema
        .iter()
        .filter_map(|row| {
            let fresh = fresh_schema
                .iter()
                .find(|f| (f.0.as_str(), f.1.as_str()) == (row.0.as_str(), row.1.as_str()));
            match fresh {
                Some(fresh) if fresh.2 == row.2 => None,
                other => Some((row.clone(), other.cloned())),
            }
        })
        .collect();
    assert!(
        differing.is_empty(),
        "an upgraded database has the schema a fresh one has: {differing:?}"
    );
    assert_eq!(upgraded_schema.len(), fresh_schema.len());
}

/// Migration 72 rebuilds `artifacts` with a nullable job and attempt and two more origins; the
/// upgraded database has to equal a fresh one and an artifact stored before it keeps its identity,
/// its refusal reason and its class.
#[test]
fn a_database_upgraded_from_071_keeps_its_artifacts_and_equals_a_fresh_one() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("metadata.sqlite");
    let (tenant, repo, run, job, attempt, captured, refused) = (
        TenantId::new(),
        RepoId::new(),
        RunId::new(),
        sentinel_core::JobId::new(),
        sentinel_core::AttemptId::new(),
        sentinel_core::ArtifactId::new(),
        sentinel_core::ArtifactId::new(),
    );
    {
        let conn = database_at(&path, 71);
        let (t, r, ru, j, a, c, f) = (
            tenant.as_bytes().as_slice(),
            repo.as_bytes().as_slice(),
            run.as_bytes().as_slice(),
            job.as_bytes().as_slice(),
            attempt.as_bytes().as_slice(),
            captured.as_bytes().as_slice(),
            refused.as_bytes().as_slice(),
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
                 manifest_version, entries, bytes, retain_until_ms, created_ms, class,
                 charged_bytes)
             VALUES(?1, ?2, ?3, ?4, ?5, 'out', 0, 1, 2, 40, 5000000000, 1, 'evidence', 40)",
            params![c, t, ru, j, a],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO artifacts(id, tenant_id, run_id, job_id, attempt_id, name, state_code,
                 manifest_version, entries, bytes, retain_until_ms, created_ms, failure)
             VALUES(?1, ?2, ?3, ?4, ?5, 'logs', 2, NULL, 0, 0, 5000000000, 1, 'quota_exceeded')",
            params![f, t, ru, j, a],
        )
        .unwrap();
        assert_eq!(version(&path), 71);
    }
    let (store, copy) = upgrade::open_upgrading(&path, Durability::Full).unwrap();
    assert!(copy.is_some(), "a pending migration takes a copy first");
    type Stored = (String, i64, String, Option<Vec<u8>>, Option<String>, i64);
    let rows: Vec<Stored> = store
        .read(|c| {
            let mut stmt = c.prepare(
                "SELECT name, origin_code, class, job_id, failure, charged_bytes
                 FROM artifacts ORDER BY name",
            )?;
            let rows = stmt
                .query_map([], |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get(3)?,
                        r.get(4)?,
                        r.get(5)?,
                    ))
                })?
                .collect::<Result<_, _>>()?;
            Ok(rows)
        })
        .unwrap();
    assert_eq!(
        rows.len(),
        2,
        "both artifacts survive the rebuild: {rows:?}"
    );
    assert_eq!(rows[0].0, "logs");
    assert_eq!(
        rows[0].1, 0,
        "an artifact stored before the migration is a job's"
    );
    assert!(
        rows[0].3.is_some(),
        "the refused row still names its job and attempt"
    );
    assert_eq!(rows[0].4.as_deref(), Some("quota_exceeded"));
    assert_eq!(rows[1].0, "out");
    assert_eq!(rows[1].2, "evidence", "its class is unchanged");
    assert_eq!(rows[1].5, 40, "and so is its charge");
    assert!(rows[1].3.is_some(), "and it still names its job");
    let upgraded = store.read(|c| Ok(schema_sql(c))).unwrap();
    drop(store);
    assert_eq!(version(&path), schema::LATEST);
    let fresh = tempfile::tempdir().unwrap();
    let fresh_store = Store::open(fresh.path().join("metadata.sqlite"), Durability::Full).unwrap();
    assert_eq!(
        upgraded,
        fresh_store.read(|c| Ok(schema_sql(c))).unwrap(),
        "the upgraded database has the schema a fresh one has, triggers and indexes included"
    );
}

/// Migration 73 widens every stored OAuth scope column and repoints the rebuilt children at the
/// rebuilt parents; every row of every OAuth table has to survive with its digest, index and
/// trigger, and the database has to equal a fresh one.
#[test]
fn a_database_upgraded_from_072_keeps_its_oauth_rows_and_equals_a_fresh_one() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("metadata.sqlite");
    let (user, grant, code, device, refresh, access) = (
        UserId::new(),
        GrantId::new(),
        [0x02u8; 32],
        [0x03u8; 32],
        [0x04u8; 32],
        [0x05u8; 32],
    );
    {
        let mut conn = database_at(&path, 72);
        conn.execute_batch("PRAGMA foreign_keys=ON;").unwrap();
        let tx = conn.transaction().unwrap();
        provisioning::insert_human(&tx, user, "Root", true, NOW).unwrap();
        tx.commit().unwrap();
        conn.execute(
            "INSERT INTO oauth_clients(client_id, name, first_party, loopback, redirect_path,
                 device, max_scopes, created_ms)
             VALUES('legacy-cli', 'Legacy', 0, 1, '/cb', 1, 1023, 1)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO oauth_client_redirects(client_id, uri)
             VALUES('legacy-cli', 'https://legacy.example/cb')",
            [],
        )
        .unwrap();
        let challenge = "a".repeat(43);
        conn.execute(
            "INSERT INTO oauth_grants(id, user_id, client_id, kind, scopes, audience, created_ms,
                 expires_ms, resource)
             VALUES(?1, ?2, 'legacy-cli', 1, 1023, 1, 1, 2, 1)",
            params![grant.as_bytes().as_slice(), user.as_bytes().as_slice()],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO oauth_codes(code_digest, client_id, redirect_uri, code_challenge, user_id,
                 scopes, audience, created_ms, expires_ms, resource)
             VALUES(?1, 'legacy-cli', 'https://legacy.example/cb', ?2, ?3, 1023, 1, 1, 2, 1)",
            params![code.as_slice(), challenge, user.as_bytes().as_slice()],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO oauth_device_codes(device_digest, user_code, client_id, scopes, audience,
                 created_ms, expires_ms, resource)
             VALUES(?1, 'BCDFGHJK', 'legacy-cli', 1023, 1, 1, 2, 1)",
            [device.as_slice()],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO oauth_refresh_tokens(token_digest, grant_id, generation, created_ms,
                 idle_expires_ms)
             VALUES(?1, ?2, 1, 1, 2)",
            params![refresh.as_slice(), grant.as_bytes().as_slice()],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO oauth_access_tokens(token_digest, grant_id, generation, scopes,
                 created_ms, expires_ms)
             VALUES(?1, ?2, 1, 1023, 1, 2)",
            params![access.as_slice(), grant.as_bytes().as_slice()],
        )
        .unwrap();
        assert_eq!(version(&path), 72);
    }
    let (store, copy) = upgrade::open_upgrading(&path, Durability::Full).unwrap();
    assert!(copy.is_some(), "a pending migration takes a copy first");
    type Oauth = (Vec<(String, i64)>, i64, Vec<u8>, Vec<u8>, i64);
    let (caps, grants, kept_refresh, kept_access, redirects): Oauth = store
        .read(|c| {
            let mut caps =
                c.prepare("SELECT client_id, max_scopes FROM oauth_clients ORDER BY 1")?;
            let caps = caps
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
                .collect::<Result<Vec<_>, _>>()?;
            let grants: i64 = c.query_row("SELECT scopes FROM oauth_grants", [], |r| r.get(0))?;
            let refresh: Vec<u8> =
                c.query_row("SELECT token_digest FROM oauth_refresh_tokens", [], |r| {
                    r.get(0)
                })?;
            let access: Vec<u8> =
                c.query_row("SELECT token_digest FROM oauth_access_tokens", [], |r| {
                    r.get(0)
                })?;
            let redirects: i64 =
                c.query_row("SELECT count(*) FROM oauth_client_redirects", [], |r| {
                    r.get(0)
                })?;
            Ok((caps, grants, refresh, access, redirects))
        })
        .unwrap();
    assert_eq!(
        caps,
        vec![
            ("legacy-cli".to_owned(), 1023),
            ("sentinel-cli".to_owned(), 2047)
        ],
        "a stored client cap is copied as it is; the CLI seed is every scope"
    );
    assert_eq!(grants, 1023, "the grant keeps the scopes it was issued");
    assert_eq!(
        kept_refresh,
        refresh.to_vec(),
        "refresh digests are unchanged"
    );
    assert_eq!(kept_access, access.to_vec(), "access digests are unchanged");
    assert_eq!(redirects, 1, "the client's redirect survives the rebuild");
    let codes: (i64, i64) = store
        .read(|c| {
            Ok((
                c.query_row("SELECT scopes FROM oauth_codes", [], |r| r.get(0))?,
                c.query_row("SELECT scopes FROM oauth_device_codes", [], |r| r.get(0))?,
            ))
        })
        .unwrap();
    assert_eq!(codes, (1023, 1023), "codes and device requests keep theirs");
    let upgraded = store.read(|c| Ok(schema_sql(c))).unwrap();
    drop(store);
    assert_eq!(version(&path), schema::LATEST);
    let fresh = tempfile::tempdir().unwrap();
    let fresh_store = Store::open(fresh.path().join("metadata.sqlite"), Durability::Full).unwrap();
    assert_eq!(
        upgraded,
        fresh_store.read(|c| Ok(schema_sql(c))).unwrap(),
        "the upgraded database has the schema a fresh one has, triggers and indexes included"
    );
}
