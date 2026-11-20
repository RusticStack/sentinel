//! `sentinel admin upgrade check`: what starting this release on a data directory would do, read
//! without migrating it ([upgrades](../../../docs/upgrades.md)).

#![cfg(all(target_os = "linux", feature = "server"))]

use std::{path::Path, process::Command};

use sentinel_store::{Connection, schema};

fn sentinel(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_sentinel"))
        .args(args)
        .output()
        .unwrap()
}

fn check(data: &Path) -> (std::process::Output, serde_json::Value) {
    let output = sentinel(&[
        "admin",
        "upgrade",
        "check",
        "--data-dir",
        data.to_str().unwrap(),
    ]);
    let report = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|e| panic!("{e}: {}", String::from_utf8_lossy(&output.stdout)));
    (output, report)
}

/// A database one migration behind this build, holding a tenant and a worker that enrolled from a
/// newer release: what an operator inspecting a populated deployment finds.
fn populated_one_behind(data: &Path) {
    std::fs::create_dir_all(data).unwrap();
    let mut conn = Connection::open(data.join(sentinel_store::METADATA_FILE)).unwrap();
    conn.execute_batch(
        "CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY, applied_ms INTEGER NOT NULL);",
    )
    .unwrap();
    for &(version, sql) in schema::MIGRATIONS
        .iter()
        .take((schema::LATEST - 1) as usize)
    {
        let tx = conn.transaction().unwrap();
        tx.execute_batch(sql).unwrap();
        if version >= schema::READABLE_BY_SINCE {
            tx.execute(
                "INSERT INTO schema_migrations VALUES (?1, 1, ?2)",
                (version, schema::readable_by(version)),
            )
            .unwrap();
        } else {
            tx.execute("INSERT INTO schema_migrations VALUES (?1, 1)", [version])
                .unwrap();
        }
        tx.commit().unwrap();
    }
    conn.execute(
        "INSERT INTO tenants(id, slug, created_ms) VALUES(?1, 'acme', 1)",
        [[1_u8; 16].as_slice()],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO pools(id, name, kind, created_ms) VALUES(?1, 'builders', 1, 1)",
        [[2_u8; 16].as_slice()],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO workers(id, pool_id, fingerprint, name, arch, capabilities, protocol,
             enrolled_ms, software)
         VALUES(?1, ?2, ?3, 'future', 'x86_64', 15, ?4, 1, 'sentinel-worker 9.9.9')",
        (
            [3_u8; 16].as_slice(),
            [2_u8; 16].as_slice(),
            [4_u8; 32].as_slice(),
            i64::from(sentinel_protocol::negotiate::SUPPORTED_MAX.0) + 1,
        ),
    )
    .unwrap();
}

#[test]
fn the_check_reports_the_upgrade_without_migrating_and_exits_two_when_it_blocks() {
    let root = tempfile::tempdir().unwrap();
    let data = root.path().join("data");

    // Nothing there yet: a fresh deployment, every migration pending, nothing blocking.
    let (output, fresh) = check(&data);
    assert_eq!(output.status.code(), Some(0), "{fresh}");
    assert_eq!(fresh["fresh"], true);
    assert_eq!(
        fresh["pending_migrations"].as_array().unwrap().len(),
        schema::MIGRATIONS.len()
    );
    assert!(
        fresh["copy"].is_null(),
        "nothing is copied for fresh: {fresh}"
    );

    populated_one_behind(&data);
    let before = std::fs::read(data.join(sentinel_store::METADATA_FILE)).unwrap();
    let (output, report) = check(&data);
    assert_eq!(output.status.code(), Some(0), "{report}");
    assert_eq!(report["fresh"], false);
    assert_eq!(report["schema"]["database"], schema::LATEST - 1);
    assert_eq!(report["schema"]["binary"], schema::LATEST);
    assert_eq!(report["integrity"], "ok");
    assert_eq!(
        report["copy"].as_str().unwrap(),
        sentinel_store::upgrade::snapshot_path(
            &data.join(sentinel_store::METADATA_FILE),
            schema::LATEST - 1
        )
        .to_str()
        .unwrap(),
        "the rollback point is named before it exists"
    );
    assert!(
        report["blocking"].as_array().unwrap().is_empty(),
        "{report}"
    );
    // The newest migration only creates two tables no earlier statement holds, so its step visits no
    // row; the storage rebuild one step below it is where a preflight from two schemas back names the
    // policy table it carries over (`sentinel-store`'s own preflight test asserts that).
    let steps = report["steps"].as_array().unwrap();
    assert_eq!(steps.len(), 1, "{report}");
    assert_eq!(steps[0]["migration"], schema::LATEST);
    assert_eq!(steps[0]["rewrites"], serde_json::json!([]), "{report}");
    // The per-tenant defaults the upgrade applies are sized from the data file system and reported, and
    // this tenant is under them, so nothing is capped.
    let defaults = &report["tenant_defaults"];
    assert!(
        defaults["tenant_quota_bytes"].as_u64().unwrap()
            > defaults["personal_quota_bytes"].as_u64().unwrap(),
        "{report}"
    );
    assert_eq!(report["capped_tenants"]["total"], 0, "{report}");
    assert!(
        report["capped_tenants"]["listed"]
            .as_array()
            .unwrap()
            .is_empty(),
        "{report}"
    );
    // A worker from a newer release is listed and marked rather than dropped.
    let workers = report["workers"].as_array().unwrap();
    assert_eq!(workers.len(), 1, "{report}");
    assert_eq!(workers[0]["name"], "future");
    assert_eq!(workers[0]["software"], "sentinel-worker 9.9.9");
    assert_eq!(workers[0]["refused_after_upgrade"], true);
    assert_eq!(
        std::fs::read(data.join(sentinel_store::METADATA_FILE)).unwrap(),
        before,
        "the check never writes to the database"
    );

    // A database a newer release migrated beyond this build's reading exits 2 and says why.
    Connection::open(data.join(sentinel_store::METADATA_FILE))
        .unwrap()
        .execute(
            "INSERT INTO schema_migrations VALUES (?1, 1, ?1)",
            [schema::LATEST + 2],
        )
        .unwrap();
    let (output, report) = check(&data);
    assert_eq!(output.status.code(), Some(2), "{report}");
    assert_eq!(report["newer_database"], true);
    assert_eq!(report["newer_needs_schema"], schema::LATEST + 2);
    let blocking = report["blocking"].as_array().unwrap();
    assert_eq!(blocking.len(), 1, "{report}");
    assert!(
        blocking[0].as_str().unwrap().contains("needs schema"),
        "{report}"
    );
}
