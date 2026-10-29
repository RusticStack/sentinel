//! A queue row whose ids cannot be decoded is passed over, counted and named, and the rows behind it are still served.

use rusqlite::{Connection, params};
use sentinel_core::{TenantId, UnixMillis};
use sentinel_store::{
    objects::Digest,
    offload::{self, Delete},
    skipped,
};

fn database() -> Connection {
    let mut conn = Connection::open_in_memory().unwrap();
    sentinel_store::migrate(&mut conn).unwrap();
    // The damage is written the way outside tampering would: past the foreign keys that tie a row to its tenant.
    conn.execute_batch("PRAGMA foreign_keys = OFF").unwrap();
    conn
}

#[test]
fn a_malformed_delete_row_does_not_hold_the_deletes_behind_it() {
    let mut conn = database();
    conn.execute(
        "INSERT INTO s3_deletes(kind, tenant_id, digest, queued_ms) VALUES (0, ?1, randomblob(32), 1)",
        [[0u8; 16].as_slice()],
    )
    .unwrap();
    let good = TenantId::new();
    let digest = Digest::from_bytes([7; 32]);
    let tx = conn.transaction().unwrap();
    offload::queue_object_delete(&tx, good, &digest, UnixMillis(2)).unwrap();
    tx.commit().unwrap();

    let before = skipped::total();
    let rows = offload::deletes(&conn, 16).unwrap();
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert!(matches!(
        &rows[0],
        Delete::Object { tenant, digest: d, .. } if *tenant == good && *d == digest
    ));
    assert!(skipped::total() > before, "the passed-over row is counted");
}

#[test]
fn a_malformed_object_row_does_not_stop_replication() {
    let conn = database();
    let insert = |tenant: &[u8], created: i64, len: i64| {
        conn.execute(
            "INSERT INTO objects(tenant_id, digest, len, created_ms) VALUES (?1, randomblob(32), ?2, ?3)",
            params![tenant, len, created],
        )
        .unwrap();
    };
    // Oldest first, as the replicator reads them: the damaged row is the head of the queue.
    insert(&[0u8; 16], 1, 3);
    let good = TenantId::new();
    insert(good.as_bytes().as_slice(), 2, 5);

    let before = skipped::total();
    let rows = offload::unreplicated(&conn, 16).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!((rows[0].tenant, rows[0].len), (good, 5));
    assert!(skipped::total() > before);
}
