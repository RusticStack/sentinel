//! D01 tenant-scoped immutable objects and versioned manifests: the
//! stage/commit order, verified reads, manifest versioning and reference
//! checks, and recovery's orphan/corrupt/missing reconciliation.
use std::io::Write;

use rusqlite::Connection;
use sentinel_core::{
    TenantId, UnixMillis, UserId,
    auth::{Namespace, Principal},
};
use sentinel_store::{
    Error,
    auth::{self, NamespaceKind, provisioning},
    objects::{self, Digest, Entry, Expect, Kind, Objects},
};

const NOW: UnixMillis = UnixMillis(1_000);

struct Fixture {
    objects: Objects,
    conn: Connection,
    dir: tempfile::TempDir,
    tenant: TenantId,
    other: TenantId,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let objects = Objects::open(dir.path()).unwrap();
    let mut conn = Connection::open_in_memory().unwrap();
    conn.execute_batch("PRAGMA foreign_keys=ON").unwrap();
    sentinel_store::migrate(&mut conn).unwrap();
    let alice = Principal::new(
        UserId::new(),
        sentinel_core::auth::Permissions::ALL,
        None,
        None,
    );
    let (tenant, other) = (TenantId::new(), TenantId::new());
    let tx = conn.transaction().unwrap();
    provisioning::insert_human(&tx, alice.user, "alice", true, NOW).unwrap();
    auth::create_namespace(
        &tx,
        alice,
        tenant,
        Namespace::parse("alice").unwrap(),
        NamespaceKind::Personal(alice.user),
        NOW,
    )
    .unwrap();
    auth::create_namespace(
        &tx,
        alice,
        other,
        Namespace::parse("other").unwrap(),
        NamespaceKind::Organization,
        NOW,
    )
    .unwrap();
    tx.commit().unwrap();
    Fixture {
        objects,
        conn,
        dir,
        tenant,
        other,
    }
}

impl Fixture {
    fn put(&mut self, tenant: TenantId, body: &[u8]) -> Digest {
        let staged = self
            .objects
            .stage(tenant, body, u64::MAX, Expect::default())
            .unwrap();
        let digest = staged.digest();
        let tx = self.conn.transaction().unwrap();
        assert!(self.objects.commit(&tx, &staged).unwrap());
        tx.commit().unwrap();
        digest
    }
}

fn entry(path: &str, digest: Digest, len: u64) -> Entry {
    Entry {
        path: path.into(),
        digest,
        len,
        mode: 0,
    }
}

#[test]
fn staged_object_becomes_committed_and_reads_back_verified() {
    let mut fx = fixture();
    let body = b"artifact payload".repeat(1000);
    let digest = fx.put(fx.tenant, &body);
    let meta = fx.objects.meta(&fx.conn, fx.tenant, digest).unwrap();
    assert_eq!(meta.len, body.len() as u64);
    let mut out = Vec::new();
    assert_eq!(
        fx.objects
            .read(&fx.conn, fx.tenant, digest, &mut out)
            .unwrap(),
        body.len() as u64
    );
    assert_eq!(out, body);
    // The file lives under the tenant's own namespace.
    let path = fx
        .dir
        .path()
        .join("objects")
        .join(fx.tenant.to_string())
        .join(&digest.to_string()[..2])
        .join(digest.to_string());
    assert!(path.is_file());
}

#[test]
fn same_content_commits_once_and_is_scoped_per_tenant() {
    let mut fx = fixture();
    let body = b"shared bytes";
    let first = fx.put(fx.tenant, body);
    // Second commit of identical content is a no-op for the same tenant…
    let staged = fx
        .objects
        .stage(fx.tenant, &body[..], u64::MAX, Expect::default())
        .unwrap();
    let tx = fx.conn.transaction().unwrap();
    assert!(!fx.objects.commit(&tx, &staged).unwrap());
    tx.commit().unwrap();
    // …and a fresh object for another tenant.
    let second = fx.put(fx.other, body);
    assert_eq!(first, second, "content-addressed digest is the same");
    let count: i64 = fx
        .conn
        .query_row("SELECT COUNT(*) FROM objects", [], |r| r.get(0))
        .unwrap();
    assert_eq!(count, 2);
    // The other tenant's lookup is its own row; an uncommitted digest is absent.
    let missing = Digest::from_bytes([9; 32]);
    assert!(matches!(
        fx.objects.meta(&fx.conn, fx.tenant, missing),
        Err(Error::NotFound)
    ));
}

#[test]
fn declared_length_or_digest_mismatch_stages_nothing() {
    let fx = fixture();
    for expect in [
        Expect {
            len: Some(1),
            digest: None,
        },
        Expect {
            len: None,
            digest: Some(Digest::from_bytes([0; 32])),
        },
    ] {
        let before: i64 = fx
            .conn
            .query_row("SELECT COUNT(*) FROM objects", [], |r| r.get(0))
            .unwrap();
        assert!(matches!(
            fx.objects
                .stage(fx.tenant, &b"real body"[..], u64::MAX, expect),
            Err(Error::InvalidInput(_))
        ));
        let after: i64 = fx
            .conn
            .query_row("SELECT COUNT(*) FROM objects", [], |r| r.get(0))
            .unwrap();
        assert_eq!(before, after);
    }
    // Nothing lingers in tmp and nothing landed under objects/.
    assert_eq!(
        std::fs::read_dir(fx.dir.path().join("tmp"))
            .unwrap()
            .count(),
        0
    );
}

#[test]
fn oversized_staging_is_refused_and_swept() {
    let fx = fixture();
    let body = vec![7u8; 1024];
    assert!(matches!(
        fx.objects
            .stage(fx.tenant, &body[..], 512, Expect::default()),
        Err(Error::InvalidInput("object size"))
    ));
    assert_eq!(
        std::fs::read_dir(fx.dir.path().join("tmp"))
            .unwrap()
            .count(),
        0
    );
}

#[test]
fn commit_for_an_unknown_tenant_is_refused_by_the_reference() {
    let mut fx = fixture();
    let staged = fx
        .objects
        .stage(TenantId::new(), &b"x"[..], u64::MAX, Expect::default())
        .unwrap();
    let tx = fx.conn.transaction().unwrap();
    // The tenant foreign key is the guard: staging may have run, but no row
    // can be committed for a tenant that does not exist.
    assert!(matches!(
        fx.objects.commit(&tx, &staged),
        Err(Error::Sqlite(_))
    ));
    tx.rollback().unwrap();
}

#[test]
fn manifest_versions_are_monotonic_and_reference_only_committed_objects() {
    let mut fx = fixture();
    let a = fx.put(fx.tenant, b"first");
    let b = fx.put(fx.tenant, b"second payload");
    // Referencing an object the tenant has not committed is refused.
    let tx = fx.conn.transaction().unwrap();
    assert!(matches!(
        fx.objects.commit_manifest(
            &tx,
            fx.tenant,
            Kind::Artifact,
            "dist",
            &[entry("out/app", Digest::from_bytes([3; 32]), 5)],
        ),
        Err(Error::InvalidInput("uncommitted object"))
    ));
    tx.rollback().unwrap();
    let tx = fx.conn.transaction().unwrap();
    let v1 = fx
        .objects
        .commit_manifest(
            &tx,
            fx.tenant,
            Kind::Artifact,
            "dist",
            &[entry("out/app", a, 5)],
        )
        .unwrap();
    let v2 = fx
        .objects
        .commit_manifest(
            &tx,
            fx.tenant,
            Kind::Artifact,
            "dist",
            &[entry("out/app", a, 5), entry("out/lib.so", b, 14)],
        )
        .unwrap();
    tx.commit().unwrap();
    assert_eq!((v1, v2), (1, 2));
    let head = fx
        .objects
        .manifest(&fx.conn, fx.tenant, Kind::Artifact, "dist", None)
        .unwrap();
    assert_eq!(head.version, 2);
    assert_eq!(head.entries.len(), 2);
    assert_eq!(head.payload_len, 19);
    let older = fx
        .objects
        .manifest(&fx.conn, fx.tenant, Kind::Artifact, "dist", Some(1))
        .unwrap();
    assert_eq!(older.entries.len(), 1);
    // Another tenant sees no such manifest.
    assert!(matches!(
        fx.objects
            .manifest(&fx.conn, fx.other, Kind::Artifact, "dist", None),
        Err(Error::NotFound)
    ));
}

#[test]
fn manifest_entry_paths_cannot_escape() {
    let mut fx = fixture();
    let a = fx.put(fx.tenant, b"x");
    for bad in [
        "../up", "/abs", "a//b", "a/./b", "a/../b", "a\\b", "c:x", "",
    ] {
        let tx = fx.conn.transaction().unwrap();
        assert!(
            matches!(
                fx.objects.commit_manifest(
                    &tx,
                    fx.tenant,
                    Kind::Artifact,
                    "m",
                    &[entry(bad, a, 1)],
                ),
                Err(Error::InvalidInput("entry path"))
            ),
            "{bad:?} must be refused"
        );
        tx.rollback().unwrap();
    }
}

#[test]
fn manifests_and_objects_are_immutable() {
    let mut fx = fixture();
    let a = fx.put(fx.tenant, b"pinned");
    let tx = fx.conn.transaction().unwrap();
    fx.objects
        .commit_manifest(&tx, fx.tenant, Kind::Artifact, "m", &[entry("p", a, 6)])
        .unwrap();
    tx.commit().unwrap();
    for sql in [
        "UPDATE objects SET len = 0",
        "DELETE FROM objects",
        "UPDATE manifests SET version = 9",
        "DELETE FROM manifests",
    ] {
        assert!(fx.conn.execute_batch(sql).is_err(), "{sql} must fail");
    }
}

#[test]
fn recovery_sweeps_staging_and_reports_orphans_corrupt_and_missing() {
    let mut fx = fixture();
    let keep = fx.put(fx.tenant, b"committed");
    let gone = fx.put(fx.tenant, b"will be deleted");
    // A staged-but-never-committed file: the crash-between-rename-and-commit case.
    let orphan = fx
        .objects
        .stage(fx.tenant, &b"orphan"[..], u64::MAX, Expect::default())
        .unwrap();
    // A torn staged write left behind in tmp/.
    let tmp = fx.dir.path().join("tmp").join("leftover.part");
    std::fs::File::create(&tmp)
        .unwrap()
        .write_all(b"partial")
        .unwrap();
    // Corrupt one committed object on disk and delete another entirely.
    let hex = gone.to_string();
    let corrupt_path = fx
        .dir
        .path()
        .join("objects")
        .join(fx.tenant.to_string())
        .join(&hex[..2])
        .join(&hex);
    std::fs::write(&corrupt_path, b"short").unwrap();
    let missing = fx.put(fx.tenant, b"missing file");
    let hex = missing.to_string();
    std::fs::remove_file(
        fx.dir
            .path()
            .join("objects")
            .join(fx.tenant.to_string())
            .join(&hex[..2])
            .join(&hex),
    )
    .unwrap();
    let report = fx.objects.recover(&fx.conn).unwrap();
    assert_eq!(report.staged, 1);
    assert!(!tmp.exists());
    assert_eq!(
        report.orphans,
        vec![
            fx.dir
                .path()
                .join("objects")
                .join(fx.tenant.to_string())
                .join(&orphan.digest().to_string()[..2])
                .join(orphan.digest().to_string())
        ],
    );
    assert_eq!(report.corrupt, vec![corrupt_path]);
    assert_eq!(report.missing.len(), 1);
    // The healthy object still verifies.
    let mut out = Vec::new();
    fx.objects
        .read(&fx.conn, fx.tenant, keep, &mut out)
        .unwrap();
    assert_eq!(out, b"committed");
}

#[test]
fn verify_catches_content_rot_that_recovery_cannot_see() {
    let mut fx = fixture();
    let digest = fx.put(fx.tenant, b"original content");
    let hex = digest.to_string();
    let path = fx
        .dir
        .path()
        .join("objects")
        .join(fx.tenant.to_string())
        .join(&hex[..2])
        .join(&hex);
    // Same length, different bytes: recovery's length check passes, only the
    // rehash sees it.
    std::fs::write(&path, b"original contenX").unwrap();
    let report = fx.objects.recover(&fx.conn).unwrap();
    assert!(report.corrupt.is_empty());
    let corrupt = fx.objects.verify(&fx.conn).unwrap();
    assert_eq!(corrupt.len(), 1);
    assert_eq!(corrupt[0].digest, digest);
    // And a verified read refuses to serve it.
    let mut out = Vec::new();
    assert!(matches!(
        fx.objects.read(&fx.conn, fx.tenant, digest, &mut out),
        Err(Error::Corrupt("object content"))
    ));
}

#[test]
fn committed_objects_survive_reopen() {
    let mut fx = fixture();
    let digest = fx.put(fx.tenant, b"durable");
    let objects = Objects::open(fx.dir.path()).unwrap();
    let mut out = Vec::new();
    objects.read(&fx.conn, fx.tenant, digest, &mut out).unwrap();
    assert_eq!(out, b"durable");
}

#[test]
fn corrupt_manifest_file_is_detected_on_read() {
    let mut fx = fixture();
    let a = fx.put(fx.tenant, b"bytes");
    let tx = fx.conn.transaction().unwrap();
    fx.objects
        .commit_manifest(&tx, fx.tenant, Kind::Artifact, "m", &[entry("p", a, 5)])
        .unwrap();
    tx.commit().unwrap();
    // Flip the file on disk: the committed digest no longer matches.
    let hash = blake3::hash(b"m").to_hex().to_string();
    let path = fx
        .dir
        .path()
        .join("manifests")
        .join(fx.tenant.to_string())
        .join("0")
        .join(hash)
        .join("1");
    let mut bytes = std::fs::read(&path).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 0xFF;
    std::fs::write(&path, &bytes).unwrap();
    assert!(matches!(
        fx.objects
            .manifest(&fx.conn, fx.tenant, Kind::Artifact, "m", None),
        Err(Error::Corrupt("manifest content"))
    ));
    let _ = objects::MAX_MANIFEST_ENTRIES;
}
