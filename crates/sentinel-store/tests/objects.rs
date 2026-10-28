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
    let staged = fx
        .objects
        .stage(fx.tenant, &body[..], u64::MAX, Expect::default())
        .unwrap();
    let tx = fx.conn.transaction().unwrap();
    assert!(!fx.objects.commit(&tx, &staged).unwrap());
    tx.commit().unwrap();
    let second = fx.put(fx.other, body);
    assert_eq!(first, second, "content-addressed digest is the same");
    let count: i64 = fx
        .conn
        .query_row("SELECT COUNT(*) FROM objects", [], |r| r.get(0))
        .unwrap();
    assert_eq!(count, 2);
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
    // The tenant foreign key refuses the commit; staging may already have run.
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
    // Updates stay sealed, but reclamation deletes through its own guarded path.
    for sql in [
        "UPDATE objects SET len = 0",
        "UPDATE manifests SET version = 9",
        "UPDATE manifests SET digest = X'00'",
        "UPDATE manifests SET refs_indexed = 0",
    ] {
        assert!(fx.conn.execute_batch(sql).is_err(), "{sql} must fail");
    }
    fx.conn
        .execute_batch("UPDATE manifests SET refs_indexed = 1")
        .unwrap();
}

#[test]
fn recovery_sweeps_staging_and_reports_orphans_corrupt_and_missing() {
    let mut fx = fixture();
    let keep = fx.put(fx.tenant, b"committed");
    let gone = fx.put(fx.tenant, b"will be deleted");
    let orphan = fx
        .objects
        .stage(fx.tenant, &b"orphan"[..], u64::MAX, Expect::default())
        .unwrap();
    let tmp = fx.dir.path().join("tmp").join("leftover.part");
    std::fs::File::create(&tmp)
        .unwrap()
        .write_all(b"partial")
        .unwrap();
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
    let mut out = Vec::new();
    fx.objects
        .read(&fx.conn, fx.tenant, keep, &mut out)
        .unwrap();
    assert_eq!(out, b"committed");
}

#[test]
fn recover_verify_and_read_catch_same_length_content_rot() {
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
    std::fs::write(&path, b"original contenX").unwrap();
    let report = fx.objects.recover(&fx.conn).unwrap();
    assert_eq!(report.corrupt, vec![path]);
    let corrupt = fx.objects.verify(&fx.conn).unwrap();
    assert_eq!(corrupt.len(), 1);
    assert_eq!(corrupt[0].digest, digest);
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

impl Fixture {
    fn begin(
        &mut self,
        tenant: TenantId,
        len: u64,
        digest: Option<Digest>,
    ) -> sentinel_core::UploadId {
        let tx = self.conn.transaction().unwrap();
        let id = self
            .objects
            .begin_upload(&tx, tenant, len, digest, objects::MAX_UPLOAD_TTL_MS, NOW)
            .unwrap();
        tx.commit().unwrap();
        id
    }

    fn chunk(
        &mut self,
        tenant: TenantId,
        id: sentinel_core::UploadId,
        offset: u64,
        bytes: &[u8],
    ) -> Result<u64, Error> {
        let tx = self.conn.transaction().unwrap();
        let result = self.objects.put_chunk(&tx, tenant, id, offset, bytes, NOW);
        match result {
            Ok(received) => {
                tx.commit().unwrap();
                Ok(received)
            }
            Err(e) => {
                tx.rollback().unwrap();
                Err(e)
            }
        }
    }

    fn seal(&mut self, tenant: TenantId, id: sentinel_core::UploadId) -> Result<Digest, Error> {
        let tx = self.conn.transaction().unwrap();
        let result = self.objects.seal_upload(&tx, tenant, id, NOW);
        match result {
            Ok(digest) => {
                tx.commit().unwrap();
                Ok(digest)
            }
            Err(e) => {
                tx.rollback().unwrap();
                Err(e)
            }
        }
    }
}

#[test]
fn upload_chunks_seal_into_a_verified_object() {
    let mut fx = fixture();
    let body = b"resumable upload body".repeat(500);
    let declared = Digest::from_bytes(*blake3::hash(&body).as_bytes());
    let id = fx.begin(fx.tenant, body.len() as u64, Some(declared));
    assert_eq!(
        fx.chunk(fx.tenant, id, 4000, &body[4000..]).unwrap(),
        body.len() as u64 - 4000
    );
    let status = fx.objects.upload(&fx.conn, fx.tenant, id).unwrap();
    assert_eq!(status.received, body.len() as u64 - 4000);
    assert_eq!(status.ranges, vec![(4000, body.len() as u64)]);
    assert_eq!(
        fx.chunk(fx.tenant, id, 0, &body[..4000]).unwrap(),
        body.len() as u64
    );
    let digest = fx.seal(fx.tenant, id).unwrap();
    assert_eq!(digest, declared);
    assert!(!fx.dir.path().join("incoming").join(id.to_string()).exists());
    let mut out = Vec::new();
    fx.objects
        .read(&fx.conn, fx.tenant, digest, &mut out)
        .unwrap();
    assert_eq!(out, body);
}

#[test]
fn uploads_resume_after_the_store_reopens() {
    let mut fx = fixture();
    let id = fx.begin(fx.tenant, 8, None);
    assert_eq!(fx.chunk(fx.tenant, id, 0, b"abcd").unwrap(), 4);
    let objects = Objects::open(fx.dir.path()).unwrap();
    let status = objects.upload(&fx.conn, fx.tenant, id).unwrap();
    assert_eq!(status.state, objects::UploadState::Open);
    assert_eq!(status.received, 4);
    assert_eq!(status.ranges, vec![(0, 4)]);
    let tx = fx.conn.transaction().unwrap();
    objects
        .put_chunk(&tx, fx.tenant, id, 4, b"efgh", NOW)
        .unwrap();
    tx.commit().unwrap();
    let tx = fx.conn.transaction().unwrap();
    let digest = objects.seal_upload(&tx, fx.tenant, id, NOW).unwrap();
    tx.commit().unwrap();
    let mut out = Vec::new();
    objects.read(&fx.conn, fx.tenant, digest, &mut out).unwrap();
    assert_eq!(out, b"abcdefgh");
}

#[test]
fn resent_chunks_are_idempotent_and_ranges_merge() {
    let mut fx = fixture();
    let id = fx.begin(fx.tenant, 10, None);
    assert_eq!(fx.chunk(fx.tenant, id, 0, b"0123").unwrap(), 4);
    assert_eq!(fx.chunk(fx.tenant, id, 0, b"0123").unwrap(), 4);
    assert_eq!(fx.chunk(fx.tenant, id, 2, b"234567").unwrap(), 8);
    let status = fx.objects.upload(&fx.conn, fx.tenant, id).unwrap();
    assert_eq!(status.ranges, vec![(0, 8)]);
    assert!(matches!(
        fx.chunk(fx.tenant, id, 0, b""),
        Err(Error::InvalidInput(_))
    ));
}

#[test]
fn chunks_outside_the_declared_length_are_refused() {
    let mut fx = fixture();
    let id = fx.begin(fx.tenant, 4, None);
    assert!(matches!(
        fx.chunk(fx.tenant, id, 3, b"xx"),
        Err(Error::InvalidInput("chunk range"))
    ));
    assert!(matches!(
        fx.chunk(fx.tenant, id, u64::MAX - 1, b"xx"),
        Err(Error::InvalidInput("chunk range"))
    ));
    let status = fx.objects.upload(&fx.conn, fx.tenant, id).unwrap();
    assert_eq!(status.received, 0);
}

#[test]
fn seal_requires_tiled_ranges_and_the_declared_digest() {
    let mut fx = fixture();
    let id = fx.begin(fx.tenant, 8, None);
    fx.chunk(fx.tenant, id, 0, b"aaaa").unwrap();
    assert!(matches!(
        fx.seal(fx.tenant, id),
        Err(Error::InvalidInput("upload incomplete"))
    ));
    let wrong = fx.begin(
        fx.tenant,
        4,
        Some(Digest::from_bytes(*blake3::hash(b"good").as_bytes())),
    );
    fx.chunk(fx.tenant, wrong, 0, b"real").unwrap();
    assert!(matches!(
        fx.seal(fx.tenant, wrong),
        Err(Error::InvalidInput("upload digest"))
    ));
    let status = fx.objects.upload(&fx.conn, fx.tenant, wrong).unwrap();
    assert_eq!(status.state, objects::UploadState::Open);
    fx.chunk(fx.tenant, wrong, 0, b"good").unwrap();
    assert_eq!(
        fx.seal(fx.tenant, wrong).unwrap(),
        Digest::from_bytes(*blake3::hash(b"good").as_bytes())
    );
}

#[test]
fn sealing_twice_returns_the_same_digest_and_abort_is_final() {
    let mut fx = fixture();
    let id = fx.begin(fx.tenant, 4, None);
    fx.chunk(fx.tenant, id, 0, b"data").unwrap();
    let first = fx.seal(fx.tenant, id).unwrap();
    assert_eq!(fx.seal(fx.tenant, id).unwrap(), first);
    assert!(matches!(
        fx.chunk(fx.tenant, id, 0, b"data"),
        Err(Error::Conflict)
    ));
    let other = fx.begin(fx.tenant, 4, None);
    fx.chunk(fx.tenant, other, 0, b"zz").unwrap();
    let tx = fx.conn.transaction().unwrap();
    fx.objects.abort_upload(&tx, fx.tenant, other).unwrap();
    tx.commit().unwrap();
    assert!(
        !fx.dir
            .path()
            .join("incoming")
            .join(other.to_string())
            .exists()
    );
    assert!(matches!(fx.seal(fx.tenant, other), Err(Error::Conflict)));
    let tx = fx.conn.transaction().unwrap();
    assert!(matches!(
        fx.objects.abort_upload(&tx, fx.tenant, id),
        Err(Error::Conflict)
    ));
    tx.rollback().unwrap();
}

#[test]
fn uploads_do_not_cross_tenants() {
    let mut fx = fixture();
    let id = fx.begin(fx.tenant, 4, None);
    assert!(matches!(
        fx.objects.upload(&fx.conn, fx.other, id),
        Err(Error::NotFound)
    ));
    assert!(matches!(
        fx.chunk(fx.other, id, 0, b"data"),
        Err(Error::NotFound)
    ));
    assert!(matches!(fx.seal(fx.other, id), Err(Error::NotFound)));
    let tx = fx.conn.transaction().unwrap();
    assert!(matches!(
        fx.objects.abort_upload(&tx, fx.other, id),
        Err(Error::NotFound)
    ));
    tx.rollback().unwrap();
}

#[test]
fn expired_uploads_are_swept_and_cannot_be_resumed() {
    let mut fx = fixture();
    let tx = fx.conn.transaction().unwrap();
    let id = fx
        .objects
        .begin_upload(&tx, fx.tenant, 4, None, 100, NOW)
        .unwrap();
    let keep = fx
        .objects
        .begin_upload(&tx, fx.tenant, 4, None, objects::MAX_UPLOAD_TTL_MS, NOW)
        .unwrap();
    tx.commit().unwrap();
    fx.chunk(fx.tenant, id, 0, b"ab").unwrap();
    let later = UnixMillis(NOW.0 + 200);
    let tx = fx.conn.transaction().unwrap();
    assert_eq!(fx.objects.sweep_uploads(&tx, later).unwrap(), 1);
    tx.commit().unwrap();
    assert!(!fx.dir.path().join("incoming").join(id.to_string()).exists());
    assert!(
        fx.dir
            .path()
            .join("incoming")
            .join(keep.to_string())
            .exists()
    );
    let tx = fx.conn.transaction().unwrap();
    assert!(matches!(
        fx.objects.put_chunk(&tx, fx.tenant, id, 2, b"cd", later),
        Err(Error::Conflict)
    ));
    tx.rollback().unwrap();
    let tx = fx.conn.transaction().unwrap();
    let stale = fx
        .objects
        .begin_upload(&tx, fx.tenant, 4, None, 50, NOW)
        .unwrap();
    tx.commit().unwrap();
    let tx = fx.conn.transaction().unwrap();
    assert!(matches!(
        fx.objects.put_chunk(&tx, fx.tenant, stale, 0, b"zz", later),
        Err(Error::InvalidInput("upload expired"))
    ));
    tx.rollback().unwrap();
}

#[test]
fn readers_are_counted_and_released_on_drop() {
    let mut fx = fixture();
    let digest = fx.put(fx.tenant, b"reader payload");
    let (reader, len) = fx.objects.open_read(&fx.conn, fx.tenant, digest).unwrap();
    assert_eq!(len, 14);
    assert!(fx.objects.reader_active(fx.tenant, digest));
    let (reader2, _) = fx.objects.open_read(&fx.conn, fx.tenant, digest).unwrap();
    assert!(fx.objects.reader_active(fx.tenant, digest));
    drop(reader);
    assert!(fx.objects.reader_active(fx.tenant, digest));
    drop(reader2);
    assert!(!fx.objects.reader_active(fx.tenant, digest));
    assert!(matches!(
        fx.objects
            .open_read(&fx.conn, fx.tenant, Digest::from_bytes([7; 32])),
        Err(Error::NotFound)
    ));
    assert!(matches!(
        fx.objects.open_read(&fx.conn, fx.other, digest),
        Err(Error::NotFound)
    ));
}

#[test]
fn recovery_keeps_open_uploads_and_removes_dead_staging() {
    let mut fx = fixture();
    let id = fx.begin(fx.tenant, 8, None);
    fx.chunk(fx.tenant, id, 0, b"live").unwrap();
    let orphan = fx.dir.path().join("incoming").join("upl_deadbeef");
    std::fs::write(&orphan, b"nobody").unwrap();
    let dead = fx.begin(fx.tenant, 4, None);
    let tx = fx.conn.transaction().unwrap();
    fx.objects.abort_upload(&tx, fx.tenant, dead).unwrap();
    tx.commit().unwrap();
    std::fs::write(
        fx.dir.path().join("incoming").join(dead.to_string()),
        b"left",
    )
    .unwrap();
    let report = fx.objects.recover(&fx.conn).unwrap();
    assert!(fx.dir.path().join("incoming").join(id.to_string()).exists());
    assert!(!orphan.exists());
    assert!(
        !fx.dir
            .path()
            .join("incoming")
            .join(dead.to_string())
            .exists()
    );
    assert_eq!(report.staged, 2);
}

#[test]
fn materialize_writes_verified_entries() {
    let mut fx = fixture();
    let a = fx.put(fx.tenant, b"file one");
    let b = fx.put(fx.tenant, b"file two is longer");
    let tx = fx.conn.transaction().unwrap();
    fx.objects
        .commit_manifest(
            &tx,
            fx.tenant,
            Kind::Artifact,
            "dist",
            &[entry("out/a.txt", a, 8), entry("out/deep/b.txt", b, 18)],
        )
        .unwrap();
    tx.commit().unwrap();
    let dest = fx.dir.path().join("extract");
    assert_eq!(
        fx.objects
            .materialize(&fx.conn, fx.tenant, Kind::Artifact, "dist", None, &dest)
            .unwrap(),
        26
    );
    assert_eq!(std::fs::read(dest.join("out/a.txt")).unwrap(), b"file one");
    assert_eq!(
        std::fs::read(dest.join("out/deep/b.txt")).unwrap(),
        b"file two is longer"
    );
}

#[test]
fn a_manifest_that_could_not_be_extracted_is_refused_at_commit() {
    let mut fx = fixture();
    let a = fx.put(fx.tenant, b"payload");
    for entries in [
        vec![entry("out/a", a, 7), entry("out/a", a, 7)],
        vec![entry("out", a, 7), entry("out/a", a, 7)],
        vec![entry("out/a", a, 7), entry("out", a, 7)],
    ] {
        let tx = fx.conn.transaction().unwrap();
        assert!(matches!(
            fx.objects
                .commit_manifest(&tx, fx.tenant, Kind::Artifact, "dup", &entries),
            Err(Error::InvalidInput(_))
        ));
        drop(tx);
    }
    let tx = fx.conn.transaction().unwrap();
    fx.objects
        .commit_manifest(
            &tx,
            fx.tenant,
            Kind::Artifact,
            "ok",
            &[
                entry("out/a", a, 7),
                entry("out/ab", a, 7),
                entry("o", a, 7),
            ],
        )
        .unwrap();
}

#[cfg(unix)]
#[test]
fn materialize_never_restores_setuid_setgid_or_sticky() {
    use std::os::unix::fs::PermissionsExt;
    let mut fx = fixture();
    let a = fx.put(fx.tenant, b"payload");
    let tx = fx.conn.transaction().unwrap();
    let mut special = entry("bin/tool", a, 7);
    special.mode = 0o7755;
    fx.objects
        .commit_manifest(&tx, fx.tenant, Kind::Artifact, "m", &[special])
        .unwrap();
    tx.commit().unwrap();
    let dest = fx.dir.path().join("extract");
    fx.objects
        .materialize(&fx.conn, fx.tenant, Kind::Artifact, "m", None, &dest)
        .unwrap();
    let mode = std::fs::metadata(dest.join("bin/tool"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o7777, 0o755);
}

#[cfg(unix)]
#[test]
fn materialize_refuses_symlinked_ancestors() {
    let mut fx = fixture();
    let a = fx.put(fx.tenant, b"payload");
    let tx = fx.conn.transaction().unwrap();
    fx.objects
        .commit_manifest(&tx, fx.tenant, Kind::Artifact, "m", &[entry("sub/x", a, 7)])
        .unwrap();
    tx.commit().unwrap();
    let dest = fx.dir.path().join("dest");
    let outside = fx.dir.path().join("outside");
    std::fs::create_dir_all(&dest).unwrap();
    std::fs::create_dir_all(&outside).unwrap();
    std::os::unix::fs::symlink(&outside, dest.join("sub")).unwrap();
    assert!(matches!(
        fx.objects
            .materialize(&fx.conn, fx.tenant, Kind::Artifact, "m", None, &dest),
        Err(Error::InvalidInput("materialize path"))
    ));
    assert!(!outside.join("x").exists());
}

#[cfg(unix)]
fn commit_entries(fx: &mut Fixture, name: &str, paths: &[&str]) {
    let a = fx.put(fx.tenant, b"payload");
    let entries: Vec<Entry> = paths.iter().map(|p| entry(p, a, 7)).collect();
    let tx = fx.conn.transaction().unwrap();
    fx.objects
        .commit_manifest(&tx, fx.tenant, Kind::Artifact, name, &entries)
        .unwrap();
    tx.commit().unwrap();
}

/// A directory swapped for a symlink after the walk opened it cannot redirect the write: the file is created
/// through the open descriptor, which names the original directory wherever the path now leads.
#[cfg(unix)]
#[test]
fn a_directory_swapped_for_a_symlink_during_extraction_cannot_redirect_a_write() {
    let mut fx = fixture();
    commit_entries(&mut fx, "m", &["sub/x", "sub/y", "other/z"]);
    let dest = fx.dir.path().join("dest");
    let outside = fx.dir.path().join("outside");
    std::fs::create_dir_all(&outside).unwrap();
    let written = fx
        .objects
        .materialize_with(
            &fx.conn,
            fx.tenant,
            Kind::Artifact,
            "m",
            None,
            &dest,
            |index| {
                if index == 0 {
                    std::fs::rename(dest.join("sub"), dest.join("sub.moved")).unwrap();
                    std::os::unix::fs::symlink(&outside, dest.join("sub")).unwrap();
                }
            },
        )
        .unwrap();
    assert_eq!(written, 21);
    assert_eq!(std::fs::read_dir(&outside).unwrap().count(), 0);
    // The walk keeps the directory it opened for the entries that follow it.
    assert_eq!(std::fs::read(dest.join("sub.moved/x")).unwrap(), b"payload");
    assert_eq!(std::fs::read(dest.join("sub.moved/y")).unwrap(), b"payload");
    assert_eq!(std::fs::read(dest.join("other/z")).unwrap(), b"payload");
}

/// The destination itself is resolved once: replacing it by a symlink mid-extract leaves every write in the
/// directory that was opened.
#[cfg(unix)]
#[test]
fn a_destination_swapped_for_a_symlink_during_extraction_cannot_redirect_a_write() {
    let mut fx = fixture();
    commit_entries(&mut fx, "m", &["a", "deep/b"]);
    let dest = fx.dir.path().join("dest");
    let moved = fx.dir.path().join("dest.moved");
    let outside = fx.dir.path().join("outside");
    std::fs::create_dir_all(&outside).unwrap();
    fx.objects
        .materialize_with(
            &fx.conn,
            fx.tenant,
            Kind::Artifact,
            "m",
            None,
            &dest,
            |index| {
                if index == 0 {
                    std::fs::rename(&dest, &moved).unwrap();
                    std::os::unix::fs::symlink(&outside, &dest).unwrap();
                }
            },
        )
        .unwrap();
    assert_eq!(std::fs::read_dir(&outside).unwrap().count(), 0);
    assert_eq!(std::fs::read(moved.join("a")).unwrap(), b"payload");
    assert_eq!(std::fs::read(moved.join("deep/b")).unwrap(), b"payload");
}

/// A symlink planted at the file's own name is not followed (`O_EXCL` fails on it) and a directory component
/// that is a regular file is refused like a symlink.
#[cfg(unix)]
#[test]
fn a_symlink_at_the_target_or_a_file_in_the_way_is_refused() {
    let mut fx = fixture();
    commit_entries(&mut fx, "m", &["sub/x"]);
    let dest = fx.dir.path().join("dest");
    let outside = fx.dir.path().join("outside");
    std::fs::create_dir_all(dest.join("sub")).unwrap();
    std::fs::create_dir_all(&outside).unwrap();
    std::os::unix::fs::symlink(outside.join("x"), dest.join("sub/x")).unwrap();
    assert!(matches!(
        fx.objects
            .materialize(&fx.conn, fx.tenant, Kind::Artifact, "m", None, &dest),
        Err(Error::InvalidInput("materialize target"))
    ));
    assert!(!outside.join("x").exists());

    let blocked = fx.dir.path().join("blocked");
    std::fs::create_dir_all(&blocked).unwrap();
    std::fs::write(blocked.join("sub"), b"in the way").unwrap();
    assert!(matches!(
        fx.objects
            .materialize(&fx.conn, fx.tenant, Kind::Artifact, "m", None, &blocked),
        Err(Error::InvalidInput("materialize path"))
    ));
}

/// Directories planted while the extract runs never lead out: whatever the interleaving, nothing lands outside.
#[cfg(unix)]
#[test]
fn a_racing_swapper_never_makes_the_extract_write_outside() {
    use std::sync::atomic::{AtomicBool, Ordering};

    const DIRS: usize = 64;
    let mut fx = fixture();
    let paths: Vec<String> = (0..DIRS).map(|i| format!("d{i}/f")).collect();
    let refs: Vec<&str> = paths.iter().map(String::as_str).collect();
    commit_entries(&mut fx, "m", &refs);
    let attempt = fx.dir.path().join("race");
    let outside = fx.dir.path().join("outside");
    std::fs::create_dir_all(&outside).unwrap();
    let stop = AtomicBool::new(false);
    std::thread::scope(|scope| {
        scope.spawn(|| {
            while !stop.load(Ordering::Relaxed) {
                for i in 0..DIRS {
                    let at = attempt.join(format!("d{i}"));
                    if std::fs::remove_dir(&at).is_ok() {
                        let _ = std::os::unix::fs::symlink(&outside, &at);
                    }
                }
            }
        });
        for _ in 0..20 {
            let _ = std::fs::remove_dir_all(&attempt);
            std::fs::create_dir_all(&attempt).unwrap();
            let result =
                fx.objects
                    .materialize(&fx.conn, fx.tenant, Kind::Artifact, "m", None, &attempt);
            // Any refusal is fine; a write through a swapped directory is not.
            assert!(matches!(
                result,
                Ok(_) | Err(Error::InvalidInput(_) | Error::Io(_))
            ));
        }
        stop.store(true, Ordering::Relaxed);
    });
    assert_eq!(std::fs::read_dir(&outside).unwrap().count(), 0);
}
