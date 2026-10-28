use std::{
    fs,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, SystemTime},
};

use rusqlite::Connection;
use sentinel_auth::secret::Secret;
use sentinel_core::{
    JobId, PoolId, RepoId, RunId, TenantId, UnixMillis, UserId, WorkerId,
    auth::{Namespace, Permissions as P, Principal},
};
use sentinel_pipeline::{PinnedSource, RunSpec, compile_str};
use sentinel_protocol::negotiate::{Arch, Capabilities, Negotiated, ProtocolVersion};
use sentinel_store::{
    Durability, Error, Store, artifacts,
    auth::{self, NamespaceKind, provisioning},
    dispatch::{self, Capacity},
    jobs,
    logs::LogStore,
    objects::{self, Digest, Entry, Expect, Kind, Objects},
    runs,
    space::{Admission, Watermarks},
    tenancy::{self, PoolKind},
    workers::{self, Presentation},
};

const NOW: UnixMillis = UnixMillis(1_000_000_000);
const TTL: Duration = Duration::from_millis(1_100);
const SHA: &str = "0123456789abcdef0123456789abcdef01234567";
const DIGEST: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

struct Fixture {
    objects: Objects,
    conn: Connection,
    dir: tempfile::TempDir,
    tenant: TenantId,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let objects = Objects::open(dir.path()).unwrap();
    let mut conn = Connection::open_in_memory().unwrap();
    conn.execute_batch("PRAGMA foreign_keys=ON").unwrap();
    sentinel_store::migrate(&mut conn).unwrap();
    let alice = Principal::new(UserId::new(), P::ALL, None, None);
    let tenant = TenantId::new();
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
    tx.commit().unwrap();
    Fixture {
        objects,
        conn,
        dir,
        tenant,
    }
}

impl Fixture {
    fn put(&mut self, body: &[u8]) -> Digest {
        let staged = self
            .objects
            .stage(self.tenant, body, u64::MAX, Expect::default())
            .unwrap();
        let digest = staged.digest();
        let tx = self.conn.transaction().unwrap();
        assert!(self.objects.commit(&tx, &staged).unwrap());
        tx.commit().unwrap();
        digest
    }

    fn usage(&self) -> u64 {
        self.objects.usage(&self.conn, self.tenant).unwrap()
    }
}

struct StoreFixture {
    _dir: tempfile::TempDir,
    store: Store,
    objects: Arc<Objects>,
    tenant: TenantId,
    repo: RepoId,
    pool: PoolId,
}

fn store_fixture() -> StoreFixture {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path().join("metadata.sqlite"), Durability::Normal).unwrap();
    let objects = Arc::new(Objects::open(dir.path().join("objects")).unwrap());
    let (root, tenant, repo, pool) = (UserId::new(), TenantId::new(), RepoId::new(), PoolId::new());
    store
        .writer()
        .write(move |tx| {
            provisioning::insert_human(tx, root, "Root", true, NOW)?;
            auth::create_namespace(
                tx,
                Principal::new(root, P::ALL, None, None),
                tenant,
                Namespace::parse("acme").unwrap(),
                NamespaceKind::Organization,
                NOW,
            )?;
            jobs::insert_repo(tx, tenant, repo, "app", NOW)?;
            tenancy::create_pool(
                tx,
                auth::Authority::HostLocal,
                pool,
                "builders",
                PoolKind::Dedicated(tenant),
                NOW,
            )
        })
        .unwrap();
    StoreFixture {
        _dir: dir,
        store,
        objects,
        tenant,
        repo,
        pool,
    }
}

impl StoreFixture {
    fn attempt(&self, job: JobId) -> sentinel_core::AttemptId {
        let (worker, pool) = (WorkerId::new(), self.pool);
        self.store
            .writer()
            .write(move |tx| {
                let issued =
                    workers::issue_enrollment(tx, auth::Authority::HostLocal, pool, 60_000, NOW)?;
                let mut text = String::new();
                issued.secret.expose(&mut text);
                workers::enroll(
                    tx,
                    &Secret::parse(&text).unwrap(),
                    Presentation {
                        worker,
                        fingerprint: Secret::generate().digest(),
                        name: "w",
                        negotiated: Negotiated {
                            protocol: ProtocolVersion(4),
                            capabilities: Capabilities::REQUIRED,
                            arch: Arch::X86_64,
                        },
                    },
                    NOW,
                )?;
                dispatch::report_capacity(
                    tx,
                    worker,
                    Capacity {
                        cpu_millis: 4_000,
                        memory_bytes: 8 << 30,
                        disk_bytes: 0,
                    },
                )
            })
            .unwrap();
        let offer = self
            .store
            .writer()
            .write(move |tx| dispatch::place(tx, worker, pool, dispatch::DEFAULT_LEASE_MS, NOW))
            .unwrap()
            .expect("a queued job was placed");
        assert_eq!(offer.job, job);
        offer.attempt
    }

    fn run(&self) -> (RunId, JobId) {
        let (tenant, repo, run) = (self.tenant, self.repo, RunId::new());
        let spec = RunSpec::new(
            PinnedSource::new("https://github.com/o/r.git", SHA, Some("main")).unwrap(),
            compile_str(
                "schema: 1\non: [push]\njobs:\n  build:\n    image: alpine:3\n    steps: [{ id: s, run: 'true' }]\n",
            )
            .unwrap(),
        )
        .unwrap();
        let jobs = self
            .store
            .writer()
            .write(move |tx| {
                let ids = runs::create_run(tx, tenant, repo, run, &spec, NOW)?;
                for job in &ids {
                    runs::resolve_image(tx, tenant, *job, DIGEST, "linux/amd64")?;
                }
                Ok(ids)
            })
            .unwrap();
        (run, jobs[0])
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

fn probed(free: &Arc<AtomicU64>, marks: Watermarks) -> Admission {
    let probe = Arc::clone(free);
    Admission::with_probe(marks, move || Ok(probe.load(Ordering::Relaxed))).unwrap()
}

/// `Admission` caches probe results for a second; tests that change the
/// figure must let the cache lapse before the next gate consults it.
fn refresh() {
    std::thread::sleep(TTL);
}

fn age(path: &std::path::Path, by: Duration) {
    let file = fs::File::options().write(true).open(path).unwrap();
    file.set_modified(SystemTime::now() - by).unwrap();
}

fn find_manifest_file(root: &std::path::Path) -> std::path::PathBuf {
    let mut stack = vec![root.join("manifests")];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir).unwrap().flatten() {
            let path = entry.path();
            if entry.file_type().unwrap().is_dir() {
                stack.push(path);
            } else {
                return path;
            }
        }
    }
    panic!("no manifest file found");
}

#[test]
fn admission_hysteresis_closes_below_low_and_reopens_above_high() {
    let free = Arc::new(AtomicU64::new(10_000));
    let admission = probed(
        &free,
        Watermarks {
            reserve: 1_000,
            low: 2_000,
            high: 4_000,
            floor: 500,
        },
    );
    let tenant = TenantId::new();
    assert!(admission.admit(tenant, 100).is_ok());
    admission.release(tenant, 100);

    free.store(2_500, Ordering::Relaxed);
    refresh();
    assert!(matches!(
        admission.admit(tenant, 1),
        Err(Error::StorageFull)
    ));
    assert!(!admission.is_open());

    free.store(4_500, Ordering::Relaxed);
    refresh();
    assert!(matches!(
        admission.admit(tenant, 1),
        Err(Error::StorageFull)
    ));
    free.store(5_500, Ordering::Relaxed);
    refresh();
    assert!(admission.admit(tenant, 1).is_ok());
    admission.release(tenant, 1);
    free.store(4_500, Ordering::Relaxed);
    refresh();
    assert!(admission.admit(tenant, 1).is_ok());
}

#[test]
fn admission_holds_the_reserve_and_the_log_floor() {
    let free = Arc::new(AtomicU64::new(800));
    let admission = probed(
        &free,
        Watermarks {
            reserve: 1_000,
            low: 2_000,
            high: 4_000,
            floor: 500,
        },
    );
    let tenant = TenantId::new();
    assert!(matches!(
        admission.admit(tenant, 1),
        Err(Error::StorageFull)
    ));
    assert!(admission.headroom());
    free.store(400, Ordering::Relaxed);
    refresh();
    assert!(!admission.headroom());
}

#[test]
fn the_reserve_follows_the_metadata_database_in_both_directions() {
    let free = Arc::new(AtomicU64::new(10_000));
    let admission = probed(
        &free,
        Watermarks {
            reserve: 1_000,
            low: 2_000,
            high: 4_000,
            floor: 500,
        },
    );
    let tenant = TenantId::new();
    assert_eq!(admission.reserve(), 1_000);
    assert!(admission.admit(tenant, 1).is_ok());
    admission.release(tenant, 1);

    // Twice a 5,000-byte database needs 10,000: nothing discretionary is left.
    admission.set_metadata_bytes(5_000);
    assert_eq!(admission.reserve(), 10_000);
    assert!(matches!(
        admission.admit(tenant, 1),
        Err(Error::StorageFull)
    ));
    assert!(!admission.is_open());

    // A database under half the configured reserve changes nothing...
    admission.set_metadata_bytes(100);
    assert_eq!(admission.reserve(), 1_000);
    // ...and once the need falls, the 6,000 left are above the high watermark.
    assert!(admission.admit(tenant, 1).is_ok());
    admission.release(tenant, 1);

    // The log floor is the disk's own and does not move with the database.
    admission.set_metadata_bytes(5_000);
    assert!(admission.headroom());
}

#[test]
fn metadata_bytes_include_the_write_ahead_log() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("metadata.sqlite");
    let store = Store::open(&path, Durability::Normal).unwrap();
    store
        .writer()
        .write(|tx| {
            tx.execute("CREATE TABLE scratch(x BLOB)", [])?;
            for _ in 0..200 {
                tx.execute("INSERT INTO scratch VALUES (zeroblob(4096))", [])?;
            }
            Ok(())
        })
        .unwrap();
    let main = fs::metadata(&path).unwrap().len();
    let mut wal = path.clone().into_os_string();
    wal.push("-wal");
    let wal = fs::metadata(&wal).map_or(0, |m| m.len());
    assert!(
        wal > 0,
        "the committed rows are in the write-ahead log until a checkpoint"
    );
    assert!(store.metadata_bytes() >= main + wal);
}

#[test]
fn inflight_charges_serialize_writers_and_release_exactly() {
    let free = Arc::new(AtomicU64::new(10_000));
    let admission = probed(
        &free,
        Watermarks {
            reserve: 1_000,
            low: 2_000,
            high: 4_000,
            floor: 500,
        },
    );
    let (a, b) = (TenantId::new(), TenantId::new());
    admission.admit(a, 6_000).unwrap();
    assert_eq!(admission.inflight(a), 6_000);
    assert_eq!(admission.total_inflight(), 6_000);
    assert!(matches!(admission.admit(b, 5_000), Err(Error::StorageFull)));
    admission.admit(b, 2_500).unwrap();
    assert!(matches!(admission.admit(a, 1), Err(Error::StorageFull)));
    admission.release(a, 6_000);
    assert_eq!(admission.total_inflight(), 2_500);
    admission.admit(a, 100).unwrap();
}

#[test]
fn upload_charges_track_deltas_and_release_partially_or_wholly() {
    let free = Arc::new(AtomicU64::new(10_000));
    let admission = probed(
        &free,
        Watermarks {
            reserve: 1_000,
            low: 2_000,
            high: 4_000,
            floor: 500,
        },
    );
    let upload = sentinel_core::UploadId::new();
    admission.admit_untracked(upload, 3_000).unwrap();
    admission.admit_untracked(upload, 2_000).unwrap();
    assert_eq!(admission.total_inflight(), 5_000);
    admission.release_upload_delta(upload, 2_000);
    assert_eq!(admission.total_inflight(), 3_000);
    admission.release_upload(upload);
    assert_eq!(admission.total_inflight(), 0);
    admission.release_upload(upload);
    admission.release_upload_delta(upload, 1);
}

#[test]
fn a_failed_probe_keeps_the_last_answer() {
    let good = Arc::new(AtomicU64::new(10_000));
    let probe = Arc::clone(&good);
    let admission = Admission::with_probe(
        Watermarks {
            reserve: 1_000,
            low: 2_000,
            high: 4_000,
            floor: 500,
        },
        move || {
            let v = probe.load(Ordering::Relaxed);
            if v == u64::MAX {
                Err(Error::InvalidInput("probe"))
            } else {
                Ok(v)
            }
        },
    )
    .unwrap();
    let tenant = TenantId::new();
    admission.admit(tenant, 100).unwrap();
    good.store(u64::MAX, Ordering::Relaxed);
    refresh();
    assert_eq!(admission.free(), 10_000);
    admission.release(tenant, 100);
}

#[test]
fn tenant_usage_tracks_objects_uploads_and_reclaims() {
    let mut fx = fixture();
    let digest = fx.put(b"committed payload");
    assert_eq!(fx.usage(), 17);

    let now = UnixMillis::now();
    let tx = fx.conn.transaction().unwrap();
    let id = fx
        .objects
        .begin_upload(&tx, fx.tenant, 100, None, 60_000, now)
        .unwrap();
    tx.commit().unwrap();
    assert_eq!(fx.usage(), 117);

    let body = vec![b'x'; 100];
    let tx = fx.conn.transaction().unwrap();
    fx.objects
        .put_chunk(&tx, fx.tenant, id, 0, &body, now)
        .unwrap();
    tx.commit().unwrap();
    assert_eq!(fx.usage(), 117);

    let tx = fx.conn.transaction().unwrap();
    let sealed = fx.objects.seal_upload(&tx, fx.tenant, id, now).unwrap();
    tx.commit().unwrap();
    assert_eq!(fx.usage(), 117);
    fx.objects.meta(&fx.conn, fx.tenant, sealed).unwrap();

    let later = UnixMillis(UnixMillis::now().0 + objects::UNREFERENCED_GRACE_MS + 1);
    let tx = fx.conn.transaction().unwrap();
    let reclaimed = fx.objects.reclaim(&tx, later, 256).unwrap();
    tx.commit().unwrap();
    assert_eq!(reclaimed.objects, 2);
    assert_eq!(reclaimed.bytes, 117);
    assert_eq!(reclaimed.doomed.len(), 2);
    let tx = fx.conn.transaction().unwrap();
    assert_eq!(fx.objects.unlink(&tx, &reclaimed.doomed).unwrap(), 2);
    tx.commit().unwrap();
    assert_eq!(fx.usage(), 0);
    assert!(matches!(
        fx.objects.meta(&fx.conn, fx.tenant, digest),
        Err(Error::NotFound)
    ));
}

#[test]
fn quota_refuses_uploads_and_commits_beyond_the_budget() {
    let mut fx = fixture();
    let tx = fx.conn.transaction().unwrap();
    fx.objects.set_quota(&tx, fx.tenant, 150).unwrap();
    tx.commit().unwrap();
    assert_eq!(fx.objects.quota(&fx.conn, fx.tenant).unwrap(), 150);

    let now = UnixMillis::now();
    let tx = fx.conn.transaction().unwrap();
    assert!(matches!(
        fx.objects
            .begin_upload(&tx, fx.tenant, 200, None, 60_000, now),
        Err(Error::QuotaExceeded)
    ));
    tx.rollback().unwrap();

    let tx = fx.conn.transaction().unwrap();
    let id = fx
        .objects
        .begin_upload(&tx, fx.tenant, 100, None, 60_000, now)
        .unwrap();
    assert!(matches!(
        fx.objects
            .begin_upload(&tx, fx.tenant, 100, None, 60_000, now),
        Err(Error::QuotaExceeded)
    ));
    tx.commit().unwrap();
    assert_eq!(fx.usage(), 100);
    let tx = fx.conn.transaction().unwrap();
    fx.objects.abort_upload(&tx, fx.tenant, id).unwrap();
    tx.commit().unwrap();
    assert_eq!(fx.usage(), 0);

    fx.put(&[b'y'; 120]);
    assert_eq!(fx.usage(), 120);
    let free = Arc::new(AtomicU64::new(1 << 40));
    let admission = Arc::new(probed(
        &free,
        Watermarks {
            reserve: 1,
            low: 1,
            high: 1,
            floor: 1,
        },
    ));
    fx.objects.set_admission(Arc::clone(&admission));
    let staged = fx
        .objects
        .stage(
            fx.tenant,
            &b"quota-buster".repeat(10)[..],
            u64::MAX,
            Expect::default(),
        )
        .unwrap();
    assert_eq!(admission.inflight(fx.tenant), 120);
    let tx = fx.conn.transaction().unwrap();
    assert!(matches!(
        fx.objects.commit(&tx, &staged),
        Err(Error::QuotaExceeded)
    ));
    tx.rollback().unwrap();
    assert_eq!(fx.usage(), 120);
    drop(staged);
    assert_eq!(admission.total_inflight(), 0);
}

#[test]
fn a_dedup_commit_never_pays_the_quota_twice() {
    let mut fx = fixture();
    let body = b"shared".repeat(10);
    fx.put(&body);
    let tx = fx.conn.transaction().unwrap();
    fx.objects.set_quota(&tx, fx.tenant, 60).unwrap();
    tx.commit().unwrap();
    let staged = fx
        .objects
        .stage(fx.tenant, &body[..], u64::MAX, Expect::default())
        .unwrap();
    let tx = fx.conn.transaction().unwrap();
    assert!(!fx.objects.commit(&tx, &staged).unwrap());
    tx.commit().unwrap();
    assert_eq!(fx.usage(), 60);
}

#[test]
fn leases_pin_an_object_until_released_or_expired() {
    let mut fx = fixture();
    let digest = fx.put(b"leased");
    let later = UnixMillis(UnixMillis::now().0 + objects::UNREFERENCED_GRACE_MS + 1);

    let tx = fx.conn.transaction().unwrap();
    fx.objects
        .lease(
            &tx,
            fx.tenant,
            digest,
            "deployment",
            objects::UNREFERENCED_GRACE_MS + 3_600_000,
            UnixMillis::now(),
        )
        .unwrap();
    tx.commit().unwrap();
    let tx = fx.conn.transaction().unwrap();
    assert_eq!(fx.objects.reclaim(&tx, later, 256).unwrap().objects, 0);
    tx.commit().unwrap();

    let tx = fx.conn.transaction().unwrap();
    fx.objects
        .release_lease(&tx, fx.tenant, digest, "deployment")
        .unwrap();
    tx.commit().unwrap();
    let tx = fx.conn.transaction().unwrap();
    assert_eq!(fx.objects.reclaim(&tx, later, 256).unwrap().objects, 1);
    tx.rollback().unwrap();

    let now = UnixMillis::now();
    let tx = fx.conn.transaction().unwrap();
    fx.objects
        .lease(&tx, fx.tenant, digest, "short", 1_000, now)
        .unwrap();
    tx.commit().unwrap();
    let after = UnixMillis(now.0 + 2_000);
    let tx = fx.conn.transaction().unwrap();
    assert_eq!(fx.objects.sweep_leases(&tx, after).unwrap(), 1);
    assert_eq!(fx.objects.reclaim(&tx, later, 256).unwrap().objects, 1);
    tx.commit().unwrap();

    let tx = fx.conn.transaction().unwrap();
    assert!(
        fx.objects
            .lease(&tx, fx.tenant, Digest::from_bytes([7; 32]), "x", 1_000, now)
            .is_err()
    );
}

#[test]
fn an_active_reader_keeps_the_object_alive() {
    let mut fx = fixture();
    let digest = fx.put(b"streamed");
    let (reader, len) = fx.objects.open_read(&fx.conn, fx.tenant, digest).unwrap();
    assert_eq!(len, 8);
    let later = UnixMillis(UnixMillis::now().0 + objects::UNREFERENCED_GRACE_MS + 1);
    let tx = fx.conn.transaction().unwrap();
    assert_eq!(fx.objects.reclaim(&tx, later, 256).unwrap().objects, 0);
    tx.commit().unwrap();
    drop(reader);
    let tx = fx.conn.transaction().unwrap();
    let reclaimed = fx.objects.reclaim(&tx, later, 256).unwrap();
    tx.commit().unwrap();
    assert_eq!(reclaimed.objects, 1);
}

#[test]
fn an_unindexed_manifest_suspends_the_tenants_reclaim() {
    let mut fx = fixture();
    fx.put(b"suspended");
    fx.conn
        .execute(
            "INSERT INTO manifests(tenant_id, kind, name, version, digest, entries,
                 payload_len, created_ms, refs_indexed)
             VALUES (?1, 0, ?2, 1, ?3, 0, 0, ?4, 0)",
            rusqlite::params![
                fx.tenant.as_bytes().as_slice(),
                b"ghost".as_slice(),
                vec![0u8; 32],
                NOW.0,
            ],
        )
        .unwrap();
    let later = UnixMillis(UnixMillis::now().0 + objects::UNREFERENCED_GRACE_MS + 1);
    let tx = fx.conn.transaction().unwrap();
    assert_eq!(fx.objects.index_refs(&tx, 256).unwrap(), 0);
    assert_eq!(fx.objects.reclaim(&tx, later, 256).unwrap().objects, 0);
    tx.commit().unwrap();
    fx.conn
        .execute("DELETE FROM manifests WHERE refs_indexed = 0", [])
        .unwrap();
    let tx = fx.conn.transaction().unwrap();
    assert_eq!(fx.objects.reclaim(&tx, later, 256).unwrap().objects, 1);
    tx.commit().unwrap();
}

#[test]
fn index_refs_backfills_edges_and_retirement_releases_them() {
    let mut fx = fixture();
    let digest = fx.put(b"manifest body");
    let tx = fx.conn.transaction().unwrap();
    fx.objects
        .commit_manifest(
            &tx,
            fx.tenant,
            Kind::Artifact,
            "m",
            &[entry("f", digest, 13)],
        )
        .unwrap();
    tx.commit().unwrap();

    let v1 = find_manifest_file(fx.dir.path());
    let v2 = v1.with_file_name("2");
    fs::copy(&v1, &v2).unwrap();
    fx.conn
        .execute(
            "INSERT INTO manifests(tenant_id, kind, name, version, digest, entries,
                 payload_len, created_ms, refs_indexed)
             SELECT tenant_id, kind, name, 2, digest, entries, payload_len,
                    created_ms, 0 FROM manifests WHERE version = 1",
            [],
        )
        .unwrap();

    let later = UnixMillis(UnixMillis::now().0 + objects::UNREFERENCED_GRACE_MS + 1);
    let tx = fx.conn.transaction().unwrap();
    assert_eq!(fx.objects.reclaim(&tx, later, 256).unwrap().objects, 0);
    tx.commit().unwrap();

    let tx = fx.conn.transaction().unwrap();
    assert_eq!(fx.objects.index_refs(&tx, 256).unwrap(), 1);
    tx.commit().unwrap();
    let edges: i64 = fx
        .conn
        .query_row("SELECT COUNT(*) FROM manifest_refs", [], |r| r.get(0))
        .unwrap();
    assert_eq!(edges, 2);

    let tx = fx.conn.transaction().unwrap();
    assert_eq!(fx.objects.reclaim(&tx, later, 256).unwrap().objects, 0);
    for version in [1u64, 2] {
        let path = fx
            .objects
            .retire_manifest(&tx, fx.tenant, Kind::Artifact, "m", version)
            .unwrap()
            .unwrap();
        fs::remove_file(path.path()).unwrap();
    }
    let edges: i64 = tx
        .query_row("SELECT COUNT(*) FROM manifest_refs", [], |r| r.get(0))
        .unwrap();
    assert_eq!(edges, 0);
    assert_eq!(fx.objects.reclaim(&tx, later, 256).unwrap().objects, 1);
    tx.commit().unwrap();
}

#[test]
fn artifact_retention_retires_the_manifest_and_frees_its_objects() {
    let f = store_fixture();
    let (run, job) = f.run();
    let attempt = f.attempt(job);
    let (tenant, objects) = (f.tenant, Arc::clone(&f.objects));

    let staged = objects
        .stage(tenant, &b"artifact bytes"[..], u64::MAX, Expect::default())
        .unwrap();
    f.store
        .writer()
        .write(move |tx| {
            objects.commit(tx, &staged)?;
            let version = objects.commit_manifest(
                tx,
                tenant,
                Kind::Artifact,
                &artifacts::manifest_name(job, "report"),
                &[entry("r", staged.digest(), 14)],
            )?;
            artifacts::record(
                tx,
                tenant,
                run,
                job,
                attempt,
                "report",
                artifacts::State::Captured,
                Some(version),
                1,
                14,
                UnixMillis(NOW.0),
                NOW,
            )?;
            Ok(())
        })
        .unwrap();

    let objects = Arc::clone(&f.objects);
    let paths = f
        .store
        .writer()
        .write(move |tx| artifacts::sweep_expired(tx, &objects, UnixMillis::now(), 256))
        .unwrap();
    assert_eq!(paths.len(), 1);
    let objects = Arc::clone(&f.objects);
    assert_eq!(
        f.store
            .writer()
            .write(move |tx| objects.unlink(tx, &paths))
            .unwrap(),
        1
    );
    f.store
        .read(|c| {
            let artifacts: i64 = c.query_row("SELECT COUNT(*) FROM artifacts", [], |r| r.get(0))?;
            let manifests: i64 = c.query_row("SELECT COUNT(*) FROM manifests", [], |r| r.get(0))?;
            Ok((artifacts, manifests))
        })
        .map(|(a, m)| {
            assert_eq!((a, m), (0, 0));
        })
        .unwrap();

    let later = UnixMillis(UnixMillis::now().0 + objects::UNREFERENCED_GRACE_MS + 1);
    let objects = Arc::clone(&f.objects);
    let reclaimed = f
        .store
        .writer()
        .write(move |tx| objects.reclaim(tx, later, 256))
        .unwrap();
    assert_eq!(reclaimed.objects, 1);
}

#[test]
fn orphan_sweep_removes_only_unowned_files_past_the_grace() {
    let mut fx = fixture();
    let digest = fx.put(b"owned");
    let tenant_dir = fx.dir.path().join("objects").join(fx.tenant.to_string());
    let stray_dir = tenant_dir.join("zz");
    fs::create_dir_all(&stray_dir).unwrap();
    let grace = Duration::from_millis(objects::FILE_ORPHAN_GRACE_MS as u64 + 60_000);
    let old_stray = stray_dir.join("a".repeat(64));
    fs::write(&old_stray, b"lost").unwrap();
    age(&old_stray, grace);
    let fresh_stray = stray_dir.join("b".repeat(64));
    fs::write(&fresh_stray, b"young").unwrap();
    let loose = tenant_dir.join("stray-file");
    fs::write(&loose, b"loose").unwrap();
    age(&loose, grace);

    assert_eq!(fx.objects.sweep_orphans(&mut fx.conn, 256).unwrap(), 2);
    assert!(!old_stray.exists());
    assert!(!loose.exists());
    assert!(fresh_stray.exists());
    let committed = tenant_dir
        .join(&digest.to_string()[..2])
        .join(digest.to_string());
    assert!(committed.is_file());
}

#[test]
fn logs_refuse_frames_below_the_floor_but_keep_the_record_honest() {
    let temp = tempfile::tempdir().unwrap();
    let logs = LogStore::open(temp.path().join("logs")).unwrap();
    let free = Arc::new(AtomicU64::new(100));
    logs.set_admission(Arc::new(probed(
        &free,
        Watermarks {
            reserve: 1_000,
            low: 2_000,
            high: 4_000,
            floor: 500,
        },
    )));
    let (run, job, attempt) = (RunId::new(), JobId::new(), sentinel_core::AttemptId::new());
    let frame = sentinel_protocol::logs::Frame {
        seq: 1,
        step: 0,
        stream: sentinel_protocol::logs::Stream::Stdout,
        bytes: b"line\n".to_vec(),
    };
    assert!(matches!(
        logs.append(run, job, attempt, &frame),
        Err(Error::StorageFull)
    ));
    free.store(1 << 40, Ordering::Relaxed);
    refresh();
    logs.append(run, job, attempt, &frame).unwrap();
    logs.finish(run, job, attempt, 1, &[]).unwrap();
    let tail = logs.tail(run, job, attempt, 0, 100, None).unwrap();
    assert_eq!(tail.frames.len(), 1);
    assert!(tail.complete);
    assert!(tail.gaps.is_empty());
}

#[test]
fn log_sweep_removes_released_logs_and_spares_open_writers() {
    let temp = tempfile::tempdir().unwrap();
    let logs = LogStore::open(temp.path().join("logs")).unwrap();
    let (run, job) = (RunId::new(), JobId::new());
    let done = sentinel_core::AttemptId::new();
    let held = sentinel_core::AttemptId::new();
    let frame = sentinel_protocol::logs::Frame {
        seq: 1,
        step: 0,
        stream: sentinel_protocol::logs::Stream::Stdout,
        bytes: b"x\n".to_vec(),
    };
    logs.append(run, job, done, &frame).unwrap();
    logs.finish(run, job, done, 1, &[]).unwrap();
    logs.append(run, job, held, &frame).unwrap();
    let legacy_id = sentinel_core::AttemptId::new();
    let legacy = temp.path().join("logs").join(format!("{legacy_id}.log"));
    fs::write(&legacy, b"old flat log").unwrap();

    let swept = logs.sweep_dirs(256, |_| true).unwrap();
    assert_eq!(swept, 2);
    assert!(!logs.attempt_dir(run, job, done).exists());
    assert!(!legacy.exists());
    assert!(logs.attempt_dir(run, job, held).exists());
}

#[test]
fn expired_uploads_release_their_disk_charge() {
    let mut fx = fixture();
    let free = Arc::new(AtomicU64::new(1 << 40));
    let admission = Arc::new(probed(
        &free,
        Watermarks {
            reserve: 1,
            low: 1,
            high: 1,
            floor: 1,
        },
    ));
    fx.objects.set_admission(Arc::clone(&admission));
    let now = UnixMillis::now();
    let tx = fx.conn.transaction().unwrap();
    let id = fx
        .objects
        .begin_upload(&tx, fx.tenant, 10, None, 1_000, now)
        .unwrap();
    fx.objects
        .put_chunk(&tx, fx.tenant, id, 0, b"0123456789", now)
        .unwrap();
    tx.commit().unwrap();
    assert_eq!(admission.total_inflight(), 10);

    let tx = fx.conn.transaction().unwrap();
    assert_eq!(
        fx.objects
            .sweep_uploads(&tx, UnixMillis(now.0 + 2_000))
            .unwrap(),
        1
    );
    tx.commit().unwrap();
    assert_eq!(admission.total_inflight(), 0);
    assert!(!fx.dir.path().join("incoming").join(id.to_string()).exists());
    assert_eq!(fx.usage(), 0);
}

#[test]
fn a_failed_chunk_returns_its_charge_to_admission() {
    let mut fx = fixture();
    let free = Arc::new(AtomicU64::new(1 << 40));
    let admission = Arc::new(probed(
        &free,
        Watermarks {
            reserve: 1,
            low: 1,
            high: 1,
            floor: 1,
        },
    ));
    fx.objects.set_admission(Arc::clone(&admission));
    let now = UnixMillis::now();
    let tx = fx.conn.transaction().unwrap();
    let id = fx
        .objects
        .begin_upload(&tx, fx.tenant, 10, None, 60_000, now)
        .unwrap();
    tx.commit().unwrap();
    fs::remove_file(fx.dir.path().join("incoming").join(id.to_string())).unwrap();
    let tx = fx.conn.transaction().unwrap();
    assert!(
        fx.objects
            .put_chunk(&tx, fx.tenant, id, 0, b"0123456789", now)
            .is_err()
    );
    tx.rollback().unwrap();
    assert_eq!(admission.total_inflight(), 0);
}

#[test]
fn a_seal_recovers_the_renamed_but_uncommitted_upload() {
    let mut fx = fixture();
    let body = b"recovered seal";
    let digest = Digest::from_bytes(*blake3::hash(body).as_bytes());
    let now = UnixMillis::now();
    let tx = fx.conn.transaction().unwrap();
    let id = fx
        .objects
        .begin_upload(&tx, fx.tenant, body.len() as u64, Some(digest), 60_000, now)
        .unwrap();
    fx.objects
        .put_chunk(&tx, fx.tenant, id, 0, body, now)
        .unwrap();
    tx.commit().unwrap();

    let hex = digest.to_string();
    let dest_dir = fx
        .dir
        .path()
        .join("objects")
        .join(fx.tenant.to_string())
        .join(&hex[..2]);
    fs::create_dir_all(&dest_dir).unwrap();
    fs::rename(
        fx.dir.path().join("incoming").join(id.to_string()),
        dest_dir.join(&hex),
    )
    .unwrap();

    let tx = fx.conn.transaction().unwrap();
    let sealed = fx.objects.seal_upload(&tx, fx.tenant, id, now).unwrap();
    tx.commit().unwrap();
    assert_eq!(sealed, digest);
    assert_eq!(fx.usage(), body.len() as u64);
    let mut out = Vec::new();
    fx.objects
        .read(&fx.conn, fx.tenant, digest, &mut out)
        .unwrap();
    assert_eq!(out, body);
}

#[test]
fn migration_27_upgrades_a_populated_database() {
    let dir = tempfile::tempdir().unwrap();
    let mut conn = Connection::open(dir.path().join("m.sqlite")).unwrap();
    conn.execute_batch("PRAGMA foreign_keys=ON").unwrap();
    conn.execute_batch(
        "CREATE TABLE schema_migrations(
            version INTEGER PRIMARY KEY, applied_ms INTEGER NOT NULL)",
    )
    .unwrap();
    for &(version, sql) in sentinel_store::schema::MIGRATIONS {
        if version > 26 {
            break;
        }
        let tx = conn.transaction().unwrap();
        tx.execute_batch(sql).unwrap();
        tx.execute(
            "INSERT INTO schema_migrations(version, applied_ms) VALUES (?1, 0)",
            [version],
        )
        .unwrap();
        tx.commit().unwrap();
    }

    let tenant = TenantId::new();
    let tid = tenant.as_bytes().to_vec();
    let object = [9u8; 32];
    let open_upload = sentinel_core::UploadId::new().as_bytes().to_vec();
    let done_upload = sentinel_core::UploadId::new().as_bytes().to_vec();
    let tx = conn.transaction().unwrap();
    tx.execute(
        "INSERT INTO tenants(id, slug, created_ms) VALUES (?1, 'acme', 0)",
        [&tid],
    )
    .unwrap();
    tx.execute(
        "INSERT INTO objects(tenant_id, digest, len, created_ms)
         VALUES (?1, ?2, 40, 0)",
        rusqlite::params![tid, object.as_slice()],
    )
    .unwrap();
    for (id, declared, state) in [
        (open_upload.as_slice(), 70i64, 0i64),
        (done_upload.as_slice(), 999, 1),
    ] {
        tx.execute(
            "INSERT INTO uploads(id, tenant_id, declared_len, state_code, ranges,
                 received, expires_ms, created_ms)
             VALUES (?1, ?2, ?3, ?4, X'', 0, 0, 0)",
            rusqlite::params![id, tid, declared, state],
        )
        .unwrap();
    }
    tx.execute(
        "INSERT INTO manifests(tenant_id, kind, name, version, digest, entries,
             payload_len, created_ms)
         VALUES (?1, 0, 'm', 1, ?2, 1, 40, 0)",
        rusqlite::params![tid, object.as_slice()],
    )
    .unwrap();
    assert!(
        tx.execute("DELETE FROM objects WHERE tenant_id = ?1", [&tid])
            .is_err()
    );
    tx.commit().unwrap();

    sentinel_store::migrate(&mut conn).unwrap();

    let owed: i64 = conn
        .query_row(
            "SELECT bytes FROM tenant_usage WHERE tenant_id = ?1",
            [&tid],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(owed, 110);
    let flagged: i64 = conn
        .query_row(
            "SELECT refs_indexed FROM manifests WHERE tenant_id = ?1",
            [&tid],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(flagged, 0);
    conn.execute(
        "UPDATE manifests SET refs_indexed = 1 WHERE tenant_id = ?1",
        [&tid],
    )
    .unwrap();
    assert!(
        conn.execute(
            "UPDATE manifests SET payload_len = 0 WHERE tenant_id = ?1",
            [&tid]
        )
        .is_err()
    );
    assert!(
        conn.execute("UPDATE objects SET len = 0 WHERE tenant_id = ?1", [&tid])
            .is_err()
    );
    conn.execute(
        "INSERT INTO object_leases(tenant_id, digest, holder, until_ms,
             created_ms) VALUES (?1, ?2, 'h', 0, 0)",
        rusqlite::params![tid, object.as_slice()],
    )
    .unwrap();
    conn.execute("DELETE FROM objects WHERE tenant_id = ?1", [&tid])
        .unwrap();
    let leases: i64 = conn
        .query_row("SELECT COUNT(*) FROM object_leases", [], |r| r.get(0))
        .unwrap();
    assert_eq!(leases, 0);
    let owed: i64 = conn
        .query_row(
            "SELECT bytes FROM tenant_usage WHERE tenant_id = ?1",
            [&tid],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(owed, 70);
    conn.execute("DELETE FROM manifests WHERE tenant_id = ?1", [&tid])
        .unwrap();
}

#[test]
fn reclaim_candidates_come_from_the_unreferenced_index() {
    let mut fx = fixture();
    let referenced = fx.put(b"kept by a manifest");
    let loose = fx.put(b"referenced by nothing");
    let tx = fx.conn.transaction().unwrap();
    fx.objects
        .commit_manifest(
            &tx,
            fx.tenant,
            Kind::Artifact,
            "m",
            &[entry("a", referenced, 18)],
        )
        .unwrap();
    tx.commit().unwrap();
    let listed: Vec<Vec<u8>> = fx
        .conn
        .prepare("SELECT digest FROM object_unreferenced")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(listed, vec![loose.as_bytes().to_vec()]);
    let plan: Vec<String> = fx
        .conn
        .prepare(&format!(
            "EXPLAIN QUERY PLAN {}",
            objects::RECLAIM_CANDIDATES
        ))
        .unwrap()
        .query_map(rusqlite::params![0i64, 0i64, 1i64], |r| {
            r.get::<_, String>(3)
        })
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert!(
        plan.iter().all(|step| !step.starts_with("SCAN")),
        "reclaim walks a table: {plan:?}"
    );
    assert!(
        plan.iter()
            .any(|step| step.contains("object_unreferenced_age")),
        "{plan:?}"
    );
}

#[test]
fn a_large_seal_does_not_hold_the_writer() {
    let f = store_fixture();
    let (tenant, objects) = (f.tenant, Arc::clone(&f.objects));
    const LEN: u64 = 64 << 20;
    let id = {
        let objects = Arc::clone(&objects);
        f.store
            .writer()
            .write(move |tx| objects.begin_upload(tx, tenant, LEN, None, 60_000, UnixMillis::now()))
            .unwrap()
    };
    let chunk = vec![7u8; 8 << 20];
    for offset in (0..LEN).step_by(chunk.len()) {
        let now = UnixMillis::now();
        let written = f
            .store
            .read(|c| objects.write_chunk(c, tenant, id, offset, &chunk, now))
            .unwrap();
        let objects::Touch::Ready(written) = written else {
            panic!("expired")
        };
        let objects = Arc::clone(&objects);
        f.store
            .writer()
            .write(move |tx| objects.record_chunk(tx, written))
            .unwrap();
    }
    let store = Arc::new(f.store);
    let sealing = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let sealer = {
        let (store, objects, sealing) = (
            Arc::clone(&store),
            Arc::clone(&objects),
            Arc::clone(&sealing),
        );
        std::thread::spawn(move || {
            let started = std::time::Instant::now();
            let plan = store
                .read(|c| objects.prepare_seal(c, tenant, id, UnixMillis::now()))
                .unwrap();
            let hashed = started.elapsed();
            sealing.store(false, Ordering::Release);
            let objects::Touch::Ready(plan) = plan else {
                panic!("expired")
            };
            let digest = store
                .writer()
                .write(move |tx| objects.finish_seal(tx, plan))
                .unwrap();
            (digest, hashed)
        })
    };
    let mut rounds = 0u32;
    let mut slowest = Duration::ZERO;
    while sealing.load(Ordering::Acquire) {
        let at = std::time::Instant::now();
        store
            .writer()
            .write(|tx| {
                tx.execute_batch("SELECT 1")?;
                Ok(())
            })
            .unwrap();
        slowest = slowest.max(at.elapsed());
        rounds += 1;
    }
    let (digest, hashed) = sealer.join().unwrap();
    assert_eq!(
        digest,
        Digest::from_bytes(*blake3::hash(&vec![7u8; LEN as usize]).as_bytes())
    );
    assert!(
        rounds >= 2,
        "{rounds} writer round trips during a {hashed:?} seal"
    );
    assert!(
        slowest < hashed,
        "a writer round trip took {slowest:?} of a {hashed:?} seal"
    );
}

#[test]
fn an_upload_past_the_object_bound_is_refused_at_begin() {
    let mut fx = fixture();
    let tx = fx.conn.transaction().unwrap();
    assert!(matches!(
        fx.objects.begin_upload(
            &tx,
            fx.tenant,
            objects::MAX_UPLOAD_BYTES + 1,
            None,
            60_000,
            UnixMillis::now()
        ),
        Err(Error::InvalidInput("upload length"))
    ));
}

#[test]
fn admission_flapping_under_sustained_writes_leaks_nothing() {
    use std::sync::atomic::AtomicBool;
    let mut fx = fixture();
    let objects = Arc::new(Objects::open(fx.dir.path()).unwrap());
    let free = Arc::new(AtomicU64::new(1 << 30));
    let admission = Arc::new(probed(
        &free,
        Watermarks {
            reserve: 1 << 20,
            low: 64 << 20,
            high: 128 << 20,
            floor: 1 << 20,
        },
    ));
    objects.set_admission(Arc::clone(&admission));
    let stop = Arc::new(AtomicBool::new(false));
    let (send, receive) = std::sync::mpsc::channel();
    let refused = Arc::new(AtomicU64::new(0));
    let writers: Vec<_> = (0..8u64)
        .map(|w| {
            let (objects, stop, send, refused, tenant) = (
                Arc::clone(&objects),
                Arc::clone(&stop),
                send.clone(),
                Arc::clone(&refused),
                fx.tenant,
            );
            std::thread::spawn(move || {
                let mut n = 0u64;
                while !stop.load(Ordering::Relaxed) {
                    n += 1;
                    let body = format!("writer {w} object {n} ").repeat(1 + (n % 64) as usize);
                    match objects.stage(tenant, body.as_bytes(), u64::MAX, Expect::default()) {
                        Ok(staged) => {
                            if n.is_multiple_of(2) {
                                send.send((staged, body)).unwrap();
                            }
                        }
                        Err(Error::StorageFull) => {
                            refused.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(other) => panic!("unexpected: {other:?}"),
                    }
                    std::thread::sleep(Duration::from_millis(2));
                }
            })
        })
        .collect();
    drop(send);
    let swings = std::thread::spawn({
        let (free, stop) = (Arc::clone(&free), Arc::clone(&stop));
        move || {
            for step in 0..8 {
                let at = [1 << 30, 32 << 20, 96 << 20, 1 << 30][step % 4];
                free.store(at, Ordering::Relaxed);
                std::thread::sleep(TTL);
            }
            free.store(1 << 30, Ordering::Relaxed);
            std::thread::sleep(TTL);
            stop.store(true, Ordering::Relaxed);
        }
    });
    let mut committed = Vec::new();
    for (staged, body) in receive {
        let tx = fx.conn.transaction().unwrap();
        objects.commit(&tx, &staged).unwrap();
        tx.commit().unwrap();
        committed.push((staged.digest(), body));
        drop(staged);
    }
    swings.join().unwrap();
    for writer in writers {
        writer.join().unwrap();
    }
    assert!(
        refused.load(Ordering::Relaxed) > 0,
        "admission closed at least once"
    );
    assert!(
        committed.len() > 100,
        "and writes went through: {}",
        committed.len()
    );
    assert_eq!(admission.total_inflight(), 0, "every charge came back");
    refresh();
    assert!(admission.is_open());
    for (digest, body) in committed.iter().step_by(17) {
        let mut out = Vec::new();
        objects
            .read(&fx.conn, fx.tenant, *digest, &mut out)
            .unwrap();
        assert_eq!(&out, body.as_bytes());
    }
    let staging_left = fs::read_dir(fx.dir.path().join("incoming"))
        .map(|d| d.count())
        .unwrap_or(0);
    assert_eq!(staging_left, 0, "no staging file left behind");
}
