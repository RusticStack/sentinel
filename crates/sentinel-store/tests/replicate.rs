//! R02/R03: the replicator against an in-memory bucket with fault
//! injection — verified copies, multipart resume after an interruption,
//! eviction and verified read-through, deletes that follow reclamation and
//! log expiry, the backlog closing admission during an outage and reopening
//! once drained, and abandoned uploads aborted.
use std::{
    collections::{BTreeMap, HashMap},
    io::Write,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU32, Ordering},
    },
};

use sentinel_auth::secret::Secret;
use sentinel_core::{
    AttemptId, JobId, PoolId, RepoId, RunId, TenantId, UnixMillis, UserId, WorkerId,
    auth::{Namespace, Permissions as P, Principal},
};
use sentinel_pipeline::{PinnedSource, RunSpec, compile_str};
use sentinel_protocol::negotiate::{Arch, Capabilities, Negotiated, ProtocolVersion};
use sentinel_store::{
    Durability, Error, Store,
    auth::{self, Authority, NamespaceKind, provisioning},
    dispatch::{self, Capacity},
    jobs,
    logs::LogStore,
    objects::{self, Digest, Expect, Objects, Remote},
    offload,
    replicate::{Bucket, BucketError, BucketResult, Replicator, Settings},
    retention::{self, Deployment},
    runs,
    space::{Admission, Watermarks},
    tenancy::{self, PoolKind},
    workers::{self, Presentation},
};

const NOW: UnixMillis = UnixMillis(1_000_000_000);
const SHA: &str = "0123456789abcdef0123456789abcdef01234567";
const DIGEST: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

/// An object's body and its `blake3` metadata.
type Stored = (Vec<u8>, Option<String>);

struct Upload {
    key: String,
    meta: Option<String>,
    parts: BTreeMap<u32, Vec<u8>>,
    initiated: Option<i64>,
}

/// An S3-shaped bucket in memory. `down` fails every call as a transport
/// fault would; `fail_part` fails upload of that part number once.
#[derive(Default)]
struct Fake {
    objects: Mutex<HashMap<String, Stored>>,
    uploads: Mutex<HashMap<String, Upload>>,
    down: AtomicBool,
    fail_part: AtomicU32,
    parts_sent: AtomicU32,
    next_id: AtomicU32,
}

fn transient(message: &str) -> BucketError {
    BucketError {
        transient: true,
        not_found: false,
        message: message.into(),
    }
}

fn missing() -> BucketError {
    BucketError {
        transient: false,
        not_found: true,
        message: "no such key".into(),
    }
}

impl Fake {
    fn up(&self) -> BucketResult<()> {
        if self.down.load(Ordering::Relaxed) {
            Err(transient("connection refused"))
        } else {
            Ok(())
        }
    }
    fn keys(&self) -> Vec<String> {
        let mut keys: Vec<String> = self.objects.lock().unwrap().keys().cloned().collect();
        keys.sort();
        keys
    }
    fn corrupt(&self, key: &str) {
        let mut objects = self.objects.lock().unwrap();
        let body = &mut objects.get_mut(key).unwrap().0;
        body[0] ^= 0xff;
    }
}

impl Bucket for Fake {
    fn put(&self, key: &str, body: &[u8], blake3: Option<&str>) -> BucketResult<()> {
        self.up()?;
        self.objects
            .lock()
            .unwrap()
            .insert(key.into(), (body.to_vec(), blake3.map(str::to_owned)));
        Ok(())
    }
    fn create_multipart(&self, key: &str, blake3: Option<&str>) -> BucketResult<String> {
        self.up()?;
        let id = format!("u{}", self.next_id.fetch_add(1, Ordering::Relaxed));
        self.uploads.lock().unwrap().insert(
            id.clone(),
            Upload {
                key: key.into(),
                meta: blake3.map(str::to_owned),
                parts: BTreeMap::new(),
                initiated: Some(UnixMillis::now().0),
            },
        );
        Ok(id)
    }
    fn upload_part(
        &self,
        key: &str,
        upload: &str,
        number: u32,
        body: &[u8],
    ) -> BucketResult<String> {
        self.up()?;
        if self.fail_part.load(Ordering::Relaxed) == number {
            self.fail_part.store(0, Ordering::Relaxed);
            return Err(transient("reset mid-part"));
        }
        let mut uploads = self.uploads.lock().unwrap();
        let u = uploads.get_mut(upload).ok_or_else(missing)?;
        assert_eq!(u.key, key);
        u.parts.insert(number, body.to_vec());
        self.parts_sent.fetch_add(1, Ordering::Relaxed);
        Ok(format!("e{number}-{}", body.len()))
    }
    fn list_parts(&self, _key: &str, upload: &str) -> BucketResult<Vec<(u32, String, u64)>> {
        self.up()?;
        let uploads = self.uploads.lock().unwrap();
        let u = uploads.get(upload).ok_or_else(missing)?;
        Ok(u.parts
            .iter()
            .map(|(n, b)| (*n, format!("e{n}-{}", b.len()), b.len() as u64))
            .collect())
    }
    fn complete(&self, key: &str, upload: &str, parts: &[(u32, String)]) -> BucketResult<()> {
        self.up()?;
        let u = self
            .uploads
            .lock()
            .unwrap()
            .remove(upload)
            .ok_or_else(missing)?;
        let mut body = Vec::new();
        for (n, etag) in parts {
            let part = &u.parts[n];
            assert_eq!(*etag, format!("e{n}-{}", part.len()));
            body.extend_from_slice(part);
        }
        self.objects
            .lock()
            .unwrap()
            .insert(key.into(), (body, u.meta));
        Ok(())
    }
    fn abort(&self, _key: &str, upload: &str) -> BucketResult<()> {
        self.up()?;
        self.uploads.lock().unwrap().remove(upload);
        Ok(())
    }
    fn head(&self, key: &str) -> BucketResult<Option<(u64, Option<String>)>> {
        self.up()?;
        Ok(self
            .objects
            .lock()
            .unwrap()
            .get(key)
            .map(|(b, m)| (b.len() as u64, m.clone())))
    }
    fn get(&self, key: &str, out: &mut dyn Write) -> BucketResult<u64> {
        self.up()?;
        let body = self
            .objects
            .lock()
            .unwrap()
            .get(key)
            .ok_or_else(missing)?
            .0
            .clone();
        out.write_all(&body)
            .map_err(|e| transient(&e.to_string()))?;
        Ok(body.len() as u64)
    }
    fn delete(&self, key: &str) -> BucketResult<()> {
        self.up()?;
        self.objects.lock().unwrap().remove(key);
        Ok(())
    }
    fn list(&self, prefix: &str) -> BucketResult<Vec<String>> {
        self.up()?;
        Ok(self
            .keys()
            .into_iter()
            .filter(|k| k.starts_with(prefix))
            .collect())
    }
    fn list_uploads(&self) -> BucketResult<Vec<(String, String, Option<i64>)>> {
        self.up()?;
        Ok(self
            .uploads
            .lock()
            .unwrap()
            .iter()
            .map(|(id, u)| (u.key.clone(), id.clone(), u.initiated))
            .collect())
    }
}

/// The store's read-through fetch, served by the same fake.
struct Fetch(Arc<Fake>);

impl Remote for Fetch {
    fn fetch(&self, key: &str, out: &mut dyn Write) -> sentinel_store::Result<u64> {
        self.0
            .get(key, out)
            .map_err(|e| Error::Io(std::io::Error::other(e.message)))
    }
}

struct Fixture {
    dir: tempfile::TempDir,
    store: Arc<Store>,
    objects: Arc<Objects>,
    logs: Arc<LogStore>,
    bucket: Arc<Fake>,
    tenant: TenantId,
    repo: RepoId,
    pool: PoolId,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let store =
        Arc::new(Store::open(dir.path().join("metadata.sqlite"), Durability::Normal).unwrap());
    let objects = Arc::new(Objects::open(dir.path()).unwrap());
    let logs = Arc::new(LogStore::open(dir.path().join("logs")).unwrap());
    let bucket = Arc::new(Fake::default());
    objects.set_remote(Arc::new(Fetch(Arc::clone(&bucket))));
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
                Authority::HostLocal,
                pool,
                "b",
                PoolKind::Dedicated(tenant),
                NOW,
            )
        })
        .unwrap();
    Fixture {
        dir,
        store,
        objects,
        logs,
        bucket,
        tenant,
        repo,
        pool,
    }
}

impl Fixture {
    fn replicator(&self, settings: Settings) -> Replicator {
        Replicator::new(
            Arc::clone(&self.store),
            Arc::clone(&self.objects),
            Arc::clone(&self.logs),
            Arc::clone(&self.bucket) as Arc<dyn Bucket>,
            settings,
        )
    }
    fn put(&self, body: &[u8]) -> Digest {
        let staged = self
            .objects
            .stage(self.tenant, body, u64::MAX, Expect::default())
            .unwrap();
        let digest = staged.digest();
        let objects = Arc::clone(&self.objects);
        self.store
            .writer()
            .write(move |tx| objects.commit(tx, &staged))
            .unwrap();
        digest
    }
    fn read(&self, digest: Digest) -> Result<Vec<u8>, Error> {
        let mut out = Vec::new();
        self.store
            .read(|c| self.objects.read(c, self.tenant, digest, &mut out))?;
        Ok(out)
    }
    fn totals(&self) -> offload::Totals {
        self.store.read(offload::totals).unwrap()
    }
    fn local(&self, digest: Digest) -> bool {
        self.dir
            .path()
            .join("objects")
            .join(self.tenant.to_string())
            .join(&digest.to_string()[..2])
            .join(digest.to_string())
            .exists()
    }
    /// A finished attempt with a log, released long enough ago to settle,
    /// and stamped by retention.
    fn finished_log(&self) -> (RunId, JobId, AttemptId) {
        let (tenant, repo, run, pool, worker) = (
            self.tenant,
            self.repo,
            RunId::new(),
            self.pool,
            WorkerId::new(),
        );
        let spec = RunSpec::new(
            PinnedSource::new("https://github.com/o/r.git", SHA, Some("main")).unwrap(),
            compile_str("schema: 1\non: [push]\njobs:\n  build:\n    image: alpine:3\n    steps: [{ id: s, run: 'true' }]\n").unwrap(),
        )
        .unwrap();
        let released = UnixMillis(UnixMillis::now().0 - 3_600_000);
        let (job, attempt) = self
            .store
            .writer()
            .write(move |tx| {
                let ids = runs::create_run(tx, tenant, repo, run, &spec, NOW)?;
                runs::resolve_image(tx, tenant, ids[0], DIGEST, "linux/amd64")?;
                let issued =
                    workers::issue_enrollment(tx, Authority::HostLocal, pool, 60_000, NOW)?;
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
                )?;
                let offer =
                    dispatch::place(tx, worker, pool, dispatch::DEFAULT_LEASE_MS, NOW)?.unwrap();
                tx.execute(
                    "UPDATE attempts SET released_ms = ?2 WHERE id = ?1",
                    rusqlite::params![offer.attempt.as_bytes().as_slice(), released.0],
                )?;
                Ok((ids[0], offer.attempt))
            })
            .unwrap();
        let frame = sentinel_protocol::logs::Frame {
            seq: 1,
            step: 0,
            stream: sentinel_protocol::logs::Stream::Stdout,
            bytes: b"hello\n".to_vec(),
        };
        self.logs.append(run, job, attempt, &frame).unwrap();
        self.logs.finish(run, job, attempt, 1, &[]).unwrap();
        self.logs.forget(attempt);
        let rows = self.store.read(|c| retention::unstamped(c, 16)).unwrap();
        let sized: Vec<_> = rows.into_iter().map(|r| (r, 10)).collect();
        let d = Deployment::default();
        self.store
            .writer()
            .write(move |tx| retention::stamp(tx, &d, &sized))
            .unwrap();
        (run, job, attempt)
    }
}

const SETTINGS: Settings = Settings {
    part_bytes: 1 << 20,
    local_bytes: 0,
    backlog_bytes: 0,
};

#[test]
fn objects_are_copied_verified_evicted_and_fetched_back_verified() {
    let f = fixture();
    let (a, b) = (f.put(b"first object"), f.put(&[7u8; 3000]));
    assert_eq!(f.totals().unreplicated_bytes, 12 + 3000);
    let r = f.replicator(SETTINGS);
    let pass = r.pass().unwrap();
    assert_eq!(pass.replicated, 2);
    assert_eq!(f.totals().unreplicated_bytes, 0);
    let key = objects::remote_key(f.tenant, &a);
    assert_eq!(
        f.bucket.objects.lock().unwrap()[&key].1.as_deref(),
        Some(a.to_string().as_str())
    );
    assert_eq!(r.pass().unwrap().replicated, 0, "nothing twice");

    // A local budget evicts only what it needs: 3,012 bytes against 100
    // leaves at most 100 local (both were committed in the same
    // millisecond, so which goes first is the index's tie order).
    let r = f.replicator(Settings {
        local_bytes: 100,
        ..SETTINGS
    });
    let first = r.pass().unwrap().evicted;
    assert!((1..=2).contains(&first));
    assert!(f.totals().local_bytes <= 100);
    // A one-byte budget takes both.
    let r = f.replicator(Settings {
        local_bytes: 1,
        ..SETTINGS
    });
    r.pass().unwrap();
    assert!(!f.local(a) && !f.local(b));
    assert_eq!(f.totals().local_bytes, 0);
    // A read fetches it back, verified, and the next pass marks it local.
    assert_eq!(f.read(b).unwrap(), vec![7u8; 3000]);
    assert!(f.local(b));
    let r = f.replicator(SETTINGS);
    r.pass().unwrap();
    assert_eq!(f.totals().local_bytes, 3000);
    assert_eq!(r.status().fetched_objects.load(Ordering::Relaxed), 1);
    // A corrupted remote copy is refused, not served, and not placed.
    f.bucket.corrupt(&key);
    assert!(matches!(f.read(a), Err(Error::Corrupt(_))));
    assert!(!f.local(a));
    // Recovery knows an evicted object is not missing.
    let report = f.store.read(|c| f.objects.recover(c)).unwrap();
    assert!(report.missing.is_empty(), "{:?}", report.missing);
}

#[test]
fn a_multipart_upload_interrupted_mid_way_resumes_from_what_the_bucket_holds() {
    let f = fixture();
    let body: Vec<u8> = (0..(5u32 << 20) + 17).map(|i| (i % 251) as u8).collect();
    let digest = f.put(&body);
    f.bucket.fail_part.store(4, Ordering::Relaxed);
    let r = f.replicator(SETTINGS);
    assert!(r.pass().is_err(), "the fourth part fails");
    assert_eq!(f.bucket.parts_sent.load(Ordering::Relaxed), 3);
    assert_eq!(r.status().state(), "degraded");
    let key = objects::remote_key(f.tenant, &digest);
    assert!(
        f.store
            .read(|c| offload::upload(c, &key))
            .unwrap()
            .is_some(),
        "recorded to resume"
    );
    // A restart: a new replicator resumes, sending only parts 4, 5 and 6.
    let r = f.replicator(SETTINGS);
    assert_eq!(r.pass().unwrap().replicated, 1);
    assert_eq!(f.bucket.parts_sent.load(Ordering::Relaxed), 6);
    assert_eq!(f.bucket.objects.lock().unwrap()[&key].0, body);
    assert!(
        f.store
            .read(|c| offload::upload(c, &key))
            .unwrap()
            .is_none()
    );
    assert_eq!(r.status().state(), "healthy");
}

#[test]
fn copies_follow_reclamation_even_mid_upload() {
    let f = fixture();
    let digest = f.put(b"soon gone");
    let r = f.replicator(SETTINGS);
    r.pass().unwrap();
    let key = objects::remote_key(f.tenant, &digest);
    assert!(f.bucket.keys().contains(&key));
    // The row goes (reclamation's delete): its copy is queued and deleted.
    let tenant = f.tenant;
    f.store
        .writer()
        .write(move |tx| {
            tx.execute(
                "DELETE FROM objects WHERE tenant_id = ?1 AND digest = ?2",
                rusqlite::params![tenant.as_bytes().as_slice(), digest.as_bytes().as_slice()],
            )?;
            Ok(())
        })
        .unwrap();
    assert_eq!(r.pass().unwrap().deleted, 1);
    assert!(!f.bucket.keys().contains(&key));
    // A copy uploaded for a row reclaimed meanwhile is deleted too.
    let late = f.put(b"reclaimed while uploading");
    let object = f.store.read(|c| offload::unreplicated(c, 1)).unwrap()[0];
    let now = UnixMillis::now();
    f.store
        .writer()
        .write(move |tx| {
            tx.execute(
                "DELETE FROM objects WHERE tenant_id = ?1 AND digest = ?2",
                rusqlite::params![tenant.as_bytes().as_slice(), late.as_bytes().as_slice()],
            )?;
            assert!(!offload::replicated(tx, &object, now)?);
            offload::queue_object_delete(tx, tenant, &late, now)
        })
        .unwrap();
    f.bucket
        .put(&objects::remote_key(tenant, &late), b"x", None)
        .unwrap();
    r.pass().unwrap();
    assert!(f.bucket.keys().is_empty(), "{:?}", f.bucket.keys());
}

#[test]
fn finished_logs_are_copied_recopied_after_a_late_end_and_deleted_on_expiry() {
    let f = fixture();
    let (run, job, attempt) = f.finished_log();
    let r = f.replicator(SETTINGS);
    assert_eq!(r.pass().unwrap().logs, 1);
    let prefix = offload::log_prefix(run, job, attempt);
    let copied = f.bucket.list(&prefix).unwrap();
    assert!(copied.iter().any(|k| k.ends_with("/end")), "{copied:?}");
    // A stale key under the prefix and a changed log state: the next pass
    // copies again and drops the stale key.
    f.bucket
        .put(&format!("{prefix}seg-999999"), b"stale", None)
        .unwrap();
    f.store
        .writer()
        .write(move |tx| {
            tx.execute(
                "UPDATE attempts SET log_state = 1 WHERE id = ?1 AND log_state = 0",
                [attempt.as_bytes().as_slice()],
            )?;
            tx.execute(
                "UPDATE attempts SET log_state = 2 WHERE id = ?1",
                [attempt.as_bytes().as_slice()],
            )?;
            Ok(())
        })
        .unwrap();
    assert_eq!(r.pass().unwrap().logs, 1);
    assert!(!f.bucket.keys().iter().any(|k| k.ends_with("seg-999999")));
    // Retention expires it: every key under the prefix goes.
    let due = vec![retention::Expiring { attempt, run, job }];
    let at = UnixMillis(UnixMillis::now().0 + 400 * 86_400_000);
    f.store
        .writer()
        .write(move |tx| {
            tx.execute(
                "UPDATE attempts SET log_expires_ms = 1 WHERE id = ?1",
                [attempt.as_bytes().as_slice()],
            )?;
            retention::expire(tx, &due, at)
        })
        .unwrap();
    assert_eq!(r.pass().unwrap().deleted, 1);
    assert!(f.bucket.list(&prefix).unwrap().is_empty());
}

#[test]
fn an_outage_fills_the_backlog_closes_admission_and_draining_reopens_it() {
    let f = fixture();
    let admission = Arc::new(
        Admission::with_probe(
            Watermarks {
                reserve: 1 << 20,
                low: 1 << 20,
                high: 2 << 20,
                floor: 1 << 17,
            },
            || Ok(1 << 40),
        )
        .unwrap(),
    );
    f.objects.set_admission(Arc::clone(&admission));
    let r = f.replicator(Settings {
        backlog_bytes: 10_000,
        ..SETTINGS
    });
    f.bucket.down.store(true, Ordering::Relaxed);
    for i in 0..4u8 {
        f.put(&[i; 3_000]);
    }
    assert!(r.pass().is_err());
    assert!(
        r.status().backlog_full.load(Ordering::Relaxed),
        "12,000 bytes past 10,000"
    );
    assert!(!admission.is_open());
    assert!(matches!(admission.check(1), Err(Error::StorageFull)));
    assert_eq!(r.status().state(), "degraded");
    // Back up: the backlog drains and admission reopens.
    f.bucket.down.store(false, Ordering::Relaxed);
    r.pass().unwrap();
    assert_eq!(f.totals().unreplicated_bytes, 0);
    assert!(!r.status().backlog_full.load(Ordering::Relaxed));
    assert!(admission.is_open());
    assert_eq!(r.status().state(), "healthy");
}

#[test]
fn abandoned_multipart_uploads_are_aborted() {
    let f = fixture();
    // One the bucket holds that nothing here recorded, old; one recent; one
    // recorded here a day and more ago.
    let old = f.bucket.create_multipart("objects/x/old", None).unwrap();
    f.bucket
        .uploads
        .lock()
        .unwrap()
        .get_mut(&old)
        .unwrap()
        .initiated = Some(1);
    let recent = f.bucket.create_multipart("objects/x/recent", None).unwrap();
    let stale = f.bucket.create_multipart("objects/x/stale", None).unwrap();
    let id = stale.clone();
    f.store
        .writer()
        .write(move |tx| offload::record_upload(tx, "objects/x/stale", &id, 1 << 20, UnixMillis(1)))
        .unwrap();
    let r = f.replicator(SETTINGS);
    assert_eq!(r.pass().unwrap().aborted, 2);
    let open: Vec<String> = f.bucket.uploads.lock().unwrap().keys().cloned().collect();
    assert_eq!(open, vec![recent]);
    assert!(f.store.read(offload::recorded_uploads).unwrap().is_empty());
}
