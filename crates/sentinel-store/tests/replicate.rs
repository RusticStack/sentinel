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
    backup,
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

type Stored = (Vec<u8>, Option<String>);

struct Upload {
    key: String,
    meta: Option<String>,
    parts: BTreeMap<u32, Vec<u8>>,
    initiated: Option<i64>,
}

#[derive(Default)]
struct Fake {
    objects: Mutex<HashMap<String, Stored>>,
    uploads: Mutex<HashMap<String, Upload>>,
    down: AtomicBool,
    refused: AtomicBool,
    head_without_metadata: AtomicBool,
    fail_part: AtomicU32,
    parts_sent: AtomicU32,
    next_id: AtomicU32,
    on_delete: Mutex<Option<Box<dyn FnOnce() + Send>>>,
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
        if self.refused.load(Ordering::Relaxed) {
            Err(BucketError {
                transient: false,
                not_found: false,
                message: "AccessDenied: the credential has expired".into(),
            })
        } else if self.down.load(Ordering::Relaxed) {
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
        let without_metadata = self.head_without_metadata.load(Ordering::Relaxed);
        Ok(self
            .objects
            .lock()
            .unwrap()
            .get(key)
            .map(|(body, metadata)| {
                let metadata = if without_metadata {
                    None
                } else {
                    metadata.clone()
                };
                (body.len() as u64, metadata)
            }))
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
        if let Some(hook) = self.on_delete.lock().unwrap().take() {
            hook();
        }
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
    fn path(&self, digest: Digest) -> std::path::PathBuf {
        self.dir
            .path()
            .join("objects")
            .join(self.tenant.to_string())
            .join(&digest.to_string()[..2])
            .join(digest.to_string())
    }
    fn local(&self, digest: Digest) -> bool {
        self.path(digest).exists()
    }
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

    let r = f.replicator(Settings {
        local_bytes: 100,
        ..SETTINGS
    });
    let first = r.pass().unwrap().evicted;
    assert!((1..=2).contains(&first));
    assert!(f.totals().local_bytes <= 100);
    let r = f.replicator(Settings {
        local_bytes: 1,
        ..SETTINGS
    });
    r.pass().unwrap();
    assert!(!f.local(a) && !f.local(b));
    assert_eq!(f.totals().local_bytes, 0);
    assert_eq!(f.read(b).unwrap(), vec![7u8; 3000]);
    assert!(f.local(b));
    let r = f.replicator(SETTINGS);
    r.pass().unwrap();
    assert_eq!(f.totals().local_bytes, 3000);
    assert_eq!(r.status().fetched_objects.load(Ordering::Relaxed), 1);
    f.bucket.corrupt(&key);
    assert!(matches!(f.read(a), Err(Error::Corrupt(_))));
    assert!(!f.local(a));
    let report = f.store.read(|c| f.objects.recover(c)).unwrap();
    assert!(report.missing.is_empty(), "{:?}", report.missing);
}

#[test]
fn a_head_without_blake3_metadata_leaves_the_object_unreplicated_and_local() {
    let f = fixture();
    let digest = f.put(b"the stored copy needs exact digest metadata");
    f.bucket
        .head_without_metadata
        .store(true, Ordering::Relaxed);
    let r = f.replicator(SETTINGS);
    let error = r.pass().unwrap_err();
    assert!(error.contains("stored copy"), "{error}");

    let remote_ms: Option<i64> = f
        .store
        .read(|conn| {
            Ok(conn.query_row(
                "SELECT remote_ms FROM objects WHERE tenant_id = ?1 AND digest = ?2",
                rusqlite::params![f.tenant.as_bytes().as_slice(), digest.as_bytes().as_slice()],
                |row| row.get(0),
            )?)
        })
        .unwrap();
    assert!(remote_ms.is_none());
    assert!(f.local(digest));
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

#[test]
fn a_damaged_or_lost_local_object_is_skipped_and_holds_nothing_back() {
    let f = fixture();
    let small = f.put(b"a small object that will rot");
    let large: Vec<u8> = (0..(3u32 << 20) + 5).map(|i| (i % 253) as u8).collect();
    let large = f.put(&large);
    let lost = f.put(b"an object whose file goes away");
    let healthy = f.put(b"a healthy object after them");
    for digest in [small, large] {
        let path = f.path(digest);
        let mut bytes = std::fs::read(&path).unwrap();
        let at = bytes.len() / 2;
        bytes[at] ^= 1;
        std::fs::write(&path, &bytes).unwrap();
    }
    std::fs::remove_file(f.path(lost)).unwrap();
    let r = f.replicator(SETTINGS);
    let pass = r.pass().expect("local faults do not fail the pass");
    assert_eq!(pass.replicated, 1);
    assert_eq!(pass.local_faults, 3);
    assert_eq!(
        f.bucket.keys(),
        vec![objects::remote_key(f.tenant, &healthy)]
    );
    assert!(
        f.bucket.uploads.lock().unwrap().is_empty(),
        "no multipart started"
    );
    assert_eq!(r.status().state(), "healthy");
    assert_eq!(r.status().local_faults.load(Ordering::Relaxed), 3);
    assert!(r.status().last_local_fault.lock().unwrap().is_some());
    assert_eq!(f.totals().unreplicated_bytes, 28 + (3 << 20) + 5 + 30);
    let later = f.put(b"committed after the faults");
    let pass = r.pass().unwrap();
    assert_eq!((pass.replicated, pass.local_faults), (1, 3));
    assert!(
        f.bucket
            .keys()
            .contains(&objects::remote_key(f.tenant, &later))
    );
}

#[test]
fn an_evicted_object_is_unreadable_during_an_outage_and_readable_after() {
    let f = fixture();
    let a = f.put(b"evicted before the outage");
    f.replicator(SETTINGS).pass().unwrap();
    f.replicator(Settings {
        local_bytes: 1,
        ..SETTINGS
    })
    .pass()
    .unwrap();
    assert!(!f.local(a));
    f.bucket.down.store(true, Ordering::Relaxed);
    assert!(f.read(a).is_err());
    assert!(!f.local(a), "nothing placed from a failed fetch");
    let r = f.replicator(SETTINGS);
    assert!(r.pass().is_err());
    assert_eq!(r.status().state(), "degraded");
    f.bucket.down.store(false, Ordering::Relaxed);
    assert_eq!(f.read(a).unwrap(), b"evicted before the outage");
    assert!(f.local(a));
    r.pass().unwrap();
    assert_eq!(r.status().state(), "healthy");
}

#[test]
fn a_refused_credential_degrades_the_copy_until_it_is_replaced() {
    let f = fixture();
    let a = f.put(b"written while the credential is refused");
    f.bucket.refused.store(true, Ordering::Relaxed);
    let r = f.replicator(SETTINGS);
    for _ in 0..3 {
        assert!(r.pass().is_err());
    }
    assert_eq!(r.status().state(), "degraded");
    assert_eq!(r.status().consecutive_failures.load(Ordering::Relaxed), 3);
    let error = r.status().last_error.lock().unwrap().clone().unwrap();
    assert!(error.contains("AccessDenied"), "{error}");
    assert!(f.bucket.keys().is_empty());
    assert!(f.local(a), "nothing evicted while it cannot be copied");
    f.bucket.refused.store(false, Ordering::Relaxed);
    assert_eq!(r.pass().unwrap().replicated, 1);
    assert_eq!(r.status().state(), "healthy");
    assert_eq!(r.status().consecutive_failures.load(Ordering::Relaxed), 0);
}

// R07: the external copy is down or refuses the credential while a controller is backed up and restored onto a second directory.
#[test]
fn a_backup_and_restore_during_an_s3_failure_keep_local_objects_and_fetch_evicted_ones_later() {
    let f = fixture();
    let evicted = f.put(b"evicted to the external copy before the backup");
    f.replicator(SETTINGS).pass().unwrap();
    f.replicator(Settings {
        local_bytes: 1,
        ..SETTINGS
    })
    .pass()
    .unwrap();
    assert!(!f.local(evicted));
    let local = f.put(b"written after the last pass, local only");
    f.bucket.refused.store(true, Ordering::Relaxed);

    let elsewhere = tempfile::tempdir().unwrap();
    let target = elsewhere.path().join("backups");
    let report = backup::create(&f.store, &f.objects, f.dir.path(), &target, "drill").unwrap();
    assert_eq!(
        (report.objects, report.objects_remote, report.objects_copied),
        (2, 1, 1)
    );
    assert!(report.objects_missing.is_empty() && report.objects_corrupt.is_empty());
    assert!(backup::verify(&target, &report.id).unwrap().ok());

    let second = elsewhere.path().join("second");
    let restored = backup::restore(&target, &report.id, &second, None).unwrap();
    assert_eq!((restored.objects, restored.objects_remote), (1, 1));
    let store = Store::open(second.join("metadata.sqlite"), Durability::Normal).unwrap();
    let objects = Objects::open(&second).unwrap();
    objects.set_remote(Arc::new(Fetch(Arc::clone(&f.bucket))));
    let read = |digest: Digest| {
        let mut out = Vec::new();
        store
            .read(|c| objects.read(c, f.tenant, digest, &mut out))
            .map(|_| out)
    };
    let placed = |digest: Digest| {
        second
            .join("objects")
            .join(f.tenant.to_string())
            .join(&digest.to_string()[..2])
            .join(digest.to_string())
            .exists()
    };
    assert_eq!(
        read(local).unwrap(),
        b"written after the last pass, local only"
    );
    assert!(
        read(evicted).is_err(),
        "an expired credential is a clean refusal"
    );
    f.bucket.refused.store(false, Ordering::Relaxed);
    f.bucket.down.store(true, Ordering::Relaxed);
    assert!(read(evicted).is_err(), "so is an outage");
    assert!(!placed(evicted), "nothing placed from a failed fetch");
    let recovery = store.read(|c| objects.recover(c)).unwrap();
    assert!(recovery.missing.is_empty(), "{recovery:?}");
    f.bucket.down.store(false, Ordering::Relaxed);
    assert_eq!(
        read(evicted).unwrap(),
        b"evicted to the external copy before the backup"
    );
    assert!(placed(evicted));
}

#[test]
fn a_queued_delete_never_removes_the_copy_of_content_committed_again() {
    let f = fixture();
    let digest = f.put(b"same bytes twice");
    let r = f.replicator(SETTINGS);
    r.pass().unwrap();
    let key = objects::remote_key(f.tenant, &digest);
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
    // Committed again before its queued delete runs; the stale delete must not remove the live copy.
    assert_eq!(f.put(b"same bytes twice"), digest);
    let object = f.store.read(|c| offload::unreplicated(c, 1)).unwrap()[0];
    let now = UnixMillis::now();
    f.store
        .writer()
        .write(move |tx| offload::replicated(tx, &object, now).map(|_| ()))
        .unwrap();
    let pass = r.pass().unwrap();
    assert_eq!(pass.deleted, 0, "the delete no longer applies");
    assert!(f.bucket.keys().contains(&key), "the live copy stays");
    let queued: i64 = f
        .store
        .read(|c| Ok(c.query_row("SELECT COUNT(*) FROM s3_deletes", [], |r| r.get(0))?))
        .unwrap();
    assert_eq!(queued, 0, "the stale delete was dropped, not left to retry");
    assert_eq!(f.read(digest).unwrap(), b"same bytes twice");
}

#[test]
fn delete_then_replicate_heals_content_recommitted_during_the_remote_delete() {
    let f = fixture();
    let digest = f.put(b"recommitted during delete");
    let r = f.replicator(SETTINGS);
    r.pass().unwrap();
    let key = objects::remote_key(f.tenant, &digest);
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

    let store = Arc::clone(&f.store);
    let objects = Arc::clone(&f.objects);
    *f.bucket.on_delete.lock().unwrap() = Some(Box::new(move || {
        let staged = objects
            .stage(
                tenant,
                &b"recommitted during delete"[..],
                u64::MAX,
                Expect::default(),
            )
            .unwrap();
        assert_eq!(staged.digest(), digest);
        store
            .writer()
            .write(move |tx| objects.commit(tx, &staged))
            .unwrap();
    }));
    let pass = r.pass().unwrap();
    assert_eq!((pass.deleted, pass.replicated), (1, 1));
    assert_eq!(
        f.bucket.objects.lock().unwrap()[&key].0,
        b"recommitted during delete"
    );
    assert_eq!(f.read(digest).unwrap(), b"recommitted during delete");
}

#[test]
fn a_store_failure_stops_the_pass_and_degrades_health() {
    let f = fixture();
    f.put(b"anything");
    let r = f.replicator(SETTINGS);
    r.pass().unwrap();
    assert_eq!(r.status().state(), "healthy");
    f.store
        .writer()
        .write(|tx| {
            tx.execute_batch("DROP TABLE s3_deletes")?;
            Ok(())
        })
        .unwrap();
    assert!(r.pass().is_err());
    let status = r.status();
    assert_eq!(status.consecutive_failures.load(Ordering::Relaxed), 1);
    assert_eq!(status.state(), "degraded");
    assert!(status.last_error.lock().unwrap().is_some());
    assert!(r.pass().is_err());
    assert_eq!(status.consecutive_failures.load(Ordering::Relaxed), 2);
}
