use std::{
    collections::{BTreeMap, HashMap},
    io::Write,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering},
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
type Hook = Box<dyn FnOnce() + Send>;
type PartHook = Box<dyn Fn(u32) + Send>;

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
    /// Keys containing this text are refused for good: put, part and delete answer a permanent error.
    refuse: Mutex<Option<String>>,
    refused_calls: AtomicU32,
    /// Every list answers a permanent refusal, as a key without `s3:ListBucket` does.
    refuse_list: AtomicBool,
    completes: AtomicU32,
    /// Runs once, after the first put of a key containing the text.
    on_put: Mutex<Option<(String, Hook)>>,
    /// Runs after each part is stored, with its number.
    on_part: Mutex<Option<PartHook>>,
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
    fn refusing(&self, key: &str) -> BucketResult<()> {
        let refuse = self.refuse.lock().unwrap();
        if refuse.as_deref().is_some_and(|text| key.contains(text)) {
            self.refused_calls.fetch_add(1, Ordering::Relaxed);
            return Err(BucketError {
                transient: false,
                not_found: false,
                message: "AccessDenied: the object is locked".into(),
            });
        }
        Ok(())
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
        self.refusing(key)?;
        self.objects
            .lock()
            .unwrap()
            .insert(key.into(), (body.to_vec(), blake3.map(str::to_owned)));
        let hook = {
            let mut slot = self.on_put.lock().unwrap();
            if slot
                .as_ref()
                .is_some_and(|(text, _)| key.contains(text.as_str()))
            {
                slot.take().map(|(_, hook)| hook)
            } else {
                None
            }
        };
        if let Some(hook) = hook {
            hook();
        }
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
        self.refusing(key)?;
        if self.fail_part.load(Ordering::Relaxed) == number {
            self.fail_part.store(0, Ordering::Relaxed);
            return Err(transient("reset mid-part"));
        }
        let mut uploads = self.uploads.lock().unwrap();
        let u = uploads.get_mut(upload).ok_or_else(missing)?;
        assert_eq!(u.key, key);
        u.parts.insert(number, body.to_vec());
        self.parts_sent.fetch_add(1, Ordering::Relaxed);
        drop(uploads);
        if let Some(hook) = self.on_part.lock().unwrap().as_ref() {
            hook(number);
        }
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
        self.completes.fetch_add(1, Ordering::Relaxed);
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
        self.refusing(key)?;
        self.objects.lock().unwrap().remove(key);
        if let Some(hook) = self.on_delete.lock().unwrap().take() {
            hook();
        }
        Ok(())
    }
    fn list(&self, prefix: &str) -> BucketResult<Vec<String>> {
        self.up()?;
        if self.refuse_list.load(Ordering::Relaxed) {
            return Err(BucketError {
                transient: false,
                not_found: false,
                message: "AccessDenied: s3:ListBucket is not allowed".into(),
            });
        }
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
    assert_eq!(
        (pass.replicated, pass.local_faults),
        (1, 0),
        "the three damaged objects are parked, not read and hashed again"
    );
    assert_eq!(
        r.status().local_faults.load(Ordering::Relaxed),
        3,
        "each damaged object is counted once"
    );
    assert_eq!(r.status().parked_objects.load(Ordering::Relaxed), 3);
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

fn sleep_ms(ms: u64) {
    std::thread::sleep(std::time::Duration::from_millis(ms));
}

fn damage(f: &Fixture, digest: Digest) {
    let path = f.path(digest);
    let mut bytes = std::fs::read(&path).unwrap();
    let at = bytes.len() / 2;
    bytes[at] ^= 1;
    std::fs::write(&path, &bytes).unwrap();
}

fn remote_ms(f: &Fixture, digest: Digest) -> Option<i64> {
    f.store
        .read(|conn| {
            Ok(conn.query_row(
                "SELECT remote_ms FROM objects WHERE tenant_id = ?1 AND digest = ?2",
                rusqlite::params![f.tenant.as_bytes().as_slice(), digest.as_bytes().as_slice()],
                |row| row.get(0),
            )?)
        })
        .unwrap()
}

fn queued_deletes(f: &Fixture) -> i64 {
    f.store
        .read(|c| Ok(c.query_row("SELECT COUNT(*) FROM s3_deletes", [], |r| r.get(0))?))
        .unwrap()
}

fn reclaim(f: &Fixture, digest: Digest) {
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
}

#[test]
fn a_wall_of_damaged_objects_older_than_a_healthy_one_does_not_stop_replication() {
    let f = fixture();
    let mut lost = Vec::new();
    for i in 0..20u8 {
        lost.push(f.put(&[i; 700]));
    }
    sleep_ms(5);
    let healthy = f.put(b"committed after twenty damaged objects");
    for digest in &lost {
        std::fs::remove_file(f.path(*digest)).unwrap();
    }
    let r = f.replicator(SETTINGS);
    let mut passes = 0;
    let mut replicated = 0;
    loop {
        let pass = r.pass().expect("local faults do not fail the pass");
        replicated += pass.replicated;
        passes += 1;
        if !pass.more {
            break;
        }
        assert!(passes < 6, "the passes must converge, not spin");
    }
    assert_eq!(replicated, 1, "the healthy object was reached");
    assert!(remote_ms(&f, healthy).is_some());
    assert_eq!(r.status().local_faults.load(Ordering::Relaxed), 20);
    assert_eq!(r.status().parked_objects.load(Ordering::Relaxed), 20);
    assert_eq!(r.status().parked_bytes.load(Ordering::Relaxed), 20 * 700);
    assert_eq!(r.status().state(), "healthy");

    // Nothing is read or hashed again while they wait, and an idle pass asks for no more.
    let pass = r.pass().unwrap();
    assert_eq!(
        (pass.local_faults, pass.replicated, pass.more),
        (0, 0, false)
    );
    assert_eq!(r.status().local_faults.load(Ordering::Relaxed), 20);
}

#[test]
fn a_parked_object_is_tried_again_after_its_delay_and_released_once_repaired() {
    let f = fixture();
    let digest = f.put(b"an object whose file rots and is then restored");
    let original = std::fs::read(f.path(digest)).unwrap();
    damage(&f, digest);
    let r = f.replicator(SETTINGS).with_park_delays(
        std::time::Duration::from_millis(150),
        std::time::Duration::from_millis(300),
    );
    assert_eq!(r.pass().unwrap().local_faults, 1);
    assert_eq!(r.pass().unwrap().local_faults, 0, "waiting");
    std::fs::write(f.path(digest), &original).unwrap();
    assert_eq!(
        r.pass().unwrap().replicated,
        0,
        "still waiting, though repaired"
    );
    sleep_ms(200);
    let pass = r.pass().unwrap();
    assert_eq!((pass.replicated, pass.local_faults), (1, 0));
    assert!(remote_ms(&f, digest).is_some());
    assert_eq!(r.status().parked_items.load(Ordering::Relaxed), 0);
    assert_eq!(r.status().local_faults.load(Ordering::Relaxed), 1);

    // Still damaged at the retry: found again, but the same object is not counted twice.
    let again = f.put(b"a second object that stays damaged");
    damage(&f, again);
    assert_eq!(r.pass().unwrap().local_faults, 1);
    sleep_ms(200);
    assert_eq!(
        r.pass().unwrap().local_faults,
        1,
        "the retry found it still damaged"
    );
    assert_eq!(r.status().local_faults.load(Ordering::Relaxed), 2);
    assert_eq!(r.status().parked_objects.load(Ordering::Relaxed), 1);
}

#[test]
fn one_delete_the_bucket_refuses_for_good_does_not_stop_the_queue() {
    let f = fixture();
    let (locked, gone) = (
        f.put(b"held by an object lock"),
        f.put(b"reclaimed normally"),
    );
    let r = f.replicator(SETTINGS);
    r.pass().unwrap();
    reclaim(&f, locked);
    reclaim(&f, gone);
    assert_eq!(
        queued_deletes(&f),
        2,
        "the locked one is first in the queue"
    );
    *f.bucket.refuse.lock().unwrap() = Some(locked.to_string());
    let fresh = f.put(b"written while a delete is stuck");

    let pass = r.pass().expect("one item's refusal does not fail the pass");
    assert_eq!((pass.deleted, pass.replicated, pass.parked), (1, 1, 1));
    assert!(remote_ms(&f, fresh).is_some(), "later stages still ran");
    assert_eq!(queued_deletes(&f), 1, "the refused delete is still queued");
    let status = r.status();
    assert_eq!(status.parked_items.load(Ordering::Relaxed), 1);
    assert!(
        status
            .last_refusal
            .lock()
            .unwrap()
            .as_deref()
            .is_some_and(|m| m.contains("AccessDenied"))
    );
    assert_eq!(status.state(), "healthy");

    let calls = f.bucket.refused_calls.load(Ordering::Relaxed);
    r.pass().unwrap();
    assert_eq!(
        f.bucket.refused_calls.load(Ordering::Relaxed),
        calls,
        "not asked again on every pass"
    );
}

#[test]
fn one_object_the_bucket_refuses_for_good_does_not_stop_the_queue() {
    let f = fixture();
    let refused = f.put(b"the bucket refuses this key");
    sleep_ms(5);
    let healthy = f.put(b"a healthy object behind it");
    *f.bucket.refuse.lock().unwrap() = Some(refused.to_string());
    let r = f.replicator(SETTINGS);
    let pass = r.pass().expect("one item's refusal does not fail the pass");
    assert_eq!((pass.replicated, pass.parked), (1, 1));
    assert!(remote_ms(&f, healthy).is_some());
    assert!(remote_ms(&f, refused).is_none());
    assert_eq!(r.status().parked_items.load(Ordering::Relaxed), 1);
    let calls = f.bucket.refused_calls.load(Ordering::Relaxed);
    assert_eq!(r.pass().unwrap().parked, 0);
    assert_eq!(f.bucket.refused_calls.load(Ordering::Relaxed), calls);
}

#[test]
fn a_key_that_may_write_logs_but_not_list_them_degrades_the_copy_and_parks_nothing() {
    let f = fixture();
    let (run, job, attempt) = f.finished_log();
    f.bucket.refuse_list.store(true, Ordering::Relaxed);
    let r = f.replicator(SETTINGS);
    // The log files are accepted first, so a write that went through must not make the list refusal the log's own.
    assert!(
        r.pass().is_err(),
        "the listing is refused for the whole key"
    );
    let status = r.status();
    assert_eq!(status.parked_items.load(Ordering::Relaxed), 0);
    assert_eq!(status.state(), "degraded");
    assert!(
        status
            .last_error
            .lock()
            .unwrap()
            .as_deref()
            .is_some_and(|m| m.contains("ListBucket"))
    );

    f.bucket.refuse_list.store(false, Ordering::Relaxed);
    assert_eq!(
        r.pass().unwrap().logs,
        1,
        "no waiting once the grant is fixed"
    );
    assert!(
        !f.bucket
            .list(&offload::log_prefix(run, job, attempt))
            .unwrap()
            .is_empty()
    );
    assert_eq!(status.state(), "healthy");
}

#[test]
fn a_parked_delete_retried_alone_stays_parked_and_backs_off_instead_of_failing_each_pass() {
    let f = fixture();
    let (locked, gone) = (
        f.put(b"held by an object lock"),
        f.put(b"reclaimed normally"),
    );
    let r = f.replicator(SETTINGS).with_park_delays(
        std::time::Duration::from_millis(100),
        std::time::Duration::from_millis(150),
    );
    r.pass().unwrap();
    reclaim(&f, locked);
    reclaim(&f, gone);
    *f.bucket.refuse.lock().unwrap() = Some(locked.to_string());
    let pass = r
        .pass()
        .expect("judged the item's own beside a delete that succeeded");
    assert_eq!((pass.deleted, pass.parked), (1, 1));

    // At the retry the locked delete is the only one: no other delete succeeds beside it to vouch for it.
    sleep_ms(200);
    let calls = f.bucket.refused_calls.load(Ordering::Relaxed);
    let pass = r.pass().expect("the same answer is still the item's own");
    assert_eq!((pass.deleted, pass.parked), (0, 1));
    assert_eq!(f.bucket.refused_calls.load(Ordering::Relaxed), calls + 1);
    let status = r.status();
    assert_eq!(status.state(), "healthy");
    assert_eq!(status.consecutive_failures.load(Ordering::Relaxed), 0);
    assert_eq!(status.parked_items.load(Ordering::Relaxed), 1);

    // Backed off again: not asked on the next pass.
    r.pass().unwrap();
    assert_eq!(f.bucket.refused_calls.load(Ordering::Relaxed), calls + 1);

    // The lock is lifted: the delete goes through at the next retry and the shelf empties.
    *f.bucket.refuse.lock().unwrap() = None;
    sleep_ms(300);
    assert_eq!(r.pass().unwrap().deleted, 1);
    assert_eq!(status.parked_items.load(Ordering::Relaxed), 0);
    assert_eq!(queued_deletes(&f), 0);
}

#[test]
fn damaged_objects_past_a_full_shelf_are_counted_once_not_on_every_pass() {
    let f = fixture();
    let first = f.put(b"first damaged object");
    sleep_ms(5);
    let second = f.put(b"second damaged object");
    damage(&f, first);
    damage(&f, second);
    let r = f.replicator(SETTINGS).with_park_limit(1);
    assert_eq!(r.pass().unwrap().local_faults, 2);
    assert_eq!(
        r.status().local_faults.load(Ordering::Relaxed),
        1,
        "one fits on the shelf"
    );
    for _ in 0..3 {
        assert_eq!(
            r.pass().unwrap().local_faults,
            1,
            "the one left over is found again"
        );
    }
    assert_eq!(
        r.status().local_faults.load(Ordering::Relaxed),
        1,
        "an object the shelf cannot hold is not counted again on every pass"
    );
}

#[test]
fn a_refusal_with_no_success_beside_it_is_the_credential_and_nothing_stays_parked() {
    let f = fixture();
    let a = f.put(b"first");
    sleep_ms(2);
    f.put(b"second");
    f.bucket.refused.store(true, Ordering::Relaxed);
    let r = f.replicator(SETTINGS);
    assert!(r.pass().is_err());
    assert_eq!(r.status().parked_items.load(Ordering::Relaxed), 0);
    f.bucket.refused.store(false, Ordering::Relaxed);
    assert_eq!(
        r.pass().unwrap().replicated,
        2,
        "the first pass after the credential is replaced catches up"
    );
    assert!(remote_ms(&f, a).is_some());
}

#[test]
fn a_log_that_expires_while_it_is_copied_leaves_no_copy_behind() {
    let f = fixture();
    let (run, job, attempt) = f.finished_log();
    let prefix = offload::log_prefix(run, job, attempt);
    let store = Arc::clone(&f.store);
    *f.bucket.on_put.lock().unwrap() = Some((
        "logs/".into(),
        Box::new(move || {
            let due = vec![retention::Expiring { attempt, run, job }];
            let at = UnixMillis(UnixMillis::now().0 + 400 * 86_400_000);
            store
                .writer()
                .write(move |tx| {
                    tx.execute(
                        "UPDATE attempts SET log_expires_ms = 1 WHERE id = ?1",
                        [attempt.as_bytes().as_slice()],
                    )?;
                    retention::expire(tx, &due, at)
                })
                .unwrap();
        }),
    ));
    let r = f.replicator(SETTINGS);
    let pass = r.pass().unwrap();
    assert_eq!(pass.logs, 0, "an expired log is not recorded as copied");
    assert!(
        !f.bucket.list(&prefix).unwrap().is_empty(),
        "the copy exists"
    );
    assert_eq!(queued_deletes(&f), 1, "its delete was queued");
    assert_eq!(r.pass().unwrap().deleted, 1);
    assert!(f.bucket.list(&prefix).unwrap().is_empty());
}

fn late_end(f: &Fixture, attempt: AttemptId) {
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
}

#[test]
fn a_late_end_during_the_copy_makes_the_log_be_copied_again() {
    let f = fixture();
    let (_, _, attempt) = f.finished_log();
    let store = Arc::clone(&f.store);
    *f.bucket.on_put.lock().unwrap() = Some((
        "logs/".into(),
        Box::new(move || {
            store
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
        }),
    ));
    let r = f.replicator(SETTINGS);
    assert_eq!(
        r.pass().unwrap().logs,
        0,
        "the log changed under the copy, so the copy is not the log"
    );
    assert_eq!(r.pass().unwrap().logs, 1, "copied again, as it is now");
    assert_eq!(r.pass().unwrap().logs, 0);
}

#[test]
fn a_log_whose_local_directory_is_gone_keeps_its_external_copy() {
    let f = fixture();
    let (run, job, attempt) = f.finished_log();
    let prefix = offload::log_prefix(run, job, attempt);
    let r = f.replicator(SETTINGS);
    assert_eq!(r.pass().unwrap().logs, 1);
    let copied = f.bucket.list(&prefix).unwrap();
    assert!(!copied.is_empty());
    // A late end resets the copy's record, and the local directory is lost.
    late_end(&f, attempt);
    std::fs::remove_dir_all(f.logs.attempt_dir(run, job, attempt)).unwrap();
    let pass = r.pass().unwrap();
    assert_eq!((pass.logs, pass.local_faults), (0, 1));
    assert_eq!(
        f.bucket.list(&prefix).unwrap(),
        copied,
        "the only copy is not deleted"
    );
    assert_eq!(r.status().local_faults.load(Ordering::Relaxed), 1);
}

fn big_object(f: &Fixture) -> (Digest, String) {
    let body: Vec<u8> = (0..(5u32 << 20) + 17).map(|i| (i % 251) as u8).collect();
    let digest = f.put(&body);
    let key = objects::remote_key(f.tenant, &digest);
    (digest, key)
}

#[test]
fn a_large_object_that_changes_while_it_is_uploaded_is_never_completed() {
    let f = fixture();
    let (digest, key) = big_object(&f);
    let path = f.path(digest);
    // The file rots after the first part is sent, in a part not yet read.
    *f.bucket.on_part.lock().unwrap() = Some(Box::new(move |number| {
        if number == 1 {
            let mut bytes = std::fs::read(&path).unwrap();
            let at = bytes.len() - 100;
            bytes[at] ^= 0xff;
            std::fs::write(&path, &bytes).unwrap();
        }
    }));
    let r = f.replicator(SETTINGS);
    let pass = r.pass().unwrap();
    assert_eq!((pass.replicated, pass.local_faults), (0, 1));
    assert_eq!(
        f.bucket.completes.load(Ordering::Relaxed),
        0,
        "never completed"
    );
    assert!(
        f.bucket.keys().is_empty(),
        "nothing visible under the digest's name"
    );
    assert!(
        f.bucket.uploads.lock().unwrap().is_empty(),
        "the upload was aborted"
    );
    assert!(
        f.store
            .read(|c| offload::upload(c, &key))
            .unwrap()
            .is_none()
    );
    assert!(remote_ms(&f, digest).is_none());
}

#[test]
fn a_resumed_upload_still_checks_the_parts_the_bucket_already_holds() {
    let f = fixture();
    let (digest, key) = big_object(&f);
    f.bucket.fail_part.store(4, Ordering::Relaxed);
    assert!(f.replicator(SETTINGS).pass().is_err());
    assert_eq!(f.bucket.parts_sent.load(Ordering::Relaxed), 3);
    // Rot in a part the bucket already holds: the resumed pass reads it, though it does not send it.
    let path = f.path(digest);
    let mut bytes = std::fs::read(&path).unwrap();
    bytes[10] ^= 0xff;
    std::fs::write(&path, &bytes).unwrap();
    let r = f.replicator(SETTINGS);
    let pass = r.pass().unwrap();
    assert_eq!((pass.replicated, pass.local_faults), (0, 1));
    assert_eq!(f.bucket.completes.load(Ordering::Relaxed), 0);
    assert!(f.bucket.keys().is_empty());
    assert!(
        f.store
            .read(|c| offload::upload(c, &key))
            .unwrap()
            .is_none()
    );
}

#[test]
fn the_abort_sweep_leaves_other_applications_uploads_alone() {
    let f = fixture();
    let foreign = f.bucket.create_multipart("foreign/app/x", None).unwrap();
    let old = f.bucket.create_multipart("objects/x/old", None).unwrap();
    for id in [&foreign, &old] {
        f.bucket
            .uploads
            .lock()
            .unwrap()
            .get_mut(id)
            .unwrap()
            .initiated = Some(1);
    }
    let r = f.replicator(SETTINGS);
    assert_eq!(r.pass().unwrap().aborted, 1);
    let open: Vec<String> = f.bucket.uploads.lock().unwrap().keys().cloned().collect();
    assert_eq!(
        open,
        vec![foreign],
        "only the engine's own key family is swept"
    );
}

#[test]
fn a_file_left_behind_by_an_interrupted_eviction_is_collected_at_startup() {
    let f = fixture();
    let digest = f.put(b"evicted, then the process died before the unlink");
    let kept = f.put(b"a neighbour that stays");
    f.replicator(SETTINGS).pass().unwrap();
    let (tenant, now) = (f.tenant, UnixMillis::now());
    // The mark commits; the unlink never happens.
    f.store
        .writer()
        .write(move |tx| offload::evicted(tx, &[(tenant, digest)], now))
        .unwrap();
    assert!(f.local(digest));
    let before = f.totals().local_bytes;
    assert_eq!(before, 22, "the mark already took it off the books");
    let report = f.store.read(|c| f.objects.recover(c)).unwrap();
    assert_eq!(report.evicted_leftovers, 1);
    assert!(report.missing.is_empty() && report.corrupt.is_empty());
    assert!(!f.local(digest), "the file is gone");
    assert!(f.local(kept));
    assert_eq!(f.totals().local_bytes, before);
    assert_eq!(
        f.read(digest).unwrap(),
        b"evicted, then the process died before the unlink",
        "the verified external copy serves it"
    );
}

fn pressure_marks() -> Watermarks {
    Watermarks {
        reserve: 1 << 20,
        low: 1 << 20,
        high: 2 << 20,
        floor: 1 << 17,
    }
}

fn probed(free: &Arc<AtomicU64>) -> Arc<Admission> {
    let probe = Arc::clone(free);
    Arc::new(
        Admission::with_probe(pressure_marks(), move || Ok(probe.load(Ordering::Relaxed))).unwrap(),
    )
}

/// `Admission` caches its probe for a second.
fn let_the_probe_cache_lapse() {
    sleep_ms(1_100);
}

#[test]
fn disk_pressure_evicts_only_replicated_objects_and_stops_when_the_disk_has_room() {
    let f = fixture();
    let free = Arc::new(AtomicU64::new(1 << 40));
    f.objects.set_admission(probed(&free));
    let (a, b) = (f.put(&[1u8; 900]), f.put(&[2u8; 900]));
    let r = f.replicator(SETTINGS);
    r.pass().unwrap();
    let damaged = f.put(&[3u8; 900]);
    std::fs::remove_file(f.path(damaged)).unwrap();
    r.pass().unwrap();
    assert!(remote_ms(&f, a).is_some() && remote_ms(&f, b).is_some());
    assert!(
        remote_ms(&f, damaged).is_none(),
        "a lost local file cannot be copied"
    );
    assert_eq!(
        r.pass().unwrap().evicted,
        0,
        "room on the disk: nothing is evicted"
    );

    free.store(1 << 20, Ordering::Relaxed);
    let_the_probe_cache_lapse();
    let pass = r.pass().unwrap();
    assert_eq!(
        pass.evicted, 2,
        "the replicated objects go, under no budget"
    );
    assert!(!f.local(a) && !f.local(b));
    assert_eq!(
        f.totals().unreplicated_bytes,
        900,
        "the unreplicated one stays on the books"
    );

    free.store(1 << 40, Ordering::Relaxed);
    let_the_probe_cache_lapse();
    let fresh = f.put(&[4u8; 900]);
    let pass = r.pass().unwrap();
    assert_eq!(
        (pass.replicated, pass.evicted),
        (1, 0),
        "admission reopened: eviction stops"
    );
    assert!(f.local(fresh));
}

#[test]
fn a_full_backlog_does_not_evict_for_pressure() {
    let f = fixture();
    let free = Arc::new(AtomicU64::new(1 << 40));
    f.objects.set_admission(probed(&free));
    let a = f.put(&[1u8; 900]);
    let r = f.replicator(Settings {
        backlog_bytes: 100,
        ..SETTINGS
    });
    r.pass().unwrap();
    let damaged = f.put(&[3u8; 900]);
    std::fs::remove_file(f.path(damaged)).unwrap();
    r.pass().unwrap();
    assert!(
        r.status().backlog_full.load(Ordering::Relaxed),
        "900 bytes past 100"
    );
    let pass = r.pass().unwrap();
    assert_eq!(
        pass.evicted, 0,
        "the backlog closes admission, and eviction does not relieve a backlog"
    );
    assert!(f.local(a));
}
