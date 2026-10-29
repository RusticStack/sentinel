use std::{fs, sync::Arc, time::Duration};

use sentinel_auth::sealed::Key;
use sentinel_core::{AttemptId, JobId, RunId, UnixMillis, UserId};
use sentinel_store::{
    Durability, Error, Store, backup,
    local_auth::{self, Policy},
    logs::LogStore,
    mfa,
    objects::{Digest, Entry, Expect, Kind, Objects},
    reseal,
};

const PASSWORD: &[u8] = b"an operator password";

struct Fixture {
    dir: tempfile::TempDir,
    data: std::path::PathBuf,
    store: Arc<Store>,
    objects: Arc<Objects>,
    logs: LogStore,
    tenant: sentinel_core::TenantId,
    key: std::path::PathBuf,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    fs::create_dir_all(&data).unwrap();
    let store = Arc::new(Store::open(data.join("metadata.sqlite"), Durability::Normal).unwrap());
    let objects = Arc::new(Objects::open(&data).unwrap());
    let logs = LogStore::open(data.join("logs")).unwrap();
    let key = data.join("master.key");
    Key::create(&key).unwrap();
    let now = UnixMillis::now();
    local_auth::bootstrap(&store, "root", "Root", PASSWORD, now).unwrap();
    let issued = match local_auth::login(&store, "root", PASSWORD, Policy::default(), now).unwrap()
    {
        local_auth::Login::Accepted(issued) => issued,
        _ => panic!("login"),
    };
    let session = store
        .read(|c| local_auth::authenticate(c, &issued.session, now))
        .unwrap();
    mfa::begin_enrollment(
        &store,
        &Key::load(&key).unwrap(),
        &session,
        "Sentinel",
        "root",
        now,
    )
    .unwrap();
    let tenant = session.principal().tenant.unwrap_or_else(|| {
        let tenant = sentinel_core::TenantId::new();
        let principal = session.principal();
        store
            .writer()
            .write(move |tx| {
                sentinel_store::auth::create_namespace(
                    tx,
                    principal,
                    tenant,
                    sentinel_core::auth::Namespace::parse("acme").unwrap(),
                    sentinel_store::auth::NamespaceKind::Organization,
                    now,
                )
            })
            .unwrap();
        tenant
    });
    fs::write(data.join("controller.crt"), b"certificate").unwrap();
    fs::write(data.join("controller.key"), b"private").unwrap();
    fs::write(data.join("source-destinations.json"), b"[]").unwrap();
    Fixture {
        dir,
        data,
        store,
        objects,
        logs,
        tenant,
        key,
    }
}

impl Fixture {
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
    fn manifest(&self, digest: Digest, len: u64) {
        let (objects, tenant) = (Arc::clone(&self.objects), self.tenant);
        self.store
            .writer()
            .write(move |tx| {
                objects.commit_manifest(
                    tx,
                    tenant,
                    Kind::Artifact,
                    "job/out",
                    &[Entry {
                        path: "out.bin".into(),
                        digest,
                        len,
                        mode: 0o644,
                    }],
                )
            })
            .unwrap();
    }
    fn log(&self) -> (RunId, JobId, AttemptId) {
        use sentinel_auth::secret::Secret;
        use sentinel_pipeline::{PinnedSource, RunSpec, compile_str};
        use sentinel_protocol::negotiate::{Arch, Capabilities, Negotiated, ProtocolVersion};
        use sentinel_store::{auth::Authority, dispatch, jobs, runs, tenancy, workers};
        let (tenant, repo, run, pool, worker) = (
            self.tenant,
            sentinel_core::RepoId::new(),
            RunId::new(),
            sentinel_core::PoolId::new(),
            sentinel_core::WorkerId::new(),
        );
        let spec = RunSpec::new(
            PinnedSource::new(
                "https://github.com/o/r.git",
                "0123456789abcdef0123456789abcdef01234567",
                Some("main"),
            )
            .unwrap(),
            compile_str(
                "schema: 1
on: [push]
jobs:
  build:
    image: alpine:3
    steps: [{ id: s, run: 'true' }]
",
            )
            .unwrap(),
        )
        .unwrap();
        let now = UnixMillis::now();
        let (job, attempt) = self
            .store
            .writer()
            .write(move |tx| {
                jobs::insert_repo(tx, tenant, repo, "app", now)?;
                tenancy::create_pool(
                    tx,
                    Authority::HostLocal,
                    pool,
                    "b",
                    tenancy::PoolKind::Dedicated(tenant),
                    now,
                )?;
                let ids = runs::create_run(tx, tenant, repo, run, &spec, now)?;
                runs::resolve_image(
                    tx,
                    tenant,
                    ids[0],
                    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "linux/amd64",
                )?;
                let issued =
                    workers::issue_enrollment(tx, Authority::HostLocal, pool, 60_000, now)?;
                let mut text = String::new();
                issued.secret.expose(&mut text);
                workers::enroll(
                    tx,
                    &Secret::parse(&text).unwrap(),
                    workers::Presentation {
                        worker,
                        fingerprint: Secret::generate().digest(),
                        name: "w",
                        negotiated: Negotiated {
                            protocol: ProtocolVersion(4),
                            capabilities: Capabilities::REQUIRED,
                            arch: Arch::X86_64,
                        },
                    },
                    now,
                )?;
                dispatch::report_capacity(
                    tx,
                    worker,
                    dispatch::Capacity {
                        cpu_millis: 4_000,
                        memory_bytes: 8 << 30,
                        disk_bytes: 0,
                    },
                )?;
                let offer =
                    dispatch::place(tx, worker, pool, dispatch::DEFAULT_LEASE_MS, now)?.unwrap();
                Ok((ids[0], offer.attempt))
            })
            .unwrap();
        let frame = sentinel_protocol::logs::Frame {
            seq: 1,
            step: 0,
            stream: sentinel_protocol::logs::Stream::Stdout,
            bytes: b"a line\n".to_vec(),
        };
        self.logs.append(run, job, attempt, &frame).unwrap();
        self.logs.finish(run, job, attempt, 1, &[]).unwrap();
        (run, job, attempt)
    }
    fn target(&self) -> std::path::PathBuf {
        self.dir.path().join("backups")
    }
    fn backup(&self) -> backup::Report {
        backup::create(
            &self.store,
            &self.objects,
            &self.data,
            &self.target(),
            "test",
        )
        .unwrap()
    }
}

#[test]
fn an_online_backup_verifies_and_restores_byte_for_byte_with_its_key() {
    let f = fixture();
    let body: Vec<u8> = (0..300_000u32).map(|i| (i % 253) as u8).collect();
    let digest = f.put(&body);
    f.manifest(digest, body.len() as u64);
    let (run, job, attempt) = f.log();

    let writer = {
        let store = Arc::clone(&f.store);
        std::thread::spawn(move || {
            for i in 0..200 {
                store
                    .writer()
                    .write(move |tx| {
                        tx.execute(
                            "INSERT INTO idempotency_keys(tenant_id, principal, route, key, request_digest, created_ms)
                             SELECT id, X'00', 'r', ?1, X'00', 0 FROM tenants LIMIT 1",
                            [format!("k{i}")],
                        )
                        .map(|_| ())
                        .or(Ok(()))
                    })
                    .unwrap();
            }
        })
    };
    let report = f.backup();
    writer.join().unwrap();
    assert_eq!(report.objects, 1);
    assert_eq!(report.objects_copied, 1);
    assert_eq!(report.manifests, 1);
    assert!(report.log_files_copied >= 2, "{report:?}");
    assert!(report.config_files.contains(&"controller.key".to_owned()));
    assert!(
        !report.config_files.iter().any(|f| f.contains("master")),
        "never the key"
    );
    assert!(!report.key_ids.is_empty(), "the second factor is sealed");
    assert!(report.objects_corrupt.is_empty());
    assert_eq!(backup::list(&f.target()).unwrap(), vec![report.id.clone()]);

    let check = backup::verify(&f.target(), &report.id).unwrap();
    assert!(check.ok(), "{check:?}");
    assert_eq!((check.objects_checked, check.manifests_checked), (1, 1));

    std::thread::sleep(Duration::from_millis(1_100));
    let again = f.backup();
    assert_eq!(again.objects_copied, 0);
    assert_eq!(again.manifests_copied, 0);

    let fresh = f.dir.path().join("restored");
    let refused = backup::restore(&f.target(), &report.id, &fresh, None);
    assert!(
        matches!(refused, Err(Error::InvalidInput(_))),
        "{refused:?}"
    );
    assert!(!fresh.join("metadata.sqlite").exists());
    let other = f.dir.path().join("other.key");
    Key::create(&other).unwrap();
    assert!(backup::restore(&f.target(), &report.id, &fresh, Some(&other)).is_err());
    let restored = backup::restore(&f.target(), &report.id, &fresh, Some(&f.key)).unwrap();
    assert!(restored.key_checked);
    assert_eq!((restored.objects, restored.manifests), (1, 1));
    assert!(restored.config_files.contains(&"controller.crt".to_owned()));
    assert_eq!(fs::read(fresh.join("controller.key")).unwrap(), b"private");

    let store = Store::open(fresh.join("metadata.sqlite"), Durability::Normal).unwrap();
    let objects = Objects::open(&fresh).unwrap();
    let mut out = Vec::new();
    store
        .read(|c| objects.read(c, f.tenant, digest, &mut out))
        .unwrap();
    assert_eq!(out, body);
    let recovery = store.read(|c| objects.recover(c)).unwrap();
    assert!(
        recovery.missing.is_empty() && recovery.corrupt.is_empty(),
        "{recovery:?}"
    );
    let logs = LogStore::open(fresh.join("logs")).unwrap();
    let tail = logs.tail(run, job, attempt, 0, 10, None).unwrap();
    assert_eq!(tail.frames.len(), 1);
    assert!(tail.complete);
    assert!(backup::restore(&f.target(), &report.id, &fresh, Some(&f.key)).is_err());
}

#[test]
fn rotated_key_restore_requires_the_full_pre_retire_keyring_before_creating_metadata() {
    let f = fixture();
    let rotation_backup = f.dir.path().join("pre-rotate.key");
    Key::rotate(&f.key, &rotation_backup).unwrap();
    let rotated = Key::load(&f.key).unwrap();
    let other = UserId::new();
    let now = UnixMillis::now();
    f.store
        .writer()
        .write(move |tx| {
            sentinel_store::auth::provisioning::insert_human(tx, other, "Other", false, now)
        })
        .unwrap();
    mfa::begin_enrollment_host_local(&f.store, &rotated, other, "Sentinel", "other", now).unwrap();
    let report = f.backup();
    assert_eq!(
        report.key_ids.iter().copied().collect::<Vec<_>>(),
        vec![1, 2]
    );

    let progress = reseal::reseal_all(&f.store, Arc::new(rotated)).unwrap();
    assert_eq!(progress.resealed, 1);
    let pre_retire = f.dir.path().join("pre-retire.key");
    assert_eq!(Key::retire(&f.key, &pre_retire).unwrap(), 1);
    assert_eq!(Key::load(&f.key).unwrap().len(), 1);

    let fresh = f.dir.path().join("restored");
    let refused = backup::restore(&f.target(), &report.id, &fresh, Some(&f.key));
    assert!(
        matches!(refused, Err(Error::InvalidInput(message)) if message.contains("every key")),
        "{refused:?}"
    );
    assert!(
        !fresh.exists(),
        "key validation precedes directory creation"
    );
    let pre_retire_key = Key::load(&pre_retire).unwrap();
    let restored = backup::restore(&f.target(), &report.id, &fresh, Some(&pre_retire)).unwrap();
    assert!(restored.key_checked);
    assert!(fresh.join("metadata.sqlite").is_file());
    let store = Store::open(fresh.join("metadata.sqlite"), Durability::Normal).unwrap();
    store
        .read(|conn| reseal::verify_key(conn, &pre_retire_key))
        .unwrap();
}

#[test]
fn verification_catches_rot_and_loss() {
    let f = fixture();
    let digest = f.put(b"an artifact that will rot");
    f.manifest(digest, 25);
    let report = f.backup();
    let hex = digest.to_string();
    let object = f
        .target()
        .join("objects")
        .join(f.tenant.to_string())
        .join(&hex[..2])
        .join(&hex);
    let mut bytes = fs::read(&object).unwrap();
    bytes[0] ^= 1;
    fs::write(&object, &bytes).unwrap();
    let check = backup::verify(&f.target(), &report.id).unwrap();
    assert!(!check.ok());
    assert_eq!(check.corrupt.len(), 1);
    let fresh = f.dir.path().join("restored");
    assert!(matches!(
        backup::restore(&f.target(), &report.id, &fresh, Some(&f.key)),
        Err(Error::Corrupt(_))
    ));
    fs::remove_file(&object).unwrap();
    assert_eq!(
        backup::verify(&f.target(), &report.id)
            .unwrap()
            .missing
            .len(),
        1
    );
    let snapshot = f.target().join(&report.id).join("metadata.sqlite");
    let mut db = fs::read(&snapshot).unwrap();
    let last = db.len() - 1;
    db[last] ^= 1;
    fs::write(&snapshot, &db).unwrap();
    assert!(
        !backup::verify(&f.target(), &report.id)
            .unwrap()
            .metadata_matches
    );
}

#[test]
fn a_backup_holds_the_maintenance_lock_and_waits_for_it() {
    let f = fixture();
    f.put(b"held");
    let lock = f.objects.hold_maintenance();
    let (store, objects, data, target) = (
        Arc::clone(&f.store),
        Arc::clone(&f.objects),
        f.data.clone(),
        f.target(),
    );
    let run = std::thread::spawn(move || {
        backup::create(&store, &objects, &data, &target, "test").unwrap()
    });
    std::thread::sleep(Duration::from_millis(300));
    assert!(
        backup::list(&f.target()).unwrap().is_empty(),
        "it waited for a pass to end"
    );
    drop(lock);
    run.join().unwrap();
    assert_eq!(backup::list(&f.target()).unwrap().len(), 1);
    assert!(f.objects.try_maintenance().is_some(), "and released it");
}

#[test]
fn pruning_keeps_the_newest_and_exactly_what_they_name() {
    let f = fixture();
    let first = f.put(b"only in the first backup");
    let one = f.backup();
    let tenant = f.tenant;
    f.store
        .writer()
        .write(move |tx| {
            tx.execute(
                "DELETE FROM objects WHERE tenant_id = ?1 AND digest = ?2",
                (tenant.as_bytes().as_slice(), first.as_bytes().as_slice()),
            )?;
            Ok(())
        })
        .unwrap();
    let second = f.put(b"in both later backups");
    std::thread::sleep(Duration::from_millis(1_100));
    let two = f.backup();
    std::thread::sleep(Duration::from_millis(1_100));
    let three = f.backup();
    assert!(matches!(
        backup::prune(&f.target(), 0),
        Err(Error::InvalidInput(_))
    ));
    let pruned = backup::prune(&f.target(), 2).unwrap();
    assert_eq!(pruned.backups, vec![one.id]);
    assert_eq!(pruned.objects, 1, "the first object had no other backup");
    assert_eq!(
        backup::list(&f.target()).unwrap(),
        vec![two.id.clone(), three.id]
    );
    assert!(backup::verify(&f.target(), &two.id).unwrap().ok());
    let hex = second.to_string();
    assert!(
        f.target()
            .join("objects")
            .join(f.tenant.to_string())
            .join(&hex[..2])
            .join(&hex)
            .exists()
    );
}

#[test]
fn backup_ids_sort_by_time() {
    assert_eq!(
        backup::backup_id(UnixMillis(1_369_353_600_000)),
        "20130524T000000Z"
    );
    assert_eq!(
        backup::backup_id(UnixMillis(951_827_696_000)),
        "20000229T123456Z"
    );
    assert!(matches!(
        backup::manifest(std::path::Path::new("."), "../etc"),
        Err(Error::InvalidInput(_))
    ));
}

#[test]
fn an_interrupted_backup_leaves_nothing_the_next_one_does_not_clean() {
    let f = fixture();
    f.put(b"backed up before the interruption");
    let first = f.backup();
    let staging = f.target().join(".20260101T000000Z.partial");
    fs::create_dir_all(&staging).unwrap();
    fs::write(staging.join("metadata.sqlite"), b"SQLite format 3\0trunc").unwrap();
    let stray = f
        .target()
        .join("objects")
        .join(f.tenant.to_string())
        .join("00")
        .join("00dead.part");
    fs::create_dir_all(stray.parent().unwrap()).unwrap();
    fs::write(&stray, b"half an object").unwrap();
    assert_eq!(backup::list(&f.target()).unwrap(), vec![first.id.clone()]);
    assert!(backup::verify(&f.target(), &first.id).unwrap().ok());

    let lost = f.put(b"lost from the data directory");
    let hex = lost.to_string();
    fs::remove_file(
        f.data
            .join("objects")
            .join(f.tenant.to_string())
            .join(&hex[..2])
            .join(&hex),
    )
    .unwrap();
    std::thread::sleep(Duration::from_millis(1_100));
    let second = f.backup();
    assert_eq!(second.partials_removed, 1);
    assert!(!staging.exists());
    assert_eq!(second.objects_missing.len(), 1, "{second:?}");
    assert!(second.objects_missing[0].ends_with(&hex));
    let manifest = backup::manifest(&f.target(), &second.id).unwrap();
    assert_eq!(manifest["objects"]["missing"].as_array().unwrap().len(), 1);
    let check = backup::verify(&f.target(), &second.id).unwrap();
    assert_eq!(check.missing.len(), 1, "verification says so too");
    assert!(check.corrupt.is_empty());
    assert_eq!(
        backup::list(&f.target()).unwrap(),
        vec![first.id.clone(), second.id.clone()]
    );
    backup::prune(&f.target(), 2).unwrap();
    assert!(!stray.exists(), "no kept backup names the part file");
    assert!(backup::verify(&f.target(), &first.id).unwrap().ok());
}

// A shared copy is reused only while it still hashes to its digest; same-length rot is replaced.
#[test]
fn a_rotted_shared_copy_is_replaced_not_reused() {
    let f = fixture();
    let digest = f.put(b"an object whose shared copy rots in place");
    f.manifest(digest, 41);
    f.backup();
    let hex = digest.to_string();
    let shared = f
        .target()
        .join("objects")
        .join(f.tenant.to_string())
        .join(&hex[..2])
        .join(&hex);
    let mut bytes = fs::read(&shared).unwrap();
    bytes[0] ^= 1;
    fs::write(&shared, &bytes).unwrap();
    std::thread::sleep(Duration::from_millis(1_100));
    let second = f.backup();
    assert_eq!(second.objects_recopied, 1, "{second:?}");
    assert!(backup::verify(&f.target(), &second.id).unwrap().ok());
    assert_eq!(
        fs::read(&shared).unwrap(),
        fs::read(
            f.data
                .join("objects")
                .join(f.tenant.to_string())
                .join(&hex[..2])
                .join(&hex)
        )
        .unwrap()
    );
}

// prune waits for a create in another process, whose copied shared files no kept backup names yet.
#[test]
fn pruning_waits_for_a_running_backup_instead_of_deleting_its_files() {
    let f = fixture();
    f.put(b"kept");
    f.backup();
    std::thread::sleep(Duration::from_millis(1_100));
    f.backup();
    let holder = fs::OpenOptions::new()
        .write(true)
        .open(f.target().join(".lock"))
        .unwrap();
    holder.lock().unwrap();
    let target = f.target();
    let pruning = std::thread::spawn(move || backup::prune(&target, 1).unwrap());
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(
        backup::list(&f.target()).unwrap().len(),
        2,
        "prune is still waiting for the lock"
    );
    holder.unlock().unwrap();
    let pruned = pruning.join().unwrap();
    assert_eq!(pruned.backups.len(), 1);
    assert_eq!(backup::list(&f.target()).unwrap().len(), 1);
}

fn shared_object(f: &Fixture, digest: Digest) -> std::path::PathBuf {
    let hex = digest.to_string();
    f.target()
        .join("objects")
        .join(f.tenant.to_string())
        .join(&hex[..2])
        .join(&hex)
}

fn pairs(snapshot: &std::path::Path) -> (i64, i64) {
    let conn =
        rusqlite::Connection::open_with_flags(snapshot, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .unwrap();
    conn.query_row("SELECT COUNT(*), COUNT(DISTINCT i) FROM pairs", [], |r| {
        Ok((r.get(0)?, r.get(1)?))
    })
    .unwrap()
}

// Every transaction writes two rows; a snapshot that split one would hold an odd row.
#[test]
fn a_backup_taken_during_commits_never_splits_a_transaction() {
    use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
    let f = fixture();
    f.store
        .writer()
        .write(|tx| {
            tx.execute(
                "CREATE TABLE pairs(i INTEGER NOT NULL, half INTEGER NOT NULL)",
                [],
            )?;
            Ok(())
        })
        .unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let committed = Arc::new(AtomicI64::new(0));
    let writer = {
        let (store, stop, committed) = (
            Arc::clone(&f.store),
            Arc::clone(&stop),
            Arc::clone(&committed),
        );
        std::thread::spawn(move || {
            let mut i = 0i64;
            while !stop.load(Ordering::Relaxed) {
                store
                    .writer()
                    .write(move |tx| {
                        tx.execute("INSERT INTO pairs VALUES (?1, 0)", [i])?;
                        tx.execute("INSERT INTO pairs VALUES (?1, 1)", [i])?;
                        Ok(())
                    })
                    .unwrap();
                i += 1;
                committed.store(i, Ordering::Release);
            }
        })
    };
    while committed.load(Ordering::Acquire) == 0 {
        std::thread::yield_now();
    }
    for _ in 0..3 {
        let report = f.backup();
        let (rows, distinct) = pairs(&f.target().join(&report.id).join("metadata.sqlite"));
        assert_eq!(
            rows,
            distinct * 2,
            "a transaction was split: {rows} rows for {distinct}"
        );
        assert!(distinct > 0);
        assert!(backup::verify(&f.target(), &report.id).unwrap().ok());
    }
    stop.store(true, Ordering::Relaxed);
    writer.join().unwrap();
    let last = backup::list(&f.target()).unwrap().pop().unwrap();
    let fresh = f.dir.path().join("restored");
    backup::restore(&f.target(), &last, &fresh, Some(&f.key)).unwrap();
    let (rows, distinct) = pairs(&fresh.join("metadata.sqlite"));
    assert_eq!(rows, distinct * 2);
    assert!(distinct <= committed.load(Ordering::Acquire));
}

// A backup that completed with losses recorded must still bring everything else back.
#[test]
fn a_restore_goes_on_without_the_objects_the_backup_recorded_as_lost() {
    let f = fixture();
    let kept = f.put(b"an object that survived");
    let lost = f.put(b"an object the data directory lost before the backup");
    let hex = lost.to_string();
    fs::remove_file(
        f.data
            .join("objects")
            .join(f.tenant.to_string())
            .join(&hex[..2])
            .join(&hex),
    )
    .unwrap();
    let report = f.backup();
    assert_eq!(report.objects_missing.len(), 1, "{report:?}");
    assert!(!backup::verify(&f.target(), &report.id).unwrap().ok());

    let fresh = f.dir.path().join("restored");
    let restored = backup::restore(&f.target(), &report.id, &fresh, Some(&f.key)).unwrap();
    assert_eq!(restored.objects, 1);
    assert_eq!(restored.objects_unavailable, report.objects_missing);
    let store = Store::open(fresh.join("metadata.sqlite"), Durability::Normal).unwrap();
    let objects = Objects::open(&fresh).unwrap();
    let mut out = Vec::new();
    store
        .read(|c| objects.read(c, f.tenant, kept, &mut out))
        .unwrap();
    assert_eq!(out, b"an object that survived");
    let recovery = store.read(|c| objects.recover(c)).unwrap();
    assert_eq!(
        recovery.missing.len(),
        1,
        "recovery names the loss: {recovery:?}"
    );
    drop((store, objects));

    // An object lost afterwards, which the backup did not record, still stops the restore.
    fs::remove_file(shared_object(&f, kept)).unwrap();
    let second = f.dir.path().join("again");
    assert!(backup::restore(&f.target(), &report.id, &second, Some(&f.key)).is_err());
    assert!(!second.join("metadata.sqlite").exists());
}

// The database lands last: whatever stops a restore earlier leaves a directory a retry can fill.
#[test]
fn a_failed_restore_leaves_no_database_and_a_retry_succeeds() {
    let f = fixture();
    let digest = f.put(b"an object whose backup copy rots before the restore");
    let report = f.backup();
    let shared = shared_object(&f, digest);
    let good = fs::read(&shared).unwrap();
    let mut rotten = good.clone();
    rotten[0] ^= 1;
    fs::write(&shared, &rotten).unwrap();

    let fresh = f.dir.path().join("restored");
    let failed = backup::restore(&f.target(), &report.id, &fresh, Some(&f.key));
    assert!(matches!(failed, Err(Error::Corrupt(_))), "{failed:?}");
    assert!(
        !fresh.join("metadata.sqlite").exists(),
        "a half-restored directory is never taken for a controller's"
    );
    fs::write(&shared, &good).unwrap();
    let restored = backup::restore(&f.target(), &report.id, &fresh, Some(&f.key)).unwrap();
    assert_eq!(restored.objects, 1);
    assert!(fresh.join("metadata.sqlite").is_file());
}

// controller.key and controller.crt keep the workers' pin: rot in a backup's copy must not pass silently.
#[test]
fn rot_in_a_backed_up_controller_identity_is_caught_and_refused() {
    let f = fixture();
    let report = f.backup();
    let manifest = backup::manifest(&f.target(), &report.id).unwrap();
    assert!(manifest["config_blake3"]["controller.key"].is_string());
    assert!(backup::verify(&f.target(), &report.id).unwrap().ok());

    let copy = f
        .target()
        .join(&report.id)
        .join("config")
        .join("controller.key");
    let mut bytes = fs::read(&copy).unwrap();
    bytes[0] ^= 1;
    fs::write(&copy, &bytes).unwrap();
    let check = backup::verify(&f.target(), &report.id).unwrap();
    assert!(!check.ok());
    assert_eq!(check.corrupt, vec!["config/controller.key".to_owned()]);

    let fresh = f.dir.path().join("restored");
    let refused = backup::restore(&f.target(), &report.id, &fresh, Some(&f.key));
    assert!(matches!(refused, Err(Error::Corrupt(_))), "{refused:?}");
    assert!(!fresh.join("metadata.sqlite").exists());

    fs::remove_file(&copy).unwrap();
    let check = backup::verify(&f.target(), &report.id).unwrap();
    assert_eq!(check.missing, vec!["config/controller.key".to_owned()]);
    let refused = backup::restore(&f.target(), &report.id, &fresh, Some(&f.key));
    assert!(matches!(refused, Err(Error::Corrupt(_))), "{refused:?}");
}

#[test]
fn a_damaged_backup_directory_fails_verification_instead_of_crashing_it() {
    let f = fixture();
    let report = f.backup();
    let dir = f.target().join(&report.id);

    // A snapshot cut short fails its checksum and, being no database, its integrity check.
    let snapshot = fs::read(dir.join("metadata.sqlite")).unwrap();
    fs::write(dir.join("metadata.sqlite"), &snapshot[..snapshot.len() / 2]).unwrap();
    let check = backup::verify(&f.target(), &report.id).unwrap();
    assert!(!check.ok() && !check.metadata_matches, "{check:?}");
    fs::remove_file(dir.join("metadata.sqlite")).unwrap();
    let check = backup::verify(&f.target(), &report.id).unwrap();
    assert!(
        !check.ok() && check.integrity.starts_with("unreadable"),
        "{check:?}"
    );
    let fresh = f.dir.path().join("restored");
    assert!(backup::restore(&f.target(), &report.id, &fresh, Some(&f.key)).is_err());
    assert!(!fresh.join("metadata.sqlite").exists());

    // A backup.json that is not the format is an error to name, not a pass.
    fs::write(
        dir.join("backup.json"),
        b"{\"format\":\"sentinel.backup/1\"",
    )
    .unwrap();
    assert!(matches!(
        backup::verify(&f.target(), &report.id),
        Err(Error::Corrupt(_))
    ));
    fs::write(
        dir.join("backup.json"),
        b"{\"format\":\"sentinel.backup/2\"}",
    )
    .unwrap();
    assert!(matches!(
        backup::verify(&f.target(), &report.id),
        Err(Error::Corrupt("backup format"))
    ));
    assert!(matches!(
        backup::verify(&f.target(), "20260101T000000Z"),
        Err(Error::NotFound)
    ));
}

#[test]
fn a_restore_refuses_a_bad_key_file_and_a_leftover_journal_before_writing_anything() {
    let f = fixture();
    let report = f.backup();
    let garbage = f.dir.path().join("garbage.key");
    fs::write(&garbage, b"not a key").unwrap();
    let fresh = f.dir.path().join("restored");
    for key in [None, Some(garbage.as_path())] {
        let refused = backup::restore(&f.target(), &report.id, &fresh, key);
        assert!(
            matches!(refused, Err(Error::InvalidInput(_))),
            "{refused:?}"
        );
        assert!(!fresh.exists(), "nothing was written");
    }

    fs::create_dir_all(&fresh).unwrap();
    fs::write(
        fresh.join("metadata.sqlite-wal"),
        b"the journal of a database that is gone",
    )
    .unwrap();
    let refused = backup::restore(&f.target(), &report.id, &fresh, Some(&f.key));
    assert!(
        matches!(refused, Err(Error::InvalidInput(_))),
        "{refused:?}"
    );
    assert!(!fresh.join("metadata.sqlite").exists());
}

// RPO: a backup is the newest only once it is listed, so the window between two backups includes the later one's duration.
#[test]
fn the_exposure_counts_the_interval_and_the_backup_duration() {
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(
        backup::exposure(dir.path(), UnixMillis(1)).unwrap(),
        backup::Exposure::default()
    );
    let write = |id: &str, started: i64, took: i64| {
        let at = dir.path().join(id);
        fs::create_dir_all(&at).unwrap();
        fs::write(
            at.join("backup.json"),
            format!(
                "{{\"format\":\"sentinel.backup/1\",\"started_ms\":{started},\"took_ms\":{took}}}"
            ),
        )
        .unwrap();
    };
    write("20260101T000000Z", 0, 5_000);
    write("20260101T010000Z", 3_600_000, 20_000);
    write("20260101T020000Z", 7_200_000, 10_000);
    let e = backup::exposure(dir.path(), UnixMillis(7_300_000)).unwrap();
    assert_eq!(e.backups, 3);
    assert_eq!(e.newest_id.as_deref(), Some("20260101T020000Z"));
    assert_eq!(e.age_ms, Some(100_000));
    assert_eq!(
        e.worst_ms,
        Some(3_620_000),
        "the interval plus the slower backup's duration"
    );
    // Long after the last backup, the age is the worst window.
    let e = backup::exposure(dir.path(), UnixMillis(7_200_000 + 9_000_000)).unwrap();
    assert_eq!((e.age_ms, e.worst_ms), (Some(9_000_000), Some(9_000_000)));

    fs::write(
        dir.path().join("20260101T020000Z").join("backup.json"),
        b"{\"format\":\"sentinel.backup/1\"}",
    )
    .unwrap();
    assert!(matches!(
        backup::exposure(dir.path(), UnixMillis(1)),
        Err(Error::Corrupt(_))
    ));
}

// R07: a controller killed at any instant of a backup (power cut, OOM kill) must leave only complete backups behind.
#[test]
fn backups_killed_at_staggered_points_leave_only_complete_ones() {
    const CHILD: &str = "SENTINEL_R07_BACKUP_CHILD";
    const TARGET: &str = "SENTINEL_R07_BACKUP_TARGET";
    if let (Some(data), Some(target)) = (std::env::var_os(CHILD), std::env::var_os(TARGET)) {
        let data = std::path::PathBuf::from(data);
        let store = Store::open(data.join("metadata.sqlite"), Durability::Normal).unwrap();
        let objects = Objects::open(&data).unwrap();
        loop {
            let _ = backup::create(
                &store,
                &objects,
                &data,
                std::path::Path::new(&target),
                "child",
            );
        }
    }
    let f = fixture();
    for i in 0..300u32 {
        let body: Vec<u8> = (0..16 * 1024u32)
            .map(|b| (b.wrapping_mul(i + 1) >> 3) as u8)
            .collect();
        let digest = f.put(&body);
        if i == 0 {
            f.manifest(digest, body.len() as u64);
        }
    }
    f.log();
    let Fixture {
        dir,
        data,
        store,
        objects,
        key,
        ..
    } = f;
    drop((store, objects));
    let target = dir.path().join("backups");

    for delay_ms in [120, 250, 400, 650, 1_000, 1_600] {
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "backups_killed_at_staggered_points_leave_only_complete_ones",
                "--nocapture",
            ])
            .env(CHILD, &data)
            .env(TARGET, &target)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        std::thread::sleep(Duration::from_millis(delay_ms));
        child.kill().unwrap();
        child.wait().unwrap();
        for id in backup::list(&target).unwrap() {
            let check = backup::verify(&target, &id).unwrap();
            assert!(
                check.ok(),
                "a listed backup is incomplete after a kill at {delay_ms} ms: {check:?}"
            );
        }
    }

    let store = Arc::new(Store::open(data.join("metadata.sqlite"), Durability::Normal).unwrap());
    let objects = Arc::new(Objects::open(&data).unwrap());
    let survivors = backup::list(&target).unwrap().len();
    let report = backup::create(&store, &objects, &data, &target, "after").unwrap();
    assert!(report.objects_corrupt.is_empty() && report.objects_missing.is_empty());
    assert!(
        fs::read_dir(&target)
            .unwrap()
            .flatten()
            .all(|e| !e.file_name().to_string_lossy().ends_with(".partial")),
        "the next backup removed every staging directory"
    );
    backup::prune(&target, 2).unwrap();
    let ids = backup::list(&target).unwrap();
    assert!(ids.len() <= 2 && ids.contains(&report.id));
    for id in &ids {
        assert!(backup::verify(&target, id).unwrap().ok());
    }
    let fresh = dir.path().join("restored");
    let restored = backup::restore(&target, &report.id, &fresh, Some(&key)).unwrap();
    assert_eq!(restored.objects, 300);
    let reopened = Store::open(fresh.join("metadata.sqlite"), Durability::Normal).unwrap();
    let reobjects = Objects::open(&fresh).unwrap();
    let recovery = reopened.read(|c| reobjects.recover(c)).unwrap();
    assert!(
        recovery.missing.is_empty() && recovery.corrupt.is_empty(),
        "{recovery:?}"
    );
    eprintln!("{survivors} complete backups were on disk after six kills");
}

// A backup holds every tenant's objects and the sealed database: nothing in it, or in a restored directory, may be open to
// other accounts, not even for the instant between a copy and a chmod. The child runs under umask 022, the usual default.
#[cfg(unix)]
#[test]
fn backup_and_restore_leave_nothing_readable_by_group_or_other() {
    use std::os::unix::fs::PermissionsExt;
    const CHILD: &str = "SENTINEL_BACKUP_MODE_CHILD";
    const TEST: &str = "backup_and_restore_leave_nothing_readable_by_group_or_other";
    if std::env::var_os(CHILD).is_some() {
        let f = fixture();
        let body: Vec<u8> = (0..70_000u32).map(|i| (i % 251) as u8).collect();
        let digest = f.put(&body);
        f.manifest(digest, body.len() as u64);
        f.log();
        let report = f.backup();
        assert!(
            !report.target_open_to_others,
            "a target made here is private"
        );
        let fresh = f.dir.path().join("restored").join("nested");
        let restored = backup::restore(&f.target(), &report.id, &fresh, Some(&f.key)).unwrap();
        assert!(!restored.data_dir_open_to_others);

        let mut seen = 0;
        for root in [f.target(), f.dir.path().join("restored")] {
            let mut stack = vec![root];
            while let Some(path) = stack.pop() {
                let meta = fs::symlink_metadata(&path).unwrap();
                let mode = meta.permissions().mode();
                assert_eq!(
                    mode & 0o077,
                    0,
                    "{} is open to group or other ({mode:o})",
                    path.display()
                );
                seen += 1;
                if meta.is_dir() {
                    stack.extend(fs::read_dir(&path).unwrap().flatten().map(|e| e.path()));
                }
            }
        }
        for name in ["controller.key", "master.key", "metadata.sqlite"] {
            assert!(fresh.join(name).is_file(), "{name} was restored");
        }
        assert!(seen > 20, "{seen} entries checked");

        // A directory that already exists keeps its mode; the caller is told.
        let open = f.dir.path().join("open");
        fs::create_dir(&open).unwrap();
        assert_ne!(fs::metadata(&open).unwrap().permissions().mode() & 0o077, 0);
        let again = backup::create(&f.store, &f.objects, &f.data, &open, "test").unwrap();
        assert!(again.target_open_to_others);
        let into = f.dir.path().join("open-restore");
        fs::create_dir(&into).unwrap();
        let restored = backup::restore(&open, &again.id, &into, Some(&f.key)).unwrap();
        assert!(restored.data_dir_open_to_others);
        return;
    }
    let out = std::process::Command::new("sh")
        .args([
            "-c",
            &format!("umask 022 && exec \"$0\" --exact {TEST} --nocapture"),
        ])
        .arg(std::env::current_exe().unwrap())
        .env(CHILD, "1")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

fn scheduler_every(f: &Fixture, interval: Duration) -> Arc<backup::Scheduler> {
    backup::Scheduler::new(
        Arc::clone(&f.store),
        Arc::clone(&f.objects),
        f.data.clone(),
        f.target(),
        interval,
        8,
        "test".into(),
    )
}

/// Dates the newest backup as if it had been taken at `started_ms`.
fn redate_newest(f: &Fixture, started_ms: i64) {
    let id = backup::list(&f.target()).unwrap().pop().unwrap();
    let path = f.target().join(id).join("backup.json");
    let mut manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    manifest["started_ms"] = started_ms.into();
    fs::write(&path, serde_json::to_vec(&manifest).unwrap()).unwrap();
}

/// Starts the scheduler as a restarted controller would, and reports whether it took a backup within `wait`.
fn takes_a_backup_within(scheduler: &Arc<backup::Scheduler>, wait: Duration) -> bool {
    use backup::Control;
    let handle = scheduler.start().unwrap();
    let deadline = std::time::Instant::now() + wait;
    let mut taken = false;
    while std::time::Instant::now() < deadline {
        if !scheduler.status()["last_success_ms"].is_null() {
            taken = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    scheduler.stop();
    handle.join().unwrap();
    taken
}

// A controller restarted more often than its interval used to start the clock again each time and never take a backup.
#[test]
fn a_restarted_scheduler_takes_an_overdue_backup_at_once_and_waits_for_a_recent_one() {
    let f = fixture();
    f.backup();
    let hour = Duration::from_secs(3_600);

    // Overdue: the newest backup is two intervals old.
    redate_newest(&f, UnixMillis::now().0 - 2 * 3_600_000);
    let before = backup::list(&f.target()).unwrap().len();
    assert!(
        takes_a_backup_within(&scheduler_every(&f, hour), Duration::from_secs(30)),
        "an overdue backup is taken without waiting a whole interval"
    );
    assert_eq!(backup::list(&f.target()).unwrap().len(), before + 1);

    // Recent: the newest backup is seconds old, so nothing is due for most of an hour.
    let before = backup::list(&f.target()).unwrap().len();
    assert!(
        !takes_a_backup_within(&scheduler_every(&f, hour), Duration::from_millis(800)),
        "a recent backup is not repeated at once"
    );
    assert_eq!(backup::list(&f.target()).unwrap().len(), before);

    // A newest backup dated in the future (clock skew) delays the next one by one interval at most.
    redate_newest(&f, UnixMillis::now().0 + 10 * 86_400_000);
    assert!(
        takes_a_backup_within(
            &scheduler_every(&f, Duration::from_millis(1_500)),
            Duration::from_secs(30)
        ),
        "clock skew cannot postpone backups by more than one interval"
    );

    // No backups yet, or none that can be read: one is taken at once.
    let fresh = fixture();
    assert!(takes_a_backup_within(
        &scheduler_every(&fresh, hour),
        Duration::from_secs(30)
    ));
    let id = backup::list(&fresh.target()).unwrap().pop().unwrap();
    fs::write(fresh.target().join(id).join("backup.json"), b"not json").unwrap();
    assert!(takes_a_backup_within(
        &scheduler_every(&fresh, hour),
        Duration::from_secs(30)
    ));
}

// R07: the database lands last, so a restore killed at any instant leaves a directory without one, never half of a controller.
#[test]
fn restores_killed_at_staggered_points_never_leave_a_database_and_a_rerun_succeeds() {
    const CHILD: &str = "SENTINEL_R07_RESTORE_CHILD";
    const FROM: &str = "SENTINEL_R07_RESTORE_FROM";
    const ID: &str = "SENTINEL_R07_RESTORE_ID";
    const KEY: &str = "SENTINEL_R07_RESTORE_KEY";
    const OBJECTS: u64 = 120;
    if let (Some(into), Some(from), Some(id), Some(key)) = (
        std::env::var_os(CHILD),
        std::env::var_os(FROM),
        std::env::var_os(ID),
        std::env::var_os(KEY),
    ) {
        let (into, from) = (
            std::path::PathBuf::from(into),
            std::path::PathBuf::from(from),
        );
        let (id, key) = (
            id.to_string_lossy().into_owned(),
            std::path::PathBuf::from(key),
        );
        // Each restore goes to a directory of its own, so a kill never lands in the middle of cleaning one up.
        for n in 0u64.. {
            let _ = backup::restore(&from, &id, &into.join(format!("r{n}")), Some(&key));
        }
        return;
    }
    let f = fixture();
    for i in 0..OBJECTS {
        let body: Vec<u8> = (0..4_096u32)
            .map(|b| (b.wrapping_mul(i as u32 + 1) >> 2) as u8)
            .collect();
        let digest = f.put(&body);
        if i == 0 {
            f.manifest(digest, body.len() as u64);
        }
    }
    f.log();
    let report = f.backup();
    let (target, key) = (f.target(), f.key.clone());
    let into = f.dir.path().join("restores");
    fs::create_dir_all(&into).unwrap();

    let (mut interrupted, mut finished) = (0u32, 0u32);
    for delay_ms in [30, 80, 150, 250, 400, 650] {
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "restores_killed_at_staggered_points_never_leave_a_database_and_a_rerun_succeeds",
                "--nocapture",
            ])
            .env(CHILD, &into)
            .env(FROM, &target)
            .env(ID, &report.id)
            .env(KEY, &key)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        std::thread::sleep(Duration::from_millis(delay_ms));
        child.kill().unwrap();
        child.wait().unwrap();

        for entry in fs::read_dir(&into).unwrap().flatten() {
            let dir = entry.path();
            if dir.join("metadata.sqlite").exists() {
                // A database means the restore finished: everything it names is there.
                finished += 1;
            } else {
                interrupted += 1;
                let restored = backup::restore(&target, &report.id, &dir, Some(&key)).unwrap();
                assert_eq!(restored.objects, OBJECTS, "{}", dir.display());
            }
            let store = Store::open(dir.join("metadata.sqlite"), Durability::Normal).unwrap();
            let objects = Objects::open(&dir).unwrap();
            let recovery = store.read(|c| objects.recover(c)).unwrap();
            assert!(
                recovery.missing.is_empty() && recovery.corrupt.is_empty(),
                "a restore killed at {delay_ms} ms left {} unusable: {recovery:?}",
                dir.display()
            );
            drop((store, objects));
            fs::remove_dir_all(&dir).unwrap();
        }
    }
    eprintln!(
        "{interrupted} restores were cut short and rerun, {finished} had finished, over six kills"
    );
    assert!(interrupted > 0, "no kill landed inside a restore");
}
