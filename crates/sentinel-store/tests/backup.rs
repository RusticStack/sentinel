//! R04: an online backup of a store that keeps writing, verified end to end
//! and restored onto an empty data directory — objects, manifests, logs and
//! the controller's files byte for byte, the master key required and checked
//! when sealed values exist — corruption and loss caught by verification,
//! the maintenance lock held for the whole run, and pruning keeping exactly
//! what the kept backups name.
use std::{fs, sync::Arc, time::Duration};

use sentinel_auth::sealed::Key;
use sentinel_core::{AttemptId, JobId, RunId, UnixMillis};
use sentinel_store::{
    Durability, Error, Store, backup,
    local_auth::{self, Policy},
    logs::LogStore,
    mfa,
    objects::{Digest, Entry, Expect, Kind, Objects},
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
    // A super admin with a second factor: a sealed value the backup's
    // restore needs the key for.
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
        // The bootstrapped account's personal namespace, or a new one.
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
    /// A real run, job and attempt (placed on an enrolled worker), whose
    /// log is written and finished: a restore brings back the logs of
    /// attempts its snapshot knows.
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

    // Writes keep landing while the backup runs.
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

    // A second backup copies nothing it already holds.
    std::thread::sleep(Duration::from_millis(1_100));
    let again = f.backup();
    assert_eq!(again.objects_copied, 0);
    assert_eq!(again.manifests_copied, 0);

    // Restore: refused without the key, and with another key.
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

    // The restored directory is a working store: the object reads back
    // verified, the log reads, and a second restore onto it is refused.
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
    // A restore refuses a corrupt object rather than placing it.
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
    // A tampered snapshot fails its checksum.
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
    // The object leaves the store; later backups no longer name it.
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
