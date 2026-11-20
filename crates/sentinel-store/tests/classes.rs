use std::{path::Path, sync::Arc};

use rusqlite::{Connection, params};
use sentinel_auth::secret::Secret;
use sentinel_core::{
    AttemptId, PoolId, RepoId, RunId, TenantId, UnixMillis, UserId, WorkerId,
    auth::{Namespace, Permissions as P, Principal},
};
use sentinel_pipeline::{PinnedSource, RunSpec, compile_str};
use sentinel_protocol::negotiate::{Arch, Capabilities, Negotiated, ProtocolVersion};
use sentinel_store::{
    Durability, Store,
    auth::{self, Authority, NamespaceKind, provisioning},
    classes::{self, Classes, SNAPSHOT_DAYS},
    dispatch::{self, Capacity, ReportedProfile},
    jobs,
    objects::{Digest, Entry, Expect, Kind, Objects},
    retention::{self, Deployment},
    runs,
    tenancy::{self, PoolKind},
    upgrade,
    workers::{self, Presentation},
};

const NOW: UnixMillis = UnixMillis(1_000_000_000);
const FAR: UnixMillis = UnixMillis(i64::MAX / 2);
const SHA: &str = "0123456789abcdef0123456789abcdef01234567";
const IMAGE: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

#[derive(Clone, Copy)]
struct Tenant {
    id: TenantId,
    repo: RepoId,
    pool: PoolId,
}

struct Fixture {
    dir: tempfile::TempDir,
    store: Store,
    objects: Arc<Objects>,
    a: Tenant,
    b: Tenant,
    shared: PoolId,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path().join("metadata.sqlite"), Durability::Normal).unwrap();
    let objects = Arc::new(Objects::open(dir.path().join("objects")).unwrap());
    let root = UserId::new();
    let tenant = |slug: &'static str| {
        (
            slug,
            Tenant {
                id: TenantId::new(),
                repo: RepoId::new(),
                pool: PoolId::new(),
            },
        )
    };
    let ((sa, a), (sb, b)) = (tenant("acme"), tenant("other"));
    let shared = PoolId::new();
    store
        .writer()
        .write(move |tx| {
            provisioning::insert_human(tx, root, "Root", true, NOW)?;
            for (slug, t) in [(sa, a), (sb, b)] {
                auth::create_namespace(
                    tx,
                    Principal::new(root, P::ALL, None, None),
                    t.id,
                    Namespace::parse(slug).unwrap(),
                    NamespaceKind::Organization,
                    NOW,
                )?;
                jobs::insert_repo(tx, t.id, t.repo, "app", NOW)?;
                tenancy::create_pool(
                    tx,
                    Authority::HostLocal,
                    t.pool,
                    &format!("builders-{slug}"),
                    PoolKind::Dedicated(t.id),
                    NOW,
                )?;
            }
            tenancy::create_pool(
                tx,
                Authority::HostLocal,
                shared,
                "shared",
                PoolKind::Shared,
                NOW,
            )
        })
        .unwrap();
    Fixture {
        dir,
        store,
        objects,
        a,
        b,
        shared,
    }
}

fn plan(conn: &Connection, sql: &str) -> Vec<String> {
    let mut stmt = conn
        .prepare(&format!("EXPLAIN QUERY PLAN {sql}"))
        .unwrap_or_else(|e| panic!("SQLite refused {sql}: {e}"));
    let values = vec![rusqlite::types::Value::Null; stmt.parameter_count()];
    stmt.query_map(rusqlite::params_from_iter(values), |r| r.get(3))
        .unwrap()
        .map(|r| r.unwrap())
        .collect()
}

/// Every class of every tenant, as kept, must equal what the rows add up to; artifacts and uploads must split
/// the quota's object bytes exactly, logs must be the quota's log bytes, and nothing may be below zero.
fn check(store: &Store, tenants: &[TenantId], label: &str) {
    store
        .read(|c| {
            for &tenant in tenants {
                let kept = classes::tenant(c, tenant)?;
                let counted = classes::recount(c, tenant)?;
                assert_eq!(
                    kept, counted,
                    "{label}: kept classes differ from the recount"
                );
                let usage = retention::tenant_usage(c, tenant)?;
                assert_eq!(
                    kept.artifacts + kept.uploads,
                    usage.object_bytes,
                    "{label}: artifacts and uploads do not split the object bytes"
                );
                assert_eq!(kept.logs, usage.log_bytes, "{label}: logs");
            }
            let negative: i64 = c.query_row(
                "SELECT COUNT(*) FROM tenant_usage WHERE artifact_bytes < 0 OR upload_bytes < 0
                    OR log_bytes < 0 OR remote_cache_bytes < 0 OR actions_cache_bytes < 0
                    OR worker_cache_bytes < 0 OR bytes < 0",
                [],
                |r| r.get(0),
            )?;
            assert_eq!(negative, 0, "{label}: a class went below zero");
            let together = classes::deployment(c)?;
            let summed = tenants.iter().try_fold(Classes::default(), |sum, t| {
                let one = classes::tenant(c, *t)?;
                Ok::<_, sentinel_store::Error>(Classes {
                    artifacts: sum.artifacts + one.artifacts,
                    uploads: sum.uploads + one.uploads,
                    logs: sum.logs + one.logs,
                    remote_cache: sum.remote_cache + one.remote_cache,
                    actions_cache: sum.actions_cache + one.actions_cache,
                    worker_cache: sum.worker_cache + one.worker_cache,
                })
            })?;
            assert_eq!(
                together, summed,
                "{label}: the deployment is the sum of its tenants"
            );
            Ok(())
        })
        .unwrap();
}

impl Fixture {
    fn tenants(&self) -> [TenantId; 2] {
        [self.a.id, self.b.id]
    }

    fn check(&self, label: &str) {
        check(&self.store, &self.tenants(), label);
    }

    fn classes(&self, tenant: TenantId) -> Classes {
        self.store.read(|c| classes::tenant(c, tenant)).unwrap()
    }

    fn put(&self, tenant: Tenant, body: &[u8]) -> (Digest, u64) {
        let staged = self
            .objects
            .stage(tenant.id, body, u64::MAX, Expect::default())
            .unwrap();
        let (digest, len) = (staged.digest(), staged.len());
        let objects = Arc::clone(&self.objects);
        self.store
            .writer()
            .write(move |tx| objects.commit(tx, &staged))
            .unwrap();
        (digest, len)
    }

    fn manifest(&self, tenant: Tenant, name: &str, files: &[(Digest, u64)]) -> u64 {
        let entries: Vec<Entry> = files
            .iter()
            .enumerate()
            .map(|(i, (digest, len))| Entry {
                path: format!("f{i}"),
                digest: *digest,
                len: *len,
                mode: 0o644,
            })
            .collect();
        let (objects, name) = (Arc::clone(&self.objects), name.to_owned());
        self.store
            .writer()
            .write(move |tx| {
                objects.commit_manifest(tx, tenant.id, Kind::Artifact, &name, &entries)
            })
            .unwrap()
    }

    fn retire(&self, tenant: Tenant, name: &str, version: u64) {
        let (objects, name) = (Arc::clone(&self.objects), name.to_owned());
        self.store
            .writer()
            .write(move |tx| objects.retire_manifest(tx, tenant.id, Kind::Artifact, &name, version))
            .unwrap();
    }

    fn reclaim(&self) -> u32 {
        let objects = Arc::clone(&self.objects);
        self.store
            .writer()
            .write(move |tx| objects.reclaim(tx, FAR, 1_000))
            .unwrap()
            .objects
    }

    fn begin(&self, tenant: Tenant, len: u64) -> sentinel_core::UploadId {
        let objects = Arc::clone(&self.objects);
        self.store
            .writer()
            .write(move |tx| {
                objects.begin_upload(tx, tenant.id, len, None, 3_600_000, UnixMillis::now())
            })
            .unwrap()
    }

    fn seal(&self, tenant: Tenant, id: sentinel_core::UploadId, body: &[u8]) {
        let (objects, body) = (Arc::clone(&self.objects), body.to_vec());
        self.store
            .writer()
            .write(move |tx| {
                let now = UnixMillis::now();
                objects.put_chunk(tx, tenant.id, id, 0, &body, now)?;
                objects.seal_upload(tx, tenant.id, id, now)
            })
            .unwrap();
    }

    fn abort(&self, tenant: Tenant, id: sentinel_core::UploadId) {
        let objects = Arc::clone(&self.objects);
        self.store
            .writer()
            .write(move |tx| objects.abort_upload(tx, tenant.id, id))
            .unwrap();
    }

    fn worker(&self, pool: PoolId) -> WorkerId {
        let worker = WorkerId::new();
        self.store
            .writer()
            .write(move |tx| {
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
                )
            })
            .unwrap();
        worker
    }

    fn cache(&self, worker: WorkerId, bytes: i64) {
        self.store
            .writer()
            .write(move |tx| {
                dispatch::report_profile(
                    tx,
                    worker,
                    &ReportedProfile {
                        labels: &[],
                        host_id: None,
                        avail_images: &[],
                        cache_bytes: Some(bytes),
                        load_ns: None,
                    },
                )
            })
            .unwrap();
    }

    fn revoke(&self, worker: WorkerId) {
        self.store
            .writer()
            .write(move |tx| workers::revoke(tx, Authority::HostLocal, worker, NOW))
            .unwrap();
    }

    /// A released attempt of the tenant's, ready for its log to be stamped.
    fn attempt(&self, tenant: Tenant) -> AttemptId {
        let run = RunId::new();
        let spec = RunSpec::new(
            PinnedSource::new("https://github.com/o/r.git", SHA, Some("main")).unwrap(),
            compile_str(
                "schema: 1\non: [push]\njobs:\n  build:\n    image: alpine:3\n    steps: [{ id: s, run: 'true' }]\n",
            )
            .unwrap(),
        )
        .unwrap();
        let worker = self.worker(tenant.pool);
        self.store
            .writer()
            .write(move |tx| {
                let ids = runs::create_run(tx, tenant.id, tenant.repo, run, &spec, NOW)?;
                runs::resolve_image(tx, tenant.id, ids[0], IMAGE, "linux/amd64")?;
                let offer =
                    dispatch::place(tx, worker, tenant.pool, dispatch::DEFAULT_LEASE_MS, NOW)?
                        .expect("a queued job was placed");
                tx.execute(
                    "UPDATE attempts SET released_ms = ?2 WHERE id = ?1",
                    params![offer.attempt.as_bytes().as_slice(), NOW.0],
                )?;
                Ok(offer.attempt)
            })
            .unwrap()
    }

    fn stamp(&self, bytes: u64) -> u32 {
        let rows: Vec<_> = self
            .store
            .read(|c| retention::unstamped(c, 256))
            .unwrap()
            .into_iter()
            .map(|r| (r, bytes))
            .collect();
        self.store
            .writer()
            .write(move |tx| retention::stamp(tx, &Deployment::default(), &rows))
            .unwrap()
    }

    fn expire(&self) -> usize {
        let due = self
            .store
            .read(|c| retention::expiring(c, FAR, 256))
            .unwrap();
        self.store
            .writer()
            .write(move |tx| retention::expire(tx, &due, FAR))
            .unwrap()
            .len()
    }

    fn remote(&self, repos: &[(RepoId, u64)]) {
        classes::report_remote_cache(&self.store, repos).unwrap();
    }
}

#[test]
fn every_class_equals_a_full_recount_after_mixed_operations() {
    let f = fixture();
    let (a, b) = (f.a, f.b);
    f.check("empty");

    let (one, len_one) = f.put(a, b"first artifact file");
    let (two, len_two) = f.put(a, b"second artifact file, a little longer");
    let (other, len_other) = f.put(b, b"the other tenant's file");
    f.check("objects committed, none referenced yet");
    assert_eq!(f.classes(a.id).uploads, len_one + len_two);
    assert_eq!(f.classes(a.id).artifacts, 0);

    let v1 = f.manifest(a, "job/dist", &[(one, len_one), (two, len_two)]);
    f.check("a manifest references both");
    assert_eq!(f.classes(a.id).artifacts, len_one + len_two);
    assert_eq!(f.classes(a.id).uploads, 0);

    let v2 = f.manifest(a, "job/dist", &[(one, len_one)]);
    f.check("a second version shares one object");
    f.manifest(b, "job/dist", &[(other, len_other)]);
    f.check("the other tenant references its own");
    assert_eq!(
        f.classes(a.id).artifacts,
        len_one + len_two,
        "an object referenced twice is counted once"
    );

    f.retire(a, "job/dist", v1);
    f.check("the first version retired: the shared object stays referenced");
    assert_eq!(f.classes(a.id).artifacts, len_one);
    assert_eq!(
        f.classes(a.id).uploads,
        len_two,
        "the unshared one is unreferenced again"
    );
    f.retire(a, "job/dist", v2);
    f.check("the last version retired");
    assert_eq!(f.classes(a.id).artifacts, 0);
    assert_eq!(
        f.reclaim(),
        2,
        "both of A's objects are unreferenced and reclaimable"
    );
    f.check("reclaimed");
    assert_eq!(f.classes(a.id), Classes::default());
    assert_eq!(
        f.classes(b.id).artifacts,
        len_other,
        "the other tenant is untouched"
    );

    let sealed = f.begin(a, 5);
    f.check("a session reserves its declared length");
    assert_eq!(f.classes(a.id).uploads, 5);
    f.seal(a, sealed, b"12345");
    f.check("sealed into an unreferenced object");
    assert_eq!(f.classes(a.id).uploads, 5);
    let aborted = f.begin(a, 9);
    assert_eq!(f.classes(a.id).uploads, 14);
    f.abort(a, aborted);
    f.check("aborted");
    assert_eq!(f.classes(a.id).uploads, 5);

    let attempt = f.attempt(a);
    f.attempt(b);
    assert_eq!(f.stamp(300), 2);
    f.check("logs stamped");
    assert_eq!(f.classes(a.id).logs, 300);
    assert_eq!(f.expire(), 2);
    f.check("logs expired");
    assert_eq!(f.classes(a.id).logs, 0);
    let _ = attempt;

    let (dedicated, shared) = (f.worker(a.pool), f.worker(f.shared));
    f.cache(dedicated, 700);
    f.cache(shared, 9_000);
    f.check("worker caches reported");
    assert_eq!(
        f.classes(a.id).worker_cache,
        700,
        "a shared pool belongs to no tenant"
    );
    f.cache(dedicated, 200);
    assert_eq!(f.classes(a.id).worker_cache, 200);
    f.revoke(dedicated);
    f.check("the worker is revoked");
    assert_eq!(f.classes(a.id).worker_cache, 0);

    f.remote(&[(a.repo, 4_000), (a.repo, 1_000), (b.repo, 77)]);
    f.check("remote cache reported");
    assert_eq!(f.classes(a.id).remote_cache, 5_000);
    assert_eq!(f.classes(b.id).remote_cache, 77);
    f.remote(&[(b.repo, 10)]);
    f.check("the remote cache of A emptied");
    assert_eq!(f.classes(a.id).remote_cache, 0);
    assert_eq!(f.classes(b.id).remote_cache, 10);
}

fn copy_of_the_files_on_disk(from: &Path, to: &Path) {
    for name in ["metadata.sqlite", "metadata.sqlite-wal"] {
        if from.join(name).exists() {
            std::fs::copy(from.join(name), to.join(name)).unwrap();
        }
    }
}

#[test]
fn a_crash_between_an_operation_and_the_next_pass_leaves_every_class_exact() {
    let f = fixture();
    let (a, b) = (f.a, f.b);
    let (one, len_one) = f.put(a, b"kept by a manifest");
    let (two, len_two) = f.put(a, b"released by a retirement");
    let (three, len_three) = f.put(b, b"another tenant's file");
    f.manifest(a, "x/out", &[(one, len_one)]);
    let v = f.manifest(a, "x/gone", &[(two, len_two)]);
    f.manifest(b, "x/out", &[(three, len_three)]);
    let open = f.begin(a, 11);
    f.attempt(a);
    f.stamp(40);

    // The retirement committed; the reclaim that would follow it had not run when the files were copied.
    f.retire(a, "x/gone", v);
    let crashed = tempfile::tempdir().unwrap();
    copy_of_the_files_on_disk(f.dir.path(), crashed.path());
    let reopened = Store::open(crashed.path().join("metadata.sqlite"), Durability::Normal).unwrap();
    check(&reopened, &f.tenants(), "reopened after the retirement");
    let kept = reopened.read(|c| classes::tenant(c, a.id)).unwrap();
    assert_eq!(
        (kept.artifacts, kept.uploads, kept.logs),
        (len_one, len_two + 11, 40),
        "the committed retirement, the open session and the stamped log all survived"
    );

    let objects = Objects::open(crashed.path().join("objects")).unwrap();
    let reclaimed = reopened
        .writer()
        .write(move |tx| objects.reclaim(tx, FAR, 1_000))
        .unwrap();
    assert_eq!(
        reclaimed.objects, 1,
        "the pass after the reopen reclaims the released object"
    );
    check(&reopened, &f.tenants(), "reopened, then the next pass");

    // A transaction that dies before it commits leaves nothing behind in any class.
    let before = f.classes(a.id);
    let objects = Arc::clone(&f.objects);
    let failed = f
        .store
        .writer()
        .write(move |tx| -> Result<(), sentinel_store::Error> {
            let staged =
                objects.stage(a.id, &b"never committed"[..], u64::MAX, Expect::default())?;
            objects.commit(tx, &staged)?;
            objects.begin_upload(tx, a.id, 50, None, 60_000, UnixMillis::now())?;
            Err(sentinel_store::Error::Conflict)
        });
    assert!(failed.is_err());
    assert_eq!(f.classes(a.id), before);
    f.check("a transaction rolled back");
    f.abort(a, open);
    f.check("the open session aborted");
}

/// xorshift: the walk is the same on every run.
struct Walk(u64);
impl Walk {
    fn next(&mut self, below: usize) -> usize {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        (self.0 % below as u64) as usize
    }
}

#[derive(Default)]
struct Model {
    objects: Vec<(Digest, u64)>,
    manifests: Vec<(String, u64)>,
    sessions: Vec<(sentinel_core::UploadId, u64)>,
}

#[test]
fn a_seeded_walk_of_mixed_operations_never_leaves_a_class_off_the_recount_or_below_zero() {
    let f = fixture();
    let mut rng = Walk(0x9E37_79B9_7F4A_7C15);
    let mut models = [Model::default(), Model::default()];
    let tenants = [f.a, f.b];
    let workers = [f.worker(f.a.pool), f.worker(f.b.pool), f.worker(f.shared)];
    let mut live_workers = [true; 3];
    let mut attempts = 0;
    let mut manifest_serial = 0u64;
    for step in 0..400 {
        let which = rng.next(2);
        let (tenant, model) = (tenants[which], &mut models[which]);
        let op = rng.next(12);
        let mut reclaimed = false;
        match op {
            0..=2 => {
                let body = format!("body {}", rng.next(40)).repeat(1 + rng.next(5));
                let held = f.put(tenant, body.as_bytes());
                if !model.objects.iter().any(|(d, _)| *d == held.0) {
                    model.objects.push(held);
                }
            }
            3 | 4 if !model.objects.is_empty() => {
                let take = 1 + rng.next(model.objects.len().min(3));
                let mut files = Vec::new();
                for _ in 0..take {
                    let pick = model.objects[rng.next(model.objects.len())];
                    if !files.iter().any(|(d, _)| *d == pick.0) {
                        files.push(pick);
                    }
                }
                manifest_serial += 1;
                let name = format!("job{}/out{manifest_serial}", rng.next(3));
                let version = f.manifest(tenant, &name, &files);
                model.manifests.push((name, version));
            }
            5 | 6 if !model.manifests.is_empty() => {
                let (name, version) = model.manifests.swap_remove(rng.next(model.manifests.len()));
                f.retire(tenant, &name, version);
            }
            7 => {
                f.reclaim();
                reclaimed = true;
            }
            8 => {
                let len = 1 + rng.next(24) as u64;
                if rng.next(2) == 0 || model.sessions.is_empty() {
                    let id = f.begin(tenant, len);
                    model.sessions.push((id, len));
                } else {
                    let (id, len) = model.sessions.swap_remove(rng.next(model.sessions.len()));
                    if rng.next(2) == 0 {
                        f.abort(tenant, id);
                    } else {
                        let body = vec![b'a' + rng.next(26) as u8; len as usize];
                        f.seal(tenant, id, &body);
                    }
                }
            }
            9 => match rng.next(3) {
                0 if attempts < 6 => {
                    f.attempt(tenant);
                    attempts += 1;
                }
                1 => {
                    f.stamp(rng.next(500) as u64);
                }
                _ => {
                    f.expire();
                }
            },
            10 => {
                let w = rng.next(3);
                if live_workers[w] {
                    f.cache(workers[w], rng.next(2_000) as i64);
                    if rng.next(8) == 0 {
                        f.revoke(workers[w]);
                        live_workers[w] = false;
                    }
                }
            }
            11 => {
                let repos = [
                    (f.a.repo, rng.next(5_000) as u64),
                    (f.b.repo, rng.next(5_000) as u64),
                ];
                f.remote(&repos[..1 + rng.next(2)]);
            }
            _ => {}
        }
        if reclaimed {
            for (model, tenant) in models.iter_mut().zip(tenants) {
                let live: std::collections::HashSet<Vec<u8>> = f
                    .store
                    .read(|c| {
                        let mut stmt =
                            c.prepare("SELECT digest FROM objects WHERE tenant_id = ?1")?;
                        let rows = stmt
                            .query_map([tenant.id.as_bytes().as_slice()], |r| r.get(0))?
                            .collect::<Result<_, _>>()?;
                        Ok(rows)
                    })
                    .unwrap();
                model
                    .objects
                    .retain(|(d, _)| live.contains(d.as_bytes().as_slice()));
            }
        }
        f.check(&format!("step {step} (operation {op})"));
    }
}

/// A database at the last schema before per-class accounting (64): the class
/// objects are gone and so is every migration after them, so the upgrade has real
/// work to do.
fn database_at_latest_without_classes(path: &Path) {
    let db = Connection::open(path).unwrap();
    db.execute_batch(
        "PRAGMA foreign_keys = ON;
         DROP TRIGGER artifacts_class_known;
         DROP TRIGGER repo_usage_artifact_reweigh;
         DROP TRIGGER repo_usage_artifact_ins;
         DROP TRIGGER repo_usage_artifact_del;
         DROP TRIGGER artifacts_retention_cap;
         DROP INDEX artifacts_class_reapply;
         DROP TABLE artifact_classes;
         ALTER TABLE artifacts DROP COLUMN class;
         ALTER TABLE artifacts DROP COLUMN charged_bytes;
         ALTER TABLE artifacts DROP COLUMN pinned_ms;
         ALTER TABLE storage_defaults DROP COLUMN default_class;
         CREATE TRIGGER repo_usage_artifact_ins AFTER INSERT ON artifacts
             WHEN NEW.bytes > 0 BEGIN
             INSERT OR IGNORE INTO repo_usage(tenant_id, repo_id)
                 SELECT NEW.tenant_id, repo_id FROM runs WHERE id = NEW.run_id;
             UPDATE repo_usage SET artifact_bytes = artifact_bytes + NEW.bytes
                 WHERE tenant_id = NEW.tenant_id
                   AND repo_id = (SELECT repo_id FROM runs WHERE id = NEW.run_id);
         END;
         CREATE TRIGGER repo_usage_artifact_del AFTER DELETE ON artifacts
             WHEN OLD.bytes > 0 BEGIN
             UPDATE repo_usage SET artifact_bytes = artifact_bytes - OLD.bytes
                 WHERE tenant_id = OLD.tenant_id
                   AND repo_id = (SELECT repo_id FROM runs WHERE id = OLD.run_id);
         END;
         CREATE TRIGGER artifacts_retention_cap AFTER INSERT ON artifacts BEGIN
             UPDATE artifacts SET retain_until_ms = MIN(retain_until_ms, COALESCE(created_ms + (
                 SELECT MIN(COALESCE(rp.artifact_retention_ms, tp.ms), tp.ms) FROM
                     (SELECT COALESCE(
                         (SELECT artifact_retention_ms FROM storage_policies
                          WHERE tenant_id = NEW.tenant_id AND repo_id = X''),
                         (SELECT artifact_retention_ms FROM storage_defaults WHERE id = 1)) AS ms) tp
                     LEFT JOIN storage_policies rp ON rp.tenant_id = NEW.tenant_id
                         AND rp.repo_id = (SELECT repo_id FROM runs WHERE id = NEW.run_id)),
                 retain_until_ms))
             WHERE id = NEW.id;
         END;
         DROP TRIGGER class_usage_object_ins; DROP TRIGGER class_usage_object_del;
         DROP TRIGGER class_usage_ref_ins; DROP TRIGGER class_usage_ref_del;
         DROP TRIGGER class_usage_upload_ins; DROP TRIGGER class_usage_upload_close;
         DROP TRIGGER class_usage_worker_cache; DROP TRIGGER storage_class_snapshots_bound;
         DROP TABLE storage_class_snapshots;
         DROP INDEX tenant_usage_remote; DROP INDEX uploads_open;
         ALTER TABLE tenant_usage DROP COLUMN artifact_bytes;
         ALTER TABLE tenant_usage DROP COLUMN upload_bytes;
         ALTER TABLE tenant_usage DROP COLUMN remote_cache_bytes;
         ALTER TABLE tenant_usage DROP COLUMN actions_cache_bytes;
         ALTER TABLE tenant_usage DROP COLUMN worker_cache_bytes;
         DROP INDEX provenance_by_group_ref;
         ALTER TABLE run_provenance DROP COLUMN group_ref;
         DROP TABLE merge_deliveries;
         ALTER TABLE jobs DROP COLUMN outputs;
         DROP TRIGGER run_sources_immutable;
         DROP INDEX run_sources_by_run;
         DROP TABLE run_sources;
         DROP INDEX ai_requests_automatic;
         DROP INDEX ai_requests_by_attempt;
         DROP INDEX jobs_failed_on;
         ALTER TABLE ai_requests DROP COLUMN origin;
         ALTER TABLE tenant_ai DROP COLUMN auto_analysis;
         DROP TABLE tenant_ai;
         ALTER TABLE deployment_policy DROP COLUMN ai_providers;
         ALTER TABLE deployment_policy DROP COLUMN ai_enabled;
         DROP TRIGGER runner_terms_insert; DROP TRIGGER runner_terms_immutable;
         DROP TRIGGER runner_job_identity;
         DROP TRIGGER runner_lease_identity; DROP TRIGGER runner_lease_jit_once;
         DROP TRIGGER runner_lease_binding; DROP TRIGGER runner_lease_owner;
         DROP TABLE runner_leases;
         DROP TABLE runner_deliveries; DROP TABLE runner_jobs;
         ALTER TABLE installations DROP COLUMN runner_permissions;
         ALTER TABLE pools DROP COLUMN fork_prs;
         ALTER TABLE tenants DROP COLUMN runner_fork_prs;
         ALTER TABLE tenants DROP COLUMN runner_mode;
         ALTER TABLE installations DROP COLUMN migration_permissions;
         ALTER TABLE tenants DROP COLUMN migration_mode;
         ALTER TABLE tenants DROP COLUMN migration_settings;
         ALTER TABLE storage_defaults DROP COLUMN personal_quota_bytes;
         ALTER TABLE storage_defaults DROP COLUMN soft_percent;
         ALTER TABLE storage_defaults DROP COLUMN hard_percent;
         ALTER TABLE storage_policies DROP COLUMN soft_percent;
         ALTER TABLE storage_policies DROP COLUMN hard_percent;
         ALTER TABLE artifacts DROP COLUMN failure;
         DROP TABLE storage_notices;
         DROP TABLE ai_analyses;
         DROP TABLE ai_reservations;
         DROP TABLE ai_ledger;
         DROP TABLE ai_requests;
         DROP TABLE test_outcomes;
         DROP TABLE test_outcome_queue;
         DROP INDEX schedule_occurrences_by_run;
         DROP INDEX schedule_occurrences_by_age;
         DROP INDEX schedule_occurrences_by_claim;
         DROP TABLE schedule_occurrences;
         DROP INDEX schedules_due;
         DROP TABLE schedules;
         DROP INDEX provenance_by_delivery;
         ALTER TABLE runs DROP COLUMN pipeline;
         DELETE FROM schema_migrations WHERE version >= 65;",
    )
    .unwrap();
}

fn schema_objects(db: &Connection) -> Vec<(String, String)> {
    let mut stmt = db
        .prepare("SELECT type, name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name")
        .unwrap();
    stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
        .map(|r| r.unwrap())
        .collect()
}

#[test]
fn a_database_upgraded_from_064_agrees_with_one_the_triggers_kept() {
    let f = fixture();
    let (a, b) = (f.a, f.b);
    let (one, len_one) = f.put(a, b"referenced and shared");
    let (_two, len_two) = f.put(a, b"unreferenced");
    let (three, len_three) = f.put(b, b"the other tenant");
    f.manifest(a, "p/q", &[(one, len_one)]);
    f.manifest(a, "p/r", &[(one, len_one)]);
    f.manifest(b, "p/q", &[(three, len_three)]);
    f.begin(a, 21);
    let sealed = f.begin(b, 4);
    f.seal(b, sealed, b"abcd");
    let aborted = f.begin(b, 8);
    f.abort(b, aborted);
    f.attempt(a);
    f.stamp(1_234);
    let live = f.worker(a.pool);
    f.cache(live, 555);
    let revoked = f.worker(a.pool);
    f.cache(revoked, 99);
    f.revoke(revoked);
    f.cache(f.worker(f.shared), 12_345);
    f.check("before the downgrade");
    assert!(len_two > 0);
    let kept: Vec<Classes> = f.tenants().iter().map(|t| f.classes(*t)).collect();
    let fresh_schema = f.store.read(|c| Ok(schema_objects(c))).unwrap();
    let path = f.dir.path().join("metadata.sqlite");
    let Fixture { store, dir, .. } = f;
    drop(store);

    database_at_latest_without_classes(&path);
    let (upgraded, copy) = upgrade::open_upgrading(&path, Durability::Normal).unwrap();
    assert!(copy.is_some(), "a pending migration takes a copy first");
    check(&upgraded, &[a.id, b.id], "after the upgrade");
    let again: Vec<Classes> = [a.id, b.id]
        .iter()
        .map(|t| upgraded.read(|c| classes::tenant(c, *t)).unwrap())
        .collect();
    assert_eq!(again, kept, "the backfill equals what the triggers kept");
    assert_eq!(
        upgraded.read(|c| Ok(schema_objects(c))).unwrap(),
        fresh_schema,
        "the upgraded database has the schema a fresh one has"
    );
    drop(dir);
}

#[test]
fn snapshots_keep_ninety_days_a_tenant_and_never_mix_tenants() {
    let f = fixture();
    let (a, b) = (f.a, f.b);
    f.put(a, b"some bytes of A");
    f.put(b, b"some bytes of B, which are more");
    let take = |day: i64| {
        let mut after = None;
        loop {
            let (seen, last) = f
                .store
                .writer()
                .write(move |tx| {
                    classes::snapshot_day(tx, day, UnixMillis(day * classes::DAY_MS + 5), after, 1)
                })
                .unwrap();
            if seen < 1 {
                break;
            }
            after = last;
        }
    };
    for day in 0..SNAPSHOT_DAYS as i64 {
        take(day);
    }
    let rows = |t: TenantId| f.store.read(|c| classes::snapshots(c, t, 200)).unwrap();
    for t in [a.id, b.id] {
        let held = rows(t);
        assert_eq!(held.len(), SNAPSHOT_DAYS);
        assert_eq!(
            held.first().unwrap().day,
            SNAPSHOT_DAYS as i64 - 1,
            "newest first"
        );
        assert_eq!(held.last().unwrap().day, 0);
    }
    assert_ne!(
        rows(a.id)[0].classes.uploads,
        rows(b.id)[0].classes.uploads,
        "each tenant's own totals"
    );

    take(SNAPSHOT_DAYS as i64);
    for t in [a.id, b.id] {
        let held = rows(t);
        assert_eq!(held.len(), SNAPSHOT_DAYS, "the 91st day drops the oldest");
        assert_eq!(held.first().unwrap().day, SNAPSHOT_DAYS as i64);
        assert_eq!(held.last().unwrap().day, 1);
    }

    // Taking the same day again changes nothing, even though the tenant stored more since.
    let first = rows(a.id)[0];
    f.put(
        a,
        b"more bytes arriving after the first snapshot of the day",
    );
    take(SNAPSHOT_DAYS as i64);
    assert_eq!(rows(a.id)[0], first);

    // A day earlier than everything held is the oldest of 91 and leaves at once.
    take(0);
    assert_eq!(rows(a.id).last().unwrap().day, 1);
    assert_eq!(rows(a.id).len(), SNAPSHOT_DAYS);

    // The bound belongs to the table, not to the pass that fills it.
    let tenant = a.id;
    f.store
        .writer()
        .write(move |tx| {
            for day in 1_000..1_200i64 {
                tx.execute(
                    "INSERT INTO storage_class_snapshots VALUES (?1, ?2, 0, 0, 0, 0, 0, 0, 0)",
                    params![tenant.as_bytes().as_slice(), day],
                )?;
            }
            Ok(())
        })
        .unwrap();
    assert_eq!(rows(a.id).len(), SNAPSHOT_DAYS);
    assert_eq!(rows(a.id)[0].day, 1_199);
    assert_eq!(
        rows(b.id).len(),
        SNAPSHOT_DAYS,
        "another tenant's rows are not pruned by this one's"
    );
}

#[test]
fn a_snapshot_batch_resumes_from_its_last_key_and_skips_tenants_without_usage() {
    let f = fixture();
    f.put(f.a, b"a");
    let day = 20_000;
    let seen = |after, limit| {
        f.store
            .writer()
            .write(move |tx| classes::snapshot_day(tx, day, NOW, after, limit))
            .unwrap()
    };
    let (n, last) = seen(None, 10);
    assert_eq!(n, 1, "only a tenant with a usage row is snapshotted");
    let (n, _) = seen(last, 10);
    assert_eq!(n, 0, "nothing follows the last key");
    assert_eq!(
        f.store.read(|c| classes::snapshots(c, f.b.id, 5)).unwrap(),
        vec![]
    );
    let taken = f.store.read(|c| classes::snapshots(c, f.a.id, 5)).unwrap();
    assert_eq!(taken.len(), 1);
    assert_eq!(taken[0].classes.uploads, 1);
    assert_eq!(taken[0].taken_ms, NOW.0);
    assert_eq!(
        classes::day_of(UnixMillis(day * classes::DAY_MS + 86_399_999)),
        day
    );
    assert_eq!(classes::day_of(UnixMillis(day * classes::DAY_MS)), day);
}

/// The storage page's own reads: a bounded top-N list and two range reads, each answered by the index it names and
/// none of them scanning a table.
#[test]
fn the_storage_page_reads_are_answered_by_the_index_each_names() {
    let f = fixture();
    f.store
        .read(|c| {
            for (name, sql, index) in classes::PAGE_READS {
                let plan = plan(c, sql);
                assert!(
                    plan.iter()
                        .any(|p| p.contains(&format!("USING INDEX {index}"))),
                    "{name} does not use {index}: {plan:?}"
                );
                assert!(
                    plan.iter().all(|p| !p.starts_with("SCAN ")),
                    "{name} scans a table: {plan:?}"
                );
            }
            Ok(())
        })
        .unwrap();
}

#[test]
fn the_new_statements_are_answered_by_keys_not_table_scans() {
    let f = fixture();
    f.store
        .read(|c| {
            for (name, sql) in classes::STATEMENTS {
                let plan = plan(c, sql);
                for table in [
                    "objects",
                    "manifest_refs",
                    "uploads",
                    "attempts",
                    "workers",
                    "pools",
                    "repos",
                    "tenant_usage",
                    "storage_class_snapshots",
                ] {
                    assert!(
                        plan.iter()
                            .all(|p| !p.starts_with(&format!("SCAN {table}"))),
                        "{name} scans {table}: {plan:?}"
                    );
                }
                assert!(
                    plan.iter()
                        .all(|p| !p.contains("TEMP B-TREE") || sql.contains("ORDER BY tenant_id")),
                    "{name} sorts: {plan:?}"
                );
            }
            Ok(())
        })
        .unwrap();
}

/// SQLite virtual-machine steps of a statement, triggers included.
fn steps(tx: &rusqlite::Transaction<'_>, sql: &str, params: impl rusqlite::Params) -> i32 {
    let mut stmt = tx.prepare(sql).unwrap();
    stmt.execute(params).unwrap();
    stmt.get_status(rusqlite::StatementStatus::VmStep)
}

#[test]
fn a_class_update_costs_the_same_however_much_the_tenant_already_holds() {
    let f = fixture();
    let tenant = f.a.id;
    let t = tenant.as_bytes().as_slice().to_vec();
    let measure = |rows: usize| -> (i32, i32, i32, i32) {
        let t = t.clone();
        f.store
            .writer()
            .write(move |tx| {
                for i in 0..rows {
                    let digest = blake3::hash(format!("bulk {rows} {i}").as_bytes());
                    tx.execute(
                        "INSERT INTO objects(tenant_id, digest, len, created_ms) VALUES (?1, ?2, 10, 1)",
                        params![t.as_slice(), digest.as_bytes().as_slice()],
                    )?;
                    tx.execute(
                        "INSERT INTO manifests(tenant_id, kind, name, version, digest, entries, payload_len, created_ms, refs_indexed)
                         VALUES (?1, 0, ?2, 1, ?3, 1, 10, 1, 1)",
                        params![t.as_slice(), format!("m{rows}_{i}").as_bytes(), digest.as_bytes().as_slice()],
                    )?;
                    tx.execute(
                        "INSERT INTO manifest_refs(tenant_id, kind, name, version, digest) VALUES (?1, 0, ?2, 1, ?3)",
                        params![t.as_slice(), format!("m{rows}_{i}").as_bytes(), digest.as_bytes().as_slice()],
                    )?;
                }
                // One digest every manifest also references: the first edge is not the last.
                let popular = blake3::hash(format!("popular {rows}").as_bytes());
                tx.execute(
                    "INSERT INTO objects(tenant_id, digest, len, created_ms) VALUES (?1, ?2, 10, 1)",
                    params![t.as_slice(), popular.as_bytes().as_slice()],
                )?;
                for i in 0..rows {
                    tx.execute(
                        "INSERT INTO manifest_refs(tenant_id, kind, name, version, digest) VALUES (?1, 0, ?2, 1, ?3)",
                        params![t.as_slice(), format!("m{rows}_{i}").as_bytes(), popular.as_bytes().as_slice()],
                    )?;
                }
                let (late, later) = (format!("late{rows}"), format!("later{rows}"));
                let fresh = blake3::hash(format!("fresh {rows}").as_bytes());
                let insert = steps(
                    tx,
                    "INSERT INTO objects(tenant_id, digest, len, created_ms) VALUES (?1, ?2, 10, 1)",
                    params![t.as_slice(), fresh.as_bytes().as_slice()],
                );
                tx.execute(
                    "INSERT INTO manifests(tenant_id, kind, name, version, digest, entries, payload_len, created_ms, refs_indexed)
                     VALUES (?1, 0, ?3, 1, ?2, 1, 10, 1, 1)",
                    params![t.as_slice(), fresh.as_bytes().as_slice(), late.as_bytes()],
                )?;
                let first_edge = steps(
                    tx,
                    "INSERT INTO manifest_refs(tenant_id, kind, name, version, digest) VALUES (?1, 0, ?3, 1, ?2)",
                    params![t.as_slice(), fresh.as_bytes().as_slice(), late.as_bytes()],
                );
                tx.execute(
                    "INSERT INTO manifests(tenant_id, kind, name, version, digest, entries, payload_len, created_ms, refs_indexed)
                     VALUES (?1, 0, ?3, 1, ?2, 1, 10, 1, 1)",
                    params![t.as_slice(), popular.as_bytes().as_slice(), later.as_bytes()],
                )?;
                let shared_edge = steps(
                    tx,
                    "INSERT INTO manifest_refs(tenant_id, kind, name, version, digest) VALUES (?1, 0, ?3, 1, ?2)",
                    params![t.as_slice(), popular.as_bytes().as_slice(), later.as_bytes()],
                );
                let leaving = steps(
                    tx,
                    "DELETE FROM manifest_refs WHERE tenant_id = ?1 AND kind = 0 AND name = ?2 AND version = 1",
                    params![t.as_slice(), later.as_bytes()],
                );
                Ok((insert, first_edge, shared_edge, leaving))
            })
            .unwrap()
    };
    let small = measure(4);
    // A second batch on the same database, with the tenant's table much bigger and one digest on every manifest.
    let big = measure(600);
    for (name, s, b) in [
        ("an object entering", small.0, big.0),
        ("the first edge to an object", small.1, big.1),
        ("another edge to a shared object", small.2, big.2),
        ("an edge leaving a shared object", small.3, big.3),
    ] {
        assert!(
            b <= s + s / 4 + 8,
            "{name}: {s} steps with 4 rows, {b} with 600: the class update grows with the data"
        );
    }
    check(&f.store, &f.tenants(), "after the bulk rows");
}

#[test]
fn worker_cache_counts_live_workers_of_dedicated_pools_only() {
    let f = fixture();
    let (mine, theirs, shared) = (f.worker(f.a.pool), f.worker(f.b.pool), f.worker(f.shared));
    f.cache(mine, 100);
    f.cache(theirs, 50);
    f.cache(shared, 1_000_000);
    assert_eq!(f.classes(f.a.id).worker_cache, 100);
    assert_eq!(f.classes(f.b.id).worker_cache, 50);
    f.cache(mine, 100);
    assert_eq!(
        f.classes(f.a.id).worker_cache,
        100,
        "the same report twice is one report"
    );
    f.cache(mine, 0);
    assert_eq!(f.classes(f.a.id).worker_cache, 0);
    f.cache(mine, 30);
    let second = f.worker(f.a.pool);
    f.cache(second, 70);
    assert_eq!(f.classes(f.a.id).worker_cache, 100, "two workers add");
    f.revoke(second);
    assert_eq!(f.classes(f.a.id).worker_cache, 30);
    assert_eq!(
        f.classes(f.b.id).worker_cache,
        50,
        "another tenant's workers are not counted"
    );
    assert_eq!(
        f.classes(f.a.id).stored() + f.classes(f.b.id).stored(),
        0,
        "a cache class is reported and never part of what the quota counts"
    );
    f.check("worker caches");
}

#[test]
fn the_remote_cache_report_attributes_by_repository_owner_and_clears_what_left() {
    let f = fixture();
    let stranger = RepoId::new();
    f.remote(&[(f.a.repo, 10), (f.b.repo, 20), (stranger, 999)]);
    assert_eq!(f.classes(f.a.id).remote_cache, 10);
    assert_eq!(
        f.classes(f.b.id).remote_cache,
        20,
        "a repository no row names is attributed to nobody"
    );
    f.remote(&[(f.a.repo, 3)]);
    assert_eq!(
        f.classes(f.a.id).remote_cache,
        3,
        "a report replaces, it does not add"
    );
    assert_eq!(
        f.classes(f.b.id).remote_cache,
        0,
        "a tenant absent from a complete report holds nothing"
    );
    f.remote(&[]);
    assert_eq!(f.classes(f.a.id).remote_cache, 0);
    f.check("remote cache cleared");
}

#[test]
fn a_remote_report_over_more_tenants_than_a_batch_reaches_all_of_them_and_clears_all_of_them() {
    let f = fixture();
    let many = 600;
    let repos: Vec<(RepoId, TenantId)> = (0..many)
        .map(|_| (RepoId::new(), TenantId::new()))
        .collect();
    let seeded = repos.clone();
    f.store
        .writer()
        .write(move |tx| {
            for (i, (repo, tenant)) in seeded.iter().enumerate() {
                tx.execute(
                    "INSERT INTO tenants(id, slug, created_ms) VALUES (?1, ?2, 1)",
                    params![tenant.as_bytes().as_slice(), format!("t{i}")],
                )?;
                tx.execute(
                    "INSERT INTO repos(id, tenant_id, name, created_ms) VALUES (?1, ?2, 'r', 1)",
                    params![repo.as_bytes().as_slice(), tenant.as_bytes().as_slice()],
                )?;
            }
            Ok(())
        })
        .unwrap();
    let report: Vec<(RepoId, u64)> = repos.iter().map(|(r, _)| (*r, 7)).collect();
    f.remote(&report);
    let held = |f: &Fixture| -> i64 {
        f.store
            .read(|c| {
                Ok(c.query_row(
                    "SELECT COUNT(*) FROM tenant_usage WHERE remote_cache_bytes = 7",
                    [],
                    |r| r.get(0),
                )?)
            })
            .unwrap()
    };
    assert_eq!(held(&f), many as i64);
    f.remote(&[(f.a.repo, 1)]);
    assert_eq!(
        held(&f),
        0,
        "every tenant past the first page of 256 was cleared"
    );
    assert_eq!(f.classes(f.a.id).remote_cache, 1);
}
