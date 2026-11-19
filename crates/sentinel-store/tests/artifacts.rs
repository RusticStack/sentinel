use std::sync::Arc;

use sentinel_auth::secret::Secret;
use sentinel_core::{
    JobId, PoolId, RepoId, RunId, TenantId, UnixMillis, UserId, WorkerId,
    auth::{Namespace, Permissions as P, Principal},
};
use sentinel_pipeline::{PinnedSource, RunSpec, compile_str};
use sentinel_protocol::negotiate::{Arch, Capabilities, Negotiated, ProtocolVersion};
use sentinel_store::{
    Durability, Error, Store, artifacts,
    auth::{self, Authority, NamespaceKind, provisioning},
    dispatch::{self, Capacity},
    jobs,
    objects::{Entry, Expect, Kind, Objects},
    runs,
    tenancy::{self, PoolKind},
    workers::{self, Presentation},
};

const NOW: UnixMillis = UnixMillis(1_000);
const SHA: &str = "0123456789abcdef0123456789abcdef01234567";
const DIGEST: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

struct Fixture {
    _dir: tempfile::TempDir,
    store: Store,
    objects: Arc<Objects>,
    tenant: TenantId,
    other: TenantId,
    repo: RepoId,
    pool: PoolId,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path().join("metadata.sqlite"), Durability::Normal).unwrap();
    let objects = Arc::new(Objects::open(dir.path().join("objects")).unwrap());
    let (root, tenant, other, repo, pool) = (
        UserId::new(),
        TenantId::new(),
        TenantId::new(),
        RepoId::new(),
        PoolId::new(),
    );
    store
        .writer()
        .write(move |tx| {
            provisioning::insert_human(tx, root, "Root", true, NOW)?;
            for (t, slug) in [(tenant, "acme"), (other, "other")] {
                auth::create_namespace(
                    tx,
                    Principal::new(root, P::ALL, None, None),
                    t,
                    Namespace::parse(slug).unwrap(),
                    NamespaceKind::Organization,
                    NOW,
                )?;
            }
            jobs::insert_repo(tx, tenant, repo, "app", NOW)?;
            tenancy::create_pool(
                tx,
                Authority::HostLocal,
                pool,
                "builders",
                PoolKind::Dedicated(tenant),
                NOW,
            )
        })
        .unwrap();
    Fixture {
        _dir: dir,
        store,
        objects,
        tenant,
        other,
        repo,
        pool,
    }
}

impl Fixture {
    fn attempt(&self, job: JobId) -> (WorkerId, sentinel_core::AttemptId) {
        let (worker, pool) = (WorkerId::new(), self.pool);
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
        let offer = self
            .store
            .writer()
            .write(move |tx| dispatch::place(tx, worker, pool, dispatch::DEFAULT_LEASE_MS, NOW))
            .unwrap()
            .expect("a queued job was placed");
        assert_eq!(offer.job, job);
        (worker, offer.attempt)
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

#[test]
fn absent_and_failed_rows_round_trip_without_a_manifest() {
    let f = fixture();
    let (run, job) = f.run();
    let (_, attempt) = f.attempt(job);
    let (tenant, name) = (f.tenant, "dist");

    for (state, version, why) in [
        (artifacts::State::Captured, None, "captured without version"),
        (artifacts::State::Absent, Some(1), "absent with version"),
        (artifacts::State::Failed, Some(1), "failed with version"),
    ] {
        let wrote = f.store.writer().write(move |tx| {
            artifacts::record(
                tx,
                tenant,
                run,
                job,
                attempt,
                name,
                state,
                version,
                0,
                0,
                UnixMillis(9_999),
                NOW,
            )
        });
        assert!(wrote.is_err(), "{why}");
    }

    let id = f
        .store
        .writer()
        .write(move |tx| {
            artifacts::record(
                tx,
                tenant,
                run,
                job,
                attempt,
                name,
                artifacts::State::Absent,
                None,
                0,
                0,
                UnixMillis(9_999),
                NOW,
            )
        })
        .unwrap();
    let row = f
        .store
        .read(move |c| artifacts::get(c, tenant, run, id))
        .unwrap();
    assert_eq!(row.name, "dist");
    assert_eq!(row.job_name.as_deref(), Some("build"));
    assert_eq!(row.state, artifacts::State::Absent);
    assert_eq!(row.manifest_version, None);
    assert!(
        f.store
            .read(move |c| artifacts::exists(c, attempt, "dist"))
            .unwrap()
    );
    assert_eq!(
        f.store
            .read(move |c| artifacts::run_bytes(c, tenant, run))
            .unwrap(),
        0
    );
    assert_eq!(
        f.store
            .read(move |c| artifacts::for_run(c, tenant, run))
            .unwrap()
            .len(),
        1
    );
    assert!(matches!(
        f.store.read(move |c| artifacts::get(c, f.other, run, id)),
        Err(Error::NotFound)
    ));
    assert!(matches!(
        f.store
            .read(move |c| artifacts::get(c, tenant, RunId::new(), id)),
        Err(Error::NotFound)
    ));
}

#[test]
fn a_captured_row_commits_with_its_manifest_in_one_transaction() {
    let f = fixture();
    let (run, job) = f.run();
    let (_, attempt) = f.attempt(job);
    let tenant = f.tenant;

    let body = b"artifact bytes";
    let staged = f
        .objects
        .stage(tenant, &body[..], u64::MAX, Expect::default())
        .unwrap();
    let (digest, len) = (staged.digest(), staged.len());
    let manifest = artifacts::manifest_name(job, "dist");
    let objects = Arc::clone(&f.objects);
    let id = f
        .store
        .writer()
        .write(move |tx| {
            objects.commit(tx, &staged)?;
            let version = objects.commit_manifest(
                tx,
                tenant,
                Kind::Artifact,
                &manifest,
                &[Entry {
                    path: "out/a.txt".into(),
                    digest,
                    len,
                    mode: 0o644,
                }],
            )?;
            artifacts::record(
                tx,
                tenant,
                run,
                job,
                attempt,
                "dist",
                artifacts::State::Captured,
                Some(version),
                1,
                len,
                UnixMillis(9_999),
                NOW,
            )
        })
        .unwrap();

    let row = f
        .store
        .read(move |c| artifacts::get(c, tenant, run, id))
        .unwrap();
    assert_eq!(row.state, artifacts::State::Captured);
    assert_eq!((row.entries, row.bytes), (1, len));
    let m = f
        .store
        .read(move |c| {
            f.objects.manifest(
                c,
                tenant,
                Kind::Artifact,
                &artifacts::manifest_name(job, "dist"),
                row.manifest_version,
            )
        })
        .unwrap();
    assert_eq!(m.entries[0].path, "out/a.txt");
    assert_eq!(
        f.store
            .read(move |c| artifacts::run_bytes(c, tenant, run))
            .unwrap(),
        len
    );
    let found = f
        .store
        .read(move |c| artifacts::captured(c, tenant, run, "build", "dist"))
        .unwrap();
    assert_eq!(found.id, id);
    let dup = f.store.writer().write(move |tx| {
        artifacts::record(
            tx,
            tenant,
            run,
            job,
            attempt,
            "dist",
            artifacts::State::Absent,
            None,
            0,
            0,
            UnixMillis(9_999),
            NOW,
        )
    });
    assert!(dup.is_err(), "duplicate (attempt, name) must be refused");
}

#[test]
fn the_ownership_trigger_refuses_a_foreign_tenant_or_attempt() {
    let f = fixture();
    let (run, job) = f.run();
    let (_, attempt) = f.attempt(job);
    let (tenant, other) = (f.tenant, f.other);

    let wrong_tenant = f.store.writer().write(move |tx| {
        artifacts::record(
            tx,
            other,
            run,
            job,
            attempt,
            "x",
            artifacts::State::Absent,
            None,
            0,
            0,
            UnixMillis(9_999),
            NOW,
        )
    });
    assert!(wrong_tenant.is_err());

    let wrong_attempt = f.store.writer().write(move |tx| {
        artifacts::record(
            tx,
            tenant,
            run,
            job,
            sentinel_core::AttemptId::new(),
            "x",
            artifacts::State::Absent,
            None,
            0,
            0,
            UnixMillis(9_999),
            NOW,
        )
    });
    assert!(wrong_attempt.is_err());
}

#[test]
fn staging_streams_in_pieces_and_seals_only_the_declared_total() {
    let f = fixture();
    let tenant = f.tenant;

    let mut staging = f.objects.stage_begin(tenant, 11).unwrap();
    f.objects.stage_write(&mut staging, b"hello ").unwrap();
    f.objects.stage_write(&mut staging, b"world").unwrap();
    assert!(f.objects.stage_write(&mut staging, b"!").is_err());
    let mut again = f.objects.stage_begin(tenant, 5).unwrap();
    f.objects.stage_write(&mut again, b"hi").unwrap();
    assert!(f.objects.stage_seal(tenant, again, 5).is_err());
    let staged = f.objects.stage_seal(tenant, staging, 11).unwrap();
    let digest = staged.digest();
    let tx_objects = Arc::clone(&f.objects);
    f.store
        .writer()
        .write(move |tx| tx_objects.commit(tx, &staged).map(|_| ()))
        .unwrap();
    let mut out = Vec::new();
    f.store
        .read(|c| f.objects.read(c, tenant, digest, &mut out))
        .unwrap();
    assert_eq!(out, b"hello world");
}

#[test]
fn a_deduped_stage_never_deletes_the_committed_object() {
    let f = fixture();
    let tenant = f.tenant;

    let first = f
        .objects
        .stage(tenant, &b"same body"[..], u64::MAX, Expect::default())
        .unwrap();
    let digest = first.digest();
    let objects = Arc::clone(&f.objects);
    f.store
        .writer()
        .write(move |tx| objects.commit(tx, &first).map(|_| ()))
        .unwrap();

    let second = f
        .objects
        .stage(tenant, &b"same body"[..], u64::MAX, Expect::default())
        .unwrap();
    assert_eq!(second.digest(), digest);
    let objects = Arc::clone(&f.objects);
    assert!(
        !f.store
            .writer()
            .write(move |tx| objects.discard(tx, second))
            .unwrap()
    );
    let mut out = Vec::new();
    f.store
        .read(|c| f.objects.read(c, tenant, digest, &mut out))
        .unwrap();
    assert_eq!(out, b"same body");
}

// A creator's discard after a dedup commit must not remove the shared object's file.
#[test]
fn a_creator_discarding_after_a_dedup_commit_keeps_the_object() {
    let f = fixture();
    let tenant = f.tenant;
    let creator = f
        .objects
        .stage(tenant, &b"shared bytes"[..], u64::MAX, Expect::default())
        .unwrap();
    let deduper = f
        .objects
        .stage(tenant, &b"shared bytes"[..], u64::MAX, Expect::default())
        .unwrap();
    let digest = deduper.digest();
    let objects = Arc::clone(&f.objects);
    f.store
        .writer()
        .write(move |tx| objects.commit(tx, &deduper).map(|_| ()))
        .unwrap();
    let objects = Arc::clone(&f.objects);
    let removed = f
        .store
        .writer()
        .write(move |tx| objects.discard(tx, creator))
        .unwrap();
    assert!(!removed, "the discard removed a committed object's file");
    let mut out = Vec::new();
    f.store
        .read(|c| f.objects.read(c, tenant, digest, &mut out))
        .unwrap();
    assert_eq!(out, b"shared bytes");
}

// The live stage's pin keeps the file for a deduper whose commit is still pending.
#[test]
fn a_discard_before_a_pending_dedup_commit_keeps_the_file() {
    let f = fixture();
    let tenant = f.tenant;
    let creator = f
        .objects
        .stage(tenant, &b"pending bytes"[..], u64::MAX, Expect::default())
        .unwrap();
    let deduper = f
        .objects
        .stage(tenant, &b"pending bytes"[..], u64::MAX, Expect::default())
        .unwrap();
    let digest = deduper.digest();
    let objects = Arc::clone(&f.objects);
    assert!(
        !f.store
            .writer()
            .write(move |tx| objects.discard(tx, creator))
            .unwrap()
    );
    let objects = Arc::clone(&f.objects);
    f.store
        .writer()
        .write(move |tx| objects.commit(tx, &deduper).map(|_| ()))
        .unwrap();
    let mut out = Vec::new();
    f.store
        .read(|c| f.objects.read(c, tenant, digest, &mut out))
        .unwrap();
    assert_eq!(out, b"pending bytes");
    let lone = f
        .objects
        .stage(tenant, &b"nobody else"[..], u64::MAX, Expect::default())
        .unwrap();
    let objects = Arc::clone(&f.objects);
    assert!(
        f.store
            .writer()
            .write(move |tx| objects.discard(tx, lone))
            .unwrap()
    );
}

#[test]
fn a_deduped_stage_seal_leaves_nothing_in_tmp() {
    let f = fixture();
    let tenant = f.tenant;
    let mut kept = Vec::new();
    for _ in 0..2 {
        let mut staging = f.objects.stage_begin(tenant, 5).unwrap();
        f.objects.stage_write(&mut staging, b"hello").unwrap();
        kept.push(f.objects.stage_seal(tenant, staging, 5).unwrap());
    }
    let left: Vec<_> = std::fs::read_dir(f._dir.path().join("objects").join("tmp"))
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .collect();
    assert!(left.is_empty(), "tmp leftovers: {left:?}");
}

/// Eight workers publishing the same content at once, half of them giving it up: the bytes are stored once and a
/// creator's discard never takes the copy another committed.
#[test]
fn concurrent_identical_publications_store_one_object_and_lose_nothing() {
    use std::sync::Barrier;
    use std::sync::atomic::{AtomicU32, Ordering};

    let f = Arc::new(fixture());
    let tenant = f.tenant;
    let body: Arc<Vec<u8>> = Arc::new((0..(64 << 10)).map(|i| (i % 251) as u8).collect());
    let seek = Arc::new(Barrier::new(8));
    let commits = Arc::new(AtomicU32::new(0));
    let mut tries = Vec::new();
    for round in 0..8 {
        let (f, body, seek, commits) = (
            Arc::clone(&f),
            Arc::clone(&body),
            Arc::clone(&seek),
            Arc::clone(&commits),
        );
        tries.push(std::thread::spawn(move || {
            let staged = f
                .objects
                .stage(tenant, &body[..], u64::MAX, Expect::default())
                .unwrap();
            // Every stage is sealed and about to commit before any of them commits.
            seek.wait();
            let objects = Arc::clone(&f.objects);
            if round % 2 == 0 {
                let created = f
                    .store
                    .writer()
                    .write(move |tx| objects.commit(tx, &staged))
                    .unwrap();
                if created {
                    commits.fetch_add(1, Ordering::Relaxed);
                }
            } else {
                f.store
                    .writer()
                    .write(move |tx| objects.discard(tx, staged))
                    .unwrap();
            }
        }));
    }
    for tried in tries {
        tried.join().unwrap();
    }
    assert_eq!(commits.load(Ordering::Relaxed), 1, "one row for one body");
    let digest = f
        .objects
        .stage(tenant, &body[..], u64::MAX, Expect::default())
        .unwrap()
        .digest();
    let mut out = Vec::new();
    f.store
        .read(|c| f.objects.read(c, tenant, digest, &mut out))
        .unwrap();
    assert_eq!(out, *body, "the committed bytes are whole");
    let left: Vec<_> = std::fs::read_dir(f._dir.path().join("objects").join("tmp"))
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .collect();
    assert!(left.is_empty(), "tmp leftovers: {left:?}");
}

/// The same publication delivered twice at once: `UNIQUE(attempt_id, name)` admits one row and the other is a
/// conflict, never a second artifact charged twice.
#[test]
fn concurrent_identical_rows_of_one_attempt_leave_one_row() {
    use std::sync::Barrier;

    let f = Arc::new(fixture());
    let (run, job) = f.run();
    let (_, attempt) = f.attempt(job);
    let tenant = f.tenant;
    let seek = Arc::new(Barrier::new(2));
    let mut tries = Vec::new();
    for _ in 0..2 {
        let (f, seek) = (Arc::clone(&f), Arc::clone(&seek));
        tries.push(std::thread::spawn(move || {
            seek.wait();
            f.store.writer().write(move |tx| {
                artifacts::record(
                    tx,
                    tenant,
                    run,
                    job,
                    attempt,
                    "dist",
                    artifacts::State::Absent,
                    None,
                    0,
                    0,
                    UnixMillis(NOW.0 + 86_400_000),
                    NOW,
                )
            })
        }));
    }
    let mut admitted = 0;
    for tried in tries {
        match tried.join().unwrap() {
            Ok(_) => admitted += 1,
            Err(error) => assert!(
                !matches!(error, Error::NotFound),
                "the loser of the race is refused, not {error:?}"
            ),
        }
    }
    assert_eq!(admitted, 1, "one row admitted");
    let rows = f
        .store
        .read(move |c| artifacts::for_attempt(c, attempt))
        .unwrap();
    assert_eq!(rows.len(), 1, "{rows:?}");
}
