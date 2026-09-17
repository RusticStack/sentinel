//! D03 artifact records: the captured/absent/failed terminal states,
//! manifest-version invariants, the attempt→job→run→tenant ownership
//! trigger, and the incremental `Staging` writer that link frames use.

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
    /// An enrolled worker holding a placed attempt on `job`.
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

    /// A run with one job named `build`.
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

    // Captured needs a manifest version; absent/failed must not carry one.
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
    assert_eq!(row.job_name, "build");
    assert_eq!(row.state, artifacts::State::Absent);
    assert_eq!(row.manifest_version, None);
    assert!(
        f.store
            .read(move |c| artifacts::exists(c, attempt, "dist"))
            .unwrap()
    );
    // Absent contributes nothing to the run's artifact budget.
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
    // Foreign tenant or run sees nothing.
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
    // The manifest reads back with the same entries.
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
    // `captured` resolves by job and artifact name.
    let found = f
        .store
        .read(move |c| artifacts::captured(c, tenant, run, "build", "dist"))
        .unwrap();
    assert_eq!(found.id, id);
    // A second record under the same (attempt, name) is a conflict.
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

    // Right attempt, wrong tenant: the trigger joins the chain.
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

    // Right tenant, an attempt of nothing: the chain has no root.
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
    // Past the declared limit the write is refused without appending.
    assert!(f.objects.stage_write(&mut staging, b"!").is_err());
    // A different declared length cannot seal what was written.
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

    // Stage the same bytes again: the seal dedups, so `discard` must leave
    // the committed object alone.
    let second = f
        .objects
        .stage(tenant, &b"same body"[..], u64::MAX, Expect::default())
        .unwrap();
    assert_eq!(second.digest(), digest);
    second.discard();
    let mut out = Vec::new();
    f.store
        .read(|c| f.objects.read(c, tenant, digest, &mut out))
        .unwrap();
    assert_eq!(out, b"same body");
}
