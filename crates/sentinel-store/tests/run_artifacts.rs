//! Run-level and runner-mode artifacts (E04): a row that names a run and its uploader or a GitHub
//! run and job instead of a native attempt, with the same class, charge, quota and retirement as a
//! job's own artifact — and no way to stand in for a declared required one.

use std::sync::Arc;

use sentinel_auth::secret::Secret;
use sentinel_core::{
    AttemptId, JobId, PoolId, RepoId, RunId, TenantId, UnixMillis, UserId, WorkerId,
    auth::{Namespace, Permissions, Principal},
};
use sentinel_pipeline::{PinnedSource, RunSpec, compile_str};
use sentinel_protocol::negotiate::{Arch, Capabilities, Negotiated, ProtocolVersion};
use sentinel_store::{
    Durability, Error, Store, artifacts,
    auth::{self, Authority, NamespaceKind, provisioning},
    dispatch::{self, Capacity},
    jobs,
    objects::{Entry, Expect, Kind, Objects},
    retention, runs,
    tenancy::{self, PoolKind},
    workers::{self, Presentation},
};

const NOW: UnixMillis = UnixMillis(1_000);
const SHA: &str = "0123456789abcdef0123456789abcdef01234567";
const IMAGE: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

struct Fixture {
    _dir: tempfile::TempDir,
    store: Store,
    objects: Arc<Objects>,
    root: UserId,
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
            provisioning::insert_human(tx, root, "Ada", true, NOW)?;
            for (t, slug) in [(tenant, "acme"), (other, "other")] {
                auth::create_namespace(
                    tx,
                    Principal::new(root, Permissions::ALL, None, None),
                    t,
                    Namespace::parse(slug).unwrap(),
                    NamespaceKind::Organization,
                    NOW,
                )?;
            }
            auth::set_membership(
                tx,
                Principal::new(root, Permissions::ALL, None, None),
                tenant,
                root,
                sentinel_core::auth::Role::TenantAdmin,
            )?;
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
        root,
        tenant,
        other,
        repo,
        pool,
    }
}

impl Fixture {
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
                    runs::resolve_image(tx, tenant, *job, IMAGE, "linux/amd64")?;
                }
                Ok(ids)
            })
            .unwrap();
        (run, jobs[0])
    }

    /// Lease the run's job, so a test can ask what that attempt published.
    fn attempt(&self, job: JobId) -> AttemptId {
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
            .expect("the queued job was placed");
        assert_eq!(offer.job, job);
        offer.attempt
    }

    /// A committed object the tenant holds, as an upload session would have left it.
    fn object(&self, body: &[u8]) -> Entry {
        let staged = self
            .objects
            .stage(self.tenant, body, u64::MAX, Expect::default())
            .unwrap();
        let entry = Entry {
            path: "reports/run.txt".into(),
            digest: staged.digest(),
            len: staged.len(),
            mode: 0o644,
        };
        let objects = Arc::clone(&self.objects);
        self.store
            .writer()
            .write(move |tx| objects.commit(tx, &staged))
            .unwrap();
        entry
    }
}

#[test]
fn a_run_level_artifact_names_its_run_and_uploader_and_never_an_attempt() {
    let f = fixture();
    let (run, job) = f.run();
    let tenant = f.tenant;
    let entry = f.object(b"run-level bytes");
    let (uploader, len, objects) = (f.root, entry.len, Arc::clone(&f.objects));
    let id = f
        .store
        .writer()
        .write(move |tx| {
            let charge = artifacts::charge(tx, Some("release"), len)?;
            let version = objects.commit_manifest(
                tx,
                tenant,
                Kind::Artifact,
                &artifacts::run_manifest_name(run, "reports"),
                &[entry],
            )?;
            artifacts::record_upload(
                tx,
                tenant,
                run,
                "reports",
                &charge,
                version,
                1,
                len,
                UnixMillis(i64::MAX),
                uploader,
                NOW,
            )
        })
        .unwrap();
    let row = f
        .store
        .read(move |c| artifacts::get(c, tenant, run, id))
        .unwrap();
    assert_eq!(row.origin, artifacts::Origin::Run);
    assert_eq!(row.run, Some(run));
    assert_eq!(row.job, None);
    assert_eq!(row.attempt, None);
    assert_eq!(row.job_name, None);
    assert_eq!(row.class, "release");
    assert_eq!(
        row.charged_bytes,
        len * 2,
        "the release class weighs twice its bytes"
    );
    assert_eq!(
        row.manifest().unwrap(),
        artifacts::run_manifest_name(run, "reports")
    );
    let uploader_row = row.uploader.expect("a run-level row names its uploader");
    assert_eq!(uploader_row.user, f.root);
    assert_eq!(uploader_row.display_name.as_deref(), Some("Ada"));
    assert_eq!(
        f.store
            .read(move |c| artifacts::run_bytes(c, tenant, run))
            .unwrap(),
        len,
        "the run's budget counts what a client attached to it"
    );
    assert_eq!(
        f.store
            .read(move |c| retention::repo_usage(c, tenant, f.repo))
            .unwrap()
            .artifact_bytes,
        len * 2,
        "and its repository's quota counts the class's charge"
    );
    let listed = f
        .store
        .read(move |c| artifacts::for_run(c, tenant, run))
        .unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].origin, artifacts::Origin::Run);
    // A run-level row is not a job's artifact: even under a name the job declares, it is not
    // coverage, so finalization still finds the required artifact missing.
    let entry = f.object(b"attached");
    let (uploader, len, objects) = (f.root, entry.len, Arc::clone(&f.objects));
    f.store
        .writer()
        .write(move |tx| {
            let charge = artifacts::charge(tx, None, len)?;
            let version = objects.commit_manifest(
                tx,
                tenant,
                Kind::Artifact,
                &artifacts::run_manifest_name(run, "report"),
                &[entry],
            )?;
            artifacts::record_upload(
                tx,
                tenant,
                run,
                "report",
                &charge,
                version,
                1,
                len,
                UnixMillis(i64::MAX),
                uploader,
                NOW,
            )
        })
        .unwrap();
    let attempt = f.attempt(job);
    let tenant = f.tenant;
    let coverage = f
        .store
        .read(move |c| {
            Ok((
                artifacts::for_attempt(c, attempt)?,
                artifacts::captured_for_attempt(c, tenant, attempt, 16)?,
            ))
        })
        .unwrap();
    assert!(
        coverage.0.is_empty() && coverage.1.is_empty(),
        "a run-level artifact named like a declared one is not coverage: {coverage:?}"
    );
}

#[test]
fn an_uploader_who_left_the_tenant_keeps_the_record_and_not_the_name() {
    let f = fixture();
    let (run, _) = f.run();
    let (tenant, root, objects) = (f.tenant, f.root, Arc::clone(&f.objects));
    let entry = f.object(b"bytes");
    let len = entry.len;
    let id = f
        .store
        .writer()
        .write(move |tx| {
            let charge = artifacts::charge(tx, None, len)?;
            let version = objects.commit_manifest(
                tx,
                tenant,
                Kind::Artifact,
                &artifacts::run_manifest_name(run, "logs"),
                &[entry],
            )?;
            artifacts::record_upload(
                tx,
                tenant,
                run,
                "logs",
                &charge,
                version,
                1,
                len,
                UnixMillis(i64::MAX),
                root,
                NOW,
            )
        })
        .unwrap();
    let colleague = UserId::new();
    f.store
        .writer()
        .write(move |tx| {
            provisioning::insert_human(tx, colleague, "Grace", true, NOW)?;
            auth::set_membership(
                tx,
                Principal::new(colleague, Permissions::ALL, None, None),
                tenant,
                colleague,
                sentinel_core::auth::Role::TenantAdmin,
            )?;
            auth::remove_membership(
                tx,
                Principal::new(colleague, Permissions::ALL, None, None),
                tenant,
                root,
                NOW,
            )
        })
        .unwrap();
    let row = f
        .store
        .read(move |c| artifacts::get(c, tenant, run, id))
        .unwrap();
    let uploader = row.uploader.expect("the row still names who attached it");
    assert_eq!(uploader.user, f.root);
    assert_eq!(
        uploader.display_name, None,
        "a former member's name is not handed out"
    );
}

#[test]
fn a_runner_mode_artifact_is_recorded_under_its_github_run_and_job() {
    let f = fixture();
    let (tenant, repo) = (f.tenant, f.repo);
    let (github_run, first_job, second_job) = (9001u64, 11u64, 12u64);
    let entry = f.object(b"junit xml");
    let len = entry.len;
    let write = |job: u64, name: &'static str, entry: Entry| {
        let objects = Arc::clone(&f.objects);
        f.store
            .writer()
            .write(move |tx| {
                let charge = artifacts::charge(tx, Some("evidence"), len)?;
                let version = objects.commit_manifest(
                    tx,
                    tenant,
                    Kind::Artifact,
                    &artifacts::runner_manifest_name(repo, github_run, job, name),
                    &[entry],
                )?;
                artifacts::record_runner(
                    tx,
                    tenant,
                    repo,
                    github_run,
                    job,
                    name,
                    &charge,
                    version,
                    1,
                    len,
                    UnixMillis(i64::MAX),
                    NOW,
                )
            })
            .unwrap()
    };
    let second = write(second_job, "results", entry);
    let first = write(first_job, "coverage", f.object(b"coverage report"));
    let rows = f
        .store
        .read(move |c| artifacts::for_runner_run(c, tenant, repo, github_run))
        .unwrap();
    assert_eq!(
        rows.iter().map(|row| row.id).collect::<Vec<_>>(),
        vec![first, second],
        "a later job of the run reads them in job order"
    );
    assert_eq!(rows[0].origin, artifacts::Origin::Runner);
    assert_eq!(rows[0].github_run, Some(github_run));
    assert_eq!(rows[0].github_job, Some(first_job));
    assert_eq!(rows[0].job, None);
    assert_eq!(
        rows[0].manifest().unwrap(),
        artifacts::runner_manifest_name(repo, github_run, first_job, "coverage")
    );
    assert_eq!(
        f.store
            .read(move |c| retention::repo_usage(c, tenant, repo))
            .unwrap()
            .artifact_bytes,
        rows.iter().map(|row| row.charged_bytes).sum::<u64>(),
        "a row that carries no run is still charged to its repository"
    );
    assert_eq!(
        f.store
            .read(move |c| artifacts::runner_get(c, tenant, repo, github_run, second))
            .unwrap()
            .name,
        "results"
    );
    // Another GitHub run, another tenant and another repository name none of them.
    for (question_tenant, question_run) in [
        (tenant, github_run + 1),
        (f.other, github_run),
        (tenant, github_run),
    ] {
        let got = if question_run == github_run && question_tenant == tenant {
            f.store.read(move |c| {
                artifacts::runner_get(c, question_tenant, RepoId::new(), question_run, second)
            })
        } else {
            f.store.read(move |c| {
                artifacts::runner_get(c, question_tenant, repo, question_run, second)
            })
        };
        assert!(matches!(got, Err(Error::NotFound)), "{question_tenant}");
    }
    // A run-level read of it is NotFound too: it belongs to a GitHub run, not a Sentinel one.
    let run = RunId::new();
    assert!(matches!(
        f.store
            .read(move |c| artifacts::get(c, tenant, run, second)),
        Err(Error::NotFound)
    ));
}

#[test]
fn a_class_age_caps_a_run_level_row_and_the_sweep_retires_the_right_manifest() {
    let f = fixture();
    let (run, _) = f.run();
    let tenant = f.tenant;
    let entry = f.object(b"kept briefly");
    let (uploader, objects) = (f.root, Arc::clone(&f.objects));
    let len = entry.len;
    let id = f
        .store
        .writer()
        .write(move |tx| {
            let charge = artifacts::charge(tx, Some("debug"), len)?;
            let version = objects.commit_manifest(
                tx,
                tenant,
                Kind::Artifact,
                &artifacts::run_manifest_name(run, "trace"),
                &[entry],
            )?;
            artifacts::record_upload(
                tx,
                tenant,
                run,
                "trace",
                &charge,
                version,
                1,
                len,
                UnixMillis(i64::MAX),
                uploader,
                NOW,
            )
        })
        .unwrap();
    let row = f
        .store
        .read(move |c| artifacts::get(c, tenant, run, id))
        .unwrap();
    let debug = f
        .store
        .read(retention::classes)
        .unwrap()
        .classes
        .into_iter()
        .find(|class| class.name == "debug")
        .unwrap();
    assert_eq!(
        row.retain_until_ms,
        UnixMillis(NOW.0 + debug.max_age_ms),
        "the debug class's maximum age caps the row whatever deadline it asked for"
    );
    let sweep = Arc::clone(&f.objects);
    let doomed = f
        .store
        .writer()
        .write(move |tx| artifacts::sweep_expired(tx, &sweep, UnixMillis(i64::MAX), 16))
        .unwrap();
    assert_eq!(doomed.len(), 1, "the row's manifest file is retired");
    assert!(
        f.store
            .read(move |c| artifacts::for_run(c, tenant, run))
            .unwrap()
            .is_empty()
    );
}
