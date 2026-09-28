//! R01: storage quotas and retention at deployment, tenant, repository and
//! run level — policies that only narrow downwards, database-driven log
//! expiry with usage accounting, retention changes applied to what is
//! already stored, and the aborted-upload purge.
use std::sync::Arc;

use sentinel_auth::secret::Secret;
use sentinel_core::{
    AttemptId, JobId, PoolId, RepoId, RunId, TenantId, UnixMillis, UserId, WorkerId,
    auth::{Namespace, Permissions as P, Principal, Role},
};
use sentinel_pipeline::{PinnedSource, RunSpec, compile_str};
use sentinel_protocol::negotiate::{Arch, Capabilities, Negotiated, ProtocolVersion};
use sentinel_store::{
    Durability, Error, Store, artifacts,
    auth::{self, Authority, NamespaceKind, provisioning},
    dispatch::{self, Capacity},
    jobs,
    logs::LogStore,
    objects::{Expect, Objects},
    retention::{self, Deployment, Policy},
    runs,
    tenancy::{self, PoolKind},
    workers::{self, Presentation},
};

const NOW: UnixMillis = UnixMillis(1_000_000_000);
const DAY: i64 = 86_400_000;
const SHA: &str = "0123456789abcdef0123456789abcdef01234567";
const DIGEST: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

struct Fixture {
    dir: tempfile::TempDir,
    store: Store,
    objects: Arc<Objects>,
    root: UserId,
    dev: UserId,
    admin: UserId,
    tenant: TenantId,
    repo: RepoId,
    pool: PoolId,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path().join("metadata.sqlite"), Durability::Normal).unwrap();
    let objects = Arc::new(Objects::open(dir.path()).unwrap());
    let (root, dev, admin) = (UserId::new(), UserId::new(), UserId::new());
    let (tenant, repo, pool) = (TenantId::new(), RepoId::new(), PoolId::new());
    store
        .writer()
        .write(move |tx| {
            provisioning::insert_human(tx, root, "Root", true, NOW)?;
            provisioning::insert_human(tx, dev, "Dev", false, NOW)?;
            provisioning::insert_human(tx, admin, "Admin", false, NOW)?;
            let platform = Principal::new(root, P::ALL, None, None);
            auth::create_namespace(
                tx,
                platform,
                tenant,
                Namespace::parse("acme").unwrap(),
                NamespaceKind::Organization,
                NOW,
            )?;
            auth::set_membership(tx, platform, tenant, admin, Role::TenantAdmin)?;
            auth::set_membership(tx, platform, tenant, dev, Role::Operator)?;
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
        dir,
        store,
        objects,
        root,
        dev,
        admin,
        tenant,
        repo,
        pool,
    }
}

fn credential(user: UserId) -> Authority {
    Authority::credential(Principal::new(user, P::ALL, None, None))
}

impl Fixture {
    fn set(&self, authority: Authority, repo: Option<RepoId>, policy: Policy) -> Result<(), Error> {
        let tenant = self.tenant;
        self.store.writer().write(move |tx| {
            retention::set(
                tx,
                &authority,
                &Deployment::default(),
                tenant,
                repo,
                policy,
                NOW,
            )
        })
    }

    /// A run with one job, placed on a fresh worker, whose attempt was then
    /// released at `released` — the state a finished attempt's log is in.
    fn released_attempt(&self, released: UnixMillis) -> (RunId, JobId, AttemptId) {
        let (tenant, repo, run) = (self.tenant, self.repo, RunId::new());
        let spec = RunSpec::new(
            PinnedSource::new("https://github.com/o/r.git", SHA, Some("main")).unwrap(),
            compile_str(
                "schema: 1\non: [push]\njobs:\n  build:\n    image: alpine:3\n    steps: [{ id: s, run: 'true' }]\n",
            )
            .unwrap(),
        )
        .unwrap();
        let (worker, pool) = (WorkerId::new(), self.pool);
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
                let offer = dispatch::place(tx, worker, pool, dispatch::DEFAULT_LEASE_MS, NOW)?
                    .expect("a queued job was placed");
                tx.execute(
                    "UPDATE attempts SET released_ms = ?2 WHERE id = ?1",
                    rusqlite::params![offer.attempt.as_bytes().as_slice(), released.0],
                )?;
                Ok((ids[0], offer.attempt))
            })
            .unwrap();
        (run, job, attempt)
    }

    /// Stamp every unstamped log with `bytes` under `d`.
    fn stamp(&self, d: Deployment, bytes: u64) -> u32 {
        let rows = self
            .store
            .read(|c| retention::unstamped(c, 256))
            .unwrap()
            .into_iter()
            .map(|r| (r, bytes))
            .collect::<Vec<_>>();
        self.store
            .writer()
            .write(move |tx| retention::stamp(tx, &d, &rows))
            .unwrap()
    }

    fn expires(&self, attempt: AttemptId) -> Option<i64> {
        self.store
            .read(|c| {
                Ok(c.query_row(
                    "SELECT log_expires_ms FROM attempts WHERE id = ?1",
                    [attempt.as_bytes().as_slice()],
                    |r| r.get(0),
                )?)
            })
            .unwrap()
    }
}

#[test]
fn a_tenant_policy_is_platform_administration_and_a_repository_only_narrows_it() {
    let f = fixture();
    let tenant_policy = Policy {
        quota_bytes: Some(1_000),
        log_retention_ms: Some(10 * DAY),
        artifact_retention_ms: Some(20 * DAY),
    };
    // Neither a member nor the tenant's own administrator sets the tenant's.
    for user in [f.dev, f.admin] {
        assert!(matches!(
            f.set(credential(user), None, tenant_policy),
            Err(Error::Forbidden)
        ));
    }
    f.set(credential(f.root), None, tenant_policy).unwrap();

    // The tenant administrator narrows a repository; a member cannot.
    let narrow = Policy {
        quota_bytes: Some(400),
        log_retention_ms: Some(5 * DAY),
        artifact_retention_ms: None,
    };
    assert!(matches!(
        f.set(credential(f.dev), Some(f.repo), narrow),
        Err(Error::Forbidden)
    ));
    f.set(credential(f.admin), Some(f.repo), narrow).unwrap();
    let e = f
        .store
        .read(|c| retention::effective(c, &Deployment::default(), f.tenant, Some(f.repo)))
        .unwrap();
    assert_eq!(e.tenant_quota_bytes, 1_000);
    assert_eq!(e.repo_quota_bytes, 400);
    assert_eq!(e.log_retention_ms, 5 * DAY);
    assert_eq!(
        e.artifact_retention_ms,
        20 * DAY,
        "inherited from the tenant"
    );

    // Nothing past the tenant's own limits, and nothing out of range.
    for wider in [
        Policy {
            log_retention_ms: Some(11 * DAY),
            ..Policy::default()
        },
        Policy {
            artifact_retention_ms: Some(21 * DAY),
            ..Policy::default()
        },
        Policy {
            quota_bytes: Some(1_001),
            ..Policy::default()
        },
        Policy {
            log_retention_ms: Some(1_000),
            ..Policy::default()
        },
    ] {
        assert!(matches!(
            f.set(credential(f.admin), Some(f.repo), wider),
            Err(Error::InvalidInput(_))
        ));
    }

    // A tenant later narrowed below its repository's value still wins.
    f.set(
        Authority::HostLocal,
        None,
        Policy {
            log_retention_ms: Some(2 * DAY),
            ..tenant_policy
        },
    )
    .unwrap();
    let e = f
        .store
        .read(|c| retention::effective(c, &Deployment::default(), f.tenant, Some(f.repo)))
        .unwrap();
    assert_eq!(e.log_retention_ms, 2 * DAY);

    // An empty policy removes the row: the deployment's defaults apply.
    f.set(Authority::HostLocal, Some(f.repo), Policy::default())
        .unwrap();
    f.set(Authority::HostLocal, None, Policy::default())
        .unwrap();
    let e = f
        .store
        .read(|c| retention::effective(c, &Deployment::default(), f.tenant, Some(f.repo)))
        .unwrap();
    let d = Deployment::default();
    assert_eq!(
        (e.tenant_quota_bytes, e.repo_quota_bytes, e.log_retention_ms),
        (0, 0, d.log_retention_ms)
    );
}

#[test]
fn released_logs_are_stamped_counted_and_expired_from_the_database() {
    let f = fixture();
    let d = Deployment::default();
    let (_, _, attempt) = f.released_attempt(NOW);
    assert_eq!(f.stamp(d, 500), 1);
    assert_eq!(f.stamp(d, 999), 0, "a stamped log is left alone");
    assert_eq!(f.expires(attempt), Some(NOW.0 + d.log_retention_ms));
    let (usage, repo) = f
        .store
        .read(|c| {
            Ok((
                retention::tenant_usage(c, f.tenant)?,
                retention::repo_usage(c, f.tenant, f.repo)?,
            ))
        })
        .unwrap();
    assert_eq!((usage.log_bytes, repo.log_bytes), (500, 500));

    // Not due a millisecond early; due at its deadline.
    let due = |at: i64| {
        f.store
            .read(|c| retention::expiring(c, UnixMillis(at), 256))
            .unwrap()
    };
    assert!(due(NOW.0 + d.log_retention_ms - 1).is_empty());
    let expiring = due(NOW.0 + d.log_retention_ms);
    assert_eq!(expiring.len(), 1);
    let at = UnixMillis(NOW.0 + d.log_retention_ms);
    let expired = f
        .store
        .writer()
        .write(move |tx| retention::expire(tx, &expiring, at))
        .unwrap();
    assert_eq!(expired.len(), 1);
    let (usage, repo, gone, when) = f
        .store
        .read(|c| {
            Ok((
                retention::tenant_usage(c, f.tenant)?,
                retention::repo_usage(c, f.tenant, f.repo)?,
                retention::log_gone(c, attempt)?,
                retention::log_expired(c, attempt)?,
            ))
        })
        .unwrap();
    assert_eq!((usage.log_bytes, repo.log_bytes), (0, 0));
    assert!(gone);
    assert_eq!(when, Some(at));
    assert!(
        due(at.0 + DAY).is_empty(),
        "an expired log is not due again"
    );
    // The record is closed: an expired log cannot be un-expired.
    let reopened = f.store.writer().write(move |tx| {
        tx.execute(
            "UPDATE attempts SET log_expired_ms = NULL WHERE id = ?1",
            [attempt.as_bytes().as_slice()],
        )?;
        Ok(())
    });
    assert!(reopened.is_err());
    // An attempt no row names is gone too.
    assert!(
        f.store
            .read(|c| retention::log_gone(c, AttemptId::new()))
            .unwrap()
    );
}

#[test]
fn lowered_retention_applies_to_logs_and_artifacts_already_stored() {
    let f = fixture();
    let d = Deployment::default();
    f.store
        .writer()
        .write(move |tx| retention::install(tx, &d))
        .unwrap();
    let (run, job, attempt) = f.released_attempt(NOW);
    f.stamp(d, 100);
    // A pipeline asking a year is capped at the deployment's 90 days on
    // insert, whatever path writes the row.
    let tenant = f.tenant;
    let artifact = f
        .store
        .writer()
        .write(move |tx| {
            artifacts::record(
                tx,
                tenant,
                run,
                job,
                attempt,
                "out",
                artifacts::State::Failed,
                None,
                0,
                0,
                UnixMillis(NOW.0 + 365 * DAY),
                NOW,
            )
        })
        .unwrap();
    let retained = || {
        f.store
            .read(|c| {
                Ok(c.query_row(
                    "SELECT retain_until_ms FROM artifacts WHERE id = ?1",
                    [artifact.as_bytes().as_slice()],
                    |r| r.get::<_, i64>(0),
                )?)
            })
            .unwrap()
    };
    assert_eq!(retained(), NOW.0 + d.artifact_retention_ms);

    // The tenant lowers both: the stored log and artifact follow at once.
    f.set(
        Authority::HostLocal,
        None,
        Policy {
            log_retention_ms: Some(DAY),
            artifact_retention_ms: Some(7 * DAY),
            ..Policy::default()
        },
    )
    .unwrap();
    assert_eq!(f.expires(attempt), Some(NOW.0 + DAY));
    assert_eq!(retained(), NOW.0 + 7 * DAY);

    // The repository narrows further; then raising the tenant's retention
    // extends the log (still in the store) but never an artifact's deadline.
    f.set(
        Authority::HostLocal,
        Some(f.repo),
        Policy {
            log_retention_ms: Some(3_600_000),
            artifact_retention_ms: Some(DAY),
            ..Policy::default()
        },
    )
    .unwrap();
    assert_eq!(f.expires(attempt), Some(NOW.0 + 3_600_000));
    assert_eq!(retained(), NOW.0 + DAY);
    f.set(Authority::HostLocal, Some(f.repo), Policy::default())
        .unwrap();
    f.set(Authority::HostLocal, None, Policy::default())
        .unwrap();
    assert_eq!(f.expires(attempt), Some(NOW.0 + d.log_retention_ms));
    assert_eq!(retained(), NOW.0 + DAY);
}

#[test]
fn quotas_count_logs_and_hold_at_the_deployment_tenant_and_repository() {
    let f = fixture();
    let tenant = f.tenant;
    let (_, _, _) = f.released_attempt(NOW);
    f.stamp(Deployment::default(), 80);
    let commit = |bytes: &[u8]| -> Result<bool, Error> {
        let staged = f
            .objects
            .stage(tenant, bytes, u64::MAX, Expect::default())
            .unwrap();
        let objects = Arc::clone(&f.objects);
        f.store
            .writer()
            .write(move |tx| objects.commit(tx, &staged))
    };

    // The tenant's quota counts its logs: 80 of 100 are already used.
    f.set(
        Authority::HostLocal,
        None,
        Policy {
            quota_bytes: Some(100),
            ..Policy::default()
        },
    )
    .unwrap();
    f.objects.set_deployment(Deployment::default());
    // As in the server: a disk gate is installed (plenty free), so staged
    // bytes are charged and their commit is checked against the quotas.
    let marks = sentinel_store::space::Watermarks {
        reserve: 1 << 30,
        low: 2 << 30,
        high: 4 << 30,
        floor: 1 << 27,
    };
    f.objects.set_admission(Arc::new(
        sentinel_store::space::Admission::with_probe(marks, || Ok(1 << 50)).unwrap(),
    ));
    assert!(commit(&[1; 20]).unwrap());
    assert!(matches!(commit(&[2; 1]), Err(Error::QuotaExceeded)));
    let objects = Arc::clone(&f.objects);
    let upload = f
        .store
        .writer()
        .write(move |tx| objects.begin_upload(tx, tenant, 1, None, 60_000, UnixMillis::now()));
    assert!(matches!(upload, Err(Error::QuotaExceeded)));

    // The deployment's cap holds whatever the tenant's says.
    f.set(Authority::HostLocal, None, Policy::default())
        .unwrap();
    f.objects.set_deployment(Deployment {
        quota_bytes: 110,
        ..Deployment::default()
    });
    assert!(commit(&[3; 10]).unwrap());
    assert!(matches!(commit(&[4; 1]), Err(Error::QuotaExceeded)));

    // A repository over its own quota refuses another artifact byte.
    let d = Deployment::default();
    let (repo, run) = (f.repo, RunId::new());
    f.set(
        Authority::HostLocal,
        Some(f.repo),
        Policy {
            quota_bytes: Some(80),
            ..Policy::default()
        },
    )
    .unwrap();
    let full = f
        .store
        .read(move |c| Ok(retention::check_repo(c, &d, tenant, repo, 1)))
        .unwrap();
    assert!(matches!(full, Err(Error::QuotaExceeded)));
    let fits = f
        .store
        .read(move |c| Ok(retention::check_repo(c, &d, tenant, repo, 0)))
        .unwrap();
    assert!(fits.is_ok());
    // A run the store does not know has no repository quota to consult.
    assert!(
        f.store
            .read(move |c| retention::check_run_repo(c, &d, tenant, run, 1_000))
            .is_ok()
    );
}

#[test]
fn aborted_uploads_are_purged_after_a_week_and_committed_ones_stay() {
    let f = fixture();
    let tenant = f.tenant;
    let objects = Arc::clone(&f.objects);
    let start = UnixMillis::now();
    let (aborted, sealed) = f
        .store
        .writer()
        .write(move |tx| {
            let aborted = objects.begin_upload(tx, tenant, 3, None, 60_000, start)?;
            let sealed = objects.begin_upload(tx, tenant, 3, None, 60_000, start)?;
            objects.abort_upload(tx, tenant, aborted)?;
            Ok((aborted, sealed))
        })
        .unwrap();
    let objects = Arc::clone(&f.objects);
    f.store
        .writer()
        .write(move |tx| objects.put_chunk(tx, tenant, sealed, 0, b"abc", start))
        .unwrap();
    let objects = Arc::clone(&f.objects);
    f.store
        .writer()
        .write(move |tx| objects.seal_upload(tx, tenant, sealed, start))
        .unwrap();
    let purge = |at: i64| {
        f.store
            .writer()
            .write(move |tx| retention::purge_aborted_uploads(tx, UnixMillis(at), 256))
            .unwrap()
    };
    assert_eq!(purge(start.0 + DAY), 0, "kept a week for explanation");
    assert_eq!(purge(start.0 + 8 * DAY), 1);
    let left: Vec<Vec<u8>> = f
        .store
        .read(|c| {
            let mut stmt = c.prepare("SELECT id FROM uploads")?;
            let ids = stmt
                .query_map([], |r| r.get(0))?
                .collect::<Result<_, _>>()?;
            Ok(ids)
        })
        .unwrap();
    assert_eq!(left, vec![sealed.as_bytes().to_vec()]);
    assert_ne!(aborted, sealed);
}

#[test]
fn the_log_sweep_removes_only_what_the_database_released() {
    let f = fixture();
    let logs = LogStore::open(f.dir.path().join("logs")).unwrap();
    let frame = sentinel_protocol::logs::Frame {
        seq: 1,
        step: 0,
        stream: sentinel_protocol::logs::Stream::Stdout,
        bytes: b"x\n".to_vec(),
    };
    let (kept_run, kept_job, kept) = f.released_attempt(NOW);
    let (old_run, old_job, old) = f.released_attempt(NOW);
    let (stray_run, stray_job, stray) = (RunId::new(), JobId::new(), AttemptId::new());
    for (run, job, attempt) in [
        (kept_run, kept_job, kept),
        (old_run, old_job, old),
        (stray_run, stray_job, stray),
    ] {
        logs.append(run, job, attempt, &frame).unwrap();
        logs.finish(run, job, attempt, 1, &[]).unwrap();
        logs.forget(attempt);
    }
    assert!(logs.stored_bytes(kept_run, kept_job, kept) > 0);
    let d = Deployment::default();
    f.stamp(d, 10);
    // Only `old` reaches its deadline.
    f.store
        .writer()
        .write(move |tx| {
            tx.execute(
                "UPDATE attempts SET log_expires_ms = ?2 WHERE id = ?1",
                rusqlite::params![old.as_bytes().as_slice(), NOW.0],
            )?;
            Ok(())
        })
        .unwrap();
    let due = f.store.read(|c| retention::expiring(c, NOW, 256)).unwrap();
    let expired = f
        .store
        .writer()
        .write(move |tx| retention::expire(tx, &due, NOW))
        .unwrap();
    assert_eq!(expired.len(), 1);
    // A crash here would leave `old`'s files: the sweep still takes them,
    // and the stray no row names, and keeps `kept`.
    let swept = logs
        .sweep_dirs(256, |attempt| {
            f.store.read(|c| retention::log_gone(c, attempt)).unwrap()
        })
        .unwrap();
    assert_eq!(swept, 2);
    assert!(logs.attempt_dir(kept_run, kept_job, kept).exists());
    assert!(!logs.attempt_dir(old_run, old_job, old).exists());
    assert!(!logs.attempt_dir(stray_run, stray_job, stray).exists());
    // `remove` of an already-removed log is not an error.
    logs.remove(old_run, old_job, old).unwrap();
}
