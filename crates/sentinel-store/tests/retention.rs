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
        let d = Deployment::default();
        let rest = self
            .store
            .writer()
            .write(move |tx| retention::set(tx, &authority, &d, tenant, repo, policy, NOW))?;
        retention::finish_reapply(&self.store, &d, tenant, repo, rest)
    }

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
    for user in [f.dev, f.admin] {
        assert!(matches!(
            f.set(credential(user), None, tenant_policy),
            Err(Error::Forbidden)
        ));
    }
    f.set(credential(f.root), None, tenant_policy).unwrap();

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
    // Capped at the deployment limit on insert, whatever path writes the row.
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
    // Two ceilings apply at insert: the deployment's artifact retention and the class's maximum
    // age. A declaration that names no class takes the deployment's default (`standard`, 30 days).
    assert_eq!(retained(), NOW.0 + 30 * DAY);
    assert!(NOW.0 + 30 * DAY < NOW.0 + d.artifact_retention_ms);

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
fn reapplying_a_policy_is_bounded_per_write_and_resumes_to_the_same_result() {
    let f = fixture();
    let d = Deployment::default();
    f.store
        .writer()
        .write(move |tx| retention::install(tx, &d))
        .unwrap();
    let attempts: Vec<AttemptId> = (0..5).map(|_| f.released_attempt(NOW).2).collect();
    f.stamp(d, 10);
    for attempt in &attempts {
        assert_eq!(f.expires(*attempt), Some(NOW.0 + d.log_retention_ms));
    }
    let tenant = f.tenant;
    f.store
        .writer()
        .write(move |tx| {
            tx.execute(
                "INSERT INTO storage_policies(tenant_id, repo_id, log_retention_ms, updated_ms)
                 VALUES (?1, X'', ?2, ?3)
                 ON CONFLICT(tenant_id, repo_id) DO UPDATE SET
                     log_retention_ms = excluded.log_retention_ms",
                rusqlite::params![tenant.as_bytes().as_slice(), DAY, NOW.0],
            )?;
            Ok(())
        })
        .unwrap();
    let narrowed = |f: &Fixture| {
        attempts
            .iter()
            .filter(|a| f.expires(**a) == Some(NOW.0 + DAY))
            .count()
    };
    assert_eq!(narrowed(&f), 0);
    let step = |f: &Fixture, at: retention::Reapply| {
        f.store
            .writer()
            .write(move |tx| retention::reapply_step(tx, &d, tenant, None, at, 2))
            .unwrap()
    };
    let first = step(&f, retention::Reapply::default());
    assert!(!first.done());
    assert_eq!(narrowed(&f), 2, "one batch touches at most its size");
    let mut at = first;
    let mut steps = 1;
    while !at.done() {
        at = step(&f, at);
        steps += 1;
        assert!(steps < 20, "the cursor must advance");
    }
    assert_eq!(narrowed(&f), 5);
    assert!(
        steps >= 3,
        "five rows in batches of two take several writes"
    );
    let mut again = retention::Reapply::default();
    while !again.done() {
        again = step(&f, again);
    }
    assert_eq!(narrowed(&f), 5);
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

    f.set(Authority::HostLocal, None, Policy::default())
        .unwrap();
    f.objects.set_deployment(Deployment {
        quota_bytes: 110,
        ..Deployment::default()
    });
    assert!(commit(&[3; 10]).unwrap());
    assert!(matches!(commit(&[4; 1]), Err(Error::QuotaExceeded)));

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
    let swept = logs
        .sweep_dirs(256, |attempt| {
            f.store.read(|c| retention::log_gone(c, attempt)).unwrap()
        })
        .unwrap();
    assert_eq!(swept, 2);
    assert!(logs.attempt_dir(kept_run, kept_job, kept).exists());
    assert!(!logs.attempt_dir(old_run, old_job, old).exists());
    assert!(!logs.attempt_dir(stray_run, stray_job, stray).exists());
    logs.remove(old_run, old_job, old).unwrap();
}

#[test]
fn reapplying_for_a_repository_with_no_rows_finishes_and_touches_nothing() {
    let f = fixture();
    let d = Deployment::default();
    f.store
        .writer()
        .write(move |tx| retention::install(tx, &d))
        .unwrap();
    let attempts: Vec<AttemptId> = (0..3).map(|_| f.released_attempt(NOW).2).collect();
    f.stamp(d, 10);
    let (tenant, other) = (f.tenant, RepoId::new());
    f.store
        .writer()
        .write(move |tx| {
            tx.execute(
                "INSERT INTO storage_policies(tenant_id, repo_id, log_retention_ms, updated_ms)
                 VALUES (?1, X'', ?2, ?3)",
                rusqlite::params![tenant.as_bytes().as_slice(), DAY, NOW.0],
            )?;
            Ok(())
        })
        .unwrap();
    let mut at = retention::Reapply::default();
    let mut steps = 0;
    while !at.done() {
        at = f
            .store
            .writer()
            .write(move |tx| retention::reapply_step(tx, &d, tenant, Some(other), at, 1))
            .unwrap();
        steps += 1;
        assert!(steps < 20, "the cursor must advance");
    }
    for a in attempts {
        assert_eq!(f.expires(a), Some(NOW.0 + d.log_retention_ms));
    }
}

fn plan(conn: &rusqlite::Connection, sql: &str) -> Vec<String> {
    let mut stmt = conn
        .prepare(&format!("EXPLAIN QUERY PLAN {sql}"))
        .unwrap_or_else(|e| panic!("SQLite refused {sql}: {e}"));
    let values = vec![rusqlite::types::Value::Null; stmt.parameter_count()];
    stmt.query_map(rusqlite::params_from_iter(values), |r| r.get(3))
        .unwrap()
        .map(|r| r.unwrap())
        .collect()
}

fn expires_column(logs: bool) -> &'static str {
    if logs {
        "log_retention_ms"
    } else {
        "artifact_retention_ms"
    }
}

#[test]
fn reapply_statements_seek_the_tenants_keyed_index_and_probe_runs_by_key() {
    let f = fixture();
    for logs in [true, false] {
        let (table, index) = if logs {
            ("attempts", "attempts_log_reapply")
        } else {
            ("artifacts", "artifacts_reapply")
        };
        for scoped in [false, true] {
            let (bound, update) = retention::reapply_sql(
                logs,
                scoped,
                expires_column(logs),
                retention::REAPPLY_BATCH,
            );
            for (is_update, sql) in [(false, bound), (true, update)] {
                // `plan` also proves SQLite accepts INDEXED BY, including on the partial index.
                let plan = f.store.read(|c| Ok(plan(c, &sql))).unwrap();
                assert!(
                    plan.iter()
                        .any(|p| p.starts_with(&format!("SEARCH {table} USING "))
                            && p.contains(&format!("INDEX {index} (tenant_id=? AND id>?"))),
                    "{sql} does not range-seek {index} from the cursor: {plan:?}"
                );
                for scanned in ["attempts", "artifacts", "runs"] {
                    assert!(
                        plan.iter()
                            .all(|p| !p.starts_with(&format!("SCAN {scanned}"))),
                        "{sql} scans {scanned}: {plan:?}"
                    );
                }
                assert!(
                    plan.iter()
                        .all(|p| !p.contains("TEMP B-TREE") && !p.contains("LIST SUBQUERY")),
                    "{sql} sorts or builds a set per batch: {plan:?}"
                );
                if is_update && !logs {
                    // Each artifact reads its run by primary key for the retention it inherits;
                    // a repository scope adds one more such probe, and never a set of runs.
                    let probes = plan
                        .iter()
                        .filter(|p| p.starts_with("SEARCH runs USING PRIMARY KEY (id=?"))
                        .count();
                    assert_eq!(probes, 1 + usize::from(scoped), "{sql}: {plan:?}");
                }
            }
        }
    }
}

impl Fixture {
    /// `n` more released attempts, each with an artifact, all in this repository.
    fn add_rows(&self, n: usize) {
        for i in 0..n {
            let (run, job, attempt) = self.released_attempt(NOW);
            let tenant = self.tenant;
            let name = format!("out{i}");
            self.store
                .writer()
                .write(move |tx| {
                    artifacts::record(
                        tx,
                        tenant,
                        run,
                        job,
                        attempt,
                        &name,
                        artifacts::State::Failed,
                        None,
                        0,
                        0,
                        UnixMillis(NOW.0 + DAY),
                        NOW,
                    )
                })
                .unwrap();
        }
    }

    /// SQLite virtual-machine steps the cursor bound and the update take for the first batch.
    fn first_batch_steps(&self, d: Deployment, logs: bool, scoped: bool, batch: i64) -> (i32, i32) {
        use rusqlite::{params, types::ValueRef};
        let (tenant, repo) = (self.tenant, self.repo);
        self.store
            .writer()
            .write(move |tx| {
                let (bound_sql, update_sql) =
                    retention::reapply_sql(logs, scoped, expires_column(logs), batch);
                let retention = if logs {
                    d.log_retention_ms
                } else {
                    d.artifact_retention_ms
                };
                let t = tenant.as_bytes().as_slice();
                let r = scoped.then(|| repo.as_bytes().as_slice());
                let after = [0u8; 16];
                let mut bound_stmt = tx.prepare(&bound_sql)?;
                let mut rows = bound_stmt.query(params![t, retention, r, after.as_slice()])?;
                let upper: [u8; 16] = match rows.next()? {
                    Some(row) => match row.get_ref(0)? {
                        ValueRef::Blob(b) => b.try_into().expect("a 16-byte id"),
                        other => panic!("not an id: {other:?}"),
                    },
                    None => panic!("the first batch has a bound"),
                };
                drop(rows);
                let bound_steps = bound_stmt.get_status(rusqlite::StatementStatus::VmStep);
                let mut update = tx.prepare(&update_sql)?;
                let changed =
                    update.execute(params![t, retention, r, after.as_slice(), upper.as_slice()])?;
                assert!(changed >= 1 && changed as i64 <= batch, "{changed} rows");
                Ok((
                    bound_steps,
                    update.get_status(rusqlite::StatementStatus::VmStep),
                ))
            })
            .unwrap()
    }
}

#[test]
fn a_reapply_batch_scans_rows_in_proportion_to_the_batch_not_to_the_table() {
    let f = fixture();
    let d = Deployment::default();
    f.store
        .writer()
        .write(move |tx| retention::install(tx, &d))
        .unwrap();
    f.add_rows(4);
    f.stamp(d, 10);
    let cases = [(true, false), (true, true), (false, false), (false, true)];
    let small: Vec<_> = cases
        .iter()
        .map(|&(logs, scoped)| f.first_batch_steps(d, logs, scoped, 2))
        .collect();
    f.add_rows(56);
    f.stamp(d, 10);
    for (&(logs, scoped), (bound, update)) in cases.iter().zip(small) {
        let (big_bound, big_update) = f.first_batch_steps(d, logs, scoped, 2);
        // Fifteen times the rows (and runs) must not move the work of a two-row batch: a scan
        // of the tenant's rows, or a set built from the repository's runs, would multiply it.
        assert!(
            big_bound <= bound + bound / 4 && big_update <= update + update / 4,
            "logs={logs} scoped={scoped}: bound {bound} -> {big_bound}, update {update} -> {big_update}"
        );
    }
}

/// Each maintenance read names a partial index with `INDEXED BY`; SQLite refuses to prepare the statement when
/// that index cannot answer the query, so running them against the migrated schema proves the index still serves
/// its predicate.
#[test]
fn maintenance_reads_are_served_by_their_partial_indexes() {
    let f = fixture();
    f.store
        .read(|c| {
            assert!(retention::unstamped(c, 256).unwrap().is_empty());
            assert!(
                retention::expiring(c, UnixMillis(i64::MAX), 256)
                    .unwrap()
                    .is_empty()
            );
            Ok(())
        })
        .unwrap();
    f.store
        .writer()
        .write(|tx| {
            assert_eq!(
                retention::purge_aborted_uploads(tx, UnixMillis(i64::MAX), 256).unwrap(),
                0
            );
            Ok(())
        })
        .unwrap();
}

/// Outside damage to a row's id, as a disk fault or a hand-edit would leave it: still 16 bytes, so the schema's check accepts it,
/// but no UUID version 4. The immutability trigger is dropped on this separate connection only to let the test write it.
fn damage_attempt_id(f: &Fixture, attempt: AttemptId) {
    let db = rusqlite::Connection::open(f.dir.path().join("metadata.sqlite")).unwrap();
    db.busy_timeout(std::time::Duration::from_secs(10)).unwrap();
    db.execute_batch("PRAGMA foreign_keys = OFF; DROP TRIGGER attempt_update;")
        .unwrap();
    let changed = db
        .execute(
            "UPDATE attempts SET id = ?2 WHERE id = ?1",
            rusqlite::params![attempt.as_bytes().as_slice(), [0u8; 16].as_slice()],
        )
        .unwrap();
    assert_eq!(changed, 1);
}

/// A row that cannot be decoded sits at the head of both queries for good: failing the batch on it would stop every log behind it,
/// at every pass, and say nothing.
#[test]
fn a_malformed_attempt_row_does_not_stop_stamping_or_expiry() {
    let f = fixture();
    let (_, _, bad) = f.released_attempt(UnixMillis(100));
    let (_, _, first) = f.released_attempt(UnixMillis(200));
    let (_, _, second) = f.released_attempt(UnixMillis(300));
    damage_attempt_id(&f, bad);

    let skipped_before = sentinel_store::skipped::total();
    assert_eq!(f.stamp(Deployment::default(), 10), 2);
    assert!(f.expires(first).is_some() && f.expires(second).is_some());
    assert!(
        sentinel_store::skipped::total() > skipped_before,
        "the passed-over row is counted"
    );
    let row = sentinel_store::skipped::last().unwrap();
    assert_eq!(row.table, "attempts");
    assert_eq!(
        row.key,
        "00".repeat(16),
        "named by its key, nothing else of it"
    );

    // The damaged row is due as well, and still first in line.
    f.store
        .writer()
        .write(|tx| {
            tx.execute("UPDATE attempts SET log_expires_ms = 1", [])?;
            Ok(())
        })
        .unwrap();
    let skipped_before = sentinel_store::skipped::total();
    let due = f.store.read(|c| retention::expiring(c, NOW, 256)).unwrap();
    assert_eq!(
        due.iter()
            .map(|d| d.attempt)
            .collect::<std::collections::HashSet<_>>(),
        [first, second].into_iter().collect()
    );
    assert!(sentinel_store::skipped::total() > skipped_before);
    let expired = f
        .store
        .writer()
        .write(move |tx| retention::expire(tx, &due, NOW))
        .unwrap();
    assert_eq!(expired.len(), 2);
}

/// A captured artifact of this repository, with `bytes` staged content, due at `retain_until`.
fn capture(
    f: &Fixture,
    name: &str,
    class: Option<&str>,
    bytes: u64,
    retain_until: UnixMillis,
) -> Result<sentinel_core::ArtifactId, Error> {
    let (run, job, attempt) = f.released_attempt(NOW);
    let (tenant, name, class) = (f.tenant, name.to_owned(), class.map(str::to_owned));
    f.store.writer().write(move |tx| {
        artifacts::record_class(
            tx,
            tenant,
            run,
            job,
            attempt,
            &name,
            class.as_deref(),
            artifacts::State::Captured,
            Some(1),
            bytes,
            bytes,
            retain_until,
            NOW,
        )
    })
}

impl Fixture {
    fn retained(&self, artifact: sentinel_core::ArtifactId) -> (String, u64, i64, Option<i64>) {
        self.store
            .read(|c| {
                Ok(c.query_row(
                    "SELECT class, charged_bytes, retain_until_ms, pinned_ms FROM artifacts
                     WHERE id = ?1",
                    [artifact.as_bytes().as_slice()],
                    |r| {
                        Ok((
                            r.get::<_, String>(0)?,
                            r.get::<_, i64>(1)?.max(0) as u64,
                            r.get(2)?,
                            r.get(3)?,
                        ))
                    },
                )?)
            })
            .unwrap()
    }

    fn swept(&self, now: UnixMillis) -> usize {
        let objects = Arc::clone(&self.objects);
        self.store
            .writer()
            .write(move |tx| Ok(artifacts::sweep_expired_counted(tx, &objects, now, 64)?.1))
            .unwrap()
    }
}

#[test]
fn a_class_maximum_age_shortens_a_longer_retain_at_insert() {
    let f = fixture();
    let d = Deployment::default();
    f.store
        .writer()
        .write(move |tx| retention::install(tx, &d))
        .unwrap();
    let year = UnixMillis(NOW.0 + 365 * DAY);
    // A pipeline's `retain` is only a request: the class's maximum age caps it.
    let debug = capture(&f, "debug-out", Some("debug"), 10, year).unwrap();
    assert_eq!(f.retained(debug).0, "debug");
    assert_eq!(f.retained(debug).2, NOW.0 + 7 * DAY);
    // A declaration that names no class takes the deployment's default class.
    let plain = capture(&f, "plain", None, 10, year).unwrap();
    assert_eq!(f.retained(plain).0, "standard");
    assert_eq!(f.retained(plain).2, NOW.0 + 30 * DAY);
    // A class cannot outlive what the deployment keeps artifacts for.
    let evidence = capture(&f, "evidence", Some("evidence"), 10, year).unwrap();
    assert_eq!(f.retained(evidence).2, NOW.0 + d.artifact_retention_ms);
    // The class weight counts the artifact's bytes against its repository quota.
    let release = capture(&f, "release", Some("release"), 10, year).unwrap();
    assert_eq!(f.retained(release).1, 2 * 10);
    assert_eq!(
        f.store
            .read(|c| retention::repo_usage(c, f.tenant, f.repo))
            .unwrap()
            .total(),
        10 + 10 + 10 + 20
    );
    // A class the deployment does not define is refused, whatever the pipeline asked for.
    assert!(matches!(
        capture(&f, "unknown", Some("gold"), 10, year),
        Err(Error::InvalidInput("artifact class"))
    ));
}

#[test]
fn a_pin_survives_the_sweep_counts_against_the_quota_and_unpinning_restores_the_deadline() {
    let f = fixture();
    let tenant = f.tenant;
    let artifact = capture(&f, "kept", Some("debug"), 500, UnixMillis(NOW.0 + DAY)).unwrap();
    let (run, _, _) = f.released_attempt(NOW);
    let _ = run;
    let (run, artifact_id) = f
        .store
        .read(|c| {
            let (run,): (Vec<u8>,) = c.query_row(
                "SELECT run_id FROM artifacts WHERE id = ?1",
                [artifact.as_bytes().as_slice()],
                |r| Ok((r.get(0)?,)),
            )?;
            Ok((
                sentinel_core::RunId::from_bytes(<[u8; 16]>::try_from(run.as_slice()).unwrap())
                    .unwrap(),
                artifact,
            ))
        })
        .unwrap();
    // Retention is the tenant administrator's decision, never an operator's.
    assert!(matches!(
        f.store.writer().write(move |tx| retention::pin(
            tx,
            &credential(f.dev),
            tenant,
            run,
            artifact_id,
            NOW
        )),
        Err(Error::Forbidden)
    ));
    let first = f
        .store
        .writer()
        .write(move |tx| retention::pin(tx, &credential(f.admin), tenant, run, artifact_id, NOW))
        .unwrap();
    assert_eq!(first, NOW);
    let again = f
        .store
        .writer()
        .write(move |tx| {
            retention::pin(
                tx,
                &credential(f.admin),
                tenant,
                run,
                artifact_id,
                UnixMillis(NOW.0 + DAY),
            )
        })
        .unwrap();
    assert_eq!(again, NOW, "a second pin keeps the first pin's time");
    assert_eq!(f.retained(artifact).3, Some(NOW.0));
    // Past its deadline the pinned artifact is still there, and so are its bytes.
    assert_eq!(f.swept(UnixMillis(NOW.0 + 2 * DAY)), 0);
    assert_eq!(f.retained(artifact).3, Some(NOW.0));
    assert_eq!(
        f.store
            .read(|c| retention::repo_usage(c, tenant, f.repo))
            .unwrap()
            .total(),
        500
    );
    // Unpinning puts the stored deadline back into effect: the next sweep collects it.
    f.store
        .writer()
        .write(move |tx| retention::unpin(tx, &credential(f.admin), tenant, run, artifact_id))
        .unwrap();
    assert_eq!(f.retained(artifact).3, None);
    assert_eq!(f.swept(UnixMillis(NOW.0 + 2 * DAY)), 1);
    assert_eq!(
        f.store
            .read(|c| retention::repo_usage(c, tenant, f.repo))
            .unwrap()
            .total(),
        0,
        "the quota gets the bytes back with the row"
    );
    assert!(matches!(
        f.store.writer().write(move |tx| retention::unpin(
            tx,
            &credential(f.admin),
            tenant,
            run,
            artifact_id
        )),
        Err(Error::NotFound)
    ));
}

#[test]
fn a_class_change_reapplies_only_its_rows_and_keeps_its_plan_keyed() {
    let f = fixture();
    let d = Deployment::default();
    f.store
        .writer()
        .write(move |tx| retention::install(tx, &d))
        .unwrap();
    let long = UnixMillis(NOW.0 + 365 * DAY);
    let (one, two) = (
        capture(&f, "one", Some("debug"), 100, long).unwrap(),
        capture(&f, "two", Some("debug"), 100, long).unwrap(),
    );
    let other = capture(&f, "three", Some("release"), 100, long).unwrap();
    let release_before = f.retained(other);
    assert_eq!(f.retained(one).2, NOW.0 + 7 * DAY);

    // The deployment shortens `debug` to a day and doubles its weight.
    let classes = retention::Classes {
        default_class: "standard".into(),
        classes: vec![
            retention::Class {
                name: "debug".into(),
                max_age_ms: DAY,
                weight: 2,
            },
            retention::Class {
                name: "standard".into(),
                max_age_ms: 30 * DAY,
                weight: 1,
            },
            retention::Class {
                name: "evidence".into(),
                max_age_ms: 90 * DAY,
                weight: 1,
            },
            retention::Class {
                name: "release".into(),
                max_age_ms: 90 * DAY,
                weight: 2,
            },
        ],
    };
    let changed = f
        .store
        .writer()
        .write(move |tx| retention::install_classes(tx, &d, &classes))
        .unwrap();
    assert_eq!(changed, ["debug"]);
    let debug = retention::Class {
        name: "debug".into(),
        max_age_ms: DAY,
        weight: 2,
    };

    // The statements seek the class's own keyed index: no scan, no sort, one run probe a row.
    let (bound, update) = retention::class_reapply_sql(retention::REAPPLY_BATCH);
    for sql in [&bound, &update] {
        let plan = f.store.read(|c| Ok(plan(c, sql))).unwrap();
        assert!(
            plan.iter().any(|p| p
                .starts_with("SEARCH artifacts USING INDEX artifacts_class_reapply")
                && p.contains("(class=? AND id>?")),
            "{sql} does not range-seek the class index: {plan:?}"
        );
        for scanned in ["attempts", "artifacts", "runs"] {
            assert!(
                plan.iter()
                    .all(|p| !p.starts_with(&format!("SCAN {scanned}"))),
                "{sql} scans {scanned}: {plan:?}"
            );
        }
        assert!(
            plan.iter()
                .all(|p| !p.contains("TEMP B-TREE") && !p.contains("LIST SUBQUERY")),
            "{sql} sorts or builds a set per batch: {plan:?}"
        );
    }
    let plan = f.store.read(|c| Ok(plan(c, &update))).unwrap();
    assert_eq!(
        plan.iter()
            .filter(|p| p.starts_with("SEARCH runs USING PRIMARY KEY (id=?"))
            .count(),
        1,
        "each re-applied artifact reads its own run by key: {plan:?}"
    );

    // One row per write: a two-row class takes two bounded steps.
    let step = |at: retention::ClassReapply, batch: i64| {
        let class = debug.clone();
        f.store
            .writer()
            .write(move |tx| retention::class_reapply_step(tx, &class, &d, at, batch))
            .unwrap()
    };
    let first = step(retention::ClassReapply::default(), 1);
    assert!(!first.done());
    let restamped = |f: &Fixture| {
        [one, two]
            .iter()
            .filter(|a| f.retained(**a).2 == NOW.0 + DAY)
            .count()
    };
    assert_eq!(restamped(&f), 1, "one row a step, in its own class");
    assert_eq!(f.retained(one).2.max(f.retained(two).2), NOW.0 + 7 * DAY);
    let mut at = first;
    let mut steps = 1;
    while !at.done() {
        at = step(at, 1);
        steps += 1;
        assert!(steps < 8, "the cursor must advance");
    }
    assert!(steps >= 3, "two rows in batches of one take several writes");
    for artifact in [one, two] {
        assert_eq!(f.retained(artifact).2, NOW.0 + DAY);
        assert_eq!(f.retained(artifact).1, 200, "the new weight is charged");
    }
    assert_eq!(
        f.retained(other),
        release_before,
        "another class is untouched"
    );
}

#[test]
fn a_repository_narrowing_below_its_class_still_wins() {
    let f = fixture();
    let d = Deployment::default();
    f.store
        .writer()
        .write(move |tx| retention::install(tx, &d))
        .unwrap();
    let artifact = capture(
        &f,
        "kept",
        Some("evidence"),
        10,
        UnixMillis(NOW.0 + 365 * DAY),
    )
    .unwrap();
    assert_eq!(f.retained(artifact).2, NOW.0 + d.artifact_retention_ms);
    f.set(
        Authority::HostLocal,
        Some(f.repo),
        Policy {
            artifact_retention_ms: Some(3 * DAY),
            ..Policy::default()
        },
    )
    .unwrap();
    assert_eq!(f.retained(artifact).2, NOW.0 + 3 * DAY);
    // Raising the repository back under the class's ceiling extends it again; the class still caps.
    f.set(
        Authority::HostLocal,
        Some(f.repo),
        Policy {
            artifact_retention_ms: Some(200 * DAY),
            ..Policy::default()
        },
    )
    .expect_err("above the tenant's");
    f.set(Authority::HostLocal, Some(f.repo), Policy::default())
        .unwrap();
    assert_eq!(
        f.retained(artifact).2,
        NOW.0 + 3 * DAY,
        "an artifact's deadline never extends"
    );
}
