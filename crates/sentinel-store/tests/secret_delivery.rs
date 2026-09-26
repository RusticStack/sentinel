use std::sync::Arc;

use sentinel_auth::{sealed::Key, secret::Secret};
use sentinel_core::{
    Event, Fence, RepoId, RunId, TenantId, UnixMillis, UserId, WorkerId,
    auth::{Namespace, Permissions, Principal, Role},
};
use sentinel_pipeline::{PinnedSource, RunSpec, compile_str};
use sentinel_protocol::negotiate::{Arch, Capabilities, Negotiated, ProtocolVersion};
use sentinel_store::{
    Durability, Error, Store,
    auth::{self, Authority, NamespaceKind, provisioning},
    dispatch::{self, Capacity},
    runs,
    secrets::{self, Binding, Scope},
    tenancy::{self, PoolKind},
    workers::{self, Presentation},
};

const NOW: UnixMillis = UnixMillis(1_000);
const SHA: &str = "0123456789abcdef0123456789abcdef01234567";
const DIGEST: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const YAML: &str = "schema: 1\non: [push]\njobs:\n  build:\n    image: busybox@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n    resources: { cpu: 1, memory: 128MiB }\n    secrets: [TOKEN, CERT, OCI_AUTH]\n    registry_auth: OCI_AUTH\n    steps:\n      - id: test\n        run: 'test -n \"$TOKEN\"'\n        secrets: [TOKEN]\n        secret_files: { CERT: tls/client.pem }\n";

struct Fixture {
    _dir: tempfile::TempDir,
    store: Store,
    key: Arc<Key>,
    root: UserId,
    tenant: TenantId,
    repo: RepoId,
    pool: sentinel_core::PoolId,
    worker: WorkerId,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("master.key");
    Key::create(&key_path).unwrap();
    let key = Arc::new(Key::load(&key_path).unwrap());
    let store = Store::open(dir.path().join("metadata.sqlite"), Durability::Normal).unwrap();
    let (root, tenant, repo, pool, worker) = (
        UserId::new(),
        TenantId::new(),
        RepoId::new(),
        sentinel_core::PoolId::new(),
        WorkerId::new(),
    );
    let admin = Principal::new(root, Permissions::ALL, None, None);
    let fingerprint = Secret::generate().digest();
    store
        .writer()
        .write({
            let key = key.clone();
            move |tx| {
                provisioning::insert_human(tx, root, "root", true, NOW)?;
                auth::create_namespace(
                    tx,
                    admin,
                    tenant,
                    Namespace::parse("acme").unwrap(),
                    NamespaceKind::Organization,
                    NOW,
                )?;
                auth::set_membership(tx, admin, tenant, root, Role::TenantAdmin)?;
                auth::create_repo(tx, admin, tenant, repo, "app", NOW)?;
                tenancy::create_pool(
                    tx,
                    Authority::HostLocal,
                    pool,
                    "builders",
                    PoolKind::Dedicated(tenant),
                    NOW,
                )?;
                let issued =
                    workers::issue_enrollment(tx, Authority::HostLocal, pool, 60_000, NOW)?;
                let mut enrollment = String::new();
                issued.secret.expose(&mut enrollment);
                workers::enroll(
                    tx,
                    &Secret::parse(&enrollment).unwrap(),
                    Presentation {
                        worker,
                        fingerprint,
                        name: "secret-test-worker",
                        negotiated: Negotiated {
                            protocol: ProtocolVersion(10),
                            capabilities: Capabilities(
                                Capabilities::REQUIRED.0 | Capabilities::SECRET_DELIVERY.0,
                            ),
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

                let put = |name, expected, value| {
                    secrets::put(
                        tx,
                        admin,
                        secrets::Update {
                            scope: Scope::Repo(repo),
                            name,
                            expected,
                            value,
                        },
                        &key,
                        NOW,
                    )
                };
                let token = put("TOKEN", 0, b"token-v1")?;
                let cert = put("CERT", 0, b"certificate-v1")?;
                let registry = put(
                    "OCI_AUTH",
                    0,
                    br#"{"auths":{"ghcr.io":{"auth":"dG9rZW4tdjE="}}}"#,
                )?;
                for (name, secret) in [
                    ("TOKEN", token.id),
                    ("CERT", cert.id),
                    ("OCI_AUTH", registry.id),
                ] {
                    secrets::bind(
                        tx,
                        admin,
                        &Binding {
                            repo,
                            job: "build".into(),
                            step: "".into(),
                            name: name.into(),
                            secret,
                            override_tenant: false,
                        },
                        NOW,
                    )?;
                }
                Ok(())
            }
        })
        .unwrap();
    Fixture {
        _dir: dir,
        store,
        key,
        root,
        tenant,
        repo,
        pool,
        worker,
    }
}

fn create_run(f: &Fixture, now: UnixMillis) -> (RunId, sentinel_core::JobId) {
    let spec = RunSpec::new(
        PinnedSource::new("https://example.test/acme/app.git", SHA, Some("main")).unwrap(),
        compile_str(YAML).unwrap(),
    )
    .unwrap();
    let (run, tenant, repo) = (RunId::new(), f.tenant, f.repo);
    let jobs = f
        .store
        .writer()
        .write(move |tx| {
            let jobs = runs::create_run(tx, tenant, repo, run, &spec, now)?;
            runs::resolve_image(tx, tenant, jobs[0], DIGEST, "linux/amd64")?;
            Ok(jobs)
        })
        .unwrap();
    (run, jobs[0])
}

fn next_offer(f: &Fixture, now: UnixMillis) -> dispatch::Offer {
    let (worker, pool) = (f.worker, f.pool);
    f.store
        .writer()
        .write(move |tx| dispatch::place(tx, worker, pool, dispatch::DEFAULT_LEASE_MS, now))
        .unwrap()
        .unwrap()
}

fn acknowledge(f: &Fixture, offer: &dispatch::Offer, now: UnixMillis) {
    let worker = f.worker;
    let (attempt, fence) = (offer.attempt, offer.fence);
    f.store
        .writer()
        .write(move |tx| dispatch::acknowledge(tx, worker, attempt, fence, now))
        .unwrap();
}

fn finish(f: &Fixture, offer: &dispatch::Offer) {
    let worker = f.worker;
    let (attempt, fence) = (offer.attempt, offer.fence);
    f.store
        .writer()
        .write(move |tx| {
            for (ms, event) in [
                (2_200, Event::PreparationStarted),
                (2_300, Event::StepsStarted),
                (2_400, Event::FinalizationStarted),
                (2_500, Event::Passed),
            ] {
                dispatch::report(
                    tx,
                    worker,
                    attempt,
                    fence,
                    event,
                    None,
                    UnixMillis(ms),
                    None,
                )?;
            }
            Ok(())
        })
        .unwrap();
}

fn delivery(
    f: &Fixture,
    offer: &dispatch::Offer,
    now: UnixMillis,
) -> (Fence, sentinel_protocol::secrets::DeliveryBundle) {
    let worker = f.worker;
    let attempt = offer.attempt;
    let prepared = f
        .store
        .writer()
        .write({
            let key = f.key.clone();
            move |tx| secrets::prepare_delivery(tx, &key, worker, attempt, now)
        })
        .unwrap();
    let bundle = postcard::from_bytes(prepared.encoded.as_slice()).unwrap();
    (prepared.fence, bundle)
}

#[test]
fn preparation_is_acknowledgement_fenced_and_reruns_use_current_versions() {
    let f = fixture();
    let (_, job) = create_run(&f, UnixMillis(2_000));
    let first = next_offer(&f, UnixMillis(2_100));
    assert_eq!(first.job, job);

    // A worker cannot fetch any secret until its lease acknowledgement is
    // durable, even though the offer already names this worker and fence.
    assert!(matches!(
        f.store.writer().write({
            let key = f.key.clone();
            let worker = f.worker;
            let attempt = first.attempt;
            move |tx| secrets::prepare_delivery(tx, &key, worker, attempt, UnixMillis(2_110))
        }),
        Err(Error::NotFound)
    ));
    acknowledge(&f, &first, UnixMillis(2_120));
    let (first_fence, first_bundle) = delivery(&f, &first, UnixMillis(2_130));
    assert_eq!(first_fence, Fence(first.fence.0));
    assert_eq!(first_bundle.targets.len(), 3);
    assert_eq!(
        first_bundle.values[0].expose(),
        br#"{"auths":{"ghcr.io":{"auth":"dG9rZW4tdjE="}}}"#
    );
    assert_eq!(first_bundle.values[1].expose(), b"token-v1");
    assert_eq!(first_bundle.values[2].expose(), b"certificate-v1");
    finish(&f, &first);

    // Reruns keep the immutable run spec but resolve each authorized name
    // again. They use the current active version, not the earlier attempt's
    // version; revoked current versions fail closed.
    let admin = Principal::new(f.root, Permissions::ALL, None, None);
    let (tenant, repo) = (f.tenant, f.repo);
    f.store
        .writer()
        .write({
            let key = f.key.clone();
            move |tx| {
                secrets::put(
                    tx,
                    admin,
                    secrets::Update {
                        scope: Scope::Repo(repo),
                        name: "TOKEN",
                        expected: 1,
                        value: b"token-v2",
                    },
                    &key,
                    UnixMillis(2_600),
                )?;
                secrets::put(
                    tx,
                    admin,
                    secrets::Update {
                        scope: Scope::Repo(repo),
                        name: "CERT",
                        expected: 1,
                        value: b"certificate-v2",
                    },
                    &key,
                    UnixMillis(2_600),
                )?;
                secrets::put(
                    tx,
                    admin,
                    secrets::Update {
                        scope: Scope::Repo(repo),
                        name: "OCI_AUTH",
                        expected: 1,
                        value: br#"{"auths":{"ghcr.io":{"auth":"dG9rZW4tdjI="}}}"#,
                    },
                    &key,
                    UnixMillis(2_600),
                )?;
                runs::rerun_job(tx, tenant, job, UnixMillis(2_700))?;
                Ok(())
            }
        })
        .unwrap();
    let second = next_offer(&f, UnixMillis(2_800));
    assert_eq!(second.job, job);
    assert_ne!(second.attempt, first.attempt);
    acknowledge(&f, &second, UnixMillis(2_810));
    let (_, second_bundle) = delivery(&f, &second, UnixMillis(2_820));
    assert_eq!(
        second_bundle.values[0].expose(),
        br#"{"auths":{"ghcr.io":{"auth":"dG9rZW4tdjI="}}}"#
    );
    assert_eq!(second_bundle.values[1].expose(), b"token-v2");
    assert_eq!(second_bundle.values[2].expose(), b"certificate-v2");

    let repo = f.repo;
    f.store
        .writer()
        .write(move |tx| {
            secrets::revoke_version(tx, admin, Scope::Repo(repo), "TOKEN", 2, UnixMillis(2_830))
        })
        .unwrap();
    assert!(matches!(
        f.store.writer().write({
            let key = f.key.clone();
            let worker = f.worker;
            let attempt = second.attempt;
            move |tx| secrets::prepare_delivery(tx, &key, worker, attempt, UnixMillis(2_840))
        }),
        Err(Error::NotFound)
    ));
    // P10S-6: through `deliver`, the refusal itself is audited (one `use`
    // row with result `missing`, the attempt, step and version), while the
    // refused preparation's own `use` rows (OCI_AUTH resolved before TOKEN
    // failed) are rolled back.
    assert!(matches!(
        secrets::deliver(
            &f.store,
            f.key.clone(),
            f.worker,
            second.attempt,
            UnixMillis(2_850)
        ),
        Err(Error::NotFound)
    ));
    let refusals: Vec<(Option<String>, String, i64, String, String)> = f
        .store
        .read(|conn| {
            let mut stmt = conn.prepare(
                "SELECT a.step, a.name, a.version, a.result, s.name FROM secret_audit a
                 JOIN secrets s ON s.id=a.secret_id
                 WHERE a.action='use' AND a.result!='ok' AND a.attempt_id=?1",
            )?;
            Ok(stmt
                .query_map([second.attempt.as_bytes()], |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?)
        })
        .unwrap();
    assert_eq!(
        refusals,
        [(
            Some("test".into()),
            "TOKEN".into(),
            2,
            "missing".into(),
            "TOKEN".into()
        )]
    );
    let ok_uses: i64 = f
        .store
        .read(|conn| {
            Ok(conn.query_row(
                "SELECT count(*) FROM secret_audit WHERE action='use' AND result='ok' AND attempt_id=?1",
                [second.attempt.as_bytes()],
                |row| row.get(0),
            )?)
        })
        .unwrap();
    assert_eq!(ok_uses, 3, "a refused preparation leaves no use row");
    // The audit is append-only.
    for sql in [
        "UPDATE secret_audit SET result='ok'",
        "DELETE FROM secret_audit",
    ] {
        assert!(
            f.store
                .writer()
                .write(move |tx| Ok(tx.execute(sql, [])?))
                .is_err()
        );
    }

    let audit_versions: Vec<(String, i64)> = f
        .store
        .read(|conn| {
            let mut stmt = conn.prepare(
                "SELECT s.name, a.version FROM secret_audit a
                 JOIN secrets s ON s.id=a.secret_id
                 WHERE a.action='use' AND a.result='ok' AND a.attempt_id=?1 ORDER BY s.name",
            )?;
            Ok(stmt
                .query_map([first.attempt.as_bytes()], |row| {
                    Ok((row.get(0)?, row.get(1)?))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?)
        })
        .unwrap();
    assert_eq!(
        audit_versions,
        [
            ("CERT".into(), 1),
            ("OCI_AUTH".into(), 1),
            ("TOKEN".into(), 1)
        ]
    );
    let retry_versions: Vec<(String, i64)> = f
        .store
        .read(|conn| {
            let mut stmt = conn.prepare(
                "SELECT s.name, a.version FROM secret_audit a
                 JOIN secrets s ON s.id=a.secret_id
                 WHERE a.action='use' AND a.result='ok' AND a.attempt_id=?1 ORDER BY s.name",
            )?;
            Ok(stmt
                .query_map([second.attempt.as_bytes()], |row| {
                    Ok((row.get(0)?, row.get(1)?))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?)
        })
        .unwrap();
    assert_eq!(
        retry_versions,
        [
            ("CERT".into(), 2),
            ("OCI_AUTH".into(), 2),
            ("TOKEN".into(), 2)
        ]
    );
}
