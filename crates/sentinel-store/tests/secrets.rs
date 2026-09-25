use std::sync::Arc;

use sentinel_auth::sealed::Key;
use sentinel_core::{
    AttemptId, JobId, RepoId, RunId, TenantId, UnixMillis, UserId, WorkerId,
    auth::{Namespace, Permissions as P, Principal, Role},
};
use sentinel_store::{
    Durability, Error, Store,
    auth::{self, NamespaceKind, provisioning},
    secrets::{self, Binding, Scope},
};

const NOW: UnixMillis = UnixMillis(100);
fn principal(user: UserId, permissions: P) -> Principal {
    Principal::new(user, permissions, None, None)
}

#[test]
fn scoped_bindings_delegate_writes_and_resolve_only_explicit_versions() {
    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("master.key");
    Key::create(&key_path).unwrap();
    let key = Arc::new(Key::load(&key_path).unwrap());
    let store = Store::open(dir.path().join("db.sqlite"), Durability::Full).unwrap();
    let root = UserId::new();
    let admin = UserId::new();
    let writer = UserId::new();
    let tenant = TenantId::new();
    let other = TenantId::new();
    let repo = RepoId::new();
    let other_repo = RepoId::new();
    store
        .writer()
        .write(move |tx| {
            for (id, name, super_admin) in [
                (root, "root", true),
                (admin, "admin", false),
                (writer, "writer", false),
            ] {
                provisioning::insert_human(tx, id, name, super_admin, NOW)?;
            }
            for (id, slug) in [(tenant, "one"), (other, "two")] {
                auth::create_namespace(
                    tx,
                    principal(root, P::ALL),
                    id,
                    Namespace::parse(slug).unwrap(),
                    NamespaceKind::Organization,
                    NOW,
                )?;
            }
            auth::set_membership(
                tx,
                principal(root, P::ALL),
                tenant,
                admin,
                Role::TenantAdmin,
            )?;
            auth::set_membership(tx, principal(admin, P::ALL), tenant, writer, Role::Reader)?;
            auth::create_repo(tx, principal(admin, P::ALL), tenant, repo, "app", NOW)?;
            auth::create_repo(tx, principal(root, P::ALL), other, other_repo, "other", NOW)?;
            auth::set_repo_grant(tx, principal(admin, P::ALL), repo, writer, P::WRITE_SECRETS)?;
            Ok(())
        })
        .unwrap();
    let writer_principal = principal(writer, P::WRITE_SECRETS);
    let admin_principal = principal(admin, P::ALL);
    let k = key.clone();
    let repo_meta = store
        .writer()
        .write(move |tx| {
            secrets::put(
                tx,
                writer_principal,
                secrets::Update {
                    scope: Scope::Repo(repo),
                    name: "TOKEN",
                    expected: 0,
                    value: b"super-secret-value",
                },
                &k,
                NOW,
            )
        })
        .unwrap();
    assert_eq!(repo_meta.version, 1);
    assert!(matches!(
        store.writer().write({
            let k = key.clone();
            move |tx| {
                secrets::put(
                    tx,
                    writer_principal,
                    secrets::Update {
                        scope: Scope::Repo(other_repo),
                        name: "TOKEN",
                        expected: 0,
                        value: b"wrong-tenant",
                    },
                    &k,
                    NOW,
                )
            }
        }),
        Err(Error::NotFound)
    ));
    assert_eq!(
        store
            .read(|c| secrets::describe(c, writer_principal, Scope::Repo(repo), "TOKEN"))
            .unwrap()
            .version,
        1
    );
    assert!(matches!(
        store.read(|c| secrets::describe(c, admin_principal, Scope::Repo(other_repo), "TOKEN")),
        Err(Error::NotFound)
    ));
    let tenant_meta = {
        let k = key.clone();
        store
            .writer()
            .write(move |tx| {
                secrets::put(
                    tx,
                    admin_principal,
                    secrets::Update {
                        scope: Scope::Tenant(tenant),
                        name: "TOKEN",
                        expected: 0,
                        value: b"tenant-secret-value",
                    },
                    &k,
                    NOW,
                )
            })
            .unwrap()
    };
    assert!(matches!(
        store.writer().write({
            let k = key.clone();
            move |tx| {
                secrets::put(
                    tx,
                    principal(root, P::ALL),
                    secrets::Update {
                        scope: Scope::Tenant(tenant),
                        name: "ROOT_TOKEN",
                        expected: 0,
                        value: b"no-ambient-access",
                    },
                    &k,
                    NOW,
                )
            }
        }),
        Err(Error::NotFound)
    ));
    store
        .writer()
        .write(move |tx| secrets::allow_repo(tx, admin_principal, tenant, "TOKEN", repo, true, NOW))
        .unwrap();
    let repo_binding = Binding {
        repo,
        job: "build".into(),
        step: "".into(),
        name: "TOKEN".into(),
        secret: repo_meta.id,
        override_tenant: false,
    };
    assert!(matches!(
        store.writer().write({
            let b = repo_binding.clone();
            move |tx| secrets::bind(tx, writer_principal, &b, NOW)
        }),
        Err(Error::Conflict)
    ));
    let repo_binding = Binding {
        override_tenant: true,
        ..repo_binding
    };
    store
        .writer()
        .write({
            let b = repo_binding.clone();
            move |tx| secrets::bind(tx, writer_principal, &b, NOW)
        })
        .unwrap();
    assert_eq!(
        store
            .read(|c| secrets::list(c, admin_principal, Scope::Repo(repo), "", 10))
            .unwrap()[0]
            .id,
        repo_meta.id
    );
    assert_eq!(
        store
            .read(|c| secrets::list_bindings(c, admin_principal, repo, None, 10))
            .unwrap(),
        vec![repo_binding.clone()]
    );
    let picked = store
        .read(|c| secrets::resolve(c, repo, "build", "test", "TOKEN"))
        .unwrap();
    assert_eq!(picked.secret, repo_meta.id);
    assert_eq!(picked.version, 1);
    let run = RunId::new();
    let job = JobId::new();
    let attempt = AttemptId::new();
    let worker = WorkerId::new();
    let use_id = picked.clone();
    store.writer().write(move |tx| {
        tx.execute("INSERT INTO runs(id,tenant_id,repo_id,source_sha,created_ms) VALUES(?1,?2,?3,?4,?5)",rusqlite::params![run.as_bytes(),tenant.as_bytes(),repo.as_bytes(),"a".repeat(40),NOW.0])?;
        tx.execute("INSERT INTO jobs(id,tenant_id,run_id,name,state_code,priority,created_seq) VALUES(?1,?2,?3,'build',1,0,1)",rusqlite::params![job.as_bytes(),tenant.as_bytes(),run.as_bytes()])?;
        tx.execute("INSERT INTO attempts(id,tenant_id,job_id,fence,worker_id,lease_until_ms) VALUES(?1,?2,?3,1,?4,1000)",rusqlite::params![attempt.as_bytes(),tenant.as_bytes(),job.as_bytes(),worker.as_bytes()])?;
        secrets::audit_use(tx,attempt,"test",&use_id,NOW)
    }).unwrap();
    let rotated = store
        .writer()
        .write({
            let k = key.clone();
            move |tx| {
                secrets::put(
                    tx,
                    writer_principal,
                    secrets::Update {
                        scope: Scope::Repo(repo),
                        name: "TOKEN",
                        expected: 1,
                        value: b"another-secret-value",
                    },
                    &k,
                    NOW,
                )
            }
        })
        .unwrap();
    assert_eq!(rotated.version, 2);
    assert!(matches!(
        store.writer().write({
            let k = key.clone();
            move |tx| {
                secrets::put(
                    tx,
                    writer_principal,
                    secrets::Update {
                        scope: Scope::Repo(repo),
                        name: "TOKEN",
                        expected: 1,
                        value: b"retry-secret-value",
                    },
                    &k,
                    NOW,
                )
            }
        }),
        Err(Error::Conflict)
    ));
    assert_eq!(
        store
            .read(|c| secrets::resolve(c, repo, "build", "test", "TOKEN"))
            .unwrap()
            .version,
        2
    );
    let stale_use = picked.clone();
    assert!(matches!(
        store
            .writer()
            .write(move |tx| secrets::audit_use(tx, attempt, "test", &stale_use, NOW)),
        Err(Error::Conflict)
    ));
    store
        .writer()
        .write(move |tx| {
            secrets::revoke_version(tx, writer_principal, Scope::Repo(repo), "TOKEN", 1, NOW)
        })
        .unwrap();
    assert_eq!(
        store
            .read(|c| secrets::resolve(c, repo, "build", "test", "TOKEN"))
            .unwrap()
            .version,
        2
    );
    assert!(matches!(
        store.read(|c| secrets::resolve(c, repo, "other", "test", "TOKEN")),
        Err(Error::NotFound)
    ));
    let step_binding = Binding {
        repo,
        job: "build".into(),
        step: "test".into(),
        name: "TOKEN".into(),
        secret: tenant_meta.id,
        override_tenant: false,
    };
    assert!(matches!(
        store.writer().write({
            let b = step_binding.clone();
            move |tx| secrets::bind(tx, writer_principal, &b, NOW)
        }),
        Err(Error::Conflict)
    ));
    // Removing the colliding repository secret permits the tenant binding.
    store
        .writer()
        .write(move |tx| secrets::delete(tx, writer_principal, Scope::Repo(repo), "TOKEN", 2, NOW))
        .unwrap();
    store
        .writer()
        .write({
            let b = step_binding.clone();
            move |tx| secrets::bind(tx, writer_principal, &b, NOW)
        })
        .unwrap();
    assert_eq!(
        store
            .read(|c| secrets::list_bindings(c, admin_principal, repo, None, 1))
            .unwrap(),
        vec![repo_binding]
    );
    assert_eq!(
        store
            .read(|c| secrets::list_bindings(
                c,
                admin_principal,
                repo,
                Some(("build", "", "TOKEN")),
                1
            ))
            .unwrap(),
        vec![step_binding]
    );
    assert_eq!(
        store
            .read(|c| secrets::resolve(c, repo, "build", "test", "TOKEN"))
            .unwrap()
            .secret,
        tenant_meta.id
    );
    store
        .writer()
        .write(move |tx| {
            secrets::allow_repo(tx, admin_principal, tenant, "TOKEN", repo, false, NOW)
        })
        .unwrap();
    assert!(matches!(
        store.read(|c| secrets::resolve(c, repo, "build", "test", "TOKEN")),
        Err(Error::NotFound)
    ));
    store
        .writer()
        .write(move |tx| secrets::allow_repo(tx, admin_principal, tenant, "TOKEN", repo, true, NOW))
        .unwrap();
    assert!(matches!(
        store.read(|c| secrets::resolve(c, repo, "build", "test", "TOKEN")),
        Err(Error::NotFound)
    ));
    let (sealed, audit_values, use_step): (Vec<u8>, Vec<String>, String) = store
        .read(|c| {
            let sealed = c.query_row(
                "SELECT sealed FROM secret_versions WHERE secret_id=?1",
                [repo_meta.id.as_bytes()],
                |r| r.get(0),
            )?;
            let mut stmt =
                c.prepare("SELECT action FROM secret_audit WHERE secret_id=?1 ORDER BY seq")?;
            let actions = stmt
                .query_map([repo_meta.id.as_bytes()], |r| r.get(0))?
                .collect::<rusqlite::Result<Vec<String>>>()?;
            let use_step = c.query_row(
                "SELECT step FROM secret_audit WHERE secret_id=?1 AND action='use'",
                [repo_meta.id.as_bytes()],
                |r| r.get(0),
            )?;
            Ok((sealed, actions, use_step))
        })
        .unwrap();
    assert!(
        !sealed
            .windows(b"super-secret-value".len())
            .any(|w| w == b"super-secret-value")
    );
    assert_eq!(
        audit_values,
        ["create", "bind", "use", "rotate", "revoke", "delete"]
    );
    assert_eq!(use_step, "test");
    store
        .writer()
        .write(move |tx| auth::set_repo_grant(tx, admin_principal, repo, writer, P::NONE))
        .unwrap();
    assert!(matches!(
        store.writer().write({
            let k = key.clone();
            move |tx| {
                secrets::put(
                    tx,
                    writer_principal,
                    secrets::Update {
                        scope: Scope::Repo(repo),
                        name: "NEW_TOKEN",
                        expected: 0,
                        value: b"blocked-value",
                    },
                    &k,
                    NOW,
                )
            }
        }),
        Err(Error::NotFound)
    ));
}
