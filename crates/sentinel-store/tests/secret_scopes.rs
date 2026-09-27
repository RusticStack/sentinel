//! Part 10 audit (secrets cluster): delegation boundaries, the named
//! binding/allowlist/revocation surface, listing plans, idempotency-key
//! reuse, and resealing every sealed column under a new key.

use std::sync::Arc;

use sentinel_auth::sealed::{Key, key_id};
use sentinel_core::{
    RepoId, TenantId, UnixMillis, UserId,
    auth::{Namespace, Permissions as P, Principal, Role},
};
use sentinel_store::{
    Durability, Error, Store,
    auth::{self, Authority, NamespaceKind, provisioning},
    reseal,
    secrets::{self, Scope},
    sources,
};

const NOW: UnixMillis = UnixMillis(100);

fn principal(user: UserId, permissions: P) -> Principal {
    Principal::new(user, permissions, None, None)
}

struct Scoped {
    dir: tempfile::TempDir,
    store: Store,
    key: Arc<Key>,
    tenant: TenantId,
    root: UserId,
    admin: UserId,
    writer: UserId,
    repo_a: RepoId,
    repo_b: RepoId,
}

impl Scoped {
    fn key_path(&self) -> std::path::PathBuf {
        self.dir.path().join("master.key")
    }
}

/// One tenant with an administrator, and a reader holding `WRITE_SECRETS`
/// on repository `a` only; repository `b` is in the same tenant.
fn scoped() -> Scoped {
    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("master.key");
    Key::create(&key_path).unwrap();
    let key = Arc::new(Key::load(&key_path).unwrap());
    let store = Store::open(dir.path().join("db.sqlite"), Durability::Full).unwrap();
    let (root, admin, writer) = (UserId::new(), UserId::new(), UserId::new());
    let (tenant, repo_a, repo_b) = (TenantId::new(), RepoId::new(), RepoId::new());
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
            auth::create_namespace(
                tx,
                principal(root, P::ALL),
                tenant,
                Namespace::parse("one").unwrap(),
                NamespaceKind::Organization,
                NOW,
            )?;
            auth::set_membership(
                tx,
                principal(root, P::ALL),
                tenant,
                admin,
                Role::TenantAdmin,
            )?;
            auth::set_membership(tx, principal(admin, P::ALL), tenant, writer, Role::Reader)?;
            auth::create_repo(tx, principal(admin, P::ALL), tenant, repo_a, "a", NOW)?;
            auth::create_repo(tx, principal(admin, P::ALL), tenant, repo_b, "b", NOW)?;
            auth::set_repo_grant(
                tx,
                principal(admin, P::ALL),
                repo_a,
                writer,
                P::WRITE_SECRETS,
            )
        })
        .unwrap();
    Scoped {
        dir,
        store,
        key,
        tenant,
        root,
        admin,
        writer,
        repo_a,
        repo_b,
    }
}

fn put_as(
    s: &Scoped,
    who: Principal,
    scope: Scope,
    name: &'static str,
) -> sentinel_store::Result<secrets::Metadata> {
    put_with(&s.store, s.key.clone(), who, scope, name, 0, b"value")
}

fn put_with(
    store: &Store,
    key: Arc<Key>,
    who: Principal,
    scope: Scope,
    name: &'static str,
    expected: u64,
    value: &'static [u8],
) -> sentinel_store::Result<secrets::Metadata> {
    store.writer().write(move |tx| {
        secrets::put(
            tx,
            who,
            secrets::Update {
                scope,
                name,
                expected,
                value,
            },
            &key,
            NOW,
        )
    })
}

/// P10S-12: the three delegation boundaries S02 promises, each a plain
/// `NotFound`: a repo-A writer cannot write repo B of the same tenant, cannot
/// write or allowlist at tenant scope, and a principal narrowed to repo A
/// cannot reach repo B even with every permission.
#[test]
fn a_delegated_writer_stays_inside_its_repository_and_narrowing() {
    let s = scoped();
    let writer = principal(s.writer, P::WRITE_SECRETS);
    assert!(put_as(&s, writer, Scope::Repo(s.repo_a), "A_TOKEN").is_ok());
    assert!(matches!(
        put_as(&s, writer, Scope::Repo(s.repo_b), "B_TOKEN"),
        Err(Error::NotFound)
    ));
    assert!(matches!(
        put_as(&s, writer, Scope::Tenant(s.tenant), "T_TOKEN"),
        Err(Error::NotFound)
    ));
    let admin = principal(s.admin, P::ALL);
    put_as(&s, admin, Scope::Tenant(s.tenant), "T_TOKEN").unwrap();
    let (tenant, repo_a, repo_b) = (s.tenant, s.repo_a, s.repo_b);
    assert!(matches!(
        s.store
            .writer()
            .write(move |tx| secrets::allow_repo(tx, writer, tenant, "T_TOKEN", repo_a, true, NOW)),
        Err(Error::NotFound)
    ));
    // A repo-A writer cannot bind in repo B either, even by name.
    assert!(matches!(
        s.store.writer().write(move |tx| secrets::bind_named(
            tx, writer, repo_b, "", "", "A_TOKEN", false, false, NOW
        )),
        Err(Error::NotFound)
    ));

    let narrowed = Principal::new(s.admin, P::ALL, Some(s.tenant), Some(s.repo_a));
    assert!(put_as(&s, narrowed, Scope::Repo(s.repo_a), "N_TOKEN").is_ok());
    assert!(matches!(
        put_as(&s, narrowed, Scope::Repo(s.repo_b), "N_TOKEN"),
        Err(Error::NotFound)
    ));
    assert!(matches!(
        put_as(&s, narrowed, Scope::Tenant(s.tenant), "N2_TOKEN"),
        Err(Error::NotFound)
    ));
}

/// P10S-2 store surface: bind by name, list, idempotent unbind, allowlist
/// listing and idempotent single-version revocation.
#[test]
fn bindings_allowlists_and_revocations_are_idempotent_by_name() {
    let s = scoped();
    let writer = principal(s.writer, P::WRITE_SECRETS);
    let admin = principal(s.admin, P::ALL);
    put_as(&s, writer, Scope::Repo(s.repo_a), "REPO_TOKEN").unwrap();
    put_as(&s, admin, Scope::Tenant(s.tenant), "SHARED").unwrap();
    let (tenant, repo_a) = (s.tenant, s.repo_a);
    // Not allowlisted yet: the tenant source is refused like a missing one.
    assert!(matches!(
        s.store.writer().write(move |tx| secrets::bind_named(
            tx, writer, repo_a, "build", "", "SHARED", true, false, NOW
        )),
        Err(Error::NotFound)
    ));
    for _ in 0..2 {
        s.store
            .writer()
            .write(move |tx| secrets::allow_repo(tx, admin, tenant, "SHARED", repo_a, true, NOW))
            .unwrap();
    }
    let allowed = s
        .store
        .read(|c| secrets::list_allowed(c, admin, tenant, "SHARED", None, 100))
        .unwrap();
    assert_eq!(allowed, vec![(s.repo_a, "a".to_owned())]);
    let shared = s
        .store
        .writer()
        .write(move |tx| {
            secrets::bind_named(tx, writer, repo_a, "build", "", "SHARED", true, false, NOW)
        })
        .unwrap();
    let own = s
        .store
        .writer()
        .write(move |tx| {
            secrets::bind_named(tx, writer, repo_a, "", "", "REPO_TOKEN", false, false, NOW)
        })
        .unwrap();
    assert_eq!(
        s.store
            .read(|c| secrets::list_bindings(c, writer, repo_a, None, 100))
            .unwrap(),
        vec![own.clone(), shared]
    );
    assert_eq!(
        s.store
            .read(|c| secrets::resolve(c, repo_a, "build", "x", "SHARED"))
            .unwrap()
            .version,
        1
    );
    for _ in 0..2 {
        s.store
            .writer()
            .write(move |tx| secrets::unbind(tx, writer, repo_a, "build", "", "SHARED", NOW))
            .unwrap();
    }
    assert_eq!(
        s.store
            .read(|c| secrets::list_bindings(c, writer, repo_a, None, 100))
            .unwrap(),
        vec![own]
    );
    for _ in 0..2 {
        s.store
            .writer()
            .write(move |tx| {
                secrets::revoke_version(tx, writer, Scope::Repo(repo_a), "REPO_TOKEN", 1, NOW)
            })
            .unwrap();
    }
    assert!(matches!(
        s.store.writer().write(move |tx| secrets::revoke_version(
            tx,
            writer,
            Scope::Repo(repo_a),
            "REPO_TOKEN",
            2,
            NOW
        )),
        Err(Error::NotFound)
    ));
    let actions: Vec<String> = s
        .store
        .read(|c| {
            let mut stmt = c.prepare("SELECT action FROM secret_audit ORDER BY seq")?;
            Ok(stmt
                .query_map([], |r| r.get(0))?
                .collect::<rusqlite::Result<Vec<String>>>()?)
        })
        .unwrap();
    // The repeated allow, unbind and revoke are each audited once.
    assert_eq!(
        actions,
        [
            "create", "create", "allow", "bind", "bind", "unbind", "revoke"
        ]
    );
}

/// P10S-11: each listing scope is served by its own partial index, and a
/// page of one scope never contains the other scope's names.
#[test]
fn each_listing_scope_walks_only_its_own_index() {
    let s = scoped();
    let admin = principal(s.admin, P::ALL);
    put_as(&s, admin, Scope::Tenant(s.tenant), "T_ONE").unwrap();
    put_as(&s, admin, Scope::Repo(s.repo_a), "A_ONE").unwrap();
    put_as(&s, admin, Scope::Repo(s.repo_b), "B_ONE").unwrap();
    let names = |scope| {
        s.store
            .read(|c| secrets::list(c, admin, scope, "", 100))
            .unwrap()
            .into_iter()
            .map(|m| m.name)
            .collect::<Vec<_>>()
    };
    assert_eq!(names(Scope::Tenant(s.tenant)), ["T_ONE"]);
    assert_eq!(names(Scope::Repo(s.repo_a)), ["A_ONE"]);
    let plans: Vec<String> = s
        .store
        .read(|c| {
            let mut out = Vec::new();
            for sql in [
                "EXPLAIN QUERY PLAN SELECT id,tenant_id,scope_repo_id,name,current_version,active,created_ms,updated_ms
                 FROM secrets WHERE tenant_id=?1 AND scope_repo_id IS NULL AND name>?2
                 ORDER BY name LIMIT ?3",
                "EXPLAIN QUERY PLAN SELECT id,tenant_id,scope_repo_id,name,current_version,active,created_ms,updated_ms
                 FROM secrets WHERE scope_repo_id=?1 AND name>?2 ORDER BY name LIMIT ?3",
            ] {
                let mut stmt = c.prepare(sql)?;
                let detail = stmt
                    .query_map(rusqlite::params![[0u8; 16], "", 1], |r| {
                        r.get::<_, String>(3)
                    })?
                    .collect::<rusqlite::Result<Vec<_>>>()?
                    .join("; ");
                out.push(detail);
            }
            Ok(out)
        })
        .unwrap();
    assert!(plans[0].contains("secrets_tenant_name"), "{}", plans[0]);
    assert!(plans[1].contains("secrets_repo_name"), "{}", plans[1]);
    assert!(
        !plans.iter().any(|p| p.contains("TEMP B-TREE")),
        "{plans:?}"
    );
}

/// P10C-9: reusing a secret-write idempotency key for a different request
/// is `IdempotencyMismatch`, distinct from a stale-version `Conflict`.
#[test]
fn a_reused_idempotency_key_is_a_mismatch_not_a_conflict() {
    let s = scoped();
    let tenant = s.tenant;
    let key = sentinel_protocol::idempotency::IdempotencyKey::parse("k-1").unwrap();
    let save = move |fingerprint: u128| {
        move |tx: &rusqlite::Transaction<'_>| {
            let idempotency = secrets::Idempotency {
                tenant,
                principal: "p",
                route: "secret.put",
                key,
                fingerprint: sentinel_protocol::idempotency::Fingerprint(fingerprint),
            };
            if let Some(saved) = secrets::idempotency_replay(tx, idempotency, NOW)? {
                return Ok(Some(saved));
            }
            secrets::idempotency_save(tx, idempotency, b"{}", NOW)?;
            Ok(None)
        }
    };
    assert_eq!(s.store.writer().write(save(1)).unwrap(), None);
    assert_eq!(
        s.store.writer().write(save(1)).unwrap(),
        Some(b"{}".to_vec())
    );
    assert!(matches!(
        s.store.writer().write(save(2)),
        Err(Error::IdempotencyMismatch)
    ));
}

/// P10S-5: after a rotation, `reseal_all` moves every sealed column (active
/// and revoked secret versions, a confirmed second-factor seed, a source
/// credential) to the active key; a second run changes nothing, retiring
/// the old keys leaves every row readable, and the triggers still refuse
/// any rewrite of sealed bytes that is not a forward reseal.
#[test]
fn every_sealed_row_is_resealed_so_old_keys_can_be_retired() {
    let s = scoped();
    let admin = principal(s.admin, P::ALL);
    let repo = s.repo_a;
    put_as(&s, admin, Scope::Repo(repo), "OLD").unwrap();
    put_with(
        &s.store,
        s.key.clone(),
        admin,
        Scope::Repo(repo),
        "OLD",
        1,
        b"v2",
    )
    .unwrap();
    s.store
        .writer()
        .write(move |tx| secrets::revoke_version(tx, admin, Scope::Repo(repo), "OLD", 1, NOW))
        .unwrap();
    // A confirmed second factor sealed under the original key.
    let root = s.root;
    let seed = s.key.seal(
        &{
            let mut c = b"totp:".to_vec();
            c.extend_from_slice(root.as_bytes());
            c
        },
        b"0123456789abcdef0123",
    );
    s.store
        .writer()
        .write(move |tx| {
            tx.execute(
                "INSERT INTO mfa_totp(user_id,sealed_seed,created_ms,confirmed_ms) VALUES(?1,?2,1,2)",
                rusqlite::params![root.as_bytes(), seed],
            )?;
            Ok(())
        })
        .unwrap();
    let key = s.key.clone();
    s.store
        .writer()
        .write(move |tx| {
            sources::bind(
                tx,
                Authority::HostLocal,
                Some(root),
                sources::Update {
                    repo,
                    expected: 0,
                    binding: &sentinel_protocol::source::Binding {
                        remote: "https://git.example:443/team/repo.git".into(),
                        allowed_refs: vec!["refs/heads/main".into()],
                        pipeline_path: ".sentinel.yml".into(),
                        trust: String::new(),
                    },
                    credential: &sentinel_protocol::source::Credential::Https {
                        username: "deploy".into(),
                        secret: "deploy-token".into(),
                    },
                    forge: None,
                },
                &["https://git.example:443".into()],
                &key,
                NOW,
            )
        })
        .unwrap();

    Key::rotate(&s.key_path(), &s.dir.path().join("pre-rotation.key")).unwrap();
    let rotated = Arc::new(Key::load(&s.key_path()).unwrap());
    // A value written after the rotation is already current: a mixed store,
    // as after an interrupted reseal, is handled row by row.
    put_with(
        &s.store,
        rotated.clone(),
        admin,
        Scope::Repo(repo),
        "NEW",
        0,
        b"n",
    )
    .unwrap();
    assert_eq!(s.store.read(|c| reseal::stale(c, &rotated)).unwrap(), 4);
    let progress = reseal::reseal_all(&s.store, rotated.clone()).unwrap();
    assert_eq!((progress.examined, progress.resealed), (5, 4));
    assert_eq!(s.store.read(|c| reseal::stale(c, &rotated)).unwrap(), 0);
    assert_eq!(
        reseal::reseal_all(&s.store, rotated.clone())
            .unwrap()
            .resealed,
        0
    );

    assert_eq!(
        Key::retire(&s.key_path(), &s.dir.path().join("pre-retire.key")).unwrap(),
        1
    );
    let retired = Key::load(&s.key_path()).unwrap();
    assert_eq!(retired.len(), 1);
    s.store.read(|c| reseal::verify_key(c, &retired)).unwrap();
    // The original key opens nothing any more.
    let original = Key::load(&s.dir.path().join("pre-rotation.key")).unwrap();
    assert!(s.store.read(|c| reseal::verify_key(c, &original)).is_err());

    // Sealed bytes still cannot be rewritten except forward.
    let rows: Vec<Vec<u8>> = s
        .store
        .read(|c| {
            let mut stmt = c.prepare("SELECT sealed FROM secret_versions")?;
            Ok(stmt
                .query_map([], |r| r.get(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?)
        })
        .unwrap();
    assert!(rows.iter().all(|r| key_id(r) == Some(retired.active_id())));
    for sql in [
        "UPDATE secret_versions SET sealed=sealed||x'00'",
        "UPDATE secret_versions SET sealed=x'02'||x'00000001'||substr(sealed,6)",
        "UPDATE mfa_totp SET sealed_seed=x'02'||x'00000001'||substr(sealed_seed,6)",
    ] {
        assert!(
            s.store
                .writer()
                .write(move |tx| Ok(tx.execute(sql, [])?))
                .is_err(),
            "{sql}"
        );
    }
}
