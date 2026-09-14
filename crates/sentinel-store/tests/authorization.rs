use rusqlite::{Connection, params};
use sentinel_core::{
    RepoId, RunId, TenantId, UnixMillis, UserId,
    auth::{Namespace, Permissions as P, Principal, Role},
};
use sentinel_store::{
    Durability, Error, Store,
    auth::{self, NamespaceKind, provisioning},
    jobs,
};

const NOW: UnixMillis = UnixMillis(123);
fn principal(user: UserId) -> Principal {
    Principal::new(user, P::ALL, None, None)
}

#[derive(Clone, Copy)]
struct Ids {
    root: UserId,
    alice: UserId,
    bob: UserId,
    outsider: UserId,
    bot: UserId,
    a: TenantId,
    b: TenantId,
    personal: TenantId,
    ar: RepoId,
    ar2: RepoId,
    br: RepoId,
    personal_repo: RepoId,
}

fn fixture() -> (tempfile::TempDir, Store, Ids) {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path().join("auth.sqlite"), Durability::Full).unwrap();
    let i = Ids {
        root: UserId::new(),
        alice: UserId::new(),
        bob: UserId::new(),
        outsider: UserId::new(),
        bot: UserId::new(),
        a: TenantId::new(),
        b: TenantId::new(),
        personal: TenantId::new(),
        ar: RepoId::new(),
        ar2: RepoId::new(),
        br: RepoId::new(),
        personal_repo: RepoId::new(),
    };
    store
        .writer()
        .write(move |tx| {
            for (id, name, admin) in [
                (i.root, "root", true),
                (i.alice, "alice", false),
                (i.bob, "bob", false),
                (i.outsider, "alice", false),
            ] {
                provisioning::insert_human(tx, id, name, admin, NOW)?;
            }
            for (tenant, slug, kind) in [
                (i.a, "org-a", NamespaceKind::Organization),
                (i.b, "org-b", NamespaceKind::Organization),
                (i.personal, "alice", NamespaceKind::Personal(i.alice)),
            ] {
                auth::create_namespace(
                    tx,
                    principal(i.root),
                    tenant,
                    Namespace::parse(slug).unwrap(),
                    kind,
                    NOW,
                )?;
            }
            for (t, u, r) in [
                (i.a, i.alice, Role::TenantAdmin),
                (i.b, i.bob, Role::TenantAdmin),
                (i.a, i.bob, Role::Operator),
                (i.b, i.alice, Role::Reader),
            ] {
                auth::set_membership(tx, principal(i.root), t, u, r)?;
            }
            for (t, r) in [
                (i.a, i.ar),
                (i.a, i.ar2),
                (i.b, i.br),
                (i.personal, i.personal_repo),
            ] {
                auth::create_repo(
                    tx,
                    principal(i.root),
                    t,
                    r,
                    if r == i.ar2 { "other" } else { "app" },
                    NOW,
                )?;
            }
            auth::set_repo_grant(tx, principal(i.alice), i.ar, i.bob, P::READ.union(P::RUN))?;
            // A grant cannot lift Alice above her reader membership in B.
            auth::set_repo_grant(tx, principal(i.bob), i.br, i.alice, P::REPOSITORY)?;
            auth::create_service_account(
                tx,
                principal(i.alice),
                i.a,
                i.bot,
                "ci-bot",
                Role::Operator,
                NOW,
            )?;
            auth::set_repo_grant(tx, principal(i.alice), i.ar, i.bot, P::READ.union(P::RUN))?;
            Ok(())
        })
        .unwrap();
    (dir, store, i)
}

fn missing<T: std::fmt::Debug>(result: sentinel_store::Result<T>) {
    assert!(matches!(result, Err(Error::NotFound)), "{result:?}");
}

#[test]
fn roles_intersect_live_memberships_repo_grants_and_credential_scopes() {
    let (_dir, store, i) = fixture();
    store
        .read(|c| {
            assert_eq!(
                auth::require_repo(c, principal(i.alice), i.ar2, P::REPOSITORY)?,
                i.a
            );
            assert_eq!(auth::get_repo(c, principal(i.bob), i.ar)?.tenant, i.a);
            auth::require_repo(c, principal(i.bob), i.ar, P::RUN)?;
            missing(auth::require_repo(
                c,
                principal(i.bob),
                i.ar,
                P::WRITE_SECRETS,
            ));
            missing(auth::get_repo(c, principal(i.bob), i.ar2));
            auth::require_repo(c, principal(i.alice), i.br, P::READ)?;
            missing(auth::require_repo(c, principal(i.alice), i.br, P::RUN));
            // Explicit secret delegation is independent of operator status.
            auth::require_repo(c, principal(i.alice), i.br, P::WRITE_SECRETS)?;
            auth::require_repo(c, principal(i.alice), i.personal_repo, P::RUN)?;
            missing(auth::get_repo(c, principal(i.bob), i.personal_repo));
            missing(auth::get_repo(c, principal(i.outsider), i.ar));
            missing(auth::get_repo(c, principal(UserId::new()), i.ar));
            missing(auth::get_repo(c, principal(i.alice), RepoId::new()));
            missing(auth::require_repo(
                c,
                Principal::new(i.alice, P::READ, None, None),
                i.ar,
                P::RUN,
            ));
            missing(auth::get_repo(
                c,
                Principal::new(i.alice, P::ALL, Some(i.b), None),
                i.ar,
            ));
            missing(auth::get_repo(
                c,
                Principal::new(i.alice, P::ALL, Some(i.a), Some(i.ar)),
                i.ar2,
            ));
            missing(auth::require_repo(c, principal(i.alice), i.ar, P::NONE));
            missing(auth::require_repo(
                c,
                principal(i.alice),
                i.ar,
                P::PLATFORM_ADMIN,
            ));
            Ok(())
        })
        .unwrap();
}

#[test]
fn platform_admin_has_no_ambient_repo_access_and_service_accounts_cannot_administer() {
    let (_dir, store, i) = fixture();
    store
        .read(|c| {
            auth::require_platform_admin(c, principal(i.root))?;
            missing(auth::get_repo(c, principal(i.root), i.ar));
            assert!(matches!(
                auth::require_platform_admin(c, Principal::new(i.root, P::READ, None, None)),
                Err(Error::Forbidden)
            ));
            assert!(matches!(
                auth::require_platform_admin(c, Principal::new(i.root, P::ALL, Some(i.a), None)),
                Err(Error::Forbidden)
            ));
            assert!(matches!(
                auth::require_tenant_admin(c, principal(i.bob), i.a),
                Err(Error::Forbidden)
            ));
            auth::require_repo(c, principal(i.bot), i.ar, P::RUN)?;
            missing(auth::get_repo(c, principal(i.bot), i.ar2));
            missing(auth::get_repo(c, principal(i.bot), i.br));
            missing(auth::require_repo(
                c,
                principal(i.bot),
                i.ar,
                P::WRITE_SECRETS,
            ));
            assert!(matches!(
                auth::require_platform_admin(c, principal(i.bot)),
                Err(Error::Forbidden)
            ));
            assert!(matches!(
                auth::require_tenant_admin(c, principal(i.bot), i.a),
                Err(Error::Forbidden)
            ));
            Ok(())
        })
        .unwrap();
    assert!(matches!(
        store.writer().write(move |tx| auth::set_membership(
            tx,
            principal(i.alice),
            i.a,
            i.bot,
            Role::TenantAdmin
        )),
        Err(Error::NotFound)
    ));
    assert!(matches!(
        store.writer().write(move |tx| auth::set_membership(
            tx,
            principal(i.bob),
            i.b,
            i.bot,
            Role::Reader
        )),
        Err(Error::NotFound)
    ));
    assert!(matches!(
        store.writer().write(move |tx| auth::set_repo_grant(
            tx,
            principal(i.bob),
            i.ar,
            i.bob,
            P::REPOSITORY
        )),
        Err(Error::NotFound)
    ));
    assert!(matches!(
        store.writer().write(move |tx| auth::create_namespace(
            tx,
            principal(i.alice),
            TenantId::new(),
            Namespace::parse("forbidden").unwrap(),
            NamespaceKind::Organization,
            NOW
        )),
        Err(Error::Forbidden)
    ));
}

#[test]
fn namespace_identity_and_bounded_lists_do_not_leak_other_tenants() {
    let (_dir, store, i) = fixture();
    for invalid in ["", "Acme", "-acme", "acme-", "../acme", "a/b", "a b", "é"] {
        assert!(Namespace::parse(invalid).is_none());
    }
    assert!(Namespace::parse(&"a".repeat(64)).is_none());
    store
        .read(|c| {
            assert!(
                auth::get_namespace(c, principal(i.alice), Namespace::parse("alice").unwrap())?
                    .personal
            );
            missing(auth::get_namespace(
                c,
                principal(i.bob),
                Namespace::parse("alice").unwrap(),
            ));
            missing(auth::get_namespace(
                c,
                principal(i.outsider),
                Namespace::parse("org-a").unwrap(),
            ));
            missing(auth::get_namespace(
                c,
                principal(i.alice),
                Namespace::parse("absent").unwrap(),
            ));
            let all = auth::list_repos(c, principal(i.alice), i.a, None, 100)?;
            assert_eq!(all.len(), 2);
            let first = auth::list_repos(c, principal(i.alice), i.a, None, 1)?;
            let second = auth::list_repos(c, principal(i.alice), i.a, Some(first[0].id), 1)?;
            assert_eq!(all[0], first[0]);
            assert_eq!(all[1], second[0]);
            assert!(
                auth::list_repos(c, principal(i.alice), i.a, Some(second[0].id), 1)?.is_empty()
            );
            assert_eq!(
                auth::list_repos(c, principal(i.bob), i.a, None, 100)?.len(),
                1
            );
            assert!(auth::list_repos(c, principal(i.outsider), i.a, Some(i.br), 100)?.is_empty());
            assert!(
                auth::list_repos(
                    c,
                    Principal::new(i.alice, P::ALL, Some(i.b), None),
                    i.a,
                    None,
                    100
                )?
                .is_empty()
            );
            assert!(matches!(
                auth::list_repos(c, principal(i.alice), i.a, None, 101),
                Err(Error::InvalidInput(_))
            ));
            Ok(())
        })
        .unwrap();
    for (slug, kind) in [
        ("org-a", NamespaceKind::Organization),
        ("second-personal", NamespaceKind::Personal(i.alice)),
    ] {
        assert!(
            store
                .writer()
                .write(move |tx| auth::create_namespace(
                    tx,
                    principal(i.root),
                    TenantId::new(),
                    Namespace::parse(slug).unwrap(),
                    kind,
                    NOW
                ))
                .is_err()
        );
    }
    assert!(
        store
            .writer()
            .write(move |tx| auth::remove_membership(tx, principal(i.root), i.personal, i.alice))
            .is_err()
    );
    assert!(
        store
            .writer()
            .write(move |tx| auth::set_membership(
                tx,
                principal(i.root),
                i.personal,
                i.alice,
                Role::Reader
            ))
            .is_err()
    );
}

#[test]
fn identity_linking_uses_immutable_provider_subject_not_display_name() {
    let (_dir, store, i) = fixture();
    store
        .writer()
        .write(move |tx| {
            provisioning::link_verified_identity(tx, i.alice, "github", "42", NOW)?;
            provisioning::link_verified_identity(tx, i.outsider, "other_issuer", "42", NOW)
        })
        .unwrap();
    store
        .read(|c| {
            assert_eq!(
                provisioning::resolve_verified_identity(c, "github", "42")?,
                i.alice
            );
            assert_eq!(
                provisioning::resolve_verified_identity(c, "other_issuer", "42")?,
                i.outsider
            );
            missing(provisioning::resolve_verified_identity(
                c, "github", "alice",
            ));
            Ok(())
        })
        .unwrap();
    assert!(
        store
            .writer()
            .write(move |tx| provisioning::link_verified_identity(
                tx, i.outsider, "github", "42", NOW
            ))
            .is_err()
    );
    missing(
        store
            .writer()
            .write(move |tx| provisioning::link_verified_identity(tx, i.bot, "github", "99", NOW)),
    );
    let error = store
        .writer()
        .write(move |tx| {
            provisioning::link_verified_identity(tx, i.alice, "github", "credential\nvalue", NOW)
        })
        .unwrap_err();
    assert!(!error.to_string().contains("credential"));
    store
        .writer()
        .write(move |tx| {
            tx.execute(
                "UPDATE users SET active=0 WHERE id=?1",
                [i.alice.as_bytes()],
            )?;
            Ok(())
        })
        .unwrap();
    store
        .read(|c| {
            missing(provisioning::resolve_verified_identity(c, "github", "42"));
            missing(auth::get_repo(c, principal(i.alice), i.ar));
            Ok(())
        })
        .unwrap();
}

#[test]
fn revocation_is_live_and_readding_membership_does_not_restore_old_grants() {
    let (_dir, store, i) = fixture();
    store
        .writer()
        .write(move |tx| auth::set_membership(tx, principal(i.alice), i.a, i.bob, Role::Reader))
        .unwrap();
    store
        .read(|c| {
            auth::get_repo(c, principal(i.bob), i.ar)?;
            missing(auth::require_repo(c, principal(i.bob), i.ar, P::RUN));
            Ok(())
        })
        .unwrap();
    store
        .writer()
        .write(move |tx| auth::remove_membership(tx, principal(i.alice), i.a, i.bob))
        .unwrap();
    store
        .writer()
        .write(move |tx| auth::set_membership(tx, principal(i.alice), i.a, i.bob, Role::Operator))
        .unwrap();
    store
        .read(|c| {
            missing(auth::get_repo(c, principal(i.bob), i.ar));
            Ok(())
        })
        .unwrap();
    store
        .writer()
        .write(move |tx| auth::set_repo_grant(tx, principal(i.alice), i.ar, i.bot, P::NONE))
        .unwrap();
    store
        .read(|c| {
            missing(auth::get_repo(c, principal(i.bot), i.ar));
            Ok(())
        })
        .unwrap();
    store
        .writer()
        .write(move |tx| {
            tx.execute("UPDATE tenants SET active=0 WHERE id=?1", [i.a.as_bytes()])?;
            Ok(())
        })
        .unwrap();
    store
        .read(|c| {
            missing(auth::get_repo(c, principal(i.alice), i.ar));
            assert!(matches!(
                auth::require_tenant_admin(c, principal(i.root), i.a),
                Err(Error::Forbidden)
            ));
            Ok(())
        })
        .unwrap();
}

#[test]
fn authorization_and_mutation_share_the_writer_transaction() {
    let (_dir, store, i) = fixture();
    let new_repo = RepoId::new();
    // This simulates a revocation committed while a request was queued. There
    // is no reusable positive authorization decision from its earlier read.
    store
        .read(|c| auth::require_tenant_admin(c, principal(i.alice), i.a))
        .unwrap();
    store
        .writer()
        .write(move |tx| auth::set_membership(tx, principal(i.root), i.a, i.alice, Role::Reader))
        .unwrap();
    assert!(matches!(
        store.writer().write(move |tx| auth::create_repo(
            tx,
            principal(i.alice),
            i.a,
            new_repo,
            "denied",
            NOW
        )),
        Err(Error::Forbidden)
    ));
    store
        .read(|c| {
            let count: i64 = c.query_row(
                "SELECT count(*) FROM repos WHERE id=?1",
                [new_repo.as_bytes()],
                |r| r.get(0),
            )?;
            assert_eq!(count, 0);
            Ok(())
        })
        .unwrap();
    let rolled_back = UserId::new();
    assert!(
        store
            .writer()
            .write(move |tx| {
                auth::create_service_account(
                    tx,
                    principal(i.root),
                    i.a,
                    rolled_back,
                    "rollback",
                    Role::Reader,
                    NOW,
                )?;
                auth::set_repo_grant(tx, principal(i.root), i.ar, rolled_back, P::ALL)
            })
            .is_err()
    );
    store
        .read(|c| {
            let count: i64 = c.query_row(
                "SELECT count(*) FROM users WHERE id=?1",
                [rolled_back.as_bytes()],
                |r| r.get(0),
            )?;
            assert_eq!(count, 0);
            Ok(())
        })
        .unwrap();
}

#[test]
fn schema_rejects_cross_tenant_rows_even_through_raw_sql() {
    let (_dir, store, i) = fixture();
    assert!(store.writer().write(move |tx| {
        tx.execute("INSERT INTO repo_grants(tenant_id, repo_id, user_id, permissions) VALUES (?1, ?2, ?3, 1)", params![i.a.as_bytes(), i.br.as_bytes(), i.bot.as_bytes()])?; Ok(())
    }).is_err());
    assert!(
        store
            .writer()
            .write(move |tx| {
                tx.execute(
                    "INSERT INTO memberships VALUES (?1, ?2, 1)",
                    params![i.b.as_bytes(), i.bot.as_bytes()],
                )?;
                Ok(())
            })
            .is_err()
    );
    assert!(
        store
            .writer()
            .write(move |tx| {
                tx.execute(
                    "UPDATE users SET super_admin=1 WHERE id=?1",
                    [i.bot.as_bytes()],
                )?;
                Ok(())
            })
            .is_err()
    );
    assert!(store.writer().write(move |tx| {
        tx.execute("INSERT INTO runs(id, tenant_id, repo_id, source_sha, created_ms) VALUES (?1, ?2, ?3, 'sha', 1)", params![RunId::new().as_bytes(), i.b.as_bytes(), i.ar.as_bytes()])?; Ok(())
    }).is_err());
    assert!(
        store
            .writer()
            .write(move |tx| {
                tx.execute(
                    "UPDATE repos SET tenant_id=?1 WHERE id=?2",
                    params![i.b.as_bytes(), i.ar.as_bytes()],
                )?;
                Ok(())
            })
            .is_err()
    );
    store
        .read(|c| {
            assert_eq!(
                c.query_row("SELECT count(*) FROM pragma_foreign_key_check", [], |r| r
                    .get::<_, i64>(
                    0
                ))?,
                0
            );
            Ok(())
        })
        .unwrap();
}

#[test]
fn migration_preserves_v3_data_and_rejects_future_versions_and_inconsistent_ownership() {
    for corrupt in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("old.sqlite");
        let mut conn = Connection::open(&path).unwrap();
        conn.execute_batch("PRAGMA foreign_keys=ON; CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY, applied_ms INTEGER NOT NULL);").unwrap();
        for &(version, sql) in &sentinel_store::schema::MIGRATIONS[..3] {
            conn.execute_batch(sql).unwrap();
            conn.execute("INSERT INTO schema_migrations VALUES (?1, 1)", [version])
                .unwrap();
        }
        let (a, b, repo, run) = (
            TenantId::new(),
            TenantId::new(),
            RepoId::new(),
            RunId::new(),
        );
        let tx = conn.transaction().unwrap();
        jobs::insert_tenant(&tx, a, "legacy", NOW).unwrap();
        jobs::insert_tenant(&tx, b, "other", NOW).unwrap();
        jobs::insert_repo(&tx, a, repo, "app", NOW).unwrap();
        jobs::insert_run(&tx, a, repo, run, "sha", NOW).unwrap();
        if corrupt {
            tx.execute(
                "UPDATE runs SET tenant_id=?1 WHERE id=?2",
                params![b.as_bytes(), run.as_bytes()],
            )
            .unwrap();
        }
        tx.commit().unwrap();
        drop(conn);
        let opened = Store::open(&path, Durability::Full);
        if corrupt {
            assert!(opened.is_err());
            let conn = Connection::open(&path).unwrap();
            assert_eq!(
                conn.query_row("SELECT MAX(version) FROM schema_migrations", [], |r| r
                    .get::<_, i64>(0))
                    .unwrap(),
                3
            );
            assert_eq!(
                conn.query_row(
                    "SELECT count(*) FROM sqlite_master WHERE name='users'",
                    [],
                    |r| r.get::<_, i64>(0)
                )
                .unwrap(),
                0
            );
        } else {
            let store = opened.unwrap();
            store
                .read(|c| {
                    assert_eq!(
                        c.query_row(
                            "SELECT repo_id FROM runs WHERE id=?1",
                            [run.as_bytes()],
                            |r| r.get::<_, [u8; 16]>(0)
                        )?,
                        *repo.as_bytes()
                    );
                    assert_eq!(
                        c.query_row("SELECT count(*) FROM memberships", [], |r| r
                            .get::<_, i64>(0))?,
                        0
                    );
                    Ok(())
                })
                .unwrap();
            drop(store);
            let conn = Connection::open(&path).unwrap();
            conn.execute("INSERT INTO schema_migrations VALUES (999, 1)", [])
                .unwrap();
            drop(conn);
            assert!(matches!(
                Store::open(path, Durability::Full),
                Err(Error::Corrupt("unsupported database version"))
            ));
        }
    }
}

#[test]
fn identities_memberships_and_grants_survive_reopen() {
    let (dir, store, i) = fixture();
    store
        .writer()
        .write(move |tx| provisioning::link_verified_identity(tx, i.alice, "github", "1234", NOW))
        .unwrap();
    drop(store);
    let store = Store::open(dir.path().join("auth.sqlite"), Durability::Full).unwrap();
    store
        .read(|c| {
            assert_eq!(
                provisioning::resolve_verified_identity(c, "github", "1234")?,
                i.alice
            );
            auth::require_repo(c, principal(i.bot), i.ar, P::RUN)?;
            auth::require_repo(c, principal(i.alice), i.personal_repo, P::REPOSITORY)?;
            missing(auth::get_repo(c, principal(i.root), i.ar));
            Ok(())
        })
        .unwrap();
}

#[test]
fn dispatch_and_spec_read_derive_ownership_and_recheck_revoked_permissions() {
    use sentinel_pipeline::{PinnedSource, RunSpec, compile_str};
    let (_dir, store, i) = fixture();
    let spec = || {
        RunSpec::new(
            PinnedSource::new(
                "https://github.com/example/app",
                "0123456789012345678901234567890123456789",
                None,
            )
            .unwrap(),
            compile_str(include_str!("../../../fixtures/pipelines/valid/full.yml")).unwrap(),
        )
        .unwrap()
    };
    let run = RunId::new();
    let input = spec();
    let expected = input.clone();
    store
        .writer()
        .write(move |tx| auth::create_run(tx, principal(i.bot), i.ar, run, &input, NOW))
        .unwrap();
    store
        .read(|c| {
            assert_eq!(auth::get_run_spec(c, principal(i.bob), run)?, expected);
            missing(auth::get_run_spec(c, principal(i.outsider), run));
            missing(auth::get_run_spec(c, principal(i.root), run));
            missing(auth::get_run_spec(
                c,
                Principal::new(i.bob, P::READ, Some(i.b), None),
                run,
            ));
            missing(auth::get_run_spec(
                c,
                Principal::new(i.bob, P::READ, None, Some(i.ar2)),
                run,
            ));
            missing(auth::get_run_spec(c, principal(i.alice), RunId::new()));
            assert_eq!(
                c.query_row(
                    "SELECT tenant_id FROM runs WHERE id=?1",
                    [run.as_bytes()],
                    |r| r.get::<_, [u8; 16]>(0)
                )?,
                *i.a.as_bytes()
            );
            Ok(())
        })
        .unwrap();
    for (actor, repo) in [
        (principal(i.bot), i.br),
        (principal(i.alice), i.br),
        (principal(i.bob), i.ar2),
    ] {
        let input = spec();
        missing(
            store
                .writer()
                .write(move |tx| auth::create_run(tx, actor, repo, RunId::new(), &input, NOW)),
        );
    }
    store
        .writer()
        .write(move |tx| auth::remove_membership(tx, principal(i.alice), i.a, i.bot))
        .unwrap();
    let input = spec();
    missing(
        store.writer().write(move |tx| {
            auth::create_run(tx, principal(i.bot), i.ar, RunId::new(), &input, NOW)
        }),
    );
    store
        .read(|c| {
            missing(auth::get_run_spec(c, principal(i.bot), run));
            assert_eq!(
                c.query_row("SELECT count(*) FROM runs", [], |r| r.get::<_, i64>(0))?,
                1
            );
            Ok(())
        })
        .unwrap();
}
