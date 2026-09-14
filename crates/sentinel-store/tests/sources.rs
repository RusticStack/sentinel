//! G01 store behavior: tenant-owned bindings, sealed credentials, rotation and
//! revocation with compare-and-set, ref and destination policy, GitHub App
//! installation lifecycle, and migration that invents no binding.
use rusqlite::Connection;
use sentinel_auth::sealed::Key;
use sentinel_core::{
    RepoId, TenantId, UnixMillis, UserId,
    auth::{Namespace, Permissions, Principal},
};
use sentinel_protocol::source::{Binding, Credential};
use sentinel_store::{
    Error,
    auth::{self, NamespaceKind, provisioning},
    registration::{self, Authority},
    sources::{self, Update},
    sources_forge,
};

const NOW: UnixMillis = UnixMillis(1000);
struct Fixture {
    conn: Connection,
    key: Key,
    _dir: tempfile::TempDir,
    alice: Principal,
    bob: Principal,
    tenant: TenantId,
    other: TenantId,
    repo: RepoId,
    other_repo: RepoId,
}
fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("key");
    Key::create(&path).unwrap();
    let key = Key::load(&path).unwrap();
    let mut conn = Connection::open_in_memory().unwrap();
    conn.execute_batch("PRAGMA foreign_keys=ON").unwrap();
    sentinel_store::migrate(&mut conn).unwrap();
    let alice = Principal::new(UserId::new(), Permissions::ALL, None, None);
    let bob = Principal::new(UserId::new(), Permissions::ALL, None, None);
    let (tenant, other, repo, other_repo) = (
        TenantId::new(),
        TenantId::new(),
        RepoId::new(),
        RepoId::new(),
    );
    let tx = conn.transaction().unwrap();
    for (p, name) in [(alice, "alice"), (bob, "bob")] {
        provisioning::insert_human(&tx, p.user, name, true, NOW).unwrap();
    }
    for (t, r, p, name) in [
        (tenant, repo, alice, "alice"),
        (other, other_repo, bob, "bob"),
    ] {
        auth::create_namespace(
            &tx,
            p,
            t,
            Namespace::parse(name).unwrap(),
            NamespaceKind::Personal(p.user),
            NOW,
        )
        .unwrap();
        auth::create_repo(&tx, p, t, r, "project", NOW).unwrap();
    }
    tx.commit().unwrap();
    Fixture {
        conn,
        key,
        _dir: dir,
        alice,
        bob,
        tenant,
        other,
        repo,
        other_repo,
    }
}
fn binding() -> Binding {
    Binding {
        remote: "https://git.example:8443/team/repo.git".into(),
        allowed_refs: vec!["refs/heads/main".into(), "refs/tags/v*".into()],
        pipeline_path: ".sentinel.yml".into(),
        trust: String::new(),
    }
}
fn credential() -> Credential {
    Credential::Https {
        username: "deploy".into(),
        secret: "private-deploy-token".into(),
    }
}
fn with(
    f: &mut Fixture,
    authority: Authority,
    actor: Option<UserId>,
    repo: RepoId,
    expected: u64,
) -> sentinel_store::Result<u64> {
    let tx = f.conn.transaction()?;
    let v = sources::bind(
        &tx,
        authority,
        actor,
        Update {
            repo,
            expected,
            binding: &binding(),
            credential: &credential(),
            forge: None,
        },
        &["https://git.example:8443".into()],
        &f.key,
        NOW,
    )?;
    tx.commit()?;
    Ok(v)
}
fn bind(f: &mut Fixture, expected: u64) -> sentinel_store::Result<u64> {
    with(f, Authority::credential(f.alice), None, f.repo, expected)
}

#[test]
fn generic_binding_needs_no_forge_and_credentials_are_tenant_sealed() {
    let mut f = fixture();
    assert_eq!(bind(&mut f, 0).unwrap(), 1);
    let installations: i64 = f
        .conn
        .query_row("SELECT count(*) FROM installations", [], |r| r.get(0))
        .unwrap();
    assert_eq!(installations, 0);
    let sealed: Vec<u8> = f
        .conn
        .query_row("SELECT credential FROM source_bindings", [], |r| r.get(0))
        .unwrap();
    assert!(!sealed.windows(7).any(|b| b == b"private"));
    let access = sources::issue(&f.conn, f.tenant, f.repo, &f.key, NOW).unwrap();
    assert_eq!(access.credential, credential());
    assert!(!format!("{access:?}").contains("private-deploy-token"));
    assert!(sources::issue(&f.conn, f.other, f.repo, &f.key, NOW).is_err());
    assert!(matches!(
        sources::metadata(&f.conn, f.bob, f.repo),
        Err(Error::NotFound)
    ));
    // Another account cannot bind this repository even with a valid version.
    let tx = f.conn.transaction().unwrap();
    assert!(
        sources::bind(
            &tx,
            Authority::credential(f.bob),
            None,
            Update {
                repo: f.repo,
                expected: 1,
                binding: &binding(),
                credential: &credential(),
                forge: None
            },
            &["https://git.example:8443".into()],
            &f.key,
            NOW
        )
        .is_err()
    );
    tx.rollback().unwrap();
    // The host-local path is the operator's own authority: no membership is
    // required, but the attribution is recorded.
    let (actor_id, repo) = (f.alice.user, f.repo);
    assert_eq!(
        with(&mut f, Authority::HostLocal, Some(actor_id), repo, 1).unwrap(),
        2
    );
    let (actor, action): (Option<[u8; 16]>, String) = f
        .conn
        .query_row(
            "SELECT actor, action FROM source_audit ORDER BY seq DESC LIMIT 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(actor, Some(*f.alice.user.as_bytes()));
    assert_eq!(action, "bind");
    // Copying ciphertext to another owned repository fails its AEAD context.
    let (bob, other_repo) = (f.bob, f.other_repo);
    with(&mut f, Authority::credential(bob), None, other_repo, 0).unwrap();
    f.conn
        .execute(
            "UPDATE source_bindings SET credential=?1 WHERE repo_id=?2",
            rusqlite::params![sealed, f.other_repo.as_bytes()],
        )
        .unwrap();
    assert!(sources::issue(&f.conn, f.other, f.other_repo, &f.key, NOW).is_err());
}

#[test]
fn rotation_revocation_ref_policy_and_stale_updates() {
    let mut f = fixture();
    bind(&mut f, 0).unwrap();
    assert_eq!(bind(&mut f, 1).unwrap(), 2);
    assert!(matches!(bind(&mut f, 1), Err(Error::Conflict)));
    let source = |remote: &str, r: &str| {
        sentinel_pipeline::PinnedSource::new(remote, &"a".repeat(40), Some(r)).unwrap()
    };
    assert!(
        sources::validate_source(
            &f.conn,
            f.repo,
            &source(&binding().remote, "refs/heads/main")
        )
        .is_ok()
    );
    assert!(
        sources::validate_source(&f.conn, f.repo, &source(&binding().remote, "refs/tags/v1"))
            .is_ok()
    );
    assert!(
        sources::validate_source(
            &f.conn,
            f.repo,
            &source(&binding().remote, "refs/heads/other")
        )
        .is_err()
    );
    assert!(
        sources::validate_source(
            &f.conn,
            f.repo,
            &source("https://evil.example/r.git", "refs/heads/main")
        )
        .is_err()
    );
    let tx = f.conn.transaction().unwrap();
    sources::revoke(&tx, Authority::credential(f.alice), None, f.repo, 2, NOW).unwrap();
    tx.commit().unwrap();
    assert!(sources::issue(&f.conn, f.tenant, f.repo, &f.key, NOW).is_err());
    assert!(sources::metadata(&f.conn, f.alice, f.repo).unwrap().revoked);
    assert_eq!(bind(&mut f, 3).unwrap(), 4);
    f.conn
        .execute(
            "UPDATE tenants SET active=0 WHERE id=?1",
            [f.tenant.as_bytes()],
        )
        .unwrap();
    assert!(sources::issue(&f.conn, f.tenant, f.repo, &f.key, NOW).is_err());
    // A suspended tenant is not reported as usable either.
    assert!(matches!(
        sources::metadata_trusted(&f.conn, f.repo),
        Err(Error::NotFound)
    ));
}

#[test]
fn destination_policy_and_credential_transport_cannot_be_bypassed() {
    let mut f = fixture();
    let tx = f.conn.transaction().unwrap();
    assert!(
        sources::bind(
            &tx,
            Authority::credential(f.alice),
            None,
            Update {
                repo: f.repo,
                expected: 0,
                binding: &binding(),
                credential: &credential(),
                forge: None
            },
            &["https://other.example".into()],
            &f.key,
            NOW
        )
        .is_err()
    );
    assert!(
        sources::bind(
            &tx,
            Authority::credential(f.alice),
            None,
            Update {
                repo: f.repo,
                expected: 0,
                binding: &binding(),
                credential: &Credential::Ssh {
                    private_key: "key".into()
                },
                forge: None
            },
            &["https://git.example:8443".into()],
            &f.key,
            NOW
        )
        .is_err()
    );
    tx.rollback().unwrap();
}

#[test]
fn installation_lifecycle_requires_binding_and_fresh_permissions() {
    let mut f = fixture();
    let snapshot = |expected, personal, suspended| sources_forge::Snapshot {
        external_id: 42,
        account_id: 73,
        login: "account",
        personal,
        suspended,
        permissions_valid: true,
        expected,
    };
    let tx = f.conn.transaction().unwrap();
    let id = sources_forge::refresh(&tx, snapshot(0, true, false), NOW).unwrap();
    let mut b = binding();
    b.remote = "https://github.com/account/repo.git".into();
    let update = |expected| Update {
        repo: f.repo,
        expected,
        binding: &b,
        credential: &Credential::Public,
        forge: Some((id, 91)),
    };
    // Unbound installations authorize nothing, even for a valid binding.
    assert!(
        sources::bind(
            &tx,
            Authority::credential(f.alice),
            None,
            update(0),
            &["https://github.com".into()],
            &f.key,
            NOW
        )
        .is_err()
    );
    registration::bind_installation(&tx, f.alice, id, f.tenant, NOW).unwrap();
    sources::bind(
        &tx,
        Authority::credential(f.alice),
        None,
        update(0),
        &["https://github.com".into()],
        &f.key,
        NOW,
    )
    .unwrap();
    tx.commit().unwrap();
    assert_eq!(
        sources_forge::grant(&f.conn, f.tenant, f.repo)
            .unwrap()
            .account,
        73
    );
    assert!(sources_forge::grant(&f.conn, f.other, f.repo).is_err());
    let tx = f.conn.transaction().unwrap();
    sources_forge::refresh(&tx, snapshot(1, true, true), NOW).unwrap();
    tx.commit().unwrap();
    assert!(sources_forge::grant(&f.conn, f.tenant, f.repo).is_err());
    let tx = f.conn.transaction().unwrap();
    assert!(matches!(
        sources_forge::refresh(&tx, snapshot(1, true, false), NOW),
        Err(Error::Conflict)
    ));
    tx.rollback().unwrap();
    let tx = f.conn.transaction().unwrap();
    sources_forge::refresh(&tx, snapshot(2, false, false), NOW).unwrap();
    sources_forge::remove(&tx, id).unwrap();
    tx.commit().unwrap();
    assert!(sources_forge::grant(&f.conn, f.tenant, f.repo).is_err());
}

#[test]
fn a_transfer_never_reauthorizes_the_old_accounts_bindings() {
    let mut f = fixture();
    let snapshot = |account_id, expected| sources_forge::Snapshot {
        external_id: 7,
        account_id,
        login: "account",
        personal: false,
        suspended: false,
        permissions_valid: true,
        expected,
    };
    let tx = f.conn.transaction().unwrap();
    let id = sources_forge::refresh(&tx, snapshot(73, 0), NOW).unwrap();
    registration::bind_installation_trusted(&tx, id, f.tenant, NOW).unwrap();
    let mut b = binding();
    b.remote = "https://github.com/account/repo.git".into();
    sources::bind(
        &tx,
        Authority::HostLocal,
        Some(f.alice.user),
        Update {
            repo: f.repo,
            expected: 0,
            binding: &b,
            credential: &Credential::Public,
            forge: Some((id, 91)),
        },
        &["https://github.com".into()],
        &f.key,
        NOW,
    )
    .unwrap();
    tx.commit().unwrap();
    assert!(sources_forge::grant(&f.conn, f.tenant, f.repo).is_ok());
    // The installation now belongs to a different account: the binding is
    // revoked rather than silently following the transfer.
    let tx = f.conn.transaction().unwrap();
    sources_forge::refresh(&tx, snapshot(99, 1), NOW).unwrap();
    tx.commit().unwrap();
    assert!(sources_forge::grant(&f.conn, f.tenant, f.repo).is_err());
    assert!(sources::metadata_trusted(&f.conn, f.repo).unwrap().revoked);
    // Binding an unknown installation by hand is refused.
    let tx = f.conn.transaction().unwrap();
    assert!(matches!(
        registration::bind_installation_trusted(&tx, id, f.other, NOW),
        Err(Error::Conflict)
    ));
    tx.rollback().unwrap();
}

#[test]
fn migration_preserves_legacy_repositories_without_inventing_bindings() {
    let mut conn = Connection::open_in_memory().unwrap();
    conn.execute_batch(
        "PRAGMA foreign_keys=ON; CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY,applied_ms INTEGER NOT NULL)",
    )
    .unwrap();
    for &(version, sql) in sentinel_store::schema::MIGRATIONS
        .iter()
        .filter(|m| m.0 <= 16)
    {
        conn.execute_batch(sql).unwrap();
        conn.execute("INSERT INTO schema_migrations VALUES(?1,0)", [version])
            .unwrap();
    }
    let (tenant, repo) = (TenantId::new(), RepoId::new());
    conn.execute(
        "INSERT INTO tenants(id,slug,created_ms) VALUES(?1,'legacy',0)",
        [tenant.as_bytes()],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO repos(id,tenant_id,name,created_ms) VALUES(?1,?2,'legacy',0)",
        rusqlite::params![repo.as_bytes(), tenant.as_bytes()],
    )
    .unwrap();
    assert_eq!(sentinel_store::migrate(&mut conn).unwrap(), 17);
    assert!(matches!(
        sources::load_metadata(&conn, repo),
        Err(Error::NotFound)
    ));
    assert_eq!(
        conn.query_row("SELECT count(*) FROM repos", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        1
    );
}
