//! Runner mode's switch and the permission lifecycle behind it: enabling is refused naming
//! exactly what the App's installations lack, and a withdrawn permission is visible at once.

use rusqlite::Connection;
use sentinel_auth::sealed::Key;
use sentinel_core::{
    InstallationId, MigrationPermissions, RepoId, RunnerPermissions, TenantId, UnixMillis, UserId,
    auth::{Namespace, Permissions, Principal},
};
use sentinel_protocol::source::{Binding, Credential};
use sentinel_store::{
    Error,
    auth::{self, NamespaceKind, provisioning},
    registration::Authority,
    runner,
    sources::{self, Update},
    sources_forge,
    switch::Switch,
};

const NOW: UnixMillis = UnixMillis(1_000);
const REF: &str = "refs/heads/main";
const ACCOUNT: u64 = 73;
const EXTERNAL: u64 = 42;

struct Fixture {
    conn: Connection,
    key: Key,
    _dir: tempfile::TempDir,
    owner: Principal,
    tenant: TenantId,
    repo: RepoId,
}

fn fixture(personal: bool) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("key");
    Key::create(&path).unwrap();
    let key = Key::load(&path).unwrap();
    let mut conn = Connection::open_in_memory().unwrap();
    conn.execute_batch("PRAGMA foreign_keys=ON").unwrap();
    sentinel_store::migrate(&mut conn).unwrap();
    let owner = Principal::new(UserId::new(), Permissions::ALL, None, None);
    let (tenant, repo) = (TenantId::new(), RepoId::new());
    let kind = if personal {
        NamespaceKind::Personal(owner.user)
    } else {
        NamespaceKind::Organization
    };
    let tx = conn.transaction().unwrap();
    provisioning::insert_human(&tx, owner.user, "owner", true, NOW).unwrap();
    auth::create_namespace(
        &tx,
        owner,
        tenant,
        Namespace::parse("acme").unwrap(),
        kind,
        NOW,
    )
    .unwrap();
    auth::create_repo(&tx, owner, tenant, repo, "app", NOW).unwrap();
    tx.commit().unwrap();
    Fixture {
        conn,
        key,
        _dir: dir,
        owner,
        tenant,
        repo,
    }
}

fn organization() -> Fixture {
    fixture(false)
}

/// Records what GitHub last said about the installation and, the first time, binds the
/// repository through it: a fresh snapshot is exactly how a permission change arrives.
fn installation(f: &mut Fixture, runner_permissions: RunnerPermissions, personal: bool) {
    let tx = f.conn.transaction().unwrap();
    let existing: i64 = tx
        .query_row(
            "SELECT COALESCE(MAX(lifecycle_version), 0) FROM installations WHERE external_id = ?1",
            [EXTERNAL.to_string()],
            |r| r.get(0),
        )
        .unwrap();
    let id = sources_forge::refresh(
        &tx,
        sources_forge::Snapshot {
            external_id: EXTERNAL,
            account_id: ACCOUNT,
            login: "account",
            personal,
            suspended: false,
            permissions_valid: true,
            runner: runner_permissions,
            migration: MigrationPermissions::ALL,
            expected: existing as u64,
        },
        NOW,
    )
    .unwrap();
    let bound: i64 = tx
        .query_row(
            "SELECT count(*) FROM source_bindings WHERE repo_id = ?1",
            [f.repo.as_bytes()],
            |r| r.get(0),
        )
        .unwrap();
    if bound == 0 {
        sentinel_store::registration::bind_installation_trusted(&tx, id, f.tenant, NOW).unwrap();
        let binding = Binding {
            remote: "https://github.com/account/app.git".into(),
            allowed_refs: vec![REF.into()],
            pipeline_path: ".sentinel.yml".into(),
            trust: String::new(),
        };
        sources::bind(
            &tx,
            Authority::HostLocal,
            Some(f.owner.user),
            Update {
                repo: f.repo,
                expected: 0,
                binding: &binding,
                credential: &Credential::Public,
                forge: Some((id, 9)),
            },
            &["https://github.com".into()],
            &f.key,
            NOW,
        )
        .unwrap();
    }
    tx.commit().unwrap();
}

fn switch(f: &mut Fixture, enabled: bool) -> Result<Switch, Error> {
    let tx = f.conn.transaction().unwrap();
    let outcome = runner::set_mode(&tx, Authority::HostLocal, f.tenant, enabled);
    if outcome.is_ok() {
        tx.commit().unwrap();
    }
    outcome
}

#[test]
fn enabling_is_refused_naming_exactly_what_the_installations_lack() {
    let mut f = organization();
    assert_eq!(switch(&mut f, true).unwrap(), Switch::NoInstallation);

    installation(&mut f, RunnerPermissions::NONE, false);
    assert_eq!(
        switch(&mut f, true).unwrap(),
        Switch::Missing(vec!["actions", "organization_self_hosted_runners"])
    );
    assert_eq!(
        runner::missing(&f.conn, f.tenant).unwrap(),
        vec!["actions", "organization_self_hosted_runners"]
    );

    // A fresh snapshot that brings actions read leaves the registration grant missing.
    installation(&mut f, RunnerPermissions::grants(true, false), false);
    assert_eq!(
        switch(&mut f, true).unwrap(),
        Switch::Missing(vec!["organization_self_hosted_runners"])
    );

    installation(&mut f, RunnerPermissions::ALL, false);
    assert_eq!(switch(&mut f, true).unwrap(), Switch::Set);
    assert!(runner::mode(&f.conn, f.tenant).unwrap());
    assert_eq!(switch(&mut f, true).unwrap(), Switch::Unchanged);
    assert_eq!(switch(&mut f, false).unwrap(), Switch::Set);
    assert!(!runner::mode(&f.conn, f.tenant).unwrap());
    assert_eq!(switch(&mut f, false).unwrap(), Switch::Unchanged);
}

#[test]
fn a_personal_namespace_is_asked_for_administration_write_instead() {
    let mut f = fixture(true);
    installation(&mut f, RunnerPermissions::grants(false, true), true);
    assert_eq!(
        switch(&mut f, true).unwrap(),
        Switch::Missing(vec!["actions"])
    );
    installation(&mut f, RunnerPermissions::grants(true, true), true);
    assert_eq!(switch(&mut f, true).unwrap(), Switch::Set);
}

#[test]
fn a_withdrawn_permission_or_a_removed_app_stops_the_flow_at_once() {
    let mut f = organization();
    installation(&mut f, RunnerPermissions::ALL, false);
    assert_eq!(switch(&mut f, true).unwrap(), Switch::Set);
    let access = runner::access(&f.conn, f.tenant, f.repo).unwrap();
    assert!(access.enabled && access.permissions.contains(RunnerPermissions::ALL));

    // GitHub reports the installation again without the registration grant.
    installation(&mut f, RunnerPermissions::grants(true, false), false);
    let access = runner::access(&f.conn, f.tenant, f.repo).unwrap();
    assert!(access.enabled);
    assert_eq!(
        access.permissions.missing(access.personal),
        ["organization_self_hosted_runners"]
    );

    // Removing the App suspends the installation and clears every runner permission.
    let id: [u8; 16] = f
        .conn
        .query_row(
            "SELECT id FROM installations WHERE external_id = ?1",
            [EXTERNAL.to_string()],
            |r| r.get(0),
        )
        .unwrap();
    let id = InstallationId::from_bytes(id).unwrap();
    let tx = f.conn.transaction().unwrap();
    sources_forge::remove(&tx, id).unwrap();
    tx.commit().unwrap();
    assert!(matches!(
        runner::access(&f.conn, f.tenant, f.repo),
        Err(Error::NotFound)
    ));
    // Nothing live is left to wait on, so nothing is reported missing; the switch itself is
    // the refusal, and it was already on: off and back on shows the removal stopping it.
    assert!(runner::missing(&f.conn, f.tenant).unwrap().is_empty());
    assert_eq!(switch(&mut f, false).unwrap(), Switch::Set);
    assert_eq!(switch(&mut f, true).unwrap(), Switch::NoInstallation);
}

#[test]
fn only_a_tenant_administrator_turns_the_switch() {
    let mut f = organization();
    installation(&mut f, RunnerPermissions::ALL, false);
    let reader = Principal::new(f.owner.user, Permissions::READ, Some(f.tenant), None);
    let tx = f.conn.transaction().unwrap();
    assert!(matches!(
        runner::set_mode(&tx, Authority::credential(reader), f.tenant, true),
        Err(Error::Forbidden)
    ));
    drop(tx);
    assert!(!runner::mode(&f.conn, f.tenant).unwrap());
}
