//! Guided migration's switch and write gate: starting a migration is refused naming exactly what
//! the App's installations lack, and a withdrawal — on GitHub's side or by turning the switch off
//! — stops the next write at once, with the withdrawal and the refusal both in the audit trail.

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
    github_events,
    migration::{self, Writes},
    registration::Authority,
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

fn snapshot(
    expected: u64,
    migration: MigrationPermissions,
    personal: bool,
) -> sources_forge::Snapshot<'static> {
    sources_forge::Snapshot {
        external_id: EXTERNAL,
        account_id: ACCOUNT,
        login: "account",
        personal,
        suspended: false,
        permissions_valid: true,
        runner: RunnerPermissions::NONE,
        migration,
        expected,
    }
}

/// Records what GitHub last said about the installation and, the first time, binds the
/// repository through it — a fresh snapshot is exactly how a permission change arrives.
fn installation(f: &mut Fixture, migration: MigrationPermissions, personal: bool) {
    let tx = f.conn.transaction().unwrap();
    let existing: i64 = tx
        .query_row(
            "SELECT COALESCE(MAX(lifecycle_version), 0) FROM installations WHERE external_id = ?1",
            [EXTERNAL.to_string()],
            |r| r.get(0),
        )
        .unwrap();
    let id =
        sources_forge::refresh(&tx, snapshot(existing as u64, migration, personal), NOW).unwrap();
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

/// The installation webhook's own path: the delivery queues a refresh, and the lane applies the
/// snapshot GitHub reports through `github_events::apply_installation`.
fn reported(f: &mut Fixture, migration: MigrationPermissions) {
    let tx = f.conn.transaction().unwrap();
    let id: [u8; 16] = tx
        .query_row(
            "SELECT id FROM installations WHERE external_id = ?1",
            [EXTERNAL.to_string()],
            |r| r.get(0),
        )
        .unwrap();
    github_events::schedule(&tx, &id, 0, NOW).unwrap();
    tx.commit().unwrap();
    let work = github_events::due(&f.conn, NOW).unwrap().unwrap();
    let expected = github_events::install_target(&f.conn, &work.id)
        .unwrap()
        .unwrap()
        .expected;
    let tx = f.conn.transaction().unwrap();
    github_events::apply_installation(&tx, &work, snapshot(expected, migration, false), &[], NOW)
        .unwrap();
    tx.commit().unwrap();
}

fn switch(f: &mut Fixture, enabled: bool) -> Result<Switch, Error> {
    let tx = f.conn.transaction().unwrap();
    let outcome = migration::set_mode(&tx, Authority::HostLocal, f.tenant, enabled);
    if outcome.is_ok() {
        tx.commit().unwrap();
    }
    outcome
}

fn authorize(f: &mut Fixture) -> Result<Writes, Error> {
    let tx = f.conn.transaction().unwrap();
    let verdict = migration::authorize(&tx, f.tenant, f.repo, Some(f.owner.user), NOW);
    if verdict.is_ok() {
        tx.commit().unwrap();
    }
    verdict
}

/// The gate's own rows in the repository's audit trail, in the order they were written.
fn refusals(f: &Fixture) -> Vec<String> {
    let mut stmt = f
        .conn
        .prepare(
            "SELECT action FROM source_audit WHERE repo_id = ?1
             AND action IN ('migration_off', 'migration_permissions') ORDER BY at_ms",
        )
        .unwrap();
    stmt.query_map([f.repo.as_bytes()], |r| r.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect()
}

#[test]
fn starting_a_migration_is_refused_naming_exactly_what_the_installations_lack() {
    let mut f = organization();
    assert_eq!(switch(&mut f, true).unwrap(), Switch::NoInstallation);

    installation(&mut f, MigrationPermissions::NONE, false);
    assert_eq!(
        switch(&mut f, true).unwrap(),
        Switch::Missing(vec!["contents", "pull_requests", "workflows"])
    );
    assert_eq!(
        migration::missing(&f.conn, f.tenant).unwrap(),
        vec!["contents", "pull_requests", "workflows"]
    );

    // A fresh snapshot that brings contents and pull requests write still owes workflows write.
    installation(
        &mut f,
        MigrationPermissions::grants(true, true, false),
        false,
    );
    assert_eq!(
        switch(&mut f, true).unwrap(),
        Switch::Missing(vec!["workflows"])
    );

    installation(&mut f, MigrationPermissions::ALL, false);
    assert_eq!(switch(&mut f, true).unwrap(), Switch::Set);
    assert!(migration::mode(&f.conn, f.tenant).unwrap());
    assert_eq!(switch(&mut f, true).unwrap(), Switch::Unchanged);
    assert_eq!(switch(&mut f, false).unwrap(), Switch::Set);
    assert!(!migration::mode(&f.conn, f.tenant).unwrap());
    assert_eq!(switch(&mut f, false).unwrap(), Switch::Unchanged);
}

#[test]
fn a_personal_namespace_is_asked_for_the_same_three_permissions() {
    let mut f = fixture(true);
    installation(&mut f, MigrationPermissions::NONE, true);
    assert_eq!(
        switch(&mut f, true).unwrap(),
        Switch::Missing(vec!["contents", "pull_requests", "workflows"])
    );
    installation(&mut f, MigrationPermissions::ALL, true);
    assert_eq!(switch(&mut f, true).unwrap(), Switch::Set);
    assert_eq!(authorize(&mut f).unwrap(), Writes::Permitted);
}

#[test]
fn an_installation_without_migration_on_keeps_the_base_permissions() {
    let mut f = organization();
    // GitHub reports an installation with exactly the base set, and nothing is refused: the
    // snapshot is valid, source access is granted, and the switch is simply off.
    installation(&mut f, MigrationPermissions::NONE, false);
    let access = migration::access(&f.conn, f.tenant, f.repo).unwrap();
    assert!(!access.enabled && !access.granted());
    assert_eq!(authorize(&mut f).unwrap(), Writes::Off);
    assert_eq!(refusals(&f), ["migration_off"]);
    let grant = sources_forge::grant(&f.conn, f.tenant, f.repo).unwrap();
    assert_eq!(grant.account, ACCOUNT);
    // Nothing about the base set changed: the install is valid and the switch reads off.
    let valid: i64 = f
        .conn
        .query_row(
            "SELECT permissions_valid FROM installations WHERE external_id = ?1",
            [EXTERNAL.to_string()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(valid, 1);
    assert!(!migration::mode(&f.conn, f.tenant).unwrap());
}

#[test]
fn a_withdrawn_permission_stops_the_next_write_at_once() {
    let mut f = organization();
    installation(&mut f, MigrationPermissions::ALL, false);
    assert_eq!(switch(&mut f, true).unwrap(), Switch::Set);
    assert_eq!(authorize(&mut f).unwrap(), Writes::Permitted);
    assert!(refusals(&f).is_empty());

    // GitHub reports the installation again without workflows write: the snapshot the intake
    // applies is what the gate reads, so the next write is refused with no restart.
    reported(&mut f, MigrationPermissions::grants(true, true, false));
    assert_eq!(
        authorize(&mut f).unwrap(),
        Writes::Missing(vec!["workflows"])
    );
    assert_eq!(refusals(&f), ["migration_permissions"]);

    // Granting it again is the same path in reverse, and writes resume.
    reported(&mut f, MigrationPermissions::ALL);
    assert_eq!(authorize(&mut f).unwrap(), Writes::Permitted);

    // Turning the switch off stops every write path in the same transaction it reads.
    assert_eq!(switch(&mut f, false).unwrap(), Switch::Set);
    assert_eq!(authorize(&mut f).unwrap(), Writes::Off);
    assert_eq!(refusals(&f), ["migration_permissions", "migration_off"]);
}

#[test]
fn removing_the_app_stops_writes_and_the_switch_cannot_be_resumed() {
    let mut f = organization();
    installation(&mut f, MigrationPermissions::ALL, false);
    assert_eq!(switch(&mut f, true).unwrap(), Switch::Set);
    let id: [u8; 16] = f
        .conn
        .query_row(
            "SELECT id FROM installations WHERE external_id = ?1",
            [EXTERNAL.to_string()],
            |r| r.get(0),
        )
        .unwrap();
    let id = InstallationId::from_bytes(id).unwrap();
    let work = github_events::Refresh {
        id: *id.as_bytes(),
        kind: 0,
        seq: 0,
        attempts: 0,
    };
    let tx = f.conn.transaction().unwrap();
    github_events::installation_gone(&tx, &work, id.as_bytes()).unwrap();
    tx.commit().unwrap();
    assert_eq!(authorize(&mut f).unwrap(), Writes::Unbound);
    assert!(matches!(
        migration::access(&f.conn, f.tenant, f.repo),
        Err(Error::NotFound)
    ));
    assert_eq!(switch(&mut f, false).unwrap(), Switch::Set);
    assert_eq!(switch(&mut f, true).unwrap(), Switch::NoInstallation);
}

#[test]
fn only_a_tenant_administrator_turns_the_switch() {
    let mut f = organization();
    installation(&mut f, MigrationPermissions::ALL, false);
    let reader = Principal::new(f.owner.user, Permissions::READ, Some(f.tenant), None);
    {
        let tx = f.conn.transaction().unwrap();
        assert!(matches!(
            migration::set_mode(&tx, Authority::credential(reader), f.tenant, true),
            Err(Error::Forbidden)
        ));
    }
    assert!(!migration::mode(&f.conn, f.tenant).unwrap());
}
