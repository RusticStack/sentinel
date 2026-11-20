//! The rollback route: one action that puts the pre-switch workflow bytes back in a pull request,
//! re-enters shadow mode, and puts a branch's required checks back on the native path — shown, or
//! applied when the installation grants administration. Each test compares what GitHub's fake holds
//! afterwards with the fixture's own bytes and document, never with an intention.

use std::sync::Arc;

use sentinel_core::{
    MigrationPermissions, RepoId, RunnerPermissions, TenantId, UnixMillis, UserId,
    auth::{Namespace, Permissions, Principal, Role},
};
use sentinel_github::fake::FakeGithub;
use sentinel_link::{controller::Controller, identity::Identity};
use sentinel_protocol::source::{Binding, Credential};
use sentinel_store::{
    Durability, Store,
    auth::{self, Authority, NamespaceKind},
    local_auth, registration,
    sources::{self, Update},
    sources_forge,
    tokens::{self, Grant},
};

const INSTALLATION: u64 = 42;
const ACCOUNT: u64 = 73;
const FORGE_REPO: u64 = 91;
const REMOTE: &str = "https://github.com/account/widget.git";

/// The revision the migration started from: GitHub-hosted labels, nothing migrated.
const BEFORE: &str = "0123456789abcdef0123456789abcdef01234567";
/// The revision the switch committed: the same jobs on a Sentinel class.
const SWITCHED: &str = "2222222222222222222222222222222222222222";
/// A shadow revision: the original job untouched, a non-required copy named `sentinel / build`.
const SHADOW: &str = "3333333333333333333333333333333333333333";

const ORIGINAL: &str = "name: ci
on: [push, pull_request]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: cargo test
";

const SWAPPED: &str = "name: ci
on: [push, pull_request]
jobs:
  build:
    runs-on: sentinel-4vcpu-ubuntu-2404
    steps:
      - run: cargo test
";

const COPIED: &str = "name: ci
on: [push, pull_request]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: cargo test
  shadow-build:
    name: sentinel / build
    runs-on: sentinel-4vcpu-ubuntu-2404
    steps:
      - run: cargo test
";

/// The required checks before the switch, and the ones the switch put in their place.
fn pre_switch_checks() -> serde_json::Value {
    serde_json::json!({"strict": true, "checks": [{"context": "build", "app_id": 15368}]})
}

fn switched_checks() -> serde_json::Value {
    // The native switch swapped the workflow's own check for Sentinel's.
    serde_json::json!({"strict": true, "checks": [{"context": "sentinel / build", "app_id": 42}]})
}

const PATH: &str = "/api/v1/tenants/acme/repos/widget/migration/rollback";

struct Deployment {
    _dir: tempfile::TempDir,
    store: Arc<Store>,
    _controller: Controller,
    server: Option<sentinel_api::Server>,
    github: FakeGithub,
    base: String,
    token: String,
    tenant: TenantId,
    repo: RepoId,
    root: UserId,
}

impl Drop for Deployment {
    fn drop(&mut self) {
        if let Some(server) = self.server.take() {
            server.shutdown();
        }
    }
}

/// A throwaway RSA key, generated for this test alone: the App only signs a JWT the fake never
/// verifies.
fn test_key() -> &'static str {
    static KEY: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    KEY.get_or_init(|| {
        let out = std::process::Command::new("openssl")
            .args([
                "genpkey",
                "-algorithm",
                "RSA",
                "-pkeyopt",
                "rsa_keygen_bits:2048",
            ])
            .output()
            .expect("the openssl CLI must be installed to generate the test-only App key");
        assert!(out.status.success(), "openssl genpkey failed");
        String::from_utf8(out.stdout).expect("PEM is ASCII")
    })
}

/// A deployment with one installation bound to one repository, and a GitHub fake holding the
/// repository's three revisions: before the switch, after it, and the shadow's.
fn deployment(migration: MigrationPermissions, administration: bool) -> Deployment {
    let dir = tempfile::tempdir().unwrap();
    let store =
        Arc::new(Store::open(dir.path().join("metadata.sqlite"), Durability::Normal).unwrap());
    let logs = Arc::new(sentinel_store::logs::LogStore::open(dir.path().join("logs")).unwrap());
    let key_path = dir.path().join("master.key");
    sentinel_auth::sealed::Key::create(&key_path).unwrap();
    let key = sentinel_auth::sealed::Key::load(&key_path).unwrap();
    let root = local_auth::bootstrap(
        &store,
        "root",
        "Root",
        b"correct horse battery staple",
        UnixMillis::now(),
    )
    .unwrap();
    let (tenant, repo) = (TenantId::new(), RepoId::new());
    let now = UnixMillis::now();
    let owner = Principal::new(root, Permissions::ALL, None, None);
    store
        .writer()
        .write(move |tx| {
            auth::create_namespace(
                tx,
                owner,
                tenant,
                Namespace::parse("acme").unwrap(),
                NamespaceKind::Organization,
                now,
            )?;
            auth::set_membership(tx, owner, tenant, root, Role::TenantAdmin)?;
            auth::create_repo(tx, owner, tenant, repo, "widget", now)?;
            let installation = sources_forge::refresh(
                tx,
                sources_forge::Snapshot {
                    external_id: INSTALLATION,
                    account_id: ACCOUNT,
                    login: "account",
                    personal: false,
                    suspended: false,
                    permissions_valid: true,
                    runner: RunnerPermissions::NONE,
                    migration,
                    expected: 0,
                },
                now,
            )?;
            registration::bind_installation_trusted(tx, installation, tenant, now)?;
            let binding = Binding {
                remote: REMOTE.into(),
                allowed_refs: vec!["refs/heads/main".into()],
                pipeline_path: ".sentinel.yml".into(),
                trust: String::new(),
            };
            sources::bind(
                tx,
                Authority::HostLocal,
                Some(root),
                Update {
                    repo,
                    expected: 0,
                    binding: &binding,
                    credential: &Credential::Public,
                    forge: Some((installation, FORGE_REPO)),
                },
                &["https://github.com".into()],
                &key,
                now,
            )
        })
        .unwrap();
    let granted = tokens::provision(
        &store,
        Grant {
            user: root,
            name: "test",
            permissions: Permissions::ALL,
            tenant: Some(tenant),
            repo: None,
            lifetime_ms: 60_000,
        },
        UnixMillis::now(),
    )
    .unwrap();
    let objects = Arc::new(sentinel_store::objects::Objects::open(dir.path()).unwrap());
    let controller = Controller::start(
        Arc::clone(&store),
        Arc::clone(&logs),
        Arc::clone(&objects),
        Identity::generate("controller").unwrap(),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    let github = FakeGithub::start("unused-oauth-secret");
    let mut permissions = serde_json::json!({
        "checks": "write",
        "contents": "write",
        "pull_requests": "write",
        "workflows": "write",
    });
    if administration {
        permissions["administration"] = serde_json::json!("write");
    }
    github.add_installation(
        INSTALLATION,
        &serde_json::json!({
            "id": INSTALLATION,
            "app_id": 1,
            "account": {"id": ACCOUNT, "login": "account", "type": "Organization"},
            "suspended_at": null,
            "permissions": permissions,
        })
        .to_string(),
    );
    github.add_repository(
        FORGE_REPO,
        &serde_json::json!({
            "id": FORGE_REPO,
            "owner": {"id": ACCOUNT},
            "clone_url": REMOTE,
            "archived": false,
        })
        .to_string(),
    );
    github.set_workflows("account", "widget", BEFORE, &[("ci.yml", ORIGINAL)]);
    github.set_workflows("account", "widget", SWITCHED, &[("ci.yml", SWAPPED)]);
    github.set_workflows("account", "widget", SHADOW, &[("ci.yml", COPIED)]);
    // The default branch holds the switched workflow: the revert is built on its head.
    github.set_branch("account", "widget", "main", SWITCHED);
    github.set_protection("account", "widget", "main", &switched_checks());
    let app = sentinel_github::app::App::new(1, test_key())
        .unwrap()
        .with_endpoint(&github.base())
        .unwrap();
    let server = sentinel_api::Server::start_with(
        sentinel_api::Config {
            listen: "127.0.0.1:0".parse().unwrap(),
            store: Arc::clone(&store),
            logs,
            objects,
            controller: controller.handle(),
            secret_key: Some(Arc::new(
                sentinel_auth::sealed::Key::load(&key_path).unwrap(),
            )),
            sessions: local_auth::Policy::default(),
            github_webhook_secret: None,
            intake: None,
            public_url: None,
            github_sign_in: None,
            trusted_proxies: sentinel_api::TrustedProxy::loopback(),
        },
        sentinel_api::Options {
            github_app: sentinel_api::GithubAppSetup {
                web_url: github.base(),
                api_url: github.base(),
                sign_in_endpoints: github.endpoints(),
                current: Some(Arc::new(app)).into(),
                source: Some(sentinel_api::AppSource::Files),
                on_activate: None,
            },
            ..sentinel_api::Options::default()
        },
    )
    .unwrap();
    let base = format!("http://{}", server.local_addr());
    let deployment = Deployment {
        _dir: dir,
        store,
        _controller: controller,
        server: Some(server),
        github,
        base,
        token: sentinel_auth::token::format(&granted.secret),
        tenant,
        repo,
        root,
    };
    switch(&deployment, true);
    deployment
}

fn call(d: &Deployment, body: &serde_json::Value) -> (u16, serde_json::Value) {
    post(d, &d.token, body)
}

fn post(d: &Deployment, token: &str, body: &serde_json::Value) -> (u16, serde_json::Value) {
    let agent = ureq::Agent::new_with_config(
        ureq::Agent::config_builder()
            .http_status_as_error(false)
            .build(),
    );
    let response = agent
        .post(&format!("{}{PATH}", d.base))
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .send(body.to_string().as_bytes())
        .unwrap();
    let status = response.status().as_u16();
    let text = response.into_body().read_to_string().unwrap();
    let json = serde_json::from_str(&text).unwrap_or(serde_json::Value::String(text));
    (status, json)
}

/// The revert, as the wizard sends it: the pre-switch revision and nothing else.
fn revert(d: &Deployment) -> (u16, serde_json::Value) {
    call(
        d,
        &serde_json::json!({"action": "revert", "commit": BEFORE}),
    )
}

fn shadow(d: &Deployment) -> (u16, serde_json::Value) {
    call(
        d,
        &serde_json::json!({"action": "shadow", "commit": SHADOW}),
    )
}

/// The native path: the revert with the pre-switch required checks the switch's preview promised.
fn native(d: &Deployment, apply: bool) -> (u16, serde_json::Value) {
    call(
        d,
        &serde_json::json!({
            "action": "revert",
            "commit": BEFORE,
            "settings": {"required_checks": pre_switch_checks(), "apply": apply},
        }),
    )
}

fn switch(d: &Deployment, enabled: bool) {
    let agent = ureq::Agent::new_with_config(
        ureq::Agent::config_builder()
            .http_status_as_error(false)
            .build(),
    );
    let response = agent
        .post(&format!("{}/api/v1/tenants/acme/migration", d.base))
        .header("authorization", format!("Bearer {}", d.token))
        .header("content-type", "application/json")
        .send(
            serde_json::json!({"enabled": enabled})
                .to_string()
                .as_bytes(),
        )
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
}

/// GitHub reports the installation again: the snapshot is the only way a permission changes here.
fn reported(d: &Deployment, migration: MigrationPermissions) {
    let tenant = d.tenant;
    let expected: i64 = d
        .store
        .read(move |c| {
            Ok(c.query_row(
                "SELECT COALESCE(MAX(lifecycle_version), 0) FROM installations WHERE tenant_id = ?1",
                [tenant.as_bytes()],
                |r| r.get(0),
            )?)
        })
        .unwrap();
    d.store
        .writer()
        .write(move |tx| {
            sources_forge::refresh(
                tx,
                sources_forge::Snapshot {
                    external_id: INSTALLATION,
                    account_id: ACCOUNT,
                    login: "account",
                    personal: false,
                    suspended: false,
                    permissions_valid: true,
                    runner: RunnerPermissions::NONE,
                    migration,
                    expected: expected as u64,
                },
                UnixMillis::now(),
            )
        })
        .unwrap();
}

fn audit(d: &Deployment) -> Vec<String> {
    let repo = d.repo;
    d.store
        .read(move |c| {
            let mut stmt =
                c.prepare("SELECT action FROM source_audit WHERE repo_id = ?1 ORDER BY seq")?;
            let rows = stmt.query_map([repo.as_bytes()], |r| r.get::<_, String>(0))?;
            let mut out = Vec::new();
            for row in rows {
                out.push(row?);
            }
            Ok(out)
        })
        .unwrap()
}

#[test]
fn the_rollback_opens_one_pull_request_carrying_the_pre_switch_bytes() {
    let d = deployment(MigrationPermissions::ALL, false);
    let (status, body) = revert(&d);
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["schema"], "sentinel.migration-rollback/1");
    assert_eq!(body["action"], "revert");
    assert_eq!(body["branch"], "sentinel/migrate");
    assert_eq!(body["revision"], BEFORE);
    assert_eq!(body["from"], SWITCHED);
    assert_eq!(body["pull_request"]["state"], "opened");
    assert_eq!(body["pull_request"]["base"], "main");
    assert_eq!(body["workflows"][0]["path"], ".github/workflows/ci.yml");
    assert_eq!(body["workflows"][0]["jobs"], serde_json::json!(["build"]));
    assert_eq!(body["deleted"], serde_json::json!([]));
    assert_eq!(body["settings"], serde_json::Value::Null);

    // The bytes on the branch are the pre-switch revision's own, not a re-rendering of them.
    let written = d.github.written();
    assert_eq!(written.len(), 1);
    assert!(
        written[0].1 == ORIGINAL,
        "the committed text is the revision's bytes: {}",
        written[0].1
    );
    assert_eq!(
        d.github
            .refs()
            .iter()
            .map(|(name, _)| name.as_str())
            .collect::<Vec<_>>(),
        ["refs/heads/sentinel/migrate"],
        "a rollback never pushes to a default branch"
    );
    let pulls = d.github.pull_requests();
    assert_eq!(pulls.len(), 1);
    assert_eq!(pulls[0].base, "main");
    assert_eq!(pulls[0].branch, "sentinel/migrate");
    assert_eq!(audit(&d), ["bind", "migration_rollback_revert"]);
}

#[test]
fn a_second_rollback_updates_the_pull_request_it_found() {
    let d = deployment(MigrationPermissions::ALL, false);
    assert_eq!(revert(&d).0, 200);
    let (status, body) = revert(&d);
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["pull_request"]["state"], "updated");
    assert_eq!(d.github.pull_requests().len(), 1);
    assert_eq!(d.github.refs().len(), 1);
    assert_eq!(
        audit(&d),
        [
            "bind",
            "migration_rollback_revert",
            "migration_rollback_revert"
        ]
    );
}

#[test]
fn a_revision_that_is_already_migrated_is_refused_before_a_write() {
    let d = deployment(MigrationPermissions::ALL, false);
    let (status, body) = call(
        &d,
        &serde_json::json!({"action": "revert", "commit": SWITCHED}),
    );
    assert_eq!(status, 409, "{body}");
    assert_eq!(body["details"]["reason"], "not_pre_switch");
    assert!(d.github.written().is_empty() && d.github.refs().is_empty());
    assert_eq!(audit(&d), ["bind"]);
}

#[test]
fn shadow_mode_is_re_entered_with_that_revisions_bytes() {
    let d = deployment(MigrationPermissions::ALL, false);
    let (status, body) = shadow(&d);
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["action"], "shadow");
    assert_eq!(body["revision"], SHADOW);
    assert_eq!(
        body["workflows"][0]["jobs"],
        serde_json::json!(["shadow-build"]),
        "the copy the revision holds is what re-enters shadow mode"
    );
    assert_eq!(
        d.github.written(),
        [(".github/workflows/ci.yml".to_string(), COPIED.to_string())]
    );
    assert_eq!(audit(&d), ["bind", "migration_shadow_enter"]);

    // Re-enterable: the same state twice moves nothing further.
    let (status, body) = shadow(&d);
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["pull_request"]["state"], "updated");
    assert_eq!(d.github.pull_requests().len(), 1);
}

#[test]
fn a_revision_without_a_copy_does_not_enter_shadow_mode() {
    let d = deployment(MigrationPermissions::ALL, false);
    let (status, body) = call(
        &d,
        &serde_json::json!({"action": "shadow", "commit": BEFORE}),
    );
    assert_eq!(status, 409, "{body}");
    assert_eq!(body["details"]["reason"], "no_shadow");
    assert!(d.github.written().is_empty());
}

#[test]
fn the_native_settings_are_shown_then_put_back_exactly() {
    let d = deployment(MigrationPermissions::ALL, true);
    // Shown, not applied: the person keeps the write.
    let (status, body) = native(&d, false);
    assert_eq!(status, 200, "{body}");
    let settings = &body["settings"];
    assert_eq!(settings["branch"], "main");
    assert_eq!(settings["protected"], true);
    assert_eq!(settings["changed"], true);
    assert_eq!(settings["applied"], false);
    assert_eq!(settings["reason"], "not_requested");
    assert_eq!(
        settings["remove"],
        serde_json::json!([{"context": "sentinel / build", "app_id": 42}])
    );
    assert_eq!(
        settings["restore"],
        serde_json::json!([{"context": "build", "app_id": 15368}])
    );
    assert_eq!(
        d.github.protection("account", "widget", "main"),
        Some(switched_checks()),
        "showing a change writes nothing"
    );
    assert_eq!(
        audit(&d),
        [
            "bind",
            "migration_rollback_revert",
            "migration_rollback_settings"
        ]
    );

    // Applied, with the permission the installation grants: the branch states exactly the
    // pre-switch document afterwards.
    let (status, body) = native(&d, true);
    assert_eq!(status, 200, "{body}");
    let settings = &body["settings"];
    assert_eq!(settings["applied"], true);
    assert_eq!(settings["verified"], true);
    assert_eq!(settings["reason"], serde_json::Value::Null);
    assert_eq!(
        d.github.protection("account", "widget", "main"),
        Some(pre_switch_checks())
    );
    assert_eq!(
        audit(&d).last().map(String::as_str),
        Some("migration_rollback_settings_applied")
    );

    // Nothing left to change: shown as already back, and verified.
    let (status, body) = native(&d, true);
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["settings"]["reason"], "unchanged");
    assert_eq!(body["settings"]["changed"], false);
    assert_eq!(body["settings"]["verified"], true);
}

#[test]
fn without_administration_the_settings_are_shown_and_a_person_applies_them() {
    let d = deployment(MigrationPermissions::ALL, false);
    let (status, body) = native(&d, true);
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["settings"]["reason"], "not_permitted");
    assert_eq!(body["settings"]["protected"], serde_json::Value::Null);
    assert_eq!(body["settings"]["applied"], false);
    assert_eq!(body["settings"]["verified"], serde_json::Value::Null);
    assert_eq!(
        body["settings"]["target"],
        serde_json::json!({"strict": true,
            "checks": [{"context": "build", "app_id": 15368}]}),
        "the change a person applies is stated with it"
    );
    assert_eq!(
        d.github.protection("account", "widget", "main"),
        Some(switched_checks()),
        "a settings step without the permission writes nothing"
    );
    // The revert pull request is this path's primary write, and it happened.
    assert_eq!(d.github.pull_requests().len(), 1);
    assert_eq!(
        audit(&d),
        [
            "bind",
            "migration_rollback_revert",
            "migration_rollback_settings_failed"
        ]
    );
}

#[test]
fn a_tenant_that_stopped_the_migration_cannot_roll_back() {
    let d = deployment(MigrationPermissions::ALL, false);
    switch(&d, false);
    let (status, body) = revert(&d);
    assert_eq!(status, 409, "{body}");
    assert_eq!(body["details"]["reason"], "off");
    assert!(d.github.written().is_empty());
    assert_eq!(audit(&d).last().map(String::as_str), Some("migration_off"));
}

#[test]
fn a_withdrawn_permission_stops_the_rollback_before_github() {
    let d = deployment(MigrationPermissions::ALL, false);
    reported(&d, MigrationPermissions::grants(true, true, false));
    let (status, body) = revert(&d);
    assert_eq!(status, 409, "{body}");
    assert_eq!(body["details"]["missing"], serde_json::json!(["workflows"]));
    assert!(d.github.written().is_empty() && d.github.refs().is_empty());
    assert_eq!(
        audit(&d).last().map(String::as_str),
        Some("migration_permissions")
    );
}

#[test]
fn a_credential_without_tenant_admin_cannot_roll_back() {
    let d = deployment(MigrationPermissions::ALL, false);
    let grant = tokens::provision(
        &d.store,
        Grant {
            user: d.root,
            name: "reader",
            permissions: Permissions::READ,
            tenant: Some(d.tenant),
            repo: None,
            lifetime_ms: 60_000,
        },
        UnixMillis::now(),
    )
    .unwrap();
    let (status, _) = post(
        &d,
        &sentinel_auth::token::format(&grant.secret),
        &serde_json::json!({"action": "revert", "commit": BEFORE}),
    );
    assert_eq!(status, 403);
    assert!(d.github.written().is_empty());
}

#[test]
fn a_rollback_states_a_revision_and_a_bounded_document() {
    let d = deployment(MigrationPermissions::ALL, false);
    for commit in ["main", "0123456", ""] {
        let (status, body) = call(
            &d,
            &serde_json::json!({"action": "revert", "commit": commit}),
        );
        assert_eq!(status, 400, "{body}");
    }
    let (status, _) = call(
        &d,
        &serde_json::json!({"action": "restore", "commit": BEFORE}),
    );
    assert_eq!(
        status, 400,
        "an action outside revert and shadow states nothing"
    );
    let wide = serde_json::json!({
        "action": "revert",
        "commit": BEFORE,
        "settings": {"required_checks": {"strict": false, "checks": vec![
            serde_json::json!({"context": "build"}); sentinel_github::rollback::MAX_CHECKS + 1]}},
    });
    let (status, body) = call(&d, &wide);
    assert_eq!(status, 400, "{body}");
    let blank = serde_json::json!({
        "action": "revert",
        "commit": BEFORE,
        "settings": {"required_checks": {"checks": [{"context": ""}]}},
    });
    let (status, body) = call(&d, &blank);
    assert_eq!(status, 400, "{body}");
    assert!(
        d.github.written().is_empty(),
        "a refused rollback writes nothing"
    );
}
