//! The route that applies a guided migration: the `sentinel/migrate` branch from the commit the
//! analysis is pinned to, the diff as one commit, and the pull request the App's migration
//! permissions open — then a re-run that updates both, a close, and the refusals.

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
const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";

const WORKFLOW: &str = "name: ci
on: [push, pull_request]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: cargo test
  mac:
    runs-on: macos-14
    steps:
      - run: cargo test
";

const PATH: &str = "/api/v1/tenants/acme/repos/widget/migration/pull-request";

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

/// A deployment with one installation bound to one repository, granting what `migration` says, and
/// a GitHub fake that holds the repository's workflow at the analysed commit.
fn deployment(migration: MigrationPermissions) -> Deployment {
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
    github.add_installation(
        INSTALLATION,
        &serde_json::json!({
            "id": INSTALLATION,
            "app_id": 1,
            "account": {"id": ACCOUNT, "login": "account", "type": "Organization"},
            "suspended_at": null,
            "permissions": {
                "checks": "write",
                "contents": "write",
                "pull_requests": "write",
                "workflows": "write",
            },
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
    github.set_workflows("account", "widget", COMMIT, &[("ci.yml", WORKFLOW)]);
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
    let agent = ureq::Agent::new_with_config(
        ureq::Agent::config_builder()
            .http_status_as_error(false)
            .build(),
    );
    let response = agent
        .post(&format!("{}{PATH}", d.base))
        .header("authorization", format!("Bearer {}", d.token))
        .header("content-type", "application/json")
        .send(body.to_string().as_bytes())
        .unwrap();
    let status = response.status().as_u16();
    let text = response.into_body().read_to_string().unwrap();
    let json = serde_json::from_str(&text).unwrap_or(serde_json::Value::String(text));
    (status, json)
}

fn open(d: &Deployment) -> (u16, serde_json::Value) {
    call(d, &serde_json::json!({"action": "open", "commit": COMMIT}))
}

fn close(d: &Deployment) -> (u16, serde_json::Value) {
    call(d, &serde_json::json!({"action": "close"}))
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
fn the_migration_commits_the_diff_and_opens_one_pull_request() {
    let d = deployment(MigrationPermissions::ALL);
    let (status, body) = open(&d);
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["schema"], "sentinel.migration-pull-request/1");
    assert_eq!(body["branch"], "sentinel/migrate");
    assert_eq!(body["revision"], COMMIT);
    assert_eq!(body["pull_request"]["number"], 1);
    assert_eq!(body["pull_request"]["state"], "opened");
    assert_eq!(body["pull_request"]["base"], "main");
    assert_eq!(body["changed"][0]["path"], ".github/workflows/ci.yml");
    assert_eq!(body["changed"][0]["jobs"], serde_json::json!(["build"]));
    // The macOS job keeps running on GitHub's runners, with its reason.
    assert_eq!(body["kept"][0]["job"], "mac");
    assert_eq!(body["kept"][0]["reasons"], serde_json::json!(["macos"]));

    // One file committed, and the label line is the only line that differs.
    let written = d.github.written();
    assert_eq!(written.len(), 1);
    assert_eq!(written[0].0, ".github/workflows/ci.yml");
    let expected = WORKFLOW.replace(
        "runs-on: ubuntu-latest",
        "runs-on: sentinel-4vcpu-ubuntu-2404",
    );
    assert_eq!(written[0].1, expected);

    // The only ref the write moved is its own branch, and the pull request proposes into `main`.
    let refs = d.github.refs();
    assert_eq!(
        refs.iter()
            .map(|(name, _)| name.as_str())
            .collect::<Vec<_>>(),
        ["refs/heads/sentinel/migrate"],
        "a migration never pushes to the default branch"
    );
    let pulls = d.github.pull_requests();
    assert_eq!(pulls.len(), 1);
    assert_eq!(pulls[0].base, "main");
    assert_eq!(pulls[0].branch, "sentinel/migrate");
    assert!(pulls[0].body.contains("| `build` |"));
    assert_eq!(audit(&d), ["bind", "migration_pull_request_open"]);
}

#[test]
fn a_second_run_updates_the_branch_and_pull_request_instead_of_a_second_one() {
    let d = deployment(MigrationPermissions::ALL);
    assert_eq!(open(&d).0, 200);
    let (status, body) = open(&d);
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["pull_request"]["number"], 1);
    assert_eq!(body["pull_request"]["state"], "updated");
    assert_eq!(d.github.pull_requests().len(), 1);
    assert_eq!(d.github.refs().len(), 1);
    assert_eq!(
        audit(&d),
        [
            "bind",
            "migration_pull_request_open",
            "migration_pull_request_update"
        ]
    );
}

#[test]
fn closing_the_pull_request_leaves_the_branch_where_a_rerun_can_find_it() {
    let d = deployment(MigrationPermissions::ALL);
    assert_eq!(open(&d).0, 200);
    let (status, body) = close(&d);
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["pull_request"]["number"], 1);
    assert_eq!(body["pull_request"]["state"], "closed");
    assert_eq!(body["revision"], serde_json::Value::Null);
    assert_eq!(d.github.pull_requests()[0].state, "closed");
    assert_eq!(
        d.github.refs().len(),
        1,
        "the branch stays for the next run"
    );
    // Nothing is open any more: a second close states that and records nothing.
    let (status, body) = close(&d);
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["pull_request"], serde_json::Value::Null);
    assert_eq!(
        audit(&d),
        [
            "bind",
            "migration_pull_request_open",
            "migration_pull_request_close"
        ]
    );
}

#[test]
fn without_the_migration_permissions_nothing_reaches_github() {
    let d = deployment(MigrationPermissions::ALL);
    reported(&d, MigrationPermissions::grants(true, true, false));
    let (status, body) = open(&d);
    assert_eq!(status, 409, "{body}");
    assert_eq!(body["details"]["missing"], serde_json::json!(["workflows"]));
    assert!(
        d.github.refs().is_empty() && d.github.written().is_empty(),
        "the gate refuses before any request is made"
    );
    assert_eq!(
        audit(&d).last().map(String::as_str),
        Some("migration_permissions")
    );
}

#[test]
fn a_tenant_that_never_started_a_migration_is_refused_before_github() {
    let d = deployment(MigrationPermissions::ALL);
    switch(&d, false);
    let (status, body) = open(&d);
    assert_eq!(status, 409, "{body}");
    assert_eq!(body["details"]["reason"], "off");
    assert!(d.github.written().is_empty());
    assert_eq!(audit(&d).last().map(String::as_str), Some("migration_off"));
}

#[test]
fn a_protected_branch_is_reported_and_never_forced() {
    let d = deployment(MigrationPermissions::ALL);
    let (status, body) = open(&d);
    assert_eq!(status, 200, "{body}");
    let head = d.github.refs()[0].1.clone();
    // A later commit whose labels resolve to another class, so the branch has to move.
    let moved = "b".repeat(40);
    d.github.set_workflows(
        "account",
        "widget",
        &moved,
        &[(
            "ci.yml",
            WORKFLOW.replace("ubuntu-latest", "windows-latest").as_str(),
        )],
    );
    d.github.protect("sentinel/migrate");
    let (status, body) = call(&d, &serde_json::json!({"action": "open", "commit": moved}));
    assert_eq!(status, 409, "{body}");
    assert_eq!(body["details"]["reason"], "branch_protected");
    assert_eq!(
        d.github.refs()[0].1,
        head,
        "the ref the protection covers is where it was"
    );
    assert_eq!(
        audit(&d).last().map(String::as_str),
        Some("migration_pull_request_refused")
    );
}

#[test]
fn only_a_full_commit_id_starts_one() {
    let d = deployment(MigrationPermissions::ALL);
    for commit in ["main", "0123456", ""] {
        let (status, body) = call(&d, &serde_json::json!({"action": "open", "commit": commit}));
        assert_eq!(status, 400, "{body}");
    }
    let (status, _) = call(&d, &serde_json::json!({"action": "open"}));
    assert_eq!(status, 400);
    let (status, _) = call(
        &d,
        &serde_json::json!({"action": "close", "commit": COMMIT}),
    );
    assert_eq!(status, 400);
    assert!(d.github.written().is_empty());
}

#[test]
fn a_commit_with_nothing_to_change_opens_no_pull_request() {
    let d = deployment(MigrationPermissions::ALL);
    d.github.set_workflows(
        "account",
        "widget",
        &"b".repeat(40),
        &[(
            "ci.yml",
            "name: ci\non: [push]\njobs:\n  build:\n    runs-on: sentinel-4vcpu-ubuntu-2404\n    steps:\n      - run: cargo test\n",
        )],
    );
    let (status, body) = call(
        &d,
        &serde_json::json!({"action": "open", "commit": "b".repeat(40)}),
    );
    assert_eq!(status, 409, "{body}");
    assert_eq!(body["details"]["reason"], "no_change");
    assert!(d.github.written().is_empty() && d.github.pull_requests().is_empty());
}

#[test]
fn a_credential_without_tenant_admin_never_starts_one() {
    let d = deployment(MigrationPermissions::ALL);
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
    let agent = ureq::Agent::new_with_config(
        ureq::Agent::config_builder()
            .http_status_as_error(false)
            .build(),
    );
    let response = agent
        .post(&format!("{}{PATH}", d.base))
        .header(
            "authorization",
            format!("Bearer {}", sentinel_auth::token::format(&grant.secret)),
        )
        .header("content-type", "application/json")
        .send(
            serde_json::json!({"action": "open", "commit": COMMIT})
                .to_string()
                .as_bytes(),
        )
        .unwrap();
    assert_eq!(response.status().as_u16(), 403);
    assert!(d.github.written().is_empty());
}
