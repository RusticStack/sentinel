//! The switch: the runner-mode pull requests that add the shadow copies and then drop them, and the
//! native path's required-check change — previewed, applied only with the tenant's opt-in and the
//! App's grant, verified, and proved by comparing the settings read after it with the preview.
//! Nothing here reaches github.com: the fake holds the workflows, the protection and the rulesets.

use std::sync::Arc;

use sentinel_core::{
    MigrationPermissions, RepoId, RunnerPermissions, TenantId, UnixMillis,
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
const IMAGE: &str = "ghcr.io/sentinel/ubuntu-2404:1.0@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

const PATH: &str = "/api/v1/tenants/acme/repos/widget/migration/switch";
const SWITCH_PATH: &str = "/api/v1/tenants/acme/migration";

/// The workflow as the shadow phase leaves it: `build` was migrated, and its copy runs the same
/// steps on a Sentinel label under `name: sentinel / build`.
const SHADOWED: &str = "name: ci
on: [push, pull_request]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: cargo test
  sentinel-build:
    name: 'sentinel / build'
    runs-on: sentinel-4vcpu-ubuntu-2404
    steps:
      - run: cargo test
  mac:
    runs-on: macos-14
    steps:
      - run: cargo test
";

/// The same workflow before the shadow phase: nothing to copy and nothing to drop.
const PLAIN: &str = "name: ci
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

/// A workflow with nothing Sentinel can serve: one macOS job, which stays on GitHub's runner.
const KEPT: &str = "name: ci
on: [push, pull_request]
jobs:
  mac:
    runs-on: macos-14
    steps:
      - run: cargo test
";

/// A workflow the native path serves whole: one Linux job, one step, a trigger it can carry.
const NATIVE: &str = "name: ci
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: cargo test
";

struct Deployment {
    _dir: tempfile::TempDir,
    store: Arc<Store>,
    _controller: Controller,
    server: Option<sentinel_api::Server>,
    github: FakeGithub,
    base: String,
    token: String,
    repo: RepoId,
}

impl Drop for Deployment {
    fn drop(&mut self) {
        if let Some(server) = self.server.take() {
            server.shutdown();
        }
    }
}

impl Deployment {
    /// One branch's protection as a test sets it: `strict` and the contexts, each bound to no App.
    fn protect(&self, contexts: &[&str], strict: bool) {
        let checks: Vec<serde_json::Value> = contexts
            .iter()
            .map(|context| serde_json::json!({"context": context, "app_id": null}))
            .collect();
        self.github.set_protection(
            "account",
            "widget",
            "main",
            &serde_json::json!({"strict": strict, "checks": checks}),
        );
    }

    /// What the fake holds for the branch now: its contexts and `strict`, or `None` when the
    /// branch has no protection rule at all.
    fn held(&self) -> Option<(Vec<String>, bool)> {
        let document = self.github.protection("account", "widget", "main")?;
        let strict = document["strict"].as_bool().unwrap_or(false);
        let contexts = document["checks"].as_array().map(|checks| {
            checks
                .iter()
                .filter_map(|check| check["context"].as_str().map(str::to_owned))
                .collect()
        });
        Some((contexts?, strict))
    }

    fn strings(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
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

/// A deployment with one installation bound to one repository and a GitHub fake holding the
/// repository, its workflow at the analysed commit, and whatever protection the test sets.
fn deployment(workflow: &'static str) -> Deployment {
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
                    migration: MigrationPermissions::ALL,
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
    installation_json(&github, true);
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
    github.set_workflows("account", "widget", COMMIT, &[("ci.yml", workflow)]);
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
        repo,
    };
    switch(&deployment, true, None);
    deployment
}

/// What GitHub reports the installation grants. The base set includes repository administration,
/// which runner mode registers a personal namespace's runner through and the settings write needs.
fn installation_json(github: &FakeGithub, administration: bool) {
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
}

fn agent() -> ureq::Agent {
    ureq::Agent::new_with_config(
        ureq::Agent::config_builder()
            .http_status_as_error(false)
            .build(),
    )
}

fn call(d: &Deployment, body: &serde_json::Value) -> (u16, serde_json::Value) {
    let response = agent()
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

fn switch(d: &Deployment, enabled: bool, settings: Option<bool>) {
    let mut body = serde_json::json!({"enabled": enabled});
    if let Some(settings) = settings {
        body["settings"] = serde_json::json!(settings);
    }
    let response = agent()
        .post(&format!("{}{SWITCH_PATH}", d.base))
        .header("authorization", format!("Bearer {}", d.token))
        .header("content-type", "application/json")
        .send(body.to_string().as_bytes())
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
}

fn tenant_view(d: &Deployment) -> serde_json::Value {
    let response = agent()
        .get(&format!("{}{SWITCH_PATH}", d.base))
        .header("authorization", format!("Bearer {}", d.token))
        .call()
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    let text = response.into_body().read_to_string().unwrap();
    serde_json::from_str(&text).unwrap()
}

fn audit(d: &Deployment) -> Vec<String> {
    let repo = d.repo;
    d.store
        .read(move |c| {
            let mut stmt = c.prepare(
                "SELECT action FROM source_audit WHERE repo_id = ?1 AND action LIKE 'migration%'
                 ORDER BY at_ms, seq",
            )?;
            let rows = stmt
                .query_map([repo.as_bytes()], |r| r.get::<_, String>(0))?
                .collect::<Result<Vec<_>, _>>()?;
            Ok(rows)
        })
        .unwrap()
}

/// The workflow a commit wrote, from the files the fake recorded.
fn written(d: &Deployment) -> String {
    d.github
        .written()
        .into_iter()
        .filter(|(path, _)| path == ".github/workflows/ci.yml")
        .map(|(_, text)| text)
        .next_back()
        .expect("a commit wrote the workflow")
}

#[test]
fn the_switch_drops_the_copies_and_leaves_the_required_checks_alone() {
    let d = deployment(SHADOWED);
    d.protect(&["build", "mac"], true);

    let (status, body) = call(
        &d,
        &serde_json::json!({"action": "switch", "commit": COMMIT}),
    );
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["schema"], "sentinel.migration-switch/1");
    assert_eq!(body["mode"], "runner");
    assert_eq!(body["settings"]["verdict"], "equal");
    assert_eq!(body["settings"]["branch"], "main");
    assert_eq!(
        body["settings"]["before"]["required"],
        serde_json::json!(["build", "mac"])
    );
    assert_eq!(
        body["settings"]["after"]["required"],
        serde_json::json!(["build", "mac"]),
        "the set read after the switch is the set read before it, compared rather than asserted"
    );
    assert_eq!(body["dropped"][0]["job"], "sentinel-build");
    assert_eq!(body["dropped"][0]["original"], "build");
    assert_eq!(body["dropped"][0]["name"], "sentinel / build");
    assert_eq!(body["pull_request"]["state"], "opened");
    assert_eq!(body["pull_request"]["base"], "main");

    // The commit carries the copy dropped and the original's label moved, and the original's name
    // untouched: the check a required check names does not move.
    let text = written(&d);
    assert!(!text.contains("sentinel-build"), "{text}");
    assert!(!text.contains("sentinel / build"), "{text}");
    assert!(
        text.contains("  build:\n    runs-on: sentinel-4vcpu-ubuntu-2404\n"),
        "{text}"
    );
    assert!(text.contains("  mac:\n    runs-on: macos-14\n"), "{text}");
    // The protection the fake holds is the protection it held.
    assert_eq!(
        d.held(),
        Some((Deployment::strings(&["build", "mac"]), true))
    );
    assert_eq!(
        audit(&d),
        ["migration_switch", "migration_pull_request_open"]
    );
}

#[test]
fn a_required_check_naming_a_copy_refuses_the_switch_before_any_write() {
    let d = deployment(SHADOWED);
    d.protect(&["build", "sentinel / build"], true);
    let (status, body) = call(
        &d,
        &serde_json::json!({"action": "switch", "commit": COMMIT}),
    );
    assert_eq!(status, 409, "{body}");
    assert_eq!(body["details"]["reason"], "required_check");
    assert_eq!(
        body["details"]["checks"],
        serde_json::json!(["sentinel / build"])
    );
    // Nothing written: no branch, no pull request, and the refusal in the audit trail.
    assert!(d.github.refs().is_empty(), "{:?}", d.github.refs());
    assert!(d.github.pull_requests().is_empty());
    assert_eq!(audit(&d), ["migration_settings_refused"]);
}

#[test]
fn the_shadow_step_opens_the_pull_request_that_adds_the_copies() {
    let d = deployment(PLAIN);
    let (status, body) = call(
        &d,
        &serde_json::json!({"action": "shadow", "commit": COMMIT}),
    );
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["shadow"][0]["job"], "sentinel-build");
    assert_eq!(body["shadow"][0]["name"], "sentinel / build");
    assert_eq!(body["shadow"][0]["class"], "sentinel-4vcpu-ubuntu-2404");
    assert_eq!(body["settings"]["verdict"], "unread");
    assert_eq!(body["pull_request"]["state"], "opened");

    let text = written(&d);
    assert!(
        text.contains("  sentinel-build:\n    name: 'sentinel / build'\n"),
        "{text}"
    );
    assert!(
        text.contains("  build:\n    runs-on: ubuntu-latest\n"),
        "{text}"
    );

    // The same commit again: the plan is computed from the commit GitHub holds, so it is the same
    // plan and the same pull request, updated rather than a second one or a second commit.
    let head = body["pull_request"]["head"].as_str().unwrap().to_owned();
    let (status, body) = call(
        &d,
        &serde_json::json!({"action": "shadow", "commit": COMMIT}),
    );
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["pull_request"]["state"], "updated");
    assert_eq!(body["pull_request"]["head"], head.as_str());
    assert_eq!(d.github.pull_requests().len(), 1);
}

#[test]
fn the_native_preview_states_the_change_and_refuses_to_claim_it_may_apply() {
    let d = deployment(NATIVE);
    d.protect(&["build"], true);
    let (status, body) = call(
        &d,
        &serde_json::json!({
            "action": "preview",
            "commit": COMMIT,
            "native": {"images": {"linux": IMAGE}},
        }),
    );
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["mode"], "native");
    assert_eq!(body["settings"]["verdict"], "unread");
    assert_eq!(
        body["settings"]["change"]["replaced"],
        serde_json::json!([{"context": "build", "check": "sentinel / build"}])
    );
    assert_eq!(
        body["settings"]["change"]["added"],
        serde_json::json!(["sentinel / build"])
    );
    assert_eq!(
        body["settings"]["change"]["removed"],
        serde_json::json!(["build"])
    );
    assert_eq!(
        body["settings"]["expected"]["required"],
        serde_json::json!(["sentinel / build"])
    );
    assert_eq!(body["permitted"]["settings"], false);
    assert_eq!(body["permitted"]["reason"], "settings");
    assert_eq!(body["disabled"], serde_json::json!(["build"]));
    // A preview writes nothing at all.
    assert!(d.github.refs().is_empty());
    assert_eq!(d.held(), Some((Deployment::strings(&["build"]), true)));
}

#[test]
fn the_native_apply_moves_the_required_checks_then_disables_the_replaced_jobs() {
    let d = deployment(NATIVE);
    d.protect(&["build"], true);
    switch(&d, true, Some(true));
    assert!(tenant_view(&d)["settings"].as_bool().unwrap());

    let (status, body) = call(
        &d,
        &serde_json::json!({
            "action": "apply",
            "commit": COMMIT,
            "native": {"images": {"linux": IMAGE}},
        }),
    );
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["settings"]["verdict"], "equal");
    assert_eq!(
        body["settings"]["after"]["required"],
        serde_json::json!(["sentinel / build"]),
        "the set read back is the preview"
    );
    assert_eq!(
        d.held(),
        Some((Deployment::strings(&["sentinel / build"]), true)),
        "the discipline this test proves is the settings after the switch"
    );
    // The pull request that carries the disabled job comes after the settings change.
    assert_eq!(body["pull_request"]["state"], "opened");
    let text = written(&d);
    assert!(text.contains("  build:\n    if: ${{ false }}"), "{text}");
    assert_eq!(
        audit(&d),
        ["migration_settings_applied", "migration_pull_request_open"]
    );
}

#[test]
fn an_apply_without_the_settings_opt_in_is_refused_and_writes_nothing() {
    let d = deployment(NATIVE);
    d.protect(&["build"], true);
    let (status, body) = call(
        &d,
        &serde_json::json!({
            "action": "apply",
            "commit": COMMIT,
            "native": {"images": {"linux": IMAGE}},
        }),
    );
    assert_eq!(status, 409, "{body}");
    assert_eq!(body["details"]["reason"], "settings");
    assert_eq!(d.held(), Some((Deployment::strings(&["build"]), true)));
    assert!(d.github.refs().is_empty());
    // The gate's own refusal, before the route reaches its own: the opt-in is what it reads.
    assert_eq!(audit(&d), ["migration_settings_off"]);
}

#[test]
fn an_apply_without_the_administration_grant_is_refused_naming_it() {
    let d = deployment(NATIVE);
    d.protect(&["build"], true);
    installation_json(&d.github, false);
    switch(&d, true, Some(true));
    let (status, body) = call(
        &d,
        &serde_json::json!({
            "action": "apply",
            "commit": COMMIT,
            "native": {"images": {"linux": IMAGE}},
        }),
    );
    assert_eq!(status, 409, "{body}");
    assert_eq!(body["details"]["reason"], "administration");
    assert_eq!(d.held(), Some((Deployment::strings(&["build"]), true)));
}

#[test]
fn a_removal_a_ruleset_states_refuses_the_apply_and_the_preview_states_it() {
    let d = deployment(NATIVE);
    d.protect(&[], true);
    d.github.set_ruleset(7, "required", &["build"]);
    switch(&d, true, Some(true));

    let (status, body) = call(
        &d,
        &serde_json::json!({
            "action": "preview",
            "commit": COMMIT,
            "native": {"images": {"linux": IMAGE}},
        }),
    );
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        body["settings"]["from_rulesets"],
        serde_json::json!(["build"])
    );
    assert_eq!(
        body["settings"]["rulesets"],
        serde_json::json!(["required"])
    );
    assert_eq!(body["permitted"]["reason"], "ruleset");

    let (status, body) = call(
        &d,
        &serde_json::json!({
            "action": "apply",
            "commit": COMMIT,
            "native": {"images": {"linux": IMAGE}},
        }),
    );
    assert_eq!(status, 409, "{body}");
    assert_eq!(body["details"]["reason"], "ruleset");
    assert_eq!(d.held(), Some((Vec::new(), true)));
}

#[test]
fn verify_compares_the_settings_a_person_applied_with_the_preview() {
    let d = deployment(NATIVE);
    d.protect(&["build"], true);
    // The person applied the change themselves: the branch protection now requires Sentinel's
    // per-job check.
    d.protect(&["sentinel / build"], true);
    let (status, body) = call(
        &d,
        &serde_json::json!({
            "action": "verify",
            "commit": COMMIT,
            "native": {"images": {"linux": IMAGE}},
        }),
    );
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["settings"]["verdict"], "equal");
    assert_eq!(audit(&d), ["migration_settings_verified"]);

    // A required context the preview does not expect is a difference, reported as one.
    d.protect(&["build", "lint"], true);
    let (status, body) = call(
        &d,
        &serde_json::json!({
            "action": "verify",
            "commit": COMMIT,
            "native": {"images": {"linux": IMAGE}},
        }),
    );
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["settings"]["verdict"], "moved");
    assert_eq!(
        body["settings"]["after"]["required"],
        serde_json::json!(["build", "lint"])
    );
    assert_eq!(
        audit(&d),
        ["migration_settings_verified", "migration_settings_moved"]
    );
}

#[test]
fn a_switch_with_nothing_to_do_and_a_mismatched_path_are_refused() {
    let d = deployment(KEPT);
    let (status, body) = call(
        &d,
        &serde_json::json!({"action": "switch", "commit": COMMIT}),
    );
    assert_eq!(status, 409, "{body}");
    assert_eq!(body["details"]["reason"], "no_change");

    // The runner-mode steps take no native plan, and the native steps need one.
    let (status, body) = call(
        &d,
        &serde_json::json!({
            "action": "switch",
            "commit": COMMIT,
            "native": {"images": {"linux": IMAGE}},
        }),
    );
    assert_eq!(status, 400, "{body}");
    let (status, body) = call(
        &d,
        &serde_json::json!({"action": "preview", "commit": COMMIT}),
    );
    assert_eq!(status, 400, "{body}");
    // A commit that is not a full id never reaches GitHub.
    let (status, _) = call(
        &d,
        &serde_json::json!({"action": "switch", "commit": "main"}),
    );
    assert_eq!(status, 400);
}
