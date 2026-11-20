//! A deployment for guided migration: one installation bound to one repository, a GitHub fake that
//! holds the workflows, the branch and its protection, and the App in force. Nothing here reaches
//! github.com.
#![allow(dead_code)]

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
    local_auth,
    logs::LogStore,
    objects::Objects,
    registration,
    sources::{self, Update},
    sources_forge,
    tokens::{self, Grant},
};

pub const INSTALLATION: u64 = 42;
pub const ACCOUNT: u64 = 73;
pub const FORGE_REPO: u64 = 91;
/// The forge's id for a repository a test binds second, one whose workflows nothing can move.
pub const FORGE_REPO_2: u64 = 92;
pub const REMOTE: &str = "https://github.com/account/widget.git";
/// The commit every fixture's workflows are read at: the pre-switch state, and the revision a
/// runner-mode rollback restores.
pub const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";
pub const SLUG: &str = "acme";
pub const REPO: &str = "widget";
pub const PASSWORD: &str = "correct horse battery staple";
/// The digest-pinned image the native path's plan needs: a job cannot leave GitHub's runners for a
/// platform no image was named for.
pub const IMAGE: &str = "ghcr.io/sentinel/ubuntu-2404:1.0@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

/// A throwaway RSA key, generated for this fixture alone: the App only signs a JWT the fake never
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

pub struct MigrationFixture {
    pub dir: tempfile::TempDir,
    pub store: Arc<Store>,
    pub controller: Controller,
    pub github: FakeGithub,
    pub base: String,
    pub token: String,
    pub root: UserId,
    pub tenant: TenantId,
    pub repo: RepoId,
    /// The installation both repositories are bound through.
    pub installation: sentinel_core::InstallationId,
    server: Option<sentinel_api::Server>,
}

impl Drop for MigrationFixture {
    fn drop(&mut self) {
        if let Some(server) = self.server.take() {
            server.shutdown();
        }
    }
}

impl MigrationFixture {
    /// A tenant `acme` with a repository `widget` bound through one installation, its workflows at
    /// `commit`, and its required checks `contexts` on `main`. `public_url` is the address a
    /// browser's sign-in origin is checked against; the API tests leave it out.
    pub fn start(
        workflow: &str,
        contexts: &[&str],
        public_url: Option<String>,
    ) -> MigrationFixture {
        let dir = tempfile::tempdir().unwrap();
        let store =
            Arc::new(Store::open(dir.path().join("metadata.sqlite"), Durability::Normal).unwrap());
        let logs = Arc::new(LogStore::open(dir.path().join("logs")).unwrap());
        let key_path = dir.path().join("master.key");
        sentinel_auth::sealed::Key::create(&key_path).unwrap();
        let key = sentinel_auth::sealed::Key::load(&key_path).unwrap();
        let root = local_auth::bootstrap(
            &store,
            "root",
            "Root",
            PASSWORD.as_bytes(),
            UnixMillis::now(),
        )
        .unwrap();
        let (tenant, repo) = (TenantId::new(), RepoId::new());
        let now = UnixMillis::now();
        let owner = Principal::new(root, Permissions::ALL, None, None);
        let bound = store
            .writer()
            .write(move |tx| {
                auth::create_namespace(
                    tx,
                    owner,
                    tenant,
                    Namespace::parse(SLUG).unwrap(),
                    NamespaceKind::Organization,
                    now,
                )?;
                auth::set_membership(tx, owner, tenant, root, Role::TenantAdmin)?;
                auth::create_repo(tx, owner, tenant, repo, REPO, now)?;
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
                )?;
                Ok(installation)
            })
            .unwrap();
        let granted = tokens::provision(
            &store,
            Grant {
                user: root,
                name: "migration",
                permissions: Permissions::ALL,
                tenant: Some(tenant),
                repo: None,
                lifetime_ms: 600_000,
            },
            UnixMillis::now(),
        )
        .unwrap();
        let objects = Arc::new(Objects::open(dir.path()).unwrap());
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
                    "administration": "write",
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
        github.set_workflows("account", REPO, COMMIT, &[("ci.yml", workflow)]);
        github.set_branch("account", REPO, "main", COMMIT);
        let checks: Vec<serde_json::Value> = contexts
            .iter()
            .map(|context| serde_json::json!({"context": context, "app_id": null}))
            .collect();
        github.set_protection(
            "account",
            REPO,
            "main",
            &serde_json::json!({"strict": true, "checks": checks}),
        );
        let app = sentinel_github::app::App::new(1, test_key())
            .unwrap()
            .with_endpoint(&github.base())
            .unwrap();
        let server = sentinel_api::Server::start_with(
            sentinel_api::Config {
                listen: "127.0.0.1:0".parse().unwrap(),
                store: Arc::clone(&store),
                logs: Arc::clone(&logs),
                objects: Arc::clone(&objects),
                controller: controller.handle(),
                secret_key: Some(Arc::new(
                    sentinel_auth::sealed::Key::load(&key_path).unwrap(),
                )),
                sessions: local_auth::Policy::default(),
                github_webhook_secret: None,
                intake: None,
                public_url,
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
        MigrationFixture {
            dir,
            store,
            controller,
            github,
            base,
            token: sentinel_auth::token::format(&granted.secret),
            root,
            tenant,
            repo,
            installation: bound,
            server: Some(server),
        }
    }

    /// A second repository of the same tenant, bound through the same installation and holding
    /// `workflow` at [`COMMIT`]: a repository whose workflows a migration has nothing to move in.
    pub fn add_repository(&self, name: &'static str, workflow: &str) -> RepoId {
        let repo = RepoId::new();
        let remote = format!("https://github.com/account/{name}.git");
        self.github.add_repository(
            FORGE_REPO_2,
            &serde_json::json!({
                "id": FORGE_REPO_2,
                "owner": {"id": ACCOUNT},
                "clone_url": remote,
                "archived": false,
            })
            .to_string(),
        );
        self.github
            .set_workflows("account", name, COMMIT, &[("ci.yml", workflow)]);
        let key = sentinel_auth::sealed::Key::load(&self.dir.path().join("master.key")).unwrap();
        let (tenant, root, installation) = (self.tenant, self.root, self.installation);
        let now = UnixMillis::now();
        let owner = Principal::new(root, Permissions::ALL, None, None);
        self.store
            .writer()
            .write(move |tx| {
                auth::create_repo(tx, owner, tenant, repo, name, now)?;
                let binding = Binding {
                    remote: remote.clone(),
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
                        forge: Some((installation, FORGE_REPO_2)),
                    },
                    &["https://github.com".into()],
                    &key,
                    now,
                )?;
                Ok(installation)
            })
            .unwrap();
        repo
    }

    /// What the fake holds for the branch now: its contexts and `strict`, or `None` when the branch
    /// has no protection rule at all.
    pub fn held(&self) -> Option<(Vec<String>, bool)> {
        let document = self.github.protection("account", REPO, "main")?;
        let strict = document["strict"].as_bool().unwrap_or(false);
        let contexts = document["checks"].as_array().map(|checks| {
            checks
                .iter()
                .filter_map(|check| check["context"].as_str().map(str::to_owned))
                .collect()
        });
        Some((contexts?, strict))
    }

    /// The repository's migration rows in its source audit trail, oldest first.
    pub fn audit(&self) -> Vec<String> {
        let repo = self.repo;
        self.store
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
}
