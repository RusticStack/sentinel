//! `sentinel service-account` end to end, portable: the real CLI binary
//! against an in-process controller with a static `sntl_` credential.
//! Creating, allowing and granting need a fresh step-up that a static
//! credential cannot give (forbidden, exit 3); list as metadata and revoke
//! work, and the issued token refreshes until revoked (the account and grant
//! are provisioned in the store with a stepped-up authority); usage and
//! authorization failures exit 2 and 3.

use std::{path::PathBuf, process::Command, sync::Arc};

use sentinel_core::{
    RepoId, TenantId, UnixMillis, UserId,
    auth::{Namespace, Permissions as P, Principal, Role, Scopes},
};
use sentinel_link::{controller::Controller, identity::Identity};
use sentinel_store::{
    Durability, Store,
    auth::{self, Authority, NamespaceKind, provisioning},
    local_auth,
    logs::LogStore,
    oauth::service,
    objects::Objects,
    tokens::{self, Grant},
};
use serde_json::Value;

struct Deployment {
    dir: tempfile::TempDir,
    _controller: Controller,
    server: Option<sentinel_api::Server>,
    base: String,
    store: Arc<Store>,
    admin: UserId,
    tenant: TenantId,
    repo: RepoId,
    /// Token files: root (super admin, administers `acme`) and dev (operator).
    root: PathBuf,
    dev: PathBuf,
}

/// A caller that has just proven presence, as a stepped-up browser session
/// would. The CLI's static credential can never do this, so the tests that
/// need a service principal or a grant provision it here, in the store.
fn stepped(user: UserId) -> Authority {
    Authority::Credential {
        principal: Principal::new(user, P::REPOSITORY.union(P::TENANT_ADMIN), None, None),
        stepped_up: true,
    }
}

impl Deployment {
    /// A service principal of `acme`, allowed read and run on `app`, made
    /// through the store with a stepped-up authority.
    fn service_account(&self, admin: UserId) -> UserId {
        let (tenant, repo, account) = (self.tenant, self.repo, UserId::new());
        self.store
            .writer()
            .write(move |tx| {
                let now = UnixMillis::now();
                auth::create_service_account(
                    tx,
                    stepped(admin),
                    tenant,
                    account,
                    "deployer",
                    Role::Operator,
                    None,
                    now,
                )?;
                service::allow_repo(
                    tx,
                    stepped(admin),
                    tenant,
                    account,
                    repo,
                    P::READ.union(P::RUN),
                    None,
                )
            })
            .unwrap();
        account
    }

    /// A grant of `account`, as the refresh token the person would hand over.
    fn grant(&self, admin: UserId, account: UserId) -> String {
        let (tenant, repo) = (self.tenant, self.repo);
        let (_, refresh, _) = self
            .store
            .writer()
            .write(move |tx| {
                service::issue_service_grant(
                    tx,
                    stepped(admin),
                    tenant,
                    account,
                    "ci",
                    Scopes::RUNS_READ.union(Scopes::LOGS_READ),
                    Some(repo),
                    7 * 24 * 60 * 60 * 1000,
                    None,
                    UnixMillis::now(),
                )
            })
            .unwrap();
        sentinel_auth::oauth::format(sentinel_auth::oauth::Kind::Refresh, &refresh)
    }
}

impl Drop for Deployment {
    fn drop(&mut self) {
        if let Some(server) = self.server.take() {
            server.shutdown();
        }
    }
}

fn deployment() -> Deployment {
    let dir = tempfile::tempdir().unwrap();
    let store =
        Arc::new(Store::open(dir.path().join("metadata.sqlite"), Durability::Normal).unwrap());
    let logs = Arc::new(LogStore::open(dir.path().join("logs")).unwrap());
    let objects = Arc::new(Objects::open(dir.path()).unwrap());
    let now = UnixMillis::now();
    let root =
        local_auth::bootstrap(&store, "root", "Root", b"correct horse battery", now).unwrap();
    let (dev, tenant, repo) = (UserId::new(), TenantId::new(), RepoId::new());
    store
        .writer()
        .write(move |tx| {
            let admin = Principal::new(root, P::ALL, None, None);
            provisioning::insert_human(tx, dev, "Dev", false, now)?;
            auth::create_namespace(
                tx,
                admin,
                tenant,
                Namespace::parse("acme").unwrap(),
                NamespaceKind::Organization,
                now,
            )?;
            auth::set_membership(tx, admin, tenant, root, Role::TenantAdmin)?;
            auth::set_membership(tx, admin, tenant, dev, Role::Operator)?;
            auth::create_repo(tx, admin, tenant, repo, "app", now)
        })
        .unwrap();
    let credential = |user, permissions, file: &str| {
        let issued = tokens::provision(
            &store,
            Grant::new(user, "cli", permissions),
            UnixMillis::now(),
        )
        .unwrap();
        let path = dir.path().join(file);
        std::fs::write(&path, sentinel_auth::token::format(&issued.secret)).unwrap();
        path
    };
    let root_file = credential(root, P::ALL, "root.token");
    let dev_file = credential(dev, P::REPOSITORY.union(P::TENANT_ADMIN), "dev.token");
    let controller = Controller::start(
        Arc::clone(&store),
        Arc::clone(&logs),
        Arc::clone(&objects),
        Identity::generate("controller").unwrap(),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    let server = sentinel_api::Server::start(sentinel_api::Config {
        listen: "127.0.0.1:0".parse().unwrap(),
        store: Arc::clone(&store),
        logs,
        objects,
        controller: controller.handle(),
        sessions: local_auth::Policy::default(),
        github_webhook_secret: None,
        intake: None,
        public_url: None,
        github_sign_in: None,
        trusted_proxies: sentinel_api::TrustedProxy::loopback(),
        secret_key: None,
    })
    .unwrap();
    Deployment {
        base: format!("http://{}", server.local_addr()),
        store: Arc::clone(&store),
        admin: root,
        tenant,
        repo,
        dir,
        _controller: controller,
        server: Some(server),
        root: root_file,
        dev: dev_file,
    }
}

struct Run {
    code: i32,
    stdout: String,
    stderr: String,
}

fn cli(d: &Deployment, token: &PathBuf, args: &[&str]) -> Run {
    let output = Command::new(env!("CARGO_BIN_EXE_sentinel"))
        .arg("service-account")
        .args(args)
        .arg("--server")
        .arg(&d.base)
        .arg("--token-file")
        .arg(token)
        .env_remove("SENTINEL_TOKEN")
        .env_remove("SENTINEL_SERVER")
        .env_remove("SENTINEL_PROFILE")
        .env("SENTINEL_CONFIG_DIR", d.dir.path().join("config"))
        .output()
        .unwrap();
    Run {
        code: output.status.code().unwrap_or(-1),
        stdout: String::from_utf8(output.stdout).unwrap(),
        stderr: String::from_utf8(output.stderr).unwrap(),
    }
}

fn refresh(d: &Deployment, token: &str) -> (u16, Value) {
    let agent = ureq::Agent::new_with_config(
        ureq::Agent::config_builder()
            .http_status_as_error(false)
            .build(),
    );
    let response = agent
        .post(&format!("{}/oauth/token", d.base))
        .header("content-type", "application/x-www-form-urlencoded")
        .send(
            format!("grant_type=refresh_token&client_id=sentinel-cli&refresh_token={token}")
                .as_bytes(),
        )
        .unwrap();
    let status = response.status().as_u16();
    let body = response.into_body().read_to_string().unwrap();
    (status, serde_json::from_str(&body).unwrap())
}

/// Minting who can authenticate needs fresh step-up, which a static
/// credential cannot give: create, allow and grant are forbidden with
/// `step_up` set, exit 3, and nothing is created.
#[test]
fn the_cli_cannot_mint_service_credentials_without_a_step_up() {
    let d = deployment();
    let created = cli(
        &d,
        &d.root,
        &["create", "--tenant", "acme", "--name", "deployer", "--json"],
    );
    assert_eq!(created.code, 3, "{}", created.stderr);
    assert!(created.stdout.is_empty());
    let document: Value = serde_json::from_str(created.stderr.trim()).unwrap();
    assert_eq!(document["code"], "forbidden");
    assert_eq!(document["details"]["step_up"], true);

    let account = d.service_account(d.admin).to_string();
    for args in [
        &[
            "allow", &account, "--tenant", "acme", "--repo", "app", "--access", "read",
        ][..],
        &[
            "grant",
            &account,
            "--tenant",
            "acme",
            "--name",
            "ci",
            "--scope",
            "runs:read",
        ],
    ] {
        let run = cli(&d, &d.root, args);
        assert_eq!(run.code, 3, "{args:?}: {}", run.stderr);
        assert!(run.stdout.is_empty(), "{}", run.stdout);
    }
    let listed = cli(&d, &d.root, &["grants", &account, "--tenant", "acme"]);
    assert_eq!(listed.code, 0, "{}", listed.stderr);
    assert!(listed.stdout.trim().is_empty(), "{}", listed.stdout);
}

#[test]
fn an_administrator_lists_and_revokes_an_agent_grant_from_the_cli() {
    let d = deployment();
    // Provisioned with a stepped-up authority: the CLI only reads and revokes.
    let account = d.service_account(d.admin);
    let token = d.grant(d.admin, account);
    assert!(
        token.starts_with("sntl_rt_") && token.len() == 72,
        "{token}"
    );
    let account = account.to_string();

    let listed = cli(
        &d,
        &d.root,
        &["grants", &account, "--tenant", "acme", "--output", "ndjson"],
    );
    assert_eq!(listed.code, 0, "{}", listed.stderr);
    assert_eq!(listed.stdout.lines().count(), 1);
    assert!(!listed.stdout.contains("sntl_"));
    let record: Value = serde_json::from_str(listed.stdout.trim()).unwrap();
    let grant = record["id"].as_str().unwrap().to_owned();
    assert!(grant.starts_with("grt_"));
    assert_eq!(record["scope"], "runs:read logs:read");
    assert_eq!(record["revoked"], false);

    // The agent's import works until the grant is revoked.
    let (status, tokens) = refresh(&d, &token);
    assert_eq!(status, 200, "{tokens}");
    let next = tokens["refresh_token"].as_str().unwrap().to_owned();
    let revoked = cli(&d, &d.root, &["revoke", &grant]);
    assert_eq!(revoked.code, 0, "{}", revoked.stderr);
    assert_eq!(
        revoked.stdout,
        format!(
            "revoked {grant}
"
        )
    );
    let (status, answer) = refresh(&d, &next);
    assert_eq!(status, 400);
    assert_eq!(answer["error"], "invalid_grant");
    let listed = cli(&d, &d.root, &["grants", &account, "--tenant", "acme"]);
    assert_eq!(listed.code, 0);
    assert!(listed.stdout.contains("revoked"), "{}", listed.stdout);
}

#[test]
fn usage_and_authorization_failures_have_their_exit_codes() {
    let d = deployment();
    // No tenant and no profile context: usage, before any request.
    let no_tenant = cli(&d, &d.root, &["create", "--name", "x"]);
    assert_eq!(no_tenant.code, 2, "{}", no_tenant.stderr);
    assert!(no_tenant.stderr.contains("--tenant"));
    for args in [
        &[
            "create", "--tenant", "acme", "--name", "x", "--role", "admin",
        ][..],
        &[
            "grant",
            "usr_x",
            "--tenant",
            "acme",
            "--name",
            "n",
            "--scope",
            "runs:read",
            "--expires-in",
            "30",
        ],
        &["allow", "usr_x", "--tenant", "acme", "--repo", "../x"],
        &[
            "allow", "usr_x", "--tenant", "acme", "--repo", "app", "--access", "write",
        ],
        &["revoke", "grt/../x"],
    ] {
        let run = cli(&d, &d.root, args);
        assert_eq!(run.code, 2, "{args:?}: {}", run.stderr);
    }
    // An operator is not an administrator: forbidden is exit 3.
    let refused = cli(&d, &d.dev, &["create", "--tenant", "acme", "--name", "x"]);
    assert_eq!(refused.code, 3, "{}", refused.stderr);
    // The step-up check comes before any validation: an administrative scope
    // is refused for want of it, in JSON mode as one error document on
    // stderr and nothing on stdout (the scope rule itself is a store test).
    let account = d.service_account(d.admin).to_string();
    let admin = cli(
        &d,
        &d.root,
        &[
            "grant",
            &account,
            "--tenant",
            "acme",
            "--name",
            "n",
            "--scope",
            "tenant:admin",
            "--json",
        ],
    );
    assert_eq!(admin.code, 3, "{}", admin.stderr);
    assert!(admin.stdout.is_empty());
    let document: Value = serde_json::from_str(admin.stderr.trim()).unwrap();
    assert_eq!(document["code"], "forbidden");
    // Revoking a well-formed but unknown grant is not found (exit 4, P09-18).
    let missing = sentinel_core::GrantId::new().to_string();
    let unknown = cli(&d, &d.root, &["revoke", &missing]);
    assert_eq!(unknown.code, 4, "{}", unknown.stderr);
}
