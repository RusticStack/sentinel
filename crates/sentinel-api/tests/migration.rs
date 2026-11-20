//! The tenant's guided-migration switch over the API: reading what the App's installations still
//! lack, starting a migration only when nothing is missing, and a withdrawal refusing the write
//! gate at once — in an organization's and a personal namespace's installation alike.

use std::sync::Arc;

use sentinel_core::{
    InstallationId, MigrationPermissions, RepoId, TenantId, UnixMillis, UserId,
    auth::{Namespace, Permissions, Principal},
};
use sentinel_link::{controller::Controller, identity::Identity};
use sentinel_protocol::source::{Binding, Credential};
use sentinel_store::{
    Durability, Store,
    auth::{self, Authority, NamespaceKind},
    local_auth, migration, registration,
    sources::{self, Update},
    sources_forge,
    tokens::{self, Grant},
};

struct Deployment {
    _dir: tempfile::TempDir,
    store: Arc<Store>,
    _controller: Controller,
    server: Option<sentinel_api::Server>,
    base: String,
    token: String,
    tenant: TenantId,
    root: UserId,
}

impl Drop for Deployment {
    fn drop(&mut self) {
        if let Some(server) = self.server.take() {
            server.shutdown();
        }
    }
}

/// A deployment with one installation bound to one repository, granting what `migration` says.
/// A personal namespace is a person's own, which GitHub binds a personal installation to.
fn deployment(migration: MigrationPermissions, personal_tenant: bool) -> Deployment {
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
    let kind = if personal_tenant {
        NamespaceKind::Personal(root)
    } else {
        NamespaceKind::Organization
    };
    store
        .writer()
        .write(move |tx| {
            auth::create_namespace(
                tx,
                owner,
                tenant,
                Namespace::parse("acme").unwrap(),
                kind,
                now,
            )?;
            auth::create_repo(tx, owner, tenant, repo, "widget", now)?;
            let installation = sources_forge::refresh(
                tx,
                sources_forge::Snapshot {
                    external_id: 42,
                    account_id: 73,
                    login: "account",
                    personal: personal_tenant,
                    suspended: false,
                    permissions_valid: true,
                    runner: sentinel_core::RunnerPermissions::ALL,
                    migration,
                    expected: 0,
                },
                now,
            )?;
            registration::bind_installation_trusted(tx, installation, tenant, now)?;
            let binding = Binding {
                remote: "https://github.com/account/widget.git".into(),
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
                    forge: Some((installation, 91)),
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
        sentinel_api::Options::default(),
    )
    .unwrap();
    let base = format!("http://{}", server.local_addr());
    Deployment {
        _dir: dir,
        store,
        _controller: controller,
        server: Some(server),
        base,
        token: sentinel_auth::token::format(&granted.secret),
        tenant,
        root,
    }
}

fn call(
    d: &Deployment,
    method: &str,
    path: &str,
    body: Option<&serde_json::Value>,
) -> (u16, serde_json::Value) {
    let url = format!("{}{path}", d.base);
    let agent = ureq::Agent::new_with_config(
        ureq::Agent::config_builder()
            .http_status_as_error(false)
            .build(),
    );
    let request = match method {
        "GET" => agent.get(&url).force_send_body(),
        "POST" => agent.post(&url),
        _ => unreachable!(),
    }
    .header("authorization", format!("Bearer {}", d.token));
    let response = match body {
        Some(body) => request
            .header("content-type", "application/json")
            .send(body.to_string().as_bytes())
            .unwrap(),
        None => request.send_empty().unwrap(),
    };
    let status = response.status().as_u16();
    let text = response.into_body().read_to_string().unwrap();
    let json = if text.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_str(&text).unwrap_or(serde_json::Value::String(text))
    };
    (status, json)
}

fn switch(d: &Deployment, enabled: bool) -> (u16, serde_json::Value) {
    call(
        d,
        "POST",
        "/api/v1/tenants/acme/migration",
        Some(&serde_json::json!({ "enabled": enabled })),
    )
}

/// GitHub reports the installation again: a `installation` delivery queues the refresh and the
/// lane applies the snapshot it read, which is the only way a permission changes here.
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
                    external_id: 42,
                    account_id: 73,
                    login: "account",
                    personal: false,
                    suspended: false,
                    permissions_valid: true,
                    runner: sentinel_core::RunnerPermissions::ALL,
                    migration,
                    expected: expected as u64,
                },
                UnixMillis::now(),
            )
        })
        .unwrap();
}

fn authorize(d: &Deployment) -> Vec<&'static str> {
    let (tenant, repo) = (d.tenant, repo_of(d));
    let outcome = d
        .store
        .writer()
        .write(move |tx| migration::authorize(tx, tenant, repo, None, UnixMillis::now()))
        .unwrap();
    match outcome {
        migration::Writes::Permitted => Vec::new(),
        migration::Writes::Off => vec!["off"],
        migration::Writes::Missing(missing) => missing,
        migration::Writes::Unbound => vec!["unbound"],
    }
}

fn repo_of(d: &Deployment) -> RepoId {
    let tenant = d.tenant;
    d.store
        .read(move |c| {
            Ok(RepoId::from_bytes(c.query_row(
                "SELECT id FROM repos WHERE tenant_id = ?1",
                [tenant.as_bytes()],
                |r| r.get(0),
            )?)
            .unwrap())
        })
        .unwrap()
}

fn audit_events(d: &Deployment) -> Vec<&'static str> {
    d.store
        .read(|c| local_auth::audit_page(c, None, 100))
        .unwrap()
        .into_iter()
        .map(|record| record.event.name())
        .collect()
}

#[test]
fn the_switch_reports_what_the_installations_still_lack() {
    let d = deployment(MigrationPermissions::grants(true, true, false), false);
    let (status, body) = call(&d, "GET", "/api/v1/tenants/acme/migration", None);
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["enabled"], false);
    assert_eq!(body["missing"], serde_json::json!(["workflows"]));
    assert_eq!(
        authorize(&d),
        ["off"],
        "nothing writes until the switch is on"
    );
}

#[test]
fn starting_a_migration_is_refused_naming_what_is_missing_and_accepted_once_granted() {
    let d = deployment(MigrationPermissions::NONE, false);
    let (status, body) = call(&d, "GET", "/api/v1/tenants/acme/migration", None);
    assert_eq!(status, 200);
    assert_eq!(
        body["missing"],
        serde_json::json!(["contents", "pull_requests", "workflows"])
    );

    let (status, body) = switch(&d, true);
    assert_eq!(status, 409, "{body}");
    assert_eq!(
        body["details"]["missing"],
        serde_json::json!(["contents", "pull_requests", "workflows"])
    );
    assert_eq!(body["code"], "conflict");
    assert_eq!(authorize(&d), ["off"]);

    reported(&d, MigrationPermissions::ALL);
    let (status, body) = switch(&d, true);
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["enabled"], true);
    assert_eq!(authorize(&d), Vec::<&str>::new());
    let (status, body) = call(&d, "GET", "/api/v1/tenants/acme/migration", None);
    assert_eq!(status, 200);
    assert_eq!(body["enabled"], true);
    assert_eq!(body["missing"], serde_json::json!([]));

    assert_eq!(
        switch(&d, true),
        (200, serde_json::json!({"enabled": true, "settings": false}))
    );
    assert_eq!(
        switch(&d, false),
        (
            200,
            serde_json::json!({"enabled": false, "settings": false})
        )
    );
    assert_eq!(
        authorize(&d),
        ["off"],
        "the switch stops every write at once"
    );
    assert_eq!(
        audit_events(&d)
            .iter()
            .filter(|event| **event == "migration-mode-changed")
            .count(),
        2,
        "one row per change, none for a repeat"
    );
}

#[test]
fn a_withdrawn_permission_shows_at_once_and_closes_the_write_gate() {
    let d = deployment(MigrationPermissions::ALL, false);
    assert_eq!(
        switch(&d, true),
        (200, serde_json::json!({"enabled": true, "settings": false}))
    );
    assert_eq!(authorize(&d), Vec::<&str>::new());

    reported(&d, MigrationPermissions::grants(true, false, true));
    let (status, body) = call(&d, "GET", "/api/v1/tenants/acme/migration", None);
    assert_eq!(status, 200);
    assert_eq!(body["enabled"], true);
    assert_eq!(body["missing"], serde_json::json!(["pull_requests"]));
    assert_eq!(authorize(&d), ["pull_requests"]);

    reported(&d, MigrationPermissions::ALL);
    assert_eq!(authorize(&d), Vec::<&str>::new());
}

#[test]
fn a_personal_namespace_migrates_with_the_same_three_permissions() {
    let d = deployment(MigrationPermissions::NONE, true);
    let (status, body) = call(&d, "GET", "/api/v1/tenants/acme/migration", None);
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        body["missing"],
        serde_json::json!(["contents", "pull_requests", "workflows"])
    );
    let (status, body) = switch(&d, true);
    assert_eq!(status, 409);
    assert_eq!(
        body["details"]["missing"],
        serde_json::json!(["contents", "pull_requests", "workflows"])
    );
}

#[test]
fn a_tenant_without_an_installation_cannot_start_a_migration() {
    let d = deployment(MigrationPermissions::ALL, false);
    let tenant = d.tenant;
    let id: [u8; 16] = d
        .store
        .read(move |c| {
            Ok(c.query_row(
                "SELECT id FROM installations WHERE tenant_id = ?1",
                [tenant.as_bytes()],
                |r| r.get(0),
            )?)
        })
        .unwrap();
    let id = InstallationId::from_bytes(id).unwrap();
    d.store
        .writer()
        .write(move |tx| sources_forge::remove(tx, id))
        .unwrap();
    let (status, body) = switch(&d, true);
    assert_eq!(status, 409, "{body}");
    assert_eq!(body["details"]["reason"], "not_configured");
}

#[test]
fn a_credential_without_tenant_administration_cannot_read_or_write_the_switch() {
    let d = deployment(MigrationPermissions::ALL, false);
    let read_only = tokens::provision(
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
    assert_eq!(
        switch(&d, true),
        (200, serde_json::json!({"enabled": true, "settings": false}))
    );
    let agent = ureq::Agent::new_with_config(
        ureq::Agent::config_builder()
            .http_status_as_error(false)
            .build(),
    );
    let read = agent
        .get(&format!("{}/api/v1/tenants/acme/migration", d.base))
        .header(
            "authorization",
            format!("Bearer {}", sentinel_auth::token::format(&read_only.secret)),
        )
        .call()
        .unwrap();
    assert_eq!(read.status().as_u16(), 403);
    let write = agent
        .post(&format!("{}/api/v1/tenants/acme/migration", d.base))
        .header(
            "authorization",
            format!("Bearer {}", sentinel_auth::token::format(&read_only.secret)),
        )
        .header("content-type", "application/json")
        .send(br#"{"enabled":false}"#)
        .unwrap();
    assert_eq!(write.status().as_u16(), 403);
}
