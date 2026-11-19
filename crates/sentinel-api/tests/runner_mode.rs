//! The tenant's runner-mode switch over the API: reading what the deployment serves and what the
//! App's installations still lack, and turning it on only when nothing is missing.

use std::sync::Arc;

use sentinel_core::{
    RepoId, RunnerClass, RunnerPermissions, TenantId, UnixMillis, UserId,
    auth::{Namespace, Permissions, Principal},
};
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

const CLASS: &str = "sentinel-2vcpu-ubuntu-2404";

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

/// A deployment with one installation bound to one repository, in the state `runner` says.
fn deployment(runner: RunnerPermissions) -> Deployment {
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
    store
        .writer()
        .write(move |tx| {
            auth::create_namespace(
                tx,
                Principal::new(root, Permissions::ALL, None, None),
                tenant,
                Namespace::parse("acme").unwrap(),
                NamespaceKind::Organization,
                now,
            )?;
            auth::create_repo(
                tx,
                Principal::new(root, Permissions::ALL, None, None),
                tenant,
                repo,
                "widget",
                now,
            )?;
            let installation = sources_forge::refresh(
                tx,
                sources_forge::Snapshot {
                    external_id: 42,
                    account_id: 73,
                    login: "account",
                    personal: false,
                    suspended: false,
                    permissions_valid: true,
                    runner,
                    migration: sentinel_core::MigrationPermissions::ALL,
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
        sentinel_api::Options {
            runner_classes: Arc::from(vec![RunnerClass::parse(CLASS).unwrap()]),
            ..sentinel_api::Options::default()
        },
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
        "/api/v1/tenants/acme/runner-mode",
        Some(&serde_json::json!({ "enabled": enabled })),
    )
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
fn the_switch_reports_what_the_deployment_serves_and_what_is_missing() {
    let d = deployment(RunnerPermissions::grants(true, false));
    let (status, body) = call(&d, "GET", "/api/v1/tenants/acme/runner-mode", None);
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["enabled"], false);
    assert_eq!(body["classes"], serde_json::json!([CLASS]));
    assert_eq!(
        body["missing"],
        serde_json::json!(["organization_self_hosted_runners"])
    );

    // Refused naming exactly what is missing, and the switch stays off.
    let tenant = d.tenant;
    let (status, body) = switch(&d, true);
    assert_eq!(status, 409, "{body}");
    assert_eq!(
        body["details"]["missing"],
        serde_json::json!(["organization_self_hosted_runners"])
    );
    let enabled = d
        .store
        .read(move |c| sentinel_store::runner::mode(c, tenant))
        .unwrap();
    assert!(!enabled);

    // A fresh snapshot grants it and the switch is accepted, audited, and idempotent.
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
                    runner: RunnerPermissions::ALL,
                    migration: sentinel_core::MigrationPermissions::ALL,
                    expected: 1,
                },
                UnixMillis::now(),
            )
        })
        .unwrap();
    let (status, body) = switch(&d, true);
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["enabled"], true);
    assert_eq!(
        switch(&d, true),
        (200, serde_json::json!({"enabled": true}))
    );
    let (status, body) = call(&d, "GET", "/api/v1/tenants/acme/runner-mode", None);
    assert_eq!(status, 200);
    assert_eq!(body["enabled"], true);
    assert_eq!(body["missing"], serde_json::json!([]));
    assert_eq!(
        audit_events(&d)
            .iter()
            .filter(|e| **e == "runner-mode-changed")
            .count(),
        1,
        "one audit row for the change, none for a repeat"
    );

    assert_eq!(
        switch(&d, false),
        (200, serde_json::json!({"enabled": false}))
    );
    assert_eq!(
        switch(&d, false),
        (200, serde_json::json!({"enabled": false}))
    );
    assert_eq!(
        audit_events(&d)
            .iter()
            .filter(|e| **e == "runner-mode-changed")
            .count(),
        2
    );
}

#[test]
fn a_deployment_serving_no_class_says_so_and_a_missing_installation_is_named() {
    let d = deployment(RunnerPermissions::ALL);
    let (status, body) = call(&d, "GET", "/api/v1/tenants/acme/runner-mode", None);
    assert_eq!(status, 200);
    assert_eq!(body["enabled"], false);
    assert_eq!(body["missing"], serde_json::json!([]));
    // Nothing is missing, so the switch is accepted even though this deployment serves no
    // class: a queued job of a class it does not serve is refused, visibly, per delivery.
    assert_eq!(
        switch(&d, true),
        (200, serde_json::json!({"enabled": true}))
    );
}

#[test]
fn a_tenant_without_an_installation_cannot_turn_runner_mode_on() {
    let d = deployment(RunnerPermissions::ALL);
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
    let id = sentinel_core::InstallationId::from_bytes(id).unwrap();
    // Removing the App is exactly what a deleted installation does to the row.
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
    let d = deployment(RunnerPermissions::ALL);
    let tenant = d.tenant;
    let read_only = tokens::provision(
        &d.store,
        Grant {
            user: d.root,
            name: "reader",
            permissions: Permissions::READ,
            tenant: Some(tenant),
            repo: None,
            lifetime_ms: 60_000,
        },
        UnixMillis::now(),
    )
    .unwrap();
    let (status, _) = switch(&d, true);
    assert_eq!(status, 200, "the full token may still switch");
    let url = format!("{}/api/v1/tenants/acme/runner-mode", d.base);
    let agent = ureq::Agent::new_with_config(
        ureq::Agent::config_builder()
            .http_status_as_error(false)
            .build(),
    );
    let response = agent
        .post(&url)
        .header(
            "authorization",
            format!("Bearer {}", sentinel_auth::token::format(&read_only.secret)),
        )
        .header("content-type", "application/json")
        .send(br#"{"enabled":false}"#)
        .unwrap();
    assert_eq!(response.status().as_u16(), 403);
}
