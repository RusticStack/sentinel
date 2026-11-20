//! Part 22 Y01 over HTTP: the deployment's allow-list and a tenant's opt-in, who may set
//! each, and what a disabled tenant admits. Nothing here reaches a provider, and nothing in
//! the workspace can: no provider client exists until Y03. What this proves instead is that
//! the policy route is the only AI route served and that the gate the future request path
//! must call refuses every provider while either side is off.

use std::sync::Arc;

use sentinel_core::{
    TenantId, UnixMillis, UserId,
    auth::{Permissions as P, Principal, Role},
};
use sentinel_link::{controller::Controller, identity::Identity};
use sentinel_store::{
    Durability, Store,
    ai::{self, Deployment as DeploymentPolicy, Provider},
    auth::{self, Authority, provisioning},
    jobs, local_auth,
    logs::LogStore,
    objects::Objects,
};
use serde_json::{Value, json};

const ROOT: &str = "correct horse battery staple";
const ADMIN: &str = "ada-password-is-long";
const MEMBER: &str = "mia-password-is-long";

struct Deployment {
    _dir: tempfile::TempDir,
    store: Arc<Store>,
    _controller: Controller,
    server: Option<sentinel_api::Server>,
    base: String,
    tenant: TenantId,
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
    let key_path = dir.path().join("master.key");
    sentinel_auth::sealed::Key::create(&key_path).unwrap();
    let key = Arc::new(sentinel_auth::sealed::Key::load(&key_path).unwrap());
    let root =
        local_auth::bootstrap(&store, "root", "Root", ROOT.as_bytes(), UnixMillis::now()).unwrap();
    let tenant = TenantId::new();
    let (admin, member) = (UserId::new(), UserId::new());
    let now = UnixMillis::now();
    store
        .writer()
        .write(move |tx| {
            jobs::insert_tenant(tx, tenant, "acme", now)?;
            provisioning::insert_human(tx, admin, "Ada", false, now)?;
            provisioning::insert_human(tx, member, "Mia", false, now)?;
            let root = Principal::new(root, P::ALL, None, None);
            auth::set_membership(tx, root, tenant, admin, Role::TenantAdmin)?;
            auth::set_membership(tx, root, tenant, member, Role::Reader)?;
            for (user, name, password) in [
                (admin, "ada", ADMIN.as_bytes()),
                (member, "mia", MEMBER.as_bytes()),
            ] {
                let phc = sentinel_auth::password::hash(password).unwrap();
                local_auth::provision_credential(tx, Authority::HostLocal, user, name, &phc, now)?;
            }
            Ok(())
        })
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
    let server = sentinel_api::Server::start_with(
        sentinel_api::Config {
            listen: "127.0.0.1:0".parse().unwrap(),
            store: Arc::clone(&store),
            logs,
            objects,
            controller: controller.handle(),
            secret_key: Some(key),
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
        tenant,
    }
}

struct Reply {
    status: u16,
    headers: Vec<(String, String)>,
    text: String,
}

impl Reply {
    fn json(&self) -> Value {
        serde_json::from_str(&self.text).unwrap_or(Value::Null)
    }

    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }
}

fn send(
    d: &Deployment,
    method: &str,
    path: &str,
    body: Option<&Value>,
    headers: &[(&str, &str)],
) -> Reply {
    let agent = ureq::Agent::new_with_config(
        ureq::Agent::config_builder()
            .http_status_as_error(false)
            .max_redirects(0)
            .build(),
    );
    let url = format!("{}{path}", d.base);
    let mut request = if method == "GET" {
        agent.get(&url).force_send_body()
    } else if method == "PUT" {
        agent.put(&url)
    } else {
        agent.post(&url)
    }
    .header("content-type", "application/json");
    for (key, value) in headers {
        request = request.header(*key, *value);
    }
    let response = request
        .send(
            body.map_or_else(|| "{}".to_owned(), Value::to_string)
                .as_bytes(),
        )
        .unwrap();
    let headers = response
        .headers()
        .iter()
        .map(|(name, value)| {
            (
                name.as_str().to_ascii_lowercase(),
                value.to_str().unwrap_or_default().to_owned(),
            )
        })
        .collect();
    Reply {
        status: response.status().as_u16(),
        headers,
        text: response.into_body().read_to_string().unwrap_or_default(),
    }
}

struct Session {
    cookie: String,
    csrf: String,
}

impl Session {
    fn headers(&self) -> [(&str, &str); 2] {
        [("cookie", &self.cookie), ("x-sentinel-csrf", &self.csrf)]
    }
}

fn sign_in(d: &Deployment, username: &str, password: &str) -> Session {
    let reply = send(
        d,
        "POST",
        "/api/v1/login",
        Some(&json!({ "username": username, "password": password })),
        &[],
    );
    assert_eq!(reply.status, 200, "{}", reply.text);
    Session {
        cookie: reply
            .header("set-cookie")
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned(),
        csrf: reply.json()["csrf"].as_str().unwrap().to_owned(),
    }
}

fn stepped_up(d: &Deployment, username: &str, password: &str) -> Session {
    let session = sign_in(d, username, password);
    let reply = send(
        d,
        "POST",
        "/api/v1/step-up",
        Some(&json!({ "method": "password", "code": password })),
        &session.headers(),
    );
    assert_eq!(reply.status, 200, "{}", reply.text);
    session
}

fn allow(d: &Deployment, session: &Session, body: Value) -> Reply {
    send(
        d,
        "PUT",
        "/api/v1/admin/ai",
        Some(&body),
        &session.headers(),
    )
}

fn opt_in(d: &Deployment, session: &Session, body: Value) -> Reply {
    send(
        d,
        "PUT",
        "/api/v1/tenants/acme/ai",
        Some(&body),
        &session.headers(),
    )
}

#[test]
fn a_fresh_deployment_states_ai_off_and_nothing_else() {
    let d = deployment();
    let root = sign_in(&d, "root", ROOT);
    let reply = send(&d, "GET", "/api/v1/admin/ai", None, &root.headers());
    assert_eq!(reply.status, 200, "{}", reply.text);
    assert_eq!(reply.json(), json!({ "enabled": false, "providers": [] }));

    let ada = sign_in(&d, "ada", ADMIN);
    let reply = send(&d, "GET", "/api/v1/tenants/acme/ai", None, &ada.headers());
    assert_eq!(reply.status, 200, "{}", reply.text);
    assert_eq!(
        reply.json(),
        json!({
            "enabled": false,
            "data_policy": null,
            "providers": [],
            "auto_analysis": false,
            "budgets": {
            "monthly_tokens": 0,
            "monthly_cost_micros": 0,
            "max_input_tokens": 32000,
            "max_output_tokens": 4096,
            "max_cost_micros": 100000,
            "concurrency": 2,
        },
        })
    );
}

#[test]
fn only_a_stepped_up_platform_administrator_sets_the_allow_list() {
    let d = deployment();
    let root = sign_in(&d, "root", ROOT);
    let body = json!({ "enabled": true, "providers": ["local", "openrouter"] });
    let reply = allow(&d, &root, body.clone());
    assert_eq!(reply.status, 403, "{}", reply.text);
    assert_eq!(reply.json()["details"]["step_up"], true, "{}", reply.text);

    let ada = stepped_up(&d, "ada", ADMIN);
    let reply = allow(&d, &ada, body.clone());
    assert_eq!(reply.status, 403, "{}", reply.text);

    let root = stepped_up(&d, "root", ROOT);
    let reply = allow(&d, &root, body);
    assert_eq!(reply.status, 200, "{}", reply.text);
    assert_eq!(
        reply.json(),
        json!({ "enabled": true, "providers": ["local", "openrouter"] })
    );
    let reply = send(&d, "GET", "/api/v1/admin/ai", None, &root.headers());
    assert_eq!(
        reply.json(),
        json!({ "enabled": true, "providers": ["local", "openrouter"] })
    );

    let reply = allow(
        &d,
        &root,
        json!({ "enabled": true, "providers": ["local", "gemini"] }),
    );
    assert_eq!(reply.status, 400, "{}", reply.text);
    assert_eq!(reply.json()["details"]["provider"], "gemini");
    let reply = allow(&d, &root, json!({ "enabled": true, "providers": [] }));
    assert_eq!(reply.status, 400, "{}", reply.text);

    let reply = allow(&d, &root, json!({ "enabled": false, "providers": [] }));
    assert_eq!(reply.status, 200, "{}", reply.text);
    assert_eq!(
        reply.json(),
        json!({ "enabled": false, "providers": [] }),
        "an empty allow list is kept"
    );
}

#[test]
fn a_tenant_administrator_opts_in_behind_a_step_up_and_a_known_data_policy() {
    let d = deployment();
    let root = stepped_up(&d, "root", ROOT);
    let reply = allow(
        &d,
        &root,
        json!({ "enabled": true, "providers": ["local", "anthropic"] }),
    );
    assert_eq!(reply.status, 200, "{}", reply.text);

    let ada = sign_in(&d, "ada", ADMIN);
    let body = json!({ "enabled": true, "data_policy": "local_only" });
    let reply = opt_in(&d, &ada, body.clone());
    assert_eq!(reply.status, 403, "{}", reply.text);
    assert_eq!(reply.json()["details"]["step_up"], true, "{}", reply.text);

    let mia = stepped_up(&d, "mia", MEMBER);
    let reply = opt_in(&d, &mia, body.clone());
    assert_eq!(reply.status, 403, "{}", reply.text);
    assert_ne!(
        reply.json()["details"]["step_up"],
        true,
        "a reader was refused for the wrong reason: {}",
        reply.text
    );

    let ada = stepped_up(&d, "ada", ADMIN);
    let reply = opt_in(
        &d,
        &ada,
        json!({ "enabled": true, "data_policy": "keep_forever" }),
    );
    assert_eq!(reply.status, 400, "{}", reply.text);
    assert_eq!(reply.json()["details"]["data_policy"], "keep_forever");

    let reply = opt_in(&d, &ada, body);
    assert_eq!(reply.status, 200, "{}", reply.text);
    assert_eq!(
        reply.json(),
        json!({
            "enabled": true,
            "data_policy": "local_only",
            "providers": ["local"],
            "auto_analysis": false,
            "budgets": {
            "monthly_tokens": 0,
            "monthly_cost_micros": 0,
            "max_input_tokens": 32000,
            "max_output_tokens": 4096,
            "max_cost_micros": 100000,
            "concurrency": 2,
        },
        }),
        "local_only leaves only the local endpoint usable"
    );

    let reply = send(&d, "GET", "/api/v1/tenants/acme/ai", None, &ada.headers());
    assert_eq!(
        reply.json(),
        json!({
            "enabled": true,
            "data_policy": "local_only",
            "providers": ["local"],
            "auto_analysis": false,
            "budgets": {
            "monthly_tokens": 0,
            "monthly_cost_micros": 0,
            "max_input_tokens": 32000,
            "max_output_tokens": 4096,
            "max_cost_micros": 100000,
            "concurrency": 2,
        },
        })
    );

    let reply = opt_in(
        &d,
        &ada,
        json!({ "enabled": false, "data_policy": "local_only" }),
    );
    assert_eq!(reply.status, 200, "{}", reply.text);
    assert_eq!(
        reply.json(),
        json!({
            "enabled": false,
            "data_policy": "local_only",
            "providers": [],
            "auto_analysis": false,
            "budgets": {
            "monthly_tokens": 0,
            "monthly_cost_micros": 0,
            "max_input_tokens": 32000,
            "max_output_tokens": 4096,
            "max_cost_micros": 100000,
            "concurrency": 2,
        },
        })
    );
    let audit: Vec<(String, i64)> = d
        .store
        .read(|c| {
            Ok(local_auth::audit_page(c, None, 100)?
                .into_iter()
                .map(|record| (record.event.name().to_owned(), record.at.0))
                .collect())
        })
        .unwrap();
    let names: Vec<&str> = audit.iter().map(|(name, _)| name.as_str()).collect();
    assert!(names.contains(&"tenant-ai-policy-changed"), "{names:?}");
    assert!(names.contains(&"ai-policy-changed"), "{names:?}");
}

#[test]
fn no_request_path_reaches_a_provider_while_the_tenant_is_off() {
    let d = deployment();
    let root = stepped_up(&d, "root", ROOT);
    let reply = allow(
        &d,
        &root,
        json!({ "enabled": true, "providers": ["local", "openrouter"] }),
    );
    assert_eq!(reply.status, 200, "{}", reply.text);

    let ada = stepped_up(&d, "ada", ADMIN);
    let reply = send(&d, "GET", "/api/v1/tenants/acme/ai", None, &ada.headers());
    assert_eq!(
        reply.json(),
        json!({
            "enabled": false,
            "data_policy": null,
            "providers": [],
            "auto_analysis": false,
            "budgets": {
            "monthly_tokens": 0,
            "monthly_cost_micros": 0,
            "max_input_tokens": 32000,
            "max_output_tokens": 4096,
            "max_cost_micros": 100000,
            "concurrency": 2,
        },
        })
    );
    let tenant = d.tenant;
    for provider in Provider::ALL {
        assert_eq!(
            d.store.read(|c| ai::admit(c, tenant, provider)).unwrap(),
            None,
            "{} was admitted for a tenant that never opted in",
            provider.as_str()
        );
    }
    // Y02's evidence bundle exists and refuses while either side is off: a session holds only the
    // scopes its permissions imply, and no permission implies `ai:context`, so the only caller that
    // could ask is refused before a byte of evidence is read. Y03's request route and Y05's
    // analyses do not exist at all.
    let attempt = sentinel_core::AttemptId::new();
    let reply = send(
        &d,
        "GET",
        &format!("/api/v1/attempts/{attempt}/ai-context"),
        None,
        &ada.headers(),
    );
    assert_eq!(reply.status, 403, "{}", reply.text);
    assert_eq!(reply.json()["details"]["scope"], "ai:context");
    let reply = send(
        &d,
        "POST",
        "/api/v1/tenants/acme/ai/analyses",
        None,
        &ada.headers(),
    );
    assert_eq!(reply.status, 404, "{}", reply.text);
}

#[test]
fn a_deployment_that_allows_nothing_leaves_the_tenant_off() {
    let d = deployment();
    let root = stepped_up(&d, "root", ROOT);
    let reply = allow(
        &d,
        &root,
        json!({ "enabled": true, "providers": ["openrouter"] }),
    );
    assert_eq!(reply.status, 200, "{}", reply.text);
    let reply = allow(&d, &root, json!({ "enabled": false, "providers": [] }));
    assert_eq!(reply.status, 200, "{}", reply.text);
    let ada = stepped_up(&d, "ada", ADMIN);
    let reply = opt_in(
        &d,
        &ada,
        json!({ "enabled": true, "data_policy": "provider_terms" }),
    );
    assert_eq!(reply.status, 403, "{}", reply.text);
    let tenant = d.tenant;
    assert_eq!(
        d.store.read(|c| ai::tenant(c, tenant)).unwrap(),
        None,
        "a refused opt-in left a row"
    );
    assert_eq!(
        d.store.read(ai::deployment).unwrap(),
        DeploymentPolicy::default()
    );
}
