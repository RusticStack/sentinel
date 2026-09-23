//! O06 over real HTTP on loopback: a tenant administrator creates a service
//! account, allows it a repository and issues it a grant; the agent refreshes
//! and reads runs; the grant is listed as metadata and revoked, after which
//! its refresh token is `invalid_grant`. Plus the refusals: non-admins,
//! missing `tenant:admin` scope, administrative scopes, lifetime bounds,
//! foreign repositories and outsiders revoking.
//!
//! The harness (`deployment()`, `send()`, `get()`, `grant()`, `bearer()`)
//! is copied from `oauth_core.rs`.

use std::sync::Arc;

use sentinel_auth::{
    oauth::{self as forms, Kind},
    secret::Secret,
};
use sentinel_core::{
    RepoId, TenantId, UnixMillis, UserId,
    auth::{Audience, Namespace, Permissions as P, Principal, Role, Scopes},
};
use sentinel_link::{controller::Controller, identity::Identity};
use sentinel_protocol::oauth::CLI_CLIENT_ID;
use sentinel_store::{
    Durability, Store,
    auth::{self, NamespaceKind, provisioning},
    local_auth,
    logs::LogStore,
    oauth::{self, GrantKind, Minted, NewGrant},
    objects::Objects,
    tokens::{self, Grant},
};
use serde_json::{Value, json};

pub const PASSWORD: &str = "correct horse battery staple";

pub struct Deployment {
    _dir: tempfile::TempDir,
    pub store: Arc<Store>,
    _controller: Controller,
    server: Option<sentinel_api::Server>,
    /// `http://127.0.0.1:PORT`; also the issuer.
    pub base: String,
    /// A `sntl_` credential for root with every permission.
    pub token: String,
    pub root: UserId,
    pub dev: UserId,
    pub tenant: TenantId,
    pub repo: RepoId,
}

impl Drop for Deployment {
    fn drop(&mut self) {
        if let Some(server) = self.server.take() {
            server.shutdown();
        }
    }
}

pub fn deployment() -> Deployment {
    let dir = tempfile::tempdir().unwrap();
    let store =
        Arc::new(Store::open(dir.path().join("metadata.sqlite"), Durability::Normal).unwrap());
    let logs = Arc::new(LogStore::open(dir.path().join("logs")).unwrap());
    let objects = Arc::new(Objects::open(dir.path()).unwrap());
    let now = UnixMillis::now();
    let root = local_auth::bootstrap(&store, "root", "Root", PASSWORD.as_bytes(), now).unwrap();
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
            auth::create_repo(tx, admin, tenant, repo, "app", now)?;
            auth::set_repo_grant(tx, admin, repo, dev, P::READ.union(P::RUN))
        })
        .unwrap();
    let granted =
        tokens::provision(&store, Grant::new(root, "test", P::ALL), UnixMillis::now()).unwrap();
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
    })
    .unwrap();
    let base = format!("http://{}", server.local_addr());
    assert_eq!(server.issuer(), base);
    Deployment {
        _dir: dir,
        store,
        _controller: controller,
        server: Some(server),
        base,
        token: sentinel_auth::token::format(&granted.secret),
        root,
        dev,
        tenant,
        repo,
    }
}

/// A request body: none, JSON, or a raw `application/x-www-form-urlencoded` form.
pub enum Body<'a> {
    None,
    Json(&'a Value),
    Form(&'a str),
}

/// What came back: status, every header (lower-case names) and the body as
/// JSON (or a JSON string when it is not JSON).
pub struct Reply {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Value,
}

impl Reply {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// One request; redirects are returned, never followed.
pub fn send(
    d: &Deployment,
    method: &str,
    path: &str,
    body: Body<'_>,
    headers: &[(&str, &str)],
) -> Reply {
    let url = format!("{}{path}", d.base);
    let agent = ureq::Agent::new_with_config(
        ureq::Agent::config_builder()
            .http_status_as_error(false)
            .max_redirects(0)
            .build(),
    );
    let response = match (method, body) {
        ("GET", _) => {
            let mut request = agent.get(&url);
            for (k, v) in headers {
                request = request.header(*k, *v);
            }
            request.call()
        }
        (method, body) => {
            let mut request = match method {
                "POST" => agent.post(&url),
                "PUT" => agent.put(&url),
                "DELETE" => agent.delete(&url).force_send_body(),
                _ => unreachable!(),
            };
            for (k, v) in headers {
                request = request.header(*k, *v);
            }
            match body {
                Body::None => request.send_empty(),
                Body::Json(value) => request
                    .header("content-type", "application/json")
                    .send(value.to_string().as_bytes()),
                Body::Form(form) => request
                    .header("content-type", "application/x-www-form-urlencoded")
                    .send(form.as_bytes()),
            }
        }
    }
    .unwrap();
    let status = response.status().as_u16();
    let headers = response
        .headers()
        .iter()
        .map(|(k, v)| {
            (
                k.as_str().to_ascii_lowercase(),
                v.to_str().unwrap_or("").to_owned(),
            )
        })
        .collect();
    let text = response.into_body().read_to_string().unwrap();
    let body = if text.is_empty() {
        Value::Null
    } else {
        serde_json::from_str(&text).unwrap_or(Value::String(text))
    };
    Reply {
        status,
        headers,
        body,
    }
}

/// `GET` with an `Authorization` header.
pub fn get(d: &Deployment, path: &str, authorization: &str) -> Reply {
    send(
        d,
        "GET",
        path,
        Body::None,
        &[("authorization", authorization)],
    )
}

/// A login grant for `user` issued without the browser, as the flows would.
pub fn grant(d: &Deployment, user: UserId, scopes: Scopes) -> Minted {
    oauth::issue_grant_trusted(
        &d.store,
        NewGrant {
            user,
            client_id: CLI_CLIENT_ID,
            kind: GrantKind::Code,
            scopes,
            tenant: None,
            repo: None,
            audience: Audience::Api,
            name: None,
            lifetime_ms: oauth::LOGIN_GRANT_MS,
            created_by: None,
        },
        UnixMillis::now(),
    )
    .unwrap()
}

pub fn bearer(access: &Secret) -> String {
    format!("Bearer {}", forms::format(Kind::Access, access))
}

const ACCOUNTS: &str = "/api/v1/tenants/acme/service-accounts";

fn call(d: &Deployment, method: &str, path: &str, body: &Value, authorization: &str) -> Reply {
    let body = if method == "GET" || method == "DELETE" {
        Body::None
    } else {
        Body::Json(body)
    };
    send(d, method, path, body, &[("authorization", authorization)])
}

fn root(d: &Deployment) -> String {
    format!("Bearer {}", d.token)
}

fn refresh(d: &Deployment, refresh_token: &str) -> Reply {
    send(
        d,
        "POST",
        "/oauth/token",
        Body::Form(&format!(
            "grant_type=refresh_token&client_id={CLI_CLIENT_ID}&refresh_token={refresh_token}"
        )),
        &[],
    )
}

/// Create a service account `deployer` in `acme` as root; its `usr_` id.
fn create_account(d: &Deployment) -> String {
    let created = call(
        d,
        "POST",
        ACCOUNTS,
        &json!({"name": "deployer", "role": "operator"}),
        &root(d),
    );
    assert_eq!(created.status, 201, "{}", created.body);
    assert_eq!(created.body["name"], "deployer");
    assert_eq!(created.body["role"], "operator");
    created.body["user"].as_str().unwrap().to_owned()
}

#[test]
fn an_agent_grant_is_issued_refreshed_used_listed_and_revoked() {
    let d = deployment();
    let account = create_account(&d);
    let allowed = call(
        &d,
        "PUT",
        &format!("{ACCOUNTS}/{account}/repos/app"),
        &json!({"access": ["read", "run"]}),
        &root(&d),
    );
    assert_eq!(allowed.status, 200, "{}", allowed.body);
    assert_eq!(allowed.body["access"], json!(["read", "run"]));

    let issued = call(
        &d,
        "POST",
        &format!("{ACCOUNTS}/{account}/grants"),
        &json!({"name": "ci", "scope": "runs:read runs:write logs:read", "repo": "app"}),
        &root(&d),
    );
    assert_eq!(issued.status, 201, "{}", issued.body);
    let refresh_token = issued.body["refresh_token"].as_str().unwrap().to_owned();
    assert!(refresh_token.starts_with("sntl_rt_"));
    assert_eq!(issued.body["scope"], "runs:read runs:write logs:read");
    let grant = issued.body["grant"].as_str().unwrap().to_owned();
    assert!(grant.starts_with("grt_"));
    let expires = issued.body["expires_ms"].as_i64().unwrap();
    let expected = UnixMillis::now().0 + oauth::SERVICE_DEFAULT_MS;
    assert!((expected - 60_000..=expected).contains(&expires));

    // The agent imports it: refresh, then read runs as the service account.
    let tokens = refresh(&d, &refresh_token);
    assert_eq!(tokens.status, 200, "{}", tokens.body);
    assert_eq!(tokens.body["sentinel_grant"], grant);
    let access = format!("Bearer {}", tokens.body["access_token"].as_str().unwrap());
    let runs = get(&d, "/api/v1/tenants/acme/repos/app/runs", &access);
    assert_eq!(runs.status, 200, "{}", runs.body);
    let me = get(&d, "/api/v1/me", &access);
    assert_eq!(me.body["user"], account);
    assert_eq!(me.body["via"], "oauth");
    assert_eq!(me.body["repo"], d.repo.to_string());
    // Its own grants, as metadata.
    let own = get(&d, "/api/v1/grants", &access);
    assert_eq!(own.status, 200);
    assert_eq!(own.body["grants"][0]["id"], grant);

    // The administrator's listing: metadata only, never token material.
    let listed = call(
        &d,
        "GET",
        &format!("{ACCOUNTS}/{account}/grants"),
        &Value::Null,
        &root(&d),
    );
    assert_eq!(listed.status, 200);
    let record = &listed.body["grants"][0];
    assert_eq!(record["id"], grant);
    assert_eq!(record["name"], "ci");
    assert_eq!(record["kind"], "service");
    assert_eq!(record["repo"], d.repo.to_string());
    assert_eq!(record["tenant"], d.tenant.to_string());
    assert_eq!(record["revoked"], false);
    assert!(record["last_used_ms"].is_i64());
    let text = listed.body.to_string();
    assert!(!text.contains("sntl_"));
    assert!(!text.contains(&refresh_token[8..]));

    // An operator of the tenant cannot revoke it; the administrator can.
    let dev = tokens::provision(
        &d.store,
        Grant::new(d.dev, "dev", P::REPOSITORY.union(P::TENANT_ADMIN)),
        UnixMillis::now(),
    )
    .unwrap();
    let dev = format!("Bearer {}", sentinel_auth::token::format(&dev.secret));
    let refused = call(
        &d,
        "DELETE",
        &format!("/api/v1/grants/{grant}"),
        &Value::Null,
        &dev,
    );
    assert_eq!(refused.status, 404);
    let revoked = call(
        &d,
        "DELETE",
        &format!("/api/v1/grants/{grant}"),
        &Value::Null,
        &root(&d),
    );
    assert_eq!(revoked.status, 200, "{}", revoked.body);
    assert_eq!(get(&d, "/api/v1/me", &access).status, 401);
    let next = tokens.body["refresh_token"].as_str().unwrap();
    let after = refresh(&d, next);
    assert_eq!(after.status, 400);
    assert_eq!(after.body["error"], "invalid_grant");
    let listed = call(
        &d,
        "GET",
        &format!("{ACCOUNTS}/{account}/grants"),
        &Value::Null,
        &root(&d),
    );
    assert_eq!(listed.body["grants"][0]["revoked"], true);
}

#[test]
fn only_tenant_administrators_with_the_scope_manage_service_accounts() {
    let d = deployment();
    let account = create_account(&d);
    let body = json!({"name": "ci", "scope": "runs:read"});
    // An operator holding every permission bit is still not an administrator.
    let dev = tokens::provision(
        &d.store,
        Grant::new(d.dev, "dev", P::REPOSITORY.union(P::TENANT_ADMIN)),
        UnixMillis::now(),
    )
    .unwrap();
    let dev = format!("Bearer {}", sentinel_auth::token::format(&dev.secret));
    for (method, path, body) in [
        ("POST", ACCOUNTS.to_owned(), json!({"name": "x"})),
        (
            "PUT",
            format!("{ACCOUNTS}/{account}/repos/app"),
            json!({"access": ["read"]}),
        ),
        ("POST", format!("{ACCOUNTS}/{account}/grants"), body.clone()),
        ("GET", format!("{ACCOUNTS}/{account}/grants"), Value::Null),
    ] {
        let reply = call(&d, method, &path, &body, &dev);
        assert!(
            reply.status == 403 || reply.status == 404,
            "{method} {path}: {} {}",
            reply.status,
            reply.body
        );
    }
    // An OAuth grant without tenant:admin is refused by scope, even for root.
    let narrow = grant(&d, d.root, Scopes::CLI_DEFAULT);
    let scoped = call(
        &d,
        "POST",
        &format!("{ACCOUNTS}/{account}/grants"),
        &body,
        &bearer(&narrow.access),
    );
    assert_eq!(scoped.status, 403);
    assert_eq!(scoped.body["details"]["scope"], "tenant:admin");
    // With it, root may.
    let admin = grant(&d, d.root, Scopes::CLI_DEFAULT.union(Scopes::TENANT_ADMIN));
    let ok = call(
        &d,
        "POST",
        &format!("{ACCOUNTS}/{account}/grants"),
        &body,
        &bearer(&admin.access),
    );
    assert_eq!(ok.status, 201, "{}", ok.body);
    // No credential at all.
    let anonymous = send(
        &d,
        "GET",
        &format!("{ACCOUNTS}/{account}/grants"),
        Body::None,
        &[],
    );
    assert_eq!(anonymous.status, 401);
}

#[test]
fn grant_terms_are_validated() {
    let d = deployment();
    let account = create_account(&d);
    let path = format!("{ACCOUNTS}/{account}/grants");
    for (body, status) in [
        (json!({"name": "a", "scope": "runs:read tenant:admin"}), 400),
        (json!({"name": "a", "scope": "platform:admin"}), 400),
        (json!({"name": "a", "scope": "runs:fly"}), 400),
        (json!({"name": "a", "scope": ""}), 400),
        (
            json!({"name": "a", "scope": "runs:read", "expires_in_ms": 1_000}),
            400,
        ),
        (
            json!({"name": "a", "scope": "runs:read", "expires_in_ms": oauth::SERVICE_MAX_MS + 1}),
            400,
        ),
        (json!({"name": "", "scope": "runs:read"}), 400),
        (
            json!({"name": "a", "scope": "runs:read", "repo": "nope"}),
            404,
        ),
        (json!({"name": "a", "scope": "runs:read", "extra": 1}), 400),
    ] {
        let reply = call(&d, "POST", &path, &body, &root(&d));
        assert_eq!(reply.status, status, "{body}: {}", reply.body);
        assert!(!reply.body.to_string().contains("sntl_rt_"));
    }
    // A person is not a service account; an unknown one is not found.
    let person = call(
        &d,
        "POST",
        &format!("{ACCOUNTS}/{}/grants", d.dev),
        &json!({"name": "a", "scope": "runs:read"}),
        &root(&d),
    );
    assert_eq!(person.status, 404);
    let roles = call(
        &d,
        "POST",
        ACCOUNTS,
        &json!({"name": "boss", "role": "admin"}),
        &root(&d),
    );
    assert_eq!(roles.status, 400);
    let access = call(
        &d,
        "PUT",
        &format!("{ACCOUNTS}/{account}/repos/app"),
        &json!({"access": ["write"]}),
        &root(&d),
    );
    assert_eq!(access.status, 400);
    let bounds = call(
        &d,
        "POST",
        &path,
        &json!({"name": "a", "scope": "runs:read", "expires_in_ms": oauth::SERVICE_MIN_MS}),
        &root(&d),
    );
    assert_eq!(bounds.status, 201, "{}", bounds.body);
}

/// A tenant the caller has no part in is the same `not_found` as one that
/// does not exist, on every service-account route (P02-9: routes resolve
/// slugs through the membership-checked lookup).
#[test]
fn a_foreign_tenant_is_not_found_like_a_missing_one() {
    let d = deployment();
    let (globex, root) = (TenantId::new(), d.root);
    let now = UnixMillis::now();
    d.store
        .writer()
        .write(move |tx| {
            auth::create_namespace(
                tx,
                Principal::new(root, P::ALL, None, None),
                globex,
                Namespace::parse("globex").unwrap(),
                NamespaceKind::Organization,
                now,
            )
        })
        .unwrap();
    let dev = tokens::provision(
        &d.store,
        Grant::new(d.dev, "dev", P::REPOSITORY.union(P::TENANT_ADMIN)),
        UnixMillis::now(),
    )
    .unwrap();
    let dev = format!("Bearer {}", sentinel_auth::token::format(&dev.secret));
    let account = UserId::new();
    for (method, suffix, body) in [
        ("POST", String::new(), json!({"name": "x"})),
        (
            "PUT",
            format!("/{account}/repos/app"),
            json!({"access": ["read"]}),
        ),
        (
            "POST",
            format!("/{account}/grants"),
            json!({"name": "ci", "scope": "runs:read"}),
        ),
        ("GET", format!("/{account}/grants"), Value::Null),
    ] {
        let foreign = call(
            &d,
            method,
            &format!("/api/v1/tenants/globex/service-accounts{suffix}"),
            &body,
            &dev,
        );
        let missing = call(
            &d,
            method,
            &format!("/api/v1/tenants/nowhere/service-accounts{suffix}"),
            &body,
            &dev,
        );
        assert_eq!(foreign.status, 404, "{method} {suffix}: {}", foreign.body);
        assert_eq!(
            (foreign.status, &foreign.body),
            (missing.status, &missing.body),
            "{method} {suffix}"
        );
    }
}
