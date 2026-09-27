//! O02 over real HTTP on loopback: authorization-server and protected-
//! resource metadata, OAuth access tokens on `/api/v1` with per-route
//! scopes and `WWW-Authenticate` challenges, the `refresh_token` grant, RFC
//! 7009 revocation, the RFC 6749 error shape, and unchanged sessions and
//! `sntl_` credentials.
//!
//! `deployment()`, `send()` and `grant()` below are the minimal harness the
//! other OAuth suites (`oauth_code.rs`, `oauth_device.rs`, `oauth_service.rs`,
//! `wait.rs`) copy: one bootstrapped super admin `root` (password
//! `PASSWORD`) administering tenant `acme` with repository `app`, one
//! ordinary member `dev`, an `sntl_` credential for root, and a real
//! server on `127.0.0.1:0` whose issuer is its own base URL.

use std::sync::Arc;

use sentinel_auth::{
    oauth::{self as forms, Kind},
    secret::Secret,
};
use sentinel_core::{
    AttemptId, GrantId, RepoId, TenantId, UnixMillis, UserId,
    auth::{Audience, Namespace, Permissions as P, Principal, Role, Scopes},
};
use sentinel_link::{controller::Controller, identity::Identity};
use sentinel_protocol::oauth::{CLI_CLIENT_ID, Metadata, ProtectedResource};
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
    deployment_under(None)
}

/// A deployment whose `public_url` carries `path` (`/sentinel`), reached
/// directly (the tests play both a stripping and a forwarding proxy).
pub fn deployment_under(path: Option<&str>) -> Deployment {
    let (listen, public_url): (std::net::SocketAddr, Option<String>) = match path {
        None => ("127.0.0.1:0".parse().unwrap(), None),
        Some(path) => {
            let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = probe.local_addr().unwrap();
            drop(probe);
            (addr, Some(format!("http://{addr}{path}")))
        }
    };
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
        listen,
        store: Arc::clone(&store),
        logs,
        objects,
        controller: controller.handle(),
        secret_key: None,
        sessions: local_auth::Policy::default(),
        github_webhook_secret: None,
        intake: None,
        public_url: public_url.clone(),
        github_sign_in: None,
        trusted_proxies: sentinel_api::TrustedProxy::loopback(),
    })
    .unwrap();
    let base = format!("http://{}", server.local_addr());
    assert_eq!(server.issuer(), public_url.as_deref().unwrap_or(&base));
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

fn refresh_form(refresh: &Secret) -> String {
    format!(
        "grant_type=refresh_token&client_id={CLI_CLIENT_ID}&refresh_token={}",
        forms::format(Kind::Refresh, refresh)
    )
}

fn runs_path() -> &'static str {
    "/api/v1/tenants/acme/repos/app/runs"
}

const PIPELINE: &str = "schema: 1
on: [push]
jobs:
  build:
    image: docker.io/library/busybox@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662
    steps: [{ id: s, run: 'true' }]
";

fn dispatch_body() -> Value {
    json!({
        "pipeline": PIPELINE,
        "source": { "repo": "https://github.com/o/r.git", "sha": "0123456789abcdef0123456789abcdef01234567", "ref": "main" }
    })
}

#[test]
fn metadata_documents_name_this_deployment_exactly() {
    let d = deployment();
    let meta = send(
        &d,
        "GET",
        "/.well-known/oauth-authorization-server",
        Body::None,
        &[],
    );
    assert_eq!(meta.status, 200);
    // The default instance policy: metadata documents, no DCR.
    let expected =
        Metadata::for_issuer(&d.base, &Scopes::NAMES).with_client_registration(false, true);
    assert_eq!(
        serde_json::from_value::<Metadata>(meta.body.clone()).unwrap(),
        expected
    );
    assert_eq!(meta.body["issuer"], d.base);
    assert_eq!(
        meta.body["token_endpoint"],
        format!("{}/oauth/token", d.base)
    );
    assert_eq!(
        meta.body["authorization_endpoint"],
        format!("{}/oauth/authorize", d.base)
    );
    assert_eq!(
        meta.body["revocation_endpoint"],
        format!("{}/oauth/revoke", d.base)
    );
    assert_eq!(
        meta.body["device_authorization_endpoint"],
        format!("{}/oauth/device_authorization", d.base)
    );
    assert_eq!(
        meta.body["code_challenge_methods_supported"],
        json!(["S256"])
    );
    assert_eq!(
        meta.body["token_endpoint_auth_methods_supported"],
        json!(["none"])
    );
    assert_eq!(meta.body["response_types_supported"], json!(["code"]));
    assert_eq!(meta.body["scopes_supported"].as_array().unwrap().len(), 10);
    assert_eq!(
        meta.body["authorization_response_iss_parameter_supported"],
        true
    );

    let resource = send(
        &d,
        "GET",
        "/.well-known/oauth-protected-resource/api/v1",
        Body::None,
        &[],
    );
    assert_eq!(resource.status, 200);
    let resource: ProtectedResource = serde_json::from_value(resource.body).unwrap();
    assert_eq!(resource.resource, format!("{}/api/v1", d.base));
    assert_eq!(resource.authorization_servers, vec![d.base.clone()]);
    assert_eq!(resource.bearer_methods_supported, vec!["header".to_owned()]);
}

#[test]
fn an_access_token_reads_runs_and_me_reports_the_grant() {
    let d = deployment();
    let dispatched = send(
        &d,
        "POST",
        runs_path(),
        Body::Json(&dispatch_body()),
        &[("authorization", &format!("Bearer {}", d.token))],
    );
    assert_eq!(dispatched.status, 201, "{}", dispatched.body);
    let minted = grant(&d, d.dev, Scopes::CLI_DEFAULT);
    let auth = bearer(&minted.access);
    let runs = get(&d, runs_path(), &auth);
    assert_eq!(runs.status, 200, "{}", runs.body);
    assert_eq!(runs.body["runs"][0]["id"], dispatched.body["id"]);
    let run = get(
        &d,
        &format!("/api/v1/runs/{}", dispatched.body["id"].as_str().unwrap()),
        &auth,
    );
    assert_eq!(run.status, 200);

    let me = get(&d, "/api/v1/me", &auth);
    assert_eq!(me.status, 200);
    assert_eq!(me.body["user"], d.dev.to_string());
    assert_eq!(me.body["via"], "oauth");
    assert_eq!(me.body["grant"], minted.grant.to_string());
    assert_eq!(me.body["expires_ms"], minted.access_expires.0);
    assert_eq!(me.body["super_admin"], false);
    assert_eq!(
        me.body["scopes"],
        json!([
            "runs:read",
            "runs:write",
            "logs:read",
            "artifacts:read",
            "cache:read"
        ])
    );
    // No local password for dev; root has one.
    assert_eq!(me.body["username"], Value::Null);
    let root = get(&d, "/api/v1/me", &format!("Bearer {}", d.token));
    assert_eq!(root.body["username"], "root");
    assert_eq!(root.body["via"], "bearer");
    assert_eq!(root.body["grant"], Value::Null);
    assert_eq!(root.body["scopes"].as_array().unwrap().len(), 10);
}

#[test]
fn a_missing_scope_is_forbidden_with_an_insufficient_scope_challenge() {
    let d = deployment();
    let minted = grant(&d, d.root, Scopes::RUNS_READ);
    let auth = bearer(&minted.access);
    assert_eq!(get(&d, runs_path(), &auth).status, 200);
    let cases = [
        (
            "GET",
            format!("/api/v1/attempts/{}/logs", AttemptId::new()),
            "logs:read",
        ),
        ("POST", runs_path().to_owned(), "runs:write"),
        (
            "GET",
            format!("/api/v1/runs/{}/artifacts", sentinel_core::RunId::new()),
            "artifacts:read",
        ),
        (
            "POST",
            format!("/api/v1/workers/{}/drain", sentinel_core::WorkerId::new()),
            "platform:admin",
        ),
    ];
    for (method, path, scope) in cases {
        let body = dispatch_body();
        let refused = send(
            &d,
            method,
            &path,
            if method == "POST" {
                Body::Json(&body)
            } else {
                Body::None
            },
            &[("authorization", &auth)],
        );
        assert_eq!(refused.status, 403, "{path}: {}", refused.body);
        assert_eq!(refused.body["code"], "forbidden");
        assert_eq!(refused.body["details"]["scope"], scope);
        assert_eq!(
            refused.header("www-authenticate"),
            Some(format!("Bearer error=\"insufficient_scope\", scope=\"{scope}\"").as_str()),
            "{path}"
        );
    }
}

#[test]
fn unusable_bearers_are_401_with_a_resource_metadata_challenge() {
    let d = deployment();
    let challenge = format!(
        "Bearer realm=\"sentinel\", resource_metadata=\"{}/.well-known/oauth-protected-resource/api/v1\"",
        d.base
    );
    let anonymous = send(&d, "GET", "/api/v1/me", Body::None, &[]);
    assert_eq!(anonymous.status, 401);
    assert_eq!(
        anonymous.header("www-authenticate"),
        Some(challenge.as_str())
    );

    let minted = grant(&d, d.dev, Scopes::CLI_DEFAULT);
    let mut hex = String::new();
    Secret::generate().expose(&mut hex);
    // An access token for another audience (the reserved MCP code), only
    // insertable with the CHECK constraint lifted.
    let foreign = Secret::generate();
    let (digest, grant_id, dev) = (foreign.digest().0, GrantId::new(), d.dev);
    let now = UnixMillis::now().0;
    d.store
        .writer()
        .raw(move |c| {
            c.execute_batch("PRAGMA ignore_check_constraints = ON")?;
            c.execute(
                "INSERT INTO oauth_grants(id, user_id, client_id, kind, scopes, audience,
                    created_ms, expires_ms) VALUES (?1, ?2, 'sentinel-cli', 1, 1, 2, ?3, ?4)",
                rusqlite_params(grant_id.as_bytes(), dev.as_bytes(), now),
            )?;
            c.execute(
                "INSERT INTO oauth_access_tokens(token_digest, grant_id, generation, scopes,
                    created_ms, expires_ms) VALUES (?1, ?2, 1, 1, ?3, ?4)",
                (digest, grant_id.as_bytes().as_slice(), now, now + 600_000),
            )?;
            c.execute_batch("PRAGMA ignore_check_constraints = OFF")?;
            Ok(())
        })
        .unwrap();
    for presented in [
        bearer(&foreign),
        format!("Bearer {}", forms::format(Kind::Refresh, &minted.refresh)),
        format!("Bearer gho_{}", &hex[..36]),
        format!("Bearer ghp_{}", &hex[..36]),
        format!("Bearer github_pat_{}", &hex[..60]),
        format!("Bearer {hex}"),
        format!(
            "Bearer {}",
            forms::format(Kind::Access, &Secret::generate())
        ),
    ] {
        let refused = get(&d, "/api/v1/me", &presented);
        assert_eq!(refused.status, 401, "{presented}");
        assert_eq!(refused.body["code"], "unauthenticated");
        assert_eq!(
            refused.header("www-authenticate"),
            Some(format!("{challenge}, error=\"invalid_token\"").as_str()),
            "{presented}"
        );
    }
}

fn rusqlite_params<'a>(
    grant: &'a [u8; 16],
    user: &'a [u8; 16],
    now: i64,
) -> (&'a [u8], &'a [u8], i64, i64) {
    (grant.as_slice(), user.as_slice(), now, now + 600_000)
}

#[test]
fn the_refresh_grant_rotates_and_a_replay_is_invalid_grant() {
    let d = deployment();
    let first = grant(&d, d.dev, Scopes::CLI_DEFAULT);
    let rotated = send(
        &d,
        "POST",
        "/oauth/token",
        Body::Form(&refresh_form(&first.refresh)),
        &[],
    );
    assert_eq!(rotated.status, 200, "{}", rotated.body);
    assert_eq!(rotated.header("cache-control"), Some("no-store"));
    assert_eq!(rotated.header("pragma"), Some("no-cache"));
    let body = &rotated.body;
    assert_eq!(body["token_type"], "Bearer");
    assert_eq!(body["sentinel_grant"], first.grant.to_string());
    assert_eq!(body["scope"], Scopes::CLI_DEFAULT.to_names());
    assert!(
        (598..=600).contains(&body["expires_in"].as_u64().unwrap()),
        "{body}"
    );
    assert!(body["sentinel_refresh_expires_in"].as_u64().unwrap() > 29 * 86_400);
    let access = body["access_token"].as_str().unwrap().to_owned();
    let refresh = body["refresh_token"].as_str().unwrap().to_owned();
    assert!(access.starts_with("sntl_at_") && access.len() == 72);
    assert!(refresh.starts_with("sntl_rt_") && refresh.len() == 72);
    assert_eq!(
        get(&d, "/api/v1/me", &format!("Bearer {access}")).status,
        200
    );

    // Narrowing on refresh.
    let narrowed = send(
        &d,
        "POST",
        "/oauth/token",
        Body::Form(&format!(
            "grant_type=refresh_token&client_id={CLI_CLIENT_ID}&refresh_token={refresh}&scope=runs%3Aread"
        )),
        &[],
    );
    assert_eq!(narrowed.status, 200, "{}", narrowed.body);
    assert_eq!(narrowed.body["scope"], "runs:read");
    let latest = narrowed.body["refresh_token"].as_str().unwrap().to_owned();
    let latest_access = narrowed.body["access_token"].as_str().unwrap().to_owned();

    // The first refresh token's successor was used: presenting it again is
    // a replay, which is invalid_grant and revokes the whole grant.
    let replay = send(
        &d,
        "POST",
        "/oauth/token",
        Body::Form(&refresh_form(&first.refresh)),
        &[],
    );
    assert_eq!(replay.status, 400);
    assert_eq!(
        replay.body,
        json!({"error": "invalid_grant", "error_description": "refresh token is not valid"})
    );
    assert_eq!(
        get(&d, "/api/v1/me", &format!("Bearer {latest_access}")).status,
        401
    );
    let after = send(
        &d,
        "POST",
        "/oauth/token",
        Body::Form(&format!(
            "grant_type=refresh_token&client_id={CLI_CLIENT_ID}&refresh_token={latest}"
        )),
        &[],
    );
    assert_eq!(after.body["error"], "invalid_grant");
}

#[test]
fn the_token_endpoint_refuses_malformed_requests_in_the_rfc_shape() {
    let d = deployment();
    let minted = grant(&d, d.dev, Scopes::RUNS_READ);
    let rt = forms::format(Kind::Refresh, &minted.refresh);
    let cases: [(String, u16, &str); 9] = [
        (
            format!(
                "grant_type=refresh_token&client_id={CLI_CLIENT_ID}&refresh_token={rt}&refresh_token={rt}"
            ),
            400,
            "invalid_request",
        ),
        (
            format!("client_id={CLI_CLIENT_ID}&refresh_token={rt}"),
            400,
            "invalid_request",
        ),
        (
            format!("grant_type=refresh_token&refresh_token={rt}"),
            400,
            "invalid_request",
        ),
        (
            format!("grant_type=password&client_id={CLI_CLIENT_ID}&username=root"),
            400,
            "unsupported_grant_type",
        ),
        (
            format!("grant_type=refresh_token&client_id=nobody&refresh_token={rt}"),
            401,
            "invalid_client",
        ),
        (
            format!(
                "grant_type=refresh_token&client_id={CLI_CLIENT_ID}&refresh_token=sntl_rt_short"
            ),
            400,
            "invalid_grant",
        ),
        (
            format!(
                "grant_type=refresh_token&client_id={CLI_CLIENT_ID}&refresh_token={rt}&scope=runs%3Awrite"
            ),
            400,
            "invalid_scope",
        ),
        (
            format!(
                "grant_type=refresh_token&client_id={CLI_CLIENT_ID}&refresh_token={rt}&scope=everything"
            ),
            400,
            "invalid_scope",
        ),
        (
            format!(
                "grant_type=refresh_token&client_id={CLI_CLIENT_ID}&refresh_token={rt}&resource=https%3A%2F%2Felsewhere.example%2Fapi%2Fv1"
            ),
            400,
            "invalid_target",
        ),
    ];
    for (form, status, code) in cases {
        let reply = send(&d, "POST", "/oauth/token", Body::Form(&form), &[]);
        assert_eq!(
            (reply.status, reply.body["error"].as_str()),
            (status, Some(code)),
            "{form}"
        );
        assert!(reply.body["error_description"].is_string());
        assert!(
            reply.body.get("schema").is_none(),
            "RFC shape, not sentinel.error/1"
        );
        assert_eq!(reply.header("cache-control"), Some("no-store"));
    }
    // Not a form at all.
    let json_body = json!({"grant_type": "refresh_token"});
    let reply = send(&d, "POST", "/oauth/token", Body::Json(&json_body), &[]);
    assert_eq!(
        (reply.status, reply.body["error"].as_str()),
        (400, Some("invalid_request"))
    );
    // Larger than the form bound.
    let huge = format!("grant_type=refresh_token&padding={}", "a".repeat(9 << 10));
    let reply = send(&d, "POST", "/oauth/token", Body::Form(&huge), &[]);
    assert_eq!(
        (reply.status, reply.body["error"].as_str()),
        (413, Some("invalid_request"))
    );
    // The refused requests spent nothing: the token still rotates, and
    // `resource` naming this API is accepted.
    let ok = send(
        &d,
        "POST",
        "/oauth/token",
        Body::Form(&format!(
            "{}&resource={}",
            refresh_form(&minted.refresh),
            form_urlencoded::byte_serialize(format!("{}/api/v1", d.base).as_bytes())
                .collect::<String>()
        )),
        &[],
    );
    assert_eq!(ok.status, 200, "{}", ok.body);
}

#[test]
fn revocation_ends_the_grant_and_always_answers_200() {
    let d = deployment();
    let minted = grant(&d, d.dev, Scopes::CLI_DEFAULT);
    let auth = bearer(&minted.access);
    assert_eq!(get(&d, "/api/v1/me", &auth).status, 200);
    for unknown in [
        format!("token={}", forms::format(Kind::Access, &Secret::generate())),
        "token=garbage".to_owned(),
    ] {
        let reply = send(
            &d,
            "POST",
            "/oauth/revoke",
            Body::Form(&format!("{unknown}&client_id={CLI_CLIENT_ID}")),
            &[],
        );
        assert_eq!(reply.status, 200, "{unknown}");
    }
    assert_eq!(get(&d, "/api/v1/me", &auth).status, 200);
    let reply = send(
        &d,
        "POST",
        "/oauth/revoke",
        Body::Form(&format!(
            "token={}&token_type_hint=access_token&client_id={CLI_CLIENT_ID}",
            forms::format(Kind::Access, &minted.access)
        )),
        &[],
    );
    assert_eq!(reply.status, 200);
    let refused = get(&d, "/api/v1/me", &auth);
    assert_eq!(refused.status, 401);
    assert!(
        refused
            .header("www-authenticate")
            .unwrap()
            .contains("invalid_token")
    );
    let refreshed = send(
        &d,
        "POST",
        "/oauth/token",
        Body::Form(&refresh_form(&minted.refresh)),
        &[],
    );
    assert_eq!(refreshed.body["error"], "invalid_grant");
    let missing = send(
        &d,
        "POST",
        "/oauth/revoke",
        Body::Form(&format!("client_id={CLI_CLIENT_ID}")),
        &[],
    );
    assert_eq!(missing.body["error"], "invalid_request");
    let grants = d
        .store
        .read(|c| oauth::grants(c, sentinel_store::auth::Authority::HostLocal, d.dev, 10))
        .unwrap();
    assert!(grants[0].revoked);
}

#[test]
fn sessions_and_api_credentials_keep_their_behavior() {
    let d = deployment();
    let bearer_me = get(&d, "/api/v1/me", &format!("Bearer {}", d.token));
    assert_eq!(bearer_me.status, 200);
    assert_eq!(bearer_me.body["via"], "bearer");
    assert_eq!(bearer_me.body["super_admin"], true);
    // A read-only API credential keeps reading and cannot dispatch.
    let read_only = tokens::provision(
        &d.store,
        Grant::new(d.dev, "ro", P::READ),
        UnixMillis::now(),
    )
    .unwrap();
    let read_only = format!("Bearer {}", sentinel_auth::token::format(&read_only.secret));
    assert_eq!(get(&d, runs_path(), &read_only).status, 200);
    let body = dispatch_body();
    let refused = send(
        &d,
        "POST",
        runs_path(),
        Body::Json(&body),
        &[("authorization", &read_only)],
    );
    assert_eq!(refused.status, 403, "{}", refused.body);

    let login = send(
        &d,
        "POST",
        "/api/v1/login",
        Body::Json(&json!({"username": "root", "password": PASSWORD})),
        &[],
    );
    assert_eq!(login.status, 200);
    assert!(login.header("www-authenticate").is_none());
    let cookie = login
        .header("set-cookie")
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    let csrf = login.body["csrf"].as_str().unwrap().to_owned();
    let me = send(&d, "GET", "/api/v1/me", Body::None, &[("cookie", &cookie)]);
    assert_eq!(me.status, 200);
    assert_eq!(me.body["via"], "session");
    assert_eq!(me.body["username"], "root");
    let without_csrf = send(
        &d,
        "POST",
        runs_path(),
        Body::Json(&body),
        &[("cookie", &cookie)],
    );
    assert_eq!(without_csrf.status, 403);
    let with_csrf = send(
        &d,
        "POST",
        runs_path(),
        Body::Json(&body),
        &[("cookie", &cookie), ("x-sentinel-csrf", &csrf)],
    );
    assert_eq!(with_csrf.status, 201, "{}", with_csrf.body);
    // A refused password login carries no bearer challenge.
    let refused = send(
        &d,
        "POST",
        "/api/v1/login",
        Body::Json(&json!({"username": "root", "password": "wrong"})),
        &[],
    );
    assert_eq!(refused.status, 401);
    assert!(refused.header("www-authenticate").is_none());
}

#[test]
fn oauth_pages_carry_the_security_headers() {
    let d = deployment();
    let page = send(&d, "GET", "/oauth/authorize", Body::None, &[]);
    assert_eq!(
        page.header("content-type"),
        Some("text/html; charset=utf-8")
    );
    assert_eq!(page.header("x-frame-options"), Some("DENY"));
    assert_eq!(page.header("referrer-policy"), Some("no-referrer"));
    assert_eq!(page.header("cache-control"), Some("no-store"));
    let csp = page.header("content-security-policy").unwrap();
    assert!(csp.contains("frame-ancestors 'none'") && !csp.contains("form-action"));
}

/// P09-2: one client flooding revocation (or device authorization) takes
/// its own budget, not everyone's; another client's refresh still goes
/// through. Loopback is a proxy address, so `X-Forwarded-For` names the
/// client here as a reverse proxy would.
#[test]
fn a_flooding_client_cannot_stop_another_clients_refresh() {
    let d = deployment();
    let minted = grant(&d, d.dev, Scopes::CLI_DEFAULT);
    let flood = format!("client_id={CLI_CLIENT_ID}&token=garbage");
    let mut refused = 0;
    for _ in 0..120 {
        let reply = send(
            &d,
            "POST",
            "/oauth/revoke",
            Body::Form(&flood),
            &[("x-forwarded-for", "198.51.100.1")],
        );
        if reply.status == 503 {
            assert_eq!(reply.body["error"], "temporarily_unavailable");
            refused += 1;
        }
    }
    assert!(refused > 0, "the flooding client was never limited");
    let device_flood = format!("client_id={CLI_CLIENT_ID}");
    for _ in 0..40 {
        send(
            &d,
            "POST",
            "/oauth/device_authorization",
            Body::Form(&device_flood),
            &[("x-forwarded-for", "198.51.100.1")],
        );
    }
    let refreshed = send(
        &d,
        "POST",
        "/oauth/token",
        Body::Form(&refresh_form(&minted.refresh)),
        &[("x-forwarded-for", "203.0.113.7")],
    );
    assert_eq!(refreshed.status, 200, "{}", refreshed.body);
    // And another client can still start a device login.
    let device = send(
        &d,
        "POST",
        "/oauth/device_authorization",
        Body::Form(&device_flood),
        &[("x-forwarded-for", "203.0.113.8")],
    );
    assert_eq!(device.status, 200, "{}", device.body);
}

/// P09-3: a store too busy to check a credential is `rate_limited`, never
/// `401` — a `401` would make an OAuth client spend its refresh token.
#[test]
fn a_busy_store_is_rate_limited_not_unauthenticated() {
    let d = deployment();
    let minted = grant(&d, d.dev, Scopes::CLI_DEFAULT);
    let auth = bearer(&minted.access);
    assert_eq!(get(&d, "/api/v1/me", &auth).status, 200);
    // Hold every reader for longer than read admission waits.
    let (hold, held) = (
        std::sync::Arc::new(std::sync::Barrier::new(sentinel_store::READER_LIMIT + 1)),
        std::time::Duration::from_millis(sentinel_store::READ_ADMISSION.as_millis() as u64 + 2_000),
    );
    let holders: Vec<_> = (0..sentinel_store::READER_LIMIT)
        .map(|_| {
            let (store, hold) = (
                std::sync::Arc::clone(&d.store),
                std::sync::Arc::clone(&hold),
            );
            std::thread::spawn(move || {
                store
                    .read(|_| {
                        hold.wait();
                        std::thread::sleep(held);
                        Ok(())
                    })
                    .unwrap();
            })
        })
        .collect();
    hold.wait();
    let busy = get(&d, "/api/v1/me", &auth);
    assert_ne!(busy.status, 401, "{}", busy.body);
    assert_eq!(busy.status, 429, "{}", busy.body);
    assert_eq!(busy.body["code"], "rate_limited");
    assert!(busy.header("www-authenticate").is_none());
    for holder in holders {
        holder.join().unwrap();
    }
    assert_eq!(get(&d, "/api/v1/me", &auth).status, 200);
}

/// P09-4: with a path-carrying `public_url`, every URL handed out stays
/// inside the issuer, the RFC 8414 / 9728 well-known locations answer, and
/// a proxy that forwards the prefix unstripped still reaches the routes.
#[test]
fn a_path_issuer_keeps_every_url_inside_its_mount() {
    let d = deployment_under(Some("/sentinel"));
    let issuer = format!("{}/sentinel", d.base);
    for path in [
        "/.well-known/oauth-authorization-server",
        "/.well-known/oauth-authorization-server/sentinel",
        "/sentinel/.well-known/oauth-authorization-server",
    ] {
        let reply = send(&d, "GET", path, Body::None, &[]);
        assert_eq!(reply.status, 200, "{path}");
        let metadata: Metadata = serde_json::from_value(reply.body).unwrap();
        assert_eq!(metadata.issuer, issuer, "{path}");
        assert_eq!(
            metadata.device_authorization_endpoint,
            format!("{issuer}/oauth/device_authorization")
        );
    }
    for path in [
        "/.well-known/oauth-protected-resource/api/v1",
        "/.well-known/oauth-protected-resource/sentinel/api/v1",
    ] {
        let reply = send(&d, "GET", path, Body::None, &[]);
        assert_eq!(reply.status, 200, "{path}");
        assert_eq!(reply.body["resource"], format!("{issuer}/api/v1"));
    }
    // The challenge names the RFC 9728 location of the resource.
    let anonymous = send(&d, "GET", "/sentinel/api/v1/me", Body::None, &[]);
    assert_eq!(anonymous.status, 401);
    assert_eq!(
        anonymous.header("www-authenticate"),
        Some(
            format!(
                "Bearer realm=\"sentinel\", resource_metadata=\"{}/.well-known/oauth-protected-resource/sentinel/api/v1\"",
                d.base
            )
            .as_str()
        )
    );
    // The sign-in and the device forms post inside the mount.
    for path in ["/device", "/sentinel/device"] {
        let page = send(&d, "GET", path, Body::None, &[]);
        assert_eq!(page.status, 200, "{path}");
        let text = page.body.as_str().unwrap();
        assert!(
            text.contains(&format!("fetch(\"{issuer}/api/v1/login\"")),
            "{text}"
        );
        assert!(!text.contains("fetch(\"/api"), "{text}");
    }
    let cookie = {
        let reply = send(
            &d,
            "POST",
            "/sentinel/api/v1/login",
            Body::Json(&json!({"username": "root", "password": PASSWORD})),
            &[],
        );
        assert_eq!(reply.status, 200, "{}", reply.body);
        reply
            .header("set-cookie")
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned()
    };
    let entry = send(&d, "GET", "/device", Body::None, &[("cookie", &cookie)]);
    assert!(
        entry
            .body
            .as_str()
            .unwrap()
            .contains(&format!("action=\"{issuer}/device\""))
    );
    // A foreign well-known path is still nothing.
    let other = send(
        &d,
        "GET",
        "/.well-known/oauth-authorization-server/other",
        Body::None,
        &[],
    );
    assert_eq!(other.status, 404);
}
