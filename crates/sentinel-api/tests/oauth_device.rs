//! O03 over real HTTP on loopback: `POST /oauth/device_authorization`, the
//! device-code grant with `authorization_pending`, `slow_down` (and a
//! growing interval), `access_denied`, `expired_token` and single
//! redemption, the pending cap, and the `/device` approval page with its
//! session requirement, form token, `Origin` check and wrong-code lockout.
//! No HTML page ever carries the device code.
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
    oauth::{self, ClientSpec, GrantKind, Minted, NewGrant},
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
        github_sign_in: None,
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

const DEVICE_GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";

/// A started device request as the client sees it.
struct Started {
    device_code: String,
    /// Canonical (no dash).
    user_code: String,
}

fn start(d: &Deployment, form: &str) -> Reply {
    send(
        d,
        "POST",
        "/oauth/device_authorization",
        Body::Form(form),
        &[],
    )
}

fn started(d: &Deployment) -> Started {
    let reply = start(d, &format!("client_id={CLI_CLIENT_ID}"));
    assert_eq!(reply.status, 200, "{}", reply.body);
    let display = reply.body["user_code"].as_str().unwrap();
    Started {
        device_code: reply.body["device_code"].as_str().unwrap().to_owned(),
        user_code: forms::normalize_user_code(display).unwrap(),
    }
}

fn poll(d: &Deployment, device_code: &str) -> Reply {
    send(
        d,
        "POST",
        "/oauth/token",
        Body::Form(&format!(
            "grant_type={DEVICE_GRANT}&client_id={CLI_CLIENT_ID}&device_code={device_code}"
        )),
        &[],
    )
}

fn oauth_error(reply: &Reply) -> &str {
    reply.body["error"].as_str().unwrap_or("")
}

/// A root session cookie.
fn sign_in(d: &Deployment) -> String {
    let login = send(
        d,
        "POST",
        "/api/v1/login",
        Body::Json(&json!({"username": "root", "password": PASSWORD})),
        &[],
    );
    assert_eq!(login.status, 200);
    login
        .header("set-cookie")
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned()
}

fn html(reply: &Reply) -> &str {
    reply.body.as_str().unwrap_or("")
}

/// The approval page for a user code, and its form token.
fn approval_page(d: &Deployment, cookie: &str, user_code: &str) -> (Reply, String) {
    let page = send(
        d,
        "GET",
        &format!("/device?user_code={user_code}"),
        Body::None,
        &[("cookie", cookie)],
    );
    assert_eq!(page.status, 200, "{}", html(&page));
    let text = html(&page);
    let at = text
        .find("name=\"form_token\" value=\"")
        .expect("form token")
        + 25;
    let token = text[at..at + 64].to_owned();
    (page, token)
}

fn decide(d: &Deployment, cookie: &str, form: &str) -> Reply {
    send(
        d,
        "POST",
        "/device",
        Body::Form(form),
        &[("cookie", cookie)],
    )
}

/// Every HTML page must be free of the device code, in text or as its hex.
fn assert_no_device_code(pages: &[&Reply], device_code: &str) {
    let hex = device_code.strip_prefix("sntl_dc_").unwrap();
    for page in pages {
        let text = html(page);
        assert!(!text.contains("sntl_dc_"), "{text}");
        assert!(!text.contains(hex), "{text}");
    }
}

#[test]
fn a_device_login_is_approved_on_the_page_and_redeemed_once() {
    let d = deployment();
    let reply = start(
        &d,
        &format!("client_id={CLI_CLIENT_ID}&scope=runs%3Aread+logs%3Aread"),
    );
    assert_eq!(reply.status, 200, "{}", reply.body);
    assert_eq!(reply.header("pragma"), Some("no-cache"));
    assert_eq!(reply.header("cache-control"), Some("no-store"));
    let device_code = reply.body["device_code"].as_str().unwrap().to_owned();
    assert!(device_code.starts_with("sntl_dc_") && device_code.len() == 72);
    let display = reply.body["user_code"].as_str().unwrap();
    assert_eq!(display.len(), 9);
    assert_eq!(&display[4..5], "-");
    let user_code = forms::normalize_user_code(display).unwrap();
    assert_eq!(reply.body["verification_uri"], format!("{}/device", d.base));
    assert_eq!(
        reply.body["verification_uri_complete"],
        format!("{}/device?user_code={user_code}", d.base)
    );
    assert_eq!(reply.body["interval"], 5);
    assert_eq!(reply.body["expires_in"], 600);

    let cookie = sign_in(&d);
    let entry = send(&d, "GET", "/device", Body::None, &[("cookie", &cookie)]);
    assert_eq!(entry.status, 200);
    assert!(html(&entry).contains("name=\"user_code\""));
    // The user code as the person types it: lower case, with the dash.
    let (page, token) = approval_page(&d, &cookie, &display.to_ascii_lowercase());
    let text = html(&page);
    assert!(text.contains("Sentinel CLI"));
    assert!(text.contains(display));
    assert!(text.contains("root"));
    assert!(text.contains("scope_runs:read") && text.contains("scope_logs:read"));
    assert!(!text.contains("scope_runs:write"));
    assert_eq!(page.header("x-frame-options"), Some("DENY"));
    // Approve runs:read only.
    let done = decide(
        &d,
        &cookie,
        &format!("user_code={user_code}&form_token={token}&action=approve&scope_runs%3Aread=1"),
    );
    assert_eq!(done.status, 200, "{}", html(&done));
    assert!(html(&done).contains("Device connected"));

    let issued = poll(&d, &device_code);
    assert_eq!(issued.status, 200, "{}", issued.body);
    assert_eq!(issued.header("pragma"), Some("no-cache"));
    assert_eq!(issued.body["scope"], "runs:read");
    let access = issued.body["access_token"].as_str().unwrap();
    let authorization = format!("Bearer {access}");
    let runs = get(&d, "/api/v1/tenants/acme/repos/app/runs", &authorization);
    assert_eq!(runs.status, 200, "{}", runs.body);
    let me = get(&d, "/api/v1/me", &authorization);
    assert_eq!(me.body["via"], "oauth");
    assert_eq!(me.body["scopes"], json!(["runs:read"]));
    assert_eq!(me.body["username"], "root");

    // Redeemed once: every later poll is invalid_grant.
    let again = poll(&d, &device_code);
    assert_eq!(again.status, 400);
    assert_eq!(oauth_error(&again), "invalid_grant");
    // The page no longer finds the code.
    let gone = send(
        &d,
        "GET",
        &format!("/device?user_code={user_code}"),
        Body::None,
        &[("cookie", &cookie)],
    );
    assert_eq!(gone.status, 404);
    assert_no_device_code(&[&entry, &page, &done, &gone], &device_code);
}

#[test]
fn polling_answers_pending_then_slows_a_fast_poller_down() {
    let d = deployment();
    let s = started(&d);
    let pending = poll(&d, &s.device_code);
    assert_eq!(pending.status, 400);
    assert_eq!(oauth_error(&pending), "authorization_pending");
    // Polling again at once is too fast, and again: the interval grows by
    // five seconds each time (5 -> 10 -> 15 s).
    for _ in 0..2 {
        let fast = poll(&d, &s.device_code);
        assert_eq!(oauth_error(&fast), "slow_down", "{}", fast.body);
    }
    // Waiting the original five seconds is not enough any more.
    std::thread::sleep(std::time::Duration::from_millis(5_200));
    let still = poll(&d, &s.device_code);
    assert_eq!(oauth_error(&still), "slow_down");
    // Unknown and malformed device codes are invalid_grant, never pending.
    let unknown = poll(&d, &forms::format(Kind::Device, &Secret::generate()));
    assert_eq!(oauth_error(&unknown), "invalid_grant");
    let malformed = poll(&d, "sntl_rt_00");
    assert_eq!(oauth_error(&malformed), "invalid_grant");
    let missing = send(
        &d,
        "POST",
        "/oauth/token",
        Body::Form(&format!(
            "grant_type={DEVICE_GRANT}&client_id={CLI_CLIENT_ID}"
        )),
        &[],
    );
    assert_eq!(oauth_error(&missing), "invalid_request");
}

#[test]
fn a_denied_request_answers_access_denied() {
    let d = deployment();
    let s = started(&d);
    let cookie = sign_in(&d);
    let (_, token) = approval_page(&d, &cookie, &s.user_code);
    let done = decide(
        &d,
        &cookie,
        &format!("user_code={}&form_token={token}&action=deny", s.user_code),
    );
    assert_eq!(done.status, 200);
    assert!(html(&done).contains("denied"));
    let denied = poll(&d, &s.device_code);
    assert_eq!(denied.status, 400);
    assert_eq!(oauth_error(&denied), "access_denied");
}

#[test]
fn an_expired_request_answers_expired_token() {
    let d = deployment();
    let past = UnixMillis(UnixMillis::now().0 - oauth::DEVICE_LIFETIME_MS - 1_000);
    let seeded = oauth::device::begin(
        &d.store,
        CLI_CLIENT_ID,
        Scopes::RUNS_READ,
        Audience::Api,
        past,
    )
    .unwrap();
    let expired = poll(&d, &forms::format(Kind::Device, &seeded.device));
    assert_eq!(expired.status, 400);
    assert_eq!(oauth_error(&expired), "expired_token");
    // Its user code is no longer approvable either.
    let cookie = sign_in(&d);
    let page = send(
        &d,
        "GET",
        &format!("/device?user_code={}", seeded.user_code),
        Body::None,
        &[("cookie", &cookie)],
    );
    assert_eq!(page.status, 404);
}

#[test]
fn the_pending_cap_answers_429_slow_down() {
    let d = deployment();
    let now = UnixMillis::now();
    for _ in 0..oauth::MAX_PENDING_DEVICE {
        oauth::device::begin(
            &d.store,
            CLI_CLIENT_ID,
            Scopes::RUNS_READ,
            Audience::Api,
            now,
        )
        .unwrap();
    }
    let full = start(&d, &format!("client_id={CLI_CLIENT_ID}"));
    assert_eq!(full.status, 429);
    assert_eq!(oauth_error(&full), "slow_down");
    assert!(full.header("retry-after").is_some());
}

#[test]
fn clients_scopes_and_resources_are_checked() {
    let d = deployment();
    oauth::register_client(
        &d.store,
        &ClientSpec {
            id: "no-device",
            name: "Browser only",
            first_party: false,
            loopback: false,
            redirect_path: None,
            device: false,
            max_scopes: Scopes::CLI_DEFAULT,
        },
        &[],
    )
    .unwrap();
    for (form, expected) in [
        ("client_id=no-device".to_owned(), "unauthorized_client"),
        ("client_id=nobody".to_owned(), "invalid_client"),
        ("scope=runs%3Aread".to_owned(), "invalid_request"),
        (
            format!("client_id={CLI_CLIENT_ID}&scope=runs%3Afly"),
            "invalid_scope",
        ),
        (
            format!("client_id={CLI_CLIENT_ID}&resource=https%3A%2F%2Felsewhere%2Fapi%2Fv1"),
            "invalid_target",
        ),
        (
            format!("client_id={CLI_CLIENT_ID}&client_id={CLI_CLIENT_ID}"),
            "invalid_request",
        ),
    ] {
        let reply = start(&d, &form);
        assert_eq!(oauth_error(&reply), expected, "{form}: {}", reply.body);
    }
    let s = started(&d);
    let foreign = send(
        &d,
        "POST",
        "/oauth/token",
        Body::Form(&format!(
            "grant_type={DEVICE_GRANT}&client_id=no-device&device_code={}",
            s.device_code
        )),
        &[],
    );
    assert_eq!(oauth_error(&foreign), "unauthorized_client");
}

#[test]
fn the_page_requires_a_session_and_its_own_form() {
    let d = deployment();
    let s = started(&d);
    // No session, or only a bearer credential or access token: sign in.
    let access = grant(&d, d.root, Scopes::CLI_DEFAULT);
    let token = format!("Bearer {}", d.token);
    let oauth_bearer = bearer(&access.access);
    let path = format!("/device?user_code={}", s.user_code);
    let mut pages = Vec::new();
    for headers in [
        Vec::new(),
        vec![("authorization", token.as_str())],
        vec![("authorization", oauth_bearer.as_str())],
    ] {
        let page = send(&d, "GET", &path, Body::None, &headers);
        assert_eq!(page.status, 200);
        assert!(html(&page).contains("sentinel-sign-in"));
        assert!(!html(&page).contains("form_token"));
        pages.push(page);
    }
    let unsigned = send(
        &d,
        "POST",
        "/device",
        Body::Form(&format!(
            "user_code={}&action=approve&scope_runs%3Aread=1",
            s.user_code
        )),
        &[],
    );
    assert!(html(&unsigned).contains("sentinel-sign-in"));

    let cookie = sign_in(&d);
    let (page, token) = approval_page(&d, &cookie, &s.user_code);
    let approve = format!(
        "user_code={}&action=approve&scope_runs%3Aread=1&form_token=",
        s.user_code
    );
    // A missing or foreign form token, or a foreign Origin, decides nothing.
    let missing = decide(&d, &cookie, &approve);
    assert_eq!(missing.status, 403);
    let wrong = decide(&d, &cookie, &format!("{approve}{}", "0".repeat(64)));
    assert_eq!(wrong.status, 403);
    let foreign = send(
        &d,
        "POST",
        "/device",
        Body::Form(&format!("{approve}{token}")),
        &[("cookie", &cookie), ("origin", "https://evil.example")],
    );
    assert_eq!(foreign.status, 403);
    assert_eq!(
        oauth_error(&poll(&d, &s.device_code)),
        "authorization_pending"
    );
    // Narrowing to a tenant that does not exist is refused too.
    let nowhere = decide(&d, &cookie, &format!("{approve}{token}&tenant=nowhere"));
    assert_eq!(nowhere.status, 403);
    // The same-origin form works.
    let own = send(
        &d,
        "POST",
        "/device",
        Body::Form(&format!("{approve}{token}&tenant=acme&repo=app")),
        &[("cookie", &cookie), ("origin", &d.base)],
    );
    assert_eq!(own.status, 200, "{}", html(&own));
    std::thread::sleep(std::time::Duration::from_millis(5_100));
    let issued = poll(&d, &s.device_code);
    assert_eq!(issued.status, 200, "{}", issued.body);
    let narrowed = format!("Bearer {}", issued.body["access_token"].as_str().unwrap());
    let me = get(&d, "/api/v1/me", &narrowed);
    assert_eq!(me.body["tenant"], d.tenant.to_string());
    assert_eq!(me.body["repo"], d.repo.to_string());
    let refs: Vec<&Reply> = pages
        .iter()
        .chain([&unsigned, &page, &missing, &wrong, &foreign, &nowhere, &own])
        .collect();
    assert_no_device_code(&refs, &s.device_code);
}

#[test]
fn five_wrong_user_codes_lock_the_account_out_for_a_while() {
    let d = deployment();
    let s = started(&d);
    let cookie = sign_in(&d);
    let (_, token) = approval_page(&d, &cookie, &s.user_code);
    let wrong = if s.user_code == "BCDFGHJK" {
        "ZXWVTSRQ"
    } else {
        "BCDFGHJK"
    };
    for n in 0..4 {
        let page = send(
            &d,
            "GET",
            &format!("/device?user_code={wrong}"),
            Body::None,
            &[("cookie", &cookie)],
        );
        assert_eq!(page.status, 404, "attempt {n}");
    }
    // Malformed codes and wrong codes on the form count as well.
    let posted = decide(
        &d,
        &cookie,
        &format!("user_code=AEIOU123&form_token={token}&action=approve&scope_runs%3Aread=1"),
    );
    assert_eq!(posted.status, 400);
    // Now even the right code is refused, on the page and on the form.
    let locked = send(
        &d,
        "GET",
        &format!("/device?user_code={}", s.user_code),
        Body::None,
        &[("cookie", &cookie)],
    );
    assert_eq!(locked.status, 429);
    let locked_post = decide(
        &d,
        &cookie,
        &format!(
            "user_code={}&form_token={token}&action=approve&scope_runs%3Aread=1",
            s.user_code
        ),
    );
    assert_eq!(locked_post.status, 429);
    assert_eq!(
        oauth_error(&poll(&d, &s.device_code)),
        "authorization_pending"
    );
    assert_no_device_code(&[&posted, &locked, &locked_post], &s.device_code);
}

/// P09-1: narrowing an approval to a tenant or repository the account has
/// no part in answers exactly as narrowing to one that does not exist, and
/// each such answer counts toward the wrong-code lockout.
#[test]
fn foreign_and_missing_narrowings_are_indistinguishable_and_limited() {
    let d = deployment();
    // An organization root does not belong to, with a repository.
    let (globex, secret) = (TenantId::new(), RepoId::new());
    let root = d.root;
    let now = UnixMillis::now();
    d.store
        .writer()
        .write(move |tx| {
            let admin = Principal::new(root, P::ALL, None, None);
            auth::create_namespace(
                tx,
                admin,
                globex,
                Namespace::parse("globex").unwrap(),
                NamespaceKind::Organization,
                now,
            )?;
            auth::create_repo(tx, admin, globex, secret, "secret", now)
        })
        .unwrap();
    let s = started(&d);
    let cookie = sign_in(&d);
    let (_, token) = approval_page(&d, &cookie, &s.user_code);
    let attempt = |terms: &str| {
        decide(
            &d,
            &cookie,
            &format!(
                "user_code={}&form_token={token}&action=approve&scope_runs%3Aread=1&{terms}",
                s.user_code
            ),
        )
    };
    let foreign = attempt("tenant=globex");
    let missing = attempt("tenant=nowhere");
    assert_eq!(foreign.status, 403);
    assert_eq!(
        (foreign.status, html(&foreign)),
        (missing.status, html(&missing))
    );
    let foreign_repo = attempt("tenant=globex&repo=secret");
    let missing_repo = attempt("tenant=acme&repo=nothing");
    assert_eq!(
        (foreign_repo.status, html(&foreign_repo)),
        (missing.status, html(&missing))
    );
    assert_eq!(
        (missing_repo.status, html(&missing_repo)),
        (missing.status, html(&missing))
    );
    // Four refusals so far; the fifth locks the account out of the page.
    assert_eq!(attempt("tenant=elsewhere").status, 403);
    assert_eq!(attempt("tenant=acme").status, 429);
    // Nothing was spent: the request is still pending.
    assert_eq!(
        oauth_error(&poll(&d, &s.device_code)),
        "authorization_pending"
    );
}
