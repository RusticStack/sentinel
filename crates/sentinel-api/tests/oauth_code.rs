//! O01 over real HTTP on loopback, driving a "browser" with a session
//! cookie: sign-in without a session, error pages that never redirect to an
//! untrusted client, RFC 6749 error redirects with `state` and `iss`, the
//! consent form's anti-forgery checks, deny and approve, the single-use
//! code exchange with replay revocation, and the page security headers.
//!
//! The harness is the minimal copy of `oauth_core.rs`'s.

use std::sync::Arc;

use sentinel_auth::{
    oauth::{self as forms, Kind, pkce},
    secret::Secret,
};
use sentinel_core::{
    RepoId, TenantId, UnixMillis, UserId,
    auth::{Namespace, Permissions as P, Principal, Role},
};
use sentinel_link::{controller::Controller, identity::Identity};
use sentinel_protocol::oauth::CLI_CLIENT_ID;
use sentinel_store::{
    Durability, Store,
    auth::{self, Authority, NamespaceKind, provisioning},
    local_auth::{self, Event},
    logs::LogStore,
    objects::Objects,
};
use serde_json::{Value, json};

pub const PASSWORD: &str = "correct horse battery staple";
const REDIRECT: &str = "http://127.0.0.1:49152/callback";
const STATE: &str = "af0ifjsldkj";

/// Authorization request parameters, in order.
type Pairs = Vec<(&'static str, String)>;

pub struct Deployment {
    _dir: tempfile::TempDir,
    pub store: Arc<Store>,
    _controller: Controller,
    server: Option<sentinel_api::Server>,
    /// `http://127.0.0.1:PORT`; also the issuer.
    pub base: String,
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

/// Super admin `root` administering `acme` (repository `app`); `dev`, an
/// operator of `acme` with its own password, and no platform rights.
pub fn deployment() -> Deployment {
    let dir = tempfile::tempdir().unwrap();
    let store =
        Arc::new(Store::open(dir.path().join("metadata.sqlite"), Durability::Normal).unwrap());
    let logs = Arc::new(LogStore::open(dir.path().join("logs")).unwrap());
    let objects = Arc::new(Objects::open(dir.path()).unwrap());
    let now = UnixMillis::now();
    let root = local_auth::bootstrap(&store, "root", "Root", PASSWORD.as_bytes(), now).unwrap();
    let (dev, tenant, repo) = (UserId::new(), TenantId::new(), RepoId::new());
    let phc = sentinel_auth::password::hash(PASSWORD.as_bytes()).unwrap();
    store
        .writer()
        .write(move |tx| {
            let admin = Principal::new(root, P::ALL, None, None);
            provisioning::insert_human(tx, dev, "Dev", false, now)?;
            local_auth::provision_credential(tx, Authority::HostLocal, dev, "dev", &phc, now)?;
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

    fn text(&self) -> &str {
        self.body.as_str().unwrap_or_default()
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
        (_, body) => {
            let mut request = agent.post(&url);
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

pub fn bearer(access: &Secret) -> String {
    format!("Bearer {}", forms::format(Kind::Access, access))
}

/// A password session: the `cookie` request header value.
fn sign_in(d: &Deployment, username: &str) -> String {
    let reply = send(
        d,
        "POST",
        "/api/v1/login",
        Body::Json(&json!({ "username": username, "password": PASSWORD })),
        &[],
    );
    assert_eq!(reply.status, 200);
    reply
        .header("set-cookie")
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned()
}

fn encode(pairs: &[(&str, &str)]) -> String {
    form_urlencoded::Serializer::new(String::new())
        .extend_pairs(pairs)
        .finish()
}

/// A complete, valid authorization request for the CLI client.
fn request_pairs(challenge: &str) -> Pairs {
    vec![
        ("response_type", "code".into()),
        ("client_id", CLI_CLIENT_ID.into()),
        ("redirect_uri", REDIRECT.into()),
        ("state", STATE.into()),
        ("code_challenge", challenge.into()),
        ("code_challenge_method", "S256".into()),
        ("scope", "runs:read logs:read".into()),
    ]
}

fn authorize_path(pairs: &[(&str, String)]) -> String {
    let borrowed: Vec<(&str, &str)> = pairs.iter().map(|(k, v)| (*k, v.as_str())).collect();
    format!("/oauth/authorize?{}", encode(&borrowed))
}

fn with(mut pairs: Pairs, name: &'static str, value: Option<&str>) -> Pairs {
    pairs.retain(|(k, _)| *k != name);
    if let Some(value) = value {
        pairs.push((name, value.to_owned()));
    }
    pairs
}

/// The query of a `303` back to the client, which must target `REDIRECT`.
fn returned(reply: &Reply) -> Vec<(String, String)> {
    assert_eq!(reply.status, 303, "{:?}", reply.body);
    let location = reply.header("location").expect("location");
    let (target, query) = location.split_once('?').expect("query");
    assert_eq!(target, REDIRECT);
    form_urlencoded::parse(query.as_bytes())
        .into_owned()
        .collect()
}

fn param<'a>(pairs: &'a [(String, String)], name: &str) -> Option<&'a str> {
    pairs
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
}

/// Every hidden field of the consent page, unescaped.
fn hidden_fields(page: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for piece in page.split("<input type=\"hidden\" name=\"").skip(1) {
        let (name, rest) = piece.split_once('"').unwrap();
        let value = rest
            .strip_prefix(" value=\"")
            .unwrap()
            .split_once('"')
            .unwrap()
            .0;
        let value = value
            .replace("&quot;", "\"")
            .replace("&#39;", "'")
            .replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&amp;", "&");
        out.push((name.to_owned(), value));
    }
    out
}

fn assert_page_headers(reply: &Reply) {
    let csp = reply.header("content-security-policy").unwrap();
    assert!(csp.contains("default-src 'none'"), "{csp}");
    assert!(csp.contains("frame-ancestors 'none'"), "{csp}");
    assert_eq!(reply.header("x-frame-options"), Some("DENY"));
    assert_eq!(reply.header("referrer-policy"), Some("no-referrer"));
    assert_eq!(reply.header("cache-control"), Some("no-store"));
    assert!(
        reply
            .header("content-type")
            .unwrap()
            .starts_with("text/html")
    );
}

/// Render consent for `cookie` and return the hidden fields to post back.
fn consent(d: &Deployment, cookie: &str, pairs: &[(&str, String)]) -> Vec<(String, String)> {
    let page = send(
        d,
        "GET",
        &authorize_path(pairs),
        Body::None,
        &[("cookie", cookie)],
    );
    assert_eq!(page.status, 200, "{:?}", page.body);
    assert_page_headers(&page);
    let fields = hidden_fields(page.text());
    assert!(fields.iter().any(|(k, _)| k == "form_token"));
    fields
}

fn post_consent(
    d: &Deployment,
    cookie: Option<&str>,
    origin: Option<&str>,
    fields: &[(String, String)],
    extra: &[(&str, &str)],
) -> Reply {
    let mut pairs: Vec<(&str, &str)> = fields
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    pairs.extend_from_slice(extra);
    let body = encode(&pairs);
    let mut headers = Vec::new();
    if let Some(cookie) = cookie {
        headers.push(("cookie", cookie));
    }
    if let Some(origin) = origin {
        headers.push(("origin", origin));
    }
    send(d, "POST", "/oauth/authorize", Body::Form(&body), &headers)
}

fn exchange(d: &Deployment, code: &str, verifier: &str) -> Reply {
    let body = encode(&[
        ("grant_type", "authorization_code"),
        ("client_id", CLI_CLIENT_ID),
        ("code", code),
        ("redirect_uri", REDIRECT),
        ("code_verifier", verifier),
    ]);
    send(d, "POST", "/oauth/token", Body::Form(&body), &[])
}

#[test]
fn without_a_session_the_endpoint_asks_to_sign_in_and_sets_nothing() {
    let d = deployment();
    let challenge = pkce::challenge(&pkce::verifier());
    let page = send(
        &d,
        "GET",
        &authorize_path(&request_pairs(&challenge)),
        Body::None,
        &[],
    );
    assert_eq!(page.status, 200);
    assert_page_headers(&page);
    assert!(page.text().contains("/api/v1/login"));
    assert!(page.text().contains("Sentinel CLI"));
    assert!(page.header("set-cookie").is_none());
    assert!(page.header("location").is_none());
    // Nothing reached the store: no code, no audit row about consent.
    let codes: i64 = d
        .store
        .read(|c| Ok(c.query_row("SELECT count(*) FROM oauth_codes", [], |r| r.get(0))?))
        .unwrap();
    assert_eq!(codes, 0);
}

#[test]
fn an_untrusted_client_or_redirect_gets_a_page_and_never_a_redirect() {
    let d = deployment();
    let cookie = sign_in(&d, "root");
    let challenge = pkce::challenge(&pkce::verifier());
    let base = request_pairs(&challenge);
    let cases: Vec<(&str, Pairs)> = vec![
        (
            "unknown client",
            with(base.clone(), "client_id", Some("nobody")),
        ),
        ("no client", with(base.clone(), "client_id", None)),
        ("no redirect", with(base.clone(), "redirect_uri", None)),
        (
            "localhost",
            with(
                base.clone(),
                "redirect_uri",
                Some("http://localhost:49152/callback"),
            ),
        ),
        (
            "https loopback",
            with(
                base.clone(),
                "redirect_uri",
                Some("https://127.0.0.1:49152/callback"),
            ),
        ),
        (
            "missing port",
            with(
                base.clone(),
                "redirect_uri",
                Some("http://127.0.0.1/callback"),
            ),
        ),
        (
            "wrong path",
            with(
                base.clone(),
                "redirect_uri",
                Some("http://127.0.0.1:49152/other"),
            ),
        ),
        (
            "query-bearing",
            with(
                base.clone(),
                "redirect_uri",
                Some("http://127.0.0.1:49152/callback?x=1"),
            ),
        ),
        (
            "fragment",
            with(
                base.clone(),
                "redirect_uri",
                Some("http://127.0.0.1:49152/callback#x"),
            ),
        ),
        (
            "foreign host",
            with(
                base.clone(),
                "redirect_uri",
                Some("https://evil.example/callback"),
            ),
        ),
    ];
    for (what, pairs) in cases {
        for cookie in [None, Some(cookie.as_str())] {
            let headers: Vec<(&str, &str)> = cookie.map(|c| ("cookie", c)).into_iter().collect();
            let reply = send(&d, "GET", &authorize_path(&pairs), Body::None, &headers);
            assert_eq!(reply.status, 400, "{what}");
            assert!(reply.header("location").is_none(), "{what}");
            assert_page_headers(&reply);
        }
    }
    // A repeated parameter is malformed, also without a redirect.
    let reply = send(
        &d,
        "GET",
        &format!(
            "{}&client_id=sentinel-cli",
            authorize_path(&request_pairs(&challenge))
        ),
        Body::None,
        &[("cookie", &cookie)],
    );
    assert_eq!(reply.status, 400);
    assert!(reply.header("location").is_none());
}

#[test]
fn other_request_errors_redirect_with_error_state_and_iss() {
    let d = deployment();
    let cookie = sign_in(&d, "root");
    let challenge = pkce::challenge(&pkce::verifier());
    let base = request_pairs(&challenge);
    let resource = format!("{}/api/v1", d.base);
    let cases: Vec<(&str, Pairs, &str)> = vec![
        (
            "missing challenge",
            with(base.clone(), "code_challenge", None),
            "invalid_request",
        ),
        (
            "malformed challenge",
            with(base.clone(), "code_challenge", Some("short")),
            "invalid_request",
        ),
        (
            "plain method",
            with(base.clone(), "code_challenge_method", Some("plain")),
            "invalid_request",
        ),
        (
            "missing method",
            with(base.clone(), "code_challenge_method", None),
            "invalid_request",
        ),
        (
            "token response type",
            with(base.clone(), "response_type", Some("token")),
            "unsupported_response_type",
        ),
        (
            "unknown scope",
            with(base.clone(), "scope", Some("runs:read bogus")),
            "invalid_scope",
        ),
        (
            "foreign resource",
            with(
                base.clone(),
                "resource",
                Some("https://other.example/api/v1"),
            ),
            "invalid_target",
        ),
    ];
    for (what, pairs, error) in cases {
        let reply = send(
            &d,
            "GET",
            &authorize_path(&pairs),
            Body::None,
            &[("cookie", &cookie)],
        );
        let back = returned(&reply);
        assert_eq!(param(&back, "error"), Some(error), "{what}");
        assert_eq!(param(&back, "state"), Some(STATE), "{what}");
        assert_eq!(param(&back, "iss"), Some(d.base.as_str()), "{what}");
        assert!(param(&back, "code").is_none(), "{what}");
    }
    // Without state the redirect still names the error and the issuer.
    let reply = send(
        &d,
        "GET",
        &authorize_path(&with(base.clone(), "state", None)),
        Body::None,
        &[("cookie", &cookie)],
    );
    let back = returned(&reply);
    assert_eq!(param(&back, "error"), Some("invalid_request"));
    assert_eq!(param(&back, "state"), None);
    assert_eq!(param(&back, "iss"), Some(d.base.as_str()));

    // The right resource is accepted; platform:admin needs a super admin.
    let ok = send(
        &d,
        "GET",
        &authorize_path(&with(base.clone(), "resource", Some(&resource))),
        Body::None,
        &[("cookie", &cookie)],
    );
    assert_eq!(ok.status, 200);
    let dev = sign_in(&d, "dev");
    let reply = send(
        &d,
        "GET",
        &authorize_path(&with(base, "scope", Some("runs:read platform:admin"))),
        Body::None,
        &[("cookie", &dev)],
    );
    let back = returned(&reply);
    assert_eq!(param(&back, "error"), Some("invalid_scope"));
    assert_eq!(param(&back, "state"), Some(STATE));
}

#[test]
fn the_consent_form_needs_its_session_token_and_our_origin() {
    let d = deployment();
    let cookie = sign_in(&d, "root");
    let challenge = pkce::challenge(&pkce::verifier());
    let pairs = request_pairs(&challenge);
    let page = send(
        &d,
        "GET",
        &authorize_path(&pairs),
        Body::None,
        &[("cookie", &cookie)],
    );
    assert_eq!(page.status, 200);
    let text = page.text();
    for expected in [
        "Sentinel CLI",
        d.base.as_str(),
        "runs:read",
        "logs:read",
        "acme",
        "root",
    ] {
        assert!(text.contains(expected), "{expected}");
    }
    assert!(!text.contains("Administrative access"));
    let fields = consent(&d, &cookie, &pairs);
    let without_token: Vec<(String, String)> = fields
        .iter()
        .filter(|(k, _)| k != "form_token")
        .cloned()
        .collect();
    let wrong_token: Vec<(String, String)> = fields
        .iter()
        .map(|(k, v)| {
            if k == "form_token" {
                (k.clone(), "0".repeat(64))
            } else {
                (k.clone(), v.clone())
            }
        })
        .collect();
    let approve = [("decision", "approve")];
    let other = sign_in(&d, "dev");
    let refusals = [
        (
            "no form token",
            post_consent(&d, Some(&cookie), None, &without_token, &approve),
            403,
        ),
        (
            "wrong form token",
            post_consent(&d, Some(&cookie), None, &wrong_token, &approve),
            403,
        ),
        (
            "another session's token",
            post_consent(&d, Some(&other), None, &fields, &approve),
            403,
        ),
        (
            "foreign origin",
            post_consent(
                &d,
                Some(&cookie),
                Some("https://evil.example"),
                &fields,
                &approve,
            ),
            403,
        ),
        (
            "no session",
            post_consent(&d, None, Some(&d.base), &fields, &approve),
            401,
        ),
        (
            "no decision",
            post_consent(&d, Some(&cookie), None, &fields, &[]),
            400,
        ),
    ];
    for (what, reply, status) in refusals {
        assert_eq!(reply.status, status, "{what}");
        assert!(reply.header("location").is_none(), "{what}");
        assert_page_headers(&reply);
    }
    let codes: i64 = d
        .store
        .read(|c| Ok(c.query_row("SELECT count(*) FROM oauth_codes", [], |r| r.get(0))?))
        .unwrap();
    assert_eq!(codes, 0);

    // A tampered hidden parameter is re-validated on POST.
    let tampered: Vec<(String, String)> = fields
        .iter()
        .map(|(k, v)| {
            if k == "code_challenge_method" {
                (k.clone(), "plain".to_owned())
            } else {
                (k.clone(), v.clone())
            }
        })
        .collect();
    let back = returned(&post_consent(
        &d,
        Some(&cookie),
        Some(&d.base),
        &tampered,
        &approve,
    ));
    assert_eq!(param(&back, "error"), Some("invalid_request"));
}

#[test]
fn denial_redirects_access_denied_and_is_audited() {
    let d = deployment();
    let cookie = sign_in(&d, "root");
    let challenge = pkce::challenge(&pkce::verifier());
    let fields = consent(&d, &cookie, &request_pairs(&challenge));
    let reply = post_consent(
        &d,
        Some(&cookie),
        Some(&d.base),
        &fields,
        &[("decision", "deny")],
    );
    let back = returned(&reply);
    assert_eq!(param(&back, "error"), Some("access_denied"));
    assert_eq!(param(&back, "state"), Some(STATE));
    assert_eq!(param(&back, "iss"), Some(d.base.as_str()));
    assert!(param(&back, "code").is_none());
    let audit = d
        .store
        .read(|c| local_auth::recent_audit(c, 1))
        .unwrap()
        .remove(0);
    assert_eq!(audit.event, Event::OAuthConsentDenied);
    assert_eq!(audit.subject, Some(d.root));
}

#[test]
fn approval_returns_a_code_that_exchanges_exactly_once() {
    let d = deployment();
    let cookie = sign_in(&d, "root");
    let verifier = pkce::verifier();
    let challenge = pkce::challenge(&verifier);
    let fields = consent(&d, &cookie, &request_pairs(&challenge));
    let reply = post_consent(
        &d,
        Some(&cookie),
        Some(&d.base),
        &fields,
        &[("decision", "approve")],
    );
    assert_eq!(reply.body, Value::Null);
    let back = returned(&reply);
    assert_eq!(param(&back, "state"), Some(STATE));
    assert_eq!(param(&back, "iss"), Some(d.base.as_str()));
    assert!(param(&back, "error").is_none());
    let code = param(&back, "code").unwrap().to_owned();
    assert!(code.starts_with("sntl_ac_"));

    // The first exchange mints a working pair.
    let first = exchange(&d, &code, &verifier);
    assert_eq!(first.status, 200, "{:?}", first.body);
    assert_eq!(first.header("cache-control"), Some("no-store"));
    assert_eq!(first.header("pragma"), Some("no-cache"));
    assert_eq!(first.body["token_type"], "Bearer");
    assert_eq!(first.body["scope"], "runs:read logs:read");
    let access = forms::parse(Kind::Access, first.body["access_token"].as_str().unwrap()).unwrap();
    let me = send(
        &d,
        "GET",
        "/api/v1/me",
        Body::None,
        &[("authorization", &bearer(&access))],
    );
    assert_eq!(me.status, 200, "{:?}", me.body);
    assert_eq!(me.body["via"], "oauth");

    let second = exchange(&d, &code, &verifier);
    assert_eq!(second.status, 400);
    assert_eq!(second.body["error"], "invalid_grant");
    let me = send(
        &d,
        "GET",
        "/api/v1/me",
        Body::None,
        &[("authorization", &bearer(&access))],
    );
    assert_eq!(me.status, 401);
    let audit = d
        .store
        .read(|c| local_auth::recent_audit(c, 1))
        .unwrap()
        .remove(0);
    assert_eq!(audit.event, Event::OAuthCodeReplay);
}

#[test]
fn the_token_endpoint_refuses_wrong_verifiers_and_missing_parameters() {
    let d = deployment();
    let cookie = sign_in(&d, "root");
    let verifier = pkce::verifier();
    let challenge = pkce::challenge(&verifier);
    let fields = consent(&d, &cookie, &request_pairs(&challenge));
    let back = returned(&post_consent(
        &d,
        Some(&cookie),
        Some(&d.base),
        &fields,
        &[("decision", "approve")],
    ));
    let code = param(&back, "code").unwrap().to_owned();
    let wrong = exchange(&d, &code, &pkce::verifier());
    assert_eq!(
        (wrong.status, wrong.body["error"].as_str()),
        (400, Some("invalid_grant"))
    );
    // The failed attempt spent it.
    let late = exchange(&d, &code, &verifier);
    assert_eq!(late.body["error"], "invalid_grant");

    let missing = send(
        &d,
        "POST",
        "/oauth/token",
        Body::Form(&encode(&[
            ("grant_type", "authorization_code"),
            ("client_id", CLI_CLIENT_ID),
            ("code", &code),
        ])),
        &[],
    );
    assert_eq!(missing.body["error"], "invalid_request");
    let garbage = exchange(&d, "sntl_rt_not-a-code", &verifier);
    assert_eq!(garbage.body["error"], "invalid_grant");
}

#[test]
fn approval_can_narrow_to_a_tenant_and_repository() {
    let d = deployment();
    let cookie = sign_in(&d, "dev");
    let verifier = pkce::verifier();
    let challenge = pkce::challenge(&verifier);
    let pairs = with(
        request_pairs(&challenge),
        "scope",
        Some("runs:read runs:write"),
    );
    let fields = consent(&d, &cookie, &pairs);
    let tenant = d.tenant.to_string();
    // A repository needs a tenant; an unknown name is a correctable choice.
    for (extra, notice) in [
        (vec![("repo", "app")], "Choose a tenant"),
        (
            vec![("tenant", tenant.as_str()), ("repo", "missing")],
            "no repository",
        ),
    ] {
        let mut extra = extra;
        extra.push(("decision", "approve"));
        let reply = post_consent(&d, Some(&cookie), Some(&d.base), &fields, &extra);
        assert_eq!(reply.status, 400);
        assert!(reply.text().contains(notice), "{notice}");
        assert!(reply.header("location").is_none());
    }
    let reply = post_consent(
        &d,
        Some(&cookie),
        Some(&d.base),
        &fields,
        &[
            ("tenant", &tenant),
            ("repo", "app"),
            ("decision", "approve"),
        ],
    );
    let back = returned(&reply);
    let code = param(&back, "code").unwrap().to_owned();
    let tokens = exchange(&d, &code, &verifier);
    assert_eq!(tokens.status, 200, "{:?}", tokens.body);
    let grants = d
        .store
        .read(|c| sentinel_store::oauth::grants(c, Authority::HostLocal, d.dev, 10))
        .unwrap();
    assert_eq!(grants.len(), 1);
    assert_eq!(
        (grants[0].tenant, grants[0].repo),
        (Some(d.tenant), Some(d.repo))
    );
    let access = forms::parse(Kind::Access, tokens.body["access_token"].as_str().unwrap()).unwrap();
    let runs = send(
        &d,
        "GET",
        "/api/v1/tenants/acme/repos/app/runs",
        Body::None,
        &[("authorization", &bearer(&access))],
    );
    assert_eq!(runs.status, 200, "{:?}", runs.body);
}
