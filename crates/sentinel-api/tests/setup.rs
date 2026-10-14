//! First-run setup and self-service organizations over real HTTP: the status
//! route that says only whether setup is open, the one-time token's every
//! refusal, one commit creating the administrator and signing them in, and an
//! approved account creating an organization under policy.

#[path = "support/web_fixture.rs"]
mod fixture;

use std::sync::Arc;

use fixture::{Fixture, PASSWORD, call};
use sentinel_auth::secret::Secret;
use sentinel_core::UnixMillis;
use sentinel_link::{controller::Controller, identity::Identity};
use sentinel_store::{
    Durability, Store,
    local_auth::{self, Policy},
    logs::LogStore,
    objects::Objects,
    registration::{self, Authority, DeploymentPolicy, TenantCreation},
    setup,
};
use serde_json::{Value, json};

/// A controller on an empty database: nobody has been admitted.
struct Fresh {
    _dir: tempfile::TempDir,
    store: Arc<Store>,
    _controller: Controller,
    server: Option<sentinel_api::Server>,
    base: String,
}

impl Drop for Fresh {
    fn drop(&mut self) {
        if let Some(server) = self.server.take() {
            server.shutdown();
        }
    }
}

fn fresh() -> Fresh {
    fresh_with(None)
}

fn fresh_with(mail: Option<Arc<sentinel_mail::Resend>>) -> Fresh {
    let dir = tempfile::tempdir().unwrap();
    let store =
        Arc::new(Store::open(dir.path().join("metadata.sqlite"), Durability::Normal).unwrap());
    let logs = Arc::new(LogStore::open(dir.path().join("logs")).unwrap());
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
            secret_key: None,
            sessions: Policy::default(),
            github_webhook_secret: None,
            intake: None,
            public_url: None,
            github_sign_in: None,
            trusted_proxies: sentinel_api::TrustedProxy::loopback(),
        },
        sentinel_api::Options {
            mail,
            ..Default::default()
        },
    )
    .unwrap();
    let base = format!("http://{}", server.local_addr());
    Fresh {
        _dir: dir,
        store,
        _controller: controller,
        server: Some(server),
        base,
    }
}

fn token_text(secret: &Secret) -> String {
    let mut text = String::new();
    secret.expose(&mut text);
    text
}

fn body(token: &str) -> Value {
    json!({
        "token": token,
        "email": "ada@example.com",
        "password": PASSWORD,
        "registration": "approval-required",
        "tenant_creation": "approved-users",
        "instance_name": "Acme CI",
        "organization": "acme",
    })
}

fn post(f: &Fresh, path: &str, value: &Value) -> (u16, Vec<(String, String)>, Value) {
    call(&f.base, "POST", path, Some(value), &[])
}

#[test]
fn status_says_only_whether_setup_is_open() {
    let f = fresh();
    let (status, headers, answer) = call(&f.base, "GET", "/api/v1/setup", None, &[]);
    assert_eq!(status, 200);
    assert_eq!(answer, json!({ "open": true, "mail_configured": false }));
    assert!(
        headers
            .iter()
            .any(|(n, v)| n == "cache-control" && v == "no-store")
    );
    local_auth::bootstrap(
        &f.store,
        "root",
        "Root",
        b"an operator password",
        UnixMillis::now(),
    )
    .unwrap();
    let (_, _, closed) = call(&f.base, "GET", "/api/v1/setup", None, &[]);
    assert_eq!(closed, json!({ "open": false, "mail_configured": false }));
}

#[test]
fn the_wizard_creates_the_administrator_and_signs_them_in() {
    let f = fresh();
    let token = setup::issue(&f.store, UnixMillis::now()).unwrap().unwrap();
    let (status, headers, answer) = post(&f, "/api/v1/setup", &body(&token_text(&token)));
    assert_eq!(status, 201, "{answer}");
    assert_eq!(answer["organization"], "acme");
    let cookie = headers
        .iter()
        .find(|(n, _)| n == "set-cookie")
        .map(|(_, v)| v.split(';').next().unwrap().to_owned())
        .expect("a session cookie");
    let csrf = answer["csrf"].as_str().unwrap().to_owned();

    // The session is the administrator's.
    let (_, _, me) = call(&f.base, "GET", "/api/v1/me", None, &[("cookie", &cookie)]);
    assert_eq!(me["super_admin"], true);
    assert_eq!(me["email"], "ada@example.com");
    assert_eq!(me["email_verified"], true);
    let (_, _, tenants) = call(
        &f.base,
        "GET",
        "/api/v1/tenants",
        None,
        &[("cookie", &cookie), ("x-sentinel-csrf", &csrf)],
    );
    assert_eq!(tenants["tenants"][0]["slug"], "acme");
    assert_eq!(tenants["tenants"][0]["role"], "admin");
    // The switcher groups by kind and membership source without another read.
    assert_eq!(tenants["tenants"][0]["kind"], "organization");
    assert_eq!(tenants["tenants"][0]["membership"], "app");

    // Setup is closed for everyone afterwards, the same token included.
    let (_, _, closed) = call(&f.base, "GET", "/api/v1/setup", None, &[]);
    assert_eq!(closed, json!({ "open": false, "mail_configured": false }));
    let (status, _, _) = post(&f, "/api/v1/setup", &body(&token_text(&token)));
    assert_eq!(status, 404);
    // And the password signs in by address.
    let (status, _, _) = post(
        &f,
        "/api/v1/login",
        &json!({ "username": "ada@example.com", "password": PASSWORD }),
    );
    assert_eq!(status, 200);
}

#[test]
fn a_wrong_expired_or_malformed_token_is_one_refusal_and_creates_nothing() {
    let f = fresh();
    let token = setup::issue(&f.store, UnixMillis::now()).unwrap().unwrap();
    let wrong = token_text(&Secret::generate());
    for presented in [wrong.as_str(), "not-a-token", ""] {
        let (status, _, answer) = post(&f, "/api/v1/setup", &body(presented));
        assert_eq!(status, 403, "{answer}");
        assert_eq!(answer["message"], "setup token refused");
    }
    assert!(f.store.read(setup::is_open).unwrap());

    // Age the token past its life: the right token is now refused too.
    f.store
        .writer()
        .write(|tx| {
            tx.execute("UPDATE setup_token SET expires_ms = 1, created_ms = 0", [])?;
            Ok(())
        })
        .unwrap();
    let (status, _, _) = post(&f, "/api/v1/setup", &body(&token_text(&token)));
    assert_eq!(status, 403);
    assert!(f.store.read(setup::is_open).unwrap());
}

#[test]
fn guessing_is_throttled_and_a_locked_setup_refuses_the_right_token() {
    let f = fresh();
    let token = setup::issue(&f.store, UnixMillis::now()).unwrap().unwrap();
    // The per-client budget answers `429` once the burst is spent; whatever
    // got through counted against the lock. Either way the right token never
    // completes while guesses are landing.
    let mut statuses = Vec::new();
    for _ in 0..12 {
        let guess = token_text(&Secret::generate());
        statuses.push(post(&f, "/api/v1/setup", &body(&guess)).0);
    }
    assert!(
        statuses.iter().all(|s| *s == 403 || *s == 429),
        "{statuses:?}"
    );
    assert!(statuses.contains(&429), "{statuses:?}");
    let (status, _, _) = post(&f, "/api/v1/setup", &body(&token_text(&token)));
    assert!(status == 403 || status == 429, "{status}");
    assert!(f.store.read(setup::is_open).unwrap());
}

#[test]
fn setup_refuses_a_foreign_origin_and_a_form_body() {
    let f = fresh();
    let token = setup::issue(&f.store, UnixMillis::now()).unwrap().unwrap();
    let (status, _, _) = call(
        &f.base,
        "POST",
        "/api/v1/setup",
        Some(&body(&token_text(&token))),
        &[("origin", "https://evil.example")],
    );
    assert_eq!(status, 403);
    assert!(f.store.read(setup::is_open).unwrap());
}

#[test]
fn a_bad_field_is_a_bad_request_and_the_token_survives() {
    let f = fresh();
    let token = setup::issue(&f.store, UnixMillis::now()).unwrap().unwrap();
    let text = token_text(&token);
    for patch in [
        json!({ "password": "short" }),
        json!({ "email": "nope" }),
        json!({ "registration": "anyone" }),
        json!({ "organization": "settings" }),
    ] {
        let mut request = body(&text);
        for (key, value) in patch.as_object().unwrap() {
            request[key] = value.clone();
        }
        let (status, _, answer) = post(&f, "/api/v1/setup", &request);
        assert_eq!(status, 400, "{patch}: {answer}");
    }
    let (status, _, _) = post(&f, "/api/v1/setup", &body(&text));
    assert_eq!(status, 201);
}

const RESEND_KEY: &str = "re_wizardkey_0123456789";

/// A Resend stand-in answering each request with the next scripted status;
/// returns its endpoint and the requests it saw.
fn fake_resend(statuses: Vec<u16>) -> (String, Arc<std::sync::Mutex<Vec<String>>>) {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/emails", listener.local_addr().unwrap());
    let seen: Arc<std::sync::Mutex<Vec<String>>> = Arc::default();
    let log = Arc::clone(&seen);
    std::thread::spawn(move || {
        for status in statuses {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            let mut raw = Vec::new();
            let mut chunk = [0u8; 4096];
            loop {
                let n = stream.read(&mut chunk).unwrap_or(0);
                if n == 0 {
                    break;
                }
                raw.extend_from_slice(&chunk[..n]);
                let Some(end) = raw.windows(4).position(|w| w == b"\r\n\r\n") else {
                    continue;
                };
                let head = String::from_utf8_lossy(&raw[..end]).to_lowercase();
                let length = head
                    .lines()
                    .find_map(|l| l.strip_prefix("content-length:"))
                    .and_then(|v| v.trim().parse::<usize>().ok())
                    .unwrap_or(0);
                if raw.len() >= end + 4 + length {
                    break;
                }
            }
            log.lock()
                .unwrap()
                .push(String::from_utf8_lossy(&raw).into_owned());
            let body = if status == 200 {
                r#"{"id":"x"}"#
            } else {
                r#"{"name":"validation_error","message":"ada@example.com is invalid"}"#
            };
            let _ = write!(
                stream,
                "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
        }
    });
    (url, seen)
}

fn resend_at(url: &str) -> Arc<sentinel_mail::Resend> {
    Arc::new(sentinel_mail::Resend::with_endpoint(
        sentinel_mail::ApiKey::new(RESEND_KEY.as_bytes().to_vec()).unwrap(),
        sentinel_mail::Sender::parse("Sentinel <ci@example.com>").unwrap(),
        url,
    ))
}

#[test]
fn the_mail_test_without_a_sender_says_not_configured_and_blocks_nothing() {
    let f = fresh();
    let token = setup::issue(&f.store, UnixMillis::now()).unwrap().unwrap();
    let test = |token: &str| json!({ "token": token, "to": "ada@example.com" });
    let (status, _, _) = post(&f, "/api/v1/setup/mail-test", &test("bogus"));
    assert_eq!(status, 403);
    let (status, _, answer) = post(&f, "/api/v1/setup/mail-test", &test(&token_text(&token)));
    assert_eq!(status, 200, "{answer}");
    assert_eq!(
        (&answer["sent"], &answer["failure"]),
        (&json!(false), &json!("not_configured"))
    );
    assert!(f.store.read(setup::is_open).unwrap());
    // Relay fields are not part of the contract: the body is token and to.
    let (status, _, _) = post(
        &f,
        "/api/v1/setup/mail-test",
        &json!({ "token": token_text(&token), "to": "ada@example.com", "host": "x", "port": 25 }),
    );
    assert_eq!(status, 400);
    let (status, _, _) = post(&f, "/api/v1/setup", &body(&token_text(&token)));
    assert_eq!(status, 201);
}

#[test]
fn the_mail_test_sends_through_the_configured_sender_and_reports_failures_briefly() {
    let (url, seen) = fake_resend(vec![200, 422]);
    let f = fresh_with(Some(resend_at(&url)));
    let (_, _, status) = call(&f.base, "GET", "/api/v1/setup", None, &[]);
    assert_eq!(status, json!({ "open": true, "mail_configured": true }));
    let token = setup::issue(&f.store, UnixMillis::now()).unwrap().unwrap();
    let text = token_text(&token);
    // An address that is not one is reported before anything is sent.
    let (status, _, answer) = post(
        &f,
        "/api/v1/setup/mail-test",
        &json!({ "token": text, "to": "not an address" }),
    );
    assert_eq!(
        (status, &answer["failure"]),
        (200, &json!("invalid_settings"))
    );
    assert!(seen.lock().unwrap().is_empty());
    let (status, _, answer) = post(
        &f,
        "/api/v1/setup/mail-test",
        &json!({ "token": text, "to": "Ada@Example.com" }),
    );
    assert_eq!((status, &answer), (200, &json!({ "sent": true })));
    {
        let seen = seen.lock().unwrap();
        assert!(seen[0].contains(&format!("Bearer {RESEND_KEY}")));
        assert!(seen[0].contains("\"to\":[\"ada@example.com\"]"));
    }
    let (status, _, answer) = post(
        &f,
        "/api/v1/setup/mail-test",
        &json!({ "token": text, "to": "ada@example.com" }),
    );
    assert_eq!(status, 200, "{answer}");
    assert_eq!(
        (&answer["sent"], &answer["failure"]),
        (&json!(false), &json!("permanent"))
    );
    let reason = answer["reason"].as_str().unwrap();
    assert!(reason.contains("422"), "{reason}");
    for secret in [RESEND_KEY, "ada@example.com", "is invalid"] {
        assert!(!answer.to_string().contains(secret), "{secret} leaked");
    }
    assert!(f.store.read(setup::is_open).unwrap());
}

fn allow_creation(f: &Fixture, creation: TenantCreation) {
    f.store
        .writer()
        .write(move |tx| {
            registration::set_policy(
                tx,
                Authority::HostLocal,
                DeploymentPolicy {
                    tenant_creation: creation,
                    ..registration::policy(tx)?
                },
                UnixMillis::now(),
            )
        })
        .unwrap();
}

fn session(f: &Fixture, username: &str) -> (String, String) {
    let (status, headers, answer) = call(
        &f.base,
        "POST",
        "/api/v1/login",
        Some(&json!({ "username": username, "password": PASSWORD })),
        &[],
    );
    assert_eq!(status, 200, "{answer}");
    let cookie = headers
        .iter()
        .find(|(n, _)| n == "set-cookie")
        .map(|(_, v)| v.split(';').next().unwrap().to_owned())
        .unwrap();
    (cookie, answer["csrf"].as_str().unwrap().to_owned())
}

fn send(
    f: &Fixture,
    method: &str,
    path: &str,
    body: Option<Value>,
    s: &(String, String),
) -> (u16, Value) {
    let (status, _, answer) = call(
        &f.base,
        method,
        path,
        body.as_ref(),
        &[("cookie", &s.0), ("x-sentinel-csrf", &s.1)],
    );
    (status, answer)
}

#[test]
fn an_approved_user_creates_an_organization_when_policy_allows() {
    let f = Fixture::new(1);
    let dana = session(&f, "dana");
    // The default keeps creation with the platform.
    let (status, _) = send(
        &f,
        "POST",
        "/api/v1/orgs",
        Some(json!({ "slug": "dana-co" })),
        &dana,
    );
    assert_eq!(status, 403);
    allow_creation(&f, TenantCreation::ApprovedUsers);
    let (status, answer) = send(
        &f,
        "POST",
        "/api/v1/orgs",
        Some(json!({ "slug": "dana-co" })),
        &dana,
    );
    assert_eq!(
        (status, &answer["role"]),
        (201, &json!("admin")),
        "{answer}"
    );
    let (status, settings) = send(&f, "GET", "/api/v1/tenants/dana-co/settings", None, &dana);
    assert_eq!(status, 200, "{settings}");
    assert_eq!(settings["kind"], "organization");
    assert_eq!(settings["membership"], "app");
    assert_eq!(settings["role"], "admin");
    assert_eq!(settings["auto_join"]["applies"], false);
    // An app-created organization has no GitHub standing to report.
    assert!(settings.get("github_sync").is_none(), "{settings}");
    // A taken name and a reserved one are refused, uniformly for anyone.
    let (status, _) = send(
        &f,
        "POST",
        "/api/v1/orgs",
        Some(json!({ "slug": "acme" })),
        &dana,
    );
    assert_eq!(status, 409);
    let (status, _) = send(
        &f,
        "POST",
        "/api/v1/orgs",
        Some(json!({ "slug": "api" })),
        &dana,
    );
    assert_eq!(status, 400);
}

#[test]
fn organization_creation_needs_a_browser_session_and_a_budget() {
    let f = Fixture::new(1);
    allow_creation(&f, TenantCreation::ApprovedUsers);
    // A bearer credential cannot create what the account will own.
    let (status, _, _) = call(
        &f.base,
        "POST",
        "/api/v1/orgs",
        Some(&json!({ "slug": "via-bearer" })),
        &[("authorization", &f.auth)],
    );
    assert!(status == 400 || status == 401 || status == 403, "{status}");
    let dana = session(&f, "dana");
    let mut statuses = Vec::new();
    for n in 0..12 {
        let slug = format!("probe-{n}");
        statuses.push(
            send(
                &f,
                "POST",
                "/api/v1/orgs",
                Some(json!({ "slug": slug })),
                &dana,
            )
            .0,
        );
    }
    // The per-client budget (and the account quota) stop probing.
    assert!(
        statuses.contains(&429) || statuses.contains(&403),
        "{statuses:?}"
    );
    assert!(
        statuses.iter().filter(|s| **s == 201).count() <= 3,
        "{statuses:?}"
    );
}

#[test]
fn settings_never_confirm_a_namespace_to_someone_outside_it() {
    let f = Fixture::new(1);
    let rui = session(&f, "rui");
    for slug in ["beta", "no-such-org"] {
        let (status, _) = send(
            &f,
            "GET",
            &format!("/api/v1/tenants/{slug}/settings"),
            None,
            &rui,
        );
        assert_eq!(status, 404, "{slug}");
    }
    // A member who does not administer sees no auto-join detail at all.
    let (status, settings) = send(&f, "GET", "/api/v1/tenants/acme/settings", None, &rui);
    assert_eq!(status, 200);
    assert!(settings.get("auto_join").is_none(), "{settings}");
    assert_eq!(settings["role"], "reader");
}
