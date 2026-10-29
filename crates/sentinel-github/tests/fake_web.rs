//! The fake's GitHub web pages in isolation: the manifest create page and its confirm click, the
//! one-time conversion of the code it mints, the installation page, and that one idle connection
//! never stalls another request.
#![cfg(feature = "fake")]

use std::{net::TcpStream, time::Duration};

use sentinel_github::fake::{Blueprint, FakeGithub};
use serde_json::{Value, json};

const SECRET: &str = "oauth-client-secret-canary";

fn blueprint() -> Blueprint {
    Blueprint {
        id: 4242,
        slug: "acme-ci".into(),
        name: "Acme CI".into(),
        owner_login: "acme-gh".into(),
        owner_id: 9000,
        owner_kind: "Organization".into(),
        client_id: "Iv23.acmeclient".into(),
        client_secret: "app-client-secret-canary".into(),
        webhook_secret: "app-webhook-secret-canary".into(),
        pem: "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n".into(),
    }
}

fn manifest() -> Value {
    json!({
        "name": "Acme <CI>",
        "url": "http://127.0.0.1:8080",
        "redirect_url": "http://127.0.0.1:8080/setup/github/created",
        "setup_url": "http://127.0.0.1:8080/setup/github/installed",
        "hook_attributes": { "url": "http://127.0.0.1:8080/api/v1/hooks/github", "active": false },
        "default_permissions": { "checks": "write", "contents": "read" },
    })
}

fn agent() -> ureq::Agent {
    ureq::Agent::new_with_config(
        ureq::Agent::config_builder()
            .http_status_as_error(false)
            .max_redirects(0)
            .build(),
    )
}

struct Answer {
    status: u16,
    location: Option<String>,
    text: String,
}

fn answer(response: ureq::http::Response<ureq::Body>) -> Answer {
    let status = response.status().as_u16();
    let location = response
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    Answer {
        status,
        location,
        text: response.into_body().read_to_string().unwrap_or_default(),
    }
}

fn form(url: &str, fields: &[(&str, &str)]) -> Answer {
    let body = fields
        .iter()
        .map(|(k, v)| format!("{}={}", escape(k), escape(v)))
        .collect::<Vec<_>>()
        .join("&");
    answer(
        agent()
            .post(url)
            .header("content-type", "application/x-www-form-urlencoded")
            .send(body.as_bytes())
            .unwrap(),
    )
}

fn get(url: &str) -> Answer {
    answer(agent().get(url).call().unwrap())
}

fn escape(text: &str) -> String {
    let mut out = String::new();
    for b in text.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// The hidden `token` the confirm page carries.
fn token_of(page: &str) -> String {
    let at = page.find("name=\"token\" value=\"").expect("a token field") + 20;
    page[at..].split('"').next().unwrap().to_owned()
}

fn query_of(location: &str, key: &str) -> Option<String> {
    let query = location.split_once('?')?.1;
    query
        .split('&')
        .find_map(|pair| pair.strip_prefix(&format!("{key}=")))
        .map(str::to_owned)
}

fn convert(fake: &FakeGithub, code: &str) -> Answer {
    answer(
        agent()
            .post(format!("{}/app-manifests/{code}/conversions", fake.base()))
            .send_empty()
            .unwrap(),
    )
}

#[test]
fn a_confirmed_manifest_returns_a_code_that_converts_once() {
    let fake = FakeGithub::start(SECRET);
    fake.set_blueprint(blueprint());
    // GitHub's web side is another site than the API side, on the same port.
    assert_eq!(
        fake.web_base(),
        fake.base().replace("127.0.0.1", "localhost")
    );
    let text = manifest().to_string();
    let posted = form(
        &format!(
            "{}/organizations/acme-gh/settings/apps/new?state=state0123456789abcdef",
            fake.base()
        ),
        &[("manifest", &text)],
    );
    assert_eq!(posted.status, 200, "{}", posted.text);
    assert!(posted.text.contains("id=\"create-app\""));
    assert!(posted.text.contains("the organization acme-gh"));
    assert!(
        posted.text.contains("Acme &lt;CI&gt;") && !posted.text.contains("Acme <CI>"),
        "the App's name is escaped"
    );
    assert_eq!(fake.manifests_posted(), vec![text]);

    let token = token_of(&posted.text);
    let confirmed = form(
        &format!("{}/__fake/create", fake.base()),
        &[("token", &token)],
    );
    assert_eq!(confirmed.status, 302, "{}", confirmed.text);
    let location = confirmed.location.unwrap();
    assert!(
        location.starts_with("http://127.0.0.1:8080/setup/github/created?code=manifestcode"),
        "{location}"
    );
    assert_eq!(
        query_of(&location, "state").as_deref(),
        Some("state0123456789abcdef")
    );
    let code = query_of(&location, "code").unwrap();

    let converted = convert(&fake, &code);
    assert_eq!(converted.status, 201, "{}", converted.text);
    let body: Value = serde_json::from_str(&converted.text).unwrap();
    assert_eq!(body["slug"], "acme-ci");
    assert_eq!(body["owner"]["login"], "acme-gh");
    assert_eq!(body["webhook_secret"], "app-webhook-secret-canary");
    assert!(body["pem"].as_str().unwrap().contains("BEGIN PRIVATE KEY"));
    assert_eq!(convert(&fake, &code).status, 404, "a code converts once");
    assert_eq!(
        form(
            &format!("{}/__fake/create", fake.base()),
            &[("token", &token)]
        )
        .status,
        404,
        "a confirm click is spent with its manifest"
    );
    assert_eq!(
        fake.web_requests(),
        vec![
            "POST /organizations/acme-gh/settings/apps/new",
            "POST /__fake/create",
            "POST /__fake/create",
        ]
    );
}

#[test]
fn a_malformed_or_oversized_manifest_is_refused_and_nothing_is_created() {
    let fake = FakeGithub::start(SECRET);
    fake.set_blueprint(blueprint());
    let create = format!("{}/settings/apps/new?state=abcdefgh", fake.base());
    let mut without_redirect = manifest();
    without_redirect
        .as_object_mut()
        .unwrap()
        .remove("redirect_url");
    let mut hostile = manifest();
    hostile["setup_url"] = json!("javascript:alert(1)");
    for (what, fields) in [
        ("not JSON", vec![("manifest", "{not json".to_owned())]),
        ("no manifest field", vec![("other", "1".to_owned())]),
        ("a JSON array", vec![("manifest", "[]".to_owned())]),
        (
            "no redirect_url",
            vec![("manifest", without_redirect.to_string())],
        ),
        ("a script URL", vec![("manifest", hostile.to_string())]),
    ] {
        let fields: Vec<(&str, &str)> = fields.iter().map(|(k, v)| (*k, v.as_str())).collect();
        assert_eq!(form(&create, &fields).status, 400, "{what}");
    }
    let no_state = form(
        &format!("{}/settings/apps/new", fake.base()),
        &[("manifest", &manifest().to_string())],
    );
    assert_eq!(no_state.status, 400, "a post without a state");
    let big = json!({ "name": "x".repeat(70 * 1024) }).to_string();
    let oversized = form(&create, &[("manifest", &big)]);
    assert_eq!(oversized.status, 413, "{}", oversized.text);
    assert!(fake.manifests_posted().is_empty(), "nothing was kept");

    let unknown = form(
        &format!("{}/__fake/create", fake.base()),
        &[("token", "0123456789abcdef")],
    );
    assert_eq!(unknown.status, 404, "an unknown confirm token");
    assert_eq!(convert(&fake, "manifestcodeabc").status, 404);
}

#[test]
fn without_an_app_to_create_the_confirm_click_is_refused() {
    let fake = FakeGithub::start(SECRET);
    let posted = form(
        &format!("{}/settings/apps/new?state=abcdefgh", fake.base()),
        &[("manifest", &manifest().to_string())],
    );
    assert_eq!(posted.status, 200);
    let confirmed = form(
        &format!("{}/__fake/create", fake.base()),
        &[("token", &token_of(&posted.text))],
    );
    assert_eq!(confirmed.status, 409, "no blueprint was set");
}

fn confirmed_fake() -> FakeGithub {
    let fake = FakeGithub::start(SECRET);
    fake.set_blueprint(blueprint());
    fake.offer_installation("acme-gh", 9000, false);
    let posted = form(
        &format!("{}/settings/apps/new?state=abcdefgh", fake.base()),
        &[("manifest", &manifest().to_string())],
    );
    let confirmed = form(
        &format!("{}/__fake/create", fake.base()),
        &[("token", &token_of(&posted.text))],
    );
    assert_eq!(confirmed.status, 302);
    fake
}

#[test]
fn the_install_page_registers_the_installation_and_returns_to_the_setup_url() {
    let fake = confirmed_fake();
    let page = get(&format!(
        "{}/apps/acme-ci/installations/new?state=install-state-0123",
        fake.base()
    ));
    assert_eq!(page.status, 200, "{}", page.text);
    assert!(
        page.text.contains("id=\"install-app\"") && page.text.contains("id=\"request-install\"")
    );
    assert!(page.text.contains("acme-gh"));

    let installed = form(
        &format!("{}/__fake/install", fake.base()),
        &[
            ("slug", "acme-ci"),
            ("state", "install-state-0123"),
            ("action", "install"),
        ],
    );
    assert_eq!(installed.status, 302, "{}", installed.text);
    let location = installed.location.unwrap();
    assert!(
        location.starts_with("http://127.0.0.1:8080/setup/github/installed?installation_id=9001&"),
        "{location}"
    );
    assert_eq!(
        query_of(&location, "setup_action").as_deref(),
        Some("install")
    );
    assert_eq!(
        query_of(&location, "state").as_deref(),
        Some("install-state-0123")
    );

    // The installation is the one the App's JWT lookup finds.
    let lookup = answer(
        agent()
            .get(format!("{}/app/installations/9001", fake.base()))
            .header("authorization", "Bearer eyJ.fake.jwt")
            .call()
            .unwrap(),
    );
    assert_eq!(lookup.status, 200, "{}", lookup.text);
    let found: Value = serde_json::from_str(&lookup.text).unwrap();
    assert_eq!(found["app_id"], 4242);
    assert_eq!(found["account"]["login"], "acme-gh");
    assert_eq!(found["account"]["type"], "Organization");

    // Another click allocates the next installation.
    let again = form(
        &format!("{}/__fake/install", fake.base()),
        &[("slug", "acme-ci"), ("action", "install")],
    );
    let location = again.location.unwrap();
    assert!(location.contains("installation_id=9002"), "{location}");
    assert_eq!(
        query_of(&location, "state"),
        None,
        "no state, none returned"
    );
}

#[test]
fn a_request_to_install_returns_setup_action_request_and_registers_nothing() {
    let fake = confirmed_fake();
    let asked = form(
        &format!("{}/__fake/install", fake.base()),
        &[
            ("slug", "acme-ci"),
            ("state", "install-state-0123"),
            ("action", "request"),
        ],
    );
    assert_eq!(asked.status, 302);
    let location = asked.location.unwrap();
    assert_eq!(
        query_of(&location, "setup_action").as_deref(),
        Some("request")
    );
    assert_eq!(query_of(&location, "installation_id"), None);
    let lookup = answer(
        agent()
            .get(format!("{}/app/installations/9001", fake.base()))
            .header("authorization", "Bearer eyJ.fake.jwt")
            .call()
            .unwrap(),
    );
    assert_eq!(lookup.status, 404, "a request makes no installation");
}

#[test]
fn an_install_page_for_another_app_or_an_unknown_action_is_refused() {
    let fake = confirmed_fake();
    assert_eq!(
        get(&format!("{}/apps/other-ci/installations/new", fake.base())).status,
        404
    );
    let wrong = form(
        &format!("{}/__fake/install", fake.base()),
        &[("slug", "other-ci"), ("action", "install")],
    );
    assert_eq!(wrong.status, 404);
    let unknown = form(
        &format!("{}/__fake/install", fake.base()),
        &[("slug", "acme-ci"), ("action", "delete")],
    );
    assert_eq!(unknown.status, 400);
}

#[test]
fn an_idle_connection_does_not_stall_the_next_request() {
    let fake = FakeGithub::start(SECRET);
    // A browser's speculative connection: open, silent.
    let port: u16 = fake.base().rsplit(':').next().unwrap().parse().unwrap();
    let _idle = TcpStream::connect(("127.0.0.1", port)).unwrap();
    let started = std::time::Instant::now();
    let reply = get(&format!("{}/apps/acme-ci/installations/new", fake.base()));
    assert_eq!(reply.status, 404);
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "the idle connection held the request for {:?}",
        started.elapsed()
    );
}
