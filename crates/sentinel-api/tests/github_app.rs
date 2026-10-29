//! One-click GitHub App setup over loopback HTTP against `sentinel_github::fake`: the manifest,
//! the conversion, the App put in force without a restart, installation binding and every
//! refusal, with canary credentials that must never leave the sealed columns.

use std::sync::{Arc, Mutex};

#[path = "support/github_app.rs"]
mod support;
use support::{CLIENT_SECRET, WEBHOOK_SECRET, test_key};

use sentinel_core::{
    TenantId, UnixMillis, UserId,
    auth::{Namespace, Permissions as P, Principal, Role},
};
use sentinel_github::fake::FakeGithub;
use sentinel_link::{controller::Controller, identity::Identity};
use sentinel_store::{
    Durability, Store,
    auth::{self, Authority, NamespaceKind, provisioning},
    local_auth,
    logs::LogStore,
    objects::Objects,
    registration::{self, Applicant, Terms},
};
use serde_json::{Value, json};

const PASSWORD: &str = "correct horse battery staple";
const PUBLIC_URL: &str = "https://ci.example.com";
const APP_ID: u64 = 4242;
type Seen = Arc<Mutex<Vec<String>>>;

struct Deployment {
    dir: tempfile::TempDir,
    store: Arc<Store>,
    _controller: Controller,
    server: Option<sentinel_api::Server>,
    github: FakeGithub,
    base: String,
    root: UserId,
    tenants: Vec<(&'static str, TenantId)>,
    activated: Arc<Mutex<Vec<u64>>>,
    seen: Seen,
}

impl Drop for Deployment {
    fn drop(&mut self) {
        if let Some(server) = self.server.take() {
            server.shutdown();
        }
    }
}

enum Files {
    None,
    App,
}

fn deployment(public_url: Option<&str>, files: Files) -> Deployment {
    let dir = tempfile::tempdir().unwrap();
    let store =
        Arc::new(Store::open(dir.path().join("metadata.sqlite"), Durability::Normal).unwrap());
    let logs = Arc::new(LogStore::open(dir.path().join("logs")).unwrap());
    let objects = Arc::new(Objects::open(dir.path()).unwrap());
    let key_path = dir.path().join("master.key");
    sentinel_auth::sealed::Key::create(&key_path).unwrap();
    let key = Arc::new(sentinel_auth::sealed::Key::load(&key_path).unwrap());
    let now = UnixMillis::now();
    let root = local_auth::bootstrap(&store, "root", "Root", PASSWORD.as_bytes(), now).unwrap();
    let mut tenants = Vec::new();
    for (slug, kind) in [
        ("acme", NamespaceKind::Organization),
        ("beta", NamespaceKind::Organization),
        ("gamma", NamespaceKind::Organization),
        ("root-home", NamespaceKind::Personal(root)),
    ] {
        let id = TenantId::new();
        store
            .writer()
            .write(move |tx| {
                let admin = Principal::new(root, P::ALL, None, None);
                auth::create_namespace(tx, admin, id, Namespace::parse(slug).unwrap(), kind, now)?;
                if slug == "acme" {
                    auth::set_membership(tx, admin, id, root, Role::TenantAdmin)?;
                }
                Ok(())
            })
            .unwrap();
        tenants.push((slug, id));
    }
    let tenant = |slug: &str| tenants.iter().find(|(s, _)| *s == slug).unwrap().1;
    let person = |name: &str, tenant: TenantId, role: Role, github: Option<u64>| {
        let invitation = store
            .writer()
            .write(move |tx| {
                registration::invite(
                    tx,
                    Authority::HostLocal,
                    Terms {
                        tenant: Some(tenant),
                        role: Some(role),
                        identity: None,
                        lifetime_ms: 3_600_000,
                    },
                    now,
                )
            })
            .unwrap();
        let user = match registration::register(
            &store,
            Applicant::Local {
                display_name: name,
                username: &name.to_ascii_lowercase(),
                password: PASSWORD.as_bytes(),
            },
            Some(&invitation.secret),
            now,
        )
        .unwrap()
        {
            registration::Admission::Admitted(user) => user,
            other => panic!("{other:?}"),
        };
        if let Some(id) = github {
            store
                .writer()
                .write(move |tx| {
                    provisioning::link_verified_identity(tx, user, "github", &id.to_string(), now)
                })
                .unwrap();
        }
        user
    };
    person("Alice", tenant("beta"), Role::TenantAdmin, Some(7001));
    person("Bob", tenant("gamma"), Role::TenantAdmin, Some(7002));
    person("Carol", tenant("beta"), Role::Operator, Some(7003));
    let ops = person("Ops", tenant("acme"), Role::Reader, None);
    store
        .writer()
        .write(move |tx| local_auth::set_super_admin(tx, Authority::HostLocal, ops, true, now))
        .unwrap();

    let controller = Controller::start(
        Arc::clone(&store),
        Arc::clone(&logs),
        Arc::clone(&objects),
        Identity::generate("controller").unwrap(),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    let github = FakeGithub::start("unused-oauth-secret");
    let activated = Arc::new(Mutex::new(Vec::new()));
    let (current, source, webhook) = match files {
        Files::None => (
            sentinel_github::app::Current::default(),
            None,
            None::<Arc<[u8]>>,
        ),
        Files::App => (
            Some(Arc::new(
                sentinel_github::app::App::new(1234, test_key())
                    .unwrap()
                    .with_endpoint(&github.base())
                    .unwrap(),
            ))
            .into(),
            Some(sentinel_api::AppSource::Files),
            Some(Arc::from(&b"file-webhook-secret-0123456789"[..])),
        ),
    };
    let recorder = Arc::clone(&activated);
    let server = sentinel_api::Server::start_with(
        sentinel_api::Config {
            listen: "127.0.0.1:0".parse().unwrap(),
            store: Arc::clone(&store),
            logs,
            objects,
            controller: controller.handle(),
            secret_key: Some(key),
            sessions: local_auth::Policy::default(),
            github_webhook_secret: webhook,
            intake: None,
            public_url: public_url.map(str::to_owned),
            github_sign_in: None,
            trusted_proxies: sentinel_api::TrustedProxy::loopback(),
        },
        sentinel_api::Options {
            github_app: sentinel_api::GithubAppSetup {
                web_url: github.base(),
                api_url: github.base(),
                sign_in_endpoints: github.endpoints(),
                current,
                source,
                on_activate: Some(Arc::new(move |activation: &sentinel_api::Activation| {
                    recorder.lock().unwrap().push(activation.app_id);
                })),
            },
            ..sentinel_api::Options::default()
        },
    )
    .unwrap();
    let base = format!("http://{}", server.local_addr());
    Deployment {
        dir,
        store,
        _controller: controller,
        server: Some(server),
        github,
        base,
        root,
        tenants,
        activated,
        seen: Seen::default(),
    }
}

impl Deployment {
    fn tenant(&self, slug: &str) -> TenantId {
        self.tenants.iter().find(|(s, _)| *s == slug).unwrap().1
    }

    /// Every status line, header and body the controller answers is kept for the leak scan.
    fn call(
        &self,
        method: &str,
        path: &str,
        body: Option<&Value>,
        headers: &[(&str, &str)],
    ) -> (u16, Vec<(String, String)>, Value) {
        self.call_raw(method, path, body.map(Value::to_string), headers)
    }

    fn call_raw(
        &self,
        method: &str,
        path: &str,
        body: Option<String>,
        headers: &[(&str, &str)],
    ) -> (u16, Vec<(String, String)>, Value) {
        let agent = ureq::Agent::new_with_config(
            ureq::Agent::config_builder()
                .http_status_as_error(false)
                .max_redirects(0)
                .build(),
        );
        let url = format!("{}{path}", self.base);
        let response = if method == "GET" {
            let mut r = agent.get(&url);
            for (k, v) in headers {
                r = r.header(*k, *v);
            }
            r.call()
        } else {
            let mut r = agent.post(&url).header("content-type", "application/json");
            for (k, v) in headers {
                r = r.header(*k, *v);
            }
            r.send(body.unwrap_or_else(|| "{}".into()).as_bytes())
        }
        .unwrap();
        let status = response.status().as_u16();
        let out: Vec<(String, String)> = response
            .headers()
            .iter()
            .map(|(n, v)| {
                (
                    n.as_str().to_ascii_lowercase(),
                    v.to_str().unwrap_or_default().to_owned(),
                )
            })
            .collect();
        let text = response.into_body().read_to_string().unwrap_or_default();
        let mut seen = self.seen.lock().unwrap();
        seen.push(format!("{status}"));
        seen.extend(out.iter().map(|(n, v)| format!("{n}: {v}")));
        seen.push(text.clone());
        (
            status,
            out,
            serde_json::from_str(&text).unwrap_or(Value::String(text)),
        )
    }

    fn login(&self, username: &str) -> Session {
        let (status, headers, body) = self.call(
            "POST",
            "/api/v1/login",
            Some(&json!({ "username": username, "password": PASSWORD })),
            &[],
        );
        assert_eq!(status, 200, "{body}");
        let cookie = headers
            .iter()
            .find(|(n, _)| n == "set-cookie")
            .map(|(_, v)| v.split(';').next().unwrap().to_owned())
            .unwrap();
        Session {
            cookie,
            csrf: body["csrf"].as_str().unwrap().to_owned(),
        }
    }

    fn post(&self, s: &Session, path: &str, body: Value) -> (u16, Value) {
        let (status, _, body) = self.call(
            "POST",
            path,
            Some(&body),
            &[("cookie", &s.cookie), ("x-sentinel-csrf", &s.csrf)],
        );
        (status, body)
    }

    fn get(&self, s: &Session, path: &str) -> (u16, Value) {
        let (status, _, body) = self.call("GET", path, None, &[("cookie", &s.cookie)]);
        (status, body)
    }

    fn step_up(&self, s: &Session) {
        let (status, body) = self.post(
            s,
            "/api/v1/step-up",
            json!({ "method": "password", "code": PASSWORD }),
        );
        assert_eq!(status, 200, "{body}");
    }

    fn hook(&self, secret: &[u8], body: &str) -> (u16, Value) {
        let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, secret);
        let tag = ring::hmac::sign(&key, body.as_bytes());
        let signature = format!(
            "sha256={}",
            tag.as_ref()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        );
        let (status, _, body) = self.call_raw(
            "POST",
            "/api/v1/hooks/github",
            Some(body.to_owned()),
            &[
                ("x-github-event", "ping"),
                ("x-github-delivery", "72d3162e-cc78-11e3-81ab-4c9367dc0958"),
                ("x-hub-signature-256", &signature),
            ],
        );
        (status, body)
    }

    fn conversion(&self) -> String {
        let body = json!({
            "id": APP_ID,
            "slug": "acme-ci",
            "node_id": "A_kwHO",
            "name": "Acme CI",
            "owner": { "login": "acme-gh", "id": 9000, "type": "Organization" },
            "html_url": format!("{}/apps/acme-ci", self.github.base()),
            "client_id": "Iv23.acmeclient",
            "client_secret": CLIENT_SECRET,
            "webhook_secret": WEBHOOK_SECRET,
            "pem": test_key(),
        })
        .to_string();
        // The positive control: the canaries are in what the fake serves, so the scans below can fail.
        support::assert_present_in_source(&body);
        body
    }

    /// Runs the whole platform-administrator half and returns the stepped-up session.
    fn configure(&self) -> Session {
        let root = self.login("root");
        self.step_up(&root);
        let (status, manifest) = self.post(
            &root,
            "/api/v1/github/app/manifest",
            json!({ "owner": { "kind": "user" } }),
        );
        assert_eq!(status, 200, "{manifest}");
        self.github.add_manifest("code0123", &self.conversion());
        let (status, converted) = self.post(
            &root,
            "/api/v1/github/app/conversion",
            json!({ "code": "code0123", "state": manifest["state"] }),
        );
        assert_eq!(status, 200, "{converted}");
        root
    }

    fn installation(&self, id: u64, login: &str, account: u64, personal: bool) {
        self.github.add_installation(
            id,
            &json!({
                "id": id,
                "app_id": APP_ID,
                "account": {
                    "id": account,
                    "login": login,
                    "type": if personal { "User" } else { "Organization" },
                },
                "suspended_at": null,
                "permissions": {
                    "checks": "write", "contents": "read", "metadata": "read",
                    "pull_requests": "read", "members": "read"
                },
            })
            .to_string(),
        );
    }

    fn org_role(&self, org: &str, org_id: u64, login: &str, user: u64, role: &str) {
        self.github.add_membership(
            org,
            login,
            &json!({
                "state": "active",
                "role": role,
                "user": { "id": user, "login": login },
                "organization": { "id": org_id, "login": org },
            })
            .to_string(),
        );
    }

    fn mint(&self, s: &Session, slug: &str, body: Value) -> (u16, Value) {
        self.post(
            s,
            &format!("/api/v1/tenants/{slug}/github/installation-url"),
            body,
        )
    }

    fn bind(&self, s: &Session, installation: u64, state: &str) -> (u16, Value) {
        self.post(
            s,
            "/api/v1/github/app/installation",
            json!({ "installation_id": installation, "state": state, "setup_action": "install" }),
        )
    }

    fn audit_details(&self) -> Vec<String> {
        self.store
            .read(|c| local_auth::recent_audit(c, 100))
            .unwrap()
            .into_iter()
            .map(|r| format!("{} {}", r.event.name(), r.detail.unwrap_or_default()))
            .collect()
    }
}

struct Session {
    cookie: String,
    csrf: String,
}

fn state_of(url: &str) -> String {
    url.split_once("state=").unwrap().1.to_owned()
}

#[test]
fn one_click_setup_puts_the_app_in_force_without_a_restart_and_leaks_no_secret() {
    let d = deployment(Some(PUBLIC_URL), Files::None);
    let root = d.login("root");
    let (status, view) = d.get(&root, "/api/v1/github/app");
    assert_eq!(status, 200);
    assert_eq!(view["configured"], false);
    assert_eq!(view["source"], Value::Null);
    assert_eq!(view["can_create"], true);
    assert_eq!(view["webhook_reachable"], true);
    assert_eq!(view["reason"], Value::Null);
    assert_eq!(view["public_url"], PUBLIC_URL);
    assert_eq!(
        view["webhook_url"],
        "https://ci.example.com/api/v1/hooks/github"
    );

    let (status, refused) = d.post(
        &root,
        "/api/v1/github/app/manifest",
        json!({ "owner": { "kind": "user" } }),
    );
    assert_eq!(
        (status, &refused["details"]["step_up"]),
        (403, &json!(true))
    );
    d.step_up(&root);
    let (status, manifest) = d.post(
        &root,
        "/api/v1/github/app/manifest",
        json!({ "owner": { "kind": "organization", "login": "acme-gh" } }),
    );
    assert_eq!(status, 200, "{manifest}");
    let state = manifest["state"].as_str().unwrap();
    assert_eq!(
        manifest["action_url"],
        format!(
            "{}/organizations/acme-gh/settings/apps/new?state={state}",
            d.github.base()
        )
    );
    assert!(manifest["expires_ms"].as_i64().unwrap() > UnixMillis::now().0);
    let text: Value = serde_json::from_str(manifest["manifest"].as_str().unwrap()).unwrap();
    assert_eq!(text["url"], PUBLIC_URL);
    assert_eq!(
        text["hook_attributes"],
        json!({ "url": "https://ci.example.com/api/v1/hooks/github", "active": true })
    );
    assert_eq!(
        text["redirect_url"],
        "https://ci.example.com/setup/github/created"
    );
    assert_eq!(
        text["setup_url"],
        "https://ci.example.com/setup/github/installed"
    );
    assert_eq!(
        text["callback_urls"],
        json!(["https://ci.example.com/auth/github/callback"])
    );
    assert_eq!(text["public"], false);
    assert!(text["name"].as_str().unwrap().len() <= 34);

    // Before the conversion there is no webhook route and no GitHub sign-in.
    assert_eq!(d.hook(WEBHOOK_SECRET.as_bytes(), "{}").0, 404);
    let (_, health) = d.get(&root, "/api/v1/health");
    assert_eq!(health["github_sign_in"], false);

    d.github.add_manifest("code0123", &d.conversion());
    let (status, converted) = d.post(
        &root,
        "/api/v1/github/app/conversion",
        json!({ "code": "code0123", "state": state }),
    );
    assert_eq!(status, 200, "{converted}");
    assert_eq!(
        converted["app"],
        json!({
            "id": APP_ID, "slug": "acme-ci", "name": "Acme CI", "owner": "acme-gh",
            "html_url": format!("{}/apps/acme-ci", d.github.base()),
        })
    );
    assert_eq!(
        converted["install_url"],
        format!("{}/apps/acme-ci/installations/new", d.github.base())
    );
    assert_eq!(*d.activated.lock().unwrap(), vec![APP_ID]);

    // In force at once: the webhook verifies with the new secret, sign-in uses the App's client.
    assert_eq!(
        d.hook(WEBHOOK_SECRET.as_bytes(), "{\"zen\":\"x\"}"),
        (200, json!({ "pong": true }))
    );
    assert_ne!(
        d.hook(b"some-other-secret-0123456789", "{\"zen\":\"x\"}").0,
        200
    );
    let (_, health) = d.get(&root, "/api/v1/health");
    assert_eq!(health["github_sign_in"], true);

    let (status, view) = d.get(&root, "/api/v1/github/app");
    assert_eq!(status, 200);
    assert_eq!(view["configured"], true);
    assert_eq!(view["source"], "manifest");
    assert_eq!(view["can_create"], false);
    assert_eq!(view["create_refusal"], "configured");
    assert_eq!(view["app"]["slug"], "acme-ci");

    // Replaying the state, or making a second App, is refused.
    let (status, replay) = d.post(
        &root,
        "/api/v1/github/app/conversion",
        json!({ "code": "code0123", "state": state }),
    );
    assert_eq!(status, 409, "{replay}");
    let (status, again) = d.post(
        &root,
        "/api/v1/github/app/manifest",
        json!({ "owner": { "kind": "user" } }),
    );
    assert_eq!(
        (status, &again["details"]["reason"]),
        (409, &json!("configured"))
    );

    // A signed-in non-administrator sees the reduced view.
    let alice = d.login("alice");
    let (status, reduced) = d.get(&alice, "/api/v1/github/app");
    assert_eq!(status, 200);
    assert_eq!(reduced["configured"], true);
    assert_eq!(reduced["public_url"], Value::Null);
    assert_eq!(reduced["webhook_url"], Value::Null);
    assert_eq!(reduced["can_create"], false);
    assert_eq!(reduced["app"]["slug"], "acme-ci");
    let (status, _, _) = d.call("GET", "/api/v1/github/app", None, &[]);
    assert_eq!(status, 401);

    assert!(
        d.audit_details()
            .iter()
            .any(|line| line == &format!("github-app-created app {APP_ID} acme-ci"))
    );
    assert_no_canary(&d);
}

/// No answer, audit row or database byte outside the sealed columns holds a canary.
fn assert_no_canary(d: &Deployment) {
    support::assert_clean_text(
        "an HTTP answer",
        &d.seen.lock().unwrap().join(
            "
",
        ),
    );
    support::assert_clean_text(
        "the audit log",
        &d.audit_details().join(
            "
",
        ),
    );
    support::assert_clean_database(d.dir.path());
}

#[test]
fn a_refused_state_answers_one_way_and_is_audited() {
    let d = deployment(Some(PUBLIC_URL), Files::None);
    let root = d.login("root");
    d.step_up(&root);
    let manifest = |s: &Session| {
        let (status, body) = d.post(
            s,
            "/api/v1/github/app/manifest",
            json!({ "owner": { "kind": "user" } }),
        );
        assert_eq!(status, 200, "{body}");
        body["state"].as_str().unwrap().to_owned()
    };
    let convert = |s: &Session, state: &str| {
        d.post(
            s,
            "/api/v1/github/app/conversion",
            json!({ "code": "code0123", "state": state }),
        )
    };
    let state = manifest(&root);
    // The same person in another session, and another platform administrator.
    let elsewhere = d.login("root");
    d.step_up(&elsewhere);
    let ops = d.login("ops");
    d.step_up(&ops);
    let wrong = "0".repeat(64);
    let mut answers = Vec::new();
    for (session, presented) in [
        (&elsewhere, state.as_str()),
        (&ops, state.as_str()),
        (&root, wrong.as_str()),
        (&root, "not-a-state"),
    ] {
        answers.push(convert(session, presented));
    }
    for (status, body) in &answers {
        assert_eq!(*status, 404, "{body}");
        assert_eq!(body["message"], answers[0].1["message"]);
    }
    assert_eq!(
        d.github.received().len(),
        0,
        "a refused state never reaches GitHub"
    );

    // Expiry: age the state as ten minutes would.
    d.store
        .writer()
        .write(|tx| {
            tx.execute_batch(
                "DROP TRIGGER github_app_state_update;
                 UPDATE github_app_states SET expires_ms = created_ms + 1;",
            )?;
            Ok(())
        })
        .unwrap();
    assert_eq!(convert(&root, &state).0, 404);

    let audit = d.audit_details();
    for line in [
        "github-app-state-refused manifest foreign",
        "github-app-state-refused manifest unknown",
        "github-app-state-refused manifest expired",
    ] {
        assert!(audit.iter().any(|l| l == line), "{line}: {audit:?}");
    }

    // A non-administrator never reaches the flow; a stale step-up is asked for again.
    let alice = d.login("alice");
    d.step_up(&alice);
    let (status, body) = d.post(
        &alice,
        "/api/v1/github/app/manifest",
        json!({ "owner": { "kind": "user" } }),
    );
    assert_eq!((status, body.get("details")), (403, None));
    assert_eq!(convert(&alice, &state).0, 403);
    let (status, body) = d.post(
        &root,
        "/api/v1/github/app/manifest",
        json!({ "owner": { "kind": "organization", "login": "../evil" } }),
    );
    assert_eq!(status, 400, "{body}");

    // A spent state stays spent even when GitHub fails the conversion.
    let fresh = manifest(&root);
    let (status, failed) = convert(&root, &fresh);
    assert_eq!(status, 502, "{failed}");
    assert_eq!(failed["code"], "upstream_failed");
    d.github.add_manifest("code0123", &d.conversion());
    assert_eq!(convert(&root, &fresh).0, 404);
    assert!(d.activated.lock().unwrap().is_empty());
    assert_no_canary(&d);
}

#[test]
fn an_installation_binds_only_for_its_account_or_an_owner_and_only_once() {
    let d = deployment(Some(PUBLIC_URL), Files::None);
    let root = d.configure();
    d.installation(11, "beta-gh", 8001, false);
    d.installation(12, "gamma-gh", 8002, false);
    d.installation(13, "alice-gh", 7001, true);
    d.installation(14, "someone-gh", 7999, true);
    d.github.add_user(7001, "alice-gh");
    d.github.add_user(7002, "bob-gh");
    d.org_role("beta-gh", 8001, "alice-gh", 7001, "admin");
    d.org_role("gamma-gh", 8002, "alice-gh", 7001, "member");
    d.org_role("beta-gh", 8001, "bob-gh", 7002, "admin");

    let alice = d.login("alice");
    let (status, minted) = d.mint(&alice, "beta", json!({}));
    assert_eq!(status, 200, "{minted}");
    let url = minted["install_url"].as_str().unwrap();
    assert!(
        url.starts_with(&format!(
            "{}/apps/acme-ci/installations/new?state=",
            d.github.base()
        )),
        "{url}"
    );
    let first = state_of(url);
    let (status, bound) = d.bind(&alice, 11, &first);
    assert_eq!(status, 200, "{bound}");
    assert_eq!(bound, json!({ "tenant": "beta", "account": "beta-gh" }));
    assert_eq!(d.bind(&alice, 11, &first).0, 404, "a state binds once");

    let next = |s: &Session, slug: &str| {
        state_of(
            d.mint(s, slug, json!({})).1["install_url"]
                .as_str()
                .unwrap(),
        )
    };
    let refusal = |(status, body): (u16, Value)| (status, body["details"]["reason"].clone());
    assert_eq!(
        refusal(d.bind(&alice, 12, &next(&alice, "beta"))),
        (403, json!("not_org_owner"))
    );
    assert_eq!(
        refusal(d.bind(&alice, 14, &next(&alice, "beta"))),
        (403, json!("cross_account"))
    );
    assert_eq!(
        refusal(d.bind(&alice, 99, &next(&alice, "beta"))),
        (403, json!("foreign_installation"))
    );
    // The tenant comes from the state: a personal installation lands where the state was minted.
    assert_eq!(
        d.bind(&alice, 13, &next(&alice, "beta")),
        (200, json!({ "tenant": "beta", "account": "alice-gh" }))
    );

    // Bob owns beta-gh on GitHub too, but the installation is bound to beta already.
    let bob = d.login("bob");
    assert_eq!(
        refusal(d.bind(&bob, 11, &next(&bob, "gamma"))),
        (409, json!("bound_elsewhere"))
    );
    // A state belongs to the person who minted it.
    let alices = next(&alice, "beta");
    assert_eq!(d.bind(&bob, 13, &alices).0, 404);
    // Bob administers gamma only, Carol administers nothing.
    assert_eq!(d.mint(&bob, "beta", json!({})).0, 404);
    let carol = d.login("carol");
    assert_eq!(d.mint(&carol, "beta", json!({})).0, 403);

    // A platform administrator outside the tenant gives a reason and a fresh step-up.
    assert_eq!(d.mint(&root, "gamma", json!({})).0, 400);
    let (status, minted) = d.mint(&root, "gamma", json!({ "reason": "onboarding gamma" }));
    assert_eq!(status, 200, "{minted}");
    let stale = d.login("root");
    let (status, body) = d.mint(&stale, "gamma", json!({ "reason": "onboarding gamma" }));
    assert_eq!((status, &body["details"]["step_up"]), (403, &json!(true)));
    assert!(
        d.audit_details()
            .iter()
            .any(|l| l == "platform-override onboarding gamma")
    );
    // An organization's installation never lands in a personal namespace.
    let (_, home) = d.mint(&root, "root-home", json!({ "reason": "home" }));
    assert_eq!(
        refusal(d.bind(&root, 12, &state_of(home["install_url"].as_str().unwrap()))),
        (403, json!("tenant_mismatch"))
    );
    // A platform administrator needs no GitHub proof: gamma-gh binds to gamma.
    assert_eq!(
        d.bind(
            &root,
            12,
            &state_of(minted["install_url"].as_str().unwrap())
        ),
        (200, json!({ "tenant": "gamma", "account": "gamma-gh" }))
    );
    let bound: Vec<(String, Vec<u8>)> = d
        .store
        .read(|c| {
            let mut stmt = c.prepare(
                "SELECT external_id, tenant_id FROM installations WHERE tenant_id IS NOT NULL ORDER BY external_id",
            )?;
            let mut rows = Vec::new();
            for row in stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))? {
                rows.push(row?);
            }
            Ok(rows)
        })
        .unwrap();
    assert_eq!(
        bound,
        vec![
            ("11".to_owned(), d.tenant("beta").as_bytes().to_vec()),
            ("12".to_owned(), d.tenant("gamma").as_bytes().to_vec()),
            ("13".to_owned(), d.tenant("beta").as_bytes().to_vec()),
        ]
    );
    let _ = d.root;
    assert_no_canary(&d);
}

#[test]
fn a_file_configuration_keeps_working_and_blocks_one_click_setup() {
    let d = deployment(Some(PUBLIC_URL), Files::App);
    let root = d.login("root");
    d.step_up(&root);
    let (status, view) = d.get(&root, "/api/v1/github/app");
    assert_eq!(status, 200);
    assert_eq!(view["configured"], true);
    assert_eq!(view["source"], "files");
    assert_eq!(view["app"]["id"], 1234);
    assert_eq!(view["can_create"], false);
    assert_eq!(view["create_refusal"], "files");
    let (status, body) = d.post(
        &root,
        "/api/v1/github/app/manifest",
        json!({ "owner": { "kind": "user" } }),
    );
    assert_eq!((status, &body["details"]["reason"]), (409, &json!("files")));
    assert_eq!(
        d.hook(b"file-webhook-secret-0123456789", "{\"zen\":\"x\"}"),
        (200, json!({ "pong": true }))
    );
    // The installation link reads the App's slug from GitHub once.
    d.github.set_app(
        &json!({
            "id": 1234, "slug": "files-ci", "name": "Files CI",
            "html_url": format!("{}/apps/files-ci", d.github.base()),
            "owner": { "login": "acme-gh", "id": 9000 },
        })
        .to_string(),
    );
    let (status, minted) = d.mint(&root, "acme", json!({}));
    assert_eq!(status, 200, "{minted}");
    assert!(
        minted["install_url"]
            .as_str()
            .unwrap()
            .starts_with(&format!(
                "{}/apps/files-ci/installations/new?state=",
                d.github.base()
            ))
    );
}

#[test]
fn an_unreachable_controller_is_told_so_and_gets_an_inactive_webhook() {
    let d = deployment(Some("https://ci.tail1234.ts.net"), Files::None);
    let root = d.login("root");
    d.step_up(&root);
    let (_, view) = d.get(&root, "/api/v1/github/app");
    assert_eq!(view["webhook_reachable"], false);
    assert_eq!(view["reason"], "tailnet_only");
    assert_eq!(view["can_create"], true);
    let (status, manifest) = d.post(
        &root,
        "/api/v1/github/app/manifest",
        json!({ "owner": { "kind": "user" } }),
    );
    assert_eq!(status, 200, "{manifest}");
    let text: Value = serde_json::from_str(manifest["manifest"].as_str().unwrap()).unwrap();
    assert_eq!(text["hook_attributes"]["active"], false);
    assert!(text.get("default_events").is_none());

    let none = deployment(None, Files::None);
    let root = none.login("root");
    let (_, view) = none.get(&root, "/api/v1/github/app");
    assert_eq!(view["webhook_reachable"], false);
    assert_eq!(view["reason"], "no_public_url");
    assert_eq!(view["webhook_url"], Value::Null);
    assert_eq!(view["can_create"], false);
    assert_eq!(view["create_refusal"], "no_public_url");
}
