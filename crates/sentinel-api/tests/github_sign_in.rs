use std::sync::Arc;

use sentinel_auth::oauth::pkce;
use sentinel_core::{
    RepoId, TenantId, UnixMillis, UserId,
    auth::{Namespace, Permissions as P, Principal, Role},
};
use sentinel_github::fake::{Account, FakeGithub};
use sentinel_link::{controller::Controller, identity::Identity};
use sentinel_protocol::oauth::CLI_CLIENT_ID;
use sentinel_store::{
    Durability, Store,
    auth::{self, Authority, NamespaceKind, provisioning},
    local_auth,
    logs::LogStore,
    objects::Objects,
    registration::{self, Admission, Applicant, DeploymentPolicy, Registration, Terms},
};
use serde_json::{Value, json};

const PASSWORD: &str = "correct horse battery staple";
const SECRET: &str = "fake-client-secret-0123456789";
const REDIRECT: &str = "http://127.0.0.1:49152/callback";
const OCTO: u64 = 4242;

fn octo_github() -> Account {
    Account {
        id: OCTO,
        login: "octo".into(),
        email: "octo@example.com".into(),
    }
}

struct Deployment {
    _dir: tempfile::TempDir,
    store: Arc<Store>,
    _controller: Controller,
    server: Option<sentinel_api::Server>,
    logs: Arc<LogStore>,
    objects: Arc<Objects>,
    key: Arc<sentinel_auth::sealed::Key>,
    configured: bool,
    github: FakeGithub,
    base: String,
    root: UserId,
}

impl Drop for Deployment {
    fn drop(&mut self) {
        if let Some(server) = self.server.take() {
            server.shutdown();
        }
    }
}

fn serve(
    store: &Arc<Store>,
    logs: &Arc<LogStore>,
    objects: &Arc<Objects>,
    key: &Arc<sentinel_auth::sealed::Key>,
    controller: &Controller,
    github: &FakeGithub,
    configured: bool,
) -> sentinel_api::Server {
    sentinel_api::Server::start(sentinel_api::Config {
        listen: "127.0.0.1:0".parse().unwrap(),
        store: Arc::clone(store),
        logs: Arc::clone(logs),
        objects: Arc::clone(objects),
        controller: controller.handle(),
        secret_key: Some(Arc::clone(key)),
        sessions: local_auth::Policy::default(),
        github_webhook_secret: None,
        intake: None,
        public_url: None,
        github_sign_in: configured.then(|| sentinel_api::GithubSignIn {
            client_id: "Iv1.fake0123456789".into(),
            client_secret: SECRET.into(),
            endpoints: github.endpoints(),
        }),
        trusted_proxies: sentinel_api::TrustedProxy::loopback(),
    })
    .unwrap()
}

impl Deployment {
    /// Stops the API server and starts a new one over the same store: everything the old one held in memory is gone.
    fn restart_api(&mut self) {
        self.server.take().unwrap().shutdown();
        let server = serve(
            &self.store,
            &self.logs,
            &self.objects,
            &self.key,
            &self._controller,
            &self.github,
            self.configured,
        );
        self.base = format!("http://{}", server.local_addr());
        self.server = Some(server);
    }
}

fn deployment(configured: bool) -> (Deployment, UserId) {
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
    let (tenant, repo) = (TenantId::new(), RepoId::new());
    store
        .writer()
        .write(move |tx| {
            let admin = Principal::new(root, P::ALL, None, None);
            auth::create_namespace(
                tx,
                admin,
                tenant,
                Namespace::parse("acme").unwrap(),
                NamespaceKind::Organization,
                now,
            )?;
            auth::set_membership(tx, admin, tenant, root, Role::TenantAdmin)?;
            auth::create_repo(tx, admin, tenant, repo, "app", now)
        })
        .unwrap();
    let subject = OCTO.to_string();
    let invitation = store
        .writer()
        .write(move |tx| {
            registration::invite(
                tx,
                Authority::HostLocal,
                Terms {
                    tenant: Some(tenant),
                    role: Some(Role::Operator),
                    identity: Some(("github", &subject)),
                    ..Terms::default()
                },
                now,
            )
        })
        .unwrap();
    let octo = match registration::register(
        &store,
        Applicant::External {
            display_name: "Octo",
            provider: "github",
            subject: &OCTO.to_string(),
        },
        Some(&invitation.secret),
        now,
    )
    .unwrap()
    {
        Admission::Admitted(user) => user,
        other => panic!("{other:?}"),
    };
    store
        .writer()
        .write(move |tx| {
            let admin = Principal::new(root, P::ALL, None, None);
            auth::set_repo_grant(tx, admin, repo, octo, P::READ.union(P::RUN))
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
    let github = FakeGithub::start(SECRET);
    let server = serve(
        &store,
        &logs,
        &objects,
        &key,
        &controller,
        &github,
        configured,
    );
    let base = format!("http://{}", server.local_addr());
    (
        Deployment {
            _dir: dir,
            store,
            _controller: controller,
            server: Some(server),
            logs,
            objects,
            key,
            configured,
            github,
            base,
            root,
        },
        octo,
    )
}

struct Reply {
    status: u16,
    headers: Vec<(String, String)>,
    text: String,
}

impl Reply {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }
    fn set_cookies(&self) -> Vec<&str> {
        self.headers
            .iter()
            .filter(|(n, _)| n == "set-cookie")
            .map(|(_, v)| v.as_str())
            .collect()
    }
    fn json(&self) -> Value {
        serde_json::from_str(&self.text).unwrap_or(Value::Null)
    }
}

/// Mimics the browser SameSite=Strict and Sec-Fetch-Site rules that the sign-in depends on.
#[derive(Default)]
struct Browser {
    jar: Vec<(String, String)>,
    strict: Vec<String>,
    cross_site: bool,
    seen: Vec<String>,
    github: String,
}

impl Browser {
    fn new(d: &Deployment) -> Browser {
        Browser {
            github: d.github.base(),
            ..Browser::default()
        }
    }

    fn cookie_header(&self, cross_site: bool) -> String {
        self.jar
            .iter()
            .filter(|(k, _)| !(cross_site && self.strict.contains(k)))
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join("; ")
    }

    fn cookie(&self, name: &str) -> Option<&str> {
        self.jar
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    fn request(
        &mut self,
        method: &str,
        url: &str,
        form: Option<&str>,
        extra: &[(&str, &str)],
    ) -> Reply {
        let agent = ureq::Agent::new_with_config(
            ureq::Agent::config_builder()
                .http_status_as_error(false)
                .max_redirects(0)
                .build(),
        );
        let cross_site = std::mem::take(&mut self.cross_site);
        let cookies = self.cookie_header(cross_site);
        let site = if url.starts_with(&self.github) {
            None
        } else if cross_site {
            Some("cross-site")
        } else {
            Some("same-origin")
        };
        let response = if method == "GET" {
            let mut r = agent.get(url);
            if let Some(site) = site {
                r = r.header("sec-fetch-site", site);
            }
            if !cookies.is_empty() {
                r = r.header("cookie", &cookies);
            }
            for (k, v) in extra {
                r = r.header(*k, *v);
            }
            r.call()
        } else {
            let mut r = agent.post(url);
            if let Some(site) = site {
                r = r.header("sec-fetch-site", site);
            }
            if !cookies.is_empty() {
                r = r.header("cookie", &cookies);
            }
            for (k, v) in extra {
                r = r.header(*k, *v);
            }
            r.header("content-type", "application/x-www-form-urlencoded")
                .send(form.unwrap_or_default().as_bytes())
        }
        .unwrap();
        let status = response.status().as_u16();
        let headers: Vec<(String, String)> = response
            .headers()
            .iter()
            .map(|(k, v)| {
                (
                    k.as_str().to_ascii_lowercase(),
                    v.to_str().unwrap_or("").to_owned(),
                )
            })
            .collect();
        let text = response.into_body().read_to_string().unwrap_or_default();
        let reply = Reply {
            status,
            headers,
            text,
        };
        for set in reply.set_cookies() {
            self.accept(set);
        }
        if !url.starts_with(&self.github) {
            self.seen
                .push(format!("{:?}\n{}", reply.headers, reply.text));
        }
        reply
    }

    fn get(&mut self, url: &str) -> Reply {
        self.request("GET", url, None, &[])
    }

    fn accept(&mut self, set: &str) {
        let pair = set.split(';').next().unwrap();
        let (name, value) = pair.split_once('=').unwrap();
        self.jar.retain(|(k, _)| k != name);
        self.strict.retain(|k| k != name);
        if !set.contains("Max-Age=0") {
            self.jar.push((name.to_owned(), value.to_owned()));
            if set.contains("SameSite=Strict") {
                self.strict.push(name.to_owned());
            }
        }
    }

    fn cross_site_get(&mut self, url: &str) -> Reply {
        self.cross_site = true;
        self.get(url)
    }

    fn callback(&mut self, url: &str) -> Reply {
        let back = self.cross_site_get(url);
        if back.status != 200 {
            return back;
        }
        let hop = continue_target(&back);
        assert!(hop.ends_with("/auth/github/finish"), "{hop}");
        let base = url.split("/auth/github/callback").next().unwrap();
        self.get(&format!("{base}{hop}"))
    }
}

fn unescape(text: &str) -> String {
    text.replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
}

fn github_link(page: &Reply) -> String {
    let at = page
        .text
        .find("id=\"sentinel-github\" href=\"")
        .unwrap_or_else(|| panic!("no GitHub link in {}", page.text))
        + 27;
    unescape(page.text[at..].split('"').next().unwrap())
}

fn continue_target(page: &Reply) -> String {
    let at = page.text.find("url=").expect("a refresh") + 4;
    unescape(page.text[at..].split('"').next().unwrap())
}

fn through_github(d: &Deployment, browser: &mut Browser, sign_in_page: &Reply) -> Reply {
    let start = browser.get(&github_link(sign_in_page));
    assert_eq!(start.status, 303, "{}", start.text);
    let to_github = start.header("location").unwrap().to_owned();
    assert!(to_github.starts_with(&d.github.base()), "{to_github}");
    let at_github = browser.get(&to_github);
    assert_eq!(at_github.status, 302);
    let back = at_github.header("location").unwrap().to_owned();
    assert!(
        back.starts_with(&format!("{}/auth/github/callback?", d.base)),
        "{back}"
    );
    browser.callback(&back)
}

fn encode(pairs: &[(&str, &str)]) -> String {
    form_urlencoded::Serializer::new(String::new())
        .extend_pairs(pairs)
        .finish()
}

fn authorize_query(challenge: &str) -> String {
    encode(&[
        ("response_type", "code"),
        ("client_id", CLI_CLIENT_ID),
        ("redirect_uri", REDIRECT),
        ("state", "client-state-123"),
        ("code_challenge", challenge),
        ("code_challenge_method", "S256"),
        ("scope", "runs:read logs:read"),
    ])
}

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
        out.push((name.to_owned(), unescape(value)));
    }
    out
}

fn count(d: &Deployment, sql: &str) -> i64 {
    d.store
        .read(|c| Ok(c.query_row(sql, [], |r| r.get::<_, i64>(0))?))
        .unwrap()
}

fn sessions_of(d: &Deployment, user: UserId) -> i64 {
    d.store
        .read(|c| {
            Ok(c.query_row(
                "SELECT count(*) FROM sessions WHERE user_id = ?1 AND revoked_ms IS NULL",
                [user.as_bytes().as_slice()],
                |r| r.get::<_, i64>(0),
            )?)
        })
        .unwrap()
}

fn assert_nothing_leaked(d: &Deployment, browser: &Browser) {
    let tokens = d.github.issued_tokens();
    assert!(!tokens.is_empty());
    for page in &browser.seen {
        for token in &tokens {
            assert!(!page.contains(token.as_str()), "a GitHub token in {page}");
        }
        assert!(!page.contains("gho_"), "{page}");
        assert!(!page.contains(SECRET), "{page}");
        assert!(
            !page.contains("sntl_at_") && !page.contains("sntl_rt_"),
            "{page}"
        );
    }
    for request in d.github.received() {
        if let Some(code) = request
            .split("code=")
            .nth(1)
            .map(|rest| rest.split(['&', ' ', '\r']).next().unwrap().to_owned())
            .filter(|c| c.starts_with("ghcode"))
        {
            for page in &browser.seen {
                assert!(!page.contains(&code), "the GitHub code in {page}");
            }
        }
    }
}

#[test]
fn a_github_only_account_approves_an_oauth_consent_and_lands_where_it_started() {
    let (d, octo) = deployment(true);
    d.github.sign_in_as(Some(octo_github()));
    let mut browser = Browser::new(&d);
    let verifier = pkce::verifier();
    let query = authorize_query(&pkce::challenge(&verifier));
    let page = browser.get(&format!("{}/oauth/authorize?{query}", d.base));
    assert_eq!(page.status, 200);
    assert!(page.text.contains("Sign in with GitHub"));
    assert!(
        page.text.contains("sentinel-sign-in"),
        "the password form stays"
    );
    let csp = page.header("content-security-policy").unwrap();
    assert!(csp.starts_with("default-src 'none'") && !csp.contains("form-action"));
    assert_eq!(
        github_link(&page),
        format!(
            "{}/auth/github/start?return_to={}",
            d.base,
            form_urlencoded::byte_serialize(format!("/oauth/authorize?{query}").as_bytes())
                .collect::<String>()
        )
    );

    let start = browser.get(&github_link(&page));
    assert_eq!(start.status, 303);
    let set = start.set_cookies();
    assert_eq!(set.len(), 1);
    assert!(set[0].starts_with("__Host-sentinel_signin="), "{}", set[0]);
    for attribute in [
        "Path=/",
        "Secure",
        "HttpOnly",
        "SameSite=Lax",
        "Max-Age=600",
    ] {
        assert!(set[0].contains(attribute), "{attribute}: {}", set[0]);
    }
    assert!(!set[0].contains("Domain="));
    let to_github = start.header("location").unwrap().to_owned();
    let expected_prefix = format!("{}/login/oauth/authorize?", d.github.base());
    assert!(to_github.starts_with(&expected_prefix), "{to_github}");
    assert!(to_github.contains("client_id=Iv1.fake0123456789"));
    assert!(to_github.contains(&format!(
        "redirect_uri={}",
        form_urlencoded::byte_serialize(format!("{}/auth/github/callback", d.base).as_bytes())
            .collect::<String>()
    )));
    assert!(to_github.contains("scope=&"));
    let at_github = browser.get(&to_github);
    let back = at_github.header("location").unwrap().to_owned();

    let done = browser.callback(&back);
    assert_eq!(done.status, 200, "{}", done.text);
    let set = done.set_cookies();
    let session = set
        .iter()
        .find(|c| c.starts_with("__Host-sentinel_session="))
        .expect("a session cookie");
    for attribute in [
        "Path=/",
        "Secure",
        "HttpOnly",
        "SameSite=Strict",
        "Max-Age=",
    ] {
        assert!(session.contains(attribute), "{attribute}: {session}");
    }
    assert!(!session.contains("Domain="));
    assert!(
        set.iter()
            .any(|c| c.starts_with("__Host-sentinel_signin=;") && c.contains("Max-Age=0"))
    );
    assert!(browser.cookie("__Host-sentinel_signin").is_none());
    assert_eq!(continue_target(&done), format!("/oauth/authorize?{query}"));
    assert!(
        !done.text.contains("sentinel-csrf"),
        "no CSRF copy for OAuth pages"
    );
    assert_eq!(done.header("x-frame-options"), Some("DENY"));
    assert_eq!(sessions_of(&d, octo), 1);

    let consent = browser.get(&format!("{}{}", d.base, continue_target(&done)));
    assert_eq!(consent.status, 200, "{}", consent.text);
    assert!(
        consent.text.contains("as <strong>you</strong>"),
        "{}",
        consent.text
    );
    let mut fields = hidden_fields(&consent.text);
    assert!(fields.iter().any(|(k, _)| k == "form_token"));
    fields.push(("decision".into(), "approve".into()));
    let pairs: Vec<(&str, &str)> = fields
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    let base = d.base.clone();
    let approved = browser.request(
        "POST",
        &format!("{base}/oauth/authorize"),
        Some(&encode(&pairs)),
        &[("origin", &base)],
    );
    assert_eq!(approved.status, 303, "{}", approved.text);
    let location = approved.header("location").unwrap().to_owned();
    assert!(location.starts_with(REDIRECT), "{location}");
    let code = form_urlencoded::parse(location.split_once('?').unwrap().1.as_bytes())
        .find(|(k, _)| k == "code")
        .unwrap()
        .1
        .into_owned();
    let token = browser.request(
        "POST",
        &format!("{base}/oauth/token"),
        Some(&encode(&[
            ("grant_type", "authorization_code"),
            ("client_id", CLI_CLIENT_ID),
            ("code", &code),
            ("redirect_uri", REDIRECT),
            ("code_verifier", &verifier),
        ])),
        &[],
    );
    assert_eq!(token.status, 200, "{}", token.text);
    let access = token.json()["access_token"].as_str().unwrap().to_owned();
    let me = Browser::new(&d).request(
        "GET",
        &format!("{base}/api/v1/me"),
        None,
        &[("authorization", &format!("Bearer {access}"))],
    );
    assert_eq!(me.json()["user"], json!(octo.to_string()));
    let runs = Browser::new(&d).request(
        "GET",
        &format!("{base}/api/v1/tenants/acme/repos/app/runs"),
        None,
        &[("authorization", &format!("Bearer {access}"))],
    );
    assert_eq!(runs.status, 200, "{}", runs.text);
    browser
        .seen
        .retain(|page| !page.contains("\"access_token\""));
    for page in &browser.seen {
        assert!(!page.contains(&code) || page.contains("location"), "{page}");
    }
    assert_nothing_leaked(&d, &browser);
    let received = d.github.received();
    assert!(
        received
            .iter()
            .all(|r| !r.lines().next().unwrap().contains(SECRET))
    );
    assert!(
        received
            .iter()
            .any(|r| r.starts_with("POST /login/oauth/access_token") && r.contains(SECRET))
    );
}

#[test]
fn a_github_only_account_approves_a_device_code() {
    let (d, octo) = deployment(true);
    d.github.sign_in_as(Some(octo_github()));
    let base = d.base.clone();
    let started = Browser::new(&d).request(
        "POST",
        &format!("{base}/oauth/device_authorization"),
        Some(&format!("client_id={CLI_CLIENT_ID}&scope=runs%3Aread")),
        &[],
    );
    assert_eq!(started.status, 200, "{}", started.text);
    let body = started.json();
    let device_code = body["device_code"].as_str().unwrap().to_owned();
    let complete = body["verification_uri_complete"]
        .as_str()
        .unwrap()
        .to_owned();
    let user_code = complete.split("user_code=").nth(1).unwrap().to_owned();

    let mut browser = Browser::new(&d);
    let page = browser.get(&complete);
    assert!(page.text.contains("Sign in with GitHub"), "{}", page.text);
    let done = through_github(&d, &mut browser, &page);
    assert_eq!(done.status, 200, "{}", done.text);
    assert_eq!(
        continue_target(&done),
        format!("/device?user_code={user_code}")
    );
    let approval = browser.get(&format!("{base}{}", continue_target(&done)));
    assert_eq!(approval.status, 200, "{}", approval.text);
    let at = approval.text.find("name=\"form_token\" value=\"").unwrap() + 25;
    let token = approval.text[at..at + 64].to_owned();
    let decided = browser.request(
        "POST",
        &format!("{base}/device"),
        Some(&format!(
            "user_code={user_code}&form_token={token}&action=approve&scope_runs%3Aread=1"
        )),
        &[],
    );
    assert_eq!(decided.status, 200, "{}", decided.text);
    assert!(decided.text.contains("Device connected"));
    let issued = Browser::new(&d).request(
        "POST",
        &format!("{base}/oauth/token"),
        Some(&format!(
            "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code&client_id={CLI_CLIENT_ID}&device_code={device_code}"
        )),
        &[],
    );
    assert_eq!(issued.status, 200, "{}", issued.text);
    let access = issued.json()["access_token"].as_str().unwrap().to_owned();
    let me = Browser::new(&d).request(
        "GET",
        &format!("{base}/api/v1/me"),
        None,
        &[("authorization", &format!("Bearer {access}"))],
    );
    assert_eq!(me.json()["user"], json!(octo.to_string()));
    let hex = device_code.strip_prefix("sntl_dc_").unwrap();
    assert!(browser.seen.iter().all(|p| !p.contains(hex)));
    assert_nothing_leaked(&d, &browser);
}

#[test]
fn replayed_foreign_and_cookie_less_states_are_refused_without_spending_anything() {
    let (d, octo) = deployment(true);
    d.github.sign_in_as(Some(octo_github()));
    let start = format!("{}/auth/github/start?return_to=%2Fdevice", d.base);

    let (mut a, mut b) = (Browser::new(&d), Browser::new(&d));
    let to_github = a.get(&start).header("location").unwrap().to_owned();
    let callback_a = a.get(&to_github).header("location").unwrap().to_owned();
    let to_github = b.get(&start).header("location").unwrap().to_owned();
    let callback_b = b.get(&to_github).header("location").unwrap().to_owned();
    assert_eq!(count(&d, "SELECT count(*) FROM sign_in_states"), 2);

    let foreign = a.cross_site_get(&callback_b);
    assert_eq!(foreign.status, 400);
    assert!(
        foreign
            .set_cookies()
            .iter()
            .all(|c| !c.contains("sentinel_session"))
    );
    let bare = Browser::new(&d).cross_site_get(&callback_b);
    assert_eq!(bare.status, 400);
    assert!(bare.set_cookies().is_empty());
    assert_eq!(
        count(
            &d,
            "SELECT count(*) FROM sign_in_states WHERE consumed_ms IS NULL"
        ),
        2
    );
    assert_eq!(sessions_of(&d, octo), 0);

    assert_eq!(a.callback(&callback_a).status, 200);
    assert_eq!(b.callback(&callback_b).status, 200);
    assert_eq!(sessions_of(&d, octo), 2);

    let state = callback_a.split("state=").nth(1).unwrap().to_owned();
    let mut replay = Browser::new(&d);
    replay
        .jar
        .push(("__Host-sentinel_signin".into(), state.clone()));
    let again = replay.callback(&callback_a);
    assert_eq!(again.status, 400, "{}", again.text);
    assert!(
        again
            .set_cookies()
            .iter()
            .all(|c| !c.contains("sentinel_session"))
    );
    assert_eq!(sessions_of(&d, octo), 2);

    d.github.sign_in_as(None);
    let mut c = Browser::new(&d);
    let to_github = c.get(&start).header("location").unwrap().to_owned();
    let back = c.get(&to_github).header("location").unwrap().to_owned();
    let denied = c.cross_site_get(&back);
    assert_eq!(denied.status, 403);
    assert!(denied.text.contains("cancelled"));
    assert_eq!(sessions_of(&d, octo), 2);
}

#[test]
fn return_to_accepts_only_the_sign_in_pages() {
    let (d, _) = deployment(true);
    for bad in [
        "https%3A%2F%2Fevil.example%2F",
        "%2F%2Fevil.example%2F",
        "%2F%5Cevil.example",
        "%2Fapi%2Fv1%2Fme",
        "%2F%3Fnext%3Dhttps%3A%2F%2Fevil.example",
        "%2Fdevice%23x",
        "%2Fdevice%3Fx%3D%22%3E%3Cscript%3E",
        "%2Fdevice&return_to=%2F",
        "javascript%3Aalert(1)",
    ] {
        let mut browser = Browser::new(&d);
        let reply = browser.get(&format!("{}/auth/github/start?return_to={bad}", d.base));
        assert_eq!(reply.status, 400, "{bad} accepted");
        assert!(reply.header("location").is_none(), "{bad}");
        assert!(reply.set_cookies().is_empty(), "{bad}");
    }
    assert_eq!(count(&d, "SELECT count(*) FROM sign_in_states"), 0);
    let reply = Browser::new(&d).get(&format!("{}/auth/github/start", d.base));
    assert_eq!(reply.status, 303);
    assert_eq!(
        count(
            &d,
            "SELECT count(*) FROM sign_in_states WHERE redirect_to = '/'"
        ),
        1
    );
}

#[test]
fn pending_and_merely_matching_accounts_get_no_session_and_no_link() {
    let (d, _) = deployment(true);
    d.store
        .writer()
        .write(|tx| {
            registration::set_policy(
                tx,
                Authority::HostLocal,
                DeploymentPolicy {
                    registration: Registration::ApprovalRequired,
                    ..registration::policy(tx)?
                },
                UnixMillis::now(),
            )
        })
        .unwrap();
    let pending = match registration::register(
        &d.store,
        Applicant::External {
            display_name: "Pending",
            provider: "github",
            subject: "5151",
        },
        None,
        UnixMillis::now(),
    )
    .unwrap()
    {
        Admission::Pending(user) => user,
        other => panic!("{other:?}"),
    };
    let now = UnixMillis::now();
    let phc = sentinel_auth::password::hash(PASSWORD.as_bytes()).unwrap();
    let local = UserId::new();
    d.store
        .writer()
        .write(move |tx| {
            provisioning::insert_human(tx, local, "octocat", false, now)?;
            local_auth::provision_credential(tx, Authority::HostLocal, local, "octocat", &phc, now)
        })
        .unwrap();
    let links_before = count(&d, "SELECT count(*) FROM external_identities");

    for (account, user) in [
        (
            Account {
                id: 5151,
                login: "pending".into(),
                email: "pending@example.com".into(),
            },
            pending,
        ),
        (
            Account {
                id: 7777,
                login: "octocat".into(),
                email: "octocat@example.com".into(),
            },
            local,
        ),
    ] {
        d.github.sign_in_as(Some(account));
        let mut browser = Browser::new(&d);
        let start = browser.get(&format!("{}/auth/github/start?return_to=%2Fdevice", d.base));
        let to_github = start.header("location").unwrap().to_owned();
        let back = browser
            .get(&to_github)
            .header("location")
            .unwrap()
            .to_owned();
        let done = browser.callback(&back);
        assert_eq!(done.status, 403, "{}", done.text);
        assert!(done.text.contains("No active Sentinel account"));
        assert!(
            done.set_cookies()
                .iter()
                .all(|c| !c.contains("sentinel_session"))
        );
        assert!(browser.cookie("__Host-sentinel_session").is_none());
        assert_eq!(sessions_of(&d, user), 0);
    }
    assert_eq!(
        count(&d, "SELECT count(*) FROM external_identities"),
        links_before
    );
    assert_eq!(count(&d, "SELECT count(*) FROM sessions"), 0);
}

#[test]
fn a_github_sign_in_replaces_the_browsers_previous_session() {
    let (d, octo) = deployment(true);
    d.github.sign_in_as(Some(octo_github()));
    let base = d.base.clone();
    let mut browser = Browser::new(&d);
    let agent = ureq::Agent::new_with_config(
        ureq::Agent::config_builder()
            .http_status_as_error(false)
            .build(),
    );
    let reply = agent
        .post(&format!("{base}/api/v1/login"))
        .header("content-type", "application/json")
        .send(
            json!({"username": "root", "password": PASSWORD})
                .to_string()
                .as_bytes(),
        )
        .unwrap();
    let cookie = reply
        .headers()
        .get("set-cookie")
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    let value = cookie
        .split(';')
        .next()
        .unwrap()
        .split_once('=')
        .unwrap()
        .1
        .to_owned();
    browser.accept(&cookie);
    assert_eq!(sessions_of(&d, d.root), 1);

    let health = browser.get(&format!("{base}/api/v1/health"));
    assert!(
        health.text.contains("\"github_sign_in\":true"),
        "{}",
        health.text
    );
    let done = through_github(
        &d,
        &mut browser,
        &Reply {
            status: 200,
            headers: Vec::new(),
            text: format!(
                "<a id=\"sentinel-github\" href=\"{base}/auth/github/start?return_to=%2F\">"
            ),
        },
    );
    assert_eq!(done.status, 200, "{}", done.text);
    assert_eq!(sessions_of(&d, d.root), 0);
    assert_eq!(sessions_of(&d, octo), 1);
    assert_ne!(
        browser.cookie("__Host-sentinel_session"),
        Some(value.as_str())
    );
    assert_eq!(continue_target(&done), "/");
    let needle = "localStorage.setItem(\"sentinel-csrf\", \"";
    let at = done.text.find(needle).unwrap() + needle.len();
    let csrf = done.text[at..at + 64].to_owned();
    let logout = browser.request(
        "POST",
        &format!("{base}/api/v1/logout"),
        Some(""),
        &[("x-sentinel-csrf", &csrf)],
    );
    assert_eq!(logout.status, 200, "{}", logout.text);
    assert_eq!(sessions_of(&d, octo), 0);
}

/// SameSite=Strict cookies are not sent on GitHub redirect back, so the same-origin hop does the hand-off.
#[test]
fn the_same_origin_hop_revokes_the_session_the_callback_could_not_see() {
    let (d, octo) = deployment(true);
    d.github.sign_in_as(Some(octo_github()));
    let base = d.base.clone();
    let agent = ureq::Agent::new_with_config(
        ureq::Agent::config_builder()
            .http_status_as_error(false)
            .build(),
    );
    let login = agent
        .post(&format!("{base}/api/v1/login"))
        .header("content-type", "application/json")
        .send(
            json!({"username": "root", "password": PASSWORD})
                .to_string()
                .as_bytes(),
        )
        .unwrap();
    let cookie = login
        .headers()
        .get("set-cookie")
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    assert!(cookie.contains("SameSite=Strict"), "{cookie}");
    let mut browser = Browser::new(&d);
    browser.accept(&cookie);
    assert_eq!(sessions_of(&d, d.root), 1);

    let start = browser.get(&format!("{base}/auth/github/start?return_to=%2F"));
    let to_github = start.header("location").unwrap().to_owned();
    let back = browser
        .get(&to_github)
        .header("location")
        .unwrap()
        .to_owned();
    let page = browser.cross_site_get(&back);
    assert_eq!(page.status, 200, "{}", page.text);
    assert!(page.set_cookies().is_empty(), "{:?}", page.set_cookies());
    assert_eq!(continue_target(&page), "/auth/github/finish");
    assert_eq!(sessions_of(&d, d.root), 1);
    assert_eq!(sessions_of(&d, octo), 0);
    let finish = format!("{base}/auth/github/finish");

    let forged = browser.cross_site_get(&finish);
    assert_eq!(forged.status, 403, "{}", forged.text);
    assert_eq!(Browser::new(&d).get(&finish).status, 400);
    let mut stranger = Browser::new(&d);
    stranger
        .jar
        .push(("__Host-sentinel_signin".into(), "0".repeat(64)));
    assert_eq!(stranger.get(&finish).status, 400);
    assert_eq!(sessions_of(&d, d.root), 1);
    assert_eq!(sessions_of(&d, octo), 0);

    let done = browser.get(&finish);
    assert_eq!(done.status, 200, "{}", done.text);
    assert_eq!(continue_target(&done), "/");
    assert_eq!(sessions_of(&d, d.root), 0);
    assert_eq!(sessions_of(&d, octo), 1);
    assert!(browser.cookie("__Host-sentinel_signin").is_none());

    assert_eq!(browser.get(&finish).status, 400);
    assert_eq!(sessions_of(&d, octo), 1);
}

fn signed_in(d: &Deployment, username: &str) -> (Browser, String) {
    let agent = ureq::Agent::new_with_config(
        ureq::Agent::config_builder()
            .http_status_as_error(false)
            .build(),
    );
    let mut login = agent
        .post(&format!("{}/api/v1/login", d.base))
        .header("content-type", "application/json")
        .send(
            json!({"username": username, "password": PASSWORD})
                .to_string()
                .as_bytes(),
        )
        .unwrap();
    assert_eq!(login.status().as_u16(), 200);
    let cookie = login
        .headers()
        .get("set-cookie")
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    let body: Value = serde_json::from_str(&login.body_mut().read_to_string().unwrap()).unwrap();
    let mut browser = Browser::new(d);
    browser.accept(&cookie);
    (browser, body["csrf"].as_str().unwrap().to_owned())
}

fn api_post(
    d: &Deployment,
    browser: &Browser,
    path: &str,
    body: Value,
    csrf: &str,
) -> (u16, Value) {
    let agent = ureq::Agent::new_with_config(
        ureq::Agent::config_builder()
            .http_status_as_error(false)
            .build(),
    );
    let mut response = agent
        .post(&format!("{}{path}", d.base))
        .header("content-type", "application/json")
        .header("cookie", &browser.cookie_header(false))
        .header("x-sentinel-csrf", csrf)
        .send(body.to_string().as_bytes())
        .unwrap();
    let status = response.status().as_u16();
    let text = response.body_mut().read_to_string().unwrap_or_default();
    (status, serde_json::from_str(&text).unwrap_or(Value::Null))
}

fn link_through_github(d: &Deployment, browser: &mut Browser, csrf: &str) -> Reply {
    let started = browser.request(
        "POST",
        &format!("{}/api/v1/identities/github/link", d.base),
        Some("{}"),
        &[("x-sentinel-csrf", csrf)],
    );
    assert_eq!(started.status, 200, "{}", started.text);
    let authorize = started.json()["authorize_url"].as_str().unwrap().to_owned();
    assert!(authorize.starts_with(&d.github.base()), "{authorize}");
    assert!(browser.cookie("__Host-sentinel_signin").is_some());
    let at_github = browser.get(&authorize);
    assert_eq!(at_github.status, 302);
    let back = at_github.header("location").unwrap().to_owned();
    browser.callback(&back)
}

fn linked_subjects(d: &Deployment, user: UserId) -> Vec<String> {
    d.store
        .read(|c| sentinel_store::sign_in::identities(c, Authority::HostLocal, user))
        .unwrap()
        .into_iter()
        .map(|i| format!("{}:{}", i.provider, i.subject))
        .collect()
}

#[test]
fn a_signed_in_account_links_github_through_its_own_session_after_a_step_up() {
    let (d, _octo) = deployment(true);
    d.github.sign_in_as(Some(Account {
        id: 9001,
        login: "root-gh".into(),
        email: "root@example.com".into(),
    }));
    let (mut browser, csrf) = signed_in(&d, "root");
    let link = format!("{}/api/v1/identities/github/link", d.base);

    let cold = browser.request("POST", &link, Some("{}"), &[("x-sentinel-csrf", &csrf)]);
    assert_eq!(cold.status, 403, "{}", cold.text);
    assert_eq!(cold.json()["details"]["step_up"], true);
    assert!(browser.cookie("__Host-sentinel_signin").is_none());
    assert_eq!(browser.request("POST", &link, Some("{}"), &[]).status, 403);
    let anonymous = Browser::new(&d).request("POST", &link, Some("{}"), &[]);
    assert_eq!(anonymous.status, 401);

    let (status, body) = api_post(
        &d,
        &browser,
        "/api/v1/step-up",
        json!({ "method": "password", "code": PASSWORD }),
        &csrf,
    );
    assert_eq!(status, 200, "{body}");
    let done = link_through_github(&d, &mut browser, &csrf);
    assert_eq!(done.status, 200, "{}", done.text);
    assert!(done.text.contains("GitHub is linked"), "{}", done.text);

    assert_eq!(linked_subjects(&d, d.root), ["github:9001"]);
    assert_eq!(sessions_of(&d, d.root), 1);
    assert!(browser.cookie("__Host-sentinel_signin").is_none());
    assert_eq!(
        browser
            .get(&format!("{}/auth/github/finish", d.base))
            .status,
        400
    );
    let security = browser.get(&format!("{}/api/v1/me/security", d.base));
    assert_eq!(
        security.json()["identities"][0]["provider"],
        "github",
        "{}",
        security.text
    );
    assert!(
        security.json()["identities"][0].get("subject").is_none(),
        "no subject is shown"
    );
    assert_nothing_leaked(&d, &browser);
}

#[test]
fn an_identity_already_linked_elsewhere_is_never_taken() {
    let (d, octo) = deployment(true);
    d.github.sign_in_as(Some(octo_github()));
    let (mut browser, csrf) = signed_in(&d, "root");
    let (status, _) = api_post(
        &d,
        &browser,
        "/api/v1/step-up",
        json!({ "method": "password", "code": PASSWORD }),
        &csrf,
    );
    assert_eq!(status, 200);

    let done = link_through_github(&d, &mut browser, &csrf);
    assert_eq!(done.status, 409, "{}", done.text);
    assert!(linked_subjects(&d, d.root).is_empty());
    assert_eq!(linked_subjects(&d, octo), ["github:4242"]);
}

#[test]
fn a_link_completes_only_in_the_session_that_began_it() {
    let (d, _) = deployment(true);
    d.github.sign_in_as(Some(Account {
        id: 9002,
        login: "root-gh".into(),
        email: "root@example.com".into(),
    }));
    let (mut browser, csrf) = signed_in(&d, "root");
    let (status, _) = api_post(
        &d,
        &browser,
        "/api/v1/step-up",
        json!({ "method": "password", "code": PASSWORD }),
        &csrf,
    );
    assert_eq!(status, 200);
    let started = browser.request(
        "POST",
        &format!("{}/api/v1/identities/github/link", d.base),
        Some("{}"),
        &[("x-sentinel-csrf", &csrf)],
    );
    let authorize = started.json()["authorize_url"].as_str().unwrap().to_owned();
    let back = browser
        .get(&authorize)
        .header("location")
        .unwrap()
        .to_owned();
    let page = browser.cross_site_get(&back);
    assert_eq!(page.status, 200, "{}", page.text);

    let (other, _) = signed_in(&d, "root");
    let (name, value) = other.jar[0].clone();
    browser.jar.retain(|(k, _)| *k != name);
    browser.jar.push((name, value));
    let hop = browser.get(&format!("{}/auth/github/finish", d.base));
    assert_eq!(hop.status, 403, "{}", hop.text);
    assert!(linked_subjects(&d, d.root).is_empty());
    assert_eq!(
        browser
            .get(&format!("{}/auth/github/finish", d.base))
            .status,
        400
    );
}

fn csrf_from(page: &Reply) -> String {
    let at = page
        .text
        .find("sentinel-csrf\", \"")
        .expect("a CSRF secret")
        + 17;
    page.text[at..].split('"').next().unwrap().to_owned()
}

#[test]
fn a_github_only_account_enrolls_a_second_factor_and_can_then_step_up() {
    let (d, _octo) = deployment(true);
    d.github.sign_in_as(Some(octo_github()));
    let sign_in = |d: &Deployment| -> (Browser, String) {
        let mut browser = Browser::new(d);
        let start = browser.get(&format!("{}/auth/github/start?return_to=%2F", d.base));
        let to_github = start.header("location").unwrap().to_owned();
        let back = browser
            .get(&to_github)
            .header("location")
            .unwrap()
            .to_owned();
        let done = browser.callback(&back);
        assert_eq!(done.status, 200, "{}", done.text);
        let csrf = csrf_from(&done);
        (browser, csrf)
    };
    let (mut browser, csrf) = sign_in(&d);
    let state = browser
        .get(&format!("{}/api/v1/me/security", d.base))
        .json();
    assert_eq!(
        (
            state["password"].as_bool(),
            state["mfa"]["enrolled"].as_bool()
        ),
        (Some(false), Some(false)),
        "{state}"
    );
    let (status, body) = api_post(
        &d,
        &browser,
        "/api/v1/password",
        json!({ "current": PASSWORD, "new": "some other long passphrase" }),
        &csrf,
    );
    assert_eq!(
        (status, body["message"].as_str()),
        (403, Some("password change refused"))
    );

    let (status, body) = api_post(&d, &browser, "/api/v1/mfa/enroll", json!({}), &csrf);
    assert_eq!(status, 200, "{body}");
    let uri = body["provisioning_uri"].as_str().unwrap();
    assert!(uri.starts_with("otpauth://totp/"), "{uri}");
    let start = uri.find("secret=").unwrap() + 7;
    let end = uri[start..].find('&').map_or(uri.len(), |e| start + e);
    let seed = sentinel_auth::mfa::Seed::from_base32(&uri[start..end]).unwrap();
    let seconds = UnixMillis::now().0 as u64 / 1000;
    let code = (0..1_000_000u32)
        .map(|n| format!("{n:06}"))
        .find(|c| sentinel_auth::mfa::check(&seed, c, seconds).is_some())
        .unwrap();
    let (status, body) = api_post(
        &d,
        &browser,
        "/api/v1/mfa/enroll/confirm",
        json!({ "code": code }),
        &csrf,
    );
    assert_eq!(status, 200, "{body}");
    let recovery = body["recovery_codes"][0].as_str().unwrap().to_owned();

    let (later, later_csrf) = sign_in(&d);
    let (status, body) = api_post(
        &d,
        &later,
        "/api/v1/step-up",
        json!({ "method": "password", "code": PASSWORD }),
        &later_csrf,
    );
    assert_eq!(status, 403, "{body}");
    let (status, body) = api_post(
        &d,
        &later,
        "/api/v1/step-up",
        json!({ "method": "recovery", "code": recovery }),
        &later_csrf,
    );
    assert_eq!(status, 200, "{body}");
}

#[test]
fn the_start_route_is_limited_per_client() {
    let (d, _) = deployment(true);
    let url = format!("{}/auth/github/start?return_to=%2Fdevice", d.base);
    let mut statuses = Vec::new();
    for _ in 0..16 {
        statuses.push(Browser::new(&d).get(&url).status);
    }
    assert!(statuses[..10].iter().all(|s| *s == 303), "{statuses:?}");
    assert!(statuses.contains(&429), "{statuses:?}");
    assert_eq!(
        count(&d, "SELECT count(*) FROM sign_in_states") as usize,
        statuses.iter().filter(|s| **s == 303).count()
    );
}

#[test]
fn without_github_configured_no_page_offers_it_and_the_routes_do_not_exist() {
    let (d, _) = deployment(false);
    let mut browser = Browser::new(&d);
    let query = authorize_query(&pkce::challenge(&pkce::verifier()));
    let page = browser.get(&format!("{}/oauth/authorize?{query}", d.base));
    assert_eq!(page.status, 200);
    assert!(!page.text.contains("Sign in with GitHub"));
    let device = browser.get(&format!("{}/device", d.base));
    assert!(!device.text.contains("Sign in with GitHub"));
    let health = browser.get(&format!("{}/api/v1/health", d.base));
    assert!(
        health.text.contains("\"github_sign_in\":false"),
        "{}",
        health.text
    );
    for path in [
        "/auth/github/start?return_to=%2F",
        "/auth/github/callback?code=a&state=b",
    ] {
        assert_eq!(
            browser.get(&format!("{}{path}", d.base)).status,
            404,
            "{path}"
        );
    }
}

/// Hand-offs live in controller memory (docs/github-sign-in.md, "A restart between the callback and the finish").
/// The loss is accepted: the state was spent at the callback, so the browser must start over, and nothing is issued.
#[test]
fn a_restart_between_the_callback_and_the_finish_issues_nothing_and_a_new_sign_in_works() {
    let (mut d, octo) = deployment(true);
    d.github.sign_in_as(Some(octo_github()));
    let mut browser = Browser::new(&d);

    let start = browser.get(&format!("{}/auth/github/start?return_to=%2F", d.base));
    assert_eq!(start.status, 303, "{}", start.text);
    let to_github = start.header("location").unwrap().to_owned();
    let back = browser
        .get(&to_github)
        .header("location")
        .unwrap()
        .to_owned();
    let page = browser.cross_site_get(&back);
    assert_eq!(page.status, 200, "{}", page.text);
    assert_eq!(continue_target(&page), "/auth/github/finish");
    assert_eq!(sessions_of(&d, octo), 0);

    d.restart_api();
    let finish = format!("{}/auth/github/finish", d.base);
    let lost = browser.get(&finish);
    assert_eq!(lost.status, 400, "{}", lost.text);
    assert!(lost.text.contains("Start again"), "{}", lost.text);
    assert_eq!(sessions_of(&d, octo), 0);
    assert!(browser.cookie("__Host-sentinel_signin").is_none());
    assert!(
        lost.set_cookies()
            .iter()
            .all(|c| !c.contains("sentinel_session")),
        "{:?}",
        lost.set_cookies()
    );

    // The old callback URL cannot be replayed either: its state was spent before the restart.
    let replay = browser.cross_site_get(
        &back.replace(back.split("/auth/github/callback").next().unwrap(), &d.base),
    );
    assert_eq!(replay.status, 400, "{}", replay.text);
    assert_eq!(sessions_of(&d, octo), 0);

    // Starting again on the restarted server completes normally.
    let start = browser.get(&format!("{}/auth/github/start?return_to=%2F", d.base));
    assert_eq!(start.status, 303, "{}", start.text);
    let to_github = start.header("location").unwrap().to_owned();
    let back = browser
        .get(&to_github)
        .header("location")
        .unwrap()
        .to_owned();
    let done = browser.callback(&back);
    assert_eq!(done.status, 200, "{}", done.text);
    assert_eq!(continue_target(&done), "/");
    assert_eq!(sessions_of(&d, octo), 1);
}
