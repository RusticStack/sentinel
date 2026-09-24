//! U07 over real HTTP on loopback: GitHub web sign-in through the browser
//! pages, against the A04 flow's GitHub-shaped fake
//! (`sentinel_github::fake`), with this test playing the browser — a cookie
//! jar, following the pages' links and the `303`s the way a browser does.
//!
//! Covered: a GitHub-only account (admitted by an identity-bound invitation)
//! approving an OAuth consent and a device code and landing back on the exact
//! page it came from; replayed, foreign and cookie-less state refused without
//! spending anything; open redirects in `return_to` refused before any state
//! exists; a pending account and a local account that merely shares the
//! GitHub login getting no session and no link; the cookies' attributes and
//! the fixation-safe replacement of a prior session; the per-client limit on
//! the start route; no GitHub code or token, and no Sentinel code, in any
//! page; and a deployment without GitHub configured offering no button.

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
/// The GitHub account admitted by invitation, and one nobody linked.
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

/// `root` (password) administering `acme` with repository `app`; `octo`, an
/// account that exists only through GitHub, admitted as an operator of
/// `acme` by an invitation bound to GitHub account [`OCTO`].
fn deployment(configured: bool) -> (Deployment, UserId) {
    let dir = tempfile::tempdir().unwrap();
    let store =
        Arc::new(Store::open(dir.path().join("metadata.sqlite"), Durability::Normal).unwrap());
    let logs = Arc::new(LogStore::open(dir.path().join("logs")).unwrap());
    let objects = Arc::new(Objects::open(dir.path()).unwrap());
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
        github_sign_in: configured.then(|| sentinel_api::GithubSignIn {
            client_id: "Iv1.fake0123456789".into(),
            client_secret: SECRET.into(),
            endpoints: github.endpoints(),
        }),
    })
    .unwrap();
    let base = format!("http://{}", server.local_addr());
    (
        Deployment {
            _dir: dir,
            store,
            _controller: controller,
            server: Some(server),
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

/// A browser: a cookie jar (name -> value), and everything it was served.
#[derive(Default)]
struct Browser {
    jar: Vec<(String, String)>,
    seen: Vec<String>,
    /// The fake GitHub's base URL, whose answers are not Sentinel's pages.
    github: String,
}

impl Browser {
    fn new(d: &Deployment) -> Browser {
        Browser {
            github: d.github.base(),
            ..Browser::default()
        }
    }

    fn cookie_header(&self) -> String {
        self.jar
            .iter()
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
        let cookies = self.cookie_header();
        let response = if method == "GET" {
            let mut r = agent.get(url);
            if !cookies.is_empty() {
                r = r.header("cookie", &cookies);
            }
            for (k, v) in extra {
                r = r.header(*k, *v);
            }
            r.call()
        } else {
            let mut r = agent.post(url);
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
            let pair = set.split(';').next().unwrap();
            let (name, value) = pair.split_once('=').unwrap();
            self.jar.retain(|(k, _)| k != name);
            if !set.contains("Max-Age=0") {
                self.jar.push((name.to_owned(), value.to_owned()));
            }
        }
        // What the browser was shown by Sentinel (GitHub's own redirect
        // back carries its code, as it must).
        if !url.starts_with(&self.github) {
            self.seen
                .push(format!("{:?}\n{}", reply.headers, reply.text));
        }
        reply
    }

    fn get(&mut self, url: &str) -> Reply {
        self.request("GET", url, None, &[])
    }
}

fn unescape(text: &str) -> String {
    text.replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
}

/// The "Sign in with GitHub" link of a sign-in page.
fn github_link(page: &Reply) -> String {
    let at = page
        .text
        .find("id=\"sentinel-github\" href=\"")
        .unwrap_or_else(|| panic!("no GitHub link in {}", page.text))
        + 27;
    unescape(page.text[at..].split('"').next().unwrap())
}

/// The destination of the page a successful callback answers.
fn continue_target(page: &Reply) -> String {
    let at = page.text.find("url=").expect("a refresh") + 4;
    unescape(page.text[at..].split('"').next().unwrap())
}

/// From a sign-in page to signed in: the GitHub link, GitHub (the fake,
/// signed in as whoever it is told), the callback. Returns the callback's
/// answer.
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
    browser.get(&back)
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

/// Nothing the browser was served holds a GitHub code or token, the client
/// secret, or a Sentinel authorization code or token.
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
    // Every GitHub code went only to the fake and the callback URL: none is
    // repeated in a page Sentinel rendered.
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
    // The page's CSP is unchanged, and has no form-action to block anything.
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

    // Start: a Lax, host-only sign-in cookie and a 303 to GitHub with no
    // scope and this deployment's exact callback.
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

    // The callback: a session like password login's, the sign-in cookie
    // cleared, and a page that continues to the exact authorize request.
    let done = browser.get(&back);
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
        !done.text.contains("sessionStorage"),
        "no CSRF copy for OAuth pages"
    );
    assert_eq!(done.header("x-frame-options"), Some("DENY"));
    assert_eq!(sessions_of(&d, octo), 1);

    // Back on the consent page, signed in: its form token is minted now,
    // from the new session. Approve, and the client gets its code.
    let consent = browser.get(&format!("{}{}", d.base, continue_target(&done)));
    assert_eq!(consent.status, 200, "{}", consent.text);
    // An account without a password has no username; the page says "you".
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
    // The token response is the client's, not a page; drop it before the
    // leak scan of what a browser was shown.
    browser
        .seen
        .retain(|page| !page.contains("\"access_token\""));
    for page in &browser.seen {
        assert!(!page.contains(&code) || page.contains("location"), "{page}");
    }
    assert_nothing_leaked(&d, &browser);
    // What reached GitHub: the secret only in the token request body.
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

    // Two sign-ins in two browsers, both at GitHub.
    let (mut a, mut b) = (Browser::new(&d), Browser::new(&d));
    let to_github = a.get(&start).header("location").unwrap().to_owned();
    let callback_a = a.get(&to_github).header("location").unwrap().to_owned();
    let to_github = b.get(&start).header("location").unwrap().to_owned();
    let callback_b = b.get(&to_github).header("location").unwrap().to_owned();
    assert_eq!(count(&d, "SELECT count(*) FROM sign_in_states"), 2);

    // B's callback in A's browser (a foreign state), and with no cookie at
    // all (a stolen callback URL): refused, nothing spent, no session.
    let foreign = a.get(&callback_b);
    assert_eq!(foreign.status, 400);
    assert!(
        foreign
            .set_cookies()
            .iter()
            .all(|c| !c.contains("sentinel_session"))
    );
    let bare = Browser::new(&d).get(&callback_b);
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

    // Each browser's own callback works once.
    assert_eq!(a.get(&callback_a).status, 200);
    assert_eq!(b.get(&callback_b).status, 200);
    assert_eq!(sessions_of(&d, octo), 2);

    // Replayed with the same cookie (put back): the state is spent.
    let state = callback_a.split("state=").nth(1).unwrap().to_owned();
    let mut replay = Browser::new(&d);
    replay
        .jar
        .push(("__Host-sentinel_signin".into(), state.clone()));
    let again = replay.get(&callback_a);
    assert_eq!(again.status, 400, "{}", again.text);
    assert!(
        again
            .set_cookies()
            .iter()
            .all(|c| !c.contains("sentinel_session"))
    );
    assert_eq!(sessions_of(&d, octo), 2);

    // A GitHub denial ends the attempt without a session.
    d.github.sign_in_as(None);
    let mut c = Browser::new(&d);
    let to_github = c.get(&start).header("location").unwrap().to_owned();
    let back = c.get(&to_github).header("location").unwrap().to_owned();
    let denied = c.get(&back);
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
    // No return_to is the first page.
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
    // A pending GitHub applicant, under approval-required registration.
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
    // A local account whose username, display name and (on GitHub) email all
    // match GitHub account 7777's — which nobody linked.
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
        let done = browser.get(&back);
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
    // A password session in this browser first (JSON login).
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
    let (name, value) = cookie.split(';').next().unwrap().split_once('=').unwrap();
    browser.jar.push((name.to_owned(), value.to_owned()));
    assert_eq!(sessions_of(&d, d.root), 1);

    let page = browser.get(&format!("{base}/"));
    assert!(page.text.contains("const github = true;"));
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
    // The old session is revoked; the new cookie is a different secret.
    assert_eq!(sessions_of(&d, d.root), 0);
    assert_eq!(sessions_of(&d, octo), 1);
    assert_ne!(browser.cookie("__Host-sentinel_session"), Some(value));
    // The first page gets its CSRF secret through session storage, and the
    // secret works as the header for this session.
    assert_eq!(continue_target(&done), "/");
    let needle = "sessionStorage.setItem(\"sentinel-csrf\", \"";
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
    // Refusals created no state.
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
    let index = browser.get(&format!("{}/", d.base));
    assert!(index.text.contains("const github = /*github*/false;"));
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
