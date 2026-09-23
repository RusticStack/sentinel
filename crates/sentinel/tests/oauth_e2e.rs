//! O07: the OAuth sign-in end to end, portable. The real `sentinel` binary
//! (`CARGO_BIN_EXE_sentinel`) runs against an in-process controller API on
//! loopback, with a temporary `SENTINEL_CONFIG_DIR` and the file credential
//! store. A "browser" is played by this test: it signs in with a local
//! password (`/api/v1/login`), submits the consent or device page with the
//! session cookie, and follows the `303` to the CLI's own loopback
//! listener. Opening a real browser is not automated: every browser login
//! here uses `--no-browser`, which prints the same URL.
//!
//! Every CLI output (stdout and stderr) passes [`assert_no_token_material`].
//!
//! The server's clock cannot be moved, so the two "outside the 60 s grace
//! window" presentations go through `sentinel_store::oauth::refresh` with a
//! clock 61 s ahead; their effect (a revoked grant) is observed over HTTP.

use std::{
    io::{BufRead, BufReader, Read},
    net::TcpListener,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        Arc, Mutex,
        mpsc::{self, Receiver},
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use sentinel_auth::{
    oauth::{self as forms, Kind, pkce},
    secret::Secret,
};
use sentinel_core::{
    GrantId, RepoId, TenantId, UnixMillis, UserId,
    auth::{Audience, Namespace, Permissions as P, Principal, Role, Scopes},
};
use sentinel_link::{controller::Controller, identity::Identity};
use sentinel_protocol::oauth::CLI_CLIENT_ID;
use sentinel_store::{
    Durability, Store,
    auth::{self, Authority, NamespaceKind, provisioning},
    local_auth::{self, Event},
    logs::LogStore,
    oauth::{self, GrantKind, NewGrant, RefreshError},
    objects::Objects,
    tokens::{self, Grant},
};
use serde_json::{Value, json};

const PASSWORD: &str = "correct horse battery staple";
/// Bound on any one CLI process, so a hang fails the test instead of CI.
const PROCESS_LIMIT: Duration = Duration::from_secs(90);

// ---------------------------------------------------------------- harness

struct Deployment {
    _dir: tempfile::TempDir,
    store: Arc<Store>,
    _controller: Controller,
    server: Option<sentinel_api::Server>,
    /// `http://127.0.0.1:PORT`; also the issuer.
    base: String,
    /// An `sntl_` credential for root with every permission.
    root_token: String,
    dev: UserId,
    tenant: TenantId,
}

impl Deployment {
    fn stop(&mut self) {
        if let Some(server) = self.server.take() {
            server.shutdown();
        }
    }
}

impl Drop for Deployment {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Super admin `root` administering `acme` (repository `app`); `dev`, an
/// operator of `acme` with read and run on `app`; both sign in with
/// [`PASSWORD`].
fn deployment() -> Deployment {
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
    let granted =
        tokens::provision(&store, Grant::new(root, "e2e", P::ALL), UnixMillis::now()).unwrap();
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
        root_token: sentinel_auth::token::format(&granted.secret),
        dev,
        tenant,
    }
}

/// One HTTP answer: status, headers (lower-case names), body as JSON or a
/// JSON string.
struct Reply {
    status: u16,
    headers: Vec<(String, String)>,
    body: Value,
}

impl Reply {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }
    fn text(&self) -> &str {
        self.body.as_str().unwrap_or_default()
    }
}

enum Body<'a> {
    None,
    Json(&'a Value),
    Form(&'a str),
}

/// One request to an absolute URL; redirects are returned, not followed.
fn request(method: &str, url: &str, body: Body<'_>, headers: &[(&str, &str)]) -> Reply {
    let agent = ureq::Agent::new_with_config(
        ureq::Agent::config_builder()
            .http_status_as_error(false)
            .max_redirects(0)
            .timeout_global(Some(Duration::from_secs(30)))
            .build(),
    );
    let response = match method {
        "GET" => {
            let mut r = agent.get(url);
            for (k, v) in headers {
                r = r.header(*k, *v);
            }
            r.call()
        }
        _ => {
            let mut r = match method {
                "POST" => agent.post(url),
                "PUT" => agent.put(url),
                _ => unreachable!(),
            };
            for (k, v) in headers {
                r = r.header(*k, *v);
            }
            match body {
                Body::None => r.send_empty(),
                Body::Json(value) => r
                    .header("content-type", "application/json")
                    .send(value.to_string().as_bytes()),
                Body::Form(form) => r
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
    let text = response.into_body().read_to_string().unwrap_or_default();
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

fn send(
    d: &Deployment,
    method: &str,
    path: &str,
    body: Body<'_>,
    headers: &[(&str, &str)],
) -> Reply {
    request(method, &format!("{}{path}", d.base), body, headers)
}

fn encode(pairs: &[(&str, &str)]) -> String {
    form_urlencoded::Serializer::new(String::new())
        .extend_pairs(pairs)
        .finish()
}

/// A password session for `username`: the `cookie` header value.
fn session(d: &Deployment, username: &str) -> String {
    let reply = send(
        d,
        "POST",
        "/api/v1/login",
        Body::Json(&json!({ "username": username, "password": PASSWORD })),
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
}

fn me(d: &Deployment, access: &str) -> Reply {
    send(
        d,
        "GET",
        "/api/v1/me",
        Body::None,
        &[("authorization", &format!("Bearer {access}"))],
    )
}

fn refresh_http(d: &Deployment, refresh: &str) -> Reply {
    send(
        d,
        "POST",
        "/oauth/token",
        Body::Form(&encode(&[
            ("grant_type", "refresh_token"),
            ("client_id", CLI_CLIENT_ID),
            ("refresh_token", refresh),
        ])),
        &[],
    )
}

fn grant_revoked(d: &Deployment, grant: GrantId) -> bool {
    d.store
        .read(|c| {
            Ok(c.query_row(
                "SELECT revoked_ms IS NOT NULL FROM oauth_grants WHERE id = ?1",
                [grant.as_bytes().as_slice()],
                |r| r.get::<_, bool>(0),
            )?)
        })
        .unwrap()
}

fn refresh_rows(d: &Deployment, grant: GrantId) -> i64 {
    d.store
        .read(|c| {
            Ok(c.query_row(
                "SELECT count(*) FROM oauth_refresh_tokens WHERE grant_id = ?1",
                [grant.as_bytes().as_slice()],
                |r| r.get::<_, i64>(0),
            )?)
        })
        .unwrap()
}

/// Token material: `sntl_` (optionally a kind prefix) followed by at least
/// 16 hex digits. Plain mentions such as "a sntl_rt_ refresh token" are
/// fine; a token, or a recognizable part of one, is not.
fn assert_no_token_material(what: &str, text: &str) {
    let mut from = 0;
    while let Some(at) = text[from..].find("sntl_") {
        let start = from + at + 5;
        let rest = &text[start..];
        let rest = ["at_", "rt_", "ac_", "dc_"]
            .iter()
            .find_map(|p| rest.strip_prefix(p))
            .unwrap_or(rest);
        let hex = rest.bytes().take_while(u8::is_ascii_hexdigit).count();
        assert!(hex < 16, "token material in {what}: {text}");
        from = start;
    }
    assert!(
        !text.contains("sntl_dc_"),
        "a device code in {what}: {text}"
    );
}

/// One CLI user: a configuration directory and the file credential store.
struct Machine {
    dir: tempfile::TempDir,
}

impl Machine {
    fn new() -> Machine {
        Machine {
            dir: tempfile::tempdir().unwrap(),
        }
    }

    fn config(&self) -> PathBuf {
        self.dir.path().join("config")
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_sentinel"));
        command
            .env("SENTINEL_CONFIG_DIR", self.config())
            .env("SENTINEL_CREDENTIAL_STORE", "file")
            .env_remove("SENTINEL_TOKEN")
            .env_remove("SENTINEL_SERVER")
            .env_remove("SENTINEL_PROFILE")
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        command
    }

    /// Start the CLI; its stderr lines are readable as they arrive.
    fn spawn(&self, args: &[&str]) -> Running {
        Running::start(self.command(args).spawn().unwrap())
    }

    fn run(&self, args: &[&str]) -> Out {
        self.spawn(args).finish()
    }

    fn run_env(&self, env: &[(&str, &str)], args: &[&str]) -> Out {
        let mut command = self.command(args);
        for (k, v) in env {
            command.env(k, v);
        }
        Running::start(command.spawn().unwrap()).finish()
    }

    /// The stored credential blob of `profile`.
    fn credentials(&self, profile: &str) -> Option<Value> {
        let path = self
            .config()
            .join("credentials")
            .join(format!("{profile}.json"));
        std::fs::read(path)
            .ok()
            .map(|b| serde_json::from_slice(&b).unwrap())
    }

    fn write_credentials(&self, profile: &str, blob: &Value) {
        let path = self
            .config()
            .join("credentials")
            .join(format!("{profile}.json"));
        std::fs::write(&path, blob.to_string()).unwrap();
        // A re-created file must be owner-only again, or the store refuses it.
        #[cfg(unix)]
        std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o600))
            .unwrap();
    }

    fn profiles(&self) -> Value {
        serde_json::from_slice(&std::fs::read(self.config().join("profiles.json")).unwrap())
            .unwrap()
    }

    fn grant(&self, profile: &str) -> GrantId {
        self.profiles()["profiles"][profile]["grant"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap()
    }
}

/// A finished CLI process.
#[derive(Debug)]
struct Out {
    code: i32,
    stdout: String,
    stderr: String,
}

/// A running CLI process whose output is collected on reader threads.
struct Running {
    child: Child,
    lines: Receiver<String>,
    stderr: Arc<Mutex<String>>,
    stdout: thread::JoinHandle<String>,
    stderr_reader: thread::JoinHandle<()>,
}

impl Running {
    fn start(mut child: Child) -> Running {
        let err = child.stderr.take().unwrap();
        let mut out = child.stdout.take().unwrap();
        let (tx, lines) = mpsc::channel();
        let stderr = Arc::new(Mutex::new(String::new()));
        let collected = Arc::clone(&stderr);
        let stderr_reader = thread::spawn(move || {
            for line in BufReader::new(err).lines() {
                let Ok(line) = line else { break };
                let mut all = collected.lock().unwrap();
                all.push_str(&line);
                all.push('\n');
                let _ = tx.send(line);
            }
        });
        let stdout = thread::spawn(move || {
            let mut text = String::new();
            let _ = out.read_to_string(&mut text);
            text
        });
        Running {
            child,
            lines,
            stderr,
            stdout,
            stderr_reader,
        }
    }

    /// The first stderr line containing `needle`.
    fn line_with(&self, needle: &str) -> String {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            match self.lines.recv_timeout(left) {
                Ok(line) if line.contains(needle) => return line,
                Ok(_) => {}
                Err(_) => panic!(
                    "no stderr line with {needle:?}: {}",
                    self.stderr.lock().unwrap()
                ),
            }
        }
    }

    fn finish(mut self) -> Out {
        let deadline = Instant::now() + PROCESS_LIMIT;
        let status = loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                break status;
            }
            if Instant::now() >= deadline {
                let _ = self.child.kill();
                panic!("the CLI did not finish: {}", self.stderr.lock().unwrap());
            }
            thread::sleep(Duration::from_millis(20));
        };
        let stdout = self.stdout.join().unwrap();
        self.stderr_reader.join().unwrap();
        let stderr = std::mem::take(&mut *self.stderr.lock().unwrap());
        assert_no_token_material("stdout", &stdout);
        assert_no_token_material("stderr", &stderr);
        Out {
            code: status.code().unwrap_or(-1),
            stdout,
            stderr,
        }
    }
}

/// Every hidden field of a consent page, unescaped.
fn hidden_fields(page: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for piece in page.split("<input type=\"hidden\" name=\"").skip(1) {
        let (name, rest) = piece.split_once('"').unwrap();
        let value = rest
            .strip_prefix(" value=\"")
            .unwrap()
            .split_once('"')
            .unwrap()
            .0
            .replace("&quot;", "\"")
            .replace("&#39;", "'")
            .replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&amp;", "&");
        out.push((name.to_owned(), value));
    }
    out
}

fn query_of(url: &str) -> Vec<(String, String)> {
    let query = url.split_once('?').map_or("", |(_, q)| q);
    form_urlencoded::parse(query.as_bytes())
        .into_owned()
        .collect()
}

fn param<'a>(pairs: &'a [(String, String)], name: &str) -> &'a str {
    pairs
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
        .unwrap_or_else(|| panic!("no {name} in {pairs:?}"))
}

/// The sign-in URL a `--no-browser` login printed.
fn authorize_url(login: &Running, d: &Deployment) -> String {
    let line = login.line_with("/oauth/authorize?");
    let url = line.trim().to_owned();
    assert!(
        url.starts_with(&format!("{}/oauth/authorize?", d.base)),
        "{url}"
    );
    url
}

/// Play the browser: consent as `username` and follow the `303` to the
/// CLI's loopback listener.
fn consent_in_browser(d: &Deployment, url: &str, username: &str) {
    let cookie = session(d, username);
    let path = url.strip_prefix(&d.base).unwrap();
    let page = send(d, "GET", path, Body::None, &[("cookie", &cookie)]);
    assert_eq!(page.status, 200, "{}", page.body);
    let mut fields = hidden_fields(page.text());
    assert!(fields.iter().any(|(k, _)| k == "form_token"));
    fields.push(("decision".into(), "approve".into()));
    let pairs: Vec<(&str, &str)> = fields
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    let back = send(
        d,
        "POST",
        "/oauth/authorize",
        Body::Form(&encode(&pairs)),
        &[("cookie", &cookie), ("origin", &d.base)],
    );
    assert_eq!(back.status, 303, "{}", back.body);
    let location = back.header("location").unwrap().to_owned();
    assert!(location.starts_with("http://127.0.0.1:"), "{location}");
    let landed = request("GET", &location, Body::None, &[]);
    assert_eq!(landed.status, 200);
    assert!(landed.text().contains("complete"), "{}", landed.text());
}

/// A complete browser login of `username` into `profile`.
fn browser_login(d: &Deployment, m: &Machine, username: &str, profile: &str) -> Out {
    browser_login_with(d, m, username, profile, &[])
}

fn browser_login_with(
    d: &Deployment,
    m: &Machine,
    username: &str,
    profile: &str,
    extra: &[&str],
) -> Out {
    let mut args = vec![
        "auth",
        "login",
        "--server",
        &d.base,
        "--profile",
        profile,
        "--no-browser",
    ];
    args.extend_from_slice(extra);
    let login = m.spawn(&args);
    let url = authorize_url(&login, d);
    consent_in_browser(d, &url, username);
    let out = login.finish();
    assert_eq!(out.code, 0, "{out:?}");
    out
}

fn run_list(m: &Machine, profile: &str) -> Out {
    m.run(&[
        "run",
        "list",
        "--tenant",
        "acme",
        "--repo",
        "app",
        "--profile",
        profile,
    ])
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

/// A listener that is never answered: afterwards, how many connections
/// reached it.
struct Silent(TcpListener);

impl Silent {
    fn start() -> Silent {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        Silent(listener)
    }
    fn url(&self) -> String {
        format!("http://{}", self.0.local_addr().unwrap())
    }
    fn connections(&self) -> usize {
        let mut n = 0;
        while self.0.accept().is_ok() {
            n += 1;
        }
        n
    }
}

fn not_signed_in_hint(d: &Deployment, profile: &str) -> String {
    format!(
        "not signed in to {base} (profile {profile}); run: sentinel auth login --server {base} --profile {profile}",
        base = d.base
    )
}

// ---------------------------------------------------------------- flows

#[test]
fn browser_login_then_status_and_commands_work() {
    let d = deployment();
    let m = Machine::new();
    let out = browser_login(&d, &m, "dev", "work");
    assert!(out.stdout.is_empty(), "login prints nothing on stdout");
    assert!(out.stderr.contains("Signed in to"), "{}", out.stderr);
    assert!(out.stderr.contains("as dev"), "{}", out.stderr);

    let status = m.run(&["auth", "status", "--json"]);
    assert_eq!(status.code, 0, "{status:?}");
    let doc: Value = serde_json::from_str(&status.stdout).unwrap();
    assert_eq!(doc["schema"], "sentinel.auth-status/1");
    assert_eq!(doc["profile"], "work");
    assert_eq!(doc["username"], "dev");
    assert_eq!(doc["server"], d.base.as_str());
    assert_eq!(
        (doc["signed_in"].as_bool(), doc["verified"].as_bool()),
        (Some(true), Some(true))
    );
    assert_eq!(doc["store"], "file");

    let runs = run_list(&m, "work");
    assert_eq!(runs.code, 0, "{runs:?}");
    // The profile file never holds a secret.
    let profiles = std::fs::read_to_string(m.config().join("profiles.json")).unwrap();
    assert!(!profiles.contains("sntl_"), "{profiles}");
    // The grant is a kind-1 grant of dev's.
    let grant = m.grant("work");
    let grants = d
        .store
        .read(|c| oauth::grants(c, Authority::HostLocal, d.dev, 10))
        .unwrap();
    assert_eq!(grants.len(), 1);
    assert_eq!((grants[0].id, grants[0].kind), (grant, GrantKind::Code));
}

#[test]
fn device_login_is_approved_on_the_device_page_and_never_shows_the_device_code() {
    let d = deployment();
    let m = Machine::new();
    let login = m.spawn(&[
        "auth",
        "login",
        "--device",
        "--server",
        &d.base,
        "--profile",
        "box",
    ]);
    let line = login.line_with("enter the code ");
    let display = line
        .split("enter the code ")
        .nth(1)
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .to_owned();
    let user_code = forms::normalize_user_code(&display).unwrap();
    // The person approves in a browser where they are signed in.
    let cookie = session(&d, "dev");
    let page = send(
        &d,
        "GET",
        &format!("/device?user_code={user_code}"),
        Body::None,
        &[("cookie", &cookie)],
    );
    assert_eq!(page.status, 200, "{}", page.text());
    assert!(!page.text().contains("sntl_dc_"));
    let at = page.text().find("name=\"form_token\" value=\"").unwrap() + 25;
    let token = page.text()[at..at + 64].to_owned();
    let scopes: Vec<String> = [
        "runs:read",
        "runs:write",
        "logs:read",
        "artifacts:read",
        "cache:read",
    ]
    .iter()
    .map(|s| format!("scope_{s}"))
    .collect();
    let mut form = vec![
        ("user_code", user_code.as_str()),
        ("form_token", token.as_str()),
        ("action", "approve"),
    ];
    form.extend(scopes.iter().map(|s| (s.as_str(), "1")));
    let done = send(
        &d,
        "POST",
        "/device",
        Body::Form(&encode(&form)),
        &[("cookie", &cookie), ("origin", &d.base)],
    );
    assert_eq!(done.status, 200, "{}", done.text());
    assert!(!done.text().contains("sntl_dc_"));
    let out = login.finish();
    assert_eq!(out.code, 0, "{out:?}");
    assert!(out.stderr.contains(&display), "the user code is shown");
    assert!(out.stderr.contains("Signed in to"), "{}", out.stderr);
    let runs = run_list(&m, "box");
    assert_eq!(runs.code, 0, "{runs:?}");
    let grants = d
        .store
        .read(|c| oauth::grants(c, Authority::HostLocal, d.dev, 10))
        .unwrap();
    assert_eq!(grants[0].kind, GrantKind::Device);
}

#[test]
fn untrusted_redirects_wrong_verifiers_and_foreign_audiences_are_refused() {
    let d = deployment();
    let cookie = session(&d, "dev");
    let verifier = pkce::verifier();
    let challenge = pkce::challenge(&verifier);
    let authorize = |redirect: &str, extra: &[(&str, &str)]| {
        let mut pairs = vec![
            ("response_type", "code"),
            ("client_id", CLI_CLIENT_ID),
            ("redirect_uri", redirect),
            ("state", "s1"),
            ("code_challenge", challenge.as_str()),
            ("code_challenge_method", "S256"),
        ];
        for (name, value) in extra {
            pairs.retain(|(k, _)| k != name);
            pairs.push((name, value));
        }
        send(
            &d,
            "GET",
            &format!("/oauth/authorize?{}", encode(&pairs)),
            Body::None,
            &[("cookie", &cookie)],
        )
    };
    // Redirects other than the exact loopback form: a page, never a redirect.
    for redirect in [
        "http://localhost:49152/callback",
        "https://127.0.0.1:49152/callback",
        "http://127.0.0.1:49152/other",
        "http://127.0.0.1:49152/callback?x=1",
        "https://evil.example/callback",
    ] {
        let reply = authorize(redirect, &[]);
        assert_eq!(reply.status, 400, "{redirect}");
        assert!(reply.header("location").is_none(), "{redirect}");
    }
    let good = "http://127.0.0.1:49152/callback";
    // A foreign audience (resource) and the plain PKCE method come back as errors.
    for (extra, error) in [
        (
            vec![("resource", "https://other.example/api/v1")],
            "invalid_target",
        ),
        (vec![("code_challenge_method", "plain")], "invalid_request"),
    ] {
        let reply = authorize(good, &extra);
        assert_eq!(reply.status, 303);
        let back = query_of(reply.header("location").unwrap());
        assert_eq!(param(&back, "error"), error);
        assert_eq!(param(&back, "iss"), d.base.as_str());
    }
    // Approve, then present the wrong verifier: the code is spent.
    let page = authorize(good, &[("resource", &format!("{}/api/v1", d.base))]);
    assert_eq!(page.status, 200);
    let mut fields = hidden_fields(page.text());
    fields.push(("decision".into(), "approve".into()));
    let pairs: Vec<(&str, &str)> = fields
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    let back = send(
        &d,
        "POST",
        "/oauth/authorize",
        Body::Form(&encode(&pairs)),
        &[("cookie", &cookie), ("origin", &d.base)],
    );
    let code = param(&query_of(back.header("location").unwrap()), "code").to_owned();
    let exchange = |verifier: &str| {
        send(
            &d,
            "POST",
            "/oauth/token",
            Body::Form(&encode(&[
                ("grant_type", "authorization_code"),
                ("client_id", CLI_CLIENT_ID),
                ("code", &code),
                ("redirect_uri", good),
                ("code_verifier", verifier),
            ])),
            &[],
        )
    };
    assert_eq!(exchange(&pkce::verifier()).body["error"], "invalid_grant");
    assert_eq!(exchange(&verifier).body["error"], "invalid_grant", "spent");
    // A refresh token is never a bearer; an access token is never a refresh token.
    let minted = oauth::issue_grant_trusted(
        &d.store,
        NewGrant {
            user: d.dev,
            client_id: CLI_CLIENT_ID,
            kind: GrantKind::Code,
            scopes: Scopes::CLI_DEFAULT,
            tenant: None,
            repo: None,
            audience: Audience::Api,
            name: None,
            lifetime_ms: oauth::LOGIN_GRANT_MS,
            created_by: None,
        },
        UnixMillis::now(),
    )
    .unwrap();
    let refresh = forms::format(Kind::Refresh, &minted.refresh);
    let access = forms::format(Kind::Access, &minted.access);
    let refused = me(&d, &refresh);
    assert_eq!(refused.status, 401);
    assert!(refused.header("www-authenticate").is_some());
    assert_eq!(refresh_http(&d, &access).body["error"], "invalid_grant");
    assert_eq!(me(&d, &access).status, 200);
}

#[test]
fn the_cli_refuses_a_callback_with_the_wrong_state_or_issuer() {
    let d = deployment();
    let m = Machine::new();
    let fake_code = forms::format(Kind::Code, &Secret::generate());
    for (what, wrong_state, iss) in [
        ("state", true, d.base.clone()),
        ("issuer", false, "http://127.0.0.1:1".to_owned()),
    ] {
        let login = m.spawn(&["auth", "login", "--server", &d.base, "--no-browser"]);
        let url = authorize_url(&login, &d);
        let pairs = query_of(&url);
        let redirect = param(&pairs, "redirect_uri").to_owned();
        let state = if wrong_state {
            "0".repeat(64)
        } else {
            param(&pairs, "state").to_owned()
        };
        let callback = format!(
            "{redirect}?{}",
            encode(&[("code", &fake_code), ("state", &state), ("iss", &iss)])
        );
        let landed = request("GET", &callback, Body::None, &[]);
        assert_eq!(landed.status, 400, "{what}");
        assert!(landed.text().contains("did not complete"), "{what}");
        let out = login.finish();
        assert_eq!(out.code, 3, "{what}: {out:?}");
        assert!(!out.stderr.contains(&fake_code), "the code is never echoed");
        assert!(
            !m.config().join("profiles.json").exists(),
            "{what}: nothing saved"
        );
    }
    // Nothing reached the token endpoint: no grant exists.
    let grants = d
        .store
        .read(|c| oauth::grants(c, Authority::HostLocal, d.dev, 10))
        .unwrap();
    assert!(grants.is_empty());
}

#[test]
fn four_processes_on_a_nearly_expired_profile_refresh_exactly_once() {
    let d = deployment();
    let m = Machine::new();
    browser_login(&d, &m, "dev", "race");
    let grant = m.grant("race");
    assert_eq!(refresh_rows(&d, grant), 1);
    // The stored access token is about to lapse on this machine's clock.
    let mut blob = m.credentials("race").unwrap();
    blob["access_expires_ms"] = json!(now_ms());
    m.write_credentials("race", &blob);
    let racers: Vec<Running> = (0..4)
        .map(|_| {
            m.spawn(&[
                "run",
                "list",
                "--tenant",
                "acme",
                "--repo",
                "app",
                "--profile",
                "race",
            ])
        })
        .collect();
    for racer in racers {
        let out = racer.finish();
        assert_eq!(out.code, 0, "{out:?}");
    }
    assert_eq!(refresh_rows(&d, grant), 2, "exactly one successor");
    assert!(!grant_revoked(&d, grant));
    let stored = m.credentials("race").unwrap();
    assert_ne!(stored["refresh"], blob["refresh"]);
    assert!(stored["access_expires_ms"].as_u64().unwrap() > now_ms() + 60_000);
    assert_eq!(run_list(&m, "race").code, 0);
}

fn trusted_grant(d: &Deployment) -> oauth::Minted {
    oauth::issue_grant_trusted(
        &d.store,
        NewGrant {
            user: d.dev,
            client_id: CLI_CLIENT_ID,
            kind: GrantKind::Code,
            scopes: Scopes::CLI_DEFAULT,
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

#[test]
fn a_lost_refresh_response_is_recovered_inside_the_grace_window_and_replayed_outside_it() {
    let d = deployment();
    let minted = trusted_grant(&d);
    let first = forms::format(Kind::Refresh, &minted.refresh);
    // The answer to this refresh is "lost": the client never stores it.
    let lost = refresh_http(&d, &first);
    assert_eq!(lost.status, 200, "{}", lost.body);
    let lost_access = lost.body["access_token"].as_str().unwrap().to_owned();
    // Retrying the same token inside the grace window recovers.
    let retry = refresh_http(&d, &first);
    assert_eq!(retry.status, 200, "{}", retry.body);
    let access = retry.body["access_token"].as_str().unwrap().to_owned();
    let second = retry.body["refresh_token"].as_str().unwrap().to_owned();
    assert_ne!(second, lost.body["refresh_token"].as_str().unwrap());
    assert_eq!(me(&d, &access).status, 200);
    assert_eq!(me(&d, &lost_access).status, 401, "the lost pair is dead");
    assert!(!grant_revoked(&d, minted.grant));
    // Rotation goes on normally from the recovered token.
    let third = refresh_http(&d, &second);
    assert_eq!(third.status, 200);
    let access = third.body["access_token"].as_str().unwrap().to_owned();
    let latest = third.body["refresh_token"].as_str().unwrap().to_owned();
    // The same token presented again after the window (61 s on) is replay.
    let late = oauth::refresh(
        &d.store,
        CLI_CLIENT_ID,
        &forms::parse(Kind::Refresh, &second).unwrap(),
        None,
        UnixMillis(UnixMillis::now().0 + oauth::ROTATION_GRACE_MS + 1_000),
    );
    assert!(matches!(late, Err(RefreshError::Replay)));
    assert!(grant_revoked(&d, minted.grant));
    assert_eq!(me(&d, &access).status, 401);
    assert_eq!(refresh_http(&d, &latest).body["error"], "invalid_grant");
    let audit = d.store.read(|c| local_auth::recent_audit(c, 5)).unwrap();
    assert!(audit.iter().any(|a| a.event == Event::OAuthRefreshReplay));
}

#[test]
fn a_superseded_or_twice_used_refresh_token_revokes_its_grant() {
    let d = deployment();
    let minted = trusted_grant(&d);
    let first = forms::format(Kind::Refresh, &minted.refresh);
    let lost = refresh_http(&d, &first);
    let superseded = lost.body["refresh_token"].as_str().unwrap().to_owned();
    let recovered = refresh_http(&d, &first);
    assert_eq!(recovered.status, 200);
    let access = recovered.body["access_token"].as_str().unwrap().to_owned();
    // The successor the recovery replaced is a replay, over HTTP, at once.
    let replay = refresh_http(&d, &superseded);
    assert_eq!(
        (replay.status, replay.body["error"].as_str()),
        (400, Some("invalid_grant"))
    );
    assert!(grant_revoked(&d, minted.grant));
    assert_eq!(me(&d, &access).status, 401);

    // Double use inside the window after the successor was used: replay too.
    let minted = trusted_grant(&d);
    let first = forms::format(Kind::Refresh, &minted.refresh);
    let next = refresh_http(&d, &first);
    let successor = next.body["refresh_token"].as_str().unwrap().to_owned();
    assert_eq!(
        refresh_http(&d, &successor).status,
        200,
        "the successor is used"
    );
    assert_eq!(refresh_http(&d, &first).body["error"], "invalid_grant");
    assert!(grant_revoked(&d, minted.grant));
}

#[test]
fn removed_membership_and_suspension_stop_the_cli_with_actionable_exits() {
    let d = deployment();
    let m = Machine::new();
    browser_login(&d, &m, "dev", "p");
    assert_eq!(run_list(&m, "p").code, 0);
    // Membership removed: the repository is gone for this account.
    let (tenant, dev) = (d.tenant, d.dev);
    let root = d
        .store
        .read(|c| sentinel_store::lookup::user_by_username(c, "root"))
        .unwrap();
    d.store
        .writer()
        .write(move |tx| {
            auth::remove_membership(
                tx,
                Principal::new(root, P::ALL, None, None),
                tenant,
                dev,
                UnixMillis::now(),
            )
        })
        .unwrap();
    let out = run_list(&m, "p");
    assert!(matches!(out.code, 3 | 4), "{out:?}");
    assert!(out.stdout.is_empty());

    // A suspended account's grants are revoked: exit 3 with the login hint.
    let d = deployment();
    let m = Machine::new();
    browser_login(&d, &m, "dev", "p");
    let dev = d.dev;
    d.store
        .writer()
        .write(move |tx| {
            local_auth::set_active(tx, Authority::HostLocal, dev, false, UnixMillis::now())
        })
        .unwrap();
    let out = run_list(&m, "p");
    assert_eq!(out.code, 3, "{out:?}");
    assert!(
        out.stderr.contains(&not_signed_in_hint(&d, "p")),
        "{}",
        out.stderr
    );
    assert!(grant_revoked(&d, m.grant("p")));
}

#[test]
fn a_server_other_than_the_profiles_is_refused_before_any_connection() {
    let d = deployment();
    let m = Machine::new();
    browser_login(&d, &m, "dev", "a");
    let other = Silent::start();
    let b = other.url();
    for (env, args) in [
        (
            vec![],
            vec![
                "run", "list", "--tenant", "acme", "--repo", "app", "--server", &b,
            ],
        ),
        (
            vec![("SENTINEL_SERVER", b.as_str())],
            vec!["run", "list", "--tenant", "acme", "--repo", "app"],
        ),
        (vec![], vec!["auth", "status", "--server", &b]),
        (vec![("SENTINEL_SERVER", b.as_str())], vec!["doctor"]),
    ] {
        let out = m.run_env(&env, &args);
        assert_eq!(out.code, 2, "{args:?} {env:?}: {out:?}");
        assert!(out.stderr.contains(&b), "{}", out.stderr);
    }
    assert_eq!(other.connections(), 0, "B never saw a connection");
    // The same spelling of A (a trailing slash, upper-case host) is A.
    let same = format!("{}/", d.base.to_uppercase().replace("HTTP://", "http://"));
    let out = m.run(&[
        "run", "list", "--tenant", "acme", "--repo", "app", "--server", &same,
    ]);
    assert_eq!(out.code, 0, "{out:?}");
    // A server whose metadata names another issuer is refused at login.
    let localhost = d.base.replace("127.0.0.1", "localhost");
    let out = m.run(&[
        "auth",
        "login",
        "--server",
        &localhost,
        "--profile",
        "b",
        "--no-browser",
    ]);
    assert_eq!(out.code, 2, "{out:?}");
    assert!(out.stderr.contains("issuer"), "{}", out.stderr);
}

#[test]
fn logout_revokes_on_the_server_and_offline_logout_exits_one() {
    let mut d = deployment();
    let m = Machine::new();
    browser_login(&d, &m, "dev", "p");
    let stored = m.credentials("p").unwrap();
    let (access, refresh) = (
        stored["access"].as_str().unwrap().to_owned(),
        stored["refresh"].as_str().unwrap().to_owned(),
    );
    assert_eq!(me(&d, &access).status, 200);
    let out = m.run(&["auth", "logout"]);
    assert_eq!(out.code, 0, "{out:?}");
    assert_eq!(me(&d, &access).status, 401);
    assert_eq!(refresh_http(&d, &refresh).body["error"], "invalid_grant");
    assert!(m.credentials("p").is_none(), "the local credential is gone");
    // The profile stays: a command says exactly how to sign in again.
    let out = run_list(&m, "p");
    assert_eq!(out.code, 3, "{out:?}");
    assert!(
        out.stderr.contains(&not_signed_in_hint(&d, "p")),
        "{}",
        out.stderr
    );

    // Offline: the credential is deleted anyway, and the exit says so.
    browser_login(&d, &m, "dev", "p");
    let grant = m.grant("p");
    d.stop();
    let out = m.run(&["auth", "logout", "--profile", "p"]);
    assert_eq!(out.code, 1, "{out:?}");
    assert!(out.stderr.contains("warning"), "{}", out.stderr);
    assert!(m.credentials("p").is_none());
    assert!(!grant_revoked(&d, grant), "the server never heard of it");
}

#[test]
fn a_service_grant_is_imported_and_used_without_any_prompt() {
    let d = deployment();
    let bearer = format!("Bearer {}", d.root_token);
    let created = send(
        &d,
        "POST",
        "/api/v1/tenants/acme/service-accounts",
        Body::Json(&json!({ "name": "deployer", "role": "operator" })),
        &[("authorization", &bearer)],
    );
    assert_eq!(created.status, 201, "{}", created.body);
    let account = created.body["user"].as_str().unwrap().to_owned();
    let allowed = send(
        &d,
        "PUT",
        &format!("/api/v1/tenants/acme/service-accounts/{account}/repos/app"),
        Body::Json(&json!({ "access": ["read", "run"] })),
        &[("authorization", &bearer)],
    );
    assert_eq!(allowed.status, 200, "{}", allowed.body);
    let issued = send(
        &d,
        "POST",
        &format!("/api/v1/tenants/acme/service-accounts/{account}/grants"),
        Body::Json(&json!({ "name": "ci", "scope": "runs:read runs:write" })),
        &[("authorization", &bearer)],
    );
    assert_eq!(issued.status, 201, "{}", issued.body);
    let m = Machine::new();
    let file = m.dir.path().join("agent.token");
    std::fs::write(&file, issued.body["refresh_token"].as_str().unwrap()).unwrap();
    // stdin is closed: anything that tried to prompt would fail.
    let out = m.run(&[
        "auth",
        "login",
        "--server",
        &d.base,
        "--profile",
        "agent",
        "--grant-file",
        file.to_str().unwrap(),
    ]);
    assert_eq!(out.code, 0, "{out:?}");
    let runs = run_list(&m, "agent");
    assert_eq!(runs.code, 0, "{runs:?}");
    let status = m.run(&["auth", "status", "--json", "--profile", "agent"]);
    let doc: Value = serde_json::from_str(&status.stdout).unwrap();
    assert_eq!(doc["user"], account.as_str());
    assert_eq!(doc["narrowing"]["tenant"], d.tenant.to_string());
    // Audited: the account's creation and the grant's issuance.
    let audit = d.store.read(|c| local_auth::recent_audit(c, 10)).unwrap();
    for event in [Event::ServiceAccountCreated, Event::ServiceGrantIssued] {
        assert!(audit.iter().any(|a| a.event == event), "{event:?}");
    }
}

// ---------------------------------------------------------------- doctor

fn doctor(m: &Machine, env: &[(&str, &str)]) -> (Out, Value) {
    let out = m.run_env(env, &["doctor", "--json"]);
    let doc: Value =
        serde_json::from_str(&out.stdout).unwrap_or_else(|e| panic!("doctor --json: {e}: {out:?}"));
    assert_eq!(doc["schema"], "sentinel.doctor/1");
    (out, doc)
}

fn check<'a>(doc: &'a Value, name: &str) -> &'a Value {
    doc["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == name)
        .unwrap_or_else(|| panic!("no {name} check: {doc}"))
}

#[test]
fn doctor_passes_every_check_for_a_working_profile_and_names_each_fix() {
    let mut d = deployment();
    let m = Machine::new();
    // Nothing configured: exit 3 and the login command.
    let (out, doc) = doctor(&m, &[]);
    assert_eq!(out.code, 3, "{out:?}");
    assert_eq!(check(&doc, "profile")["ok"], false);
    assert_eq!(
        check(&doc, "profile")["fix"],
        "sentinel auth login --server URL"
    );
    assert_eq!(check(&doc, "health")["skipped"], true);

    browser_login(&d, &m, "dev", "p");
    let grant = m.grant("p");
    let before = refresh_rows(&d, grant);
    let (out, doc) = doctor(&m, &[]);
    assert_eq!(out.code, 0, "{out:?}");
    assert_eq!(doc["ok"], true);
    let names: Vec<&str> = doc["checks"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["name"].as_str().unwrap())
        .collect();
    assert_eq!(
        names,
        [
            "config_dir",
            "profile",
            "health",
            "issuer",
            "credential_store",
            "access_token",
            "refresh"
        ]
    );
    for c in doc["checks"].as_array().unwrap() {
        assert_eq!(c["ok"], true, "{c}");
        assert!(c["fix"].is_null());
    }
    assert!(
        check(&doc, "access_token")["detail"]
            .as_str()
            .unwrap()
            .contains("dev")
    );
    assert_eq!(
        refresh_rows(&d, grant),
        before + 1,
        "the refresh check rotated once"
    );
    assert!(!grant_revoked(&d, grant));
    // Text mode: one line per check.
    let text = m.run(&["doctor"]);
    assert_eq!(text.code, 0, "{text:?}");
    assert_eq!(
        text.stdout.lines().filter(|l| l.starts_with("ok")).count(),
        7
    );

    // The credential removed: exit 3, the fix is the login command.
    let blob = m.credentials("p").unwrap();
    std::fs::remove_file(m.config().join("credentials").join("p.json")).unwrap();
    let (out, doc) = doctor(&m, &[]);
    assert_eq!(out.code, 3, "{out:?}");
    let store = check(&doc, "credential_store");
    assert_eq!(store["ok"], false);
    assert_eq!(
        store["fix"],
        format!("sentinel auth login --server {} --profile p", d.base).as_str()
    );
    assert_eq!(check(&doc, "access_token")["skipped"], true);
    m.write_credentials("p", &blob);

    // The controller down: exit 6, health names what to check.
    d.stop();
    let (out, doc) = doctor(&m, &[]);
    assert_eq!(out.code, 6, "{out:?}");
    let health = check(&doc, "health");
    assert_eq!(health["ok"], false);
    assert!(health["fix"].as_str().unwrap().contains("/api/v1/health"));
    assert_eq!(
        check(&doc, "credential_store")["ok"],
        true,
        "local checks still run"
    );
    assert_eq!(check(&doc, "refresh")["skipped"], true);
    // JSON mode: the report on stdout, one error document on stderr.
    let error: Value = serde_json::from_str(out.stderr.trim()).unwrap();
    assert_eq!(error["schema"], "sentinel.error/1");
}

#[test]
fn doctor_refuses_a_configuration_directory_inside_a_git_work_tree() {
    let m = Machine::new();
    let repo = m.dir.path().join("repo");
    std::fs::create_dir_all(repo.join(".git")).unwrap();
    let inside = repo.join("sentinel");
    let (out, doc) = doctor(&m, &[("SENTINEL_CONFIG_DIR", inside.to_str().unwrap())]);
    assert_eq!(out.code, 2, "{out:?}");
    let config = check(&doc, "config_dir");
    assert_eq!(config["ok"], false);
    assert!(
        config["fix"]
            .as_str()
            .unwrap()
            .contains("SENTINEL_CONFIG_DIR")
    );
    assert_eq!(check(&doc, "profile")["skipped"], true);
    assert!(!Path::new(&inside).exists(), "nothing was created");
}

#[test]
fn a_missing_scope_names_the_login_that_asks_for_it() {
    let d = deployment();
    let m = Machine::new();
    browser_login_with(&d, &m, "dev", "narrow", &["--scope", "runs:read"]);
    assert_eq!(run_list(&m, "narrow").code, 0);
    let run = sentinel_core::RunId::new().to_string();
    let out = m.run(&["artifact", "list", &run, "--profile", "narrow"]);
    assert_eq!(out.code, 3, "{out:?}");
    let expected = format!(
        "sentinel auth login --server {} --profile narrow --scope \"runs:read artifacts:read\"",
        d.base
    );
    assert!(out.stderr.contains(&expected), "{}", out.stderr);
    // JSON mode keeps the server's document, with the scope it lacked.
    let out = m.run(&["artifact", "list", &run, "--profile", "narrow", "--json"]);
    let error: Value = serde_json::from_str(out.stderr.trim()).unwrap();
    assert_eq!(
        (error["code"].as_str(), error["details"]["scope"].as_str()),
        (Some("forbidden"), Some("artifacts:read"))
    );
}
