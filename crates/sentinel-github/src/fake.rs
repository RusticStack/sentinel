//! `/user` returns an email so a test can check that a client ignores it: emails are not identities.
//!
//! It also plays GitHub's web pages for the App manifest flow (the confirm pages a browser sees)
//! so a real browser can drive one-click setup end to end. Their origin is [`FakeGithub::web_base`],
//! `localhost`, which is cross-site to the `127.0.0.1` API and web origins, as github.com is to a
//! controller's address; a `SameSite=Strict` cookie is withheld on the return, as it is from github.com.

use std::{
    collections::HashMap,
    io::{BufRead, BufReader, Read, Write},
    net::{TcpListener, TcpStream},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread::JoinHandle,
    time::Duration,
};

use crate::oauth::{Endpoints, decode};

/// A client that sends nothing (a browser's speculative connection) holds a thread this long, no longer.
const IDLE: Duration = Duration::from_secs(5);
/// The ceiling on one request's body, as GitHub bounds a manifest form.
const BODY_LIMIT: usize = 64 * 1024;
/// Connections served at once; a test double needs no more, and a flood does not grow threads.
const CONNECTIONS: usize = 64;

#[derive(Clone, Debug)]
pub struct Account {
    pub id: u64,
    pub login: String,
    pub email: String,
}

/// The App GitHub's web pages create when a manifest is confirmed. The secrets are
/// handed back once through the conversion, as GitHub does, and are never printed.
#[derive(Clone)]
pub struct Blueprint {
    pub id: u64,
    pub slug: String,
    pub name: String,
    pub owner_login: String,
    pub owner_id: u64,
    /// `Organization` or `User`.
    pub owner_kind: String,
    pub client_id: String,
    pub client_secret: String,
    pub webhook_secret: String,
    pub pem: String,
}

impl std::fmt::Debug for Blueprint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Blueprint")
            .field("id", &self.id)
            .field("slug", &self.slug)
            .finish_non_exhaustive()
    }
}

/// The account whose installation the install page offers.
struct Offer {
    login: String,
    account_id: u64,
    personal: bool,
}

/// A manifest posted to the create page, waiting for its confirm click.
struct Pending {
    manifest: serde_json::Value,
    state: String,
}

#[derive(Default)]
struct Inner {
    browser: Option<Account>,
    codes: HashMap<String, (Account, String)>,
    tokens: HashMap<String, Account>,
    received: Vec<String>,
    /// App manifest codes and the conversion each returns once.
    manifests: HashMap<String, String>,
    /// `GET /app/installations/{id}` bodies, answered to any App JWT.
    installations: HashMap<u64, String>,
    users: HashMap<u64, String>,
    memberships: HashMap<(String, String), String>,
    app: Option<String>,
    /// Sequence for authorization codes.
    serial: u64,
    blueprint: Option<Blueprint>,
    offer: Option<Offer>,
    pending: HashMap<String, Pending>,
    /// Where the install confirm returns to: the setup URL of the last confirmed manifest.
    setup_url: Option<String>,
    next_installation: u64,
    /// Every manifest text posted to a create page.
    posted: Vec<String>,
    /// `METHOD /path` of each web request, never a query or body.
    web_log: Vec<String>,
}

pub struct FakeGithub {
    port: u16,
    secret: String,
    inner: Arc<Mutex<Inner>>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl FakeGithub {
    pub fn start(client_secret: &str) -> FakeGithub {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let port = listener.local_addr().expect("local address").port();
        let inner = Arc::new(Mutex::new(Inner {
            serial: 1,
            next_installation: 9001,
            ..Inner::default()
        }));
        let stop = Arc::new(AtomicBool::new(false));
        let secret = client_secret.to_owned();
        let thread = {
            let (inner, stop, secret) = (Arc::clone(&inner), Arc::clone(&stop), secret.clone());
            let live = Arc::new(AtomicUsize::new(0));
            std::thread::spawn(move || {
                for socket in listener.incoming() {
                    if stop.load(Ordering::SeqCst) {
                        return;
                    }
                    let Ok(socket) = socket else { continue };
                    // Each connection on its own thread: a browser opens speculative connections that
                    // send nothing, and one of them must not stall a request that follows it.
                    if live.fetch_add(1, Ordering::AcqRel) >= CONNECTIONS {
                        live.fetch_sub(1, Ordering::AcqRel);
                        continue;
                    }
                    let (inner, secret, live) =
                        (Arc::clone(&inner), secret.clone(), Arc::clone(&live));
                    std::thread::spawn(move || {
                        let _ = serve(socket, &inner, &secret, port);
                        live.fetch_sub(1, Ordering::AcqRel);
                    });
                }
            })
        };
        FakeGithub {
            port,
            secret,
            inner,
            stop,
            thread: Some(thread),
        }
    }

    pub fn base(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    /// GitHub's web pages. `localhost`, not the loopback address of [`base`](Self::base): a browser
    /// treats it as another site than a `127.0.0.1` controller, as it treats github.com.
    pub fn web_base(&self) -> String {
        format!("http://localhost:{}", self.port)
    }

    pub fn endpoints(&self) -> Endpoints {
        Endpoints::loopback(self.port)
    }

    pub fn client_secret(&self) -> &str {
        &self.secret
    }

    pub fn sign_in_as(&self, account: Option<Account>) {
        self.lock().browser = account;
    }

    pub fn code_for(&self, account: Account, redirect_uri: &str) -> String {
        let code = format!("ghcode{:016x}", rand_u64());
        self.lock()
            .codes
            .insert(code.clone(), (account, redirect_uri.to_owned()));
        code
    }

    pub fn received(&self) -> Vec<String> {
        self.lock().received.clone()
    }

    pub fn issued_tokens(&self) -> Vec<String> {
        self.lock().tokens.keys().cloned().collect()
    }

    /// The App manifest flow: `code` converts once into `conversion` (a JSON object).
    pub fn add_manifest(&self, code: &str, conversion: &str) {
        self.lock()
            .manifests
            .insert(code.to_owned(), conversion.to_owned());
    }

    pub fn add_installation(&self, id: u64, body: &str) {
        self.lock().installations.insert(id, body.to_owned());
    }

    pub fn add_user(&self, id: u64, login: &str) {
        self.lock()
            .users
            .insert(id, format!(r#"{{"id":{id},"login":"{login}"}}"#));
    }

    pub fn add_membership(&self, org: &str, login: &str, body: &str) {
        self.lock()
            .memberships
            .insert((org.to_owned(), login.to_owned()), body.to_owned());
    }

    pub fn set_app(&self, body: &str) {
        self.lock().app = Some(body.to_owned());
    }

    /// The App the web pages create when a posted manifest is confirmed.
    pub fn set_blueprint(&self, blueprint: Blueprint) {
        self.lock().blueprint = Some(blueprint);
    }

    /// The account the App's install page offers; installing it registers the installation.
    pub fn offer_installation(&self, login: &str, account_id: u64, personal: bool) {
        self.lock().offer = Some(Offer {
            login: login.to_owned(),
            account_id,
            personal,
        });
    }

    /// Each manifest text a create page received, oldest first.
    pub fn manifests_posted(&self) -> Vec<String> {
        self.lock().posted.clone()
    }

    /// `METHOD /path` of every web-page request, oldest first. Never a query string or a body.
    pub fn web_requests(&self) -> Vec<String> {
        self.lock().web_log.clone()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }
}

impl Drop for FakeGithub {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(("127.0.0.1", self.port));
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn rand_u64() -> u64 {
    let mut bytes = [0u8; 8];
    ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut bytes)
        .expect("operating system entropy");
    u64::from_le_bytes(bytes)
}

fn params(text: &str) -> HashMap<String, String> {
    text.split('&')
        .filter(|p| !p.is_empty())
        .filter_map(|pair| {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            Some((decode(k).ok()?, decode(v).ok()?))
        })
        .collect()
}

fn encode(value: &str) -> String {
    let mut out = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

type Answer = (u16, Option<String>, String);

fn not_found() -> Answer {
    (404, None, r#"{"message":"Not Found"}"#.to_owned())
}

/// The App side: manifest conversion (unauthenticated), installation lookups and tokens (App
/// JWT), and the reads an installation token makes for membership.
fn app_route(
    state: &mut Inner,
    request_line: &str,
    path: &str,
    authorization: Option<String>,
    body: &str,
) -> Option<Answer> {
    let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    let post = request_line.starts_with("POST ");
    let get = request_line.starts_with("GET ");
    let jwt = authorization
        .as_deref()
        .is_some_and(|t| t.starts_with("ey"));
    Some(match parts.as_slice() {
        ["app-manifests", code, "conversions"] if post => {
            if authorization.is_some() {
                return Some((400, None, r#"{"message":"unexpected credential"}"#.into()));
            }
            match state.manifests.remove(*code) {
                Some(conversion) => (201, None, conversion),
                None => not_found(),
            }
        }
        ["app"] if get && jwt => match &state.app {
            Some(app) => (200, None, app.clone()),
            None => not_found(),
        },
        ["app", "installations", id] if get && jwt => {
            match id
                .parse()
                .ok()
                .and_then(|id: u64| state.installations.get(&id))
            {
                Some(found) => (200, None, found.clone()),
                None => not_found(),
            }
        }
        ["app", "installations", id, "access_tokens"] if post && jwt => {
            let known = id
                .parse()
                .ok()
                .is_some_and(|id: u64| state.installations.contains_key(&id));
            if !known {
                return Some(not_found());
            }
            let asked: serde_json::Value = serde_json::from_str(body).unwrap_or_default();
            let expires = (time::OffsetDateTime::now_utc() + time::Duration::hours(1))
                .format(&time::format_description::well_known::Rfc3339)
                .expect("format expiry");
            let token = format!("ghs_{:016x}{:016x}", rand_u64(), rand_u64());
            (
                201,
                None,
                serde_json::json!({
                    "token": token,
                    "expires_at": expires,
                    "permissions": asked["permissions"],
                })
                .to_string(),
            )
        }
        ["user", id] if get && authorization.is_some() => {
            match id.parse().ok().and_then(|id: u64| state.users.get(&id)) {
                Some(found) => (200, None, found.clone()),
                None => not_found(),
            }
        }
        ["orgs", org, "memberships", login] if get && authorization.is_some() => {
            match state
                .memberships
                .get(&((*org).to_owned(), (*login).to_owned()))
            {
                Some(found) => (200, None, found.clone()),
                None => not_found(),
            }
        }
        _ => return None,
    })
}

/// One answer: status, `Location`, content type, body.
struct Reply {
    status: u16,
    location: Option<String>,
    content_type: &'static str,
    body: String,
}

const JSON: &str = "application/json";
const HTML: &str = "text/html; charset=utf-8";

impl Reply {
    fn json(answer: Answer) -> Reply {
        Reply {
            status: answer.0,
            location: answer.1,
            content_type: JSON,
            body: answer.2,
        }
    }

    fn html(status: u16, body: String) -> Reply {
        Reply {
            status,
            location: None,
            content_type: HTML,
            body,
        }
    }

    fn redirect(location: String) -> Reply {
        Reply {
            status: 302,
            location: Some(location),
            content_type: HTML,
            body: String::new(),
        }
    }

    fn refuse(status: u16, why: &str) -> Reply {
        Reply::html(status, page("Refused", &format!("<p>{}</p>", escape(why))))
    }
}

fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

fn page(title: &str, body: &str) -> String {
    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>{}</title></head><body><h1>{}</h1>{body}</body></html>",
        escape(title),
        escape(title)
    )
}

fn with_query(url: &str, pairs: &[(&str, &str)]) -> String {
    let mut out = url.to_owned();
    let mut sep = if url.contains('?') { '&' } else { '?' };
    for (key, value) in pairs.iter().filter(|(_, v)| !v.is_empty()) {
        out.push(sep);
        out.push_str(key);
        out.push('=');
        out.push_str(&encode(value));
        sep = '&';
    }
    out
}

/// A URL the redirect may carry: http(s), no control characters, no whitespace.
fn plain_url(value: &serde_json::Value) -> Option<&str> {
    value
        .as_str()
        .filter(|u| u.starts_with("http://") || u.starts_with("https://"))
        .filter(|u| u.len() <= 2048 && !u.bytes().any(|b| b <= b' ' || b == 127))
}

fn login_like(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= 39
        && text.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

/// GitHub's web pages for the App manifest flow: the create page a manifest is posted to, its
/// confirm click, and the App's installation page with its confirm click.
fn web_route(
    state: &mut Inner,
    request_line: &str,
    path: &str,
    query: &str,
    body: &str,
    oversized: bool,
    port: u16,
) -> Option<Reply> {
    let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    let method = request_line.split(' ').next().unwrap_or_default();
    let reply = match (method, parts.as_slice()) {
        ("POST", ["settings", "apps", "new"]) => {
            state.web_log.push(format!("POST {path}"));
            manifest_page(state, None, query, body, oversized)
        }
        ("POST", ["organizations", org, "settings", "apps", "new"]) => {
            state.web_log.push(format!("POST {path}"));
            manifest_page(state, Some(org), query, body, oversized)
        }
        ("POST", ["__fake", "create"]) => {
            state.web_log.push(format!("POST {path}"));
            confirm_create(state, body, port)
        }
        ("GET", ["apps", slug, "installations", "new"]) => {
            state.web_log.push(format!("GET {path}"));
            install_page(state, slug, query)
        }
        ("POST", ["__fake", "install"]) => {
            state.web_log.push(format!("POST {path}"));
            confirm_install(state, body)
        }
        _ => return None,
    };
    Some(reply)
}

/// `POST /settings/apps/new?state=S` and `POST /organizations/{org}/settings/apps/new?state=S`:
/// the manifest arrives in a form field; the answer is the confirm page.
fn manifest_page(
    state: &mut Inner,
    org: Option<&str>,
    query: &str,
    body: &str,
    oversized: bool,
) -> Reply {
    if oversized {
        return Reply::refuse(413, "the manifest is too large");
    }
    if org.is_some_and(|org| !login_like(org)) {
        return Reply::refuse(404, "no such organization");
    }
    let state_value = params(query).get("state").cloned().unwrap_or_default();
    if state_value.is_empty() || state_value.len() > 256 {
        return Reply::refuse(400, "the state is missing");
    }
    let text = params(body).get("manifest").cloned().unwrap_or_default();
    let Ok(manifest) = serde_json::from_str::<serde_json::Value>(&text) else {
        return Reply::refuse(400, "the manifest is not JSON");
    };
    let valid = manifest.is_object()
        && ["url", "redirect_url", "setup_url"]
            .iter()
            .all(|key| plain_url(&manifest[*key]).is_some())
        && manifest["hook_attributes"].is_object()
        && manifest["default_permissions"].is_object();
    if !valid {
        return Reply::refuse(400, "the manifest is incomplete");
    }
    if state.pending.len() >= 64 {
        return Reply::refuse(429, "too many manifests waiting");
    }
    let name = manifest["name"].as_str().unwrap_or_default().to_owned();
    let token = format!("{:016x}{:016x}", rand_u64(), rand_u64());
    state.posted.push(text);
    state.pending.insert(
        token.clone(),
        Pending {
            manifest,
            state: state_value,
        },
    );
    let owner = match org {
        Some(org) => format!("the organization {org}"),
        None => "your personal account".to_owned(),
    };
    Reply::html(
        200,
        page(
            "Register a new GitHub App",
            &format!(
                "<p id=\"owner\">{}</p><p id=\"app-name\">{}</p>\
                 <form method=\"post\" action=\"/__fake/create\">\
                 <input type=\"hidden\" name=\"token\" value=\"{token}\">\
                 <button id=\"create-app\" type=\"submit\">Create GitHub App</button></form>",
                escape(&owner),
                escape(&name)
            ),
        ),
    )
}

/// `POST /__fake/create`: the confirm click. Mints the manifest code, which converts once at the
/// API, and returns the browser to the manifest's `redirect_url` with the code and the state.
fn confirm_create(state: &mut Inner, body: &str, port: u16) -> Reply {
    let token = params(body).get("token").cloned().unwrap_or_default();
    let Some(pending) = state.pending.remove(&token) else {
        return Reply::refuse(404, "that manifest is not waiting");
    };
    let Some(blueprint) = state.blueprint.clone() else {
        return Reply::refuse(409, "the fake has no App to create");
    };
    let (Some(redirect), Some(setup)) = (
        plain_url(&pending.manifest["redirect_url"]),
        plain_url(&pending.manifest["setup_url"]),
    ) else {
        return Reply::refuse(400, "the manifest is incomplete");
    };
    let code = format!("manifestcode{:016x}", rand_u64());
    let conversion = serde_json::json!({
        "id": blueprint.id,
        "slug": blueprint.slug,
        "node_id": "A_kwHO",
        "name": blueprint.name,
        "owner": {
            "login": blueprint.owner_login,
            "id": blueprint.owner_id,
            "type": blueprint.owner_kind,
        },
        "html_url": format!("http://127.0.0.1:{port}/apps/{}", blueprint.slug),
        "client_id": blueprint.client_id,
        "client_secret": blueprint.client_secret,
        "webhook_secret": blueprint.webhook_secret,
        "pem": blueprint.pem,
    })
    .to_string();
    let location = with_query(redirect, &[("code", &code), ("state", &pending.state)]);
    let setup = setup.to_owned();
    state.setup_url = Some(setup);
    state.manifests.insert(code, conversion);
    Reply::redirect(location)
}

/// `GET /apps/{slug}/installations/new?state=S`: the page that installs the App on the offered
/// account, or only asks for the installation when the person cannot install it.
fn install_page(state: &Inner, slug: &str, query: &str) -> Reply {
    let (Some(blueprint), Some(offer)) = (&state.blueprint, &state.offer) else {
        return Reply::refuse(404, "there is nothing to install");
    };
    if blueprint.slug != slug {
        return Reply::refuse(404, "no such App");
    }
    let state_value = params(query).get("state").cloned().unwrap_or_default();
    if state_value.len() > 256 {
        return Reply::refuse(400, "the state is too long");
    }
    Reply::html(
        200,
        page(
            &format!("Install {}", blueprint.name),
            &format!(
                "<p id=\"account\">{}</p>\
                 <form method=\"post\" action=\"/__fake/install\">\
                 <input type=\"hidden\" name=\"slug\" value=\"{}\">\
                 <input type=\"hidden\" name=\"state\" value=\"{}\">\
                 <button id=\"install-app\" type=\"submit\" name=\"action\" value=\"install\">Install</button>\
                 <button id=\"request-install\" type=\"submit\" name=\"action\" value=\"request\">Request</button>\
                 </form>",
                escape(&offer.login),
                escape(slug),
                escape(&state_value)
            ),
        ),
    )
}

/// `POST /__fake/install`: `install` registers the installation and returns to the setup URL with
/// its id; `request` (a member who cannot install) returns with `setup_action=request` and no id.
fn confirm_install(state: &mut Inner, body: &str) -> Reply {
    let form = params(body);
    let get = |key: &str| form.get(key).cloned().unwrap_or_default();
    let (slug, state_value, action) = (get("slug"), get("state"), get("action"));
    let (Some(blueprint), Some(offer)) = (&state.blueprint, &state.offer) else {
        return Reply::refuse(404, "there is nothing to install");
    };
    if blueprint.slug != slug {
        return Reply::refuse(404, "no such App");
    }
    let Some(setup) = state.setup_url.clone() else {
        return Reply::refuse(409, "no manifest was confirmed");
    };
    if state_value.len() > 256 {
        return Reply::refuse(400, "the state is too long");
    }
    match action.as_str() {
        "install" => {
            let id = state.next_installation;
            let installation = serde_json::json!({
                "id": id,
                "app_id": blueprint.id,
                "account": {
                    "id": offer.account_id,
                    "login": offer.login,
                    "type": if offer.personal { "User" } else { "Organization" },
                },
                "suspended_at": null,
                "permissions": {
                    "checks": "write", "contents": "read", "metadata": "read",
                    "pull_requests": "read", "members": "read",
                },
            })
            .to_string();
            state.next_installation += 1;
            state.installations.insert(id, installation);
            Reply::redirect(with_query(
                &setup,
                &[
                    ("installation_id", &id.to_string()),
                    ("setup_action", "install"),
                    ("state", &state_value),
                ],
            ))
        }
        "request" => Reply::redirect(with_query(
            &setup,
            &[("setup_action", "request"), ("state", &state_value)],
        )),
        _ => Reply::refuse(400, "unknown action"),
    }
}

fn serve(
    mut socket: TcpStream,
    inner: &Mutex<Inner>,
    secret: &str,
    port: u16,
) -> std::io::Result<()> {
    socket.set_read_timeout(Some(IDLE))?;
    socket.set_write_timeout(Some(IDLE))?;
    let mut reader = BufReader::new(socket.try_clone()?);
    let mut head = String::new();
    let mut declared = 0usize;
    let mut authorization = None;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            break;
        }
        let lower = line.to_ascii_lowercase();
        if let Some(value) = lower.strip_prefix("content-length:") {
            declared = value.trim().parse().unwrap_or(0);
        }
        if lower.starts_with("authorization:") {
            authorization = line
                .split_once(':')
                .map(|(_, v)| v.trim().to_owned())
                .and_then(|v| {
                    v.strip_prefix("Bearer ")
                        .or_else(|| v.strip_prefix("bearer "))
                        .map(str::to_owned)
                });
        }
        let done = line == "\r\n";
        head.push_str(&line);
        if done {
            break;
        }
        if head.len() > 32 * 1024 {
            return Err(std::io::ErrorKind::InvalidData.into());
        }
    }
    let oversized = declared > BODY_LIMIT;
    let mut body = vec![0u8; declared.min(BODY_LIMIT)];
    reader.read_exact(&mut body)?;
    if oversized {
        // Read what is left (bounded), so closing does not reset the connection before the answer is read.
        let rest = u64::try_from(declared - BODY_LIMIT).unwrap_or(u64::MAX);
        let _ = std::io::copy(
            &mut reader.by_ref().take(rest.min(1 << 20)),
            &mut std::io::sink(),
        );
    }
    let body = String::from_utf8_lossy(&body).into_owned();
    let request_line = head.lines().next().unwrap_or_default().to_owned();
    let mut state = inner.lock().unwrap_or_else(|p| p.into_inner());
    state.received.push(format!("{head}{body}"));
    let target = request_line.split(' ').nth(1).unwrap_or_default();
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let reply = if request_line.starts_with("GET ") && path == "/login/oauth/authorize" {
        let q = params(query);
        let redirect = q.get("redirect_uri").cloned().unwrap_or_default();
        let st = q.get("state").cloned().unwrap_or_default();
        let location = match state.browser.clone() {
            Some(account) => {
                let code = format!("ghcode{:08x}{:016x}", state.serial, rand_u64());
                state.serial += 1;
                state
                    .codes
                    .insert(code.clone(), (account, redirect.clone()));
                format!("{redirect}?code={}&state={}", encode(&code), encode(&st))
            }
            None => format!("{redirect}?error=access_denied&state={}", encode(&st)),
        };
        Reply::json((302, Some(location), String::new()))
    } else if request_line.starts_with("POST ") && path == "/login/oauth/access_token" {
        let form = params(&body);
        let code = form.get("code").cloned().unwrap_or_default();
        let redirect = form.get("redirect_uri").cloned().unwrap_or_default();
        let secret_ok = form.get("client_secret").map(String::as_str) == Some(secret);
        let json = match state.codes.remove(&code) {
            Some((account, bound)) if secret_ok && bound == redirect => {
                let token = format!("gho_{:016x}{:016x}", rand_u64(), rand_u64());
                state.tokens.insert(token.clone(), account);
                format!(r#"{{"access_token":"{token}","token_type":"bearer","scope":""}}"#)
            }
            _ => r#"{"error":"bad_verification_code"}"#.to_owned(),
        };
        Reply::json((200, None, json))
    } else if request_line.starts_with("GET ") && path == "/user" {
        Reply::json(
            match authorization.and_then(|t| state.tokens.get(&t).cloned()) {
                Some(a) => (
                    200,
                    None,
                    format!(
                        r#"{{"id":{},"login":"{}","name":"{}","email":"{}"}}"#,
                        a.id, a.login, a.login, a.email
                    ),
                ),
                None => (401, None, r#"{"message":"Bad credentials"}"#.to_owned()),
            },
        )
    } else if let Some(reply) = web_route(
        &mut state,
        &request_line,
        path,
        query,
        &body,
        oversized,
        port,
    ) {
        reply
    } else if let Some(answer) = app_route(&mut state, &request_line, path, authorization, &body) {
        Reply::json(answer)
    } else {
        Reply::json((404, None, "{}".to_owned()))
    };
    drop(state);
    let mut response = format!(
        "HTTP/1.1 {} X\r\ncontent-type: {}\r\ncache-control: no-store\r\n",
        reply.status, reply.content_type
    );
    if let Some(location) = reply.location {
        response.push_str(&format!("location: {location}\r\n"));
    }
    response.push_str(&format!(
        "content-length: {}\r\nconnection: close\r\n\r\n{}",
        reply.body.len(),
        reply.body
    ));
    socket.write_all(response.as_bytes())
}
