//! A GitHub-shaped OAuth server on loopback, for tests only (feature `fake`).
//!
//! It answers the three endpoints the sign-in flow touches, the way github.com
//! does, and keeps what a test needs to check the flow end to end:
//!
//! - `GET /login/oauth/authorize` plays the browser's GitHub session: with an
//!   account signed in ([`FakeGithub::sign_in_as`]) it mints a single-use code
//!   bound to the `redirect_uri` it was given and answers `302` back to it with
//!   `code` and `state`; without one it answers `302` with
//!   `error=access_denied`.
//! - `POST /login/oauth/access_token` spends a code once, only with the right
//!   client secret and the same `redirect_uri`, and returns a bearer token.
//! - `GET /user` answers the token's account: numeric `id`, `login`, `name`
//!   and an `email`, which a correct client must ignore.
//!
//! Every request line and body it receives is kept ([`FakeGithub::received`])
//! so a test can check what reached "GitHub". Connections are served one at
//! a time on one thread; dropping the fake stops it.

use std::{
    collections::HashMap,
    io::{BufRead, BufReader, Read, Write},
    net::{TcpListener, TcpStream},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread::JoinHandle,
};

use crate::oauth::{Endpoints, decode};

/// One GitHub account as `/user` describes it.
#[derive(Clone, Debug)]
pub struct Account {
    pub id: u64,
    pub login: String,
    pub email: String,
}

#[derive(Default)]
struct Inner {
    /// Who the browser is signed in to GitHub as.
    browser: Option<Account>,
    /// Unspent code -> (account, redirect URI it was issued for).
    codes: HashMap<String, (Account, String)>,
    /// Issued token -> account.
    tokens: HashMap<String, Account>,
    received: Vec<String>,
}

pub struct FakeGithub {
    port: u16,
    secret: String,
    inner: Arc<Mutex<Inner>>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl FakeGithub {
    /// Start a fake that accepts `client_secret` at its token endpoint.
    pub fn start(client_secret: &str) -> FakeGithub {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let port = listener.local_addr().expect("local address").port();
        let inner = Arc::new(Mutex::new(Inner::default()));
        let stop = Arc::new(AtomicBool::new(false));
        let secret = client_secret.to_owned();
        let thread = {
            let (inner, stop, secret) = (Arc::clone(&inner), Arc::clone(&stop), secret.clone());
            let serial = AtomicU64::new(1);
            std::thread::spawn(move || {
                for socket in listener.incoming() {
                    if stop.load(Ordering::SeqCst) {
                        return;
                    }
                    if let Ok(socket) = socket {
                        let _ = serve(socket, &inner, &secret, &serial);
                    }
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

    /// `http://127.0.0.1:PORT`, the fake's base URL.
    pub fn base(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    pub fn endpoints(&self) -> Endpoints {
        Endpoints::loopback(self.port)
    }

    /// The client secret this fake accepts.
    pub fn client_secret(&self) -> &str {
        &self.secret
    }

    /// Sign the "browser" in to GitHub as `account`; `None` signs it out.
    pub fn sign_in_as(&self, account: Option<Account>) {
        self.lock().browser = account;
    }

    /// Mint a code for `account` directly, as if the browser had approved,
    /// bound to `redirect_uri`.
    pub fn code_for(&self, account: Account, redirect_uri: &str) -> String {
        let code = format!("ghcode{:016x}", rand_u64());
        self.lock()
            .codes
            .insert(code.clone(), (account, redirect_uri.to_owned()));
        code
    }

    /// Every request received so far: request line, headers and body.
    pub fn received(&self) -> Vec<String> {
        self.lock().received.clone()
    }

    /// Tokens this fake has issued, so a test can prove none leaked.
    pub fn issued_tokens(&self) -> Vec<String> {
        self.lock().tokens.keys().cloned().collect()
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

fn serve(
    mut socket: TcpStream,
    inner: &Mutex<Inner>,
    secret: &str,
    serial: &AtomicU64,
) -> std::io::Result<()> {
    let mut reader = BufReader::new(socket.try_clone()?);
    let mut head = String::new();
    let mut length = 0usize;
    let mut authorization = None;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            break;
        }
        let lower = line.to_ascii_lowercase();
        if let Some(value) = lower.strip_prefix("content-length:") {
            length = value.trim().parse().unwrap_or(0).min(64 * 1024);
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
    }
    let mut body = vec![0u8; length];
    reader.read_exact(&mut body)?;
    let body = String::from_utf8_lossy(&body).into_owned();
    let request_line = head.lines().next().unwrap_or_default().to_owned();
    let mut state = inner.lock().unwrap_or_else(|p| p.into_inner());
    state.received.push(format!("{head}{body}"));
    let target = request_line.split(' ').nth(1).unwrap_or_default();
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let (status, location, json) =
        if request_line.starts_with("GET ") && path == "/login/oauth/authorize" {
            let q = params(query);
            let redirect = q.get("redirect_uri").cloned().unwrap_or_default();
            let st = q.get("state").cloned().unwrap_or_default();
            let location = match state.browser.clone() {
                Some(account) => {
                    let code = format!(
                        "ghcode{:08x}{:016x}",
                        serial.fetch_add(1, Ordering::SeqCst),
                        rand_u64()
                    );
                    state
                        .codes
                        .insert(code.clone(), (account, redirect.clone()));
                    format!("{redirect}?code={}&state={}", encode(&code), encode(&st))
                }
                None => format!("{redirect}?error=access_denied&state={}", encode(&st)),
            };
            (302, Some(location), String::new())
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
            (200, None, json)
        } else if request_line.starts_with("GET ") && path == "/user" {
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
            }
        } else {
            (404, None, "{}".to_owned())
        };
    drop(state);
    let mut response = format!("HTTP/1.1 {status} X\r\ncontent-type: application/json\r\n");
    if let Some(location) = location {
        response.push_str(&format!("location: {location}\r\n"));
    }
    response.push_str(&format!(
        "content-length: {}\r\nconnection: close\r\n\r\n{json}",
        json.len()
    ));
    socket.write_all(response.as_bytes())
}
