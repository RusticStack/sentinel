//! Profiles, credential storage and the `sentinel auth`/`context` commands
//! (O04), portable. The OAuth server is a scripted fake on loopback that
//! speaks the fixed wire contract (`sentinel_protocol::oauth`); every test
//! uses its own `SENTINEL_CONFIG_DIR` and the file store, except the one
//! Windows Credential Manager test. Nothing the CLI prints may contain
//! `sntl_` token material.

use std::{
    io::{BufRead, BufReader, Read, Write},
    net::{TcpListener, TcpStream},
    path::Path,
    process::{Command, Output, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};

use sentinel::{
    auth_cmd,
    client::Exit,
    keystore::{self, Backend},
    loopback::Listener,
    profile::{self, Config, Credentials, Profile, now_ms},
};
use sentinel_protocol::oauth::{DeviceAuthorization, Metadata, TokenResponse};
use serde_json::{Value, json};

const SCOPES: [&str; 10] = [
    "runs:read",
    "runs:write",
    "logs:read",
    "artifacts:read",
    "cache:read",
    "cache:write",
    "secrets:metadata",
    "secrets:write",
    "tenant:admin",
    "platform:admin",
];

fn token(prefix: &str, n: u64) -> String {
    format!("{prefix}{n:064x}")
}

// ---------------------------------------------------------------- fake server

#[derive(Clone, Debug)]
struct Req {
    method: String,
    path: String,
    body: String,
    authorization: Option<String>,
    at: Instant,
}

impl Req {
    fn form(&self) -> Vec<(String, String)> {
        form_urlencoded::parse(self.body.as_bytes())
            .into_owned()
            .collect()
    }
    fn param(&self, name: &str) -> Option<String> {
        self.form()
            .into_iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v)
    }
}

type Handler = dyn Fn(&str, &Req) -> (u16, String) + Send + Sync;

/// A loopback HTTP server: each connection is one request answered by
/// `handler(base_url, request)` on its own thread; every request is logged.
struct Fake {
    url: String,
    log: Arc<Mutex<Vec<Req>>>,
    stop: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}

impl Fake {
    fn start(handler: impl Fn(&str, &Req) -> (u16, String) + Send + Sync + 'static) -> Fake {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let log = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let handler: Arc<Handler> = Arc::new(handler);
        let (base, seen, halt) = (url.clone(), Arc::clone(&log), Arc::clone(&stop));
        let thread = thread::spawn(move || {
            for stream in listener.incoming() {
                if halt.load(Ordering::Acquire) {
                    return;
                }
                let Ok(stream) = stream else { continue };
                let (handler, base, seen) = (Arc::clone(&handler), base.clone(), Arc::clone(&seen));
                thread::spawn(move || serve(stream, &base, &*handler, &seen));
            }
        });
        Fake {
            url,
            log,
            stop,
            thread: Some(thread),
        }
    }

    fn requests(&self, path: &str) -> Vec<Req> {
        self.log
            .lock()
            .unwrap()
            .iter()
            .filter(|r| r.path == path)
            .cloned()
            .collect()
    }

    fn total(&self) -> usize {
        self.log.lock().unwrap().len()
    }
}

impl Drop for Fake {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        let _ = TcpStream::connect(self.url.trim_start_matches("http://"));
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn serve(stream: TcpStream, base: &str, handler: &Handler, log: &Mutex<Vec<Req>>) {
    let mut reader = BufReader::new(&stream);
    let mut line = String::new();
    if reader.read_line(&mut line).unwrap_or(0) == 0 {
        return;
    }
    let mut parts = line.split_whitespace();
    let method = parts.next().unwrap_or("").to_owned();
    let target = parts.next().unwrap_or("").to_owned();
    let path = target.split('?').next().unwrap_or("").to_owned();
    let (mut length, mut authorization) = (0usize, None);
    loop {
        line.clear();
        if reader.read_line(&mut line).unwrap_or(0) == 0 {
            return;
        }
        let trimmed = line.trim_end();
        if trimmed.is_empty() {
            break;
        }
        if let Some((name, value)) = trimmed.split_once(':') {
            if name.eq_ignore_ascii_case("content-length") {
                length = value.trim().parse().unwrap_or(0);
            } else if name.eq_ignore_ascii_case("authorization") {
                authorization = Some(value.trim().to_owned());
            }
        }
    }
    let mut body = vec![0u8; length];
    let _ = reader.read_exact(&mut body);
    let req = Req {
        method,
        path,
        body: String::from_utf8_lossy(&body).into_owned(),
        authorization,
        at: Instant::now(),
    };
    log.lock().unwrap().push(req.clone());
    let (status, body) = handler(base, &req);
    let response = format!(
        "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    );
    let mut stream = &stream;
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.flush();
}

fn metadata(base: &str) -> String {
    serde_json::to_string(&Metadata::for_issuer(base, &SCOPES)).unwrap()
}

fn tokens_json(n: u64, grant: &str) -> String {
    serde_json::to_string(&TokenResponse {
        access_token: token("sntl_at_", n),
        token_type: "Bearer".into(),
        expires_in: 600,
        refresh_token: token("sntl_rt_", n),
        scope: "runs:read runs:write".into(),
        sentinel_grant: grant.into(),
        sentinel_refresh_expires_in: 30 * 86_400,
    })
    .unwrap()
}

fn oauth_error(code: &str) -> (u16, String) {
    (400, format!(r#"{{"error":"{code}"}}"#))
}

fn me_json() -> String {
    json!({
        "user": "usr_0123456789abcdef0123456789",
        "username": "alice",
        "via": "oauth",
        "tenant": "ten_narrowed",
        "repo": null,
        "scopes": ["runs:read", "runs:write"],
        "grant": "grt_fake",
        "expires_ms": 0,
    })
    .to_string()
}

/// Metadata, `/me` for any `sntl_at_` bearer, and revocation; `token`
/// answers the token endpoint.
fn oauth_server(token_endpoint: impl Fn(&Req) -> (u16, String) + Send + Sync + 'static) -> Fake {
    Fake::start(
        move |base, req| match (req.method.as_str(), req.path.as_str()) {
            ("GET", "/.well-known/oauth-authorization-server") => (200, metadata(base)),
            ("POST", "/oauth/token") => token_endpoint(req),
            ("POST", "/oauth/revoke") => (200, "{}".into()),
            ("GET", "/api/v1/me")
                if req
                    .authorization
                    .as_deref()
                    .is_some_and(|a| a.starts_with("Bearer sntl_at_")) =>
            {
                (200, me_json())
            }
            ("GET", "/api/v1/me") => (
                401,
                r#"{"schema":"sentinel.error/1","code":"unauthenticated","message":"no"}"#.into(),
            ),
            _ => (404, "{}".into()),
        },
    )
}

// ------------------------------------------------------------------- helpers

fn config(dir: &tempfile::TempDir) -> Config {
    Config::at(dir.path().join("cfg")).unwrap()
}

fn credentials(n: u64, access_left_ms: i64) -> Credentials {
    let now = now_ms() as i64;
    Credentials {
        refresh: token("sntl_rt_", n),
        access: token("sntl_at_", n),
        access_expires_ms: (now + access_left_ms).max(0) as u64,
        refresh_expires_ms: (now + 86_400_000) as u64,
        grant: None,
    }
}

fn seed(config: &Config, name: &str, server: &str, creds: &Credentials) -> Profile {
    let entry = Profile {
        server: server.to_owned(),
        issuer: server.to_owned(),
        client_id: "sentinel-cli".into(),
        user: "usr_0123456789abcdef0123456789".into(),
        username: Some("alice".into()),
        grant: "grt_seeded".into(),
        scopes: "runs:read runs:write".into(),
        tenant: None,
        store: Backend::File,
        key: None,
        created_ms: now_ms(),
    };
    config.write_credentials(name, &entry, creds).unwrap();
    let stored = entry.clone();
    config
        .update(|p| {
            p.profiles.insert(name.to_owned(), stored);
            p.current = Some(name.to_owned());
            Ok(())
        })
        .unwrap();
    entry
}

fn agent() -> ureq::Agent {
    profile::agent()
}

fn sentinel(dir: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_sentinel"));
    command
        .env("SENTINEL_CONFIG_DIR", dir)
        .env("SENTINEL_CREDENTIAL_STORE", "file")
        .env_remove("SENTINEL_TOKEN")
        .env_remove("SENTINEL_SERVER")
        .env_remove("SENTINEL_PROFILE");
    command
}

fn run(dir: &Path, args: &[&str]) -> Output {
    let output = sentinel(dir).args(args).output().unwrap();
    assert_no_tokens(&output);
    output
}

/// Whether `text` holds token material: `sntl_`, an optional kind prefix
/// (`at_`, `rt_`, `ac_`, `dc_`), then a run of hex. Naming a prefix in a
/// message ("a sntl_rt_ refresh token") is not a leak.
fn leaks(text: &str) -> bool {
    text.match_indices("sntl_").any(|(at, _)| {
        let rest = &text[at + 5..];
        let rest = ["at_", "rt_", "ac_", "dc_"]
            .iter()
            .find_map(|p| rest.strip_prefix(p))
            .unwrap_or(rest);
        rest.bytes().take_while(u8::is_ascii_hexdigit).count() >= 16
    })
}

/// No `sntl_` material on either stream.
fn assert_no_tokens(output: &Output) {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!leaks(&stdout), "stdout leaks a token: {stdout}");
    assert!(!leaks(&stderr), "stderr leaks a token: {stderr}");
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

// --------------------------------------------------------------------- tests

#[test]
fn a_profile_round_trips_and_profiles_json_holds_no_secret() {
    let dir = tempfile::tempdir().unwrap();
    let config = config(&dir);
    assert!(config.handle(None).unwrap().is_none(), "nothing configured");
    let creds = credentials(1, 600_000);
    let entry = seed(&config, "default", "https://ci.example.com", &creds);

    let loaded = config.load().unwrap();
    assert_eq!(loaded.schema, "sentinel.profiles/1");
    assert_eq!(loaded.current.as_deref(), Some("default"));
    assert_eq!(loaded.profiles["default"], entry);
    assert_eq!(
        config.read_credentials("default", &entry).unwrap(),
        Some(creds.clone())
    );
    let text = std::fs::read_to_string(config.dir().join("profiles.json")).unwrap();
    assert!(!text.contains("sntl_"), "{text}");
    assert!(text.contains(r#""store": "file""#), "{text}");
    let blob = std::fs::read_to_string(config.dir().join("credentials/default.json")).unwrap();
    assert!(blob.contains(&creds.refresh));
    assert!(!format!("{creds:?}").contains("sntl_"), "Debug redacts");
    assert!(leaks(&format!("x {} y", creds.access)) && leaks(&token("sntl_", 3)));
    assert!(!leaks("the file does not hold a sntl_rt_ refresh token"));

    // A valid access token is answered without any request.
    let handle = config.handle(None).unwrap().unwrap();
    assert_eq!(handle.name(), "default");
    assert_eq!(handle.server(), "https://ci.example.com");
    assert_eq!(handle.tenant(), None);
    assert_eq!(handle.access_token(&agent()).unwrap(), creds.access);

    // Unknown named profiles and bad names are local errors.
    assert_eq!(config.handle(Some("other")).unwrap_err().exit, Exit::Usage);
    assert_eq!(config.handle(Some("../x")).unwrap_err().exit, Exit::Usage);

    // A profile without a stored credential is "not signed in", exit 3.
    config.delete_credentials("default", &entry).unwrap();
    let handle = config.handle(None).unwrap().unwrap();
    let error = handle.access_token(&agent()).unwrap_err();
    assert_eq!(error.exit, Exit::Auth);
    assert!(
        error
            .message
            .contains("sentinel auth login --server https://ci.example.com --profile default")
    );
}

#[test]
fn a_configuration_directory_inside_a_git_work_tree_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join(".git")).unwrap();
    let inside = dir.path().join("nested").join("cfg");
    let error = Config::at(&inside).unwrap_err();
    assert_eq!(error.exit, Exit::Usage);
    assert!(error.message.contains("Git work tree"), "{}", error.message);

    let output = run(&inside, &["auth", "status", "--offline"]);
    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
    assert!(stderr(&output).contains("SENTINEL_CONFIG_DIR"));
    assert!(!inside.exists(), "nothing was created");

    // A `.git` file (a worktree or submodule) counts too.
    let other = tempfile::tempdir().unwrap();
    std::fs::write(other.path().join(".git"), "gitdir: elsewhere").unwrap();
    assert!(Config::at(other.path().join("cfg")).is_err());
}

#[cfg(unix)]
#[test]
fn unix_files_are_owner_only_and_loose_or_foreign_ones_are_refused() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let config = config(&dir);
    let entry = seed(
        &config,
        "default",
        "https://ci.example.com",
        &credentials(1, 600_000),
    );
    let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
    let cfg = config.dir();
    assert_eq!(mode(cfg), 0o700);
    assert_eq!(mode(&cfg.join("credentials")), 0o700);
    assert_eq!(mode(&cfg.join("locks")), 0o700);
    assert_eq!(mode(&cfg.join("profiles.json")), 0o600);
    assert_eq!(mode(&cfg.join("credentials/default.json")), 0o600);

    // Group-readable credential: refused with the fix.
    let file = cfg.join("credentials/default.json");
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o640)).unwrap();
    let error = config.read_credentials("default", &entry).unwrap_err();
    assert_eq!(error.exit, Exit::Usage);
    assert!(error.message.contains("chmod 600"), "{}", error.message);
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(
        config
            .read_credentials("default", &entry)
            .unwrap()
            .is_some()
    );

    // A world-readable configuration directory: refused with the fix.
    std::fs::set_permissions(cfg, std::fs::Permissions::from_mode(0o755)).unwrap();
    let error = config.load().unwrap_err();
    assert!(error.message.contains("chmod 700"), "{}", error.message);
    std::fs::set_permissions(cfg, std::fs::Permissions::from_mode(0o700)).unwrap();

    // Owned by someone else: refused (simulated as another effective uid).
    let me = rustix_euid();
    keystore::file::check_private_as(&file, me).unwrap();
    let error = keystore::file::check_private_as(&file, me.wrapping_add(1)).unwrap_err();
    assert!(error.message.contains("owned by"), "{}", error.message);
    assert!(error.message.contains("chown"), "{}", error.message);
}

#[cfg(unix)]
fn rustix_euid() -> u32 {
    use std::os::unix::fs::MetadataExt;
    // The owner of a file this test just created is the effective user.
    let probe = tempfile::NamedTempFile::new().unwrap();
    std::fs::metadata(probe.path()).unwrap().uid()
}

#[test]
fn eight_concurrent_callers_refresh_exactly_once() {
    let refreshes = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&refreshes);
    let server = oauth_server(move |req| {
        assert_eq!(req.param("grant_type").as_deref(), Some("refresh_token"));
        assert_eq!(req.param("client_id").as_deref(), Some("sentinel-cli"));
        assert_eq!(req.param("refresh_token"), Some(token("sntl_rt_", 1)));
        let n = counter.fetch_add(1, Ordering::AcqRel) as u64;
        // Widen the race: the others are already waiting for the lock.
        thread::sleep(Duration::from_millis(150));
        (200, tokens_json(2 + n, "grt_seeded"))
    });
    let dir = tempfile::tempdir().unwrap();
    let config = config(&dir);
    // Ten seconds left: under the 30 s margin, so every caller wants a refresh.
    seed(&config, "default", &server.url, &credentials(1, 10_000));

    let start = Arc::new(std::sync::Barrier::new(8));
    let callers: Vec<_> = (0..8)
        .map(|_| {
            let (config, start) = (config.clone(), Arc::clone(&start));
            thread::spawn(move || {
                let handle = config.handle(None).unwrap().unwrap();
                start.wait();
                handle.access_token(&agent()).unwrap()
            })
        })
        .collect();
    let tokens: Vec<String> = callers.into_iter().map(|t| t.join().unwrap()).collect();
    assert_eq!(refreshes.load(Ordering::Acquire), 1, "exactly one refresh");
    assert_eq!(server.requests("/oauth/token").len(), 1);
    assert!(
        tokens.iter().all(|t| *t == token("sntl_at_", 2)),
        "{tokens:?}"
    );
    let entry = config.load().unwrap().profiles["default"].clone();
    let stored = config.read_credentials("default", &entry).unwrap().unwrap();
    assert_eq!(
        stored.refresh,
        token("sntl_rt_", 2),
        "the successor is stored"
    );
    assert!(stored.access_expires_ms > now_ms() + 500_000);
}

#[test]
fn force_refresh_with_a_stale_rejected_token_reuses_the_newer_one() {
    let server = oauth_server(|req| {
        assert_eq!(req.param("refresh_token"), Some(token("sntl_rt_", 2)));
        (200, tokens_json(3, "grt_seeded"))
    });
    let dir = tempfile::tempdir().unwrap();
    let config = config(&dir);
    let entry = seed(&config, "default", &server.url, &credentials(1, 600_000));
    let handle = config.handle(None).unwrap().unwrap();
    assert_eq!(handle.access_token(&agent()).unwrap(), token("sntl_at_", 1));

    // Another process refreshed meanwhile: the server rejected token 1, but
    // token 2 is already stored, so no refresh token is spent.
    config
        .write_credentials("default", &entry, &credentials(2, 600_000))
        .unwrap();
    let newer = handle
        .force_refresh(&agent(), &token("sntl_at_", 1))
        .unwrap();
    assert_eq!(newer, token("sntl_at_", 2));
    assert_eq!(server.requests("/oauth/token").len(), 0);
    assert_eq!(handle.access_token(&agent()).unwrap(), newer, "cached");

    // Token 2 itself rejected: now the refresh happens, once.
    let fresh = handle.force_refresh(&agent(), &newer).unwrap();
    assert_eq!(fresh, token("sntl_at_", 3));
    assert_eq!(server.requests("/oauth/token").len(), 1);
}

#[test]
fn a_refused_refresh_is_exit_3_with_the_login_command() {
    let server = oauth_server(|_| oauth_error("invalid_grant"));
    let dir = tempfile::tempdir().unwrap();
    let config = config(&dir);
    seed(&config, "ci", &server.url, &credentials(1, 0));
    let handle = config.handle(Some("ci")).unwrap().unwrap();
    let error = handle.access_token(&agent()).unwrap_err();
    assert_eq!(error.exit, Exit::Auth);
    assert!(
        error.message.contains(&format!(
            "sentinel auth login --server {} --profile ci",
            server.url
        )),
        "{}",
        error.message
    );
    assert!(!leaks(&error.message));

    // An unreachable token endpoint is busy (exit 6), not signed out.
    let closed = {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        format!("http://{}", listener.local_addr().unwrap())
    };
    seed(&config, "gone", &closed, &credentials(1, 0));
    let handle = config.handle(Some("gone")).unwrap().unwrap();
    assert_eq!(handle.access_token(&agent()).unwrap_err().exit, Exit::Busy);
}

/// P09-2: a refresh that meets a busy authorization server retries once
/// after the server's `retry-after`, instead of failing the command.
#[test]
fn a_busy_token_endpoint_is_retried_once() {
    let calls = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&calls);
    let server = oauth_server(move |_| {
        if seen.fetch_add(1, Ordering::SeqCst) == 0 {
            (503, r#"{"error":"temporarily_unavailable"}"#.into())
        } else {
            (200, tokens_json(2, "grt_seeded"))
        }
    });
    let dir = tempfile::tempdir().unwrap();
    let config = config(&dir);
    seed(&config, "ci", &server.url, &credentials(1, 0));
    let handle = config.handle(Some("ci")).unwrap().unwrap();
    assert_eq!(handle.access_token(&agent()).unwrap(), token("sntl_at_", 2));
    assert_eq!(calls.load(Ordering::SeqCst), 2);

    // Still busy the second time: exit 6, after exactly one retry.
    let calls = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&calls);
    let busy = oauth_server(move |_| {
        seen.fetch_add(1, Ordering::SeqCst);
        (503, r#"{"error":"temporarily_unavailable"}"#.into())
    });
    seed(&config, "busy", &busy.url, &credentials(1, 0));
    let handle = config.handle(Some("busy")).unwrap().unwrap();
    assert_eq!(handle.access_token(&agent()).unwrap_err().exit, Exit::Busy);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

/// Send one raw request to the listener and return the status line.
fn hit(port: u16, target: &str) -> String {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    write!(stream, "GET {target} HTTP/1.1\r\nhost: x\r\n\r\n").unwrap();
    let mut answer = String::new();
    let _ = stream.read_to_string(&mut answer);
    answer.lines().next().unwrap_or("").to_owned()
}

#[test]
fn the_loopback_listener_checks_state_and_issuer_and_ignores_other_paths() {
    let issuer = "http://127.0.0.1:9";
    let state = "ab".repeat(32);
    let good = |state: &str, iss: &str| {
        let q = profile::form(&[
            ("code", &token("sntl_ac_", 7)),
            ("state", state),
            ("iss", iss),
        ]);
        format!("/callback?{q}")
    };

    // Other paths are 404 and the wait goes on; the right callback wins.
    let listener = Listener::bind().unwrap();
    let port = listener.port();
    assert_eq!(
        listener.redirect_uri(),
        format!("http://127.0.0.1:{port}/callback")
    );
    let target = good(&state, issuer);
    let browser = thread::spawn(move || {
        let favicon = hit(port, "/favicon.ico");
        let ok = hit(port, &target);
        (favicon, ok)
    });
    let code = listener
        .wait(&state, issuer, Duration::from_secs(10))
        .unwrap();
    assert_eq!(code, token("sntl_ac_", 7));
    let (favicon, ok) = browser.join().unwrap();
    assert!(favicon.contains("404"), "{favicon}");
    assert!(ok.contains("200"), "{ok}");

    // P09C-4: a callback with another `state` (a stray process or a web
    // page that found the port), a denial for another login, and an idle
    // connection that never sends a head: each answered or left, none ends
    // the wait or holds it up, and this login's callback then wins at once.
    let listener = Listener::bind().unwrap();
    let port = listener.port();
    let (target, other) = (good(&state, issuer), "cd".repeat(32));
    let browser = thread::spawn(move || {
        let idle = TcpStream::connect(("127.0.0.1", port)).unwrap();
        let wrong = hit(port, &good(&other, issuer));
        let denied = hit(
            port,
            &format!("/callback?error=access_denied&state={other}&iss={issuer}"),
        );
        let ok = hit(port, &target);
        drop(idle);
        (wrong, denied, ok)
    });
    let started = Instant::now();
    let code = listener
        .wait(&state, issuer, Duration::from_secs(30))
        .unwrap();
    assert_eq!(code, token("sntl_ac_", 7));
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "an idle connection held up the listener: {:?}",
        started.elapsed()
    );
    let (wrong, denied, ok) = browser.join().unwrap();
    assert!(wrong.contains("400"), "{wrong}");
    assert!(denied.contains("400"), "{denied}");
    assert!(ok.contains("200"), "{ok}");

    // This login's callback with the wrong issuer, a missing issuer, a
    // repeated parameter, or a denial: each refused (exit 3) and the
    // browser gets a 400 page.
    for target in [
        good(&state, "http://127.0.0.1:10"),
        format!("/callback?code=x&state={state}"),
        format!("{}&state={state}", good(&state, issuer)),
        format!("/callback?error=access_denied&state={state}&iss={issuer}"),
    ] {
        let listener = Listener::bind().unwrap();
        let port = listener.port();
        let browser = thread::spawn(move || hit(port, &target));
        let error = listener
            .wait(&state, issuer, Duration::from_secs(10))
            .unwrap_err();
        assert_eq!(error.exit, Exit::Auth);
        assert!(!leaks(&error.message));
        assert!(browser.join().unwrap().contains("400"));
    }

    // An oversized head is refused and ignored.
    let listener = Listener::bind().unwrap();
    let port = listener.port();
    let target = good(&state, issuer);
    let browser = thread::spawn(move || {
        let huge = format!("/callback?pad={}", "a".repeat(9000));
        let big = hit(port, &huge);
        (big, hit(port, &target))
    });
    assert!(
        listener
            .wait(&state, issuer, Duration::from_secs(10))
            .is_ok()
    );
    let (big, ok) = browser.join().unwrap();
    assert!(big.contains("431"), "{big}");
    assert!(ok.contains("200"));

    // Nobody comes: the wait ends at its bound.
    let listener = Listener::bind().unwrap();
    let started = Instant::now();
    let error = listener
        .wait(&state, issuer, Duration::from_millis(300))
        .unwrap_err();
    assert_eq!(error.exit, Exit::Auth);
    assert!(started.elapsed() >= Duration::from_millis(300));
    assert!(started.elapsed() < Duration::from_secs(5));
}

fn device_answer(base: &str, interval: u64) -> String {
    serde_json::to_string(&DeviceAuthorization {
        device_code: token("sntl_dc_", 9),
        user_code: "BCDF-GHJK".into(),
        verification_uri: format!("{base}/device"),
        verification_uri_complete: format!("{base}/device?user_code=BCDFGHJK"),
        expires_in: 600,
        interval,
    })
    .unwrap()
}

fn device_server(script: Vec<(u16, String)>) -> Fake {
    let script = Mutex::new(script.into_iter());
    Fake::start(
        move |base, req| match (req.method.as_str(), req.path.as_str()) {
            ("GET", "/.well-known/oauth-authorization-server") => (200, metadata(base)),
            ("POST", "/oauth/device_authorization") => (200, device_answer(base, 1)),
            ("POST", "/oauth/token") => {
                assert_eq!(
                    req.param("grant_type").as_deref(),
                    Some("urn:ietf:params:oauth:grant-type:device_code")
                );
                assert_eq!(req.param("device_code"), Some(token("sntl_dc_", 9)));
                script
                    .lock()
                    .unwrap()
                    .next()
                    .unwrap_or_else(|| oauth_error("expired_token"))
            }
            ("GET", "/api/v1/me") => (200, me_json()),
            ("POST", "/oauth/revoke") => (200, "{}".into()),
            _ => (404, "{}".into()),
        },
    )
}

#[test]
fn device_polling_honors_the_interval_and_slow_down() {
    let server = device_server(vec![
        oauth_error("slow_down"),
        oauth_error("authorization_pending"),
        (200, tokens_json(4, "grt_device")),
    ]);
    let meta = auth_cmd::discover(&agent(), &server.url).unwrap();
    let unit = Duration::from_millis(40);
    let started = Instant::now();
    let (tokens, _) = auth_cmd::device_login(&agent(), &meta, "runs:read", unit).unwrap();
    assert_eq!(tokens.sentinel_grant, "grt_device");
    let polls: Vec<Instant> = server
        .requests("/oauth/token")
        .iter()
        .map(|r| r.at)
        .collect();
    assert_eq!(polls.len(), 3);
    // interval 1 before the first poll; slow_down makes it 1 + 5 = 6.
    assert!(polls[0] - started >= unit);
    assert!(polls[1] - polls[0] >= unit * 6, "{:?}", polls[1] - polls[0]);
    assert!(polls[2] - polls[1] >= unit * 6, "{:?}", polls[2] - polls[1]);

    // Denied and expired end the flow with exit 3.
    for code in ["access_denied", "expired_token"] {
        let server = device_server(vec![oauth_error(code)]);
        let meta = auth_cmd::discover(&agent(), &server.url).unwrap();
        let error = auth_cmd::device_login(&agent(), &meta, "runs:read", unit).unwrap_err();
        assert_eq!(error.exit, Exit::Auth, "{code}");
    }
}

#[test]
fn device_login_prints_the_user_code_but_never_the_device_code() {
    let server = device_server(vec![(200, tokens_json(5, "grt_device"))]);
    let dir = tempfile::tempdir().unwrap();
    let cfg = dir.path().join("cfg");
    let output = run(
        &cfg,
        &[
            "auth",
            "login",
            "--device",
            "--server",
            &format!("{}/", server.url),
        ],
    );
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let err = stderr(&output);
    assert!(err.contains("BCDF-GHJK"), "{err}");
    assert!(err.contains(&format!("{}/device", server.url)), "{err}");
    assert!(output.stdout.is_empty());
    let request = &server.requests("/oauth/device_authorization")[0];
    assert_eq!(request.param("client_id").as_deref(), Some("sentinel-cli"));
    assert_eq!(
        request.param("scope").as_deref(),
        Some(auth_cmd::DEFAULT_SCOPE)
    );
    assert_eq!(
        request.param("resource"),
        Some(format!("{}/api/v1", server.url))
    );

    let config = Config::at(&cfg).unwrap();
    let profiles = config.load().unwrap();
    assert_eq!(profiles.current.as_deref(), Some("default"));
    let entry = &profiles.profiles["default"];
    assert_eq!(entry.server, server.url, "stored normalized");
    assert_eq!(entry.grant, "grt_device");
    assert_eq!(entry.username.as_deref(), Some("alice"));
    assert_eq!(entry.store, Backend::File);
    let stored = config.read_credentials("default", entry).unwrap().unwrap();
    assert_eq!(stored.access, token("sntl_at_", 5));
    let text = std::fs::read_to_string(cfg.join("profiles.json")).unwrap();
    assert!(!text.contains("sntl_"));
}

#[test]
fn browser_login_checks_state_and_iss_and_proves_pkce() {
    let challenge: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let expected = Arc::clone(&challenge);
    let server = oauth_server(move |req| {
        assert_eq!(
            req.param("grant_type").as_deref(),
            Some("authorization_code")
        );
        assert_eq!(req.param("code"), Some(token("sntl_ac_", 1)));
        let verifier = req.param("code_verifier").unwrap();
        let challenge = expected.lock().unwrap().clone().unwrap();
        if !sentinel_auth::oauth::pkce::verify(&verifier, &challenge) {
            return oauth_error("invalid_grant");
        }
        (200, tokens_json(6, "grt_browser"))
    });
    let dir = tempfile::tempdir().unwrap();
    let cfg = dir.path().join("cfg");
    let mut child = sentinel(&cfg)
        .args([
            "auth",
            "login",
            "--no-browser",
            "--profile",
            "work",
            "--server",
            &server.url,
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let (lines, rx) = mpsc::channel::<String>();
    let err = child.stderr.take().unwrap();
    let reader = thread::spawn(move || {
        for line in BufReader::new(err).lines() {
            let _ = lines.send(line.unwrap());
        }
    });
    let mut printed = Vec::new();
    let url = loop {
        let line = rx.recv_timeout(Duration::from_secs(20)).unwrap();
        printed.push(line.clone());
        if let Some(url) = line
            .trim()
            .strip_prefix(&format!("{}/oauth/authorize?", server.url))
        {
            break url.to_owned();
        }
    };
    let query: Vec<(String, String)> = form_urlencoded::parse(url.as_bytes())
        .into_owned()
        .collect();
    let get = |name: &str| {
        query
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.clone())
            .unwrap_or_default()
    };
    assert_eq!(get("response_type"), "code");
    assert_eq!(get("client_id"), "sentinel-cli");
    assert_eq!(get("code_challenge_method"), "S256");
    assert_eq!(get("resource"), format!("{}/api/v1", server.url));
    assert_eq!(get("state").len(), 64);
    let redirect = get("redirect_uri");
    assert!(
        sentinel_auth::oauth::loopback_redirect(&redirect, "/callback").is_some(),
        "{redirect}"
    );
    *challenge.lock().unwrap() = Some(get("code_challenge"));

    // Play the browser: follow the server's redirect to the loopback.
    let callback = format!(
        "{redirect}?{}",
        profile::form(&[
            ("code", &token("sntl_ac_", 1)),
            ("state", &get("state")),
            ("iss", &server.url),
        ])
    );
    let page = agent().get(&callback).call().unwrap();
    assert_eq!(page.status().as_u16(), 200);
    let status = child.wait().unwrap();
    reader.join().unwrap();
    printed.extend(rx.try_iter());
    let all = printed.join("\n");
    assert_eq!(status.code(), Some(0), "{all}");
    assert!(!leaks(&all), "{all}");
    let config = Config::at(&cfg).unwrap();
    let entry = &config.load().unwrap().profiles["work"];
    assert_eq!(entry.grant, "grt_browser");
    assert_eq!(
        config
            .read_credentials("work", entry)
            .unwrap()
            .unwrap()
            .refresh,
        token("sntl_rt_", 6)
    );
}

#[test]
fn login_refuses_a_server_whose_metadata_names_another_issuer() {
    let server = Fake::start(|base, req| match req.path.as_str() {
        "/.well-known/oauth-authorization-server" => {
            // Right endpoints, wrong issuer (a proxy or an impostor).
            let mut meta = Metadata::for_issuer(base, &SCOPES);
            meta.issuer = "https://elsewhere.example".into();
            (200, serde_json::to_string(&meta).unwrap())
        }
        _ => (500, "{}".into()),
    });
    let dir = tempfile::tempdir().unwrap();
    let cfg = dir.path().join("cfg");
    for flow in [&["--device"][..], &["--no-browser"][..]] {
        let mut args = vec!["auth", "login", "--server", &server.url];
        args.extend_from_slice(flow);
        let output = run(&cfg, &args);
        assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
        assert!(stderr(&output).contains("issuer"));
    }
    // Only the metadata was fetched; nothing else was sent anywhere.
    assert_eq!(
        server.total(),
        server
            .requests("/.well-known/oauth-authorization-server")
            .len()
    );

    // An endpoint on another origin is refused as well.
    let split = Fake::start(|base, _| {
        let mut meta = Metadata::for_issuer(base, &SCOPES);
        meta.token_endpoint = "https://collector.example/oauth/token".into();
        (200, serde_json::to_string(&meta).unwrap())
    });
    let error = auth_cmd::discover(&agent(), &split.url).unwrap_err();
    assert_eq!(error.exit, Exit::Remote);
    assert!(
        !Config::at(&cfg)
            .unwrap()
            .dir()
            .join("profiles.json")
            .exists()
    );
}

#[test]
fn grant_file_import_spends_the_provisioned_token_and_stores_the_successor() {
    let server = oauth_server(|req| {
        assert_eq!(req.param("grant_type").as_deref(), Some("refresh_token"));
        assert_eq!(req.param("refresh_token"), Some(token("sntl_rt_", 70)));
        (200, tokens_json(71, "grt_service"))
    });
    let dir = tempfile::tempdir().unwrap();
    let cfg = dir.path().join("cfg");
    let mut child = sentinel(&cfg)
        .args([
            "auth",
            "login",
            "--grant-file",
            "-",
            "--profile",
            "agent",
            "--server",
            &server.url,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    writeln!(child.stdin.take().unwrap(), "{}", token("sntl_rt_", 70)).unwrap();
    let output = child.wait_with_output().unwrap();
    assert_no_tokens(&output);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let config = Config::at(&cfg).unwrap();
    let entry = &config.load().unwrap().profiles["agent"];
    assert_eq!(entry.grant, "grt_service");
    let stored = config.read_credentials("agent", entry).unwrap().unwrap();
    assert_eq!(
        stored.refresh,
        token("sntl_rt_", 71),
        "the provisioned token is spent"
    );

    // Not a refresh token: refused locally, nothing sent.
    let file = dir.path().join("grant");
    std::fs::write(&file, token("sntl_at_", 1)).unwrap();
    let before = server.requests("/oauth/token").len();
    let output = run(
        &cfg,
        &[
            "auth",
            "login",
            "--grant-file",
            file.to_str().unwrap(),
            "--server",
            &server.url,
        ],
    );
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(server.requests("/oauth/token").len(), before);
}

/// A profile may be called `profiles`: signing in holds the profile's lock
/// while it updates `profiles.json`, whose own lock must be a different file.
#[test]
fn a_profile_named_profiles_signs_in_without_waiting_on_itself() {
    let server = oauth_server(|_| (200, tokens_json(81, "grt_profiles")));
    let dir = tempfile::tempdir().unwrap();
    let cfg = dir.path().join("cfg");
    let started = Instant::now();
    let mut child = sentinel(&cfg)
        .args([
            "auth",
            "login",
            "--grant-file",
            "-",
            "--profile",
            "profiles",
            "--server",
            &server.url,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    writeln!(child.stdin.take().unwrap(), "{}", token("sntl_rt_", 80)).unwrap();
    let output = child.wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert!(started.elapsed() < profile::LOCK_DEADLINE);
    let config = Config::at(&cfg).unwrap();
    assert_eq!(
        config.load().unwrap().profiles["profiles"].grant,
        "grt_profiles"
    );
}

#[test]
fn logout_revokes_then_deletes_and_offline_still_deletes_with_exit_1() {
    let server = oauth_server(|_| oauth_error("invalid_grant"));
    let dir = tempfile::tempdir().unwrap();
    let cfg_dir = dir.path().join("cfg");
    let config = Config::at(&cfg_dir).unwrap();
    let entry = seed(&config, "default", &server.url, &credentials(1, 600_000));

    let output = run(&cfg_dir, &["auth", "logout"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let revoke = &server.requests("/oauth/revoke")[0];
    assert_eq!(revoke.param("token"), Some(token("sntl_rt_", 1)));
    assert_eq!(revoke.param("client_id").as_deref(), Some("sentinel-cli"));
    assert!(
        config
            .read_credentials("default", &entry)
            .unwrap()
            .is_none()
    );
    assert!(
        config.load().unwrap().profiles.contains_key("default"),
        "kept without --forget"
    );

    // Server unreachable: the local credential goes anyway, exit 1, warning.
    let closed = {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        format!("http://{}", listener.local_addr().unwrap())
    };
    let entry = seed(&config, "offline", &closed, &credentials(2, 600_000));
    let output = run(
        &cfg_dir,
        &["auth", "logout", "--profile", "offline", "--forget"],
    );
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    assert!(stderr(&output).contains("warning"), "{}", stderr(&output));
    assert!(
        config
            .read_credentials("offline", &entry)
            .unwrap()
            .is_none()
    );
    let profiles = config.load().unwrap();
    assert!(!profiles.profiles.contains_key("offline"), "--forget");
    assert_eq!(profiles.current, None, "the forgotten profile was current");
    assert!(!cfg_dir.join("credentials/offline.json").exists());

    // --all signs out every profile.
    seed(&config, "a", &server.url, &credentials(3, 600_000));
    seed(&config, "b", &server.url, &credentials(4, 600_000));
    let output = run(&cfg_dir, &["auth", "logout", "--all", "--forget"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert!(config.load().unwrap().profiles.is_empty());
}

#[test]
fn status_reports_the_profile_without_token_material() {
    let server = oauth_server(|_| (200, tokens_json(8, "grt_seeded")));
    let dir = tempfile::tempdir().unwrap();
    let cfg_dir = dir.path().join("cfg");
    let config = Config::at(&cfg_dir).unwrap();

    // Nothing configured: exit 3 with the login hint.
    let output = run(&cfg_dir, &["auth", "status"]);
    assert_eq!(output.status.code(), Some(3));
    assert!(stderr(&output).contains("sentinel auth login"));

    seed(&config, "default", &server.url, &credentials(1, 600_000));
    let output = run(&cfg_dir, &["auth", "status", "--offline", "--json"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let doc: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(doc["schema"], "sentinel.auth-status/1");
    assert_eq!(doc["profile"], "default");
    assert_eq!(doc["current"], true);
    assert_eq!(doc["server"], server.url.as_str());
    assert_eq!(doc["store"], "file");
    assert_eq!(doc["signed_in"], true);
    assert_eq!(doc["verified"], false);
    assert_eq!(doc["scopes"], json!(["runs:read", "runs:write"]));
    assert!(doc["refresh_expires_ms"].as_u64().unwrap() > now_ms());
    assert_eq!(server.total(), 0, "--offline sends nothing");

    // Online: /me through the profile, narrowing reported.
    let output = run(&cfg_dir, &["auth", "status", "--json"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let doc: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(doc["verified"], true);
    assert_eq!(doc["narrowing"]["tenant"], "ten_narrowed");
    let text = run(&cfg_dir, &["auth", "status"]);
    assert!(String::from_utf8_lossy(&text.stdout).contains("verified"));

    // A server/profile mismatch is exit 2 before any request.
    let before = server.total();
    let output = run(
        &cfg_dir,
        &["auth", "status", "--server", "https://other.example"],
    );
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(server.total(), before);

    // Signed out: status still describes the profile, and exits 3.
    run(&cfg_dir, &["auth", "logout"]);
    let output = run(&cfg_dir, &["auth", "status", "--json"]);
    assert_eq!(output.status.code(), Some(3));
    let doc: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(doc["signed_in"], false);
}

#[test]
fn context_use_sets_the_profile_default_tenant() {
    let dir = tempfile::tempdir().unwrap();
    let cfg_dir = dir.path().join("cfg");
    let config = Config::at(&cfg_dir).unwrap();
    seed(
        &config,
        "default",
        "https://ci.example.com",
        &credentials(1, 600_000),
    );

    let output = run(&cfg_dir, &["context", "show"]);
    assert_eq!(output.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&output.stdout).contains("no default tenant"));
    let output = run(&cfg_dir, &["context", "use", "acme"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let output = run(&cfg_dir, &["context", "show", "--json"]);
    let doc: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(doc["tenant"], "acme");
    assert_eq!(config.handle(None).unwrap().unwrap().tenant(), Some("acme"));
    let output = run(&cfg_dir, &["context", "use", "bad/slug"]);
    assert_eq!(output.status.code(), Some(2));
    let output = run(
        &cfg_dir,
        &["context", "use", "acme", "--profile", "missing"],
    );
    assert_eq!(output.status.code(), Some(2));
}

/// P09-10: outside `%APPDATA%` the file store must still be owner-only. A
/// directory under the temporary directory inherits a broad ACL; after a
/// credential write the `credentials` directory and its file grant only
/// this user and SYSTEM, with inheritance cut.
#[cfg(windows)]
#[test]
fn windows_file_store_is_owner_only_wherever_it_lives() {
    let dir = tempfile::tempdir().unwrap();
    let config = config(&dir);
    seed(
        &config,
        "default",
        "http://127.0.0.1:1",
        &credentials(1, 600_000),
    );
    let user = std::env::var("USERNAME").unwrap().to_ascii_lowercase();
    for path in [
        config.dir().join("credentials"),
        config.dir().join("credentials").join("default.json"),
    ] {
        let listing = Command::new("icacls").arg(&path).output().unwrap();
        assert!(listing.status.success());
        let text = String::from_utf8_lossy(&listing.stdout).to_ascii_lowercase();
        let grants: Vec<&str> = text
            .lines()
            .filter(|l| l.contains(":("))
            .map(|l| {
                l.trim_start_matches(&*path.to_string_lossy().to_ascii_lowercase())
                    .trim()
            })
            .collect();
        // Only this user and SYSTEM (icacls may list each twice: the
        // object's own entry and the inheritable one).
        let system = r"nt authority\system:";
        let own = format!(r"\{user}:");
        assert!(
            grants
                .iter()
                .all(|g| g.starts_with(system) || g.contains(&own)),
            "{text}"
        );
        assert!(grants.iter().any(|g| g.contains(&own)), "{text}");
        assert!(grants.iter().any(|g| g.starts_with(system)), "{text}");
    }
}

#[cfg(windows)]
#[test]
fn windows_credential_manager_stores_reads_and_deletes() {
    use sentinel::keystore::windows;
    struct Cleanup(Vec<String>);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            for key in &self.0 {
                let _ = windows::delete(key);
            }
        }
    }
    let unique = format!(
        "{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let issuer = format!("http://127.0.0.1:1/sentinel-test-{unique}");
    let key = format!("sentinel-test:{unique}");
    let _cleanup = Cleanup(vec![key.clone(), keystore::key(&issuer, "default")]);

    assert_eq!(windows::read(&key).unwrap(), None);
    windows::write(&key, b"first").unwrap();
    assert_eq!(windows::read(&key).unwrap().as_deref(), Some(&b"first"[..]));
    windows::write(&key, b"second").unwrap();
    assert_eq!(
        windows::read(&key).unwrap().as_deref(),
        Some(&b"second"[..])
    );
    windows::delete(&key).unwrap();
    assert_eq!(windows::read(&key).unwrap(), None);
    windows::delete(&key).unwrap();

    // Through a profile: the credential lives in Credential Manager, not on disk.
    let dir = tempfile::tempdir().unwrap();
    let config = config(&dir);
    let creds = credentials(1, 600_000);
    let (store, os_key) = config
        .store_credentials("default", &issuer, Backend::Os, &creds)
        .unwrap();
    assert_eq!(store, Backend::Os);
    let _scoped = Cleanup(os_key.clone().into_iter().collect());
    assert!(
        os_key
            .as_deref()
            .is_some_and(|k| k.starts_with(&keystore::key(&issuer, "default")))
    );
    let entry = Profile {
        server: issuer.clone(),
        issuer: issuer.clone(),
        client_id: "sentinel-cli".into(),
        user: "usr_x".into(),
        username: None,
        grant: "grt_x".into(),
        scopes: "runs:read".into(),
        tenant: None,
        store,
        key: os_key,
        created_ms: 0,
    };
    assert_eq!(
        config.read_credentials("default", &entry).unwrap(),
        Some(creds)
    );
    assert!(!config.dir().join("credentials").exists());

    // A second configuration directory with the same profile for the same
    // server holds its own credential: signing in there neither replaces
    // nor deletes this one (each directory has its own refresh lock).
    let other_dir = tempfile::tempdir().unwrap();
    let other = self::config(&other_dir);
    let other_creds = credentials(2, 600_000);
    let (_, other_key) = other
        .store_credentials("default", &issuer, Backend::Os, &other_creds)
        .unwrap();
    let _other_scoped = Cleanup(other_key.clone().into_iter().collect());
    assert_ne!(other_key, entry.key);
    let other_entry = Profile {
        key: other_key,
        ..entry.clone()
    };
    assert_eq!(
        config
            .read_credentials("default", &entry)
            .unwrap()
            .map(|c| c.refresh),
        Some(credentials(1, 600_000).refresh)
    );
    assert_eq!(
        other
            .read_credentials("default", &other_entry)
            .unwrap()
            .map(|c| c.refresh),
        Some(other_creds.refresh.clone())
    );
    other.delete_credentials("default", &other_entry).unwrap();
    assert!(
        config
            .read_credentials("default", &entry)
            .unwrap()
            .is_some()
    );

    config.delete_credentials("default", &entry).unwrap();
    assert_eq!(config.read_credentials("default", &entry).unwrap(), None);
}

/// P09C-3: `profiles.json` decides where refresh tokens go (`issuer`) and
/// which OS-store entry is read and deleted (`key`). An entry no sign-in
/// could have written is refused before anything is sent or deleted.
#[test]
fn a_tampered_profile_is_refused_before_any_request() {
    let server = oauth_server(|_| (200, tokens_json(2, "grt_seeded")));
    let thief = oauth_server(|_| (200, tokens_json(9, "grt_seeded")));
    let dir = tempfile::tempdir().unwrap();
    let config = config(&dir);
    // The access token is spent, so the next command refreshes.
    let entry = seed(&config, "default", &server.url, &credentials(1, 0));
    let tamper = |change: &dyn Fn(&mut Profile)| {
        config
            .update(|p| {
                let mut edited = entry.clone();
                change(&mut edited);
                p.profiles.insert("default".into(), edited);
                Ok(())
            })
            .unwrap();
    };

    tamper(&|p| p.issuer = thief.url.clone());
    let error = config.handle(None).unwrap_err();
    assert_eq!(error.exit, Exit::Usage, "{}", error.message);
    let output = run(
        config.dir(),
        &["run", "list", "--tenant", "acme", "--repo", "app"],
    );
    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
    assert!(stderr(&output).contains("issuer"), "{}", stderr(&output));

    // A key naming another profile's (or another application's) entry is
    // neither read nor deleted.
    tamper(&|p| p.key = Some("sentinel:http://127.0.0.1:1:other:0123456789abcdef".into()));
    assert_eq!(config.handle(None).unwrap_err().exit, Exit::Usage);
    let edited = config.load().unwrap().profiles["default"].clone();
    assert_eq!(
        config
            .delete_credentials("default", &edited)
            .unwrap_err()
            .exit,
        Exit::Usage
    );
    let output = run(config.dir(), &["auth", "logout"]);
    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));

    assert_eq!(thief.total(), 0, "nothing reached the rewritten issuer");
    assert_eq!(server.total(), 0);
    // The genuine entry still works.
    tamper(&|_| {});
    let handle = config.handle(None).unwrap().unwrap();
    assert_eq!(handle.access_token(&agent()).unwrap(), token("sntl_at_", 2));
}

/// P09C-3: on Windows a configuration directory that existed before —
/// here one another account can modify — is refused (exit 2) the way Unix
/// refuses a loose mode, `doctor` reports it, and the `icacls` command the
/// refusal names fixes it.
#[cfg(windows)]
#[test]
fn windows_a_preexisting_configuration_directory_others_can_modify_is_refused() {
    use std::os::windows::process::CommandExt;

    let dir = tempfile::tempdir().unwrap();
    // Made owner-only by the first sign-in (a directory under %TEMP% may
    // already let other accounts in, and would be refused outright); from
    // then on it is a directory that exists.
    let shared = dir.path().join("shared");
    let config = Config::at(&shared).unwrap();
    seed(
        &config,
        "default",
        "http://127.0.0.1:1",
        &credentials(1, 600_000),
    );
    assert!(config.handle(None).unwrap().is_some());

    // Authenticated Users may now modify it, and everything inside.
    let granted = Command::new("icacls")
        .arg(&shared)
        .args(["/grant", "*S-1-5-11:(OI)(CI)M"])
        .output()
        .unwrap();
    assert!(granted.status.success(), "{granted:?}");

    let error = config.load().unwrap_err();
    assert_eq!(error.exit, Exit::Usage);
    assert!(error.message.contains("S-1-5-11"), "{}", error.message);
    let (_, fix) = error.message.split_once("; fix: ").expect("a fix");
    assert!(fix.starts_with("icacls "), "{fix}");
    assert!(config.handle(None).is_err());

    let output = run(&shared, &["doctor", "--json"]);
    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    let check = &report["checks"][0];
    assert_eq!(check["name"], "config_dir");
    assert_eq!(check["ok"], false);
    assert_eq!(check["fix"], fix);

    // The command the refusal names restores owner-only access.
    let fixed = Command::new("cmd")
        .raw_arg("/C")
        .raw_arg(fix)
        .output()
        .unwrap();
    assert!(fixed.status.success(), "{fixed:?}");
    config.load().unwrap();
    assert!(config.handle(None).unwrap().is_some());
    let output = run(&shared, &["doctor", "--json"]);
    let report: Value = serde_json::from_slice(&output.stdout).unwrap_or_default();
    assert_eq!(report["checks"][0]["ok"], true, "{}", stderr(&output));
}

/// P09C-8: profiles signed in before OS-store keys named their directory
/// share one Credential Manager entry per profile name and issuer. The
/// next refresh moves this directory's credential to its own key; an entry
/// that turns out to hold another directory's sign-in is left to it.
#[cfg(windows)]
#[test]
fn windows_a_legacy_shared_entry_moves_to_its_directory_or_is_left_to_its_owner() {
    use sentinel::keystore::windows;
    struct Cleanup(Vec<String>);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            for key in &self.0 {
                let _ = windows::delete(key);
            }
        }
    }
    let grant = Arc::new(Mutex::new("grt_seeded"));
    let answering = Arc::clone(&grant);
    let calls = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&calls);
    let server = oauth_server(move |_| {
        let n = counted.fetch_add(1, Ordering::SeqCst) as u64;
        (200, tokens_json(10 + n, *answering.lock().unwrap()))
    });
    let legacy = keystore::key(&server.url, "default");
    let blob = |creds: &Credentials| serde_json::to_vec(creds).unwrap();
    let legacy_profile = |config: &Config| {
        let entry = Profile {
            server: server.url.clone(),
            issuer: server.url.clone(),
            client_id: "sentinel-cli".into(),
            user: "usr_0123456789abcdef0123456789".into(),
            username: None,
            grant: "grt_seeded".into(),
            scopes: "runs:read".into(),
            tenant: None,
            store: Backend::Os,
            key: None,
            created_ms: 0,
        };
        let stored = entry.clone();
        config
            .update(|p| {
                p.profiles.insert("default".into(), stored);
                p.current = Some("default".into());
                Ok(())
            })
            .unwrap();
        entry
    };

    // Directory A's own sign-in, from an older build (no grant recorded),
    // with its access token spent.
    let a_dir = tempfile::tempdir().unwrap();
    let a = config(&a_dir);
    legacy_profile(&a);
    // Computed once the directory exists, as sign-in does.
    let scoped = keystore::scoped_key(a.dir(), &server.url, "default");
    let _cleanup = Cleanup(vec![legacy.clone(), scoped.clone()]);
    windows::write(&legacy, &blob(&credentials(1, 0))).unwrap();
    let handle = a.handle(None).unwrap().unwrap();
    assert_eq!(
        handle.access_token(&agent()).unwrap(),
        token("sntl_at_", 10)
    );
    let moved = a.load().unwrap().profiles["default"].clone();
    assert_eq!(moved.key.as_deref(), Some(scoped.as_str()));
    assert_eq!(
        windows::read(&legacy).unwrap(),
        None,
        "the shared entry is gone"
    );
    let stored = a.read_credentials("default", &moved).unwrap().unwrap();
    assert_eq!(stored.refresh, token("sntl_rt_", 10));
    assert_eq!(stored.grant.as_deref(), Some("grt_seeded"));
    // A fresh handle (another process) finds it under the scoped key.
    let again = a.handle(None).unwrap().unwrap();
    assert_eq!(again.access_token(&agent()).unwrap(), token("sntl_at_", 10));

    // Directory B's legacy profile, but the shared entry holds another
    // directory's newer sign-in (another grant): refreshing it hands that
    // directory's successor back and signs B out.
    *grant.lock().unwrap() = "grt_other";
    let b_dir = tempfile::tempdir().unwrap();
    let b = config(&b_dir);
    legacy_profile(&b);
    windows::write(&legacy, &blob(&credentials(2, 0))).unwrap();
    let handle = b.handle(None).unwrap().unwrap();
    let error = handle.access_token(&agent()).unwrap_err();
    assert_eq!(error.exit, Exit::Auth, "{}", error.message);
    let kept: Credentials =
        serde_json::from_slice(&windows::read(&legacy).unwrap().unwrap()).unwrap();
    assert_eq!(kept.refresh, token("sntl_rt_", 11), "the owner's successor");
    assert_eq!(kept.grant.as_deref(), Some("grt_other"));
    assert!(b.load().unwrap().profiles["default"].is_legacy());

    // Now the entry names its grant: B is refused without a request, and
    // signing out of B neither revokes nor deletes the other directory's
    // sign-in.
    let before = calls.load(Ordering::SeqCst);
    let handle = b.handle(None).unwrap().unwrap();
    assert_eq!(handle.access_token(&agent()).unwrap_err().exit, Exit::Auth);
    let output = run(b.dir(), &["auth", "logout"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert!(server.requests("/oauth/revoke").is_empty());
    assert_eq!(calls.load(Ordering::SeqCst), before);
    assert!(
        windows::read(&legacy).unwrap().is_some(),
        "left to its owner"
    );
}

/// P09C-8 residual: two configuration directories refresh the same legacy
/// shared entry at the same moment. The token endpoint holds the first
/// refresh until a second one arrives (or a second has passed), so without
/// serialization both directories present the same refresh token. With the
/// legacy-entry lock only one does: the winner moves the entry to its own
/// directory, and the other finds it gone and is signed out instead of
/// replaying a spent token.
#[cfg(windows)]
#[test]
fn windows_two_directories_never_refresh_one_legacy_entry_at_once() {
    use sentinel::keystore::windows;
    struct Cleanup(Vec<String>);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            for key in &self.0 {
                let _ = windows::delete(key);
            }
        }
    }
    let calls = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&calls);
    let server = oauth_server(move |_| {
        let n = counted.fetch_add(1, Ordering::SeqCst);
        if n == 0 {
            let until = Instant::now() + Duration::from_secs(1);
            while counted.load(Ordering::SeqCst) < 2 && Instant::now() < until {
                thread::sleep(Duration::from_millis(5));
            }
        }
        (200, tokens_json(10 + n as u64, "grt_seeded"))
    });
    let legacy = keystore::key(&server.url, "default");
    let legacy_profile = |config: &Config| {
        let entry = Profile {
            server: server.url.clone(),
            issuer: server.url.clone(),
            client_id: "sentinel-cli".into(),
            user: "usr_0123456789abcdef0123456789".into(),
            username: None,
            grant: "grt_seeded".into(),
            scopes: "runs:read".into(),
            tenant: None,
            store: Backend::Os,
            key: None,
            created_ms: 0,
        };
        config
            .update(|p| {
                p.profiles.insert("default".into(), entry);
                p.current = Some("default".into());
                Ok(())
            })
            .unwrap();
    };
    let (a_dir, b_dir) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (a, b) = (config(&a_dir), config(&b_dir));
    legacy_profile(&a);
    legacy_profile(&b);
    let _cleanup = Cleanup(vec![
        legacy.clone(),
        keystore::scoped_key(a.dir(), &server.url, "default"),
        keystore::scoped_key(b.dir(), &server.url, "default"),
    ]);
    windows::write(&legacy, &serde_json::to_vec(&credentials(1, 0)).unwrap()).unwrap();
    let start = Arc::new(std::sync::Barrier::new(2));
    let refresh = |config: Config| {
        let start = Arc::clone(&start);
        thread::spawn(move || {
            let handle = config.handle(None).unwrap().unwrap();
            start.wait();
            handle.access_token(&agent())
        })
    };
    let (ra, rb) = (refresh(a.clone()), refresh(b.clone()));
    let results = [ra.join().unwrap(), rb.join().unwrap()];
    let presented: Vec<String> = server
        .requests("/oauth/token")
        .iter()
        .filter_map(|r| r.param("refresh_token"))
        .collect();
    assert_eq!(presented, vec![token("sntl_rt_", 1)], "one presentation");
    let won = results.iter().filter(|r| r.is_ok()).count();
    assert_eq!(won, 1, "exactly one directory refreshed");
    for result in &results {
        match result {
            Ok(access) => assert_eq!(*access, token("sntl_at_", 10)),
            Err(error) => assert_eq!(error.exit, Exit::Auth, "{}", error.message),
        }
    }
    assert_eq!(windows::read(&legacy).unwrap(), None, "the entry moved");
}
