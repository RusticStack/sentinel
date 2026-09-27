//! The shared API client, portable: how server answers become exit codes,
//! how JSON mode reports failures, retries on busy answers, and the static
//! credential rules. A fake HTTP server on loopback answers every request
//! with one canned response and counts what it saw.

use std::{
    io::{BufRead, BufReader, Read, Write},
    net::{TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
};

use sentinel::client::{Client, ClientArgs, Exit};

/// Answers every request with `status` and `body`, then closes.
struct Fake {
    url: String,
    requests: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}

impl Fake {
    fn start(status: u16, body: &str) -> Fake {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let requests = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let (seen, halt, body) = (Arc::clone(&requests), Arc::clone(&stop), body.to_owned());
        let thread = thread::spawn(move || {
            for stream in listener.incoming() {
                if halt.load(Ordering::Acquire) {
                    return;
                }
                let Ok(stream) = stream else { continue };
                if answer(stream, status, &body) {
                    seen.fetch_add(1, Ordering::AcqRel);
                }
            }
        });
        Fake {
            url,
            requests,
            stop,
            thread: Some(thread),
        }
    }

    fn requests(&self) -> usize {
        self.requests.load(Ordering::Acquire)
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

/// Read one request head (and any declared body), answer, close.
fn answer(stream: TcpStream, status: u16, body: &str) -> bool {
    let mut reader = BufReader::new(&stream);
    let mut length = 0usize;
    let mut line = String::new();
    let mut first = true;
    loop {
        line.clear();
        if reader.read_line(&mut line).unwrap_or(0) == 0 {
            return false;
        }
        if first {
            first = false;
            continue;
        }
        let trimmed = line.trim_end();
        if trimmed.is_empty() {
            break;
        }
        if let Some((name, value)) = trimmed.split_once(':')
            && name.eq_ignore_ascii_case("content-length")
        {
            length = value.trim().parse().unwrap_or(0);
        }
    }
    let mut discard = vec![0u8; length];
    let _ = reader.read_exact(&mut discard);
    let content_type = if body.starts_with('{') {
        "application/json"
    } else {
        "text/plain"
    };
    let response = format!(
        "HTTP/1.1 {status} X\r\ncontent-type: {content_type}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    );
    let mut stream = &stream;
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.flush();
    true
}

fn error_body(code: &str) -> String {
    format!(
        r#"{{"schema":"sentinel.error/1","code":"{code}","message":"canned","retryable":false}}"#
    )
}

fn token_file(dir: &tempfile::TempDir) -> PathBuf {
    let path = dir.path().join("token");
    std::fs::write(&path, format!("sntl_{}\n", "ab".repeat(32))).unwrap();
    path
}

fn api(server: &str, token: &Path, extra: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sentinel"))
        .env_remove("SENTINEL_TOKEN")
        .env_remove("SENTINEL_SERVER")
        .env_remove("SENTINEL_PROFILE")
        .args([
            "api",
            "--server",
            server,
            "--token-file",
            token.to_str().unwrap(),
        ])
        .args(extra)
        .arg("me")
        .output()
        .unwrap()
}

#[test]
fn server_answers_become_stable_exit_codes() {
    let dir = tempfile::tempdir().unwrap();
    let token = token_file(&dir);
    let cases: Vec<(u16, String, i32, usize)> = vec![
        (200, r#"{"user":"usr_x","via":"bearer"}"#.into(), 0, 1),
        (401, error_body("unauthenticated"), 3, 1),
        (403, error_body("forbidden"), 3, 1),
        (404, error_body("not_found"), 4, 1),
        (409, error_body("conflict"), 5, 1),
        (422, error_body("idempotency_mismatch"), 5, 1),
        (400, error_body("invalid_request"), 1, 1),
        // Busy answers are retried (a GET is safe to repeat), then exit 6.
        (429, error_body("rate_limited"), 6, 3),
        (507, error_body("storage_full"), 6, 3),
        (500, error_body("internal"), 6, 3),
        (503, error_body("outcome_unknown"), 6, 3),
        // A proxy's answer that is not sentinel.error/1, and a malformed 200.
        (502, "bad gateway".into(), 1, 3),
        (200, "not json".into(), 1, 1),
    ];
    for (status, body, exit, requests) in cases {
        let fake = Fake::start(status, &body);
        let output = api(&fake.url, &token, &[]);
        assert_eq!(
            output.status.code(),
            Some(exit),
            "{status} {body}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(fake.requests(), requests, "{status} {body}");
        if exit != 0 {
            assert!(output.stdout.is_empty(), "{status}");
            assert!(String::from_utf8_lossy(&output.stderr).starts_with("error: "));
        }
    }
}

#[test]
fn json_mode_reports_one_error_document_on_stderr_only() {
    let dir = tempfile::tempdir().unwrap();
    let token = token_file(&dir);
    let fake = Fake::start(404, &error_body("not_found"));
    let output = api(&fake.url, &token, &["--json"]);
    assert_eq!(output.status.code(), Some(4));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert_eq!(stderr.lines().count(), 1, "{stderr}");
    let document: serde_json::Value = serde_json::from_str(stderr.trim()).unwrap();
    assert_eq!(document["schema"], "sentinel.error/1");
    assert_eq!(document["code"], "not_found");

    // A failure with no server document gets a client_ code in the same shape.
    let bad = dir.path().join("bad-token");
    std::fs::write(&bad, "not-a-token").unwrap();
    let output = api(&fake.url, &bad, &["--json"]);
    assert_eq!(output.status.code(), Some(2));
    let document: serde_json::Value =
        serde_json::from_str(String::from_utf8(output.stderr).unwrap().trim()).unwrap();
    assert_eq!(document["code"], "client_usage");
    assert_eq!(fake.requests(), 1, "a usage error sends nothing");
}

#[test]
fn an_unreachable_server_is_busy_after_retries() {
    let dir = tempfile::tempdir().unwrap();
    let token = token_file(&dir);
    let closed = {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        format!("http://{}", listener.local_addr().unwrap())
    };
    let output = api(&closed, &token, &[]);
    assert_eq!(output.status.code(), Some(6));
    assert!(String::from_utf8_lossy(&output.stderr).contains("cannot reach"));
}

#[test]
fn a_static_credential_is_checked_before_any_request() {
    let dir = tempfile::tempdir().unwrap();
    let fake = Fake::start(200, "{}");
    let good = token_file(&dir);
    let access = dir.path().join("access");
    std::fs::write(&access, format!("sntl_at_{}", "cd".repeat(32))).unwrap();
    let refresh = dir.path().join("refresh");
    std::fs::write(&refresh, format!("sntl_rt_{}", "cd".repeat(32))).unwrap();
    let args = |server: &str, token: &PathBuf| ClientArgs {
        server: Some(server.to_owned()),
        token_file: Some(token.clone()),
        ..ClientArgs::default()
    };
    let client = Client::connect(&args(&format!("{}/", fake.url), &good)).unwrap();
    assert_eq!(client.server(), fake.url);
    assert_eq!(client.default_tenant(), None);
    assert!(Client::connect(&args(&fake.url, &access)).is_ok());
    for (server, token) in [
        (fake.url.as_str(), &refresh),
        ("http://10.0.0.5:7080", &good),
        ("https://user@ci.example.com", &good),
        ("ci.example.com", &good),
    ] {
        let refused = Client::connect(&args(server, token)).unwrap_err();
        assert_eq!(refused.exit, Exit::Usage, "{server}");
    }
    let missing = ClientArgs {
        server: Some(fake.url.clone()),
        token_file: Some(dir.path().join("absent")),
        ..ClientArgs::default()
    };
    assert_eq!(Client::connect(&missing).unwrap_err().exit, Exit::Usage);
    assert_eq!(fake.requests(), 0, "connecting sends nothing");

    // The same client maps answers to exits in-process.
    let not_found = Fake::start(404, &error_body("not_found"));
    let client = Client::connect(&args(&not_found.url, &good)).unwrap();
    let error = client.get("/api/v1/me").unwrap_err();
    assert_eq!(error.exit, Exit::NotFound);
    assert_eq!(error.api.unwrap()["code"], "not_found");
}

#[test]
fn a_closed_stdout_ends_a_networked_command_quietly_with_exit_zero() {
    // P09-13: `… --output ndjson | head -1` used to end in a panic (exit 101).
    let dir = tempfile::tempdir().unwrap();
    let token = token_file(&dir);
    let fake = Fake::start(200, r#"{"user":"usr_x","via":"bearer"}"#);
    for mode in [&[][..], &["--json"][..]] {
        let (reader, writer) = std::io::pipe().unwrap();
        drop(reader);
        let output = Command::new(env!("CARGO_BIN_EXE_sentinel"))
            .env_remove("SENTINEL_TOKEN")
            .env_remove("SENTINEL_SERVER")
            .env_remove("SENTINEL_PROFILE")
            .args(["api", "--server", &fake.url, "--token-file"])
            .arg(&token)
            .args(mode)
            .arg("me")
            .stdout(writer)
            .stderr(std::process::Stdio::piped())
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(0), "{mode:?}: {stderr}");
        assert!(stderr.is_empty(), "{mode:?}: {stderr}");
    }
}

#[test]
fn an_unknown_write_outcome_is_repeated_only_under_its_idempotency_key() {
    let dir = tempfile::tempdir().unwrap();
    let args = |server: &str| ClientArgs {
        server: Some(server.to_owned()),
        token_file: Some(token_file(&dir)),
        ..ClientArgs::default()
    };
    let body = r#"{"schema":"sentinel.error/1","code":"outcome_unknown","message":"canned","retryable":false,"details":{"retry_with_idempotency_key":true}}"#;
    // P02-1: the first write may still commit, so an unkeyed POST is sent once.
    let fake = Fake::start(503, body);
    let client = Client::connect(&args(&fake.url)).unwrap();
    let error = client
        .post("/api/v1/x", &serde_json::json!({}), None)
        .unwrap_err();
    assert_eq!(error.exit, Exit::Busy);
    assert!(
        error.message.contains("may have been applied"),
        "{}",
        error.message
    );
    assert_eq!(fake.requests(), 1);
    // The same key makes a repeat a replay, never a second execution.
    let keyed = Fake::start(503, body);
    let client = Client::connect(&args(&keyed.url)).unwrap();
    let error = client
        .post("/api/v1/x", &serde_json::json!({}), Some("k1"))
        .unwrap_err();
    assert_eq!(error.api.unwrap()["code"], "outcome_unknown");
    assert_eq!(keyed.requests(), 3);
}

const NAMED_BACKOFF: &str = r#"{"schema":"sentinel.error/1","code":"rate_limited","message":"controller busy; retry","retryable":true,"details":{"retry_after_ms":1000}}"#;

#[test]
fn a_named_server_backoff_is_honored_then_retried() {
    // P09C-2: a store too busy to check the credential answers
    // `rate_limited` with `retry_after_ms`, like a refused long poll. It is
    // an overload like any other, so a request safe to repeat is retried —
    // but only after the server's own back-off (P09-15), plus jitter.
    let dir = tempfile::tempdir().unwrap();
    let fake = Fake::start(429, NAMED_BACKOFF);
    let client = Client::connect(&ClientArgs {
        server: Some(fake.url.clone()),
        token_file: Some(token_file(&dir)),
        ..ClientArgs::default()
    })
    .unwrap();
    let started = std::time::Instant::now();
    let error = client.get("/api/v1/runs/x").unwrap_err();
    assert_eq!(error.exit, Exit::Busy);
    assert_eq!(error.api.unwrap()["details"]["retry_after_ms"], 1000);
    assert_eq!(fake.requests(), 3, "retried up to three attempts");
    let waited = started.elapsed();
    assert!(
        waited >= std::time::Duration::from_millis(2000),
        "two named back-offs of at least 1 s: {waited:?}"
    );
    // An unkeyed POST is still never repeated.
    let once = Fake::start(429, NAMED_BACKOFF);
    let client = Client::connect(&ClientArgs {
        server: Some(once.url.clone()),
        token_file: Some(token_file(&dir)),
        ..ClientArgs::default()
    })
    .unwrap();
    assert!(
        client
            .post("/api/v1/x", &serde_json::json!({}), None)
            .is_err()
    );
    assert_eq!(once.requests(), 1);
}

/// P09C-2 through MCP: a tool call meets the same overload and is retried
/// by the shared client before the tool reports it.
#[test]
fn an_mcp_tool_call_retries_a_named_backoff() {
    let dir = tempfile::tempdir().unwrap();
    let token = token_file(&dir);
    let fake = Fake::start(429, NAMED_BACKOFF);
    let input = concat!(
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2025-11-25\",\"capabilities\":{},\"clientInfo\":{\"name\":\"t\",\"version\":\"1\"}}}\n",
        "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n",
        "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"list_runs\",\"arguments\":{\"tenant\":\"acme\",\"repo\":\"app\"}}}\n"
    );
    let mut child = Command::new(env!("CARGO_BIN_EXE_sentinel"))
        .env_remove("SENTINEL_TOKEN")
        .env_remove("SENTINEL_SERVER")
        .env_remove("SENTINEL_PROFILE")
        .env("SENTINEL_CONFIG_DIR", dir.path().join("no-profiles"))
        .args(["mcp", "--server", &fake.url, "--token-file"])
        .arg(&token)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let replies: Vec<serde_json::Value> = String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(replies[1]["result"]["isError"], true, "{replies:?}");
    assert_eq!(
        replies[1]["result"]["structuredContent"]["code"],
        "rate_limited"
    );
    assert_eq!(fake.requests(), 3);
}

/// Both worker listings show how each worker is reached: `{path} {rtt}ms`
/// when measured, `rtt=-` when the round trip was not, `transport=-` when
/// the worker never reported. JSON output stays the server's document.
#[test]
fn worker_listings_show_each_workers_transport_and_json_stays_the_server_document() {
    let body = r#"{"pools":[{"name":"linux","kind":"shared","workers":[
        {"id":"wrk_a","name":"alpha","arch":"x86_64","connected":true,
         "transport":{"path":"direct","rtt_ns":1234567,"reconnects":0,"bytes_in":1,"bytes_out":2}},
        {"id":"wrk_b","name":"beta","arch":"aarch64","connected":true,
         "transport":{"path":"relay","reconnects":3,"bytes_in":0,"bytes_out":0}},
        {"id":"wrk_c","name":"gamma","arch":"x86_64","connected":false,"transport":null}]}]}"#;
    let fake = Fake::start(200, body);
    let dir = tempfile::tempdir().unwrap();
    let token = token_file(&dir);
    let token = token.to_str().unwrap();
    let run = |args: &[&str]| {
        let output = Command::new(env!("CARGO_BIN_EXE_sentinel"))
            .env_remove("SENTINEL_TOKEN")
            .env_remove("SENTINEL_SERVER")
            .env_remove("SENTINEL_PROFILE")
            .env("SENTINEL_CONFIG_DIR", dir.path().join("no-profiles"))
            .args(args)
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        assert_eq!(output.status.code(), Some(0), "{args:?}: {stderr}");
        String::from_utf8(output.stdout).unwrap()
    };
    let list = |extra: &[&str]| {
        let mut args = vec![
            "workers",
            "list",
            "--tenant",
            "acme",
            "--server",
            &fake.url,
            "--token-file",
            token,
        ];
        args.extend_from_slice(extra);
        run(&args)
    };
    let legacy = |extra: &[&str]| {
        let mut args = vec!["api", "--server", &fake.url, "--token-file", token];
        args.extend_from_slice(extra);
        args.extend_from_slice(&["workers", "--tenant", "acme"]);
        run(&args)
    };
    let expected = "pool linux (shared)\n\
                    \x20 wrk_a alpha x86_64 connected direct 1.2ms\n\
                    \x20 wrk_b beta aarch64 connected relay rtt=-\n\
                    \x20 wrk_c gamma x86_64 offline transport=-\n";
    assert_eq!(list(&[]), expected);
    assert_eq!(legacy(&[]), expected);

    let server: serde_json::Value = serde_json::from_str(body).unwrap();
    let listed: serde_json::Value = serde_json::from_str(&list(&["--output", "json"])).unwrap();
    assert_eq!(listed["pools"], server["pools"]);
    let raw: serde_json::Value = serde_json::from_str(&legacy(&["--json"])).unwrap();
    assert_eq!(raw, server);
}

// ------------------------------------------------- scripted server (paced)

/// One request as the scripted server saw it.
#[derive(Clone, Debug)]
struct Seen {
    target: String,
    range: Option<String>,
}

/// An answer: status, content type, body, and how to send the body.
struct Reply {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    /// Send the body in pieces of this many bytes, pausing between them.
    pace: Option<(usize, std::time::Duration)>,
    /// Send only this many body bytes, then hold the connection silently.
    stall_after: Option<usize>,
}

impl Reply {
    fn json(value: &serde_json::Value) -> Reply {
        Reply {
            status: 200,
            headers: vec![("content-type".into(), "application/json".into())],
            body: value.to_string().into_bytes(),
            pace: None,
            stall_after: None,
        }
    }
}

type Script = dyn Fn(&Seen) -> Reply + Send + Sync;

/// A loopback server answering each connection on its own thread from a
/// script, able to trickle or stall a body.
struct Scripted {
    url: String,
    seen: Arc<std::sync::Mutex<Vec<Seen>>>,
    stop: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}

impl Scripted {
    fn start(script: impl Fn(&Seen) -> Reply + Send + Sync + 'static) -> Scripted {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let script: Arc<Script> = Arc::new(script);
        let (log, halt) = (Arc::clone(&seen), Arc::clone(&stop));
        let thread = thread::spawn(move || {
            for stream in listener.incoming() {
                if halt.load(Ordering::Acquire) {
                    return;
                }
                let Ok(stream) = stream else { continue };
                let (script, log) = (Arc::clone(&script), Arc::clone(&log));
                thread::spawn(move || serve_scripted(stream, &*script, &log));
            }
        });
        Scripted {
            url,
            seen,
            stop,
            thread: Some(thread),
        }
    }

    fn seen(&self, prefix: &str) -> Vec<Seen> {
        self.seen
            .lock()
            .unwrap()
            .iter()
            .filter(|s| s.target.starts_with(prefix))
            .cloned()
            .collect()
    }
}

impl Drop for Scripted {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        let _ = TcpStream::connect(self.url.trim_start_matches("http://"));
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn serve_scripted(stream: TcpStream, script: &Script, log: &std::sync::Mutex<Vec<Seen>>) {
    let mut reader = BufReader::new(&stream);
    let mut line = String::new();
    if reader.read_line(&mut line).unwrap_or(0) == 0 {
        return;
    }
    let target = line.split(' ').nth(1).unwrap_or("").to_owned();
    let mut range = None;
    loop {
        line.clear();
        if reader.read_line(&mut line).unwrap_or(0) == 0 {
            return;
        }
        let trimmed = line.trim_end();
        if trimmed.is_empty() {
            break;
        }
        if let Some((name, value)) = trimmed.split_once(':')
            && name.eq_ignore_ascii_case("range")
        {
            range = Some(value.trim().to_owned());
        }
    }
    let seen = Seen { target, range };
    log.lock().unwrap().push(seen.clone());
    let reply = script(&seen);
    let mut head = format!(
        "HTTP/1.1 {} X\r\ncontent-length: {}\r\nconnection: close\r\n",
        reply.status,
        reply.body.len()
    );
    for (name, value) in &reply.headers {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    head.push_str("\r\n");
    let mut out = &stream;
    if out.write_all(head.as_bytes()).is_err() {
        return;
    }
    let sent = reply.stall_after.unwrap_or(reply.body.len());
    match reply.pace {
        None => {
            let _ = out.write_all(&reply.body[..sent]);
        }
        Some((piece, pause)) => {
            for chunk in reply.body[..sent].chunks(piece) {
                if out.write_all(chunk).and_then(|()| out.flush()).is_err() {
                    return;
                }
                thread::sleep(pause);
            }
        }
    }
    let _ = out.flush();
    if reply.stall_after.is_some() {
        // Hold the connection open without a byte, as a stuck proxy would.
        thread::sleep(std::time::Duration::from_secs(8));
    }
}

/// A payload, its manifest answer and the object path the CLI will fetch.
struct Object {
    payload: Vec<u8>,
    digest: String,
}

impl Object {
    fn new(len: usize) -> Object {
        let payload: Vec<u8> = (0..len).map(|i| (i * 31 % 251) as u8).collect();
        let digest = blake3::hash(&payload).to_hex().to_string();
        Object { payload, digest }
    }

    fn manifest(&self) -> serde_json::Value {
        serde_json::json!({
            "id": "art_x", "name": "report", "state": "captured", "tenant": "acme",
            "manifest": { "entries": [
                { "path": "out.bin", "digest": self.digest, "len": self.payload.len() }
            ] },
        })
    }

    fn path(&self) -> String {
        format!("/api/v1/tenants/acme/objects/{}", self.digest)
    }

    /// The object's bytes after `range` (`bytes=START-END`), as the
    /// controller serves them: `206` with `content-range`, or `200` whole.
    fn answer(&self, range: Option<&str>) -> Reply {
        let len = self.payload.len();
        match range.and_then(|r| r.strip_prefix("bytes=")) {
            Some(spec) => {
                let (start, end) = spec.split_once('-').unwrap();
                let start: usize = start.parse().unwrap();
                let end: usize = end.parse().unwrap();
                Reply {
                    status: 206,
                    headers: vec![("content-range".into(), format!("bytes {start}-{end}/{len}"))],
                    body: self.payload[start..=end].to_vec(),
                    pace: None,
                    stall_after: None,
                }
            }
            None => Reply {
                status: 200,
                headers: Vec::new(),
                body: self.payload.clone(),
                pace: None,
                stall_after: None,
            },
        }
    }
}

/// `sentinel artifact download run_x art_x --path out.bin --out OUT` with
/// the transfer bounds scaled from 60 s and 30 s down to `timeout_ms`.
fn download(server: &str, dir: &tempfile::TempDir, out: &Path, timeout_ms: u64) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sentinel"))
        .env_remove("SENTINEL_TOKEN")
        .env_remove("SENTINEL_SERVER")
        .env_remove("SENTINEL_PROFILE")
        .env("SENTINEL_CONFIG_DIR", dir.path().join("no-profiles"))
        .env("SENTINEL_TEST_TIMEOUT_MS", timeout_ms.to_string())
        .args([
            "artifact", "download", "run_x", "art_x", "--path", "out.bin",
        ])
        .arg("--out")
        .arg(out)
        .args(["--server", server, "--token-file"])
        .arg(token_file(dir))
        .output()
        .unwrap()
}

fn parts(dir: &Path) -> Vec<PathBuf> {
    std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.to_string_lossy().ends_with(".sentinel-part"))
        .collect()
}

/// P09C-1: a transfer that takes far longer than the whole-call bound (60 s
/// in production, 1 s here) still completes while bytes keep arriving:
/// downloads are bounded per wait for the network, not as a whole.
#[test]
fn a_slow_download_longer_than_the_call_bound_completes() {
    let object = Arc::new(Object::new(64 << 10));
    let served = Arc::clone(&object);
    let server = Scripted::start(move |seen| {
        if seen.target == "/api/v1/runs/run_x/artifacts/art_x" {
            return Reply::json(&served.manifest());
        }
        assert_eq!(seen.target, served.path());
        Reply {
            // 2 KiB every 100 ms: 3.2 s for the whole body.
            pace: Some((2 << 10, std::time::Duration::from_millis(100))),
            ..served.answer(seen.range.as_deref())
        }
    });
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out.bin");
    let started = std::time::Instant::now();
    let output = download(&server.url, &dir, &out, 1_000);
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(started.elapsed() >= std::time::Duration::from_secs(3));
    assert_eq!(std::fs::read(&out).unwrap(), object.payload);
    assert_eq!(
        server.seen(&object.path()).len(),
        1,
        "one uninterrupted transfer"
    );
    assert!(parts(dir.path()).is_empty());
}

/// P09C-1: a transfer that stalls mid-body resumes with a `Range` request
/// for the rest, and the digest of the whole still decides.
#[test]
fn a_stalled_download_resumes_from_its_partial_file() {
    let object = Arc::new(Object::new(96 << 10));
    let served = Arc::clone(&object);
    let half = object.payload.len() / 2;
    let server = Scripted::start(move |seen| {
        if seen.target == "/api/v1/runs/run_x/artifacts/art_x" {
            return Reply::json(&served.manifest());
        }
        match seen.range {
            None => Reply {
                stall_after: Some(half),
                ..served.answer(None)
            },
            Some(_) => served.answer(seen.range.as_deref()),
        }
    });
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out.bin");
    let output = download(&server.url, &dir, &out, 1_000);
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(std::fs::read(&out).unwrap(), object.payload);
    let fetched = server.seen(&object.path());
    assert_eq!(fetched.len(), 2, "{fetched:?}");
    assert_eq!(fetched[0].range, None);
    assert_eq!(
        fetched[1].range.as_deref(),
        Some(format!("bytes={half}-{}", object.payload.len() - 1).as_str())
    );
    assert!(parts(dir.path()).is_empty());
}

/// P09C-1: a transfer that stops making progress exits 6 and keeps what it
/// has; running the command again continues after those bytes instead of
/// starting over.
#[test]
fn an_interrupted_download_keeps_its_bytes_and_the_next_run_resumes() {
    let object = Arc::new(Object::new(64 << 10));
    let served = Arc::clone(&object);
    let quarter = object.payload.len() / 4;
    let healthy = Arc::new(AtomicBool::new(false));
    let mode = Arc::clone(&healthy);
    let server = Scripted::start(move |seen| {
        if seen.target == "/api/v1/runs/run_x/artifacts/art_x" {
            return Reply::json(&served.manifest());
        }
        let reply = served.answer(seen.range.as_deref());
        if mode.load(Ordering::Acquire) {
            return reply;
        }
        // Broken: the first request gets a quarter, every resume nothing.
        let stall = if seen.range.is_none() { quarter } else { 0 };
        Reply {
            stall_after: Some(stall),
            ..reply
        }
    });
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out.bin");
    std::fs::write(&out, b"previous").unwrap();
    let output = download(&server.url, &dir, &out, 700);
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert_eq!(output.status.code(), Some(6), "{stderr}");
    assert!(stderr.contains("run the same command again"), "{stderr}");
    assert_eq!(std::fs::read(&out).unwrap(), b"previous", "untouched");
    let kept = parts(dir.path());
    assert_eq!(kept.len(), 1);
    assert_eq!(std::fs::metadata(&kept[0]).unwrap().len(), quarter as u64);
    let tries = server.seen(&object.path()).len();

    healthy.store(true, Ordering::Release);
    let output = download(&server.url, &dir, &out, 700);
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(std::fs::read(&out).unwrap(), object.payload);
    let fetched = server.seen(&object.path());
    assert_eq!(fetched.len(), tries + 1, "{fetched:?}");
    assert_eq!(
        fetched[tries].range.as_deref(),
        Some(format!("bytes={quarter}-{}", object.payload.len() - 1).as_str())
    );
    assert!(parts(dir.path()).is_empty());
}

/// P09C-7: an answer that says `finished` next to a view of a live run
/// (a rerun committed between the server's two reads) is progress, not
/// the end; `wait` goes on and judges the run it finally sees.
#[test]
fn wait_does_not_judge_a_finished_answer_whose_run_is_live_again() {
    let polls = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&polls);
    let server = Scripted::start(move |seen| {
        assert!(
            seen.target.starts_with("/api/v1/runs/run_x/wait"),
            "{seen:?}"
        );
        let n = counted.fetch_add(1, Ordering::AcqRel);
        let (state, terminal) = if n == 0 {
            ("queued", false)
        } else {
            ("passed", true)
        };
        Reply::json(&serde_json::json!({
            "version": format!("{:016x}", n + 1),
            "changed": true,
            "finished": true,
            "run": {
                "id": "run_x", "state": state,
                "jobs": [{ "name": "build", "state": state, "terminal": terminal }],
            },
        }))
    });
    let dir = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_sentinel"))
        .env_remove("SENTINEL_TOKEN")
        .env_remove("SENTINEL_SERVER")
        .env_remove("SENTINEL_PROFILE")
        .env("SENTINEL_CONFIG_DIR", dir.path().join("no-profiles"))
        .args(["wait", "run_x", "--timeout", "20s", "--json", "--server"])
        .arg(&server.url)
        .arg("--token-file")
        .arg(token_file(&dir))
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let view: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(view["state"], "passed");
    assert_eq!(polls.load(Ordering::Acquire), 2);
}
