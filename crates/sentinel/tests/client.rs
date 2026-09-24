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

#[test]
fn a_named_server_backoff_is_left_to_the_caller() {
    // P09-15: a subscriber refusal names its own back-off; the client must
    // not add two lockstep retries of its own before the caller's jitter.
    let dir = tempfile::tempdir().unwrap();
    let fake = Fake::start(
        429,
        r#"{"schema":"sentinel.error/1","code":"rate_limited","message":"canned","retryable":true,"details":{"retry_after_ms":1000}}"#,
    );
    let client = Client::connect(&ClientArgs {
        server: Some(fake.url.clone()),
        token_file: Some(token_file(&dir)),
        ..ClientArgs::default()
    })
    .unwrap();
    let error = client.get("/api/v1/runs/x/wait").unwrap_err();
    assert_eq!(error.exit, Exit::Busy);
    assert_eq!(error.api.unwrap()["details"]["retry_after_ms"], 1000);
    assert_eq!(fake.requests(), 1);
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
