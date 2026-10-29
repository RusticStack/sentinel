//! The real controller puts a GitHub App stored by one-click setup in force at start: the
//! webhook verifies with its sealed secret, the check lanes and sign-in start, and no log line
//! carries the App's private key, client secret or webhook secret.
#![cfg(all(target_os = "linux", feature = "server"))]

use std::{
    fs,
    io::{BufRead, BufReader},
    process::{Child, Command, Stdio},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

use sentinel_core::UnixMillis;
use sentinel_store::{Durability, Store, github_app, local_auth};
use serde_json::{Value, json};

const PASSWORD: &str = "correct horse battery staple";
/// A test-only RSA key generated fresh for this process with the `openssl` CLI; it authenticates nothing and no
/// private key is committed (see `no_committed_keys` in the `sentinel` crate tests).
fn test_key() -> &'static str {
    static KEY: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    KEY.get_or_init(|| {
        let out = std::process::Command::new("openssl")
            .args([
                "genpkey",
                "-algorithm",
                "RSA",
                "-pkeyopt",
                "rsa_keygen_bits:2048",
            ])
            .output()
            .expect("the openssl CLI must be installed to generate the test-only App key");
        assert!(out.status.success(), "openssl genpkey failed");
        String::from_utf8(out.stdout).expect("PEM is ASCII")
    })
}
const KEY_CANARY: &str = "lfnygBuVfX5FiM4XtRB7CajdRR18a6A";
const CLIENT_SECRET: &str = "client-secret-canary-6f1d2a9e0b7c4d3e8f5a";
const WEBHOOK_SECRET: &str = "webhook-secret-canary-3e9f0a1b2c7d4e5f6a8b";

struct Server {
    child: Child,
    lines: mpsc::Receiver<String>,
    seen: Vec<String>,
}

impl Server {
    fn spawn(root: &std::path::Path, data_dir: &std::path::Path) -> Server {
        let config = root.join("server.toml");
        fs::write(
            &config,
            "listen = '127.0.0.1:0'\napi_listen = '127.0.0.1:0'\npublic_url = 'https://ci.example.com'\n",
        )
        .unwrap();
        let mut child = Command::new(env!("CARGO_BIN_EXE_sentinel"))
            .args(["server", "--config"])
            .arg(&config)
            .arg("--data-dir")
            .arg(data_dir)
            .args(["--log-format", "json", "--log-level", "debug"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let (sender, lines) = mpsc::channel();
        for stream in [
            Box::new(child.stdout.take().unwrap()) as Box<dyn std::io::Read + Send>,
            Box::new(child.stderr.take().unwrap()),
        ] {
            let sender = sender.clone();
            thread::spawn(move || {
                for line in BufReader::new(stream).lines() {
                    let Ok(line) = line else { break };
                    if sender.send(line).is_err() {
                        break;
                    }
                }
            });
        }
        Server {
            child,
            lines,
            seen: Vec::new(),
        }
    }

    fn event(&mut self, event: &str) -> Value {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if let Some(found) = self
                .seen
                .iter()
                .filter_map(|line| serde_json::from_str::<Value>(line).ok())
                .find(|record| record["fields"]["event"] == event)
            {
                return found;
            }
            let line = self
                .lines
                .recv_timeout(deadline.saturating_duration_since(Instant::now()))
                .unwrap_or_else(|_| panic!("no {event}: {:?}", self.seen));
            self.seen.push(line);
        }
    }

    /// Stops the controller and returns every line it wrote.
    fn stop(mut self) -> Vec<String> {
        assert!(
            Command::new("kill")
                .args(["-TERM", &self.child.id().to_string()])
                .status()
                .unwrap()
                .success()
        );
        let deadline = Instant::now() + Duration::from_secs(10);
        while self.child.try_wait().unwrap().is_none() {
            assert!(Instant::now() < deadline, "shutdown timed out");
            thread::sleep(Duration::from_millis(10));
        }
        while let Ok(line) = self.lines.recv_timeout(Duration::from_millis(200)) {
            self.seen.push(line);
        }
        std::mem::take(&mut self.seen)
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn request(
    method: &str,
    url: &str,
    body: &str,
    headers: &[(&str, &str)],
) -> (u16, Vec<String>, Value) {
    let agent = ureq::Agent::new_with_config(
        ureq::Agent::config_builder()
            .http_status_as_error(false)
            .build(),
    );
    let response = if method == "GET" {
        let mut r = agent.get(url);
        for (k, v) in headers {
            r = r.header(*k, *v);
        }
        r.call()
    } else {
        let mut r = agent.post(url).header("content-type", "application/json");
        for (k, v) in headers {
            r = r.header(*k, *v);
        }
        r.send(body.as_bytes())
    }
    .unwrap();
    let status = response.status().as_u16();
    let headers = response
        .headers()
        .iter()
        .map(|(n, v)| format!("{n}: {}", v.to_str().unwrap_or_default()))
        .collect();
    let text = response.into_body().read_to_string().unwrap_or_default();
    (
        status,
        headers,
        serde_json::from_str(&text).unwrap_or(Value::String(text)),
    )
}

fn signature(secret: &[u8], body: &str) -> String {
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, secret);
    let tag = ring::hmac::sign(&key, body.as_bytes());
    let hex: String = tag.as_ref().iter().map(|b| format!("{b:02x}")).collect();
    format!("sha256={hex}")
}

#[test]
fn a_stored_app_is_in_force_at_start_and_no_log_line_carries_its_secrets() {
    let temp = tempfile::tempdir().unwrap();
    let data = temp.path().join("controller");
    fs::create_dir_all(&data).unwrap();
    let key_path = data.join("master.key");
    sentinel_auth::sealed::Key::create(&key_path).unwrap();
    let key = sentinel_auth::sealed::Key::load(&key_path).unwrap();
    {
        let store = Store::open(data.join("metadata.sqlite"), Durability::Full).unwrap();
        let now = UnixMillis::now();
        let root = local_auth::bootstrap(&store, "root", "Root", PASSWORD.as_bytes(), now).unwrap();
        let sealed = github_app::seal(&key, 4242, test_key(), CLIENT_SECRET, Some(WEBHOOK_SECRET));
        let public = github_app::Public {
            app_id: 4242,
            slug: "acme-ci".into(),
            name: "Acme CI".into(),
            owner: "acme-gh".into(),
            owner_id: 9000,
            html_url: "https://github.com/apps/acme-ci".into(),
            client_id: "Iv23.acmeclient".into(),
        };
        store
            .writer()
            .write(move |tx| github_app::store(tx, &public, &sealed, root, now))
            .unwrap();
    }

    let mut server = Server::spawn(temp.path(), &data);
    let listening = server.event("api_listening");
    let base = format!("http://{}", listening["fields"]["addr"].as_str().unwrap());
    let enabled = server.event("github_sign_in_enabled");
    assert_eq!(enabled["fields"]["client_id"], "Iv23.acmeclient");
    server.event("checks_enabled");
    server.event("github_webhook_enabled");

    let mut answers = Vec::new();
    let ping = "{\"zen\":\"Keep it logically awesome.\"}";
    for (secret, expected) in [
        (WEBHOOK_SECRET.as_bytes(), 200),
        (&b"a-different-secret-0123456789"[..], 401),
    ] {
        let sig = signature(secret, ping);
        let (status, headers, body) = request(
            "POST",
            &format!("{base}/api/v1/hooks/github"),
            ping,
            &[
                ("x-github-event", "ping"),
                ("x-github-delivery", "72d3162e-cc78-11e3-81ab-4c9367dc0958"),
                ("x-hub-signature-256", &sig),
            ],
        );
        assert_eq!(status, expected, "{body}");
        answers.push(format!("{headers:?} {body}"));
    }
    let (status, headers, login) = request(
        "POST",
        &format!("{base}/api/v1/login"),
        &json!({ "username": "root", "password": PASSWORD }).to_string(),
        &[],
    );
    assert_eq!(status, 200, "{login}");
    let cookie = headers
        .iter()
        .find_map(|h| h.strip_prefix("set-cookie: "))
        .map(|v| v.split(';').next().unwrap().to_owned())
        .unwrap();
    let (status, headers, view) = request(
        "GET",
        &format!("{base}/api/v1/github/app"),
        "",
        &[("cookie", &cookie)],
    );
    assert_eq!(status, 200, "{view}");
    assert_eq!(view["configured"], true);
    assert_eq!(view["source"], "manifest");
    assert_eq!(view["app"]["slug"], "acme-ci");
    assert_eq!(view["create_refusal"], "configured");
    answers.push(format!("{headers:?} {view}"));

    let lines = server.stop();
    assert!(!lines.is_empty());
    for canary in [KEY_CANARY, CLIENT_SECRET, WEBHOOK_SECRET] {
        assert!(
            !lines.iter().any(|line| line.contains(canary)),
            "{canary} in the controller's output"
        );
        assert!(
            !answers.iter().any(|a| a.contains(canary)),
            "{canary} in an answer"
        );
    }
}
