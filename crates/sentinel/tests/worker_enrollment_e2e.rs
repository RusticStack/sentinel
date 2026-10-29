//! The real controller issues, serves, redeems and withdraws worker enrollments, and no line it writes at debug level
//! carries an enrollment secret.
//!
//! A direct enrollment is driven here. A Tailcat enrollment carries the controller's Tailcat address, which needs the
//! helper and a live tunnel (X4, X6); the address staying out of the controller's log is therefore covered by the API
//! tests' answers and database scan and stays an unverified limit for the real log until Wave 4.
#![cfg(all(target_os = "linux", feature = "server"))]

use std::{
    fs,
    io::{BufRead, BufReader},
    process::{Child, Command, Stdio},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

use sentinel_core::{PoolId, UnixMillis};
use sentinel_store::{
    Durability, Store,
    auth::Authority,
    local_auth,
    tenancy::{self, PoolKind},
};
use serde_json::{Value, json};

const PASSWORD: &str = "correct horse battery staple";
const SUM_X86: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const SUM_ARM: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

struct Server {
    child: Child,
    lines: mpsc::Receiver<String>,
    seen: Vec<String>,
}

impl Server {
    fn spawn(root: &std::path::Path, data_dir: &std::path::Path, sums: &std::path::Path) -> Server {
        let config = root.join("server.toml");
        fs::write(
            &config,
            format!(
                "listen = '127.0.0.1:0'\napi_listen = '127.0.0.1:0'\npublic_url = 'https://ci.example.com'\n\
                 [worker_bootstrap]\ncontroller = '10.0.0.5:7443'\nrelease_url = 'https://releases.example.test/sentinel/0.1.0'\n\
                 release_sums = '{}'\napi_url = 'http://127.0.0.1:8080'\n",
                sums.display()
            ),
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

struct Answer {
    status: u16,
    headers: Vec<(String, String)>,
    text: String,
}

impl Answer {
    fn json(&self) -> Value {
        serde_json::from_str(&self.text).unwrap_or(Value::Null)
    }
}

fn call(method: &str, url: &str, body: Option<&Value>, headers: &[(&str, &str)]) -> Answer {
    let agent = ureq::Agent::new_with_config(
        ureq::Agent::config_builder()
            .http_status_as_error(false)
            .build(),
    );
    let response = match method {
        "GET" | "DELETE" => {
            let mut r = if method == "GET" {
                agent.get(url).force_send_body()
            } else {
                agent.delete(url).force_send_body()
            };
            for (k, v) in headers {
                r = r.header(*k, *v);
            }
            r.send_empty()
        }
        _ => {
            let mut r = agent.post(url).header("content-type", "application/json");
            for (k, v) in headers {
                r = r.header(*k, *v);
            }
            r.send(
                body.map_or_else(|| "{}".to_owned(), Value::to_string)
                    .as_bytes(),
            )
        }
    }
    .unwrap();
    let status = response.status().as_u16();
    let headers = response
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
    Answer {
        status,
        headers,
        text,
    }
}

#[test]
fn no_controller_log_line_carries_an_enrollment_secret() {
    let temp = tempfile::tempdir().unwrap();
    let data = temp.path().join("controller");
    fs::create_dir_all(&data).unwrap();
    sentinel_auth::sealed::Key::create(&data.join("master.key")).unwrap();
    let sums = temp.path().join("SHA256SUMS");
    fs::write(
        &sums,
        format!(
            "{SUM_X86}  sentinel-0.1.0-x86_64-linux-worker.tar.gz\n{SUM_ARM}  sentinel-0.1.0-aarch64-linux-worker.tar.gz\n"
        ),
    )
    .unwrap();
    let pool = PoolId::new();
    {
        let store = Store::open(data.join("metadata.sqlite"), Durability::Full).unwrap();
        local_auth::bootstrap(
            &store,
            "root",
            "Root",
            PASSWORD.as_bytes(),
            UnixMillis::now(),
        )
        .unwrap();
        store
            .writer()
            .write(move |tx| {
                tenancy::create_pool(
                    tx,
                    Authority::HostLocal,
                    pool,
                    "fleet",
                    PoolKind::Shared,
                    UnixMillis::now(),
                )
            })
            .unwrap();
    }

    let mut server = Server::spawn(temp.path(), &data, &sums);
    let listening = server.event("api_listening");
    let base = format!("http://{}", listening["fields"]["addr"].as_str().unwrap());
    server.event("worker_bootstrap_enabled");

    let login = call(
        "POST",
        &format!("{base}/api/v1/login"),
        Some(&json!({ "username": "root", "password": PASSWORD })),
        &[],
    );
    assert_eq!(login.status, 200, "{}", login.text);
    let cookie = login
        .headers
        .iter()
        .find(|(n, _)| n == "set-cookie")
        .map(|(_, v)| v.split(';').next().unwrap().to_owned())
        .unwrap();
    let csrf = login.json()["csrf"].as_str().unwrap().to_owned();
    let session = [
        ("cookie", cookie.as_str()),
        ("x-sentinel-csrf", csrf.as_str()),
    ];
    let proof = call(
        "POST",
        &format!("{base}/api/v1/step-up"),
        Some(&json!({ "method": "password", "code": PASSWORD })),
        &session,
    );
    assert_eq!(proof.status, 200, "{}", proof.text);

    let mut secrets = Vec::new();
    let mut ids = Vec::new();
    for _ in 0..2 {
        let issued = call(
            "POST",
            &format!("{base}/api/v1/admin/worker-enrollments"),
            Some(&json!({ "pool": pool.to_string(), "transport": "direct" })),
            &session,
        );
        assert_eq!(issued.status, 201, "{}", issued.text);
        let issued = issued.json();
        let secret = issued["secret"].as_str().unwrap().to_owned();
        assert!(secret.starts_with("sntl_") && secret.len() == 69);
        secrets.push(secret);
        ids.push(issued["id"].as_str().unwrap().to_owned());
    }

    let options = call(
        "GET",
        &format!("{base}/api/v1/admin/worker-bootstrap"),
        None,
        &session,
    );
    assert_eq!(options.status, 200, "{}", options.text);
    assert_eq!(options.json()["configured"], true);
    let script = call(
        "GET",
        &format!(
            "{base}/api/v1/admin/worker-enrollments/{}/bootstrap.sh",
            ids[0]
        ),
        None,
        &session,
    );
    assert_eq!(script.status, 200);
    let digest: String = ring::digest::digest(&ring::digest::SHA256, script.text.as_bytes())
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_eq!(
        options.json()["transports"]["direct"]["bootstrap_sha256"],
        digest
    );

    // One machine redeems; the other enrollment is withdrawn.
    let redeemed = call(
        "POST",
        &format!("{base}/api/v1/worker-enrollments/redeem"),
        Some(&json!({
            "secret": secrets[0],
            "worker": sentinel_core::WorkerId::new().to_string(),
            "name": "build-1",
            "fingerprint": "11".repeat(32),
            "arch": "x86_64",
        })),
        &[],
    );
    assert_eq!(redeemed.status, 200, "{}", redeemed.text);
    let withdrawn = call(
        "DELETE",
        &format!("{base}/api/v1/admin/worker-enrollments/{}", ids[1]),
        None,
        &session,
    );
    assert_eq!(withdrawn.status, 204);
    // A refused secret is logged and audited without the guess.
    let guess = format!("sntl_{}", "ef".repeat(32));
    let refused = call(
        "POST",
        &format!("{base}/api/v1/worker-enrollments/redeem"),
        Some(&json!({
            "secret": guess,
            "worker": sentinel_core::WorkerId::new().to_string(),
            "name": "build-2",
            "fingerprint": "22".repeat(32),
            "arch": "x86_64",
        })),
        &[],
    );
    assert_eq!(refused.status, 403);

    let lines = server.stop();
    assert!(!lines.is_empty());
    secrets.push(guess);
    for secret in &secrets {
        for needle in [secret.as_str(), &secret[5..]] {
            assert!(
                !lines.iter().any(|line| line.contains(needle)),
                "an enrollment secret is in the controller's output"
            );
        }
    }
    // The controller did log, so the scan above had lines to read.
    assert!(
        lines.iter().any(|l| l.contains("worker_bootstrap_enabled")),
        "{lines:?}"
    );
}
