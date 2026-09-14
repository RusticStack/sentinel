//! G02 through the real binaries: a running server loads its webhook secret
//! and accepts an authenticated generic ref update; the intake lane settles it
//! (the server logs `intake_settled`); after shutdown the host-local CLI shows
//! the durable record and purges it under retention.
#![cfg(all(target_os = "linux", feature = "server"))]

use std::{
    fs,
    io::{BufRead, BufReader, Write},
    process::{Child, Command, Stdio},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

use tempfile::tempdir;

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_sentinel")
}

struct Server {
    child: Child,
    lines: mpsc::Receiver<String>,
    seen: Vec<serde_json::Value>,
}

impl Server {
    fn spawn(data_dir: &str) -> Server {
        let mut child = Command::new(binary())
            .args([
                "server",
                "--data-dir",
                data_dir,
                "--log-format",
                "json",
                "--log-level",
                "info",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let stderr = child.stderr.take().unwrap();
        let (sender, lines) = mpsc::channel();
        thread::spawn(move || {
            for line in BufReader::new(stderr).lines() {
                if sender.send(line.unwrap()).is_err() {
                    break;
                }
            }
        });
        Server {
            child,
            lines,
            seen: Vec::new(),
        }
    }

    fn event(&mut self, event: &str) -> serde_json::Value {
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            if let Some(found) = self
                .seen
                .iter()
                .find(|record| record["fields"]["event"] == event)
            {
                return found.clone();
            }
            let line = self
                .lines
                .recv_timeout(deadline.saturating_duration_since(Instant::now()))
                .unwrap_or_else(|_| panic!("no {event}: {:?}", self.seen));
            self.seen
                .push(serde_json::from_str(&line).expect("complete JSON event"));
        }
    }

    fn stop(mut self) {
        assert!(
            Command::new("kill")
                .args(["-TERM", &self.child.id().to_string()])
                .status()
                .unwrap()
                .success()
        );
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                assert!(status.success(), "{status}");
                return;
            }
            assert!(Instant::now() < deadline, "shutdown timed out");
            thread::sleep(Duration::from_millis(10));
        }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// `sentinel admin <path> --data-dir <data> <args>` with `stdin` fed in.
/// Nested command groups need the data directory before their subcommand; the
/// path parameter is what says where it goes.
fn admin_stdin(data: &str, path: &[&str], args: &[&str], stdin: &[u8]) -> std::process::Output {
    let mut child = Command::new(binary())
        .args(["admin"])
        .args(path)
        .args(["--data-dir", data])
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.as_mut().unwrap().write_all(stdin).unwrap();
    child.wait_with_output().unwrap()
}

fn admin_path(data: &str, path: &[&str], args: &[&str]) -> String {
    let output = admin_stdin(data, path, args, b"correct horse battery staple");
    assert!(
        output.status.success(),
        "{path:?} {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

fn post(url: &str, token: &str, body: &serde_json::Value) -> (u16, serde_json::Value) {
    let agent = ureq::Agent::new_with_config(
        ureq::Agent::config_builder()
            .http_status_as_error(false)
            .build(),
    );
    let response = agent
        .post(url)
        .header("content-type", "application/json")
        .header("authorization", &format!("Bearer {token}"))
        .send(body.to_string().as_bytes())
        .unwrap();
    let status = response.status().as_u16();
    let text = response.into_body().read_to_string().unwrap();
    (
        status,
        serde_json::from_str(&text).unwrap_or(serde_json::Value::Null),
    )
}

#[test]
fn a_ref_update_is_accepted_durably_and_resolved_by_the_running_server() {
    let temp = tempdir().unwrap();
    let data = temp.path().join("controller");
    fs::create_dir(&data).unwrap();
    let data = data.to_str().unwrap();
    admin_path(data, &["bootstrap"], &["--username", "root"]);
    admin_path(data, &["key", "create"], &[]);
    let tenant = admin_path(data, &["tenant", "create"], &["--slug", "acme"])
        .trim()
        .to_owned();
    // The actor must be a real account; use the bootstrapped super admin.
    let status = admin_path(data, &["status"], &[]);
    let actor = status
        .split("subject=")
        .nth(1)
        .and_then(|rest| rest.split_whitespace().next())
        .expect("bootstrap audit names the account")
        .to_owned();
    let source = ["source", "--actor", actor.as_str()];
    let created = admin_path(
        data,
        &source,
        &["create", "--tenant", &tenant, "--name", "app"],
    );
    let repo = created
        .split("\"repo\":\"")
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .expect("create prints the repository")
        .to_owned();
    fs::write(
        temp.path().join("controller/source-destinations.json"),
        "[\"https://git.example:8443\"]",
    )
    .unwrap();
    let bind = serde_json::json!({
        "binding": {
            "remote": "https://git.example:8443/team/repo.git",
            "allowed_refs": ["refs/heads/main"],
            "pipeline_path": ".sentinel.yml",
            "trust": "",
        },
        "credential": {"Https": {"username": "deploy", "secret": "deploy-token"}},
        "forge": null,
    });
    let bound = admin_stdin(
        data,
        &source,
        &["bind", "--repo", &repo, "--expected", "0"],
        bind.to_string().as_bytes(),
    );
    assert!(
        bound.status.success(),
        "{}",
        String::from_utf8_lossy(&bound.stderr)
    );
    let hook_token = admin_path(data, &source, &["hook-token", "--repo", &repo]);
    let hook_token = hook_token.trim().to_owned();
    assert!(hook_token.starts_with("sentinel_hook_"));
    // A webhook secret makes the GitHub route exist; the generic route does
    // not need one.
    let webhook = serde_json::json!({ "secret": "a-webhook-secret-value" });
    fs::write(
        temp.path().join("controller/github-webhook.json"),
        webhook.to_string(),
    )
    .unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(
            temp.path().join("controller/github-webhook.json"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
    }

    let mut server = Server::spawn(data);
    let api = server.event("api_listening");
    let base = format!("http://{}", api["fields"]["addr"].as_str().unwrap());
    let intake = format!("{base}/api/v1/intake/{repo}");

    // A bad secret is refused before the body is looked at.
    let update = serde_json::json!({
        "delivery_id": "e2e-1",
        "ref": "refs/heads/main",
        "old_sha": "a".repeat(40),
        "new_sha": "b".repeat(40),
    });
    let (status, _) = post(&intake, "sentinel_hook_00", &update);
    assert_eq!(status, 401);
    let (status, _) = post(
        &format!("{base}/api/v1/hooks/github"),
        "irrelevant",
        &serde_json::json!({}),
    );
    assert_eq!(status, 401, "the webhook secret is loaded and required");

    // The delivery is accepted with its record id, and the same identity
    // redelivered is a duplicate of that record.
    let (status, first) = post(&intake, &hook_token, &update);
    assert_eq!(
        (status, first["duplicate"].as_bool()),
        (202, Some(false)),
        "{first}"
    );
    let id = first["delivery"].as_str().unwrap().to_owned();
    let (status, again) = post(&intake, &hook_token, &update);
    assert_eq!(
        (
            status,
            again["duplicate"].as_bool(),
            again["delivery"].as_str()
        ),
        (202, Some(true), Some(id.as_str()))
    );

    // The lane resolves it off the request path: the server says so, and the
    // outcome is `ready` (allowed ref, non-zero revision).
    let settled = server.event("intake_settled");
    assert_eq!(settled["fields"]["delivery"], id);
    assert_eq!(settled["fields"]["outcome"], "ready");

    server.stop();
    // The durable record survives the process and is exactly what the lane
    // settled; the CLI reads it without the server running.
    let listed = admin_path(
        data,
        &["intake"],
        &["list", "--repo", &repo, "--state", "ready"],
    );
    let listed: serde_json::Value = serde_json::from_str(&listed).unwrap();
    assert_eq!(listed["deliveries"][0]["id"], id);
    assert_eq!(listed["deliveries"][0]["provider"], "generic");
    assert_eq!(listed["deliveries"][0]["event"], "ref_update");
    assert_eq!(listed["deliveries"][0]["ref"], "refs/heads/main");
    let unknown_state = admin_stdin(
        data,
        &["intake"],
        &["list", "--repo", &repo, "--state", "sideways"],
        b"",
    );
    assert_eq!(unknown_state.status.code(), Some(2));
    // Retention purges the settled record, never a pending one.
    thread::sleep(Duration::from_millis(1200));
    let purged = admin_path(data, &["intake"], &["purge", "--older-than", "1s"]);
    assert!(purged.contains("\"purged\":1"), "{purged}");
    let remaining = admin_path(data, &["intake"], &["list", "--repo", &repo]);
    assert!(remaining.contains("\"deliveries\":[]"), "{remaining}");
}
