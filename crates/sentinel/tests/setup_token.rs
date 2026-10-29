//! The setup token on a running controller: the file is owner-only, carries the logged token, and a
//! restart voids the previous token. The unit tests cover the store; this starts the real server.
#![cfg(all(target_os = "linux", feature = "server"))]

use std::{
    fs,
    io::{BufRead, BufReader},
    os::unix::fs::PermissionsExt,
    path::Path,
    process::{Child, Command, Stdio},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

struct Server {
    child: Child,
    lines: mpsc::Receiver<String>,
    seen: Vec<serde_json::Value>,
}

impl Server {
    fn spawn(root: &Path, data_dir: &Path) -> Server {
        let config = root.join("server.toml");
        fs::write(
            &config,
            "listen = '127.0.0.1:0'\napi_listen = '127.0.0.1:0'",
        )
        .unwrap();
        let mut child = Command::new(env!("CARGO_BIN_EXE_sentinel"))
            .args(["server", "--config"])
            .arg(&config)
            .arg("--data-dir")
            .arg(data_dir)
            .args(["--log-format", "json", "--log-level", "info"])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let stderr = child.stderr.take().unwrap();
        let (sender, lines) = mpsc::channel();
        thread::spawn(move || {
            for line in BufReader::new(stderr).lines() {
                let Ok(line) = line else { break };
                if sender.send(line).is_err() {
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
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if let Some(found) = self.seen.iter().find(|r| r["fields"]["event"] == event) {
                return found.clone();
            }
            let line = self
                .lines
                .recv_timeout(deadline.saturating_duration_since(Instant::now()))
                .unwrap_or_else(|_| panic!("no {event} event"));
            if let Ok(record) = serde_json::from_str(&line) {
                self.seen.push(record);
            }
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
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            if self.child.try_wait().unwrap().is_some() {
                return;
            }
            assert!(Instant::now() < deadline, "shutdown timed out");
            thread::sleep(Duration::from_millis(20));
        }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Presents `token` to the setup mail test, which checks the token first and sends nothing for an
/// address that is not one: a refused token is 403, a good one is answered `200`.
fn present(base: &str, token: &str) -> u16 {
    let agent = ureq::Agent::new_with_config(
        ureq::Agent::config_builder()
            .http_status_as_error(false)
            .build(),
    );
    let body = serde_json::json!({ "token": token, "to": "not-an-address" });
    agent
        .post(&format!("{base}/api/v1/setup/mail-test"))
        .header("content-type", "application/json")
        .send(body.to_string().as_bytes())
        .unwrap()
        .status()
        .as_u16()
}

fn start(root: &Path, data: &Path) -> (Server, String, String) {
    let mut server = Server::spawn(root, data);
    let issued = server.event("setup_required");
    let logged = issued["fields"]["token"].as_str().unwrap().to_owned();
    let api = server.event("api_listening");
    let base = format!("http://{}", api["fields"]["addr"].as_str().unwrap());
    (server, base, logged)
}

#[test]
fn the_setup_token_file_is_owner_only_and_a_restart_voids_the_old_token() {
    let temp = tempfile::tempdir().unwrap();
    let data = temp.path().join("data");
    let file = data.join("setup-token");

    let (server, base, first) = start(temp.path(), &data);
    let mode = fs::metadata(&file).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "the token file must be owner-only");
    assert_eq!(fs::read_to_string(&file).unwrap(), first);
    assert_eq!(present(&base, &first), 200, "the fresh token is accepted");
    server.stop();

    let (server, base, second) = start(temp.path(), &data);
    assert_ne!(first, second, "a restart mints a new token");
    let mode = fs::metadata(&file).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
    assert_eq!(fs::read_to_string(&file).unwrap(), second);
    assert_eq!(present(&base, &first), 403, "the previous token is void");
    assert_eq!(present(&base, &second), 200, "the new token is accepted");
    server.stop();
}
