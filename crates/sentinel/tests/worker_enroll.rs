//! `sentinel worker enroll` against a stand-in controller: the secret reaches the controller's body and
//! nothing else, and a failed enrollment leaves no identity, configuration or key behind.

#![cfg(all(target_os = "linux", feature = "worker"))]

use std::{
    fs,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    sync::{Arc, Mutex},
    thread::JoinHandle,
};

const SECRET: &str = "sntl_00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
const FINGERPRINT: &str = "ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12";
const KEY: &str = "0123456789abcdeffedcba98765432100123456789abcdeffedcba9876543210";
const ADDRESS: &str = "tcabcdefghijklmnopqrstuvwxyz0123";

#[derive(Clone, Copy)]
enum Answer {
    Redeemed,
    Refused,
    OtherWorker,
}

/// Answers every POST once per connection, recording each request's head and body.
struct Controller {
    port: u16,
    seen: Arc<Mutex<Vec<(String, String)>>>,
    thread: Option<JoinHandle<()>>,
}

impl Controller {
    fn start(answer: Answer, tailcat: bool) -> Controller {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let log = Arc::clone(&seen);
        let thread = std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { return };
                let Some((head, body)) = read_request(&stream) else {
                    continue;
                };
                if head.starts_with("GET /stop ") {
                    return;
                }
                log.lock().unwrap().push((head, body.clone()));
                respond(stream, answer, tailcat, &body);
            }
        });
        Controller {
            port,
            seen,
            thread: Some(thread),
        }
    }

    fn url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    fn requests(&self) -> Vec<(String, String)> {
        self.seen.lock().unwrap().clone()
    }
}

impl Drop for Controller {
    fn drop(&mut self) {
        if let Ok(mut stream) = TcpStream::connect(("127.0.0.1", self.port)) {
            let _ = stream.write_all(b"GET /stop HTTP/1.1\r\nhost: x\r\n\r\n");
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn read_request(mut stream: &TcpStream) -> Option<(String, String)> {
    let mut data = Vec::new();
    let mut chunk = [0u8; 1024];
    let end = loop {
        let n = stream.read(&mut chunk).ok()?;
        if n == 0 {
            return None;
        }
        data.extend_from_slice(&chunk[..n]);
        if let Some(at) = data.windows(4).position(|w| w == b"\r\n\r\n") {
            break at + 4;
        }
    };
    let head = String::from_utf8_lossy(&data[..end]).into_owned();
    let length = head
        .lines()
        .find_map(|line| {
            line.to_ascii_lowercase()
                .strip_prefix("content-length:")
                .and_then(|value| value.trim().parse::<usize>().ok())
        })
        .unwrap_or(0);
    while data.len() < end + length {
        let n = stream.read(&mut chunk).ok()?;
        if n == 0 {
            break;
        }
        data.extend_from_slice(&chunk[..n]);
    }
    Some((head, String::from_utf8_lossy(&data[end..]).into_owned()))
}

fn respond(mut stream: TcpStream, answer: Answer, tailcat: bool, body: &str) {
    let (status, text) = match answer {
        Answer::Refused => ("403 Forbidden", r#"{"error":"refused"}"#.to_owned()),
        Answer::Redeemed | Answer::OtherWorker => {
            let request: serde_json::Value = serde_json::from_str(body).unwrap_or_default();
            let worker = match answer {
                Answer::OtherWorker => "wrk_00000000-0000-4000-8000-000000000009".to_owned(),
                _ => request["worker"].as_str().unwrap_or("").to_owned(),
            };
            let reply = serde_json::json!({
                "worker": worker,
                "pool": "default",
                "transport": if tailcat { "tailcat" } else { "direct" },
                "host": {"cpu_millis": 2000, "memory_bytes": null, "disk_bytes": 1_000_000, "priority": 5},
                "controller": "10.0.0.5:7443",
                "controller_fingerprint": FINGERPRINT,
                "tailcat_address": if tailcat { Some(ADDRESS) } else { None },
            });
            ("200 OK", reply.to_string())
        }
    };
    let _ = write!(
        stream,
        "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{text}",
        text.len()
    );
}

fn fake_helper(dir: &Path) -> (PathBuf, String) {
    let binary = dir.join("helper");
    let script = format!(
        concat!(
            "#!/bin/sh\n",
            "case \"$1\" in\n",
            "  --version) printf 'tailcat v0.6.0\\n'; exit 0 ;;\n",
            "  genkey) case \"$*\" in\n",
            "    *--delete*) exit 0 ;;\n",
            "    *--client*) printf 'nodekey:{key}\\n' ;;\n",
            "    *) printf '{address}\\n' ;;\n",
            "  esac; exit 0 ;;\n",
            "esac\n",
            "exit 64\n",
        ),
        key = KEY,
        address = ADDRESS,
    );
    fs::write(&binary, script).unwrap();
    fs::set_permissions(&binary, fs::Permissions::from_mode(0o700)).unwrap();
    let digest = ring::digest::digest(&ring::digest::SHA256, &fs::read(&binary).unwrap())
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    (binary, digest)
}

struct Host {
    root: tempfile::TempDir,
}

impl Host {
    fn new() -> Host {
        Host {
            root: tempfile::tempdir().unwrap(),
        }
    }

    fn data(&self) -> PathBuf {
        self.root.path().join("data")
    }

    fn config(&self) -> PathBuf {
        self.root.path().join("worker.toml")
    }

    fn enroll(&self, url: &str, stdin: &str, extra: &[String]) -> Output {
        let mut child = Command::new(env!("CARGO_BIN_EXE_sentinel"))
            .args([
                "worker",
                "enroll",
                "--api-url",
                url,
                "--secret-stdin",
                "--name",
                "build-7",
            ])
            .arg("--data-dir")
            .arg(self.data())
            .arg("--config")
            .arg(self.config())
            .args(extra)
            .env("HOME", self.root.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut input = child.stdin.take().unwrap();
        let _ = input.write_all(stdin.as_bytes());
        drop(input);
        child.wait_with_output().unwrap()
    }

    /// Every file under the host's root, with its contents, for scanning.
    fn files(&self) -> Vec<(PathBuf, Vec<u8>)> {
        fn walk(dir: &Path, out: &mut Vec<(PathBuf, Vec<u8>)>) {
            for entry in fs::read_dir(dir).into_iter().flatten().flatten() {
                let path = entry.path();
                if path.is_dir() {
                    walk(&path, out);
                } else if let Ok(bytes) = fs::read(&path) {
                    out.push((path, bytes));
                }
            }
        }
        let mut out = Vec::new();
        walk(self.root.path(), &mut out);
        out
    }
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn assert_nothing_left(host: &Host) {
    for name in ["worker.id", "worker.crt", "worker.key", "tailcat"] {
        assert!(
            host.data().join(name).symlink_metadata().is_err(),
            "{name} was left behind"
        );
    }
    assert!(
        host.config().symlink_metadata().is_err(),
        "the configuration was left behind"
    );
    let strays: Vec<_> = fs::read_dir(host.root.path())
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with("worker.toml"))
        .collect();
    assert!(strays.is_empty(), "staging files left: {strays:?}");
}

#[test]
fn an_enrollment_writes_identity_and_config_and_the_secret_goes_only_to_the_controllers_body() {
    let controller = Controller::start(Answer::Redeemed, false);
    let host = Host::new();
    let run = host.enroll(&controller.url(), &format!("{SECRET}\n"), &[]);
    assert!(run.status.success(), "{}", text(&run.stderr));

    let config = fs::read_to_string(host.config()).unwrap();
    for line in [
        "controller = \"10.0.0.5:7443\"",
        &format!("controller_fingerprint = \"{FINGERPRINT}\""),
        "worker_name = \"build-7\"",
        "cpu_millis=2000",
        "disk_bytes=1000000",
        "priority=5",
    ] {
        assert!(config.contains(line), "worker.toml lacks {line}:\n{config}");
    }
    let id = fs::read_to_string(host.data().join("worker.id")).unwrap();
    assert!(id.trim().starts_with("wrk_"), "{id}");
    assert_eq!(
        fs::metadata(host.data().join("worker.key"))
            .unwrap()
            .permissions()
            .mode()
            & 0o077,
        0
    );

    // The controller got the secret in the body, once, and never in the request line or headers.
    let requests = controller.requests();
    assert_eq!(requests.len(), 1);
    let (head, body) = &requests[0];
    assert!(
        head.starts_with("POST /api/v1/worker-enrollments/redeem "),
        "{head}"
    );
    assert!(
        !head.contains(SECRET),
        "the secret reached the request line or headers"
    );
    assert!(body.contains(SECRET));
    assert!(
        body.contains(id.trim()),
        "the body names the generated worker"
    );

    // Nothing the process wrote or printed keeps a copy.
    assert!(!text(&run.stdout).contains(SECRET) && !text(&run.stderr).contains(SECRET));
    for (path, bytes) in host.files() {
        assert!(
            !text(&bytes).contains(SECRET),
            "{} holds the secret",
            path.display()
        );
    }
}

#[test]
fn a_tailcat_enrollment_binds_the_node_key_and_records_the_helper_in_the_config() {
    let controller = Controller::start(Answer::Redeemed, true);
    let host = Host::new();
    let (helper, digest) = fake_helper(host.root.path());
    let extra = vec![
        "--tailcat-binary".to_owned(),
        helper.display().to_string(),
        "--tailcat-sha256".to_owned(),
        digest.clone(),
    ];
    let run = host.enroll(&controller.url(), &format!("{SECRET}\n"), &extra);
    assert!(run.status.success(), "{}", text(&run.stderr));
    let config = fs::read_to_string(host.config()).unwrap();
    for line in [
        "controller = \"127.0.0.1:7443\"",
        &format!("tailcat_address = \"{ADDRESS}\""),
        "[tailcat]",
        &format!("sha256 = \"{digest}\""),
    ] {
        assert!(config.contains(line), "worker.toml lacks {line}:\n{config}");
    }
    let (_, body) = &controller.requests()[0];
    assert!(body.contains(&format!("nodekey:{KEY}")), "{body}");
    let seen = format!("{}{}", text(&run.stdout), text(&run.stderr));
    assert!(!seen.contains(KEY) && !seen.contains(SECRET), "{seen}");
}

#[test]
fn a_refused_enrollment_leaves_no_identity_key_or_config() {
    let controller = Controller::start(Answer::Refused, false);
    let host = Host::new();
    let run = host.enroll(&controller.url(), &format!("{SECRET}\n"), &[]);
    assert!(!run.status.success());
    let stderr = text(&run.stderr);
    assert!(stderr.contains("refused"), "{stderr}");
    assert!(!stderr.contains(SECRET));
    assert_eq!(controller.requests().len(), 1, "a refusal is not retried");
    assert_nothing_left(&host);
    assert!(
        !host.data().exists(),
        "the data directory this run created was removed"
    );
}

#[test]
fn an_answer_about_another_worker_is_not_trusted_and_is_rolled_back() {
    let controller = Controller::start(Answer::OtherWorker, false);
    let host = Host::new();
    let run = host.enroll(&controller.url(), &format!("{SECRET}\n"), &[]);
    assert!(!run.status.success());
    let stderr = text(&run.stderr);
    assert!(stderr.contains("another worker"), "{stderr}");
    // The controller already holds the binding, so the failure names the worker to remove.
    assert!(stderr.contains("wrk_"), "{stderr}");
    assert_nothing_left(&host);
}

#[test]
fn bad_input_is_refused_before_any_request_and_never_echoed() {
    let controller = Controller::start(Answer::Redeemed, false);
    let host = Host::new();

    let run = host.enroll(&controller.url(), "sntl_not-a-secret\n", &[]);
    assert!(!run.status.success());
    assert!(!text(&run.stderr).contains("not-a-secret"));

    // The secret is never an argument: the flag does not exist and its value is not echoed back.
    let out = Command::new(env!("CARGO_BIN_EXE_sentinel"))
        .args([
            "worker",
            "enroll",
            "--api-url",
            &controller.url(),
            "--secret",
            SECRET,
        ])
        .arg("--data-dir")
        .arg(host.data())
        .arg("--config")
        .arg(host.config())
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(!text(&out.stderr).contains(SECRET) && !text(&out.stdout).contains(SECRET));

    // A URL that could carry a credential is refused outright.
    let run = host.enroll(
        "https://user:pw@controller.example",
        &format!("{SECRET}\n"),
        &[],
    );
    assert!(!run.status.success());
    assert!(!text(&run.stderr).contains("pw@"), "{}", text(&run.stderr));
    let run = host.enroll("http://controller.example", &format!("{SECRET}\n"), &[]);
    assert!(!run.status.success(), "plain http is only for loopback");

    assert!(
        controller.requests().is_empty(),
        "nothing reached the controller"
    );
    assert_nothing_left(&host);
}

#[test]
fn a_host_that_looks_enrolled_is_not_enrolled_again() {
    let controller = Controller::start(Answer::Redeemed, false);
    let host = Host::new();
    fs::create_dir(host.data()).unwrap();
    fs::write(
        host.data().join("worker.id"),
        "wrk_00000000-0000-4000-8000-000000000001\n",
    )
    .unwrap();
    let run = host.enroll(&controller.url(), &format!("{SECRET}\n"), &[]);
    assert!(!run.status.success());
    assert!(
        text(&run.stderr).contains("already exists"),
        "{}",
        text(&run.stderr)
    );
    assert!(controller.requests().is_empty());
    assert_eq!(
        fs::read_to_string(host.data().join("worker.id"))
            .unwrap()
            .trim(),
        "wrk_00000000-0000-4000-8000-000000000001",
        "the existing identity is untouched"
    );
}
