//! What runner mode asks GitHub for: one ephemeral runner's configuration, its removal, and the
//! queue a reconciliation pass reads. Nothing here reaches the network: the controller's own HTTP
//! client talks to a recorded fake.

use std::{
    collections::VecDeque,
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};

use sentinel_github::{
    app::App,
    runner::{MAX_JIT_BYTES, Scope},
};

const TOKEN: &str = "ghs_testtoken";

struct Stub {
    addr: SocketAddr,
    data: Arc<Mutex<Data>>,
    stop: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}

#[derive(Default)]
struct Data {
    scripted: VecDeque<(String, String, u16, serde_json::Value)>,
    requests: Vec<(String, String, String)>,
    permissions_seen: Vec<serde_json::Value>,
}

impl Stub {
    fn start() -> Stub {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let addr = listener.local_addr().unwrap();
        let data = Arc::new(Mutex::new(Data::default()));
        let stop = Arc::new(AtomicBool::new(false));
        let thread = {
            let (data, stop) = (Arc::clone(&data), Arc::clone(&stop));
            thread::spawn(move || {
                while !stop.load(Ordering::Acquire) {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            let _ = stream.set_nonblocking(false);
                            let data = Arc::clone(&data);
                            thread::spawn(move || serve(stream, &data));
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(5));
                        }
                        Err(_) => break,
                    }
                }
            })
        };
        Stub {
            addr,
            data,
            stop,
            thread: Some(thread),
        }
    }

    fn app(&self) -> App {
        App::new(1, test_key())
            .unwrap()
            .with_endpoint(&format!("http://{}", self.addr))
            .unwrap()
    }

    fn script(&self, method: &str, path: &str, status: u16, body: serde_json::Value) {
        self.data
            .lock()
            .unwrap()
            .scripted
            .push_back((method.into(), path.into(), status, body));
    }

    fn requests(&self) -> Vec<(String, String, String)> {
        self.data.lock().unwrap().requests.clone()
    }

    fn token(&self, app: &App) -> sentinel_github::app::Token {
        app.runner_token(
            7,
            73,
            42,
            "https://github.com/acme/app.git",
            &Scope::Repository {
                owner: "acme",
                repo: "app",
            },
            now(),
        )
        .unwrap()
    }
}

impl Drop for Stub {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn now() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp() * 1_000
}

/// A throwaway RSA key, generated for this test alone: nothing is committed, and the App is only
/// ever asked to sign a JWT the fake never verifies.
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

fn serve(mut stream: TcpStream, data: &Arc<Mutex<Data>>) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(30)));
    loop {
        let Some((method, path, body)) = read_request(&mut stream) else {
            return;
        };
        let (status, reply) = {
            let mut data = data.lock().unwrap();
            data.requests
                .push((method.clone(), path.clone(), body.clone()));
            let asked: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();
            if asked.get("permissions").is_some() {
                data.permissions_seen.push(asked.clone());
            }
            if let Some(index) = data
                .scripted
                .iter()
                .position(|(m, p, _, _)| *m == method && path.contains(p.as_str()))
            {
                let (_, _, status, body) = data.scripted.remove(index).unwrap();
                (status, body)
            } else if method == "GET" && path.starts_with("/app/installations/") {
                (200, installation_answer())
            } else if method == "POST" && path.ends_with("/access_tokens") {
                (201, token_answer(&asked))
            } else if method == "GET" && path.starts_with("/repositories/") {
                (200, repository_answer())
            } else {
                (404, serde_json::json!({"message":"Not Found"}))
            }
        };
        // A 204 answer carries no body at all, as GitHub's removal does.
        let text = if status == 204 {
            String::new()
        } else {
            reply.to_string()
        };
        let response = format!(
            "HTTP/1.1 {status} X\r\ncontent-length: {}\r\ncontent-type: application/json\r\nconnection: keep-alive\r\n\r\n",
            text.len()
        );
        if stream.write_all(response.as_bytes()).is_err()
            || stream.write_all(text.as_bytes()).is_err()
        {
            return;
        }
    }
}

fn installation_answer() -> serde_json::Value {
    serde_json::json!({
        "id": 7,
        "app_id": 1,
        "suspended_at": null,
        "account": {"id": 73, "login": "acme", "type": "Organization"},
        "permissions": {
            "contents": "read",
            "checks": "write",
            "actions": "read",
            "organization_self_hosted_runners": "write",
        },
    })
}

fn token_answer(asked: &serde_json::Value) -> serde_json::Value {
    let expiry = (time::OffsetDateTime::now_utc() + time::Duration::minutes(55))
        .format(&time::format_description::well_known::Rfc3339)
        .expect("expiry");
    let mut permissions = asked["permissions"].clone();
    permissions["metadata"] = serde_json::json!("read");
    serde_json::json!({
        "token": TOKEN,
        "expires_at": expiry,
        "permissions": permissions,
    })
}

fn repository_answer() -> serde_json::Value {
    serde_json::json!({
        "id": 42,
        "owner": {"id": 73},
        "clone_url": "https://github.com/acme/app.git",
    })
}

fn read_request(stream: &mut TcpStream) -> Option<(String, String, String)> {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 4096];
    while !buffer.windows(4).any(|w| w == b"\r\n\r\n") {
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => return None,
            Ok(n) => buffer.extend_from_slice(&chunk[..n]),
        }
    }
    let text = String::from_utf8_lossy(&buffer).to_string();
    let (head, rest) = text.split_once("\r\n\r\n")?;
    let mut lines = head.lines();
    let request = lines.next()?;
    let mut parts = request.split(' ');
    let method = parts.next()?.to_owned();
    let path = parts.next()?.to_owned();
    let length = lines
        .filter_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().ok())
                .flatten()
        })
        .next()
        .unwrap_or(0);
    let mut body = rest.as_bytes()[..rest.len().min(length)].to_vec();
    while body.len() < length {
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => body.extend_from_slice(&chunk[..n]),
        }
    }
    let body = String::from_utf8_lossy(&body).to_string();
    // A path may carry a query; keep it whole for the assertions, the fake matches by prefix.
    Some((method, path, body))
}

#[test]
fn a_repository_scope_registers_one_ephemeral_runner_with_the_class_label() {
    let stub = Stub::start();
    let app = stub.app();
    stub.script(
        "POST",
        "/repos/acme/app/actions/runners/generate-jitconfig",
        201,
        serde_json::json!({
            "runner": {"id": 91, "name": "sentinel-0011-4"},
            "encoded_jit_config": "eyJzZWsiOnRydWV9",
        }),
    );
    let token = stub.token(&app);
    let config = app
        .generate_jitconfig(
            &token,
            &Scope::Repository {
                owner: "acme",
                repo: "app",
            },
            "sentinel-0011-4",
            1,
            &["sentinel-4vcpu-ubuntu-2404".to_owned()],
        )
        .unwrap();
    assert_eq!(config.runner_id, 91);
    assert_eq!(config.encoded, b"eyJzZWsiOnRydWV9".to_vec());
    assert!(!format!("{config:?}").contains("eyJzZWsi"), "never printed");
    let requests = stub.requests();
    let generated = requests
        .iter()
        .find(|(m, p, _)| m == "POST" && p.ends_with("generate-jitconfig"))
        .expect("one request");
    let body: serde_json::Value = serde_json::from_str(&generated.2).unwrap();
    assert_eq!(body["name"], "sentinel-0011-4");
    assert_eq!(
        body["labels"],
        serde_json::json!(["sentinel-4vcpu-ubuntu-2404"])
    );
    assert!(
        body.get("runner_group_id").is_none(),
        "a repository runner has no group"
    );
    let asked = stub.data.lock().unwrap().permissions_seen.clone();
    assert_eq!(
        asked[0]["permissions"],
        serde_json::json!({"administration": "write"})
    );
    assert_eq!(asked[0]["repository_ids"], serde_json::json!([42]));
}

#[test]
fn an_organization_scope_registers_in_the_bindings_runner_group_with_its_own_permission() {
    let stub = Stub::start();
    let app = stub.app();
    stub.script(
        "POST",
        "/orgs/acme/actions/runners/generate-jitconfig",
        201,
        serde_json::json!({
            "runner": {"id": 92, "name": "sentinel-0011-5"},
            "encoded_jit_config": "e30=",
        }),
    );
    let token = app
        .runner_token(
            7,
            73,
            42,
            "https://github.com/acme/app.git",
            &Scope::Organization("acme"),
            now(),
        )
        .unwrap();
    let config = app
        .generate_jitconfig(
            &token,
            &Scope::Organization("acme"),
            "sentinel-0011-5",
            3,
            &["sentinel-8vcpu-windows-2025".to_owned()],
        )
        .unwrap();
    assert_eq!(config.runner_id, 92);
    let requests = stub.requests();
    let generated = requests
        .iter()
        .find(|(m, p, _)| m == "POST" && p.ends_with("generate-jitconfig"))
        .expect("one request");
    assert!(generated.1.starts_with("/orgs/acme/"));
    let body: serde_json::Value = serde_json::from_str(&generated.2).unwrap();
    assert_eq!(body["runner_group_id"], 3);
    let asked = stub.data.lock().unwrap().permissions_seen.clone();
    assert_eq!(
        asked[0]["permissions"],
        serde_json::json!({"organization_self_hosted_runners": "write"})
    );
    assert!(
        asked[0].get("repository_ids").is_none(),
        "an organization runner is not scoped to one repository"
    );
}

#[test]
fn a_refused_registration_is_an_error_that_carries_none_of_the_answer() {
    let stub = Stub::start();
    let app = stub.app();
    stub.script(
        "POST",
        "generate-jitconfig",
        403,
        serde_json::json!({"message": "Resource not accessible by integration"}),
    );
    let token = stub.token(&app);
    let error = app
        .generate_jitconfig(
            &token,
            &Scope::Repository {
                owner: "acme",
                repo: "app",
            },
            "sentinel-0011-6",
            1,
            &["sentinel-4vcpu-ubuntu-2404".to_owned()],
        )
        .unwrap_err();
    assert!(!format!("{error} {error:?}").contains("Resource"));
}

#[test]
fn registration_bodies_are_bounded_before_anything_leaves() {
    let stub = Stub::start();
    let app = stub.app();
    let token = stub.token(&app);
    for (name, group, labels) in [
        ("", 1, vec!["sentinel-4vcpu-ubuntu-2404".to_owned()]),
        ("bad name", 1, vec!["sentinel-4vcpu-ubuntu-2404".to_owned()]),
        ("runner", 0, vec!["sentinel-4vcpu-ubuntu-2404".to_owned()]),
        ("runner", 1, Vec::new()),
        ("runner", 1, vec!["x".repeat(65)]),
        ("runner", 1, vec!["two words".to_owned()]),
    ] {
        assert!(
            app.generate_jitconfig(&token, &Scope::Organization("acme"), name, group, &labels)
                .is_err(),
            "{name} {group} {labels:?}"
        );
    }
    assert!(
        stub.requests()
            .iter()
            .all(|(_, p, _)| !p.contains("generate-jitconfig")),
        "nothing was sent"
    );
    const _: () = assert!(MAX_JIT_BYTES >= 4096);
}

#[test]
fn removal_states_whether_github_still_had_the_runner() {
    let stub = Stub::start();
    let app = stub.app();
    let token = stub.token(&app);
    stub.script(
        "DELETE",
        "/repos/acme/app/actions/runners/91",
        204,
        serde_json::json!(null),
    );
    stub.script(
        "DELETE",
        "/repos/acme/app/actions/runners/92",
        404,
        serde_json::json!({"message":"Not Found"}),
    );
    assert!(
        app.remove_runner(
            &token,
            &Scope::Repository {
                owner: "acme",
                repo: "app"
            },
            91
        )
        .unwrap()
    );
    assert!(
        !app.remove_runner(
            &token,
            &Scope::Repository {
                owner: "acme",
                repo: "app"
            },
            92
        )
        .unwrap(),
        "an ephemeral runner that already went is the state we wanted"
    );
    assert!(
        app.remove_runner(
            &token,
            &Scope::Repository {
                owner: "acme",
                repo: "app"
            },
            0
        )
        .is_err()
    );
}

#[test]
fn the_queue_listing_reads_runs_then_their_queued_jobs() {
    let stub = Stub::start();
    let app = stub.app();
    let token = stub.token(&app);
    stub.script(
        "GET",
        "/actions/runs?status=queued",
        200,
        serde_json::json!({"total_count": 1, "workflow_runs": [{"id": 900}]}),
    );
    stub.script(
        "GET",
        "/actions/runs/900/jobs?filter=queued",
        200,
        serde_json::json!({"total_count": 2, "jobs": [
            {"id": 41, "run_id": 900, "labels": ["sentinel-4vcpu-ubuntu-2404"]},
            {"id": 42, "run_id": 900, "labels": ["self-hosted", "linux"]},
        ]}),
    );
    let jobs = app.queued_jobs(&token, "acme", "app", 5, 50).unwrap();
    assert_eq!(jobs.len(), 2);
    assert_eq!(jobs[0].job, 41);
    assert_eq!(jobs[0].run, 900);
    assert_eq!(jobs[0].labels, vec!["sentinel-4vcpu-ubuntu-2404"]);
    assert_eq!(jobs[1].labels, vec!["self-hosted", "linux"]);
    let asked: Vec<String> = stub.requests().into_iter().map(|(_, p, _)| p).collect();
    assert!(asked.iter().any(|p| p.contains("per_page=5")));
    assert!(asked.iter().any(|p| p.contains("per_page=50")));
}

#[test]
fn a_repository_name_that_could_change_the_path_is_refused() {
    let stub = Stub::start();
    let app = stub.app();
    let token = stub.token(&app);
    for (owner, repo) in [
        ("../x", "app"),
        ("acme", "app/../../x"),
        ("", "app"),
        ("acme", ""),
    ] {
        assert!(
            app.queued_jobs(&token, owner, repo, 1, 1).is_err(),
            "{owner} {repo}"
        );
    }
}
