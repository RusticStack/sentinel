//! G03 through the real binaries: a running server loads its webhook secret,
//! accepts an authenticated generic ref update, resolves it off the request
//! path against a repository served on loopback HTTPS — policy, pinned
//! revision, immutable run — and the host-local CLI shows the durable record
//! with its run before retention purges it.
#![cfg(all(target_os = "linux", feature = "server"))]

use std::{
    fs,
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

use tempfile::tempdir;

const PIPELINE: &str = "schema: 1\non: {push: {branches: [main]}}\njobs:\n  build:\n    image: docker.io/library/busybox@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662\n    steps: [{ id: s, run: 'true' }]\n";

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_sentinel")
}

fn git(dir: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .args(args)
        .current_dir(dir)
        .env("GIT_AUTHOR_NAME", "t")
        .env("GIT_AUTHOR_EMAIL", "t@example.com")
        .env("GIT_COMMITTER_NAME", "t")
        .env("GIT_COMMITTER_EMAIL", "t@example.com")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}

/// The shared loopback HTTPS Git fixture: `git_https.py` serving one
/// repository, with a CA the binding pins and a deploy password it seals.
struct GitServer {
    child: Child,
    port: u16,
}

impl GitServer {
    fn start(root: &Path, cert: &Path, key: &Path, password: &Path) -> GitServer {
        let mut child = Command::new("python3")
            .arg(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../fixtures/git_https.py"
            ))
            .arg(root)
            .arg(cert)
            .arg(key)
            .env("FIXTURE_PASSWORD", password)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut line = String::new();
        BufReader::new(child.stdout.as_mut().unwrap())
            .read_line(&mut line)
            .unwrap();
        GitServer {
            child,
            port: line.trim().parse().unwrap(),
        }
    }

    fn authority(&self) -> String {
        format!("https://127.0.0.1:{}", self.port)
    }

    fn remote(&self) -> String {
        format!("{}/repo", self.authority())
    }
}

impl Drop for GitServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
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
        self.wait(|record| record["fields"]["event"] == event, event)
    }

    /// The `intake_settled` record for one delivery whose outcome starts with
    /// `prefix` (`ready`, `dispatched:`, `ignored:duplicate`, …).
    fn settled(&mut self, delivery: &str, prefix: &str) -> serde_json::Value {
        self.wait(
            |record| {
                record["fields"]["event"] == "intake_settled"
                    && record["fields"]["delivery"] == delivery
                    && record["fields"]["outcome"]
                        .as_str()
                        .is_some_and(|outcome| outcome.starts_with(prefix))
            },
            prefix,
        )
    }

    fn wait(
        &mut self,
        matches: impl Fn(&serde_json::Value) -> bool,
        what: &str,
    ) -> serde_json::Value {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if let Some(found) = self.seen.iter().find(|record| matches(record)) {
                return found.clone();
            }
            let line = self
                .lines
                .recv_timeout(deadline.saturating_duration_since(Instant::now()))
                .unwrap_or_else(|_| panic!("no {what}: {:?}", self.seen));
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

/// The repository the fixture serves: one pipeline commit and one source-only
/// commit, so the delivery is a real transition.
fn source_repository(root: &Path) -> (PathBuf, String, String) {
    let git_dir = root.join("repo");
    fs::create_dir(&git_dir).unwrap();
    git(&git_dir, &["init", "-q", "--initial-branch=main"]);
    fs::write(git_dir.join(".sentinel.yml"), PIPELINE).unwrap();
    fs::write(git_dir.join("src.txt"), "one\n").unwrap();
    git(&git_dir, &["add", "-A"]);
    git(&git_dir, &["commit", "-qm", "one"]);
    let first = git(&git_dir, &["rev-parse", "HEAD"]);
    fs::write(git_dir.join("src.txt"), "two\n").unwrap();
    git(&git_dir, &["add", "-A"]);
    git(&git_dir, &["commit", "-qm", "two"]);
    let second = git(&git_dir, &["rev-parse", "HEAD"]);
    // A real server must be told to serve an arbitrary pinned revision.
    git(
        &git_dir,
        &["config", "uploadpack.allowAnySHA1InWant", "true"],
    );
    (git_dir, first, second)
}

#[test]
fn a_ref_update_is_accepted_durably_and_dispatches_through_the_source_policy() {
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

    // Serve the repository over loopback HTTPS and bind it with the CA as
    // trust and the deploy password as the sealed credential.
    let (_, first, second) = source_repository(temp.path());
    let cert = temp.path().join("ca.pem");
    let tls_key = temp.path().join("tls.key");
    assert!(
        Command::new("openssl")
            .args([
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-days",
                "1",
                "-subj",
                "/CN=localhost",
                "-addext",
                "subjectAltName=IP:127.0.0.1",
                "-keyout",
            ])
            .arg(&tls_key)
            .arg("-out")
            .arg(&cert)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap()
            .success()
    );
    let password = temp.path().join("password");
    fs::write(&password, "private-source-token").unwrap();
    let server = GitServer::start(temp.path(), &cert, &tls_key, &password);
    let trust = fs::read_to_string(&cert).unwrap();
    fs::write(
        temp.path().join("controller/source-destinations.json"),
        serde_json::json!([server.authority()]).to_string(),
    )
    .unwrap();
    let bind = serde_json::json!({
        "binding": {
            "remote": server.remote(),
            "allowed_refs": ["refs/heads/main"],
            "pipeline_path": ".sentinel.yml",
            "trust": trust,
        },
        "credential": {"Https": {"username": "deploy", "secret": "private-source-token"}},
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

    let mut server_process = Server::spawn(data);
    let api = server_process.event("api_listening");
    let base = format!("http://{}", api["fields"]["addr"].as_str().unwrap());
    let intake = format!("{base}/api/v1/intake/{repo}");

    // A bad secret is refused before the body is looked at.
    let update = serde_json::json!({
        "delivery_id": "e2e-1",
        "ref": "refs/heads/main",
        "old_sha": first,
        "new_sha": second,
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
    let (status, first_answer) = post(&intake, &hook_token, &update);
    assert_eq!(
        (status, first_answer["duplicate"].as_bool()),
        (202, Some(false)),
        "{first_answer}"
    );
    let id = first_answer["delivery"].as_str().unwrap().to_owned();
    let (status, again) = post(&intake, &hook_token, &update);
    assert_eq!(
        (
            status,
            again["duplicate"].as_bool(),
            again["delivery"].as_str()
        ),
        (202, Some(true), Some(id.as_str()))
    );

    // The lane validates the binding, resolves the pipeline at the pushed
    // revision through Git and creates one immutable run, all off the request
    // path; the server says so in order.
    let validated = server_process.settled(&id, "ready");
    assert_eq!(validated["fields"]["delivery"], id);
    let dispatched = server_process.settled(&id, "dispatched:");
    let outcome = dispatched["fields"]["outcome"].as_str().unwrap();
    let run = outcome.trim_start_matches("dispatched:").to_owned();
    assert!(run.starts_with("run_") && run.len() == 40, "{outcome}");

    // A ref the binding does not allow settles with an explicit reason and no
    // run: it is history retention may remove.
    let rejected = serde_json::json!({
        "delivery_id": "e2e-2",
        "ref": "refs/heads/dev",
        "old_sha": first,
        "new_sha": second,
    });
    let (status, rejected_answer) = post(&intake, &hook_token, &rejected);
    assert_eq!(status, 202, "{rejected_answer}");
    let rejected_id = rejected_answer["delivery"].as_str().unwrap().to_owned();
    let failed = server_process.settled(&rejected_id, "failed:");
    assert_eq!(failed["fields"]["outcome"], "failed:ref_not_allowed");

    server_process.stop();
    // The durable record survives the process and names exactly the run that
    // was created; the CLI reads it without the server running.
    let listed = admin_path(
        data,
        &["intake"],
        &["list", "--repo", &repo, "--state", "dispatched"],
    );
    let listed: serde_json::Value = serde_json::from_str(&listed).unwrap();
    assert_eq!(listed["deliveries"][0]["id"], id);
    assert_eq!(listed["deliveries"][0]["provider"], "generic");
    assert_eq!(listed["deliveries"][0]["event"], "ref_update");
    assert_eq!(listed["deliveries"][0]["ref"], "refs/heads/main");
    assert_eq!(listed["deliveries"][0]["new_sha"], second);
    assert_eq!(listed["deliveries"][0]["run"], run);
    let unknown_state = admin_stdin(
        data,
        &["intake"],
        &["list", "--repo", &repo, "--state", "sideways"],
        b"",
    );
    assert_eq!(unknown_state.status.code(), Some(2));
    // Retention purges settled history that produced nothing — never an open
    // delivery and never one a run's provenance depends on.
    thread::sleep(Duration::from_millis(1200));
    let purged = admin_path(data, &["intake"], &["purge", "--older-than", "1s"]);
    assert!(purged.contains("\"purged\":1"), "{purged}");
    let remaining = admin_path(data, &["intake"], &["list", "--repo", &repo]);
    let remaining: serde_json::Value = serde_json::from_str(&remaining).unwrap();
    let remaining = remaining["deliveries"].as_array().unwrap();
    assert_eq!(remaining.len(), 1, "{remaining:?}");
    assert_eq!(remaining[0]["id"], id);
    assert_eq!(remaining[0]["run"], run);
}

/// A test-only RSA key; it authenticates nothing.
const TEST_KEY: &str = "-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCn0jnG5Bokc3Af
NRpzCYPskbFJvhtol1PCsuD1plfDG/Zl2UPU8U9Wv1d+kggr9b+yphtg4u2R1IXL
5VcSrVtEz4mHDQeRUtndXvPyCe3i+WIFkWd5YrVnFHzEyYyAXc2gxKlxvo715SEB
Zd+de78/2q706hZwHQ7SdODjQW5ly0JDwletAUTXMvzV7JaJ0ocwya9oIZi71PYW
v4QxOD8SQNHynMmJDJv5HADHijrFAaQyFAtsQjRGQfY/WxocdlB6YdNDCg5OOkke
tOri30xDGAPZvoPgtQp7WuEQY1AnyKKKkLjVVpNYraHy7GI2qGGKzHXylyjnqVTm
lzDfjRKBAgMBAAECggEAA1EJGZr4wJ9UEsHQEoBDI6yOFjjUE4E+GLBuorGACtfl
dYYm1tv9Uee5I8QLYPcGgVIoDgZIufjlu1hTxrI3W15F8lh5vaT8r5PIpWVjK/j6
t2/JXYxBAoGp+jzzcmFS3CpWy5Z/qRth8hmgeDJxs/eEkqGCV60zVZ8VXK22hVDH
/P36FENSTBHuCkONObeb6seoTiFq1bsFm09K4DwOHkZvG47DIbiXslMi6vjOklP9
MkRqq3qO6LL1fzLzEsO02hyVil+iyPMYHGntwf78wD/vGnhXD6+i/nH0PpqxTTtk
H36BMVpbmsfqyzEtkr5h8LprcS4GJu5DAwDPcRHJWQKBgQDXvsrQ23pfLuDAsmOO
T4wLTSADVcipAmkEZWPFbssXSHLrQfynnWCIbWOHhcrH4M5gdPA8p8DZztAcjAuN
qBf5b1vb/VxTrq5M3oqnC72SAjLIc9B+PXXLKdVnE9Ci+f3v3CVgXo0t/8bmOUf2
AotKKMbv0tLkp1YHhracj41CBQKBgQDHIk89X8LwtwB7SQGbCMtywMtbI8Nhz0Ib
Ec1te9famnzicSMb/oERrzNFJw1y/xpJ+vOXcayppMR3M91pygfoUx19dRTodoYT
mwwFuYiPSCwWpxoo0M0QdRPAtCTMGCSgyHO1he4zm96/EFIk/w0cTW1LK16J97QA
VZntcnILTQKBgE8MxGmEkbEAjy9r7Zh+QxT8/GbcbrqmfG407DqyHs34KMtUkUul
GXLDif1lI2jbUSL8le3TlZD4+z4Kfk04MxidGe5gRg0PayQVQn50idBO5+aUsOcg
g+GeAWhUVVTx/n59jmBiJJ6fInTGtjxIsFrK2CGVgNpxCc+WJ6Dz5FE1AoGBAJnp
fNF1GJkw+OBRNzp6+7TAKu1QoQ0SQoflpJ/Anr/JtEjZJUfX2C6w+bGzU4PUhJ81
pd0h8VBVl7yCi9neW2pIA30aZ4SdR1gT+KDcHB6Sq/D+SwvNBxJ3S0MgeWh+KKFV
DYn58HhXOzz2Amex8pIzjgwRg0qj965ie0y5rkfpAoGBAJ/J+9Py38IDhHs6K4Ek
GNuPWmoSiHHsvDN99rO5TahlKUw6E6Zy7hc5We0ET1HdcH+H9sQakOXf9dxgLEm7
rxl8y5pZ+rkMirxkGkfSo5k0JPL96DYRYd5GPPxxAaymC2DaaSIbBT20vtXZKyCO
BXHyoYy6w9e7POYAfdFeqKcU
-----END PRIVATE KEY-----";

/// A stub GitHub API over loopback: the installation, a checks token, the
/// repository check and the check-run creations the publisher makes.
struct GithubApi {
    addr: std::net::SocketAddr,
    records: std::sync::Arc<std::sync::Mutex<Vec<serde_json::Value>>>,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}

impl GithubApi {
    fn start() -> GithubApi {
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let addr = listener.local_addr().unwrap();
        let records = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let thread = {
            let (records, stop) = (
                std::sync::Arc::clone(&records),
                std::sync::Arc::clone(&stop),
            );
            thread::spawn(move || {
                while !stop.load(std::sync::atomic::Ordering::Acquire) {
                    match listener.accept() {
                        Ok((stream, _)) => github_reply(stream, &records),
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(5));
                        }
                        Err(_) => break,
                    }
                }
            })
        };
        GithubApi {
            addr,
            records,
            stop,
            thread: Some(thread),
        }
    }

    fn endpoint(&self) -> String {
        format!("http://{}", self.addr)
    }

    fn records(&self) -> Vec<serde_json::Value> {
        self.records.lock().unwrap().clone()
    }

    fn wait_for_check(&self) -> serde_json::Value {
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            if let Some(check) = self.records().into_iter().find(|r| {
                r["method"] == "POST"
                    && r["path"]
                        .as_str()
                        .is_some_and(|p| p.ends_with("/check-runs"))
            }) {
                return check;
            }
            assert!(Instant::now() < deadline, "no check-run request arrived");
            thread::sleep(Duration::from_millis(20));
        }
    }
}

impl Drop for GithubApi {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn github_reply(
    mut stream: std::net::TcpStream,
    records: &std::sync::Mutex<Vec<serde_json::Value>>,
) {
    use std::io::{Read, Write};
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 4096];
    let header_end = loop {
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => return,
            Ok(n) => buffer.extend_from_slice(&chunk[..n]),
        }
        if let Some(position) = buffer.windows(4).position(|w| w == b"\r\n\r\n") {
            break position;
        }
    };
    let head = String::from_utf8_lossy(&buffer[..header_end]).to_string();
    let request = head.lines().next().unwrap_or_default().to_owned();
    let mut parts = request.split_whitespace();
    let method = parts.next().unwrap_or_default().to_owned();
    let path = parts.next().unwrap_or_default().to_owned();
    let mut length = 0usize;
    for line in head.lines().skip(1) {
        if let Some((key, value)) = line.split_once(':')
            && key.trim().eq_ignore_ascii_case("content-length")
        {
            length = value.trim().parse().unwrap_or(0);
        }
    }
    let mut body = buffer[header_end + 4..].to_vec();
    while body.len() < length {
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => body.extend_from_slice(&chunk[..n]),
        }
    }
    let parsed = serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null);
    records.lock().unwrap().push(serde_json::json!({
        "method": method,
        "path": path,
        "body": parsed,
    }));
    let expires = time::OffsetDateTime::now_utc() + time::Duration::hours(1);
    let expires = expires
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap();
    let (status, response) = if method == "GET" && path.contains("/app/installations/42") {
        (
            200,
            serde_json::json!({
                "id": 42,
                "app_id": 1234,
                "account": {"id": 73, "login": "account", "type": "Organization"},
                "suspended_at": null,
                "permissions": {"contents": "read", "checks": "write"},
            }),
        )
    } else if method == "POST" && path.contains("/access_tokens") {
        (
            201,
            serde_json::json!({
                "token": "ghs_e2e_token",
                "expires_at": expires,
                "permissions": {"checks": "write", "metadata": "read"},
            }),
        )
    } else if method == "GET" && path.contains("/repositories/91") {
        (
            200,
            serde_json::json!({
                "id": 91,
                "owner": {"id": 73},
                "clone_url": "https://github.com/account/widget.git",
            }),
        )
    } else if method == "GET" && path.contains("/check-runs") {
        (200, serde_json::json!({"total_count": 0, "check_runs": []}))
    } else if method == "POST" && path.contains("/check-runs") {
        (201, serde_json::json!({"id": 707}))
    } else {
        (404, serde_json::json!({"message": "not found"}))
    };
    let text = response.to_string();
    let _ = stream.write_all(
        format!(
            "HTTP/1.1 {status} X\r\ncontent-length: {}\r\nconnection: close\r\ncontent-type: application/json\r\n\r\n{text}",
            text.len()
        )
        .as_bytes(),
    );
}

fn webhook_signature(secret: &[u8], body: &[u8]) -> String {
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, secret);
    let tag = ring::hmac::sign(&key, body);
    let mut out = String::from("sha256=");
    for byte in tag.as_ref() {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

#[test]
fn a_refused_fork_pull_request_publishes_a_completed_check() {
    let temp = tempdir().unwrap();
    let data = temp.path().join("controller");
    fs::create_dir(&data).unwrap();
    let data = data.to_str().unwrap();
    admin_path(data, &["bootstrap"], &["--username", "root"]);
    admin_path(data, &["key", "create"], &[]);
    let tenant = admin_path(data, &["tenant", "create"], &["--slug", "acme"])
        .trim()
        .to_owned();
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
        &["create", "--tenant", &tenant, "--name", "widget"],
    );
    let repo = created
        .split("\"repo\":\"")
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .expect("create prints the repository")
        .to_owned();

    // The App and its API are a loopback stub; the deployment has a public URL
    // for `details_url`.
    let api = GithubApi::start();
    let app_key = temp.path().join("app.pem");
    fs::write(&app_key, TEST_KEY).unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&app_key, fs::Permissions::from_mode(0o600)).unwrap();
    }
    fs::write(
        temp.path().join("controller/github-app.json"),
        serde_json::json!({
            "app_id": 1234,
            "private_key_file": app_key.to_str().unwrap(),
            "api_url": api.endpoint(),
            "public_url": "https://ci.example",
        })
        .to_string(),
    )
    .unwrap();
    fs::write(
        temp.path().join("controller/github-webhook.json"),
        serde_json::json!({"secret": "a-webhook-secret-value"}).to_string(),
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
    // The App association is refreshed through the stub, then bound.
    let refreshed = admin_path(
        data,
        &source,
        &[
            "refresh-installation",
            "--external-id",
            "42",
            "--expected",
            "0",
        ],
    );
    let installation = refreshed
        .split("\"installation\":\"")
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .expect("refresh prints the installation")
        .to_owned();
    let bound = admin_path(
        data,
        &source,
        &[
            "bind-installation",
            "--installation",
            &installation,
            "--tenant",
            &tenant,
        ],
    );
    assert!(bound.contains("\"bound\":true"), "{bound}");
    fs::write(
        temp.path().join("controller/source-destinations.json"),
        "[\"https://github.com\"]",
    )
    .unwrap();
    let bind = serde_json::json!({
        "binding": {
            "remote": "https://github.com/account/widget.git",
            "allowed_refs": ["refs/heads/main"],
            "pipeline_path": ".sentinel.yml",
            "trust": "",
        },
        "credential": "Public",
        "forge": {"installation": installation, "repository_id": 91},
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

    let mut server_process = Server::spawn(data);
    let start = server_process.event("checks_enabled");
    assert_eq!(start["fields"]["details_url"], true);
    let api_info = server_process.event("api_listening");
    let base = format!("http://{}", api_info["fields"]["addr"].as_str().unwrap());

    // A pull request whose head lives in another repository is refused before
    // any fetch, and that refusal still owes a completed check.
    let merge = "e".repeat(40);
    let pr = serde_json::json!({
        "action": "opened",
        "number": 7,
        "installation": {"id": 42},
        "repository": {"id": 91, "full_name": "account/widget"},
        "pull_request": {
            "draft": false,
            "head": {"ref": "feature", "sha": "c".repeat(40), "repo": {"id": 999}},
            "base": {"ref": "main", "sha": "d".repeat(40)},
            "merge_commit_sha": merge,
        },
    });
    let raw = pr.to_string();
    let (status, body) = post(&format!("{base}/api/v1/hooks/github"), "irrelevant", &pr);
    // The generic `post` helper sends no signature; use the signed path.
    assert_eq!(status, 401, "{body}");
    let agent = ureq::Agent::new_with_config(
        ureq::Agent::config_builder()
            .http_status_as_error(false)
            .build(),
    );
    let signature = webhook_signature(b"a-webhook-secret-value", raw.as_bytes());
    let response = agent
        .post(format!("{base}/api/v1/hooks/github"))
        .header("content-type", "application/json")
        .header("x-hub-signature-256", &signature)
        .header("x-github-event", "pull_request")
        .header("x-github-delivery", "pr-1")
        .send(raw.as_bytes())
        .unwrap();
    assert_eq!(response.status().as_u16(), 202);

    let settled = server_process.wait(
        |record| {
            record["fields"]["event"] == "intake_settled"
                && record["fields"]["outcome"] == "ignored:fork_pr"
        },
        "the fork refusal",
    );
    assert_eq!(settled["fields"]["outcome"], "ignored:fork_pr");
    let check = api.wait_for_check();
    assert_eq!(check["body"]["name"], "sentinel / ci");
    assert_eq!(check["body"]["status"], "completed");
    assert_eq!(check["body"]["conclusion"], "neutral");
    assert_eq!(check["body"]["head_sha"], merge);
    assert!(
        check["body"]["output"]["summary"]
            .as_str()
            .unwrap()
            .contains("fork"),
        "{check}"
    );
    // A settled delivery with no run has no details link.
    assert!(check["body"]["details_url"].is_null(), "{check}");

    server_process.stop();
    let listed = admin_path(data, &["intake"], &["list", "--repo", &repo]);
    let listed: serde_json::Value = serde_json::from_str(&listed).unwrap();
    assert_eq!(listed["deliveries"][0]["reason"], "fork_pr");
    assert_eq!(listed["deliveries"][0]["state"], "ignored");
}
