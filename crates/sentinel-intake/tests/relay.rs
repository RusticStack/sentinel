//! G02 relay example: a real `git push` runs `examples/hooks/post-receive`,
//! which spools each ref update and submits it over loopback HTTP. The stub
//! server records what arrived, including the Authorization header and the
//! exact JSON body.
#![cfg(target_os = "linux")]

use std::{
    fs,
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::Command,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU16, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

const SECRET: &str =
    "sentinel_hook_00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

#[derive(Clone, Debug)]
struct Request {
    authorization: Option<String>,
    body: Vec<u8>,
}

impl Request {
    fn json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body).expect("the hook sends JSON")
    }
}

/// A loopback intake stub that records requests and answers with a status.
struct Stub {
    addr: SocketAddr,
    requests: Arc<Mutex<Vec<Request>>>,
    stop: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}

impl Stub {
    fn start(status: u16) -> Stub {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let addr = listener.local_addr().unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let status = Arc::new(AtomicU16::new(status));
        let stop = Arc::new(AtomicBool::new(false));
        let thread = {
            let (requests, status, stop) = (
                Arc::clone(&requests),
                Arc::clone(&status),
                Arc::clone(&stop),
            );
            thread::spawn(move || {
                let mut workers = Vec::new();
                while !stop.load(Ordering::Acquire) {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            let (requests, status) = (Arc::clone(&requests), Arc::clone(&status));
                            workers.push(thread::spawn(move || serve(stream, requests, status)));
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(10));
                        }
                        Err(_) => break,
                    }
                }
            })
        };
        Stub {
            addr,
            requests,
            stop,
            thread: Some(thread),
        }
    }

    fn url(&self, repo: &str) -> String {
        format!("http://{}/api/v1/intake/{repo}", self.addr)
    }

    /// Wait until at least `count` requests have arrived.
    fn wait(&self, count: usize, timeout: Duration) -> Vec<Request> {
        let deadline = Instant::now() + timeout;
        loop {
            let requests = self.requests.lock().unwrap().clone();
            if requests.len() >= count {
                return requests;
            }
            assert!(
                Instant::now() < deadline,
                "stub saw {} requests",
                requests.len()
            );
            thread::sleep(Duration::from_millis(20));
        }
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

fn serve(mut stream: TcpStream, requests: Arc<Mutex<Vec<Request>>>, status: Arc<AtomicU16>) {
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
        if buffer.len() > 64 * 1024 {
            return;
        }
    };
    let head = String::from_utf8_lossy(&buffer[..header_end]).to_string();
    let (mut length, mut authorization) = (0usize, None);
    for line in head.lines().skip(1) {
        if let Some((key, value)) = line.split_once(':') {
            match key.trim().to_ascii_lowercase().as_str() {
                "content-length" => length = value.trim().parse().unwrap_or(0),
                "authorization" => authorization = Some(value.trim().to_owned()),
                _ => {}
            }
        }
    }
    let mut body = buffer[header_end + 4..].to_vec();
    while body.len() < length {
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => body.extend_from_slice(&chunk[..n]),
        }
    }
    body.truncate(length);
    requests.lock().unwrap().push(Request {
        authorization,
        body,
    });
    let status = status.load(Ordering::Relaxed);
    let _ = stream.write_all(
        format!("HTTP/1.1 {status} Ok\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")
            .as_bytes(),
    );
}

fn run(command: &mut Command) -> (bool, String) {
    let output = command.output().expect("spawn");
    (
        output.status.success(),
        String::from_utf8_lossy(&output.stderr).to_string(),
    )
}

fn git(dir: &Path, args: &[&str]) {
    let (ok, stderr) = run(Command::new("git")
        .args(args)
        .current_dir(dir)
        .env("GIT_CONFIG_GLOBAL", "/dev/null"));
    assert!(ok, "git {args:?}: {stderr}");
}

struct Repo {
    _dir: tempfile::TempDir,
    bare: PathBuf,
    work: PathBuf,
    spool: PathBuf,
    hook: PathBuf,
}

impl Repo {
    /// A bare repository with the hook installed and an env file pointing at
    /// `url`; a working clone with one commit.
    fn create(url: &str, spool_max: Option<u32>) -> Repo {
        let dir = tempfile::tempdir().unwrap();
        let (bare, work) = (dir.path().join("origin.git"), dir.path().join("work"));
        fs::create_dir(&bare).unwrap();
        git(dir.path(), &["init", "-q", "--bare", "origin.git"]);
        fs::create_dir(&work).unwrap();
        git(&work, &["init", "-q", "--initial-branch=main"]);
        git(&work, &["remote", "add", "origin", bare.to_str().unwrap()]);
        let hook = bare.join("hooks").join("post-receive");
        fs::copy(
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../examples/hooks/post-receive"
            ),
            &hook,
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&hook, fs::Permissions::from_mode(0o755)).unwrap();
        }
        let spool = dir.path().join("spool");
        let repo = Repo {
            _dir: dir,
            bare,
            work,
            spool,
            hook,
        };
        repo.write_env(url, spool_max);
        repo.commit("one");
        repo
    }

    fn write_env(&self, url: &str, spool_max: Option<u32>) {
        let mut env = format!(
            "SENTINEL_INTAKE_URL={url}\nSENTINEL_HOOK_SECRET={SECRET}\nSENTINEL_SPOOL_DIR={}\n",
            self.spool.display()
        );
        if let Some(max) = spool_max {
            env.push_str(&format!("SENTINEL_SPOOL_MAX={max}\n"));
        }
        let path = self.bare.join("hooks").join("sentinel-hook.env");
        fs::write(&path, env).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        }
    }

    fn commit(&self, name: &str) -> String {
        fs::write(self.work.join("file.txt"), format!("{name}\n")).unwrap();
        git(&self.work, &["add", "."]);
        let commit = Command::new("git")
            .args(["commit", "-q", "-m", name])
            .current_dir(&self.work)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_AUTHOR_NAME", "t")
            .env("GIT_AUTHOR_EMAIL", "t@example.com")
            .env("GIT_COMMITTER_NAME", "t")
            .env("GIT_COMMITTER_EMAIL", "t@example.com")
            .output()
            .unwrap();
        assert!(commit.status.success());
        let sha = Command::new("git")
            .args(["rev-parse", "HEAD"])
            .current_dir(&self.work)
            .output()
            .unwrap();
        String::from_utf8(sha.stdout).unwrap().trim().to_owned()
    }

    /// Push the current branch; returns the push's stderr (where the hook's
    /// messages surface).
    fn push(&self) -> String {
        let (ok, stderr) = run(Command::new("git")
            .args(["push", "origin", "main"])
            .current_dir(&self.work));
        assert!(ok, "push failed: {stderr}");
        stderr
    }

    fn flush(&self) -> (bool, String) {
        run(Command::new("sh").arg(&self.hook).arg("--flush"))
    }

    /// Push with `dir` first on the hook's `PATH` (the hook inherits the
    /// pusher's environment through `receive-pack`).
    fn push_with_path_prefix(&self, dir: &Path) -> String {
        let path = format!(
            "{}:{}",
            dir.display(),
            std::env::var("PATH").unwrap_or_default()
        );
        let (ok, stderr) = run(Command::new("git")
            .args(["push", "origin", "main"])
            .current_dir(&self.work)
            .env("PATH", path));
        assert!(ok, "push failed: {stderr}");
        stderr
    }

    fn spooled(&self) -> Vec<PathBuf> {
        let mut files: Vec<PathBuf> = fs::read_dir(&self.spool)
            .map(|entries| {
                entries
                    .filter_map(|e| e.ok())
                    .map(|e| e.path())
                    .filter(|p| p.extension().is_some_and(|e| e == "json"))
                    .collect()
            })
            .unwrap_or_default();
        files.sort();
        files
    }

    fn failed(&self) -> Vec<PathBuf> {
        let mut files: Vec<PathBuf> = fs::read_dir(self.spool.join("failed"))
            .map(|entries| entries.filter_map(|e| e.ok()).map(|e| e.path()).collect())
            .unwrap_or_default();
        files.sort();
        files
    }
}

fn prerequisites() -> bool {
    use std::process::Stdio;
    let probe = |tool: &str| {
        Command::new("sh")
            .args(["-c", &format!("command -v {tool}")])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    };
    if !probe("curl") {
        eprintln!("relay verification requires curl; skipping");
        return false;
    }
    true
}

#[test]
fn a_push_is_delivered_once_and_a_dead_controller_spools_it_for_flush() {
    if !prerequisites() {
        return;
    }
    let stub = Stub::start(202);
    let repo = Repo::create(&stub.url("rep_test"), None);
    let sha = repo.commit("two");
    repo.push();

    // Exactly one delivery, with the scoped secret and the exact ref update.
    let requests = stub.wait(1, Duration::from_secs(10));
    assert_eq!(requests.len(), 1);
    assert_eq!(
        requests[0].authorization.as_deref(),
        Some(format!("Bearer {SECRET}").as_str())
    );
    let json = requests[0].json();
    assert_eq!(json["ref"], "refs/heads/main");
    assert_eq!(json["new_sha"], sha);
    assert_eq!(json["old_sha"].as_str().unwrap().len(), 40);
    assert!(!json["delivery_id"].as_str().unwrap().is_empty());
    assert!(
        repo.spooled().is_empty(),
        "an acknowledged event leaves no spool"
    );

    // A dead controller: the event is spooled, the push still succeeds, and
    // the same stable delivery ID is what a later flush submits.
    repo.write_env("http://127.0.0.1:9/api/v1/intake/rep_test", None);
    let sha = repo.commit("three");
    let stderr = repo.push();
    assert!(
        stderr.contains("spooled"),
        "the hook reports the spool: {stderr}"
    );
    let spooled = repo.spooled();
    assert_eq!(spooled.len(), 1);
    let delivery = spooled[0].file_stem().unwrap().to_str().unwrap().to_owned();
    assert!(
        fs::read_to_string(&spooled[0]).unwrap().contains(&sha),
        "the spooled body is the event"
    );
    repo.write_env(&stub.url("rep_test"), None);
    let (ok, stderr) = repo.flush();
    assert!(ok, "flush: {stderr}");
    let requests = stub.wait(2, Duration::from_secs(10));
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[1].json()["delivery_id"], delivery.as_str());
    assert_eq!(requests[1].json()["new_sha"], sha);
    assert!(repo.spooled().is_empty());
}

#[test]
fn a_permanent_refusal_moves_the_event_to_failed_with_its_response() {
    if !prerequisites() {
        return;
    }
    let stub = Stub::start(401);
    let repo = Repo::create(&stub.url("rep_test"), None);
    repo.commit("two");
    let stderr = repo.push();
    assert!(stderr.contains("spooled"), "{stderr}");
    assert_eq!(repo.spooled().len(), 1);
    // The flush retries once, sees the 4xx and files the event as failed.
    let (ok, stderr) = repo.flush();
    assert!(!ok, "a permanent refusal is reported: {stderr}");
    assert!(stderr.contains("refused permanently"), "{stderr}");
    assert!(repo.spooled().is_empty());
    let failed = repo.failed();
    assert_eq!(failed.len(), 1);
    assert!(
        fs::read_to_string(repo.spool.join(".response.status"))
            .unwrap()
            .contains("401"),
        "the refusal status is kept beside the event"
    );
}

#[test]
fn a_rate_limited_event_stays_spooled_for_retry() {
    if !prerequisites() {
        return;
    }
    // 429 is the controller asking for back-off (admission bound, a full
    // writer queue, an ambiguous write): the event must survive it.
    let stub = Stub::start(429);
    let repo = Repo::create(&stub.url("rep_test"), None);
    repo.commit("two");
    let stderr = repo.push();
    assert!(stderr.contains("spooled"), "{stderr}");
    assert_eq!(repo.spooled().len(), 1);
    let (ok, stderr) = repo.flush();
    assert!(!ok, "an undelivered event is reported: {stderr}");
    assert!(!stderr.contains("refused permanently"), "{stderr}");
    assert_eq!(repo.spooled().len(), 1, "still spooled for the next flush");
    assert!(
        repo.failed().is_empty(),
        "never filed as a permanent refusal"
    );
    // 408 is the same kind of answer.
    let stub = Stub::start(408);
    repo.write_env(&stub.url("rep_test"), None);
    let (ok, _) = repo.flush();
    assert!(!ok);
    assert_eq!(repo.spooled().len(), 1);
    assert!(repo.failed().is_empty());
}

#[test]
fn spooled_pushes_are_delivered_oldest_first() {
    if !prerequisites() {
        return;
    }
    // Three pushes while the controller is down; the IDs sort by time, so
    // the flush replays them in push order rather than directory order.
    let repo = Repo::create("http://127.0.0.1:9/api/v1/intake/rep_test", None);
    let mut pushed = Vec::new();
    for name in ["two", "three", "four"] {
        pushed.push(repo.commit(name));
        repo.push();
    }
    let spooled = repo.spooled();
    assert_eq!(spooled.len(), 3);
    let stub = Stub::start(202);
    repo.write_env(&stub.url("rep_test"), None);
    let (ok, stderr) = repo.flush();
    assert!(ok, "flush: {stderr}");
    let requests = stub.wait(3, Duration::from_secs(10));
    let delivered: Vec<String> = requests
        .iter()
        .map(|r| r.json()["new_sha"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(delivered, pushed, "push order, not directory order");
    // The spool file names are what order them: sorted names are the
    // delivered IDs in the same order.
    let ids: Vec<String> = requests
        .iter()
        .map(|r| r.json()["delivery_id"].as_str().unwrap().to_owned())
        .collect();
    let mut sorted = ids.clone();
    sorted.sort();
    assert_eq!(ids, sorted);
    assert!(repo.spooled().is_empty());
}

#[test]
fn a_live_push_is_delivered_after_the_events_already_spooled() {
    if !prerequisites() {
        return;
    }
    let repo = Repo::create("http://127.0.0.1:9/api/v1/intake/rep_test", None);
    let older = repo.commit("two");
    repo.push();
    assert_eq!(repo.spooled().len(), 1);
    // The controller is back; the next push must not overtake the event it
    // missed.
    let stub = Stub::start(202);
    repo.write_env(&stub.url("rep_test"), None);
    let newer = repo.commit("three");
    repo.push();
    let requests = stub.wait(2, Duration::from_secs(10));
    assert_eq!(requests[0].json()["new_sha"], older.as_str());
    assert_eq!(requests[1].json()["new_sha"], newer.as_str());
    assert!(repo.spooled().is_empty());
}

#[test]
fn the_hook_secret_never_appears_in_curl_arguments() {
    if !prerequisites() {
        return;
    }
    let stub = Stub::start(202);
    let repo = Repo::create(&stub.url("rep_test"), None);
    // A `curl` shim first on PATH records its argv and standard input, then
    // runs the real one with the same input.
    let real = Command::new("sh")
        .args(["-c", "command -v curl"])
        .output()
        .unwrap();
    let real = String::from_utf8(real.stdout).unwrap().trim().to_owned();
    let shim_dir = repo.work.parent().unwrap().join("shim");
    fs::create_dir(&shim_dir).unwrap();
    let argv_log = shim_dir.join("argv.log");
    let stdin_log = shim_dir.join("stdin.log");
    let shim = shim_dir.join("curl");
    fs::write(
        &shim,
        format!(
            "#!/bin/sh\nprintf '%s\\n' \"$@\" >>'{argv}'\ntee -a '{stdin}' | exec '{real}' \"$@\"\n",
            argv = argv_log.display(),
            stdin = stdin_log.display(),
        ),
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&shim, fs::Permissions::from_mode(0o755)).unwrap();
    }
    repo.commit("two");
    repo.push_with_path_prefix(&shim_dir);
    let requests = stub.wait(1, Duration::from_secs(10));
    // The controller still receives the bearer header…
    assert_eq!(
        requests[0].authorization.as_deref(),
        Some(format!("Bearer {SECRET}").as_str())
    );
    // …but it travelled on curl's standard input, never its command line.
    let argv = fs::read_to_string(&argv_log).unwrap();
    assert!(!argv.is_empty(), "the shim ran");
    assert!(!argv.contains(SECRET), "secret in argv: {argv}");
    assert!(fs::read_to_string(&stdin_log).unwrap().contains(SECRET));
}

#[test]
fn a_full_spool_refuses_new_events_instead_of_growing() {
    if !prerequisites() {
        return;
    }
    let repo = Repo::create("http://127.0.0.1:9/api/v1/intake/rep_test", Some(1));
    // Pre-fill the spool so the next event crosses the bound.
    fs::create_dir_all(&repo.spool).unwrap();
    fs::write(repo.spool.join("seed.json"), "{}").unwrap();
    repo.commit("two");
    let stderr = repo.push();
    assert!(stderr.contains("spool full"), "{stderr}");
    assert_eq!(repo.spooled().len(), 1, "the seed is untouched");
    assert!(
        !fs::read_dir(&repo.spool)
            .unwrap()
            .filter_map(|e| e.ok())
            .any(|e| e.file_name().to_string_lossy().starts_with("seed")
                && e.file_name().to_string_lossy() != "seed.json"),
        "no new spool file"
    );
}

#[test]
fn an_unencodable_ref_is_refused_without_a_spool_write() {
    if !prerequisites() {
        return;
    }
    let stub = Stub::start(202);
    let repo = Repo::create(&stub.url("rep_test"), None);
    // A ref that cannot be encoded in the JSON contract is skipped loudly.
    let mut child = Command::new("sh")
        .arg(&repo.hook)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"0000000000000000000000000000000000000000 1111111111111111111111111111111111111111 refs/heads/quo\"te\n")
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("unencodable"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(repo.spooled().is_empty());
}
