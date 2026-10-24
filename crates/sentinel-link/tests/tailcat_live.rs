//! Each test skips unless SENTINEL_TAILCAT_LIVE is set; with it set, a missing prerequisite fails the test.
//! ```sh
//! SENTINEL_TAILCAT_LIVE=/root/tailcat/tailcat \
//!   cargo test -p sentinel-link --all-features --test tailcat_live -- --ignored --nocapture --test-threads=1
//! ```
//! ```sh
//! cp /etc/ssl/certs/ca-certificates.crt /tmp/tailcat-live-ca.pem
//! SENTINEL_TAILCAT_DERPER=/root/derper-bin/derper \
//! SENTINEL_TAILCAT_DERP_CA=/tmp/tailcat-live-ca.pem SSL_CERT_FILE=/tmp/tailcat-live-ca.pem \
//!   (plus the command above; PATH must include /usr/sbin for podman, iptables and nft)
//! ```

#![cfg(target_os = "linux")]

use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use sentinel_link::{
    controller::{HANDOFF_BOUND, HANDOFF_RESEND_BOUND},
    session::Path as Route,
    tailcat::{self, Address, NodeKey, PINNED_SHA256, PINNED_VERSION, Role, TailcatConfig},
};
use sha2::{Digest, Sha256};

const READY: Duration = Duration::from_secs(60);
const PROBE_EVERY: Duration = Duration::from_secs(3);
const PROBLEM: Duration = Duration::from_secs(45);

static LIVE: std::sync::Mutex<()> = std::sync::Mutex::new(());

struct Helper {
    _dir: tempfile::TempDir,
    binary: PathBuf,
}

fn live_binary() -> Option<Helper> {
    let path = PathBuf::from(std::env::var_os("SENTINEL_TAILCAT_LIVE")?);
    let bytes = std::fs::read(&path)
        .unwrap_or_else(|error| panic!("SENTINEL_TAILCAT_LIVE is set but unreadable: {error}"));
    let digest = Sha256::digest(&bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    assert_eq!(
        digest, PINNED_SHA256,
        "SENTINEL_TAILCAT_LIVE is not the pinned {PINNED_VERSION} build"
    );
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    let binary = dir.path().join("tailcat");
    std::fs::write(&binary, bytes).unwrap();
    std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o755)).unwrap();
    Some(Helper { _dir: dir, binary })
}

fn gate(tools: &[&str]) -> Option<Helper> {
    let Some(helper) = live_binary() else {
        eprintln!("SENTINEL_TAILCAT_LIVE unset; skipping live tailcat test");
        return None;
    };
    for tool in tools {
        let found = Command::new(tool)
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok();
        assert!(
            found,
            "SENTINEL_TAILCAT_LIVE is set but {tool} is unavailable"
        );
    }
    Some(helper)
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn config(binary: &Path, port: u16) -> TailcatConfig {
    TailcatConfig {
        enabled: true,
        binary: binary.to_path_buf(),
        sha256: PINNED_SHA256.to_owned(),
        derpmap_url: None,
        region: None,
        listen_port: port,
    }
}

fn wait_until(what: &str, within: Duration, mut ready: impl FnMut() -> bool) {
    let deadline = Instant::now() + within;
    while Instant::now() < deadline {
        if ready() {
            return;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    panic!("timed out waiting for {what}");
}

struct Server {
    name: String,
    address: Address,
}

impl Server {
    fn start(binary: &Path, name: &str, port: u16, allow: Option<&NodeKey>, keys: &Path) -> Self {
        let bind = binary.parent().unwrap();
        let allow_arg = allow
            .map(|key| format!("--allow={}", key.expose()))
            .unwrap_or_default();
        let key_file = "/home/.config/tailcat/keys/default.private.json";
        let script = format!(
            "nc -lk -p {port} -e cat & \
             if [ ! -f {key_file} ]; then \
                 HOME=/home /tc/tailcat genkey --key=default --fixed-region >/dev/null 2>&1; \
             fi; \
             HOME=/home /tc/tailcat serve {allow_arg} {port}"
        );
        remove_container(name);
        let output = Command::new("podman")
            .args([
                "run",
                "-d",
                "--name",
                name,
                "-v",
                &format!("{}:/tc:ro", bind.display()),
                "-v",
                &format!("{}:/home", keys.display()),
                "alpine:3",
                "sh",
                "-c",
                &script,
            ])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "podman run failed for {name}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let mut server = Self {
            name: name.to_owned(),
            address: Address::parse("tcplaceholderplaceholder").unwrap(),
        };
        server.address = server.wait_address();
        server
    }

    fn wait_address(&self) -> Address {
        let deadline = Instant::now() + READY;
        while Instant::now() < deadline {
            let output = Command::new("podman")
                .args(["logs", &self.name])
                .output()
                .unwrap();
            let text = String::from_utf8_lossy(&output.stdout).into_owned()
                + &String::from_utf8_lossy(&output.stderr);
            for line in text.lines() {
                if !line.to_ascii_lowercase().contains("listening") {
                    continue;
                }
                if let Some(address) = line.split_whitespace().rev().find_map(Address::parse) {
                    return address;
                }
            }
            std::thread::sleep(Duration::from_millis(500));
        }
        panic!("container {} never reported an address", self.name);
    }

    fn restart_with(
        &self,
        binary: &Path,
        port: u16,
        allow: Option<&NodeKey>,
        keys: &Path,
    ) -> Server {
        self.stop();
        Server::start(binary, &self.name, port, allow, keys)
    }

    fn stop(&self) {
        remove_container(&self.name);
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop();
    }
}

fn remove_container(name: &str) {
    let _ = Command::new("podman")
        .args(["rm", "-f", name])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

fn echo(port: u16, payload: &[u8]) -> Vec<u8> {
    let mut stream = TcpStream::connect_timeout(
        &std::net::SocketAddr::from(([127, 0, 0, 1], port)),
        Duration::from_secs(10),
    )
    .expect("the forward does not answer on loopback");
    stream
        .set_read_timeout(Some(Duration::from_secs(15)))
        .unwrap();
    stream.write_all(payload).unwrap();
    let mut reply = vec![0u8; payload.len()];
    stream
        .read_exact(&mut reply)
        .expect("no echo through the tunnel");
    reply
}

struct HostEcho {
    stop: Arc<AtomicBool>,
}

impl HostEcho {
    fn start(port: u16) -> Self {
        let listener = TcpListener::bind(("127.0.0.1", port)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&stop);
        std::thread::spawn(move || {
            while !flag.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let _ = stream.set_nonblocking(false);
                        let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
                        let mut buffer = [0u8; 256];
                        if let Ok(read) = stream.read(&mut buffer) {
                            let _ = stream.write_all(&buffer[..read]);
                        }
                    }
                    Err(_) => std::thread::sleep(Duration::from_millis(20)),
                }
            }
        });
        Self { stop }
    }
}

impl Drop for HostEcho {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
    }
}

struct ContainerWorker {
    name: String,
    port: u16,
}

impl ContainerWorker {
    fn start(
        binary: &Path,
        name: &str,
        keys: &Path,
        controller: &Address,
        port: u16,
        extra: &[String],
    ) -> Self {
        Self::start_keyed(binary, name, keys, controller, port, extra, None)
    }

    fn start_keyed(
        binary: &Path,
        name: &str,
        keys: &Path,
        controller: &Address,
        port: u16,
        extra: &[String],
        key: Option<&str>,
    ) -> Self {
        remove_container(name);
        let mut args = vec![
            "run".to_owned(),
            "-d".to_owned(),
            "--name".to_owned(),
            name.to_owned(),
            "-v".to_owned(),
            format!("{}:/tc:ro", binary.parent().unwrap().display()),
            "-v".to_owned(),
            format!("{}:/home", keys.display()),
            "-e".to_owned(),
            "HOME=/home".to_owned(),
        ];
        args.extend(extra.iter().cloned());
        args.extend([
            "alpine:3".to_owned(),
            "/tc/tailcat".to_owned(),
            "forward".to_owned(),
            "--bind=127.0.0.1".to_owned(),
        ]);
        if let Some(key) = key {
            args.push(format!("--key={key}"));
        }
        if let Some(url) = extra
            .iter()
            .find_map(|arg| arg.strip_prefix("TAILCAT_DERPMAP_URL="))
        {
            args.push(format!("--derpmap-url={url}"));
        }
        args.push(controller.expose().to_owned());
        args.push(format!("{port}:{port}"));
        let output = Command::new("podman").args(&args).output().unwrap();
        assert!(
            output.status.success(),
            "podman run failed for {name}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        Self {
            name: name.to_owned(),
            port,
        }
    }

    fn echo(&self, payload: &str) -> String {
        let output = Command::new("podman")
            .args([
                "exec",
                &self.name,
                "sh",
                "-c",
                &format!("printf '{payload}' | nc -w 5 127.0.0.1 {}", self.port),
            ])
            .output()
            .unwrap();
        String::from_utf8_lossy(&output.stdout).into_owned()
    }

    fn ping(&self, controller: &Address, derpmap: Option<&str>) -> String {
        let mut args = vec![
            "exec".to_owned(),
            self.name.clone(),
            "/tc/tailcat".to_owned(),
            "ping".to_owned(),
            "--timeout=15s".to_owned(),
        ];
        if let Some(url) = derpmap {
            args.push(format!("--derpmap-url={url}"));
        }
        args.push(controller.expose().to_owned());
        let output = Command::new("podman").args(&args).output().unwrap();
        String::from_utf8_lossy(&output.stdout).into_owned()
            + &String::from_utf8_lossy(&output.stderr)
    }
}

impl Drop for ContainerWorker {
    fn drop(&mut self) {
        remove_container(&self.name);
    }
}

#[test]
#[ignore = "live helper: SENTINEL_TAILCAT_LIVE=<pinned tailcat> + podman"]
fn the_helper_carries_the_link_port_and_reports_telemetry() {
    let _serial = LIVE.lock().unwrap_or_else(|p| p.into_inner());
    let Some(helper) = gate(&["podman"]) else {
        return;
    };
    let binary = &helper.binary;
    let data_dir = tempfile::tempdir().unwrap();
    let port = free_port();
    let config = config(binary, port);

    let key = tailcat::ensure_key(&config, data_dir.path(), Role::Worker).unwrap();
    assert_eq!(
        key,
        tailcat::ensure_key(&config, data_dir.path(), Role::Worker).unwrap()
    );
    let recorded =
        std::fs::read_to_string(tailcat::nodekey_file(data_dir.path(), Role::Worker)).unwrap();
    assert_eq!(recorded.trim(), key.expose());

    let server_keys = tempfile::tempdir().unwrap();
    let server = Server::start(
        binary,
        "sentinel-live-serve",
        port,
        Some(&key),
        server_keys.path(),
    );
    let forward =
        tailcat::start_forward_every(&config, data_dir.path(), &server.address, PROBE_EVERY)
            .unwrap();
    wait_until("the tunnel", READY, || forward.telemetry().ready);

    let telemetry = forward.telemetry();
    assert!(telemetry.ready);
    assert!(
        telemetry
            .version
            .as_deref()
            .is_some_and(|v| v.contains(PINNED_VERSION)),
        "helper version missing from telemetry: {telemetry:?}"
    );
    let measured = forward.probe().expect("the tunnel does not answer a probe");
    assert_ne!(measured.path, Route::Unknown, "{measured:?}");
    let rtt = measured.rtt.expect("the pong reported no latency");
    assert!(rtt < Duration::from_secs(10), "probe rtt {rtt:?}");
    eprintln!("live probe: path {:?}, rtt {rtt:?}", measured.path);

    assert_eq!(echo(port, b"sentinel-live"), b"sentinel-live");

    forward.restart();
    wait_until("a replacement helper", READY, || {
        forward.telemetry().restarts >= 1 && forward.telemetry().ready
    });
    assert_eq!(echo(port, b"after-restart"), b"after-restart");

    forward.shutdown();
    assert!(forward.telemetry().pid.is_none());
    server.stop();
}

#[test]
#[ignore = "live helper: SENTINEL_TAILCAT_LIVE=<pinned tailcat> + podman"]
fn a_revoked_peer_loses_the_tunnel_and_a_new_endpoint_is_dialed() {
    let _serial = LIVE.lock().unwrap_or_else(|p| p.into_inner());
    let Some(helper) = gate(&["podman"]) else {
        return;
    };
    let binary = &helper.binary;
    let data_dir = tempfile::tempdir().unwrap();
    let port = free_port();
    let config = config(binary, port);
    let key = tailcat::ensure_key(&config, data_dir.path(), Role::Worker).unwrap();

    let server_keys = tempfile::tempdir().unwrap();
    let server = Server::start(
        binary,
        "sentinel-live-revoke",
        port,
        Some(&key),
        server_keys.path(),
    );
    let forward =
        tailcat::start_forward_every(&config, data_dir.path(), &server.address, PROBE_EVERY)
            .unwrap();
    wait_until("the tunnel", READY, || forward.telemetry().ready);
    assert_eq!(echo(port, b"before-revoke"), b"before-revoke");

    let before = server.address.expose().to_owned();
    let other = NodeKey::parse(&format!("nodekey:{}", "ab".repeat(32))).unwrap();
    let server = server.restart_with(binary, port, Some(&other), server_keys.path());
    assert_eq!(
        before,
        server.address.expose(),
        "the restarted helper must keep its identity"
    );
    wait_until("the revocation to show", PROBLEM, || {
        forward.telemetry().problem.is_some() && forward.probe().is_err()
    });
    forward.shutdown();

    let endpoint_keys = tempfile::tempdir().unwrap();
    let server_b = Server::start(
        binary,
        "sentinel-live-endpoint",
        port,
        Some(&key),
        endpoint_keys.path(),
    );
    assert_ne!(server.address.expose(), server_b.address.expose());
    let forward_b =
        tailcat::start_forward_every(&config, data_dir.path(), &server_b.address, PROBE_EVERY)
            .unwrap();
    wait_until("the new endpoint", READY, || forward_b.telemetry().ready);
    assert_eq!(echo(port, b"new-endpoint"), b"new-endpoint");

    forward_b.shutdown();
}

#[test]
#[ignore = "live helper: SENTINEL_TAILCAT_LIVE=<pinned tailcat>"]
fn a_dead_address_fails_fast_and_stays_supervised() {
    let _serial = LIVE.lock().unwrap_or_else(|p| p.into_inner());
    let Some(helper) = gate(&[]) else {
        return;
    };
    let data_dir = tempfile::tempdir().unwrap();
    let port = free_port();
    let config = config(&helper.binary, port);
    let _key = tailcat::ensure_key(&config, data_dir.path(), Role::Worker).unwrap();

    let dead = Address::parse(&format!("tc{}", "deadbeef".repeat(8))).unwrap();
    let forward =
        tailcat::start_forward_every(&config, data_dir.path(), &dead, PROBE_EVERY).unwrap();
    wait_until("the dead tunnel to show a problem", PROBLEM, || {
        forward.telemetry().problem.is_some()
    });
    assert!(forward.probe().is_err());
    assert_eq!(forward.telemetry().path, Route::Unknown);
    forward.shutdown();
}

#[test]
#[ignore = "live helper: SENTINEL_TAILCAT_LIVE=<pinned tailcat> + podman"]
fn the_controller_supervisor_admits_only_listed_workers() {
    let _serial = LIVE.lock().unwrap_or_else(|p| p.into_inner());
    let Some(helper) = gate(&["podman"]) else {
        return;
    };
    let binary = &helper.binary;
    let port = free_port();
    let _echo = HostEcho::start(port);

    let worker_dir = tempfile::tempdir().unwrap();
    let key = tailcat::ensure_key(&config(binary, port), worker_dir.path(), Role::Worker).unwrap();

    let controller_dir = tempfile::tempdir().unwrap();
    let server = tailcat::start_server(&config(binary, port), controller_dir.path(), &[]).unwrap();
    let address = server.wait_ready(READY).unwrap();
    let file = std::fs::read_to_string(server.address_file()).unwrap();
    assert_eq!(file.trim(), address.expose());

    let worker = ContainerWorker::start(
        binary,
        "sentinel-live-admission",
        &worker_dir.path().join("tailcat"),
        &address,
        port,
        &[],
    );
    std::thread::sleep(Duration::from_secs(8));
    assert_eq!(
        worker.echo("refused"),
        "",
        "an empty allow list must admit no peer"
    );

    server.set_allow(std::slice::from_ref(&key));
    wait_until("the admitted worker's echo", READY, || {
        worker.echo("admitted") == "admitted"
    });

    server.set_allow(&[]);
    wait_until("the revoked worker's tunnel to close", PROBLEM, || {
        worker.echo("revoked").is_empty()
    });
    server.shutdown();
}

fn mono_ns() -> u64 {
    let mut now = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `now` is a valid, writable timespec; CLOCK_MONOTONIC exists on
    // every Linux kernel this suite runs on.
    let result = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut now) };
    assert_eq!(result, 0);
    now.tv_sec as u64 * 1_000_000_000 + now.tv_nsec as u64
}

const WORKER_ROLE: &str = "SENTINEL_TAILCAT_LIVE_WORKER";
const WORKER_RULE: &str = "SENTINEL_TAILCAT_LIVE_WORKER_RULE";

struct Idle;
impl sentinel_link::session::Executor for Idle {
    fn offered(&self, _: &sentinel_link::session::Offer) -> bool {
        false
    }
    fn stop(&self, _: sentinel_core::AttemptId) {}
    fn cancel(&self, _: sentinel_core::AttemptId) {}
    fn held(&self) -> Vec<sentinel_core::AttemptId> {
        Vec::new()
    }
    fn renewed(&self, _: sentinel_core::UnixMillis) {}
    fn attached(&self, _: sentinel_link::session::Reporter) {}
    fn detached(&self) {}
    fn spec(&self, _: sentinel_core::AttemptId, _: sentinel_link::session::JobContext, _: Vec<u8>) {
    }
    fn no_spec(&self, _: sentinel_core::AttemptId) {}
    fn log_acked(&self, _: sentinel_core::AttemptId, _: u64) {}
    fn log_refused(&self, _: sentinel_core::AttemptId) {}
}

fn play_worker(dir: &Path) {
    use sentinel_link::{identity::Identity, worker};
    let read = |name: &str| std::fs::read_to_string(dir.join(name)).unwrap();
    let port: u16 = read("port").trim().parse().unwrap();
    let address = Address::parse(read("address").trim()).unwrap();
    let hex = read("fingerprint");
    let mut fingerprint = [0u8; 32];
    for (index, byte) in fingerprint.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex.trim()[index * 2..index * 2 + 2], 16).unwrap();
    }
    let config = config(&PathBuf::from(read("binary").trim()), port);
    let forward = tailcat::start_forward(&config, &dir.join("data"), &address).unwrap();
    let notes = Arc::new(Notes(std::sync::Mutex::new(
        std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(dir.join("events"))
            .unwrap(),
    )));
    let note = |event: &str| notes.note(event);
    let slow = slow_link(dir, forward.local_addr(), Arc::clone(&notes));
    let rule = std::env::var(WORKER_RULE).unwrap_or_default();
    let secret = std::fs::read_to_string(dir.join("enrollment"))
        .ok()
        .and_then(|text| sentinel_auth::secret::Secret::parse(text.trim()));
    let settings = worker::Config {
        controller: slow,
        server: sentinel_auth::secret::Digest(fingerprint),
        also_pinned: Vec::new(),
        worker: read("worker").trim().parse().unwrap(),
        name: "live-worker".into(),
        hello: sentinel_protocol::negotiate::Hello {
            protocol_min: sentinel_protocol::negotiate::ProtocolVersion(1),
            protocol_max: sentinel_protocol::negotiate::ProtocolVersion(3),
            capabilities: if rule == "immediate" {
                sentinel_protocol::negotiate::Capabilities::REQUIRED
            } else {
                sentinel_protocol::negotiate::Capabilities::REQUIRED
                    .union(sentinel_protocol::negotiate::Capabilities::HANDOFF_ANSWER)
            },
            arch: sentinel_protocol::negotiate::Arch::X86_64,
            software: "live".into(),
        },
        capacity: sentinel_link::session::Capacity {
            cpu_millis: 1_000,
            memory_bytes: 1 << 30,
        },
        profile: sentinel_protocol::negotiate::Profile {
            disk_bytes: 64 << 30,
            ..sentinel_protocol::negotiate::Profile::default()
        },
        transport: sentinel_link::session::TransportStats::default(),
        remote_cache: false,
    };
    let identity = Identity::load(&dir.join("worker.crt"), &dir.join("worker.key")).unwrap();
    let handle = worker::Handle::new();
    std::thread::scope(|scope| {
        scope.spawn(|| {
            std::thread::sleep(Duration::from_secs(5));
            match forward.probe() {
                Ok(measured) => note(&format!("path={:?}", measured.path)),
                Err(_) => note("path=unmeasured"),
            }
        });
        play_link(settings, identity, secret, &handle, &forward, &rule, &note);
    });
}

struct Notes(std::sync::Mutex<std::fs::File>);

impl Notes {
    fn note(&self, event: &str) {
        let mut file = self.0.lock().unwrap_or_else(|p| p.into_inner());
        writeln!(file, "{event} {}", mono_ns()).unwrap();
        file.flush().unwrap();
    }
}

const STALL: &str = "stall";

fn slow_link(
    dir: &Path,
    upstream: std::net::SocketAddr,
    notes: Arc<Notes>,
) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let local = listener.local_addr().unwrap();
    let stall = dir.join(STALL);
    std::thread::spawn(move || {
        for client in listener.incoming() {
            let Ok(client) = client else { continue };
            let Ok(server) = TcpStream::connect(upstream) else {
                continue;
            };
            let stalled = std::fs::remove_file(&stall).is_ok();
            let held = Arc::new(AtomicBool::new(false));
            let _ = client.set_nodelay(true);
            let _ = server.set_nodelay(true);
            let _ = server.set_read_timeout(Some(Duration::from_secs(120)));
            let (Ok(client_rx), Ok(server_tx)) = (client.try_clone(), server.try_clone()) else {
                continue;
            };
            let gate = Arc::clone(&held);
            std::thread::spawn(move || {
                pump(client_rx, server_tx, |_| !gate.load(Ordering::Acquire))
            });
            let notes = Arc::clone(&notes);
            std::thread::spawn(move || {
                pump(server, client, |_| {
                    if stalled && !held.swap(true, Ordering::AcqRel) {
                        notes.note("stalled");
                    }
                    true
                })
            });
        }
    });
    local
}

fn pump(mut from: TcpStream, mut to: TcpStream, mut pass: impl FnMut(usize) -> bool) {
    let mut buf = [0u8; 16 * 1024];
    loop {
        match from.read(&mut buf) {
            Ok(0) => {
                let _ = to.shutdown(std::net::Shutdown::Write);
                return;
            }
            Ok(n) => {
                if pass(n) && to.write_all(&buf[..n]).is_err() {
                    let _ = from.shutdown(std::net::Shutdown::Both);
                    return;
                }
            }
            Err(_) => {
                let _ = to.shutdown(std::net::Shutdown::Both);
                let _ = from.shutdown(std::net::Shutdown::Both);
                return;
            }
        }
    }
}

fn play_link(
    settings: sentinel_link::worker::Config,
    identity: sentinel_link::identity::Identity,
    secret: Option<sentinel_auth::secret::Secret>,
    handle: &sentinel_link::worker::Handle,
    forward: &tailcat::Forward,
    rule: &str,
    note: &(dyn Fn(&str) + Sync),
) {
    use sentinel_link::worker;
    let _ = worker::run(
        settings,
        identity,
        secret,
        &Idle,
        handle,
        &|event| match event {
            worker::Event::Connected { .. } => {
                note("connected");
                note(&format!("helper-restarts={}", forward.telemetry().restarts));
            }
            worker::Event::Disconnected(error) => {
                let clean = matches!(error, sentinel_link::Error::Closed);
                note("lost");
                note(if clean { "closed" } else { "cut" });
                if clean && rule != "immediate" {
                    forward.session_closed();
                    note("replaced");
                } else if forward.session_lost() {
                    note("replaced");
                }
            }
            worker::Event::Backoff(_) => {}
        },
    );
}

struct NetnsWorker {
    child: Child,
    events: PathBuf,
}

impl NetnsWorker {
    fn start(netns_pid: &str, dir: &Path, rule: &str) -> Self {
        let events = dir.join("events");
        let _ = std::fs::remove_file(&events);
        let mut command = Command::new("nsenter");
        command.env(WORKER_RULE, rule);
        let child = command
            .arg(format!("--net=/proc/{netns_pid}/ns/net"))
            .arg(std::env::current_exe().unwrap())
            .args(["--exact", HANDOFF_TEST, "--ignored", "--nocapture"])
            .env(WORKER_ROLE, dir)
            .stdout(Stdio::null())
            .spawn()
            .unwrap();
        Self { child, events }
    }

    fn events(&self) -> Vec<(String, u64)> {
        std::fs::read_to_string(&self.events)
            .unwrap_or_default()
            .lines()
            .filter_map(|line| {
                let (event, at) = line.split_once(' ')?;
                Some((event.to_owned(), at.parse().ok()?))
            })
            .collect()
    }

    fn first_after(&self, event: &str, since: u64, within: Duration) -> Option<u64> {
        let deadline = Instant::now() + within;
        loop {
            if let Some((_, at)) = self
                .events()
                .into_iter()
                .find(|(name, at)| name == event && *at >= since)
            {
                return Some(at);
            }
            if Instant::now() >= deadline {
                return None;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}

impl Drop for NetnsWorker {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

const HANDOFF_TEST: &str = "an_allow_list_change_hands_tunnelled_sessions_to_the_new_helper";

#[test]
#[ignore = "live helper: SENTINEL_TAILCAT_LIVE=<pinned tailcat> + podman + nsenter + iptables + nft"]
fn an_allow_list_change_hands_tunnelled_sessions_to_the_new_helper() {
    if let Some(dir) = std::env::var_os(WORKER_ROLE) {
        play_worker(Path::new(&dir));
        return;
    }
    let _serial = LIVE.lock().unwrap_or_else(|p| p.into_inner());
    let Some(helper) = gate(&["podman", "nsenter", "iptables", "nft"]) else {
        return;
    };
    use sentinel_link::{controller::Controller, identity::Identity};
    use sentinel_store::{Durability, Store, auth::Authority, tenancy, workers};

    let state = tempfile::tempdir().unwrap();
    let store = std::sync::Arc::new(
        Store::open(state.path().join("metadata.sqlite"), Durability::Normal).unwrap(),
    );
    let pool = sentinel_core::PoolId::new();
    let secret = store
        .writer()
        .write(move |tx| {
            let now = sentinel_core::UnixMillis::now();
            tenancy::create_pool(
                tx,
                Authority::HostLocal,
                pool,
                "live",
                tenancy::PoolKind::Shared,
                now,
            )?;
            workers::issue_enrollment(tx, Authority::HostLocal, pool, 600_000, now)
        })
        .unwrap()
        .secret;
    let port = free_port();
    let controller = Controller::start(
        std::sync::Arc::clone(&store),
        std::sync::Arc::new(
            sentinel_store::logs::LogStore::open(state.path().join("logs")).unwrap(),
        ),
        std::sync::Arc::new(
            sentinel_store::objects::Objects::open(state.path().join("objects")).unwrap(),
        ),
        Identity::generate("controller").unwrap(),
        std::net::SocketAddr::from(([127, 0, 0, 1], port)),
    )
    .unwrap();
    let link = controller.handle();

    let worker_dir = tempfile::tempdir().unwrap();
    let dir = worker_dir.path();
    let write = |name: &str, text: &str| std::fs::write(dir.join(name), text).unwrap();
    std::fs::create_dir(dir.join("data")).unwrap();
    let key = tailcat::ensure_key(
        &config(&helper.binary, port),
        &dir.join("data"),
        Role::Worker,
    )
    .unwrap();
    Identity::generate("worker")
        .unwrap()
        .save(&dir.join("worker.crt"), &dir.join("worker.key"))
        .unwrap();
    let mut text = String::new();
    secret.expose(&mut text);
    write("enrollment", &text);
    write("worker", &sentinel_core::WorkerId::new().to_string());
    write("port", &port.to_string());
    write("binary", &helper.binary.display().to_string());
    write(
        "fingerprint",
        &controller
            .fingerprint()
            .0
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>(),
    );
    let controller_dir = tempfile::tempdir().unwrap();
    let server = tailcat::start_server(
        &config(&helper.binary, port),
        controller_dir.path(),
        std::slice::from_ref(&key),
    )
    .unwrap();
    write("address", server.wait_ready(READY).unwrap().expose());

    let parked = ParkedNetns::start("sentinel-live-netns");

    let plan = plan();
    let mut change = 0u16;
    let mut next_allow = || {
        change += 1;
        let other =
            NodeKey::parse(&format!("nodekey:{}", format!("{change:04x}").repeat(16))).unwrap();
        (change, [key.clone(), other])
    };
    let mut measure = |rule: &str, kind: Kind, relay: bool, count: usize| -> Vec<Round> {
        let worker = NetnsWorker::start(&parked.pid, dir, rule);
        assert!(
            worker.first_after("connected", 0, READY * 2).is_some(),
            "the worker never connected over the tunnel"
        );
        let _ = std::fs::remove_file(dir.join("enrollment"));
        let label = format!(
            "{} path, {kind:?}, worker rule {}",
            if relay { "relay" } else { "direct" },
            if rule.is_empty() { "shipped" } else { rule }
        );
        let mut path = None;
        wait_until("the worker's path probe", Duration::from_secs(40), || {
            path = worker
                .events()
                .into_iter()
                .find_map(|(event, _)| event.strip_prefix("path=").map(str::to_owned));
            path.is_some()
        });
        eprintln!("{label}: probe path {path:?}");
        if relay {
            assert_eq!(path.as_deref(), Some("Relay"), "{label}: not relayed");
        }
        let mut rounds = Vec::new();
        for index in 0..count {
            std::thread::sleep(tailcat::SESSION_SETTLE + Duration::from_secs(1));
            let mut first = None;
            if kind == Kind::Stalled {
                std::fs::write(dir.join(STALL), "").unwrap();
                let at = mono_ns();
                let handed = link
                    .hand_off(&server, &next_allow().1)
                    .expect("the list changed");
                let stalled = worker
                    .first_after("stalled", at, Duration::from_secs(60))
                    .expect("the redial never reached the controller's handshake");
                let lost = worker
                    .first_after("lost", at, Duration::ZERO)
                    .filter(|lost| *lost <= stalled)
                    .map(|lost| Duration::from_nanos(lost - at));
                first = Some((handed, lost, Duration::from_nanos(stalled - at)));
            }
            let (change, allow) = next_allow();
            let loss = (kind == Kind::Lossy).then(|| NetnsLoss::engage(&parked.pid));
            let changed = mono_ns();
            let handed = if kind == Kind::Cut {
                server.set_allow(&allow);
                None
            } else {
                Some(link.hand_off(&server, &allow).expect("the list changed"))
            };
            if let Some(loss) = loss {
                loss.lift();
            }
            let back = worker
                .first_after("connected", changed, Duration::from_secs(300))
                .expect("the worker never came back after an allow-list change");
            std::thread::sleep(Duration::from_millis(200));
            let since = |at: u64| Duration::from_nanos(at - changed);
            let trail: Vec<String> = worker
                .events()
                .into_iter()
                .filter(|(_, at)| *at >= changed && *at <= back + 100_000_000)
                .map(|(event, at)| format!("{event}@{:.3}s", since(at).as_secs_f64()))
                .collect();
            let lost = worker
                .first_after("lost", changed, Duration::ZERO)
                .filter(|at| *at <= back)
                .map(since);
            eprintln!(
                "allow-list change {change} ({label}, {}/{count}): welcomed again after {:?}; lost after {lost:?}; hand-off {handed:?}; before it {first:?}; worker events {trail:?}",
                index + 1,
                since(back)
            );
            rounds.push(Round {
                outage: since(back),
                lost,
                handed,
                first,
                trail,
            });
        }
        rounds
    };
    let rule = std::env::var(WORKER_RULE).unwrap_or_default();
    let mut results = Vec::new();
    for relay in [false, true] {
        let _block = relay.then(|| NetnsUdpBlock::engage(&parked.pid));
        for (kind, rounds) in &plan {
            let rule = if *kind == Kind::Older {
                "immediate"
            } else {
                &rule
            };
            results.push((relay, *kind, measure(rule, *kind, relay, *rounds)));
        }
    }

    let worker = NetnsWorker::start(&parked.pid, dir, "");
    assert!(
        worker.first_after("connected", 0, READY * 2).is_some(),
        "the worker never connected over the tunnel"
    );
    std::thread::sleep(tailcat::SESSION_SETTLE + Duration::from_secs(1));
    let other = NodeKey::parse(&format!("nodekey:{}", "ee".repeat(32))).unwrap();
    let removed = mono_ns();
    let handed = link
        .hand_off(&server, std::slice::from_ref(&other))
        .expect("the list changed");
    let lost = worker.first_after("lost", removed, Duration::from_secs(2));
    eprintln!(
        "removal: hand-off {handed:?}; lost after {:?}",
        lost.map(|at| Duration::from_nanos(at - removed))
    );
    assert!(
        lost.is_some(),
        "the removed worker's session was not closed: {handed:?}"
    );
    assert_eq!(
        worker.first_after("connected", removed, Duration::from_secs(45)),
        None,
        "the removed worker got back in: {:?}",
        worker.events()
    );
    drop(worker);

    drop(parked);
    server.shutdown();
    drop(controller);
    for (relay, kind, rounds) in &results {
        let mut outages: Vec<Duration> = rounds.iter().map(|round| round.outage).collect();
        outages.sort_unstable();
        let late = rounds
            .iter()
            .filter(|round| !round.lost.is_some_and(|lost| lost < HANDOFF_NOTICED))
            .count();
        let unconfirmed = rounds
            .iter()
            .filter_map(|round| round.handed)
            .filter(|handed| handed.ended < handed.closed + handed.arrivals)
            .count();
        let waited: Vec<Duration> = rounds
            .iter()
            .filter_map(|round| round.handed.map(|handed| handed.waited))
            .collect();
        eprintln!(
            "summary: {} path, {kind:?}: {} changes; outage min {:?}, max {:?}, sorted {outages:?}; close not seen within {HANDOFF_NOTICED:?}: {late}; closes the controller did not see answered: {unconfirmed}; hand-off waits min {:?}, max {:?}",
            if *relay { "relay" } else { "direct" },
            rounds.len(),
            outages.first(),
            outages.last(),
            waited.iter().min(),
            waited.iter().max()
        );
    }

    for (relay, kind, rounds) in &results {
        let label = if *relay { "relay" } else { "direct" };
        for round in rounds.iter().filter(|_| *kind != Kind::Cut) {
            let handed = round.handed.expect("handed off");
            if *kind == Kind::Stalled {
                assert!(
                    handed.arrivals == 1 && handed.closed == 0,
                    "{label}: the connection in its handshake was not closed: {round:?}"
                );
            } else {
                assert!(
                    handed.closed == 1,
                    "{label}: the tunnelled session was not closed: {round:?}"
                );
            }
            if *kind == Kind::Older {
                assert!(
                    handed.waited < HANDOFF_BOUND + Duration::from_millis(250),
                    "{label}: the hand-off waited {:?} for a worker that does not answer: {round:?}",
                    handed.waited
                );
            } else {
                assert_eq!(
                    handed.ended,
                    handed.closed + handed.arrivals,
                    "{label} {kind:?}: a close went unanswered: {round:?}"
                );
            }
            let (noticed, outage) = if *kind == Kind::Lossy {
                (HANDOFF_RESEND_BOUND, LOSSY_OUTAGE)
            } else {
                (HANDOFF_NOTICED, HANDOFF_OUTAGE)
            };
            assert!(
                round.lost.is_some_and(|lost| lost < noticed),
                "{label} {kind:?}: the worker did not see the close in time: {round:?}"
            );
            assert!(
                round.outage < outage,
                "{label} {kind:?}: a handed-off change interrupted the worker for {:?} (bound {outage:?}): {round:?}",
                round.outage
            );
        }
    }
}

const HANDOFF_NOTICED: Duration = Duration::from_millis(500);
const HANDOFF_OUTAGE: Duration = Duration::from_millis(5_500);
const LOSSY_OUTAGE: Duration = Duration::from_secs(9);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Cut,
    Settled,
    Stalled,
    Lossy,
    Older,
}

const SETTLED_CHANGES: usize = 64;
const STALLED_CHANGES: usize = 10;
const CUT_CHANGES: usize = 4;
const LOSSY_CHANGES: usize = 6;
const OLDER_CHANGES: usize = 10;

fn plan() -> [(Kind, usize); 5] {
    let count = |name: &str, default: usize| {
        std::env::var(name)
            .ok()
            .map_or(default, |text| text.trim().parse().unwrap())
    };
    [
        (Kind::Cut, count("SENTINEL_TAILCAT_LIVE_CUTS", CUT_CHANGES)),
        (
            Kind::Settled,
            count("SENTINEL_TAILCAT_LIVE_CHANGES", SETTLED_CHANGES),
        ),
        (
            Kind::Stalled,
            count("SENTINEL_TAILCAT_LIVE_STALLS", STALLED_CHANGES),
        ),
        (
            Kind::Lossy,
            count("SENTINEL_TAILCAT_LIVE_LOSSY", LOSSY_CHANGES),
        ),
        (
            Kind::Older,
            count("SENTINEL_TAILCAT_LIVE_OLDER", OLDER_CHANGES),
        ),
    ]
}

#[derive(Debug)]
// `trail` and `first` are read only through `Debug`, in failure messages.
#[allow(dead_code)]
struct Round {
    outage: Duration,
    lost: Option<Duration>,
    handed: Option<sentinel_link::controller::Handoff>,
    first: Option<(
        sentinel_link::controller::Handoff,
        Option<Duration>,
        Duration,
    )>,
    trail: Vec<String>,
}

struct ParkedNetns {
    name: &'static str,
    pid: String,
}

impl ParkedNetns {
    fn start(name: &'static str) -> Self {
        remove_container(name);
        let started = Command::new("podman")
            .args(["run", "-d", "--name", name, "alpine:3", "sleep", "3600"])
            .stdout(Stdio::null())
            .status()
            .unwrap();
        assert!(started.success());
        let pid = String::from_utf8(
            Command::new("podman")
                .args(["inspect", "--format", "{{.State.Pid}}", name])
                .output()
                .unwrap()
                .stdout,
        )
        .unwrap()
        .trim()
        .to_owned();
        Self { name, pid }
    }
}

impl Drop for ParkedNetns {
    fn drop(&mut self) {
        remove_container(self.name);
    }
}

struct NetnsUdpBlock {
    pid: String,
}

impl NetnsUdpBlock {
    const RULE: [&str; 8] = ["OUTPUT", "-p", "udp", "!", "--dport", "53", "-j", "DROP"];

    fn engage(pid: &str) -> Self {
        let engaged = Command::new("nsenter")
            .arg(format!("--net=/proc/{pid}/ns/net"))
            .args(["iptables", "-I"])
            .args(Self::RULE)
            .status()
            .is_ok_and(|status| status.success());
        assert!(engaged, "iptables failed inside the worker's namespace");
        Self {
            pid: pid.to_owned(),
        }
    }
}

impl Drop for NetnsUdpBlock {
    fn drop(&mut self) {
        let _ = Command::new("nsenter")
            .arg(format!("--net=/proc/{}/ns/net", self.pid))
            .args(["iptables", "-D"])
            .args(Self::RULE)
            .status();
    }
}

const LOSS: Duration = Duration::from_millis(800);

struct NetnsLoss {
    pid: String,
    until: Instant,
    removed: bool,
}

impl NetnsLoss {
    const TABLE: &str = "sentinel_live_loss";

    fn nft(pid: &str, script: &str) -> bool {
        let Ok(mut child) = Command::new("nsenter")
            .arg(format!("--net=/proc/{pid}/ns/net"))
            .args(["nft", "-f", "-"])
            .stdin(Stdio::piped())
            .spawn()
        else {
            return false;
        };
        let written = child
            .stdin
            .take()
            .is_some_and(|mut stdin| stdin.write_all(script.as_bytes()).is_ok());
        child.wait().is_ok_and(|status| status.success()) && written
    }

    fn engage(pid: &str) -> Self {
        let table = Self::TABLE;
        let ms = LOSS.as_millis();
        let script = format!(
            "add table inet {table}\n\
             delete table inet {table}\n\
             table inet {table} {{\n\
               set until {{ type iface_type; flags timeout; }}\n\
               chain input {{ type filter hook input priority raw; policy accept; meta iiftype @until drop; }}\n\
             }}\n\
             add element inet {table} until {{ ether timeout {ms}ms }}\n"
        );
        let engaged_at = Instant::now();
        assert!(
            Self::nft(pid, &script),
            "nft failed inside the worker's namespace"
        );
        Self {
            pid: pid.to_owned(),
            until: engaged_at + LOSS,
            removed: false,
        }
    }

    fn remove(&self) -> bool {
        Self::nft(&self.pid, &format!("delete table inet {}\n", Self::TABLE))
    }

    fn lift(mut self) {
        std::thread::sleep(self.until.saturating_duration_since(Instant::now()));
        self.removed = self.remove();
        assert!(self.removed, "the loss table could not be removed");
    }
}

impl Drop for NetnsLoss {
    fn drop(&mut self) {
        if !self.removed {
            let _ = self.remove();
        }
    }
}

#[test]
#[ignore = "live helper: SENTINEL_TAILCAT_LIVE=<pinned tailcat> + podman"]
fn node_keys_rotate_with_an_overlap_window_and_revocation_still_applies() {
    let _serial = LIVE.lock().unwrap_or_else(|p| p.into_inner());
    let Some(helper) = gate(&["podman"]) else {
        return;
    };
    let binary = &helper.binary;
    let port = free_port();
    let _echo = HostEcho::start(port);
    let config = config(binary, port);
    let (old_name, new_name, moved_name) = (
        "sentinel-live-rotate-old",
        "sentinel-live-rotate-new",
        "sentinel-live-rotate-moved",
    );

    let worker_dir = tempfile::tempdir().unwrap();
    let keys = worker_dir.path().join("tailcat");
    let old = tailcat::ensure_key(&config, worker_dir.path(), Role::Worker).unwrap();
    let controller_dir = tempfile::tempdir().unwrap();
    let server =
        tailcat::start_server(&config, controller_dir.path(), std::slice::from_ref(&old)).unwrap();
    let address = server.wait_ready(READY).unwrap();
    let before = ContainerWorker::start(binary, old_name, &keys, &address, port, &[]);
    wait_until("the old key's echo", READY, || {
        before.echo("old-key") == "old-key"
    });

    let new = tailcat::stage_rotation(&config, worker_dir.path(), Role::Worker).unwrap();
    assert_ne!(new, old);
    assert!(
        tailcat::commit_rotation(&config, worker_dir.path(), Role::Worker, Some(&address)).is_err(),
        "a key the controller does not list must not commit"
    );
    assert_eq!(
        tailcat::staged_rotation(worker_dir.path(), Role::Worker).unwrap(),
        Some(new.clone())
    );
    let old_keys = tempfile::tempdir().unwrap();
    let saved = Path::new(".config/tailcat/keys/client-default.private.json");
    std::fs::create_dir_all(old_keys.path().join(saved.parent().unwrap())).unwrap();
    std::fs::copy(keys.join(saved), old_keys.path().join(saved)).unwrap();

    server.set_allow(&[old.clone(), new.clone()]);
    let before = ContainerWorker::start(binary, old_name, &keys, &address, port, &[]);
    wait_until("the old key with both listed", READY, || {
        before.echo("listed") == "listed"
    });
    let deadline = Instant::now() + READY;
    let committed = loop {
        match tailcat::commit_rotation(&config, worker_dir.path(), Role::Worker, Some(&address)) {
            Ok(committed) => break committed,
            Err(error) => {
                assert!(
                    Instant::now() < deadline,
                    "the listed key never committed: {error}"
                );
                std::thread::sleep(Duration::from_secs(1));
            }
        }
    };
    assert_eq!(committed.key, new);
    assert!(committed.previous_deleted);
    let after = ContainerWorker::start_keyed(
        binary,
        new_name,
        &keys,
        &address,
        port,
        &[],
        Some("client-rotated"),
    );
    wait_until("the new key's echo", READY, || {
        after.echo("new-key") == "new-key"
    });
    assert_eq!(before.echo("overlap"), "overlap");

    server.set_allow(std::slice::from_ref(&new));
    let after = ContainerWorker::start_keyed(
        binary,
        new_name,
        &keys,
        &address,
        port,
        &[],
        Some("client-rotated"),
    );
    wait_until("the kept key after the retire", READY, || {
        after.echo("kept") == "kept"
    });
    let before = ContainerWorker::start(binary, old_name, old_keys.path(), &address, port, &[]);
    std::thread::sleep(Duration::from_secs(8));
    assert_eq!(before.echo("retired"), "", "the retired key was admitted");
    drop(before);

    let staged = tailcat::stage_rotation(&config, controller_dir.path(), Role::Controller).unwrap();
    server.reload_keys().unwrap();
    wait_until("the staged address", READY, || {
        server.staged_address().is_some()
    });
    let next = server.staged_address().unwrap();
    assert_ne!(next.expose(), address.expose());
    assert_eq!(
        std::fs::read_to_string(tailcat::staged_address_file(controller_dir.path()))
            .unwrap()
            .trim(),
        next.expose()
    );
    let moved = ContainerWorker::start_keyed(
        binary,
        moved_name,
        &keys,
        &next,
        port,
        &[],
        Some("client-rotated"),
    );
    wait_until("the staged address's echo", READY, || {
        moved.echo("next") == "next"
    });
    assert_eq!(
        after.echo("both"),
        "both",
        "the active address during the overlap"
    );

    let committed =
        tailcat::commit_rotation(&config, controller_dir.path(), Role::Controller, None).unwrap();
    assert_eq!(committed.key, staged);
    server.reload_keys().unwrap();
    assert!(server.staged_telemetry().is_none());
    assert_eq!(server.address().unwrap().expose(), next.expose());
    assert_eq!(
        std::fs::read_to_string(server.address_file())
            .unwrap()
            .trim(),
        next.expose()
    );
    assert_eq!(
        moved.echo("committed"),
        "committed",
        "the switch broke the new address"
    );
    wait_until("the old address to stop answering", PROBLEM, || {
        after.echo("old-address").is_empty()
    });
    eprintln!("live rotation: both identities rotated with an overlap window");

    server.set_allow(&[]);
    let moved = ContainerWorker::start_keyed(
        binary,
        moved_name,
        &keys,
        &next,
        port,
        &[],
        Some("client-rotated"),
    );
    std::thread::sleep(Duration::from_secs(8));
    assert_eq!(moved.echo("revoked"), "", "a revoked worker was admitted");
    server.shutdown();
}

struct UdpBlock;

impl UdpBlock {
    fn engage() -> Self {
        let engaged = Command::new("iptables")
            .args([
                "-I",
                "OUTPUT",
                "-p",
                "udp",
                "-d",
                "10.88.0.0/16",
                "-j",
                "DROP",
            ])
            .status()
            .is_ok_and(|status| status.success());
        assert!(engaged, "SENTINEL_TAILCAT_LIVE is set but iptables failed");
        Self
    }
}

impl Drop for UdpBlock {
    fn drop(&mut self) {
        let _ = Command::new("iptables")
            .args([
                "-D",
                "OUTPUT",
                "-p",
                "udp",
                "-d",
                "10.88.0.0/16",
                "-j",
                "DROP",
            ])
            .status();
    }
}

#[test]
#[ignore = "live helper: SENTINEL_TAILCAT_LIVE=<pinned tailcat> + podman + iptables"]
fn relay_only_paths_report_derp() {
    let _serial = LIVE.lock().unwrap_or_else(|p| p.into_inner());
    let Some(helper) = gate(&["podman", "iptables"]) else {
        return;
    };
    let binary = &helper.binary;
    let data_dir = tempfile::tempdir().unwrap();
    let port = free_port();
    let config = config(binary, port);
    let key = tailcat::ensure_key(&config, data_dir.path(), Role::Worker).unwrap();
    let server_keys = tempfile::tempdir().unwrap();
    let server = Server::start(
        binary,
        "sentinel-live-relay",
        port,
        Some(&key),
        server_keys.path(),
    );

    let _block = UdpBlock::engage();

    let forward =
        tailcat::start_forward_every(&config, data_dir.path(), &server.address, PROBE_EVERY)
            .unwrap();
    wait_until("the relayed tunnel", READY, || forward.telemetry().ready);
    let measured = forward.probe().expect("the relayed tunnel does not answer");
    assert_eq!(measured.path, Route::Relay, "{measured:?}");
    assert_eq!(echo(port, b"relay-only"), b"relay-only");
    forward.shutdown();
}

fn issue_certs(dir: &Path, ip: &str, ca_out: &Path) -> (PathBuf, PathBuf) {
    let run = |args: &[&str]| {
        let status = Command::new("openssl")
            .args(args)
            .current_dir(dir)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert!(status.success(), "openssl {args:?} failed");
    };
    let ec = [
        "-newkey",
        "ec",
        "-pkeyopt",
        "ec_paramgen_curve:prime256v1",
        "-nodes",
    ];
    let mut ca = vec!["req", "-x509"];
    ca.extend(ec);
    ca.extend([
        "-days",
        "1",
        "-subj",
        "/CN=sentinel-live-ca",
        "-keyout",
        "ca.key",
        "-out",
        "ca.pem",
    ]);
    run(&ca);
    let certs = dir.join("certs");
    std::fs::create_dir_all(&certs).unwrap();
    let (crt, key) = (
        certs.join(format!("{ip}.crt")),
        certs.join(format!("{ip}.key")),
    );
    let mut leaf = vec!["req"];
    leaf.extend(ec);
    let subject = format!("/CN={ip}");
    let key_text = key.display().to_string();
    leaf.extend(["-subj", &subject, "-keyout", &key_text, "-out", "leaf.csr"]);
    run(&leaf);
    std::fs::write(dir.join("ext.cnf"), format!("subjectAltName=IP:{ip}\n")).unwrap();
    let crt_text = crt.display().to_string();
    run(&[
        "x509",
        "-req",
        "-in",
        "leaf.csr",
        "-CA",
        "ca.pem",
        "-CAkey",
        "ca.key",
        "-CAcreateserial",
        "-days",
        "1",
        "-extfile",
        "ext.cnf",
        "-out",
        &crt_text,
    ]);
    let ca = std::fs::read(dir.join("ca.pem")).unwrap();
    std::fs::OpenOptions::new()
        .append(true)
        .open(ca_out)
        .and_then(|mut bundle| bundle.write_all(&ca))
        .expect("SENTINEL_TAILCAT_DERP_CA must be an existing, writable bundle");
    (crt, key)
}

struct Background(Child);

impl Drop for Background {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
#[ignore = "live helper: SENTINEL_TAILCAT_LIVE + SENTINEL_TAILCAT_DERPER + SENTINEL_TAILCAT_DERP_CA=SSL_CERT_FILE"]
fn a_self_hosted_derp_relay_carries_the_link() {
    let _serial = LIVE.lock().unwrap_or_else(|p| p.into_inner());
    let Some(helper) = gate(&["podman", "openssl", "python3", "iptables"]) else {
        return;
    };
    let derper = PathBuf::from(
        std::env::var_os("SENTINEL_TAILCAT_DERPER")
            .expect("SENTINEL_TAILCAT_LIVE is set but SENTINEL_TAILCAT_DERPER is not"),
    );
    let ca_path = PathBuf::from(
        std::env::var_os("SENTINEL_TAILCAT_DERP_CA")
            .expect("SENTINEL_TAILCAT_LIVE is set but SENTINEL_TAILCAT_DERP_CA is not"),
    );
    assert_eq!(
        std::env::var_os("SSL_CERT_FILE")
            .map(PathBuf::from)
            .as_ref(),
        Some(&ca_path),
        "SSL_CERT_FILE must name SENTINEL_TAILCAT_DERP_CA: it is how the helper trusts the relay"
    );
    let binary = &helper.binary;
    let port = free_port();
    let _echo = HostEcho::start(port);

    assert!(derper.is_file(), "SENTINEL_TAILCAT_DERPER is not a file");
    let worker_dir = tempfile::tempdir().unwrap();
    let placeholder = "sentinel-live-derp-bridge";
    remove_container(placeholder);
    assert!(
        Command::new("podman")
            .args([
                "run",
                "-d",
                "--name",
                placeholder,
                "alpine:3",
                "sleep",
                "600"
            ])
            .stdout(Stdio::null())
            .status()
            .unwrap()
            .success()
    );
    let gateway = String::from_utf8(
        Command::new("podman")
            .args([
                "network",
                "inspect",
                "podman",
                "--format",
                "{{range .Subnets}}{{.Gateway}}{{end}}",
            ])
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap()
    .trim()
    .to_owned();
    assert!(gateway.parse::<std::net::Ipv4Addr>().is_ok(), "{gateway}");

    let relay_dir = tempfile::tempdir().unwrap();
    let (crt, _key) = issue_certs(relay_dir.path(), &gateway, &ca_path);
    let (derp_port, map_port) = (free_port(), free_port());
    let map = format!(
        "{{\"Regions\":{{\"900\":{{\"RegionID\":900,\"RegionCode\":\"local\",\"RegionName\":\"Local\",\"Nodes\":[{{\"Name\":\"900a\",\"RegionID\":900,\"HostName\":\"{gateway}\",\"IPv4\":\"{gateway}\",\"DERPPort\":{derp_port},\"STUNPort\":-1}}]}}}}}}"
    );
    std::fs::write(relay_dir.path().join("map.json"), map).unwrap();
    let _derper = Background(
        Command::new(&derper)
            .args([
                &format!("--hostname={gateway}"),
                "--certmode=manual",
                &format!("--certdir={}", crt.parent().unwrap().display()),
                &format!("-a={gateway}:{derp_port}"),
                "--stun=false",
                "--http-port=-1",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let server_py = format!(
        "import http.server, ssl, os\nos.chdir({dir:?})\nsrv = http.server.HTTPServer(({gateway:?}, {map_port}), http.server.SimpleHTTPRequestHandler)\nctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)\nctx.load_cert_chain({crt:?}, {key:?})\nsrv.socket = ctx.wrap_socket(srv.socket, server_side=True)\nsrv.serve_forever()\n",
        dir = relay_dir.path().display().to_string(),
        crt = crt.display().to_string(),
        key = crt.with_extension("key").display().to_string(),
    );
    let _map_server = Background(
        Command::new("python3")
            .args(["-c", &server_py])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let url = format!("https://{gateway}:{map_port}/map.json");
    std::thread::sleep(Duration::from_secs(2));

    let mut relayed = config(binary, port);
    relayed.derpmap_url = Some(url.clone());
    let key = tailcat::ensure_key(&relayed, worker_dir.path(), Role::Worker).unwrap();
    let controller_dir = tempfile::tempdir().unwrap();
    let server =
        tailcat::start_server(&relayed, controller_dir.path(), std::slice::from_ref(&key)).unwrap();
    let address = server.wait_ready(READY).unwrap();

    let _block = UdpBlock::engage();
    let worker = ContainerWorker::start(
        binary,
        "sentinel-live-derp",
        &worker_dir.path().join("tailcat"),
        &address,
        port,
        &[
            "-v".to_owned(),
            format!("{}:/ca.pem:ro", ca_path.display()),
            "-e".to_owned(),
            "SSL_CERT_FILE=/ca.pem".to_owned(),
            "-e".to_owned(),
            format!("TAILCAT_DERPMAP_URL={url}"),
        ],
    );
    wait_until("an echo through the self-hosted relay", READY, || {
        worker.echo("self-hosted") == "self-hosted"
    });
    let ping = worker.ping(&address, Some(&url));
    assert!(ping.contains("via DERP(local)"), "{ping}");
    eprintln!(
        "self-hosted relay ping: {}",
        ping.lines().last().unwrap_or("")
    );
    server.shutdown();
    drop(worker);
    remove_container(placeholder);
}
