//! Q07 live evidence: the pinned helper over a real NAT boundary.
//!
//! These tests need the real `tailcat` binary, Podman and the tools named
//! below; they are `#[ignore]`d by default and run on a Linux host with:
//!
//! ```sh
//! SENTINEL_TAILCAT_LIVE=/root/tailcat/tailcat \
//!   cargo test -p sentinel-link --all-features --test tailcat_live -- --ignored --nocapture --test-threads=1
//! ```
//!
//! With the gate unset every test skips; with it set, a missing prerequisite
//! fails the test rather than passing it vacuously. The Podman in use here is
//! **rootful** (the tests run as root, the relay test drops UDP with
//! `iptables` on the default `10.88.0.0/16` bridge and the self-hosted relay
//! binds that bridge's gateway): the helper crosses a real network-namespace
//! and NAT boundary, but rootless Podman / slirp4netns is not what is proven.
//! The allow-list hand-off test also needs `nsenter` (util-linux): it runs a
//! worker link in a parked container's network namespace, and for its
//! relay-only half drops UDP other than DNS there with `iptables`; for
//! 800 ms around some changes it drops everything arriving there with `nft`
//! (nftables), through a set element the kernel expires on time.
//!
//! One side of each tunnel runs in a container, so the link port on the host
//! and in the container are different sockets: a byte that comes back went
//! through the tunnel. The controller side is Sentinel's own supervisor
//! ([`tailcat::start_server`], `set_allow`, the address file) wherever the
//! test is about admission; the older tests keep a raw `tailcat serve` in the
//! container to prove the worker's forward across the NAT boundary.
//!
//! The self-hosted relay test additionally needs `derper` (Tailscale's DERP
//! server, e.g. `go install tailscale.com/cmd/derper@v1.86.2`), `openssl` and
//! `python3`, and TLS trust for its throwaway CA — the helper trusts it only
//! through `SSL_CERT_FILE`, one of the two trust overrides Sentinel passes on.
//! The runner provides a copy of the system roots; the test appends its CA:
//!
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

/// Longest a healthy tunnel may take to come up through a relay.
const READY: Duration = Duration::from_secs(60);
/// How often the worker re-proves its tunnel in these tests.
const PROBE_EVERY: Duration = Duration::from_secs(3);
/// Longest a revoked or dead tunnel may take to show a problem.
const PROBLEM: Duration = Duration::from_secs(45);

/// The relay-only test drops outbound UDP host-wide; serializing the file
/// keeps that block from overlapping another test's tunnel.
static LIVE: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// The pinned helper, copied into a directory this user owns (Sentinel
/// refuses a helper another user can rewrite), or `None` when the live gate
/// is not set. A binary that is not the pinned build fails the test.
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

/// The gate, plus every named tool: missing any of them with the gate set is
/// a failure, never a pass.
fn gate(tools: &[&str]) -> Option<Helper> {
    let Some(helper) = live_binary() else {
        eprintln!("SENTINEL_TAILCAT_LIVE unset; skipping live tailcat test");
        return None;
    };
    for tool in tools {
        // Only whether it runs at all: exit codes of `--version` vary.
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

/// A free loopback port, raced the way tests always race it.
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

/// A container serving `port` with an echo behind it, optionally restricted
/// to one worker node key. Dropping it removes the container; the key
/// directory is the caller's, so a restart with the same one keeps the same
/// helper identity (and therefore the same address).
struct Server {
    name: String,
    address: Address,
}

impl Server {
    /// `allow` is the worker node key the helper accepts; `None` serves any
    /// peer (upstream's default when `--allow` is absent — which is why
    /// Sentinel's own supervisor never omits it), `Some(key)` passes
    /// `--allow=<key>`.
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

    /// The `listening on tc…` line from the container's helper output.
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

    /// Restart the same container with a different allow list. The key
    /// directory is reused, so the helper keeps its identity and address:
    /// the allow list is then the only variable a refusal can come from.
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

/// A byte string through the worker's loopback forward and back. Nothing on
/// the host listens on this port but the forward, so a reply is tunnel proof.
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

/// The controller-side link port on the host: an echo that answers once per
/// connection and closes, so a container client sees its bytes come back
/// only through the tunnel the controller's helper serves.
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

/// A worker in a container: the pinned helper `forward`s the controller's
/// address to the container's own loopback, with a key the host generated
/// through [`tailcat::ensure_key`] (so its node key is known up front).
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

    /// As [`ContainerWorker::start`], forwarding with the saved key `key`
    /// (`--key=<name>`) instead of the helper's default client key.
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

    /// Sends `payload` to the container's forward and returns what came back
    /// (empty when the tunnel refused or dropped it).
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

    // The worker's identity persists: the same node key comes back after a
    // second ensure, which is what makes the address stable across restarts.
    let key = tailcat::ensure_key(&config, data_dir.path(), Role::Worker).unwrap();
    assert_eq!(
        key,
        tailcat::ensure_key(&config, data_dir.path(), Role::Worker).unwrap()
    );
    // …and it is on disk where the operator copies it from.
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
    // The path and latency are what `tailcat ping` measured, never a guess.
    let measured = forward.probe().expect("the tunnel does not answer a probe");
    assert_ne!(measured.path, Route::Unknown, "{measured:?}");
    let rtt = measured.rtt.expect("the pong reported no latency");
    assert!(rtt < Duration::from_secs(10), "probe rtt {rtt:?}");
    eprintln!("live probe: path {:?}, rtt {rtt:?}", measured.path);

    // The link port is carried end to end: a byte written to the loopback
    // forward comes back from the container's echo through the tunnel.
    assert_eq!(echo(port, b"sentinel-live"), b"sentinel-live");

    // A killed helper is replaced and the tunnel comes back on its own.
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

    // Revocation: the same helper identity comes back allowing a different
    // peer, so the only variable is the allow list and a refusal can only be
    // a rejection — not an endpoint that moved.
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
    // Release the loopback port: a second forward must bind it, and only one
    // listener per host port exists.
    forward.shutdown();

    // A changed endpoint is a new address: a second server with its own key
    // serves the same port, and a fresh forward dials it.
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

    // A well-formed address that no peer serves: the NAT path cannot be
    // found, so probes fail and supervision keeps replacing the helper
    // instead of trusting a bound port.
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

    // The worker's key, generated through Sentinel and handed to the
    // container as its helper's HOME.
    let worker_dir = tempfile::tempdir().unwrap();
    let key = tailcat::ensure_key(&config(binary, port), worker_dir.path(), Role::Worker).unwrap();

    // Sentinel's controller supervisor with nobody admitted: it still has an
    // address (in its owner-only file) and admits no peer.
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

    // Admitted: the same container's bytes now come back through the tunnel.
    server.set_allow(std::slice::from_ref(&key));
    wait_until("the admitted worker's echo", READY, || {
        worker.echo("admitted") == "admitted"
    });

    // Emptied again (the worker was revoked): the tunnel closes.
    server.set_allow(&[]);
    wait_until("the revoked worker's tunnel to close", PROBLEM, || {
        worker.echo("revoked").is_empty()
    });
    server.shutdown();
}

/// `CLOCK_MONOTONIC` in nanoseconds: one clock for this process and the
/// worker it runs in another network namespace, so their events compare.
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

/// When set, this binary plays the Sentinel worker in another network
/// namespace; the value names its working directory.
const WORKER_ROLE: &str = "SENTINEL_TAILCAT_LIVE_WORKER";
/// How the worker reacts to a lost session: unset is the shipped rule (a
/// clean close replaces the forward after [`tailcat::CLOSE_GRACE`],
/// anything else goes through [`tailcat::Forward::session_lost`]);
/// `immediate` is the rule before the grace, `session_lost` for every loss,
/// kept for comparison only.
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

/// The worker role: Sentinel's helper supervisor (production probe interval)
/// and the real worker link, fed the same session events `sentinel worker`
/// feeds it, appending `<event> <monotonic ns>` lines to `<dir>/events`.
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
    // The worker link dials the forward through a slow link it controls.
    let slow = slow_link(dir, forward.local_addr(), Arc::clone(&notes));
    let rule = std::env::var(WORKER_RULE).unwrap_or_default();
    // Presented only until the first session was welcomed.
    let secret = std::fs::read_to_string(dir.join("enrollment"))
        .ok()
        .and_then(|text| sentinel_auth::secret::Secret::parse(text.trim()));
    let settings = worker::Config {
        controller: slow,
        server: sentinel_auth::secret::Digest(fingerprint),
        worker: read("worker").trim().parse().unwrap(),
        name: "live-worker".into(),
        hello: sentinel_protocol::negotiate::Hello {
            protocol_min: sentinel_protocol::negotiate::ProtocolVersion(1),
            protocol_max: sentinel_protocol::negotiate::ProtocolVersion(3),
            // The shipped rule answers hand-offs, as `sentinel worker` says;
            // the comparison rule stands for a worker from before that.
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
        profile: sentinel_protocol::negotiate::Profile::default(),
        transport: sentinel_link::session::TransportStats::default(),
        remote_cache: false,
    };
    let identity = Identity::load(&dir.join("worker.crt"), &dir.join("worker.key")).unwrap();
    let handle = worker::Handle::new();
    std::thread::scope(|scope| {
        // Which path the tunnel took, as `tailcat ping` measures it, once
        // the first session is up.
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

/// The worker's `events` file: `<event> <monotonic ns>` lines.
struct Notes(std::sync::Mutex<std::fs::File>);

impl Notes {
    fn note(&self, event: &str) {
        let mut file = self.0.lock().unwrap_or_else(|p| p.into_inner());
        writeln!(file, "{event} {}", mono_ns()).unwrap();
        file.flush().unwrap();
    }
}

/// Written into the worker's directory by the controller side: the next
/// connection the worker opens is stalled (see [`slow_link`]).
const STALL: &str = "stall";

/// A slow link between the worker link and its forward, on loopback in the
/// worker's namespace. Bytes pass as they are, and so does each end (a FIN
/// or a reset) in either direction, the controller's close included. Only
/// the one connection opened after the controller side wrote [`STALL`] is
/// slowed: once the controller's first bytes (its TLS handshake flight)
/// came back, the worker's bytes stop getting through, so the controller
/// holds that connection in its TLS handshake, not yet a session. The
/// worker notes `stalled` at that moment.
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
            // Neither direction lingers past a dead tunnel forever.
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

/// Copy `from` to `to` until `from` ends, passing its end on: a FIN as a
/// FIN, an error as a reset of both. `pass` decides, per read, whether the
/// bytes are delivered or swallowed (a link that stopped delivering).
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

/// The worker link of [`play_worker`], reacting to lost sessions by `rule`.
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
                    // The shipped rule, as `sentinel worker` has it.
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

/// The worker process in the network namespace of a parked container, so
/// its loopback forward and the controller's link port on the host are
/// different sockets.
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

    /// `(event, monotonic ns)` for every line the worker wrote so far.
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

    /// The first `event` at or after `since`, waiting at most `within`.
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
        // The helper dies with the thread that started it (PDEATHSIG).
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// This test's name, for the worker process it starts in another namespace.
const HANDOFF_TEST: &str = "an_allow_list_change_hands_tunnelled_sessions_to_the_new_helper";

/// The outage an allow-list change costs a connected worker, measured on a
/// real worker link: Sentinel's controller link and helper supervisor on the
/// host, the worker link and its helper supervisor in a container's network
/// namespace, over a direct path and then over a relay only (UDP other than
/// DNS dropped inside the worker's namespace). The change restarts the
/// controller's helper. Cut, as `Server::set_allow` alone does it, the
/// tunnelled session ends without a close reaching the worker, which sees it
/// only at the session heartbeat deadline; handed off, as
/// `Handle::hand_off` does it, the controller first closes that session
/// through the old helper. The outage is from the change to the next
/// welcomed session, on `CLOCK_MONOTONIC`.
///
/// On each path: cut changes (the "before" figure), then at least 60
/// handed-off changes of a settled session (so a close lost once in 52
/// would show), changes that meet the worker's connection still in its TLS
/// handshake ([`slow_link`]), and changes during a moment of loss at the
/// worker ([`NetnsLoss`]), whose close only the old helper's resend
/// delivers. Every handed-off close must come back answered before the old
/// helper goes. Last, a worker that behaves as one from before
/// `HANDOFF_ANSWER` must never keep the old helper past the short bound.
/// It takes about 55 minutes; the `SENTINEL_TAILCAT_LIVE_*` counts in
/// [`plan`] shorten a development run.
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

    // The controller: store, a shared pool, the link on the helper's port.
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

    // The worker's files, readable from the other namespace (same host).
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

    // A parked container lends its network namespace (NAT to the relays).
    let parked = ParkedNetns::start("sentinel-live-netns");

    // Rounds of allow-list changes, each set on a fresh worker; every change
    // widens the list, so the worker stays admitted throughout.
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
        // The path the worker's helper measured; a relay-only namespace must
        // not find a direct one.
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
            // Past the settle time, as a long-running worker's helper is.
            std::thread::sleep(tailcat::SESSION_SETTLE + Duration::from_secs(1));
            let mut first = None;
            if kind == Kind::Stalled {
                // A handed-off change whose redial the slow link then holds
                // in its TLS handshake, through the restarted helper.
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
            // A lossy moment: everything reaching the worker's namespace is
            // dropped from the change on, so the close is lost in the tunnel
            // and gets through only if the old helper resends it.
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
            // The line written right after `connected` says which path the
            // new session took.
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
    // Set here, it picks the worker's rule for a comparison run.
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

    // A removal is handed off too, and still cuts the removed worker off:
    // its session is closed at once, and the restarted helper no longer
    // admits it, so it never gets back in.
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
        // A close the worker did not see promptly: it waited for a deadline.
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
                // Its answer may be lost with its forward, but the old
                // helper is never kept past the short bound for it.
                assert!(
                    handed.waited < HANDOFF_BOUND + Duration::from_millis(250),
                    "{label}: the hand-off waited {:?} for a worker that does not answer: {round:?}",
                    handed.waited
                );
            } else {
                // The worker's end came back before the old helper went:
                // the close was delivered, and the controller knew it.
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

/// A handed-off worker sees its session (or its connection in the
/// handshake) end within this long (measured over two full runs, 316
/// changes: 1.6-26 ms direct, 34-69 ms relayed).
const HANDOFF_NOTICED: Duration = Duration::from_millis(500);
/// A handed-off change costs a worker less than this, from the change to
/// the next welcomed session (measured over the same 316 changes:
/// 3.30-4.63 s, the restarted helper's own start).
const HANDOFF_OUTAGE: Duration = Duration::from_millis(5_500);
/// The same through a lossy moment, whose close only the old helper's
/// resend delivers (measured over 44 changes: 4.6-7.0 s, where a helper
/// that went at 600 ms left the direct worker to its heartbeat deadline,
/// 17.7-20.5 s).
const LOSSY_OUTAGE: Duration = Duration::from_secs(9);

/// How an allow-list change meets the worker.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    /// Cut, as `Server::set_allow` alone does it: the "before" figure.
    Cut,
    /// Handed off, the worker's session settled.
    Settled,
    /// Handed off while the worker's connection is still in its TLS
    /// handshake (see [`slow_link`]).
    Stalled,
    /// Handed off, the worker's session settled, while everything reaching
    /// the worker is dropped for [`LOSS`] ([`NetnsLoss`]): the close is lost
    /// in the tunnel and only the old helper can resend it.
    Lossy,
    /// Handed off, the worker's session settled, but the worker behaves as
    /// one from before `HANDOFF_ANSWER`: it replaces its forward on a clean
    /// close at once (when older than 10 s) and does not advertise the bit.
    Older,
}

/// Handed-off changes per path with a settled session. At least 60, so a
/// close lost once in 52 changes would show; `SENTINEL_TAILCAT_LIVE_CHANGES`
/// overrides it for a shorter development run.
const SETTLED_CHANGES: usize = 64;
/// Handed-off changes per path that meet a connection in its handshake;
/// `SENTINEL_TAILCAT_LIVE_STALLS` overrides it.
const STALLED_CHANGES: usize = 10;
/// Cut changes per path, for the figure the hand-off is compared with;
/// `SENTINEL_TAILCAT_LIVE_CUTS` overrides it.
const CUT_CHANGES: usize = 4;
/// Handed-off changes per path that meet a lossy moment;
/// `SENTINEL_TAILCAT_LIVE_LOSSY` overrides it.
const LOSSY_CHANGES: usize = 6;
/// Handed-off changes per path with a worker from before `HANDOFF_ANSWER`;
/// `SENTINEL_TAILCAT_LIVE_OLDER` overrides it.
const OLDER_CHANGES: usize = 10;

/// What each path measures, in order.
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

/// One measured allow-list change.
#[derive(Debug)]
// `trail` and `first` are read only through `Debug`, in failure messages.
#[allow(dead_code)]
struct Round {
    /// From the change to the next welcomed session.
    outage: Duration,
    /// From the change to the worker seeing its session end.
    lost: Option<Duration>,
    handed: Option<sentinel_link::controller::Handoff>,
    /// For a stalled change: the change before it (its hand-off, when the
    /// worker saw that close, and when the redial reached the handshake).
    first: Option<(
        sentinel_link::controller::Handoff,
        Option<Duration>,
        Duration,
    )>,
    trail: Vec<String>,
}

/// A parked container whose network namespace a worker process enters.
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

/// Every UDP datagram but DNS dropped inside one network namespace: the
/// helper there can reach its peer only through a DERP relay (over TCP).
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

/// How long a [`Kind::Lossy`] change drops what reaches the worker.
const LOSS: Duration = Duration::from_millis(800);

/// Everything arriving in one network namespace other than on loopback
/// dropped for [`LOSS`], from `engage` on. The kernel ends the loss: the
/// drop matches an nft set element that expires after [`LOSS`], so neither
/// a hand-off in progress nor a slow `nft` or `iptables` call can stretch
/// it. (Removing an `iptables` rule from a timer thread did: the "800 ms"
/// held for 0.85-4.1 s, and a close resent after it was lifted reached the
/// worker after the old helper had gone.) `lift` waits out the window and
/// removes the table.
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
        // `add` then `delete` makes the reset idempotent; the element is
        // added last, so the window starts once everything is in place.
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
            // The element may have been added at any point of the call.
            until: engaged_at + LOSS,
            removed: false,
        }
    }

    fn remove(&self) -> bool {
        Self::nft(&self.pid, &format!("delete table inet {}\n", Self::TABLE))
    }

    fn lift(mut self) {
        // Nothing reaching the worker is dropped past the element's expiry;
        // the table goes so that the next round starts from nothing.
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

/// Operator-driven rotation of both identities, end to end on the pinned
/// helper: a worker's staged key cannot commit until the controller lists
/// it; both worker keys are admitted through the overlap, and retiring the
/// old one refuses only it; the controller's staged key is served beside the
/// active one, and the commit keeps the workers already on the new address
/// connected while the old address stops answering; revocation still closes
/// the rotated tunnel.
///
/// An allow-list change restarts the controller's helper. The containers
/// here run a bare `tailcat forward` probed with short `nc` connections, and
/// such a forward was measured not to answer again within 300 s of the
/// restart (three restarts, none recovered). A Sentinel worker's link does
/// recover through its own forward (see
/// `an_allow_list_change_hands_tunnelled_sessions_to_the_new_helper`), so
/// this test replaces a container's helper after an allow-list change
/// before judging it.
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

    // Worker rotation. Unlisted, the staged key cannot commit: the
    // controller's helper refuses its handshake.
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
    // The old key's material, kept aside by the test only, to show later
    // that the retired key is refused (the commit deletes it).
    let old_keys = tempfile::tempdir().unwrap();
    let saved = Path::new(".config/tailcat/keys/client-default.private.json");
    std::fs::create_dir_all(old_keys.path().join(saved.parent().unwrap())).unwrap();
    std::fs::copy(keys.join(saved), old_keys.path().join(saved)).unwrap();

    // Listed beside the old key: the old key is still admitted, and the
    // commit's ping with the new key succeeds.
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
    // Both keys carry the link at once through the overlap.
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

    // Retired: the new key is the worker's only one; a fresh helper with the
    // old key is refused.
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

    // Controller rotation: the staged key is served beside the active one,
    // and both addresses carry the link.
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

    // Commit: the helper serving the new key becomes the main one without a
    // restart, so the worker already on the new address keeps its tunnel;
    // the old address stops answering.
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

    // Revocation still applies to the rotated identity.
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

/// Outbound UDP to the container subnet blocked for the scope of the guard:
/// the direct WireGuard path to the peer cannot form, so the helper can only
/// reach it through a DERP relay. Everything else stays open — WSL's DNS
/// resolver and the DERP map fetch are not on this path.
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

    // With UDP dropped the direct path cannot form: the supervisor's own
    // probe must measure a relayed path, and the forward still carries the
    // link port.
    let forward =
        tailcat::start_forward_every(&config, data_dir.path(), &server.address, PROBE_EVERY)
            .unwrap();
    wait_until("the relayed tunnel", READY, || forward.telemetry().ready);
    let measured = forward.probe().expect("the relayed tunnel does not answer");
    assert_eq!(measured.path, Route::Relay, "{measured:?}");
    assert_eq!(echo(port, b"relay-only"), b"relay-only");
    forward.shutdown();
}

/// A throwaway CA and a leaf for `ip`, written with `openssl`.
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
    // Appended to the runner's bundle (a copy of the system roots), so the
    // tests that use the public relays keep working in the same run.
    let ca = std::fs::read(dir.join("ca.pem")).unwrap();
    std::fs::OpenOptions::new()
        .append(true)
        .open(ca_out)
        .and_then(|mut bundle| bundle.write_all(&ca))
        .expect("SENTINEL_TAILCAT_DERP_CA must be an existing, writable bundle");
    (crt, key)
}

/// Kills a background process on drop.
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
    // The relay lives on the Podman bridge's gateway, which both the host and
    // the container reach. The bridge exists once a container runs.
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

    // Direct UDP between the container and the host is dropped, so the only
    // way through is the self-hosted relay — the only region in the map.
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
