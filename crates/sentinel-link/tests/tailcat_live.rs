//! Q07 live evidence: the pinned helper over a real NAT boundary.
//!
//! These tests need the real `tailcat` binary and rootless Podman; they are
//! `#[ignore]`d by default and run on a Linux host with:
//!
//! ```sh
//! SENTINEL_TAILCAT_LIVE=/root/tailcat/tailcat \
//!   cargo test -p sentinel-link --test tailcat_live -- --ignored --nocapture
//! ```
//!
//! The server side runs inside a Podman container, so the helper crosses a
//! real NAT boundary (slirp4netns) instead of a loopback shortcut: the
//! container serves the link port plus a `nc` echo, and the worker's forward
//! on loopback is the only listener on that port on the host — a byte that
//! comes back went through the tunnel. What stays unproven here is recorded,
//! not faked: a self-hosted DERP map and forced relay-only operation need an
//! operator's relay infrastructure (see docs/worker-link.md).

#![cfg(target_os = "linux")]

use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

use sentinel_link::tailcat::{
    self, Address, NodeKey, PINNED_SHA256, PINNED_VERSION, Role, TailcatConfig,
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

/// The pinned helper, or `None` when the live gate is not set. A binary that
/// is not the pinned build fails the test rather than running: that is the
/// same refusal the supervisor applies.
fn live_binary() -> Option<PathBuf> {
    let path = PathBuf::from(std::env::var("SENTINEL_TAILCAT_LIVE").ok()?);
    let digest = Sha256::digest(&std::fs::read(&path).ok()?)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    assert_eq!(
        digest, PINNED_SHA256,
        "SENTINEL_TAILCAT_LIVE is not the pinned {PINNED_VERSION} build"
    );
    Some(path)
}

fn podman() -> Option<()> {
    let ok = Command::new("podman")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success());
    ok.then_some(())
}

/// A free loopback port, raced the way tests always race it.
fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn config(binary: &Path, data_dir: &Path, port: u16) -> TailcatConfig {
    let _ = data_dir;
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
    /// peer (tailcat's default), `Some(key)` passes `--allow=<key>`. The key
    /// exists after the first start, so a restart reuses the same identity.
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
        let status = Command::new("podman")
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
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert!(status.success(), "podman run failed for {name}");
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
        let _ = Command::new("podman")
            .args(["rm", "-f", &self.name])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop();
    }
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

#[test]
#[ignore = "live helper: SENTINEL_TAILCAT_LIVE=<pinned tailcat> + podman"]
fn the_helper_carries_the_link_port_and_reports_telemetry() {
    let _serial = LIVE.lock().expect("live serial");
    let Some(binary) = live_binary() else {
        eprintln!("SENTINEL_TAILCAT_LIVE unset; skipping live tailcat test");
        return;
    };
    if podman().is_none() {
        eprintln!("podman unavailable; skipping live tailcat test");
        return;
    }
    let data_dir = tempfile::tempdir().unwrap();
    let port = free_port();
    let config = config(&binary, data_dir.path(), port);

    // The worker's identity persists: the same node key comes back after a
    // second ensure, which is what makes the address stable across restarts.
    let key = tailcat::ensure_key(&config, data_dir.path(), Role::Worker).unwrap();
    assert_eq!(
        key,
        tailcat::ensure_key(&config, data_dir.path(), Role::Worker).unwrap()
    );

    let server_keys = tempfile::tempdir().unwrap();
    let server = Server::start(
        &binary,
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
    let rtt = forward.probe().expect("the tunnel does not answer a probe");
    assert!(rtt < Duration::from_secs(10), "probe rtt {rtt:?}");

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
    let _serial = LIVE.lock().expect("live serial");
    let Some(binary) = live_binary() else {
        eprintln!("SENTINEL_TAILCAT_LIVE unset; skipping live tailcat test");
        return;
    };
    if podman().is_none() {
        eprintln!("podman unavailable; skipping live tailcat test");
        return;
    }
    let data_dir = tempfile::tempdir().unwrap();
    let port = free_port();
    let config = config(&binary, data_dir.path(), port);
    let key = tailcat::ensure_key(&config, data_dir.path(), Role::Worker).unwrap();

    let server_keys = tempfile::tempdir().unwrap();
    let server = Server::start(
        &binary,
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
    let server = server.restart_with(&binary, port, Some(&other), server_keys.path());
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
        &binary,
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
#[ignore = "live helper: SENTINEL_TAILCAT_LIVE=<pinned tailcat> + podman"]
fn a_dead_address_fails_fast_and_stays_supervised() {
    let _serial = LIVE.lock().expect("live serial");
    let Some(binary) = live_binary() else {
        eprintln!("SENTINEL_TAILCAT_LIVE unset; skipping live tailcat test");
        return;
    };
    let data_dir = tempfile::tempdir().unwrap();
    let port = free_port();
    let config = config(&binary, data_dir.path(), port);
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
    forward.shutdown();
}

/// Outbound UDP to the container subnet blocked for the scope of the guard:
/// the direct WireGuard path to the peer cannot form, so the helper can only
/// reach it through a DERP relay. Everything else stays open — WSL's DNS
/// resolver and the DERP map fetch are not on this path.
struct UdpBlock;

impl UdpBlock {
    fn engage() -> Option<Self> {
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
        engaged.then_some(Self)
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
    let _serial = LIVE.lock().expect("live serial");
    let Some(binary) = live_binary() else {
        eprintln!("SENTINEL_TAILCAT_LIVE unset; skipping live tailcat test");
        return;
    };
    if podman().is_none() {
        eprintln!("podman unavailable; skipping live tailcat test");
        return;
    }
    let data_dir = tempfile::tempdir().unwrap();
    let port = free_port();
    let config = config(&binary, data_dir.path(), port);
    let key = tailcat::ensure_key(&config, data_dir.path(), Role::Worker).unwrap();
    let server_keys = tempfile::tempdir().unwrap();
    let server = Server::start(
        &binary,
        "sentinel-live-relay",
        port,
        Some(&key),
        server_keys.path(),
    );

    let Some(_block) = UdpBlock::engage() else {
        eprintln!("iptables unavailable; skipping relay-only assertion");
        server.stop();
        return;
    };

    // With UDP dropped the direct path cannot form: every pong must arrive
    // via a DERP relay, and the forward still carries the link port.
    let output = Command::new(&binary)
        .env("HOME", data_dir.path().join("tailcat"))
        .args(["ping", "--timeout=20s", server.address.expose()])
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&output.stdout).into_owned()
        + &String::from_utf8_lossy(&output.stderr);
    assert!(
        text.contains("via DERP"),
        "expected a DERP-relayed pong, got: {text}"
    );

    let forward =
        tailcat::start_forward_every(&config, data_dir.path(), &server.address, PROBE_EVERY)
            .unwrap();
    wait_until("the relayed tunnel", READY, || forward.telemetry().ready);
    assert_eq!(echo(port, b"relay-only"), b"relay-only");
    forward.shutdown();
}
