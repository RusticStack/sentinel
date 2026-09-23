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
//!   (plus the command above; PATH must include /usr/sbin for podman and iptables)
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
