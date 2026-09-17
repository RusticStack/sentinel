//! Q06: the Tailcat supervisor's contract, exercised against a fake helper.
//!
//! The helper here is a `/bin/sh` script that records every invocation and
//! plays only the shapes these tests assert: the executable is hashed before
//! anything runs, the argv carries the link port and nothing wider, a helper
//! that dies or stops connecting is replaced, and node keys and `tc…`
//! addresses stay out of diagnostics.

#![cfg(target_os = "linux")]

use std::{
    fs,
    net::TcpListener,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use sentinel_link::tailcat::{self, Address, Error, NodeKey, TailcatConfig};
use sha2::{Digest, Sha256};

/// Hex bodies of the node keys and the address the fake helper reports.
const KEY: &str = "0123456789abcdeffedcba98765432100123456789abcdeffedcba9876543210";
const OTHER: &str = "fedcba98765432100123456789abcdeffedcba98765432100123456789abcdef";
const THIRD: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
const ADDRESS: &str = "tcabcdefghijklmnopqrstuvwxyz0123";

/// A fake helper on disk: it appends `argv …` to a log, answers `--version`
/// and `genkey`, and runs whatever `body` adds for `serve`, `forward` and
/// `ping`.
struct Fake {
    dir: tempfile::TempDir,
    binary: PathBuf,
    log: PathBuf,
}

impl Fake {
    fn write(body: &str) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("argv.log");
        let binary = dir.path().join("tailcat");
        let script = format!(
            "#!/bin/sh\nprintf 'argv %s\\n' \"$*\" >> \"{log}\"\ncase \"$1\" in\n  --version) printf 'tailcat v0.6.0\\n'; exit 0 ;;\n  genkey) printf 'nodekey:{key}\\n'; exit 0 ;;\n{body}esac\nexit 64\n",
            log = log.display(),
            key = KEY,
            body = body,
        );
        fs::write(&binary, script).unwrap();
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o700)).unwrap();
        Self { dir, binary, log }
    }

    fn path(&self) -> &Path {
        self.dir.path()
    }

    /// A configuration that accepts this fake as the helper.
    fn config(&self, listen_port: u16) -> TailcatConfig {
        TailcatConfig {
            enabled: true,
            binary: self.binary.clone(),
            sha256: digest_of(&self.binary),
            derpmap_url: None,
            region: None,
            listen_port,
        }
    }

    fn lines(&self) -> Vec<String> {
        fs::read_to_string(&self.log)
            .map(|text| text.lines().map(str::to_owned).collect())
            .unwrap_or_default()
    }

    fn calls(&self, subcommand: &str) -> Vec<String> {
        let prefix = format!("argv {subcommand} ");
        self.lines()
            .into_iter()
            .filter(|line| line.starts_with(&prefix))
            .collect()
    }
}

fn digest_of(path: &Path) -> String {
    let bytes = fs::read(path).unwrap();
    Sha256::digest(&bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn key(body: &str) -> NodeKey {
    NodeKey::parse(&format!("nodekey:{body}")).unwrap()
}

fn wait_until(what: &str, mut ready: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if ready() {
            return;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    panic!("timed out waiting for {what}");
}

const SERVE_FOREVER: &str =
    "  serve) printf 'listening on tcabcdefghijklmnopqrstuvwxyz0123\\n'; exec sleep 3600 ;;\n";

#[test]
fn a_helper_that_is_not_the_pinned_build_is_never_executed() {
    let fake = Fake::write(SERVE_FOREVER);
    let mut config = fake.config(7443);
    config.sha256 = tailcat::PINNED_SHA256.to_owned();
    let error = tailcat::start_server(&config, fake.path(), &[]).unwrap_err();
    assert!(matches!(&error, Error::Checksum { .. }), "{error:?}");
    assert!(
        !fake.log.exists(),
        "nothing may run before the digest matches"
    );
}

#[test]
fn modes_that_widen_the_helper_past_the_link_port_are_refused() {
    for banned in ["all", "exit-node", "ssh", "files", "no-auth-ssh"] {
        let fake = Fake::write(SERVE_FOREVER);
        let mut config = fake.config(7443);
        config.region = Some(banned.to_owned());
        let error = tailcat::start_server(&config, fake.path(), &[]).unwrap_err();
        match &error {
            Error::Refused(word) if *word == banned => {}
            other => panic!("{banned}: expected a refusal, got {other:?}"),
        }
        assert!(!fake.log.exists(), "{banned} must not run the helper");
    }
}

#[test]
fn a_disabled_transport_refuses_to_start_and_leaves_direct_tls_alone() {
    let fake = Fake::write(SERVE_FOREVER);
    let mut config = fake.config(7443);
    config.enabled = false;
    let error = tailcat::start_server(&config, fake.path(), &[]).unwrap_err();
    assert!(matches!(&error, Error::Unavailable(_)), "{error:?}");
    assert!(!fake.log.exists());
}

#[test]
fn serve_carries_the_link_port_and_only_the_allowed_node_keys() {
    let fake = Fake::write(SERVE_FOREVER);
    let config = fake.config(7443);
    let first = key(KEY);
    let second = key(OTHER);
    let server = tailcat::start_server(
        &config,
        fake.path(),
        &[second.clone(), first.clone(), first.clone()],
    )
    .unwrap();
    let address = server.wait_ready(Duration::from_secs(10)).unwrap();
    assert_eq!(address.expose(), ADDRESS);
    assert_eq!(server.port(), 7443);
    assert_eq!(
        fake.calls("serve"),
        vec![format!(
            "argv serve --allow={} --allow={} 7443",
            first.expose(),
            second.expose()
        )]
    );

    // Credentials: a diagnostic that prints them prints nothing usable.
    assert!(!format!("{first}").contains(KEY));
    assert!(!format!("{first:?}").contains(KEY));
    assert!(!format!("{address:?}").contains(ADDRESS));
    assert!(!format!("{:?}", server.telemetry()).contains(ADDRESS));
    assert!(first.expose().ends_with(KEY));

    // Enrolling another worker restarts serve with the wider list; the key is
    // unchanged, so the address it serves stays the same.
    let third = key(THIRD);
    server.set_allow(&[first.clone(), second.clone(), third.clone()]);
    wait_until("serve with three keys", || fake.calls("serve").len() == 2);
    assert_eq!(
        fake.calls("serve")[1],
        format!(
            "argv serve --allow={} --allow={} --allow={} 7443",
            third.expose(),
            first.expose(),
            second.expose()
        )
    );
    assert!(server.telemetry().restarts >= 1);
    assert_eq!(
        server.wait_ready(Duration::from_secs(10)).unwrap().expose(),
        ADDRESS
    );
    server.shutdown();
    assert!(server.telemetry().pid.is_none());
}

#[test]
fn forward_binds_loopback_and_health_needs_the_tunnel() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let controller = Address::parse(ADDRESS).unwrap();

    let healthy =
        Fake::write("  forward) printf 'forwarding\\n'; exec sleep 3600 ;;\n  ping) exit 0 ;;\n");
    let config = healthy.config(port);
    let forward = tailcat::start_forward(&config, healthy.path(), &controller).unwrap();
    assert_eq!(
        forward.local_addr().to_string(),
        format!("127.0.0.1:{port}")
    );
    wait_until("the forward helper to start", || {
        !healthy.calls("forward").is_empty()
    });
    assert_eq!(
        healthy.calls("forward"),
        vec![format!(
            "argv forward --bind=127.0.0.1 {} {port}:{port}",
            controller.expose()
        )]
    );
    assert!(forward.probe().is_ok(), "ping plus a loopback connect");

    // The same shape, but ping cannot reach the controller: not healthy, and
    // the failure is visible in telemetry rather than swallowed.
    let broken =
        Fake::write("  forward) printf 'forwarding\\n'; exec sleep 3600 ;;\n  ping) exit 1 ;;\n");
    let config = broken.config(port);
    let forward = tailcat::start_forward(&config, broken.path(), &controller).unwrap();
    let error = forward.probe().unwrap_err();
    assert!(matches!(&error, Error::Unavailable(_)), "{error:?}");
    assert!(!forward.telemetry().ready);
    forward.shutdown();
    assert!(forward.telemetry().pid.is_none());
}

#[test]
fn a_dead_helper_is_replaced_and_a_stalled_tunnel_is_not_trusted() {
    let dying = Fake::write(
        "  serve) printf 'listening on tcabcdefghijklmnopqrstuvwxyz0123\\n'; sleep 0.3; exit 7 ;;\n",
    );
    let config = dying.config(7443);
    let server = tailcat::start_server(&config, dying.path(), &[]).unwrap();
    wait_until("the dead helper to be replaced", || {
        dying.calls("serve").len() >= 2
    });
    assert!(server.telemetry().restarts >= 1);
    server.shutdown();
    assert!(server.telemetry().pid.is_none());

    // A helper that is alive but whose tunnel stopped answering is replaced
    // too: an open loopback port is not health.
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let stalled =
        Fake::write("  forward) printf 'forwarding\\n'; exec sleep 3600 ;;\n  ping) exit 1 ;;\n");
    let config = stalled.config(port);
    let controller = Address::parse(ADDRESS).unwrap();
    let forward = tailcat::start_forward_every(
        &config,
        stalled.path(),
        &controller,
        Duration::from_millis(200),
    )
    .unwrap();
    wait_until("the stalled tunnel to be replaced", || {
        stalled.calls("forward").len() >= 2
    });
    assert!(forward.telemetry().restarts >= 1);
    forward.shutdown();
    assert!(forward.telemetry().pid.is_none());
}

#[test]
fn the_allow_list_is_one_nodekey_per_line() {
    let dir = tempfile::tempdir().unwrap();
    assert!(tailcat::allow_list(dir.path()).unwrap().is_empty());

    let path = dir.path().join(tailcat::ALLOW_LIST_FILE);
    fs::write(
        &path,
        format!("# builders\n\n  nodekey:{KEY}  \nnodekey:{OTHER}\n"),
    )
    .unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let keys = tailcat::allow_list(dir.path()).unwrap();
    assert_eq!(keys.len(), 2);
    assert!(keys.contains(&key(KEY)));

    fs::write(&path, "nodekey:zzzz\n").unwrap();
    let error = tailcat::allow_list(dir.path()).unwrap_err();
    assert!(error.to_string().contains("line 1"), "{error:?}");
}

#[test]
fn credentials_stay_out_of_debug_output() {
    let node_key = key(KEY);
    let address = Address::parse(ADDRESS).unwrap();
    for printed in [
        format!("{node_key}"),
        format!("{node_key:?}"),
        format!("{address}"),
        format!("{address:?}"),
    ] {
        assert!(!printed.contains(KEY), "{printed}");
        assert!(!printed.contains(ADDRESS), "{printed}");
    }
    assert!(node_key.expose().contains(KEY));

    let telemetry = tailcat::Telemetry {
        pid: Some(1),
        ready: true,
        restarts: 2,
        version: Some("tailcat v0.6.0".to_owned()),
        address: Some(address),
        problem: None,
    };
    assert!(!format!("{telemetry:?}").contains(ADDRESS));
}
