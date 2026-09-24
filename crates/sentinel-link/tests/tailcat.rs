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

use sentinel_core::WorkerId;
use sentinel_link::{
    session::Path as Route,
    tailcat::{self, Address, Admission, Error, NodeKey, Role, TailcatConfig},
};
use sha2::{Digest, Sha256};

/// Hex bodies of the node keys and the address the fake helper reports.
const KEY: &str = "0123456789abcdeffedcba98765432100123456789abcdeffedcba9876543210";
const OTHER: &str = "fedcba98765432100123456789abcdeffedcba98765432100123456789abcdef";
const THIRD: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
const ADDRESS: &str = "tcabcdefghijklmnopqrstuvwxyz0123";

/// A fake helper on disk: it appends `argv …` to a log, answers `--version`,
/// `genkey` (a client key prints its node key, a server key its address, as
/// upstream does) and `parse`, and runs whatever `body` adds for `serve`,
/// `forward` and `ping`.
struct Fake {
    dir: tempfile::TempDir,
    binary: PathBuf,
    log: PathBuf,
}

impl Fake {
    fn write(body: &str) -> Self {
        Self::script(&format!(
            "  --version) printf 'tailcat v0.6.0\\n'; exit 0 ;;\n  genkey) case \"$*\" in *--client*) printf 'nodekey:{key}\\n' ;; *) printf '# wrote a key\\n{address}\\n' ;; esac; exit 0 ;;\n  parse) printf '{{\\n  \"ServerPublic\": \"nodekey:{key}\"\\n}}\\n'; exit 0 ;;\n{body}",
            key = KEY,
            address = ADDRESS,
        ))
    }

    /// A fake whose `case "$1"` arms are exactly `cases`.
    fn script(cases: &str) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("argv.log");
        // Not "tailcat": that name is the key directory inside the data dir,
        // which is this same temporary directory.
        let binary = dir.path().join("helper");
        let script = format!(
            "#!/bin/sh\nprintf 'argv %s\\n' \"$*\" >> \"{log}\"\ncase \"$1\" in\n{cases}esac\nexit 64\n",
            log = log.display(),
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

/// Polls `ready` until it holds. The deadline only bounds a hang — a passing
/// test returns the moment the condition is true — and every condition here
/// waits on real `/bin/sh` spawns, which a host short of memory has been
/// seen to stall for over 10 s; 60 s keeps a stalled host from reading as a
/// supervision bug without slowing a healthy run at all.
fn wait_until(what: &str, mut ready: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(60);
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
    // One comma-separated `--allow`: upstream keeps only the last of a
    // repeated flag, which would admit one worker of the fleet.
    assert_eq!(
        fake.calls("serve"),
        vec![format!(
            "argv serve --allow={},{} 7443",
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
            "argv serve --allow={},{},{} 7443",
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

/// A probe's verdict is about the helper it probed. Here the first helper
/// ends on its own while its probe is still in flight, and its successor
/// starts before that probe fails: the failure must not kill the successor,
/// which nothing has judged yet. Marker files order the events, so no
/// timing decides the outcome; the successor is judged only after its own
/// full interval (5 s), well after the check below.
#[test]
fn a_stale_probe_never_replaces_the_successor_it_did_not_probe() {
    let marks = tempfile::tempdir().unwrap();
    let m = marks.path().display();
    // Waits (bounded, 20 s) until the marker `name` exists.
    let wait_for = |name: &str| {
        format!(
            "i=0; while [ ! -e \"{m}/{name}\" ] && [ $i -lt 400 ]; do sleep 0.05; i=$((i+1)); done"
        )
    };
    // The first `forward` marks `a` and ends once a probe is in flight; the
    // second marks `b` and stays up. `ping` marks `pinging` and fails only
    // once `b` exists.
    let body = format!(
        concat!(
            "  forward) if [ ! -e \"{m}/a\" ]; then : > \"{m}/a\"; {until_pinging}; exit 0; fi;",
            " : > \"{m}/b\"; exec sleep 3600 ;;\n",
            "  ping) : > \"{m}/pinging\"; {until_b}; exit 1 ;;\n",
        ),
        m = m,
        until_pinging = wait_for("pinging"),
        until_b = wait_for("b"),
    );
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let fake = Fake::write(&body);
    let config = fake.config(port);
    let controller = Address::parse(ADDRESS).unwrap();
    let forward =
        tailcat::start_forward_every(&config, fake.path(), &controller, Duration::from_secs(5))
            .unwrap();
    // The first probe starts; the first helper then ends; its successor
    // starts, and only then does the probe fail.
    let deadline = Instant::now() + Duration::from_secs(30);
    while !marks.path().join("b").exists() {
        assert!(Instant::now() < deadline, "the successor never started");
        std::thread::sleep(Duration::from_millis(25));
    }
    // The stale failure lands within a poll of the successor's start; give
    // it far longer than that, yet far less than the successor's own
    // interval.
    std::thread::sleep(Duration::from_millis(1_500));
    assert_eq!(
        fake.calls("forward").len(),
        2,
        "the successor was replaced on its predecessor's probe"
    );
    forward.shutdown();
}

#[test]
fn the_allow_list_ties_each_nodekey_to_a_worker() {
    let dir = tempfile::tempdir().unwrap();
    assert!(tailcat::allow_list(dir.path()).unwrap().is_empty());

    let (one, two) = (WorkerId::new(), WorkerId::new());
    let path = dir.path().join(tailcat::ALLOW_LIST_FILE);
    fs::write(
        &path,
        format!(
            "# builders\n\n  nodekey:{KEY}   {one} \nnodekey:{OTHER} {two}\nnodekey:{KEY} {one}\n"
        ),
    )
    .unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let admitted = tailcat::allow_list(dir.path()).unwrap();
    assert_eq!(admitted.len(), 2, "a repeated line counts once");
    assert!(admitted.contains(&Admission {
        key: key(KEY),
        worker: one
    }));
    assert!(admitted.contains(&Admission {
        key: key(OTHER),
        worker: two
    }));

    // Fail closed: a bare key, a bad worker id, a key named for two workers,
    // a trailing field and a malformed key are all refused, naming only the
    // line.
    for (text, line) in [
        (format!("nodekey:{KEY}\n"), 1),
        (
            format!("nodekey:{KEY} {one}\nnodekey:{OTHER} wrk_nope\n"),
            2,
        ),
        (format!("nodekey:{KEY} {one}\nnodekey:{KEY} {two}\n"), 2),
        (format!("nodekey:{KEY} {one} extra\n"), 1),
        (format!("nodekey:zzzz {one}\n"), 1),
    ] {
        fs::write(&path, &text).unwrap();
        let error = tailcat::allow_list(dir.path()).unwrap_err();
        assert!(
            error.to_string().contains(&format!("line {line}")),
            "{error:?}"
        );
        assert!(!error.to_string().contains(KEY), "{error:?}");
    }
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
        path: Route::Relay,
        ping_rtt: Some(Duration::from_millis(3)),
        problem: None,
    };
    assert!(!format!("{telemetry:?}").contains(ADDRESS));
}

/// Whether a process still runs (a zombie waiting for its reaper does not).
fn alive(pid: u32) -> bool {
    fs::read_to_string(format!("/proc/{pid}/stat")).is_ok_and(|stat| {
        stat.rsplit_once(") ")
            .is_some_and(|(_, rest)| !rest.starts_with('Z') && !rest.starts_with('X'))
    })
}

fn allow_none() -> String {
    "argv serve --allow=none 7443".to_owned()
}

#[test]
fn an_empty_allow_list_admits_no_peer_and_still_has_an_address() {
    let fake = Fake::write(SERVE_FOREVER);
    let config = fake.config(7443);
    let server = tailcat::start_server(&config, fake.path(), &[]).unwrap();
    server.wait_ready(Duration::from_secs(10)).unwrap();
    // Upstream serves every peer when `--allow` is absent; an empty list must
    // say `none` explicitly.
    assert_eq!(fake.calls("serve"), vec![allow_none()]);
    // A server key's genkey prints an address, not a key: the controller's
    // node key is decoded from that address.
    assert_eq!(
        fs::read_to_string(tailcat::nodekey_file(fake.path(), Role::Controller))
            .unwrap()
            .trim(),
        key(KEY).expose()
    );

    // The address goes to an owner-only file, not to any output.
    let file = server.address_file();
    assert_eq!(
        file,
        fake.path().join("tailcat").join(tailcat::ADDRESS_FILE)
    );
    assert_eq!(fs::read_to_string(&file).unwrap(), format!("{ADDRESS}\n"));
    assert_eq!(
        fs::metadata(&file).unwrap().permissions().mode() & 0o777,
        0o600
    );
    server.shutdown();
}

#[test]
fn narrowing_or_emptying_the_list_replaces_the_helper_at_once() {
    let fake = Fake::write(SERVE_FOREVER);
    let config = fake.config(7443);
    let (first, second) = (key(KEY), key(OTHER));
    let server =
        tailcat::start_server(&config, fake.path(), &[first.clone(), second.clone()]).unwrap();
    server.wait_ready(Duration::from_secs(10)).unwrap();
    wait_until("the first helper's pid", || {
        server.telemetry().pid.is_some()
    });
    let old = server.telemetry().pid.unwrap();

    // Revoking `second` narrows the list: the old child (still admitting
    // `second`) is killed and the new one admits `first` only. A deliberate
    // replacement is immediate — no back-off — and records no problem.
    let asked = Instant::now();
    server.set_allow(std::slice::from_ref(&first));
    wait_until("serve with the narrower list", || {
        fake.calls("serve").len() == 2
    });
    assert!(
        asked.elapsed() < Duration::from_millis(900),
        "an intentional restart waited {:?}",
        asked.elapsed()
    );
    assert_eq!(
        fake.calls("serve")[1],
        format!("argv serve --allow={} 7443", first.expose())
    );
    wait_until("the old helper to be gone", || !alive(old));
    wait_until("the new helper", || {
        server.telemetry().pid.is_some_and(|pid| pid != old)
    });
    assert!(server.telemetry().problem.is_none());

    // Emptying it closes every tunnel: the next helper admits nobody.
    let old = server.telemetry().pid.unwrap();
    server.set_allow(&[]);
    wait_until("serve with no peer", || fake.calls("serve").len() == 3);
    assert_eq!(fake.calls("serve")[2], allow_none());
    wait_until("the old helper to be gone", || !alive(old));
    // A later non-empty list admits again.
    server.set_allow(std::slice::from_ref(&second));
    wait_until("serve with a key again", || fake.calls("serve").len() == 4);
    assert_eq!(
        fake.calls("serve")[3],
        format!("argv serve --allow={} 7443", second.expose())
    );
    server.shutdown();
}

#[test]
fn back_off_resets_after_a_healthy_helper_and_never_delays_a_new_list() {
    // Each helper reports readiness and then dies: every restart follows a
    // healthy run, so the wait stays at the minimum instead of doubling.
    let flapping = Fake::write(
        "  serve) printf 'listening on tcabcdefghijklmnopqrstuvwxyz0123\\n'; sleep 0.2; exit 7 ;;\n",
    );
    let server = tailcat::start_server(&flapping.config(7443), flapping.path(), &[]).unwrap();
    let started = Instant::now();
    wait_until("four healthy runs", || flapping.calls("serve").len() >= 4);
    assert!(
        started.elapsed() < Duration::from_millis(5_500),
        "back-off grew across healthy runs: {:?}",
        started.elapsed()
    );
    server.shutdown();

    // A helper that fails before readiness does back off — but a new allow
    // list interrupts that wait instead of queueing behind it.
    let failing = Fake::write("  serve) exit 7 ;;\n");
    let server = tailcat::start_server(&failing.config(7443), failing.path(), &[]).unwrap();
    wait_until("three failed runs", || failing.calls("serve").len() >= 3);
    let before = failing.calls("serve").len();
    std::thread::sleep(Duration::from_millis(100));
    let asked = Instant::now();
    server.set_allow(&[key(KEY)]);
    wait_until("the new list to be served", || {
        failing.calls("serve").len() > before
    });
    assert!(
        asked.elapsed() < Duration::from_millis(900),
        "a new allow list waited out the back-off: {:?}",
        asked.elapsed()
    );
    server.shutdown();
}

#[test]
fn the_probe_measures_the_path_without_touching_the_link_port() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();
    let controller = Address::parse(ADDRESS).unwrap();
    let relayed = Fake::write(
        "  forward) printf 'forwarding\\n'; exec sleep 3600 ;;\n  ping) printf 'pong in 42.1ms via DERP(fra)\\n'; exit 0 ;;\n",
    );
    let forward =
        tailcat::start_forward(&relayed.config(port), relayed.path(), &controller).unwrap();
    let measured = forward.probe().unwrap();
    assert_eq!(measured.path, Route::Relay);
    assert_eq!(measured.rtt, Some(Duration::from_micros(42_100)));
    assert_eq!(forward.telemetry().path, Route::Relay);
    // Nothing reached the (stand-in) controller listener: a probe is a
    // `ping`, not a stray connection counted as a rejected TLS handshake.
    assert_eq!(
        listener.accept().map(|_| ()).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    forward.shutdown();

    let direct = Fake::write(
        "  forward) printf 'forwarding\\n'; exec sleep 3600 ;;\n  ping) printf 'pong in 740\\302\\265s via 172.17.0.1:51223\\n'; exit 0 ;;\n",
    );
    let forward = tailcat::start_forward(&direct.config(port), direct.path(), &controller).unwrap();
    let measured = forward.probe().unwrap();
    assert_eq!(measured.path, Route::Direct);
    assert_eq!(measured.rtt, Some(Duration::from_micros(740)));
    forward.shutdown();

    // A ping that says nothing measurable leaves the path Unknown.
    let silent =
        Fake::write("  forward) printf 'forwarding\\n'; exec sleep 3600 ;;\n  ping) exit 0 ;;\n");
    let forward = tailcat::start_forward(&silent.config(port), silent.path(), &controller).unwrap();
    let measured = forward.probe().unwrap();
    assert_eq!(measured.path, Route::Unknown);
    assert_eq!(measured.rtt, None);
    forward.shutdown();
}

#[test]
fn the_helper_runs_with_only_its_home_in_the_environment() {
    let fake = Fake::write(
        "  serve) env > \"$HOME/env.txt\"; printf 'listening on tcabcdefghijklmnopqrstuvwxyz0123\\n'; exec sleep 3600 ;;\n",
    );
    let server = tailcat::start_server(&fake.config(7443), fake.path(), &[]).unwrap();
    server.wait_ready(Duration::from_secs(10)).unwrap();
    let keydir = fake.path().join("tailcat");
    let env = fs::read_to_string(keydir.join("env.txt")).unwrap();
    assert!(
        env.lines()
            .any(|line| line == format!("HOME={}", keydir.display())),
        "{env}"
    );
    // The test process has PATH (and CARGO_* variables); none of it passes.
    // Only TLS trust overrides do, and only when the operator set them.
    assert!(std::env::var_os("PATH").is_some());
    for line in env.lines() {
        let name = line.split('=').next().unwrap_or_default();
        let trust = matches!(name, "SSL_CERT_FILE" | "SSL_CERT_DIR");
        assert!(
            matches!(name, "HOME" | "PWD" | "OLDPWD" | "SHLVL" | "_")
                || (trust && std::env::var_os(name).is_some()),
            "inherited {name}"
        );
    }
    server.shutdown();
}

#[test]
fn only_a_trusted_unchanged_helper_file_runs() {
    let fake = Fake::write(SERVE_FOREVER);
    let config = fake.config(7443);

    // Writable by the group: refused before anything runs.
    fs::set_permissions(&fake.binary, fs::Permissions::from_mode(0o770)).unwrap();
    let error = tailcat::start_server(&config, fake.path(), &[]).unwrap_err();
    assert!(error.to_string().contains("writable"), "{error}");
    fs::set_permissions(&fake.binary, fs::Permissions::from_mode(0o700)).unwrap();

    // A symlink to the right file is not followed.
    let link = fake.path().join("helper-link");
    std::os::unix::fs::symlink(&fake.binary, &link).unwrap();
    let mut linked = config.clone();
    linked.binary = link;
    assert!(tailcat::start_server(&linked, fake.path(), &[]).is_err());
    assert!(!fake.log.exists(), "nothing ran");

    // Replaced after a successful start: the next execution notices the new
    // file identity, re-hashes it and refuses it.
    let server = tailcat::start_server(&config, fake.path(), &[]).unwrap();
    server.wait_ready(Duration::from_secs(10)).unwrap();
    let serves = fake.calls("serve").len();
    let swapped = fake.path().join("swapped");
    fs::write(&swapped, "#!/bin/sh\nexec sleep 3600\n").unwrap();
    fs::set_permissions(&swapped, fs::Permissions::from_mode(0o700)).unwrap();
    fs::rename(&swapped, &fake.binary).unwrap();
    server.set_allow(&[key(KEY)]);
    wait_until("the swapped helper to be refused", || {
        matches!(server.telemetry().problem, Some(Error::Checksum { .. }))
    });
    assert_eq!(
        fake.calls("serve").len(),
        serves,
        "the swapped file never ran"
    );
    server.shutdown();
}

/// When set, this test binary plays a Sentinel process that is SIGKILLed.
const ORPHAN_ROLE: &str = "SENTINEL_TAILCAT_ORPHAN_DIR";

#[test]
fn a_killed_sentinel_takes_its_helper_with_it() {
    if let Some(dir) = std::env::var_os(ORPHAN_ROLE) {
        // The child role: start a helper, report its pid, and wait to die.
        let dir = PathBuf::from(dir);
        let config = TailcatConfig {
            enabled: true,
            binary: dir.join("helper"),
            sha256: digest_of(&dir.join("helper")),
            derpmap_url: None,
            region: None,
            listen_port: 7443,
        };
        let server = tailcat::start_server(&config, &dir, &[]).unwrap();
        server.wait_ready(Duration::from_secs(10)).unwrap();
        wait_until("the helper pid", || server.telemetry().pid.is_some());
        fs::write(
            dir.join("helper.pid.tmp"),
            server.telemetry().pid.unwrap().to_string(),
        )
        .unwrap();
        fs::rename(dir.join("helper.pid.tmp"), dir.join("helper.pid")).unwrap();
        std::thread::sleep(Duration::from_secs(3600));
        return;
    }
    let fake = Fake::write(SERVE_FOREVER);
    let mut sentinel = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "a_killed_sentinel_takes_its_helper_with_it",
            "--nocapture",
        ])
        .env(ORPHAN_ROLE, fake.path())
        .stdout(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let pid_file = fake.path().join("helper.pid");
    wait_until("the child's helper", || pid_file.exists());
    let helper: u32 = fs::read_to_string(&pid_file).unwrap().parse().unwrap();
    assert!(alive(helper));
    // SIGKILL: no destructor, no shutdown — only the kernel can clean up.
    sentinel.kill().unwrap();
    sentinel.wait().unwrap();
    wait_until("the orphaned helper to die", || !alive(helper));
}

#[test]
fn a_derp_map_url_with_mode_like_path_segments_is_accepted() {
    let fake = Fake::write(SERVE_FOREVER);
    let mut config = fake.config(7443);
    config.derpmap_url = Some("https://derp.example.com/files/all/derp.json".to_owned());
    let server = tailcat::start_server(&config, fake.path(), &[]).unwrap();
    server.wait_ready(Duration::from_secs(10)).unwrap();
    assert_eq!(
        fake.calls("serve"),
        vec![
            "argv serve --allow=none --derpmap-url=https://derp.example.com/files/all/derp.json 7443"
                .to_owned()
        ]
    );
    server.shutdown();
}

#[test]
fn a_lost_session_replaces_a_settled_helper_at_once_and_spares_a_young_one() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let fake =
        Fake::write("  forward) printf 'forwarding\\n'; exec sleep 3600 ;;\n  ping) exit 0 ;;\n");
    let controller = Address::parse(ADDRESS).unwrap();
    let forward = tailcat::start_forward_every(
        &fake.config(port),
        fake.path(),
        &controller,
        Duration::from_secs(3600),
    )
    .unwrap();
    wait_until("the forward", || forward.telemetry().pid.is_some());
    let first = forward.telemetry().pid.unwrap();
    // Too young to judge (the shipped settle time is 10 s): a controller
    // still coming up must not make the worker kill a successor before it
    // could connect.
    assert!(!forward.session_lost());
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(forward.telemetry().pid, Some(first));
    // Settled: one lost session replaces it at once, as a decision (no
    // back-off, no recorded problem)...
    let asked = Instant::now();
    assert!(forward.session_lost_after(Duration::from_millis(200)));
    wait_until("the replacement helper", || {
        forward.telemetry().pid.is_some_and(|pid| pid != first)
    });
    // ...and its successor is young again.
    assert!(!forward.session_lost());
    assert!(
        asked.elapsed() < Duration::from_millis(900),
        "{:?}",
        asked.elapsed()
    );
    assert!(!alive(first));
    assert_eq!(fake.calls("forward").len(), 2);
    assert!(forward.telemetry().problem.is_none());
    forward.shutdown();
}

/// The address a controller's rotated key is served at.
const ADDRESS2: &str = "tczyxwvutsrqponmlkjihgfedcba9876";

/// A fake that tells its key pairs apart: the default keys are `KEY` (worker)
/// and `ADDRESS`/`KEY` (controller), the rotated ones `OTHER` and
/// `ADDRESS2`/`OTHER`. A worker's `ping` with the rotated key succeeds only
/// once `$HOME/admitted` exists — the controller listing that key.
fn rotating() -> Fake {
    Fake::script(&format!(
        concat!(
            "  --version) printf 'tailcat v0.6.0\\n'; exit 0 ;;\n",
            "  genkey) case \"$*\" in\n",
            "    *--delete*) exit 0 ;;\n",
            "    *--key=client-rotated*) printf 'nodekey:{other}\\n' ;;\n",
            "    *--client*) printf 'nodekey:{key}\\n' ;;\n",
            "    *--key=rotated*) printf '{address2}\\n' ;;\n",
            "    *) printf '{address}\\n' ;;\n",
            "  esac; exit 0 ;;\n",
            "  parse) case \"$2\" in\n",
            "    {address2}) printf '\"ServerPublic\": \"nodekey:{other}\"\\n' ;;\n",
            "    *) printf '\"ServerPublic\": \"nodekey:{key}\"\\n' ;;\n",
            "  esac; exit 0 ;;\n",
            "  serve) case \"$*\" in\n",
            "    *--key=rotated*) printf 'listening on {address2}\\n' ;;\n",
            "    *) printf 'listening on {address}\\n' ;;\n",
            "  esac; exec sleep 3600 ;;\n",
            "  forward) printf 'forwarding\\n'; exec sleep 3600 ;;\n",
            "  ping) case \"$*\" in\n",
            "    *--key=client-rotated*) [ -e \"$HOME/admitted\" ] && exit 0; exit 1 ;;\n",
            "    *) exit 0 ;;\n",
            "  esac ;;\n",
        ),
        key = KEY,
        other = OTHER,
        address = ADDRESS,
        address2 = ADDRESS2,
    ))
}

fn recorded(path: &Path) -> String {
    fs::read_to_string(path).unwrap().trim().to_owned()
}

fn mode(path: &Path) -> u32 {
    fs::metadata(path).unwrap().permissions().mode() & 0o777
}

/// No node key or address, of either generation, in what a diagnostic prints.
fn assert_no_credentials(printed: &str) {
    for secret in [KEY, OTHER, ADDRESS, ADDRESS2] {
        assert!(!printed.contains(secret), "{printed}");
    }
}

#[test]
fn a_worker_key_rotates_only_once_the_controller_admits_it() {
    let fake = rotating();
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let config = fake.config(port);
    let controller = Address::parse(ADDRESS).unwrap();
    let forward = tailcat::start_forward_every(
        &config,
        fake.path(),
        &controller,
        Duration::from_millis(200),
    )
    .unwrap();
    let record = tailcat::nodekey_file(fake.path(), Role::Worker);
    assert_eq!(recorded(&record), key(KEY).expose());
    let plain = format!("argv forward --bind=127.0.0.1 {ADDRESS} {port}:{port}");
    wait_until("the forward", || {
        fake.calls("forward") == vec![plain.clone()]
    });

    // Staging generates a second key beside the active one and changes
    // nothing that runs. A second stage returns the same key.
    let staged = tailcat::stage_rotation(&config, fake.path(), Role::Worker).unwrap();
    assert_eq!(staged, key(OTHER));
    assert!(
        fake.calls("genkey")
            .contains(&"argv genkey --key=client-rotated --force --client".to_owned()),
        "{:?}",
        fake.calls("genkey")
    );
    let generated = fake.calls("genkey").len();
    assert_eq!(
        tailcat::stage_rotation(&config, fake.path(), Role::Worker).unwrap(),
        staged
    );
    assert_eq!(fake.calls("genkey").len(), generated, "staged once");
    assert_eq!(
        tailcat::staged_rotation(fake.path(), Role::Worker).unwrap(),
        Some(key(OTHER))
    );
    assert_eq!(
        mode(&fake.path().join("tailcat").join("staged.nodekey")),
        0o600
    );

    // The controller does not list the new key yet: the commit is refused
    // after a ping with that key, and the worker keeps its admitted key.
    let refused = tailcat::commit_rotation(&config, fake.path(), Role::Worker, Some(&controller))
        .unwrap_err();
    assert_no_credentials(&refused.to_string());
    assert_no_credentials(&format!("{refused:?}"));
    assert!(
        fake.calls("ping")
            .iter()
            .any(|call| call.contains("--key=client-rotated")),
        "{:?}",
        fake.calls("ping")
    );
    assert_eq!(recorded(&record), key(KEY).expose());
    std::thread::sleep(Duration::from_millis(600));
    assert!(
        fake.calls("forward").iter().all(|call| *call == plain),
        "an unadmitted key was used: {:?}",
        fake.calls("forward")
    );

    // Listed: the commit switches, the record names the new key and the old
    // private key is deleted through the helper.
    fs::write(fake.path().join("tailcat").join("admitted"), "").unwrap();
    let committed =
        tailcat::commit_rotation(&config, fake.path(), Role::Worker, Some(&controller)).unwrap();
    assert_eq!(committed.key, key(OTHER));
    assert!(committed.previous_deleted);
    assert_eq!(recorded(&record), key(OTHER).expose());
    assert_eq!(mode(&record), 0o600);
    assert_eq!(
        tailcat::staged_rotation(fake.path(), Role::Worker).unwrap(),
        None
    );
    assert!(
        fake.calls("genkey")
            .contains(&"argv genkey --delete --key=client-default".to_owned())
    );

    // The running worker follows within a probe interval: its helper and
    // its probes use the new key from then on.
    let rotated =
        format!("argv forward --bind=127.0.0.1 --key=client-rotated {ADDRESS} {port}:{port}");
    wait_until("the forward on the new key", || {
        fake.calls("forward").last() == Some(&rotated)
    });
    let pings = fake.calls("ping").len();
    wait_until("a probe with the new key", || {
        fake.calls("ping").len() > pings
    });
    assert!(
        fake.calls("ping")[pings..]
            .iter()
            .all(|call| call.contains("--key=client-rotated")),
        "{:?}",
        fake.calls("ping")
    );
    assert_no_credentials(&format!("{:?}", forward.telemetry()));

    // Nothing left to commit; a new rotation stages the other name, and
    // abandoning it deletes that key and changes nothing in use.
    assert!(
        tailcat::commit_rotation(&config, fake.path(), Role::Worker, Some(&controller)).is_err()
    );
    assert_eq!(
        tailcat::stage_rotation(&config, fake.path(), Role::Worker).unwrap(),
        key(KEY)
    );
    assert!(tailcat::abandon_rotation(&config, fake.path(), Role::Worker).unwrap());
    assert_eq!(
        fake.calls("genkey")
            .iter()
            .filter(|call| *call == "argv genkey --delete --key=client-default")
            .count(),
        2
    );
    assert_eq!(
        tailcat::staged_rotation(fake.path(), Role::Worker).unwrap(),
        None
    );
    assert!(!tailcat::abandon_rotation(&config, fake.path(), Role::Worker).unwrap());
    assert_eq!(recorded(&record), key(OTHER).expose());
    forward.shutdown();
}

#[test]
fn the_controller_serves_both_keys_until_its_rotation_commits() {
    let fake = rotating();
    let config = fake.config(7443);
    let worker = key(THIRD);
    let server =
        tailcat::start_server(&config, fake.path(), std::slice::from_ref(&worker)).unwrap();
    assert_eq!(
        server.wait_ready(Duration::from_secs(10)).unwrap().expose(),
        ADDRESS
    );
    let keydir = fake.path().join("tailcat");
    let staged_file = tailcat::staged_address_file(fake.path());
    assert_eq!(staged_file, keydir.join(tailcat::STAGED_ADDRESS_FILE));
    assert!(tailcat::commit_rotation(&config, fake.path(), Role::Controller, None).is_err());

    // A staged key is served beside the active one once the controller
    // reloads; abandoning it stops that helper and removes its address.
    tailcat::stage_rotation(&config, fake.path(), Role::Controller).unwrap();
    server.reload_keys().unwrap();
    wait_until("the staged address", || staged_file.exists());
    assert!(tailcat::abandon_rotation(&config, fake.path(), Role::Controller).unwrap());
    server.reload_keys().unwrap();
    assert!(server.staged_telemetry().is_none());
    assert!(!staged_file.exists());

    let staged = tailcat::stage_rotation(&config, fake.path(), Role::Controller).unwrap();
    assert_eq!(staged, key(OTHER));
    assert!(
        fake.calls("genkey")
            .contains(&"argv genkey --key=rotated --force --fixed-region".to_owned())
    );
    // Not served yet, so no worker can have its address: no commit.
    let early = tailcat::commit_rotation(&config, fake.path(), Role::Controller, None).unwrap_err();
    assert!(early.to_string().contains("has not served"), "{early}");

    server.reload_keys().unwrap();
    wait_until("the staged helper's address", || {
        server
            .staged_address()
            .is_some_and(|address| address.expose() == ADDRESS2)
    });
    assert_eq!(
        fs::read_to_string(&staged_file).unwrap(),
        format!("{ADDRESS2}\n")
    );
    assert_eq!(mode(&staged_file), 0o600);
    let both = |allow: &str| {
        let serves = fake.calls("serve");
        serves.contains(&format!("argv serve --allow={allow} 7443"))
            && serves.contains(&format!("argv serve --allow={allow} --key=rotated 7443"))
    };
    assert!(both(worker.expose()), "{:?}", fake.calls("serve"));
    // The active identity is untouched through the overlap.
    assert_eq!(server.address().unwrap().expose(), ADDRESS);
    assert_eq!(
        fs::read_to_string(keydir.join(tailcat::ADDRESS_FILE)).unwrap(),
        format!("{ADDRESS}\n")
    );
    assert_no_credentials(&format!("{:?}", server.staged_telemetry()));
    assert_no_credentials(&format!("{server:?}"));

    // An allow-list change reaches both helpers; an unchanged reload
    // restarts neither.
    let second = key(KEY);
    server.set_allow(&[worker.clone(), second.clone()]);
    // Sorted: THIRD's body sorts before KEY's.
    let widened = format!("{},{}", worker.expose(), second.expose());
    wait_until("both helpers on the wider list", || both(&widened));
    std::thread::sleep(Duration::from_millis(300));
    let serves = fake.calls("serve").len();
    server.reload_keys().unwrap();
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(
        fake.calls("serve").len(),
        serves,
        "a no-op reload restarted a helper"
    );

    // Commit: the address file names the new address at once, the record
    // the new key, and the old private key is deleted.
    let committed = tailcat::commit_rotation(&config, fake.path(), Role::Controller, None).unwrap();
    assert_eq!(committed.key, key(OTHER));
    assert!(committed.previous_deleted);
    assert_eq!(
        fs::read_to_string(keydir.join(tailcat::ADDRESS_FILE)).unwrap(),
        format!("{ADDRESS2}\n")
    );
    assert!(!staged_file.exists());
    assert_eq!(
        recorded(&tailcat::nodekey_file(fake.path(), Role::Controller)),
        key(OTHER).expose()
    );
    assert!(
        fake.calls("genkey")
            .contains(&"argv genkey --delete --key=default".to_owned())
    );

    // The running controller switches: the helper already serving the new
    // key becomes the main one without a restart (its workers keep their
    // tunnel), and the old key's helper stops.
    let (old_main, promoted) = (
        server.telemetry().pid.unwrap(),
        server.staged_telemetry().unwrap().pid.unwrap(),
    );
    let serves = fake.calls("serve").len();
    server.reload_keys().unwrap();
    assert!(server.staged_telemetry().is_none());
    assert_eq!(server.address().unwrap().expose(), ADDRESS2);
    assert_eq!(server.telemetry().pid, Some(promoted));
    assert!(!alive(old_main), "the old key is still served");
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(
        fake.calls("serve").len(),
        serves,
        "the switch restarted a helper"
    );
    assert_eq!(
        fs::read_to_string(keydir.join(tailcat::ADDRESS_FILE)).unwrap(),
        format!("{ADDRESS2}\n")
    );
    assert!(!staged_file.exists());

    // The promoted helper follows later allow-list changes, and a restart of
    // it keeps serving the committed key.
    server.set_allow(std::slice::from_ref(&worker));
    wait_until("the promoted helper on the narrower list", || {
        fake.calls("serve").last()
            == Some(&format!(
                "argv serve --allow={} --key=rotated 7443",
                worker.expose()
            ))
    });
    assert_eq!(
        server.wait_ready(Duration::from_secs(10)).unwrap().expose(),
        ADDRESS2
    );
    assert!(
        !staged_file.exists(),
        "the promoted helper wrote the staged file"
    );
    server.shutdown();
}

#[test]
fn the_allow_list_is_edited_per_worker_with_an_overlap_window() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(tailcat::ALLOW_LIST_FILE);
    let (one, two) = (WorkerId::new(), WorkerId::new());
    let old = Admission {
        key: key(KEY),
        worker: one,
    };
    let new = Admission {
        key: key(OTHER),
        worker: one,
    };
    let other = Admission {
        key: key(THIRD),
        worker: two,
    };

    // An absent list is created owner-only.
    assert!(tailcat::admit(dir.path(), &old).unwrap());
    assert_eq!(mode(&path), 0o600);
    fs::write(&path, format!("# builders\n{} {one}", key(KEY).expose())).unwrap();
    assert!(!tailcat::admit(dir.path(), &old).unwrap(), "already listed");
    // The worker's new key is listed beside its old one: both are admitted.
    assert!(tailcat::admit(dir.path(), &new).unwrap());
    assert!(tailcat::admit(dir.path(), &other).unwrap());
    let listed = tailcat::allow_list(dir.path()).unwrap();
    for admission in [&old, &new, &other] {
        assert!(listed.contains(admission));
    }
    assert_eq!(mode(&path), 0o600);

    // One key belongs to one worker; the refusal changes nothing.
    let before = fs::read_to_string(&path).unwrap();
    let taken = tailcat::admit(
        dir.path(),
        &Admission {
            key: key(OTHER),
            worker: two,
        },
    )
    .unwrap_err();
    assert_no_credentials(&taken.to_string());
    assert_eq!(fs::read_to_string(&path).unwrap(), before);

    // Retiring keeps the named key as the worker's only one, and every
    // other worker's line and every comment.
    assert_eq!(tailcat::retire(dir.path(), &new).unwrap(), 1);
    let listed = tailcat::allow_list(dir.path()).unwrap();
    assert_eq!(listed.len(), 2);
    assert!(listed.contains(&new) && listed.contains(&other));
    assert!(
        fs::read_to_string(&path)
            .unwrap()
            .starts_with("# builders\n")
    );
    assert_eq!(tailcat::retire(dir.path(), &new).unwrap(), 0);
    // A key that is not listed for that worker cannot be the one kept.
    let unlisted = tailcat::retire(dir.path(), &old).unwrap_err();
    assert_no_credentials(&unlisted.to_string());
    assert_eq!(tailcat::allow_list(dir.path()).unwrap().len(), 2);
}
