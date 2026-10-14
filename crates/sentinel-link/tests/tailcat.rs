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

const KEY: &str = "0123456789abcdeffedcba98765432100123456789abcdeffedcba9876543210";
const OTHER: &str = "fedcba98765432100123456789abcdeffedcba98765432100123456789abcdef";
const THIRD: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
const ADDRESS: &str = "tcabcdefghijklmnopqrstuvwxyz0123";

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

    fn script(cases: &str) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("argv.log");
        // Not "tailcat": that name is the key directory inside this same temp dir.
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
    // Comma-separated --allow: a repeated flag keeps only its last value upstream.
    assert_eq!(
        fake.calls("serve"),
        vec![format!(
            "argv serve --allow={},{} 7443",
            first.expose(),
            second.expose()
        )]
    );

    assert!(!format!("{first}").contains(KEY));
    assert!(!format!("{first:?}").contains(KEY));
    assert!(!format!("{address:?}").contains(ADDRESS));
    assert!(!format!("{:?}", server.telemetry()).contains(ADDRESS));
    assert!(first.expose().ends_with(KEY));

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
fn a_stale_probe_never_replaces_the_successor_it_did_not_probe() {
    let marks = tempfile::tempdir().unwrap();
    let m = marks.path().display();
    let wait_for = |name: &str| {
        format!(
            "i=0; while [ ! -e \"{m}/{name}\" ] && [ $i -lt 400 ]; do sleep 0.05; i=$((i+1)); done"
        )
    };
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
    let deadline = Instant::now() + Duration::from_secs(30);
    while !marks.path().join("b").exists() {
        assert!(Instant::now() < deadline, "the successor never started");
        std::thread::sleep(Duration::from_millis(25));
    }
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
    assert_eq!(fake.calls("serve"), vec![allow_none()]);
    assert_eq!(
        fs::read_to_string(tailcat::nodekey_file(fake.path(), Role::Controller))
            .unwrap()
            .trim(),
        key(KEY).expose()
    );

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

    let old = server.telemetry().pid.unwrap();
    server.set_allow(&[]);
    wait_until("serve with no peer", || fake.calls("serve").len() == 3);
    assert_eq!(fake.calls("serve")[2], allow_none());
    wait_until("the old helper to be gone", || !alive(old));
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

    fs::set_permissions(&fake.binary, fs::Permissions::from_mode(0o770)).unwrap();
    let error = tailcat::start_server(&config, fake.path(), &[]).unwrap_err();
    assert!(error.to_string().contains("writable"), "{error}");
    fs::set_permissions(&fake.binary, fs::Permissions::from_mode(0o700)).unwrap();

    let link = fake.path().join("helper-link");
    std::os::unix::fs::symlink(&fake.binary, &link).unwrap();
    let mut linked = config.clone();
    linked.binary = link;
    assert!(tailcat::start_server(&linked, fake.path(), &[]).is_err());
    assert!(!fake.log.exists(), "nothing ran");

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

const ORPHAN_ROLE: &str = "SENTINEL_TAILCAT_ORPHAN_DIR";

#[test]
fn a_killed_sentinel_takes_its_helper_with_it() {
    if let Some(dir) = std::env::var_os(ORPHAN_ROLE) {
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
    assert!(!forward.session_lost());
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(forward.telemetry().pid, Some(first));
    let asked = Instant::now();
    assert!(forward.session_lost_after(Duration::from_millis(200)));
    wait_until("the replacement helper", || {
        forward.telemetry().pid.is_some_and(|pid| pid != first)
    });
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

const ADDRESS2: &str = "tczyxwvutsrqponmlkjihgfedcba9876";

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
    assert_eq!(server.address().unwrap().expose(), ADDRESS);
    assert_eq!(
        fs::read_to_string(keydir.join(tailcat::ADDRESS_FILE)).unwrap(),
        format!("{ADDRESS}\n")
    );
    assert_no_credentials(&format!("{:?}", server.staged_telemetry()));
    assert_no_credentials(&format!("{server:?}"));

    let second = key(KEY);
    server.set_allow(&[worker.clone(), second.clone()]);
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

    assert!(tailcat::admit(dir.path(), &old).unwrap());
    assert_eq!(mode(&path), 0o600);
    fs::write(&path, format!("# builders\n{} {one}", key(KEY).expose())).unwrap();
    assert!(!tailcat::admit(dir.path(), &old).unwrap(), "already listed");
    assert!(tailcat::admit(dir.path(), &new).unwrap());
    assert!(tailcat::admit(dir.path(), &other).unwrap());
    let listed = tailcat::allow_list(dir.path()).unwrap();
    for admission in [&old, &new, &other] {
        assert!(listed.contains(admission));
    }
    assert_eq!(mode(&path), 0o600);

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
    let unlisted = tailcat::retire(dir.path(), &old).unwrap_err();
    assert_no_credentials(&unlisted.to_string());
    assert_eq!(tailcat::allow_list(dir.path()).unwrap().len(), 2);
}

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

#[test]
fn a_hand_off_restarts_the_helper_only_on_a_change_and_spares_direct_tls() {
    use sentinel_link::{controller::Controller, identity::Identity, worker};
    use sentinel_store::{Durability, Store, auth::Authority, tenancy, workers};
    use std::sync::Arc;

    let state = tempfile::tempdir().unwrap();
    let store =
        Arc::new(Store::open(state.path().join("metadata.sqlite"), Durability::Normal).unwrap());
    let pool = sentinel_core::PoolId::new();
    let secret = store
        .writer()
        .write(move |tx| {
            let now = sentinel_core::UnixMillis::now();
            tenancy::create_pool(
                tx,
                Authority::HostLocal,
                pool,
                "p",
                tenancy::PoolKind::Shared,
                now,
            )?;
            workers::issue_enrollment(tx, Authority::HostLocal, pool, 600_000, now)
        })
        .unwrap()
        .secret;
    let controller = Controller::start(
        Arc::clone(&store),
        Arc::new(sentinel_store::logs::LogStore::open(state.path().join("logs")).unwrap()),
        Arc::new(sentinel_store::objects::Objects::open(state.path().join("objects")).unwrap()),
        Identity::generate("controller").unwrap(),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    let port = controller.local_addr().port();
    let link = controller.handle();

    let fake = Fake::write(SERVE_FOREVER);
    let server = tailcat::start_server(&fake.config(port), fake.path(), &[key(KEY)]).unwrap();
    server.wait_ready(Duration::from_secs(10)).unwrap();
    wait_until("the helper's pid", || server.telemetry().pid.is_some());

    let config = worker::Config {
        controller: controller.local_addr(),
        server: controller.fingerprint(),
        also_pinned: Vec::new(),
        worker: WorkerId::new(),
        name: "direct".into(),
        hello: sentinel_protocol::negotiate::Hello {
            protocol_min: sentinel_protocol::negotiate::ProtocolVersion(1),
            protocol_max: sentinel_protocol::negotiate::SUPPORTED_MAX,
            capabilities: sentinel_protocol::negotiate::Capabilities::REQUIRED,
            arch: sentinel_protocol::negotiate::Arch::X86_64,
            software: "direct".into(),
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
    let handle = Arc::new(worker::Handle::new());
    let running = {
        let handle = Arc::clone(&handle);
        std::thread::spawn(move || {
            let _ = worker::run(
                config,
                Identity::generate("worker").unwrap(),
                Some(secret),
                &Idle,
                &handle,
                &|_| {},
            );
        })
    };
    wait_until("the direct session", || link.connected().len() == 1);

    assert_eq!(link.hand_off(&server, &[key(KEY), key(KEY)]), None);
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(fake.calls("serve").len(), 1);

    let old = server.telemetry().pid.unwrap();
    let handoff = link.hand_off(&server, &[key(KEY), key(OTHER)]).unwrap();
    assert_eq!(
        (handoff.tunnelled, handoff.closed, handoff.ended),
        (0, 0, 0)
    );
    wait_until("the restarted helper", || fake.calls("serve").len() == 2);
    wait_until("the old helper to be gone", || !alive(old));
    std::thread::sleep(Duration::from_millis(500));
    assert_eq!(handle.sessions(), 1, "the direct-TLS session was closed");
    assert_eq!(
        controller
            .stats()
            .sessions_ended
            .load(std::sync::atomic::Ordering::Relaxed),
        0
    );
    assert_eq!(link.connected().len(), 1);

    handle.stop();
    running.join().unwrap();
    server.shutdown();
    assert!(controller.shutdown(Duration::from_secs(5)));
}

#[test]
fn a_hand_off_closes_a_carried_connection_still_in_its_handshake() {
    use sentinel_link::{controller::Controller, identity::Identity};
    use sentinel_store::{Durability, Store};
    use std::sync::Arc;

    let state = tempfile::tempdir().unwrap();
    let store =
        Arc::new(Store::open(state.path().join("metadata.sqlite"), Durability::Normal).unwrap());
    let controller = Controller::start(
        store,
        Arc::new(sentinel_store::logs::LogStore::open(state.path().join("logs")).unwrap()),
        Arc::new(sentinel_store::objects::Objects::open(state.path().join("objects")).unwrap()),
        Identity::generate("controller").unwrap(),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    let port = controller.local_addr().port();
    let link = controller.handle();

    let received = state.path().join("received");
    let fake = Fake::write(&format!(
        "  serve) printf 'listening on {ADDRESS}\\n'; exec bash -c 'exec 3<>/dev/tcp/127.0.0.1/{port}; exec cat <&3 > \"$0.$$\"' {} ;;\n",
        received.display()
    ));
    let server = tailcat::start_server(&fake.config(port), fake.path(), &[key(KEY)]).unwrap();
    server.wait_ready(Duration::from_secs(10)).unwrap();
    wait_until("the helper's pid", || server.telemetry().pid.is_some());
    let old = server.telemetry().pid.unwrap();
    let file = PathBuf::from(format!("{}.{old}", received.display()));
    wait_until("the helper's dial", || file.exists());
    std::thread::sleep(Duration::from_millis(300));

    let handoff = link.hand_off(&server, &[key(KEY), key(OTHER)]).unwrap();
    assert_eq!(
        (
            handoff.tunnelled,
            handoff.closed,
            handoff.arrivals,
            handoff.ended
        ),
        (1, 0, 1, 1),
        "{handoff:?}"
    );
    let bytes = fs::read(&file).unwrap();
    assert_eq!(bytes.len(), 7, "{bytes:?}");
    assert_eq!((bytes[0], &bytes[5..]), (21, &[1u8, 0][..]), "{bytes:?}");
    assert_eq!(
        controller
            .stats()
            .rejected
            .load(std::sync::atomic::Ordering::Relaxed),
        0,
        "a handed-off connection is not a rejected one"
    );
    wait_until("the old helper to be gone", || !alive(old));

    server.shutdown();
    assert!(controller.shutdown(Duration::from_secs(5)));
}
