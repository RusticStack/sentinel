//! The host-policy and Tailcat-authorization admin commands (Q11, Q12), run against a real controller
//! database: ceilings and priority approved at enrollment and changed later, the node key authorized
//! through the enrollment, an uninstall request, and keys that stay on standard input.

#![cfg(all(target_os = "linux", feature = "server"))]

use std::{
    fs,
    io::Write,
    path::Path,
    process::{Command, Output, Stdio},
};

const KEY: &str = "0123456789abcdeffedcba98765432100123456789abcdeffedcba9876543210";
const PASSWORD: &str = "correct horse battery staple";

fn sentinel(args: &[&str], stdin: &str) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_sentinel"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

struct Controller<'a> {
    dir: &'a Path,
}

impl Controller<'_> {
    fn admin(&self, args: &[&str], stdin: &str) -> Output {
        let mut full = vec!["admin"];
        full.extend_from_slice(args);
        let dir = self.dir.to_str().unwrap();
        full.extend_from_slice(&["--data-dir", dir]);
        sentinel(&full, stdin)
    }

    fn ok(&self, args: &[&str], stdin: &str) -> Output {
        let output = self.admin(args, stdin);
        assert!(
            output.status.success(),
            "{args:?}: {}",
            text(&output.stderr)
        );
        output
    }
}

fn controller(root: &Path) -> Controller<'_> {
    fs::create_dir_all(root).unwrap();
    let c = Controller { dir: root };
    c.ok(&["bootstrap", "--username", "root"], PASSWORD);
    c.ok(&["tenant", "create", "--slug", "acme"], PASSWORD);
    c.ok(
        &["pool", "create", "--name", "builders", "--tenant", "acme"],
        PASSWORD,
    );
    c
}

/// The line the bootstrap script's `identity` prints, for a worker identifier of our choosing.
fn identity_line(worker: &str) -> String {
    format!("nodekey:{KEY} {worker}\n")
}

#[test]
fn a_tailcat_enrollment_authorizes_its_key_once_and_revoking_withdraws_it() {
    let root = tempfile::tempdir().unwrap();
    let controller_dir = root.path().join("controller");
    let c = controller(&controller_dir);
    let worker = sentinel_core::WorkerId::new().to_string();

    let issued = c.ok(
        &[
            "worker",
            "enroll",
            "--pool",
            "builders",
            "--transport",
            "tailcat",
            "--cpu-millis",
            "4000",
            "--priority",
            "-10",
        ],
        "",
    );
    let stderr = text(&issued.stderr);
    let enrollment = stderr
        .split_whitespace()
        .find(|word| word.starts_with("tok_"))
        .unwrap_or_else(|| panic!("no enrollment id in {stderr}"))
        .to_owned();
    assert!(
        stderr.contains("tailcat authorize --enrollment"),
        "{stderr}"
    );

    // The key goes in on standard input and the enrollment decides whether it is accepted.
    let line = identity_line(&worker);
    let authorized = c.ok(
        &["tailcat", "authorize", "--enrollment", &enrollment],
        &line,
    );
    assert!(
        !text(&authorized.stderr).contains(KEY) && !text(&authorized.stdout).contains(KEY),
        "a node key must stay on standard input"
    );
    // Authorizing the same pair again is a no-op; another worker for the same enrollment is refused.
    c.ok(
        &["tailcat", "authorize", "--enrollment", &enrollment],
        &line,
    );
    let other = c.admin(
        &["tailcat", "authorize", "--enrollment", &enrollment],
        &identity_line(&sentinel_core::WorkerId::new().to_string()),
    );
    assert_eq!(other.status.code(), Some(2));
    assert!(text(&other.stderr).contains("no longer pending"));
    let unknown = c.admin(&["tailcat", "authorize", "--enrollment", "tok_nope"], &line);
    assert_eq!(unknown.status.code(), Some(2));

    // A direct enrollment takes no key.
    let direct = c.ok(&["worker", "enroll", "--pool", "builders"], "");
    let direct_id = text(&direct.stderr)
        .split_whitespace()
        .find(|word| word.starts_with("tok_"))
        .unwrap()
        .to_owned();
    let refused = c.admin(
        &["tailcat", "authorize", "--enrollment", &direct_id],
        &identity_line(&sentinel_core::WorkerId::new().to_string()),
    );
    assert_eq!(refused.status.code(), Some(2));
    assert!(text(&refused.stderr).contains("direct TLS"));

    // Revoking takes a hand-listed worker's keys off the list file.
    c.ok(&["tailcat", "allow"], &line);
    let allow = controller_dir.join("tailcat-allow");
    assert!(fs::read_to_string(&allow).unwrap().contains(&worker));
    let revoked = c.ok(&["tailcat", "revoke", "--id", &worker], "");
    assert!(text(&revoked.stderr).contains("removed 1"));
    assert_eq!(fs::read_to_string(&allow).unwrap(), "");
}

#[test]
fn host_policy_is_shown_changed_and_validated_through_the_admin_commands() {
    let root = tempfile::tempdir().unwrap();
    let controller_dir = root.path().join("controller");
    let c = controller(&controller_dir);

    // A worker exists once an enrollment is redeemed; do that through the store.
    let secret = c
        .ok(
            &[
                "worker",
                "enroll",
                "--pool",
                "builders",
                "--cpu-millis",
                "4000",
                "--memory-bytes",
                "8589934592",
                "--priority",
                "25",
            ],
            "",
        )
        .stdout;
    let secret = sentinel_auth::token::parse(text(&secret).trim())
        .expect("an enrollment secret on standard output");
    let worker = sentinel_core::WorkerId::new();
    let store = sentinel_store::Store::open(
        controller_dir.join("metadata.sqlite"),
        sentinel_store::Durability::Normal,
    )
    .unwrap();
    store
        .writer()
        .write(move |tx| {
            sentinel_store::workers::redeem_authorized(
                tx,
                &secret,
                sentinel_store::workers::Presentation {
                    worker,
                    fingerprint: sentinel_auth::secret::Secret::generate().digest(),
                    name: "builder",
                    negotiated: sentinel_protocol::negotiate::Negotiated {
                        protocol: sentinel_protocol::negotiate::ProtocolVersion(1),
                        capabilities: sentinel_protocol::negotiate::Capabilities::REQUIRED,
                        arch: sentinel_protocol::negotiate::Arch::X86_64,
                    },
                },
                sentinel_core::UnixMillis::now(),
            )
            .map(|_| ())
        })
        .unwrap();
    store
        .writer()
        .write(move |tx| {
            sentinel_store::dispatch::report_capacity(
                tx,
                worker,
                sentinel_store::dispatch::Capacity {
                    cpu_millis: 16_000,
                    memory_bytes: 64 << 30,
                    disk_bytes: 0,
                },
            )
        })
        .unwrap();
    drop(store);
    let id = worker.to_string();

    let shown = text(&c.ok(&["worker", "policy", "--id", &id], "").stdout);
    assert!(
        shown.contains(
            "approved  cpu_millis=4000 memory_bytes=8589934592 disk_bytes=none priority=25"
        ),
        "{shown}"
    );
    assert!(shown.contains("reported  cpu_millis=16000"), "{shown}");
    assert!(shown.contains("effective cpu_millis=4000"), "{shown}");

    // Only the flags given change; a raise applies at once, up to the report.
    let raised = text(
        &c.ok(
            &[
                "worker",
                "policy",
                "--id",
                &id,
                "--cpu-millis",
                "32000",
                "--priority",
                "-5",
            ],
            "",
        )
        .stdout,
    );
    assert!(raised.contains("memory_bytes=8589934592"), "{raised}");
    assert!(raised.contains("priority=-5"), "{raised}");
    assert!(raised.contains("effective cpu_millis=16000"), "{raised}");
    let removed = text(
        &c.ok(
            &["worker", "policy", "--id", &id, "--memory-bytes", "none"],
            "",
        )
        .stdout,
    );
    assert!(removed.contains("memory_bytes=none"), "{removed}");

    for bad in [
        vec!["--cpu-millis", "0"],
        vec!["--cpu-millis", "lots"],
        vec!["--priority", "101"],
    ] {
        let mut args = vec!["worker", "policy", "--id", &id];
        args.extend(bad.iter());
        let refused = c.admin(&args, "");
        assert_eq!(refused.status.code(), Some(2), "{bad:?}");
    }
    let missing = c.admin(
        &[
            "worker",
            "policy",
            "--id",
            &sentinel_core::WorkerId::new().to_string(),
        ],
        "",
    );
    assert_eq!(missing.status.code(), Some(2));

    // An uninstall request drains the worker; it is revoked by the controller once its work settles.
    let asked = c.ok(&["worker", "uninstall", "--id", &id], "");
    assert!(text(&asked.stderr).contains("draining"));
    let store = sentinel_store::Store::open(
        controller_dir.join("metadata.sqlite"),
        sentinel_store::Durability::Normal,
    )
    .unwrap();
    assert!(store.read(sentinel_store::workers::uninstalling).unwrap());
}
