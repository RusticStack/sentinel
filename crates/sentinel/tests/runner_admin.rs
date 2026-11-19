//! The host-local runner-mode command (AR01), against a real controller database: what the
//! deployment serves, what the App's installations still lack, and the switch refused until
//! nothing is missing.

#![cfg(all(target_os = "linux", feature = "server"))]

use std::{
    io::Write,
    path::Path,
    process::{Command, Output, Stdio},
};

use sentinel_core::{TenantId, UnixMillis};
use sentinel_store::{Durability, Store, lookup, sources_forge};

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

    fn ok(&self, args: &[&str]) -> Output {
        let output = self.admin(args, PASSWORD);
        assert!(
            output.status.success(),
            "{args:?}: {}",
            text(&output.stderr)
        );
        output
    }

    /// Records what GitHub last said about the tenant's installation: a fresh snapshot is
    /// exactly how a permission change reaches the controller.
    fn installation(&self, tenant: TenantId, runner: sentinel_core::RunnerPermissions) {
        let store = Store::open(self.dir.join("metadata.sqlite"), Durability::Full).unwrap();
        let (version, bound) = store
            .read(move |c| {
                Ok(c.query_row(
                    "SELECT COALESCE(MAX(lifecycle_version), 0),
                            COALESCE(MAX(tenant_id IS NOT NULL), 0)
                     FROM installations WHERE external_id = '42'",
                    [],
                    |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?)),
                )?)
            })
            .unwrap();
        let now = UnixMillis::now();
        store
            .writer()
            .write(move |tx| {
                let installation = sources_forge::refresh(
                    tx,
                    sources_forge::Snapshot {
                        external_id: 42,
                        account_id: 73,
                        login: "account",
                        personal: false,
                        suspended: false,
                        permissions_valid: true,
                        runner,
                        expected: version as u64,
                    },
                    now,
                )?;
                if bound == 0 {
                    sentinel_store::registration::bind_installation_trusted(
                        tx,
                        installation,
                        tenant,
                        now,
                    )?;
                }
                Ok(())
            })
            .unwrap();
    }

    fn tenant(&self) -> TenantId {
        let store = Store::open(self.dir.join("metadata.sqlite"), Durability::Full).unwrap();
        store.read(|c| lookup::tenant_by_slug(c, "acme")).unwrap()
    }
}

fn controller(root: &Path) -> Controller<'_> {
    std::fs::create_dir_all(root).unwrap();
    let c = Controller { dir: root };
    c.ok(&["bootstrap", "--username", "root"]);
    c.ok(&["tenant", "create", "--slug", "acme"]);
    c
}

#[test]
fn the_command_shows_the_switch_and_refuses_it_until_the_installations_grant_what_it_needs() {
    let dir = tempfile::tempdir().unwrap();
    let c = controller(dir.path());
    let tenant = c.tenant();

    // Nothing is served and nothing is installed yet: the switch reads off, and setting what
    // it already is succeeds.
    let shown = c.ok(&["runner-mode", "show", "--tenant", "acme"]);
    let shown = text(&shown.stdout);
    assert!(shown.contains("tenant: tnt_"), "{shown}");
    assert!(shown.contains("runner mode: off"), "{shown}");
    assert!(shown.contains("classes: none"), "{shown}");
    assert!(shown.contains("missing: none"), "{shown}");
    c.ok(&[
        "runner-mode",
        "set",
        "--tenant",
        "acme",
        "--enabled",
        "false",
    ]);

    // Enabling without an installation says exactly that.
    let refused = c.admin(
        &[
            "runner-mode",
            "set",
            "--tenant",
            "acme",
            "--enabled",
            "true",
        ],
        PASSWORD,
    );
    assert!(!refused.status.success());
    assert!(
        text(&refused.stderr)
            .contains("the tenant has no GitHub App installation to register a runner through"),
        "{}",
        text(&refused.stderr)
    );

    // An installation that grants only one of the two is refused naming the other, and the
    // switch stays off.
    c.installation(
        tenant,
        sentinel_core::RunnerPermissions::grants(true, false),
    );
    let refused = c.admin(
        &[
            "runner-mode",
            "set",
            "--tenant",
            "acme",
            "--enabled",
            "true",
        ],
        PASSWORD,
    );
    assert!(!refused.status.success());
    assert!(
        text(&refused.stderr)
            .contains("runner mode needs the GitHub App to grant organization_self_hosted_runners"),
        "{}",
        text(&refused.stderr)
    );
    let shown = text(&c.ok(&["runner-mode", "show", "--tenant", "acme"]).stdout);
    assert!(shown.contains("runner mode: off"), "{shown}");
    assert!(
        shown.contains("missing: organization_self_hosted_runners"),
        "{shown}"
    );

    // With both granted the switch is accepted, and a repeat changes nothing.
    c.installation(tenant, sentinel_core::RunnerPermissions::ALL);
    let set = c.ok(&[
        "runner-mode",
        "set",
        "--tenant",
        "acme",
        "--enabled",
        "true",
    ]);
    assert!(
        text(&set.stdout).contains(&format!("runner mode on for {tenant}")),
        "{}",
        text(&set.stdout)
    );
    let again = c.ok(&[
        "runner-mode",
        "set",
        "--tenant",
        "acme",
        "--enabled",
        "true",
    ]);
    assert!(
        text(&again.stdout).contains("was already so"),
        "{}",
        text(&again.stdout)
    );
    let shown = text(&c.ok(&["runner-mode", "show", "--tenant", "acme"]).stdout);
    assert!(shown.contains("runner mode: on"), "{shown}");
    assert!(shown.contains("missing: none"), "{shown}");

    // The identifier names the same tenant as the slug.
    let by_id = text(
        &c.ok(&["runner-mode", "show", "--tenant", &tenant.to_string()])
            .stdout,
    );
    assert!(by_id.contains("runner mode: on"), "{by_id}");
}

#[test]
fn an_unknown_tenant_and_an_unreadable_class_policy_are_refused_by_name() {
    let dir = tempfile::tempdir().unwrap();
    let c = controller(dir.path());
    let unknown = c.admin(&["runner-mode", "show", "--tenant", "nobody"], PASSWORD);
    assert!(!unknown.status.success());
    assert!(
        text(&unknown.stderr).contains("no active tenant with that slug"),
        "{}",
        text(&unknown.stderr)
    );

    // The classes this deployment serves are its own file, read by the command it is asked of.
    std::fs::write(
        dir.path().join("runner-classes.json"),
        br#"{"classes": ["sentinel-2vcpu-ubuntu-2404", "sentinel-4vcpu-windows-2025"]}"#,
    )
    .unwrap();
    let shown = text(&c.ok(&["runner-mode", "show", "--tenant", "acme"]).stdout);
    assert!(
        shown.contains("classes: sentinel-2vcpu-ubuntu-2404, sentinel-4vcpu-windows-2025"),
        "{shown}"
    );
    std::fs::write(
        dir.path().join("runner-classes.json"),
        br#"{"classes": ["sentinel-2vcpu-ubuntu-2204"]}"#,
    )
    .unwrap();
    let broken = c.admin(&["runner-mode", "show", "--tenant", "acme"], PASSWORD);
    assert!(!broken.status.success());
    assert!(
        text(&broken.stderr).contains("cannot load the runner class policy"),
        "{}",
        text(&broken.stderr)
    );

    // The provisioning bounds and the runner group are optional, and a value that is not an id or
    // not a bound refuses the file the same way a malformed class does.
    for (policy, ok) in [
        (
            r#"{"classes": ["sentinel-2vcpu-ubuntu-2404"], "runner_group_id": 4, "idle_ms": 60000, "reconcile_ms": 120000}"#,
            true,
        ),
        (
            r#"{"classes": ["sentinel-2vcpu-ubuntu-2404"], "runner_group_id": 0}"#,
            false,
        ),
        (
            r#"{"classes": ["sentinel-2vcpu-ubuntu-2404"], "idle_ms": 10}"#,
            false,
        ),
        (
            r#"{"classes": ["sentinel-2vcpu-ubuntu-2404"], "reconcile_ms": 1}"#,
            false,
        ),
        (
            r#"{"classes": ["sentinel-2vcpu-ubuntu-2404"], "reconcile_ms": 86400001}"#,
            false,
        ),
        (
            r#"{"classes": ["sentinel-2vcpu-ubuntu-2404"], "unknown_key": 1}"#,
            false,
        ),
    ] {
        std::fs::write(dir.path().join("runner-classes.json"), policy.as_bytes()).unwrap();
        let shown = c.admin(&["runner-mode", "show", "--tenant", "acme"], PASSWORD);
        assert_eq!(
            shown.status.success(),
            ok,
            "{policy}: {}",
            text(&shown.stderr)
        );
    }
}
