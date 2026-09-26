//! S03/S04 and the Part 10 secrets fixes through the real `sentinel` binary
//! against an in-process controller API: stdin byte preservation, rotate,
//! delete, exit codes, import preview pins, explicit idempotency replay, the
//! retry hint on an unknown outcome, binding/allowlist/revocation commands,
//! and a value typed as an argument never being echoed.

use std::{
    io::Write,
    process::{Command, Output, Stdio},
    sync::Arc,
};

use sentinel_auth::sealed::{Key, secret_context};
use sentinel_core::{
    RepoId, TenantId, UnixMillis,
    auth::{Namespace, Permissions as P, Principal, Role},
};
use sentinel_link::{controller::Controller, identity::Identity};
use sentinel_store::{
    Durability, Store,
    auth::{self, NamespaceKind},
    local_auth,
    logs::LogStore,
    objects::Objects,
    tokens::{self, Grant},
};
use serde_json::Value;

struct Deployment {
    dir: tempfile::TempDir,
    store: Arc<Store>,
    key: Arc<Key>,
    _controller: Controller,
    server: Option<sentinel_api::Server>,
    base: String,
    token: String,
    tenant: TenantId,
    repo: RepoId,
}

impl Drop for Deployment {
    fn drop(&mut self) {
        if let Some(server) = self.server.take() {
            server.shutdown();
        }
    }
}

fn deployment() -> Deployment {
    let dir = tempfile::tempdir().unwrap();
    let store =
        Arc::new(Store::open(dir.path().join("metadata.sqlite"), Durability::Normal).unwrap());
    let logs = Arc::new(LogStore::open(dir.path().join("logs")).unwrap());
    let objects = Arc::new(Objects::open(dir.path()).unwrap());
    let key_path = dir.path().join("master.key");
    Key::create(&key_path).unwrap();
    let key = Arc::new(Key::load(&key_path).unwrap());
    let now = UnixMillis::now();
    let root =
        local_auth::bootstrap(&store, "root", "Root", b"correct horse battery", now).unwrap();
    let (tenant, repo) = (TenantId::new(), RepoId::new());
    store
        .writer()
        .write(move |tx| {
            let admin = Principal::new(root, P::ALL, None, None);
            auth::create_namespace(
                tx,
                admin,
                tenant,
                Namespace::parse("acme").unwrap(),
                NamespaceKind::Organization,
                now,
            )?;
            auth::set_membership(tx, admin, tenant, root, Role::TenantAdmin)?;
            auth::create_repo(tx, admin, tenant, repo, "RusticStack/app", now)
        })
        .unwrap();
    let granted = tokens::provision(&store, Grant::new(root, "cli", P::ALL), now).unwrap();
    let controller = Controller::start(
        Arc::clone(&store),
        Arc::clone(&logs),
        Arc::clone(&objects),
        Identity::generate("controller").unwrap(),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    let server = sentinel_api::Server::start(sentinel_api::Config {
        listen: "127.0.0.1:0".parse().unwrap(),
        store: Arc::clone(&store),
        logs,
        objects,
        controller: controller.handle(),
        sessions: local_auth::Policy::default(),
        github_webhook_secret: None,
        intake: None,
        public_url: None,
        github_sign_in: None,
        secret_key: Some(Arc::clone(&key)),
    })
    .unwrap();
    Deployment {
        base: format!("http://{}", server.local_addr()),
        dir,
        store,
        key,
        _controller: controller,
        server: Some(server),
        token: sentinel_auth::token::format(&granted.secret),
        tenant,
        repo,
    }
}

fn cli_to(server: &str, d: &Deployment, args: &[&str], stdin: Option<&[u8]>) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_sentinel"))
        .env("SENTINEL_TOKEN", &d.token)
        .env("SENTINEL_SERVER", server)
        .env_remove("SENTINEL_PROFILE")
        .env("SENTINEL_CONFIG_DIR", d.dir.path().join("no-profiles"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    {
        let mut input = child.stdin.take().unwrap();
        if let Some(bytes) = stdin {
            input.write_all(bytes).unwrap();
        }
    }
    child.wait_with_output().unwrap()
}

fn cli(d: &Deployment, args: &[&str], stdin: Option<&[u8]>) -> Output {
    cli_to(&d.base, d, args, stdin)
}

fn code(output: &Output) -> i32 {
    output.status.code().unwrap()
}

fn err(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn json(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|_| panic!("{}", err(output)))
}

/// The stored plaintext of one version, opened with the deployment's key.
fn stored(d: &Deployment, repo: Option<RepoId>, name: &'static str, version: u64) -> Vec<u8> {
    let (tenant, key) = (d.tenant, d.key.clone());
    let sealed: Vec<u8> = d
        .store
        .read(move |c| {
            Ok(c.query_row(
                "SELECT v.sealed FROM secret_versions v JOIN secrets s ON s.id=v.secret_id
                 WHERE s.tenant_id=?1 AND s.name=?2 AND v.version=?3",
                (tenant.as_bytes().as_slice(), name, version as i64),
                |r| r.get(0),
            )?)
        })
        .unwrap();
    key.open(
        &secret_context(
            tenant.as_bytes(),
            repo.as_ref().map(RepoId::as_bytes),
            name,
            version,
        ),
        &sealed,
    )
    .unwrap()
}

const REPO: &str = "RusticStack/app";

#[test]
fn stdin_values_rotate_and_delete_with_stable_exit_codes() {
    let d = deployment();
    let scope = ["--tenant", "acme", "--repo", REPO];
    let set = cli(
        &d,
        &[
            &["secret", "--output", "json", "set", "TOKEN", "--stdin"][..],
            &scope,
        ]
        .concat(),
        Some(b"line one\r\n\xff"),
    );
    assert_eq!(code(&set), 0, "{}", err(&set));
    assert_eq!(json(&set)["version"], 1);
    assert_eq!(stored(&d, Some(d.repo), "TOKEN", 1), b"line one\r\n\xff");

    // Implicit stdin (not a terminal): the same byte-exact read.
    let implicit = cli(
        &d,
        &[&["secret", "set", "TOKEN"][..], &scope].concat(),
        Some(b"v2\n"),
    );
    assert_eq!(code(&implicit), 0, "{}", err(&implicit));
    assert_eq!(stored(&d, Some(d.repo), "TOKEN", 2), b"v2\n");

    let rotated = cli(
        &d,
        &[
            &["secret", "rotate", "TOKEN", "--stdin", "--if-version", "2"][..],
            &scope,
        ]
        .concat(),
        Some(b"v3"),
    );
    assert_eq!(code(&rotated), 0, "{}", err(&rotated));
    let stale = cli(
        &d,
        &[
            &["secret", "rotate", "TOKEN", "--stdin", "--if-version", "2"][..],
            &scope,
        ]
        .concat(),
        Some(b"stale-value"),
    );
    assert_eq!(code(&stale), 5);
    assert!(!err(&stale).contains("stale-value"));

    let deleted = cli(
        &d,
        &[
            &[
                "secret",
                "--output",
                "json",
                "delete",
                "TOKEN",
                "--if-version",
                "3",
            ][..],
            &scope,
        ]
        .concat(),
        None,
    );
    assert_eq!(code(&deleted), 0, "{}", err(&deleted));
    assert_eq!(json(&deleted)["active"], false);
    let missing = cli(
        &d,
        &[&["secret", "describe", "NOPE"][..], &scope].concat(),
        None,
    );
    assert_eq!(code(&missing), 4);
    let reuse = cli(
        &d,
        &[&["secret", "set", "TOKEN", "--stdin"][..], &scope].concat(),
        Some(b"again"),
    );
    assert_eq!(code(&reuse), 5);
}

/// P10C-2: a caller-chosen key makes a rerun replay the first write
/// instead of rotating again, and an unknown outcome names that retry.
#[test]
fn a_rerun_with_the_same_key_replays_and_an_unknown_outcome_names_it() {
    let d = deployment();
    let args = [
        "secret",
        "--output",
        "json",
        "set",
        "TOKEN",
        "--tenant",
        "acme",
        "--stdin",
        "--if-version",
        "0",
        "--idempotency-key",
        "agent-retry-1",
    ];
    let first = cli(&d, &args, Some(b"value"));
    let second = cli(&d, &args, Some(b"value"));
    assert_eq!((code(&first), code(&second)), (0, 0), "{}", err(&second));
    assert_eq!(json(&first), json(&second));
    assert_eq!(json(&second)["version"], 1);
    // The same key for a different value is a client bug, exit 5.
    let reused = cli(&d, &args, Some(b"other"));
    assert_eq!(code(&reused), 5);
    assert!(err(&reused).contains("idempotency_mismatch"));

    // No controller answers: the write's outcome is unknown (exit 6), and
    // the error names the key and version that would replay it.
    let unreachable = cli_to(
        "http://127.0.0.1:9",
        &d,
        &[
            "secret",
            "set",
            "OTHER",
            "--tenant",
            "acme",
            "--stdin",
            "--if-version",
            "0",
            "--idempotency-key",
            "agent-retry-2",
        ],
        Some(b"value"),
    );
    assert_eq!(code(&unreachable), 6, "{}", err(&unreachable));
    assert!(
        err(&unreachable).contains("--idempotency-key agent-retry-2 --if-version 0"),
        "{}",
        err(&unreachable)
    );
}

/// P10C-2 / P10C-4: preview reports literal-value hints and a pin; an
/// import bound to that pin refuses once a name moved.
#[test]
fn an_import_bound_to_its_preview_refuses_a_moved_version() {
    let d = deployment();
    let dir = d.dir.path().join("private");
    sentinel::keystore::file::ensure_private_dir(&dir).unwrap();
    let env = dir.join("app.env");
    std::fs::write(&env, b"\xEF\xBB\xBFA=\"quoted\"\r\nB=plain\r\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&env, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let env = env.to_str().unwrap();
    let a = cli(
        &d,
        &["secret", "set", "A", "--tenant", "acme", "--stdin"],
        Some(b"first"),
    );
    assert_eq!(code(&a), 0, "{}", err(&a));
    let preview = cli(
        &d,
        &[
            "secret",
            "--output",
            "json",
            "import",
            "--tenant",
            "acme",
            "--env-file",
            env,
            "--preview",
        ],
        None,
    );
    assert_eq!(code(&preview), 0, "{}", err(&preview));
    let document = json(&preview);
    assert_eq!(document["if_versions"], "A=1,B=0");
    assert_eq!(document["secrets"][0]["quoted"], true);
    assert_eq!(document["secrets"][1]["quoted"], false);
    assert!(!String::from_utf8_lossy(&preview.stdout).contains("plain"));
    let text = cli(
        &d,
        &[
            "secret",
            "import",
            "--tenant",
            "acme",
            "--env-file",
            env,
            "--preview",
        ],
        None,
    );
    assert!(String::from_utf8_lossy(&text.stdout).contains("pin: --if-versions A=1,B=0"));

    // Someone rotates A after the preview: the pinned import changes nothing.
    let moved = cli(
        &d,
        &[
            "secret",
            "rotate",
            "A",
            "--tenant",
            "acme",
            "--stdin",
            "--if-version",
            "1",
        ],
        Some(b"second"),
    );
    assert_eq!(code(&moved), 0);
    let pinned = cli(
        &d,
        &[
            "secret",
            "import",
            "--tenant",
            "acme",
            "--env-file",
            env,
            "--if-versions",
            "A=1,B=0",
        ],
        None,
    );
    assert_eq!(code(&pinned), 5, "{}", err(&pinned));
    let b = cli(&d, &["secret", "describe", "B", "--tenant", "acme"], None);
    assert_eq!(code(&b), 4);
    let imported = cli(
        &d,
        &[
            "secret",
            "--output",
            "json",
            "import",
            "--tenant",
            "acme",
            "--env-file",
            env,
        ],
        None,
    );
    assert_eq!(code(&imported), 0, "{}", err(&imported));
    assert_eq!(json(&imported)["secrets"][0]["version"], 3);
    assert_eq!(stored(&d, None, "A", 3), b"\"quoted\"");
    assert_eq!(stored(&d, None, "B", 1), b"plain");

    // A bare CR is refused with its line number, before any request.
    std::fs::write(dir.join("cr.env"), b"A=1\rB=2\r").unwrap();
    let cr = cli(
        &d,
        &[
            "secret",
            "import",
            "--tenant",
            "acme",
            "--env-file",
            dir.join("cr.env").to_str().unwrap(),
            "--preview",
        ],
        None,
    );
    assert_eq!(code(&cr), 2);
    assert!(err(&cr).contains("line 1"), "{}", err(&cr));
}

/// P10S-2: the documented provisioning flow runs entirely through the CLI.
#[test]
fn bindings_allowlists_and_revocation_run_through_the_cli() {
    let d = deployment();
    let tenant_secret = cli(
        &d,
        &["secret", "set", "SHARED", "--tenant", "acme", "--stdin"],
        Some(b"shared"),
    );
    assert_eq!(code(&tenant_secret), 0);
    let allow = cli(
        &d,
        &[
            "secret", "allow", "SHARED", "--tenant", "acme", "--repo", REPO,
        ],
        None,
    );
    assert_eq!(code(&allow), 0, "{}", err(&allow));
    let allowed = cli(
        &d,
        &[
            "secret", "--output", "json", "allowed", "SHARED", "--tenant", "acme",
        ],
        None,
    );
    assert_eq!(json(&allowed)["repos"][0]["name"], REPO);
    let bind = cli(
        &d,
        &[
            "secret",
            "--output",
            "json",
            "bind",
            "SHARED",
            "--tenant",
            "acme",
            "--repo",
            REPO,
            "--job",
            "build",
            "--step",
            "test",
            "--from-tenant",
        ],
        None,
    );
    assert_eq!(code(&bind), 0, "{}", err(&bind));
    assert_eq!(json(&bind)["step"], "test");
    let listed = cli(
        &d,
        &[
            "secret", "--output", "json", "bindings", "--tenant", "acme", "--repo", REPO,
        ],
        None,
    );
    assert_eq!(json(&listed)["bindings"][0]["name"], "SHARED");
    for _ in 0..2 {
        let unbind = cli(
            &d,
            &[
                "secret", "unbind", "SHARED", "--tenant", "acme", "--repo", REPO, "--job", "build",
                "--step", "test",
            ],
            None,
        );
        assert_eq!(code(&unbind), 0, "{}", err(&unbind));
    }
    let deny = cli(
        &d,
        &[
            "secret", "deny", "SHARED", "--tenant", "acme", "--repo", REPO,
        ],
        None,
    );
    assert_eq!(code(&deny), 0);

    for value in [&b"one"[..], b"two"] {
        let set = cli(
            &d,
            &["secret", "set", "ROTATED", "--tenant", "acme", "--stdin"],
            Some(value),
        );
        assert_eq!(code(&set), 0);
    }
    let revoked = cli(
        &d,
        &[
            "secret",
            "--output",
            "json",
            "revoke-version",
            "ROTATED",
            "--tenant",
            "acme",
            "1",
        ],
        None,
    );
    assert_eq!(code(&revoked), 0, "{}", err(&revoked));
    assert_eq!(json(&revoked)["secret"]["version"], 2);
    let absent = cli(
        &d,
        &[
            "secret",
            "revoke-version",
            "ROTATED",
            "9",
            "--tenant",
            "acme",
        ],
        None,
    );
    assert_eq!(code(&absent), 4);
}

/// P10C-5: a value mistakenly typed as an argument is refused and never
/// copied into stderr.
#[test]
fn a_value_typed_as_an_argument_is_never_echoed() {
    let d = deployment();
    for args in [
        &[
            "secret",
            "set",
            "TOKEN",
            "hunter2-positional",
            "--tenant",
            "acme",
        ][..],
        &[
            "secret",
            "set",
            "TOKEN",
            "--value",
            "hunter2-flag",
            "--tenant",
            "acme",
        ],
        &[
            "secret",
            "set",
            "TOKEN",
            "--value=hunter2-equals",
            "--tenant",
            "acme",
        ],
        &["secret", "import", "--env-file", "x", "hunter2-import"],
    ] {
        let out = cli(&d, args, None);
        assert_eq!(code(&out), 2, "{args:?}");
        let stderr = err(&out);
        assert!(!stderr.contains("hunter2"), "{stderr}");
        assert!(stderr.contains("--stdin"), "{stderr}");
    }
}
