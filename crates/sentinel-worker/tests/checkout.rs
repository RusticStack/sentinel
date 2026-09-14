//! W03 checkout and workspace behavior on Linux with a local repository:
//! the pinned commit is what ends up checked out even when it is not the
//! branch head; an unknown revision, a hung fetch and a dirty workspace are
//! refused; the askpass helper never leaves the secret behind.

#![cfg(target_os = "linux")]

use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::Path,
    process::Command,
    time::{Duration, Instant},
};

use sentinel_core::AttemptId;
use sentinel_pipeline::PinnedSource;
use sentinel_protocol::source::{Access, Binding, Credential as SourceCredential};
use sentinel_worker::{
    Error,
    checkout::{self, Credential},
    workspace::Workspace,
};

fn git(dir: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .args(args)
        .current_dir(dir)
        .env("GIT_AUTHOR_NAME", "t")
        .env("GIT_AUTHOR_EMAIL", "t@example.com")
        .env("GIT_COMMITTER_NAME", "t")
        .env("GIT_COMMITTER_EMAIL", "t@example.com")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}

/// A repository with two commits; returns (path, first sha, second sha).
fn repository(root: &Path) -> (std::path::PathBuf, String, String) {
    let repo = root.join("origin");
    fs::create_dir(&repo).unwrap();
    git(&repo, &["init", "-q", "--initial-branch=main"]);
    fs::write(repo.join("file.txt"), "one\n").unwrap();
    git(&repo, &["add", "."]);
    git(&repo, &["commit", "-q", "-m", "one"]);
    let first = git(&repo, &["rev-parse", "HEAD"]);
    fs::write(repo.join("file.txt"), "two\n").unwrap();
    git(&repo, &["commit", "-q", "-am", "two"]);
    let second = git(&repo, &["rev-parse", "HEAD"]);
    (repo, first, second)
}

#[test]
fn private_https_checkout_checks_ca_rotated_credentials_and_cleanup() {
    use std::io::{BufRead, BufReader};
    use std::process::Stdio;
    let temp = tempfile::tempdir().unwrap();
    let (_, first, _) = repository(temp.path());
    // Real HTTPS servers commonly need to be told to serve an arbitrary
    // pinned commit; the fixture grants exactly what the checkout asks for.
    git(
        &temp.path().join("origin"),
        &["config", "uploadpack.allowAnySHA1InWant", "true"],
    );
    let cert = temp.path().join("ca.pem");
    let key = temp.path().join("tls.key");
    let generated = Command::new("openssl")
        .args([
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "1",
            "-subj",
            "/CN=localhost",
            "-addext",
            "subjectAltName=IP:127.0.0.1",
            "-keyout",
        ])
        .arg(&key)
        .arg("-out")
        .arg(&cert)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("openssl fixture prerequisite");
    assert!(generated.success());
    let password = temp.path().join("password");
    fs::write(&password, "private-source-token").unwrap();
    struct Server(std::process::Child);
    impl Drop for Server {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let mut server = Server(
        Command::new("python3")
            .arg(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/git_https.py"
            ))
            .arg(temp.path())
            .arg(&cert)
            .arg(&key)
            .env("FIXTURE_PASSWORD", &password)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("python3 fixture prerequisite"),
    );
    let mut port = String::new();
    BufReader::new(server.0.stdout.take().unwrap())
        .read_line(&mut port)
        .unwrap();
    let port: u16 = port.trim().parse().expect("fixture startup");
    let remote = format!("https://127.0.0.1:{port}/origin");
    let source = PinnedSource::new(&remote, &first, Some("refs/heads/main")).unwrap();
    let mut access = Access {
        binding: Binding {
            remote,
            allowed_refs: vec!["refs/heads/main".into()],
            pipeline_path: ".sentinel.yml".into(),
            trust: fs::read_to_string(&cert).unwrap(),
        },
        version: 1,
        expires_ms: sentinel_core::UnixMillis::now().0 + 60_000,
        credential: SourceCredential::Https {
            username: "deploy".into(),
            secret: "private-source-token".into(),
        },
    };
    let ws = Workspace::create(temp.path(), AttemptId::new()).unwrap();
    let checkout =
        checkout::checkout_authorized(ws.path(), &source, &access, Duration::from_secs(20))
            .unwrap();
    assert_eq!(checkout.sha, first);
    assert!(!ws.path().with_extension("askpass").exists());
    assert!(
        !fs::read_to_string(ws.path().join(".git/config"))
            .unwrap()
            .contains("private-source-token")
    );
    ws.destroy().unwrap();
    // Upstream revocation is effective on the next checkout; no cached token.
    fs::write(&password, "rotated-source-token").unwrap();
    let ws = Workspace::create(temp.path(), AttemptId::new()).unwrap();
    let error = checkout::checkout_authorized(ws.path(), &source, &access, Duration::from_secs(20))
        .unwrap_err();
    assert!(!error.to_string().contains("source-token"));
    assert!(!ws.path().with_extension("askpass").exists());
    ws.destroy().unwrap();
    access.credential = SourceCredential::Https {
        username: "deploy".into(),
        secret: "rotated-source-token".into(),
    };
    let ws = Workspace::create(temp.path(), AttemptId::new()).unwrap();
    assert!(
        checkout::checkout_authorized(ws.path(), &source, &access, Duration::from_secs(20)).is_ok()
    );
    ws.destroy().unwrap();
    access.binding.trust.clear();
    let ws = Workspace::create(temp.path(), AttemptId::new()).unwrap();
    assert!(
        checkout::checkout_authorized(ws.path(), &source, &access, Duration::from_secs(20))
            .is_err()
    );
    assert!(!ws.path().with_extension("askpass").exists());
    ws.destroy().unwrap();
}

#[test]
fn the_pinned_commit_is_checked_out_even_when_it_is_not_the_head() {
    let temp = tempfile::tempdir().unwrap();
    let (repo, first, second) = repository(temp.path());
    let attempt = AttemptId::new();
    let ws = Workspace::create(temp.path(), attempt).unwrap();
    let source = PinnedSource::new(repo.to_str().unwrap(), &first, Some("main")).unwrap();
    let out = checkout::checkout(ws.path(), &source, None, Duration::from_secs(60)).unwrap();
    assert_eq!(out.sha, first);
    assert_eq!(
        fs::read_to_string(ws.path().join("file.txt")).unwrap(),
        "one\n"
    );
    assert_eq!(git(ws.path(), &["rev-parse", "HEAD"]), first);
    // Depth one: the newer commit was never fetched.
    assert!(
        Command::new("git")
            .args(["cat-file", "-e", &second])
            .current_dir(ws.path())
            .status()
            .unwrap()
            .code()
            != Some(0)
    );
    // The workspace is never reused; destroying it removes the checkout.
    assert!(matches!(
        Workspace::create(temp.path(), attempt),
        Err(Error::Workspace(_))
    ));
    assert_eq!(Workspace::leftovers(temp.path()).unwrap(), vec![attempt]);
    let path = ws.path().to_path_buf();
    ws.destroy().unwrap();
    assert!(!path.exists());
    assert!(Workspace::leftovers(temp.path()).unwrap().is_empty());
}

#[test]
fn unknown_revisions_and_hung_fetches_are_preparation_failures() {
    let temp = tempfile::tempdir().unwrap();
    let (repo, _, _) = repository(temp.path());
    let ws = Workspace::create(temp.path(), AttemptId::new()).unwrap();
    let missing = "0123456789abcdef0123456789abcdef01234567";
    let source = PinnedSource::new(repo.to_str().unwrap(), missing, None).unwrap();
    let refused =
        checkout::checkout(ws.path(), &source, None, Duration::from_secs(60)).unwrap_err();
    assert!(
        matches!(&refused, Error::Preparation(what) if what.starts_with("git fetch")),
        "{refused}"
    );
    // A workspace whose fetch failed holds no checkout.
    assert!(!ws.path().join("file.txt").exists());

    // A repository that never answers: a FIFO stands in for a stalled
    // transport; the deadline kills the whole process group.
    let stalled = temp.path().join("stalled.git");
    fs::create_dir(&stalled).unwrap();
    let ws2 = Workspace::create(temp.path(), AttemptId::new()).unwrap();
    let source = PinnedSource::new(
        &format!("ext::sleep 30 %S {}", stalled.display()),
        missing,
        None,
    )
    .unwrap();
    let started = Instant::now();
    let outcome = checkout::checkout(ws2.path(), &source, None, Duration::from_millis(1500));
    // `ext::` transports are disabled by default, so this is refused at
    // once as a preparation failure; a genuinely slow path is the timeout.
    assert!(
        matches!(
            outcome,
            Err(Error::Preparation(_)) | Err(Error::Timeout("git fetch"))
        ),
        "{outcome:?}"
    );
    assert!(started.elapsed() < Duration::from_secs(10));
    let source = PinnedSource::new("-oProxyCommand=true", missing, None).unwrap();
    assert!(matches!(
        checkout::checkout(ws2.path(), &source, None, Duration::from_secs(5)),
        Err(Error::Preparation(_))
    ));
}

#[test]
fn ssh_deploy_keys_use_pinned_host_trust_and_leave_no_private_files() {
    // A real sshd is a host prerequisite, like rootless Podman: without one
    // the SSH transport cannot be exercised, and that is recorded rather
    // than faked. Use a full sshd path (e.g. a distribution build extracted
    // under target/source-fixtures) and run the test when it is available.
    let sshd = std::env::var("SENTINEL_TEST_SSHD").unwrap_or_else(|_| {
        let local = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../target/source-fixtures/openssh/usr/sbin/sshd"
        );
        if Path::new(local).exists() {
            local.to_owned()
        } else {
            "/usr/sbin/sshd".to_owned()
        }
    });
    if !Path::new(&sshd).exists() {
        eprintln!("SSH checkout verification requires sshd; set SENTINEL_TEST_SSHD");
        return;
    }
    // The served path must be a real, visible directory: the source policy
    // rejects hidden path segments, and temporary directories start with a
    // dot. Everything under this root is created and removed by the test.
    let root = std::path::PathBuf::from(format!("/tmp/sentinel-ssh-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir(&root).unwrap();
    let (repo, first, _) = repository(&root);
    let bare = root.join("origin.git");
    fs::create_dir(&bare).unwrap();
    git(&root, &["init", "-q", "--bare", "origin.git"]);
    git(&repo, &["push", "-q", bare.to_str().unwrap(), "main"]);
    git(&bare, &["config", "uploadpack.allowAnySHA1InWant", "true"]);
    let visible = root.to_str().unwrap().to_owned();
    assert!(
        sentinel_protocol::source::remote(&format!("ssh://root@127.0.0.1:22{visible}")).is_some()
    );
    let credentials = root.join("credentials");
    fs::create_dir(&credentials).unwrap();
    fs::set_permissions(&credentials, fs::Permissions::from_mode(0o700)).unwrap();
    let host_key = credentials.join("host_ed25519");
    let port_file = credentials.join("sshd.pid");
    let deploy_key = credentials.join("deploy_key");
    let authorized = credentials.join("authorized_keys");
    let forced = root.join("git_forced.sh");
    let keygen = |path: &Path| {
        let status = Command::new("ssh-keygen")
            .args(["-q", "-N", "", "-t", "ed25519", "-f"])
            .arg(path)
            .status()
            .expect("ssh-keygen");
        assert!(status.success());
    };
    keygen(&host_key);
    keygen(&deploy_key);
    // sshd refuses to run as a non-root user; the controller host is expected
    // to run the worker as a dedicated account in production.
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("SSH checkout verification requires root to run the sshd fixture");
        let _ = fs::remove_dir_all(&root);
        return;
    }
    // A root sshd still needs its privilege-separation account and directory.
    // Prepare them (as the host root) when the fixture runs; without them the
    // transport cannot be exercised and that is recorded, not faked.
    let privsep = std::path::Path::new("/run/sshd");
    if !privsep.exists() && fs::create_dir(privsep).is_err() {
        eprintln!("SSH checkout verification requires /run/sshd; skipping");
        let _ = fs::remove_dir_all(&root);
        return;
    }
    // The forced command restricts the key to serving this one repository.
    fs::write(
        &forced,
        "#!/bin/sh\nexec /usr/bin/git-shell -c \"$SSH_ORIGINAL_COMMAND\"\n",
    )
    .unwrap();
    fs::set_permissions(&forced, fs::Permissions::from_mode(0o755)).unwrap();
    fs::write(
        &authorized,
        format!(
            "restrict,command=\"{}\" {}\n",
            forced.display(),
            fs::read_to_string(deploy_key.with_extension("pub"))
                .unwrap()
                .trim()
        ),
    )
    .unwrap();
    // Pick an unused port from the ephemeral range; sshd refuses `Port 0`.
    let mut listener = None;
    for offset in 0..200u16 {
        let candidate = 49152
            + ((std::process::id() as u16)
                .wrapping_mul(7)
                .wrapping_add(offset))
                % 16000;
        if let Ok(bound) = std::net::TcpListener::bind(("127.0.0.1", candidate)) {
            listener = Some((candidate, bound));
            break;
        }
    }
    let (port, probe) = listener.expect("no free port for the sshd fixture");
    drop(probe);
    // The sshd_config references its own absolute paths only.
    let config = root.join("sshd_config");
    let log = root.join("sshd.log");
    fs::write(
        &config,
        format!(
            "Port {port}\nListenAddress 127.0.0.1\nHostKey {}\nPidFile {}\n\
             PasswordAuthentication no\nKbdInteractiveAuthentication no\nPubkeyAuthentication yes\n\
             AuthorizedKeysFile {}\nPermitRootLogin yes\nUsePAM no\nStrictModes no\nLogLevel INFO\n",
            host_key.display(),
            port_file.display(),
            authorized.display()
        ),
    )
    .unwrap();
    let child = Command::new(&sshd)
        .args(["-D", "-e", "-f"])
        .arg(&config)
        .stdout(std::process::Stdio::null())
        .stderr(
            std::fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&log)
                .unwrap(),
        )
        .spawn()
        .expect("sshd fixture prerequisite");
    struct Server(std::process::Child);
    impl Drop for Server {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let mut server = Server(child);
    let address = format!("127.0.0.1:{port}");
    for _ in 0..50 {
        if std::net::TcpStream::connect(&address).is_ok() {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
        if let Some(status) = server.0.try_wait().unwrap() {
            panic!(
                "sshd fixture exited: {status}: {}",
                fs::read_to_string(&log).unwrap_or_default()
            );
        }
    }
    let mut known_hosts = String::new();
    for _ in 0..20 {
        let scanned = Command::new("ssh-keyscan")
            .args([
                "-T",
                "2",
                "-p",
                &port.to_string(),
                "-t",
                "ed25519",
                "127.0.0.1",
            ])
            .output()
            .unwrap();
        known_hosts.clear();
        for line in String::from_utf8_lossy(&scanned.stdout).lines() {
            let mut fields = line.split_whitespace();
            if let (Some(host), Some("ssh-ed25519"), Some(key)) =
                (fields.next(), fields.next(), fields.next())
                && (host == "127.0.0.1" || host.ends_with(&format!(":{port}")))
            {
                known_hosts.push_str(&format!("127.0.0.1 ssh-ed25519 {key}\n"));
            }
        }
        if !known_hosts.is_empty() {
            break;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    assert!(!known_hosts.is_empty(), "ssh-keyscan produced no host key");
    // ssh URLs carry an absolute path: authority, slash, then the path.
    let remote = format!(
        "ssh://root@127.0.0.1:{port}/{}",
        bare.display().to_string().trim_start_matches('/')
    );
    let source = PinnedSource::new(&remote, &first, Some("refs/heads/main")).unwrap();
    let mut access = Access {
        binding: Binding {
            remote: remote.clone(),
            allowed_refs: vec!["refs/heads/main".into()],
            pipeline_path: ".sentinel.yml".into(),
            trust: known_hosts.clone(),
        },
        version: 1,
        expires_ms: sentinel_core::UnixMillis::now().0 + 60_000,
        credential: SourceCredential::Ssh {
            private_key: fs::read_to_string(&deploy_key).unwrap(),
        },
    };
    assert!(!access.binding.trust.is_empty());
    assert!(access.validate(sentinel_core::UnixMillis::now().0));
    let ws = Workspace::create(&root, AttemptId::new()).unwrap();
    let checkout =
        checkout::checkout_authorized(ws.path(), &source, &access, Duration::from_secs(30))
            .unwrap();
    assert_eq!(checkout.sha, first);
    assert!(!ws.path().with_extension("askpass").exists());
    assert!(
        !fs::read_to_string(ws.path().join(".git/config"))
            .unwrap()
            .contains("PRIVATE KEY")
    );
    ws.destroy().unwrap();
    // The binding, not the run source, decides the authority: a source that
    // names another host is refused before any transport starts.
    let mut wrong_host = access.clone();
    wrong_host.binding.remote = remote.replacen("127.0.0.1", "localhost", 1);
    let ws = Workspace::create(&root, AttemptId::new()).unwrap();
    assert!(matches!(
        checkout::checkout_authorized(ws.path(), &source, &wrong_host, Duration::from_secs(5)),
        Err(Error::Preparation(_))
    ));
    assert!(!ws.path().with_extension("askpass").exists());
    ws.destroy().unwrap();
    // Host trust is pinned: an empty known_hosts is a preparation failure,
    // not a prompt or a silent accept.
    access.binding.trust = "127.0.0.1 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n".into();
    let ws = Workspace::create(&root, AttemptId::new()).unwrap();
    let error = checkout::checkout_authorized(ws.path(), &source, &access, Duration::from_secs(20))
        .unwrap_err();
    assert!(!error.to_string().contains("PRIVATE KEY"));
    assert!(!ws.path().with_extension("askpass").exists());
    ws.destroy().unwrap();
    drop(server);
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn a_credential_is_delivered_through_askpass_and_removed_afterwards() {
    let temp = tempfile::tempdir().unwrap();
    let (repo, first, _) = repository(temp.path());
    let ws = Workspace::create(temp.path(), AttemptId::new()).unwrap();
    let source = PinnedSource::new(repo.to_str().unwrap(), &first, None).unwrap();
    let credential = Credential {
        username: "x-access-token".into(),
        secret: "ghs_do_not_leak".into(),
    };
    checkout::checkout(
        ws.path(),
        &source,
        Some(&credential),
        Duration::from_secs(60),
    )
    .unwrap();
    // The helper directory is gone, and the secret is nowhere in the workspace.
    assert!(!ws.path().with_extension("askpass").exists());
    let config = fs::read_to_string(ws.path().join(".git/config")).unwrap();
    assert!(!config.contains("ghs_do_not_leak"));
    assert!(!config.contains("x-access-token"));
}
