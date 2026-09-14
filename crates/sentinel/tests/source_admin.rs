//! G01 host-local surface: a bootstrapped operator creates a repository and
//! binds a source through `sentinel admin source` with nothing but the
//! database file, and the metadata output never contains the credential.
#![cfg(all(target_os = "linux", feature = "server"))]

use std::{fs, io::Write as _, process::Command};

fn invoke(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_sentinel"))
        .args(args)
        .output()
        .expect("run sentinel")
}

fn ok(args: &[&str]) -> String {
    let output = invoke(args);
    assert!(
        output.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

fn fails(args: &[&str]) -> std::process::Output {
    let output = invoke(args);
    assert_eq!(output.status.code(), Some(2), "{args:?}");
    output
}

/// Run with `stdin` fed from a string; returns the finished output.
fn with_stdin(args: &[&str], input: &str) -> std::process::Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_sentinel"))
        .args(args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

#[test]
fn a_host_local_operator_binds_a_source_and_sees_no_credential() {
    let dir = tempfile::tempdir().unwrap();
    let data_path = dir.path().join("controller");
    fs::create_dir(&data_path).unwrap();
    let data = data_path.to_str().unwrap();
    let bootstrap = with_stdin(
        &[
            "admin",
            "bootstrap",
            "--data-dir",
            data,
            "--username",
            "root",
        ],
        "correct horse battery staple",
    );
    assert!(
        bootstrap.status.success(),
        "{}",
        String::from_utf8_lossy(&bootstrap.stderr)
    );
    assert!(
        bootstrap.status.success(),
        "{}",
        String::from_utf8_lossy(&bootstrap.stderr)
    );
    let status = ok(&["admin", "status", "--data-dir", data]);
    let actor = status
        .split("subject=")
        .nth(1)
        .and_then(|rest| rest.split_whitespace().next())
        .expect("bootstrap audit names the account")
        .to_owned();
    ok(&["admin", "key", "create", "--data-dir", data]);
    let tenant = ok(&[
        "admin",
        "tenant",
        "create",
        "--data-dir",
        data,
        "--slug",
        "acme",
    ]);
    let tenant = tenant.trim().to_owned();
    fs::write(
        data_path.join("source-destinations.json"),
        "[\"https://git.example:8443\"]",
    )
    .unwrap();
    let created = ok(&[
        "admin",
        "source",
        "--data-dir",
        data,
        "--actor",
        &actor,
        "create",
        "--tenant",
        &tenant,
        "--name",
        "app",
    ]);
    let repo = created
        .split("\"repo\":\"")
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .expect("create prints the repository")
        .to_owned();
    // No binding yet, and an off-policy destination, are refusals.
    fails(&[
        "admin",
        "source",
        "--data-dir",
        data,
        "--actor",
        &actor,
        "show",
        "--repo",
        &repo,
    ]);
    let bind = |remote: &str| {
        let body = format!(
            "{{\"binding\":{{\"remote\":\"{remote}\",\"allowed_refs\":[\"refs/heads/main\"],\"pipeline_path\":\".sentinel.yml\",\"trust\":\"\"}},\"credential\":{{\"Https\":{{\"username\":\"deploy\",\"secret\":\"s3cret-token\"}}}},\"forge\":null}}"
        );
        with_stdin(
            &[
                "admin",
                "source",
                "--data-dir",
                data,
                "--actor",
                &actor,
                "bind",
                "--repo",
                &repo,
                "--expected",
                "0",
            ],
            &body,
        )
    };
    let refused = bind("https://evil.example/r.git");
    assert_eq!(
        refused.status.code(),
        Some(2),
        "off-policy bind was not refused: {}{}",
        String::from_utf8_lossy(&refused.stdout),
        String::from_utf8_lossy(&refused.stderr)
    );
    let bound = bind("https://git.example:8443/team/repo.git");
    assert!(
        bound.status.success(),
        "{}",
        String::from_utf8_lossy(&bound.stderr)
    );
    assert!(String::from_utf8_lossy(&bound.stdout).contains("\"version\":1"));
    let shown = ok(&[
        "admin",
        "source",
        "--data-dir",
        data,
        "--actor",
        &actor,
        "show",
        "--repo",
        &repo,
    ]);
    assert!(shown.contains("\"version\":1") && shown.contains("git.example:8443"));
    assert!(!shown.contains("s3cret-token"));
    // Rotation is compare-and-set; a stale expectation is a conflict.
    let stale = bind("https://git.example:8443/team/repo.git");
    assert_eq!(stale.status.code(), Some(2));
    ok(&[
        "admin",
        "source",
        "--data-dir",
        data,
        "--actor",
        &actor,
        "revoke",
        "--repo",
        &repo,
        "--expected",
        "1",
    ]);
    let shown = ok(&[
        "admin",
        "source",
        "--data-dir",
        data,
        "--actor",
        &actor,
        "show",
        "--repo",
        &repo,
    ]);
    assert!(shown.contains("\"revoked\":true"));
}
