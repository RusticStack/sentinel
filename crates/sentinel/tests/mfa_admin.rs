#![cfg(all(target_os = "linux", feature = "server"))]

use std::process::{Command, Output, Stdio};

use sentinel_auth::mfa::{Seed, check};

const PASSWORD: &str = "correct horse battery staple";

fn sentinel(data: &std::path::Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sentinel"))
        .args(args)
        .arg("--data-dir")
        .arg(data)
        .output()
        .unwrap()
}

fn sentinel_with_stdin(data: &std::path::Path, args: &[&str], input: &str) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_sentinel"))
        .args(args)
        .arg("--data-dir")
        .arg(data)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    std::io::Write::write_all(&mut stdin, input.as_bytes()).unwrap();
    drop(stdin);
    child.wait_with_output().unwrap()
}

fn lines(out: &Output) -> Vec<String> {
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(str::to_owned)
        .collect()
}

fn bootstrapped() -> (tempfile::TempDir, std::path::PathBuf) {
    let root = tempfile::tempdir().unwrap();
    let data = root.path().join("data");
    std::fs::create_dir(&data).unwrap();
    let mut bootstrap = Command::new(env!("CARGO_BIN_EXE_sentinel"))
        .args(["admin", "bootstrap", "--username", "root", "--data-dir"])
        .arg(&data)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    std::io::Write::write_all(bootstrap.stdin.as_mut().unwrap(), PASSWORD.as_bytes()).unwrap();
    assert!(bootstrap.wait_with_output().unwrap().status.success());
    (root, data)
}

fn current_code(uri: &str) -> String {
    let start = uri.find("secret=").unwrap() + "secret=".len();
    let end = uri[start..].find('&').map_or(uri.len(), |e| start + e);
    let seed = Seed::from_base32(&uri[start..end]).unwrap();
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    (0..1_000_000u32)
        .map(|n| format!("{n:06}"))
        .find(|code| check(&seed, code, seconds).is_some())
        .unwrap()
}

#[test]
fn enrolling_from_the_host_needs_the_key_and_a_valid_code_and_prints_secrets_once() {
    let (_root, data) = bootstrapped();

    let keyless = sentinel(&data, &["admin", "mfa", "enroll", "--user", "root"]);
    assert!(!keyless.status.success());
    assert!(String::from_utf8_lossy(&keyless.stderr).contains("key create"));
    assert!(
        sentinel(&data, &["admin", "key", "create"])
            .status
            .success()
    );

    let begun = sentinel(&data, &["admin", "mfa", "enroll", "--user", "root"]);
    assert!(begun.status.success());
    let out = lines(&begun);
    assert_eq!(out.len(), 1, "{out:?}");
    assert!(
        out[0].starts_with("otpauth://totp/Sentinel:root?"),
        "{out:?}"
    );
    let status = sentinel(&data, &["admin", "mfa", "status", "--user", "root"]);
    assert!(lines(&status).contains(&"enrolled: false".to_owned()));

    let argv = sentinel(
        &data,
        &[
            "admin", "mfa", "confirm", "--user", "root", "--code", "123456",
        ],
    );
    assert!(!argv.status.success());
    assert!(!String::from_utf8_lossy(&argv.stderr).contains("123456"));

    let wrong = sentinel_with_stdin(
        &data,
        &["admin", "mfa", "confirm", "--user", "root"],
        "abcdef\n",
    );
    assert!(!wrong.status.success());
    assert!(wrong.stdout.is_empty());

    let code = current_code(&out[0]);
    let confirmed = sentinel_with_stdin(
        &data,
        &["admin", "mfa", "confirm", "--user", "root"],
        &format!("{code}\n"),
    );
    assert!(
        confirmed.status.success(),
        "{}",
        String::from_utf8_lossy(&confirmed.stderr)
    );
    let first = lines(&confirmed);
    assert_eq!(first.len(), 10, "{first:?}");
    let status = sentinel(&data, &["admin", "mfa", "status", "--user", "root"]);
    let status = lines(&status);
    assert!(status.contains(&"enrolled: true".to_owned()), "{status:?}");

    let again = sentinel(&data, &["admin", "mfa", "enroll", "--user", "root"]);
    assert!(!again.status.success());
    assert!(again.stdout.is_empty());

    let reissued = sentinel(&data, &["admin", "mfa", "codes", "--user", "root"]);
    assert!(reissued.status.success());
    let second = lines(&reissued);
    assert_eq!(second.len(), 10);
    assert!(second.iter().all(|code| !first.contains(code)));

    let (_other_root, other) = bootstrapped();
    let none = sentinel(&other, &["admin", "mfa", "codes", "--user", "root"]);
    assert!(!none.status.success() && none.stdout.is_empty());
}
