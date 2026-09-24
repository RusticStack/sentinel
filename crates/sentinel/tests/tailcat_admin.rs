//! `sentinel admin tailcat`: node-key rotation and allow-list edits through
//! the real binary, against a fake helper. Keys travel on standard input and
//! output only; standard error and argv never carry one.

#![cfg(all(target_os = "linux", any(feature = "server", feature = "worker")))]

use std::{
    fs,
    io::Write,
    os::unix::fs::PermissionsExt,
    path::Path,
    process::{Command, Output, Stdio},
};

use sentinel_core::WorkerId;

const KEY: &str = "0123456789abcdeffedcba98765432100123456789abcdeffedcba9876543210";
const OTHER: &str = "fedcba98765432100123456789abcdeffedcba98765432100123456789abcdef";
const ADDRESS: &str = "tcabcdefghijklmnopqrstuvwxyz0123";
const ADDRESS2: &str = "tczyxwvutsrqponmlkjihgfedcba9876";

/// The helper stand-in: a worker's default key is `KEY`, its rotated one
/// `OTHER`; a ping with the rotated key succeeds only once `$HOME/admitted`
/// exists (the controller listing it).
fn fake_helper(dir: &Path) -> (String, String) {
    let binary = dir.join("helper");
    let script = format!(
        concat!(
            "#!/bin/sh\n",
            "case \"$1\" in\n",
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
            "  ping) case \"$*\" in\n",
            "    *--key=client-rotated*) [ -e \"$HOME/admitted\" ] && exit 0; exit 1 ;;\n",
            "    *) exit 0 ;;\n",
            "  esac ;;\n",
            "esac\n",
            "exit 64\n",
        ),
        key = KEY,
        other = OTHER,
        address = ADDRESS,
        address2 = ADDRESS2,
    );
    fs::write(&binary, script).unwrap();
    fs::set_permissions(&binary, fs::Permissions::from_mode(0o700)).unwrap();
    let digest = ring::digest::digest(&ring::digest::SHA256, &fs::read(&binary).unwrap())
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    (binary.display().to_string(), digest)
}

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

/// Standard error names files and workers, never a key or an address.
fn assert_quiet(output: &Output) {
    let stderr = text(&output.stderr);
    for secret in [KEY, OTHER, ADDRESS, ADDRESS2] {
        assert!(!stderr.contains(secret), "{stderr}");
    }
}

#[test]
fn a_worker_rotation_runs_through_the_admin_commands_with_keys_only_on_stdio() {
    let root = tempfile::tempdir().unwrap();
    let (binary, digest) = fake_helper(root.path());
    let (worker_dir, controller_dir) = (root.path().join("worker"), root.path().join("controller"));
    fs::create_dir(&worker_dir).unwrap();
    fs::create_dir(&controller_dir).unwrap();
    let worker = WorkerId::new();
    fs::write(worker_dir.join("worker.id"), format!("{worker}\n")).unwrap();
    let helper =
        format!("[tailcat]\nenabled = true\nbinary = \"{binary}\"\nsha256 = \"{digest}\"\n");
    let worker_config = root.path().join("worker.toml");
    fs::write(
        &worker_config,
        format!(
            "data_dir = \"{}\"\ncontroller = \"127.0.0.1:7443\"\ncontroller_fingerprint = \"{}\"\ntailcat_address = \"{ADDRESS}\"\n{helper}",
            worker_dir.display(),
            "ab".repeat(32)
        ),
    )
    .unwrap();
    let controller_config = root.path().join("controller.toml");
    fs::write(
        &controller_config,
        format!("data_dir = \"{}\"\n{helper}", controller_dir.display()),
    )
    .unwrap();
    let worker_args = |command: &'static str| {
        vec![
            "admin".to_owned(),
            "tailcat".to_owned(),
            command.to_owned(),
            "--role".to_owned(),
            "worker".to_owned(),
            "--config".to_owned(),
            worker_config.display().to_string(),
        ]
    };
    let run = |args: Vec<String>, stdin: &str| {
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        sentinel(&args, stdin)
    };
    let controller_data = controller_dir.display().to_string();
    let edit = |command: &str, stdin: &str| {
        sentinel(
            &["admin", "tailcat", command, "--data-dir", &controller_data],
            stdin,
        )
    };
    let old_line = format!("nodekey:{KEY} {worker}\n");
    let new_line = format!("nodekey:{OTHER} {worker}\n");

    // The worker's current key is listed on the controller.
    let listed = edit("allow", &old_line);
    assert!(listed.status.success(), "{}", text(&listed.stderr));
    assert_quiet(&listed);

    // Rotate: the staged key's allow-list line alone goes to stdout.
    let rotated = run(worker_args("rotate"), "");
    assert!(rotated.status.success(), "{}", text(&rotated.stderr));
    assert_eq!(text(&rotated.stdout), new_line);
    assert_quiet(&rotated);

    // Not listed yet: the commit is refused and nothing switches.
    let refused = run(worker_args("commit"), "");
    assert_eq!(refused.status.code(), Some(2));
    assert!(
        text(&refused.stderr).contains("does not admit"),
        "{}",
        text(&refused.stderr)
    );
    assert!(refused.stdout.is_empty());
    assert_quiet(&refused);
    let record = worker_dir.join("tailcat").join("client-default.nodekey");
    assert_eq!(
        fs::read_to_string(&record).unwrap(),
        format!("nodekey:{KEY}\n")
    );

    // Listed beside the old key (the overlap window) and admitted by the
    // controller: the commit switches and prints the line to keep.
    let admitted = edit("allow", &text(&rotated.stdout));
    assert!(admitted.status.success(), "{}", text(&admitted.stderr));
    assert_quiet(&admitted);
    let allow = fs::read_to_string(controller_dir.join("tailcat-allow")).unwrap();
    assert!(
        allow.contains(old_line.trim()) && allow.contains(new_line.trim()),
        "both listed"
    );
    fs::write(worker_dir.join("tailcat").join("admitted"), "").unwrap();
    let committed = run(worker_args("commit"), "");
    assert!(committed.status.success(), "{}", text(&committed.stderr));
    assert_eq!(text(&committed.stdout), new_line);
    assert_quiet(&committed);
    assert_eq!(
        fs::read_to_string(&record).unwrap(),
        format!("nodekey:{OTHER}\n")
    );

    // Retire: the new key becomes the worker's only one.
    let retired = edit("retire", &text(&committed.stdout));
    assert!(retired.status.success(), "{}", text(&retired.stderr));
    assert!(
        text(&retired.stderr).contains("removed 1"),
        "{}",
        text(&retired.stderr)
    );
    assert_quiet(&retired);
    let allow = fs::read_to_string(controller_dir.join("tailcat-allow")).unwrap();
    assert_eq!(allow, new_line);
    assert_eq!(
        fs::metadata(controller_dir.join("tailcat-allow"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );

    // A malformed line is refused without echoing it.
    let bad = edit("allow", &format!("nodekey:{KEY} wrk_bogus\n"));
    assert_eq!(bad.status.code(), Some(2));
    assert_quiet(&bad);
    let two = edit("allow", &format!("{old_line}{new_line}"));
    assert_eq!(two.status.code(), Some(2));
    assert_quiet(&two);

    // The controller's rotation stages quietly and cannot commit before a
    // running controller served the staged key.
    let server_args = |command: &'static str| {
        vec![
            "admin".to_owned(),
            "tailcat".to_owned(),
            command.to_owned(),
            "--role".to_owned(),
            "server".to_owned(),
            "--config".to_owned(),
            controller_config.display().to_string(),
        ]
    };
    let staged = run(server_args("rotate"), "");
    assert!(staged.status.success(), "{}", text(&staged.stderr));
    assert!(staged.stdout.is_empty());
    assert!(
        text(&staged.stderr).contains("address.next"),
        "{}",
        text(&staged.stderr)
    );
    assert_quiet(&staged);
    let early = run(server_args("commit"), "");
    assert_eq!(early.status.code(), Some(2));
    assert!(
        text(&early.stderr).contains("has not served"),
        "{}",
        text(&early.stderr)
    );
    assert_quiet(&early);
    let dropped = run(server_args("abandon"), "");
    assert!(dropped.status.success(), "{}", text(&dropped.stderr));
    assert!(text(&dropped.stderr).contains("dropped the staged key"));
    assert!(
        !controller_dir
            .join("tailcat")
            .join("staged.nodekey")
            .exists()
    );
}
