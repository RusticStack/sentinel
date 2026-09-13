use std::process::{Command, Output};

fn invoke(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sentinel"))
        .args(args)
        .output()
        .expect("run sentinel")
}

#[test]
fn help_and_version_are_available_without_side_effects() {
    for args in [
        vec!["--help"],
        vec!["server", "--help"],
        vec!["worker", "--help"],
    ] {
        let output = invoke(&args);
        assert!(output.status.success());
        assert!(output.stderr.is_empty());
        assert!(String::from_utf8_lossy(&output.stdout).contains("Usage:"));
    }
    for args in [
        vec!["--version"],
        vec!["server", "--version"],
        vec!["worker", "--version"],
    ] {
        let output = invoke(&args);
        assert!(output.status.success());
        assert!(String::from_utf8_lossy(&output.stdout).contains(env!("CARGO_PKG_VERSION")));
    }
}

#[test]
fn missing_or_invalid_commands_are_usage_errors() {
    for args in [
        vec![],
        vec!["unknown"],
        vec!["server", "--unknown"],
        vec!["worker", "--data-dir"],
    ] {
        let output = invoke(&args);
        assert_eq!(output.status.code(), Some(2));
        assert!(!output.stderr.is_empty());
    }
}

#[test]
fn unavailable_roles_fail_explicitly() {
    for (role, enabled) in [
        ("server", cfg!(feature = "server")),
        ("worker", cfg!(feature = "worker")),
    ] {
        if !enabled {
            let output = invoke(&[role, "--check"]);
            assert_eq!(output.status.code(), Some(2));
            assert!(String::from_utf8_lossy(&output.stderr).contains("unavailable in this build"));
        }
    }
}

#[cfg(all(target_os = "linux", any(feature = "server", feature = "worker")))]
mod linux {
    use super::*;
    use std::{
        fs,
        io::{BufRead, BufReader},
        process::{Child, Stdio},
        sync::mpsc,
        thread,
        time::{Duration, Instant},
    };
    use tempfile::tempdir;

    fn roles() -> Vec<&'static str> {
        [
            ("server", cfg!(feature = "server")),
            ("worker", cfg!(feature = "worker")),
        ]
        .into_iter()
        .filter_map(|(role, enabled)| enabled.then_some(role))
        .collect()
    }

    #[test]
    fn configuration_precedence_and_check_have_no_writes() {
        let temp = tempdir().unwrap();
        let file = temp.path().join("config.toml");
        let from_file = temp.path().join("from-file");
        let from_flag = temp.path().join("from-flag");
        fs::write(&file, format!("data_dir = '{}'", from_file.display())).unwrap();
        for role in roles() {
            let output = invoke(&[role, "--check"]);
            assert!(output.status.success());
            let default = if role == "server" {
                "/var/lib/sentinel"
            } else {
                "/var/lib/sentinel-worker"
            };
            assert!(String::from_utf8_lossy(&output.stdout).contains(default));
            let output = invoke(&[role, "--config", file.to_str().unwrap(), "--check"]);
            assert!(output.status.success());
            assert!(String::from_utf8_lossy(&output.stdout).contains(from_file.to_str().unwrap()));
            let output = invoke(&[
                role,
                "--config",
                file.to_str().unwrap(),
                "--data-dir",
                from_flag.to_str().unwrap(),
                "--check",
            ]);
            assert!(output.status.success());
            assert!(String::from_utf8_lossy(&output.stdout).contains(from_flag.to_str().unwrap()));
        }
        assert!(!from_file.exists());
        assert!(!from_flag.exists());
    }

    #[test]
    fn malformed_oversized_and_missing_configuration_fail_without_echoing_input() {
        let temp = tempdir().unwrap();
        let file = temp.path().join("config.toml");
        let destination = temp.path().join("must-not-exist");
        for contents in [
            b"password = 'do-not-echo-this-secret'".to_vec(),
            b"data_dir = '/a'\ndata_dir = '/b'".to_vec(),
            b"data_dir = 42".to_vec(),
            b"[".to_vec(),
            vec![0xff],
            vec![b' '; 65537],
        ] {
            fs::write(&file, contents).unwrap();
            for role in roles() {
                let output = invoke(&[
                    role,
                    "--config",
                    file.to_str().unwrap(),
                    "--data-dir",
                    destination.to_str().unwrap(),
                ]);
                assert_eq!(output.status.code(), Some(2));
                assert!(
                    !String::from_utf8_lossy(&output.stderr).contains("do-not-echo-this-secret")
                );
            }
        }
        fs::remove_file(&file).unwrap();
        for role in roles() {
            assert_eq!(
                invoke(&[role, "--config", file.to_str().unwrap(), "--check"])
                    .status
                    .code(),
                Some(2)
            );
            assert_eq!(
                invoke(&[role, "--config", temp.path().to_str().unwrap(), "--check"])
                    .status
                    .code(),
                Some(2)
            );
        }
        assert!(!destination.exists());
    }

    #[test]
    fn unsafe_or_non_directory_data_paths_are_rejected() {
        let temp = tempdir().unwrap();
        let file = temp.path().join("file");
        fs::write(&file, "existing data").unwrap();
        for role in roles() {
            for path in [
                "",
                "relative",
                "/",
                "/.",
                "/var/../tmp",
                file.to_str().unwrap(),
            ] {
                assert_eq!(
                    invoke(&[role, "--data-dir", path, "--check"]).status.code(),
                    Some(2),
                    "{role}: {path}"
                );
            }
            let invalid_parent = file.join("child");
            let output = invoke(&[role, "--data-dir", invalid_parent.to_str().unwrap()]);
            assert!(!output.status.success());
        }
        assert_eq!(fs::read_to_string(file).unwrap(), "existing data");
    }

    struct ChildGuard(Child);
    impl Drop for ChildGuard {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    #[test]
    fn each_role_starts_and_shuts_down_cleanly_on_signals() {
        for role in roles() {
            for signal in ["-INT", "-TERM", "-HUP"] {
                let temp = tempdir().unwrap();
                let data_dir = temp.path().join("data");
                let mut child = ChildGuard(
                    Command::new(env!("CARGO_BIN_EXE_sentinel"))
                        .args([role, "--data-dir", data_dir.to_str().unwrap()])
                        .stdout(Stdio::null())
                        .stderr(Stdio::piped())
                        .spawn()
                        .unwrap(),
                );
                let stderr = child.0.stderr.take().unwrap();
                let (sender, receiver) = mpsc::channel();
                let reader = thread::spawn(move || {
                    for line in BufReader::new(stderr).lines() {
                        if sender.send(line.unwrap()).is_err() {
                            break;
                        }
                    }
                });
                let started = receiver
                    .recv_timeout(Duration::from_secs(10))
                    .expect("startup before deadline");
                assert!(
                    started.contains(&format!("{role} initialized")),
                    "{started}"
                );
                assert!(data_dir.is_dir());
                // Existing data must survive shutdown.
                let marker = data_dir.join("keep");
                fs::write(&marker, "retained").unwrap();
                assert!(
                    Command::new("kill")
                        .args([signal, &child.0.id().to_string()])
                        .status()
                        .unwrap()
                        .success()
                );
                let deadline = Instant::now() + Duration::from_secs(5);
                loop {
                    if let Some(status) = child.0.try_wait().unwrap() {
                        assert!(status.success(), "{role} {signal}: {status}");
                        break;
                    }
                    assert!(Instant::now() < deadline, "shutdown timed out");
                    thread::sleep(Duration::from_millis(10));
                }
                reader.join().unwrap();
                let tail = receiver.try_iter().collect::<Vec<_>>().join("\n");
                assert!(tail.contains("shutdown requested"));
                assert!(tail.contains(&format!("{role} stopped")));
                assert_eq!(fs::read_to_string(marker).unwrap(), "retained");
            }
        }
    }
}
