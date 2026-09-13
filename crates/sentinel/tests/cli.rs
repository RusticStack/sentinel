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

fn fixture(rel: &str) -> String {
    format!(
        "{}/../../fixtures/pipelines/{rel}",
        env!("CARGO_MANIFEST_DIR")
    )
}

#[test]
fn pipeline_validate_reports_path_and_exit_code() {
    let ok = invoke(&["pipeline", "validate", &fixture("valid/full.yml")]);
    assert!(
        ok.status.success(),
        "{}",
        String::from_utf8_lossy(&ok.stderr)
    );
    assert!(ok.stdout.is_empty(), "validate prints nothing on success");

    let bad = invoke(&["pipeline", "validate", &fixture("invalid/cycle.yml")]);
    assert_eq!(bad.status.code(), Some(1));
    let err = String::from_utf8_lossy(&bad.stderr);
    assert!(err.contains("cycle.yml"), "{err}");
    assert!(err.contains("dependency cycle through a -> b"), "{err}");
    assert!(bad.stdout.is_empty());

    let missing = invoke(&["pipeline", "validate", "does/not/exist.yml"]);
    assert_eq!(missing.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&missing.stderr).contains("cannot read"));
}

#[test]
fn pipeline_explain_lists_requirements_and_unresolved_inputs() {
    let text = invoke(&["pipeline", "explain", &fixture("valid/conditions.yml")]);
    assert!(text.status.success());
    let out = String::from_utf8_lossy(&text.stdout);
    assert!(out.contains("job test"), "{out}");
    assert!(out.contains("job report"), "{out}");
    assert!(out.contains("needs: test"), "{out}");
    assert!(out.contains("unpinned: resolved at first pull"), "{out}");
    assert!(out.contains("resolved by worker"), "{out}");
    assert!(out.contains("unresolved until runtime:"), "{out}");
    assert!(out.contains("jobs.report.cache.deps.key"), "{out}");

    let json = invoke(&["pipeline", "explain", "--json", &fixture("valid/full.yml")]);
    assert!(json.status.success());
    let v: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    assert_eq!(v["schema"], "sentinel.explain/1");
    assert_eq!(v["jobs"][0]["name"], "test");
    assert_eq!(v["jobs"][1]["needs"][0], "test");
    assert_eq!(v["jobs"][0]["caches"][0]["key_known"], false);
    assert_eq!(v["requires"]["repository_read"], true);
    assert_eq!(v["requires"]["artifacts"][0], "release");
    assert!(v["digest"].as_str().unwrap().len() == 32);
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
            b"log_format = 'xml'".to_vec(),
            b"log_level = 'verbose'".to_vec(),
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

    #[test]
    fn logging_options_use_typed_config_and_cli_precedence() {
        let temp = tempdir().unwrap();
        let file = temp.path().join("config.toml");
        fs::write(&file, "log_format = 'json'\nlog_level = 'warn'").unwrap();
        for role in roles() {
            let output = invoke(&[role, "--config", file.to_str().unwrap(), "--check"]);
            assert!(output.status.success());
            let text = String::from_utf8_lossy(&output.stdout);
            assert!(text.contains("log_format=Json"));
            assert!(text.contains("log_level=Warn"));
            let output = invoke(&[
                role,
                "--config",
                file.to_str().unwrap(),
                "--log-format",
                "text",
                "--log-level",
                "debug",
                "--check",
            ]);
            assert!(output.status.success());
            let text = String::from_utf8_lossy(&output.stdout);
            assert!(text.contains("log_format=Text"));
            assert!(text.contains("log_level=Debug"));
            assert_eq!(
                invoke(&[role, "--log-format", "xml", "--check"])
                    .status
                    .code(),
                Some(2)
            );
            assert_eq!(
                invoke(&[role, "--log-level", "verbose", "--check"])
                    .status
                    .code(),
                Some(2)
            );
        }
    }

    #[test]
    fn initialization_failure_has_json_error_and_failed_phase() {
        let temp = tempdir().unwrap();
        let data = temp.path().join("dangling-directory");
        std::os::unix::fs::symlink(temp.path().join("absent-target"), &data).unwrap();
        for role in roles() {
            let output = invoke(&[
                role,
                "--data-dir",
                data.to_str().unwrap(),
                "--log-format",
                "json",
            ]);
            assert_eq!(output.status.code(), Some(1));
            assert!(output.stdout.is_empty());
            let records: Vec<serde_json::Value> = String::from_utf8_lossy(&output.stderr)
                .lines()
                .map(|line| {
                    serde_json::from_str(line)
                        .expect("no plaintext fallback after logger initialization")
                })
                .collect();
            assert!(
                records
                    .iter()
                    .any(|record| record["fields"]["event"] == "runtime_failed"
                        && record["level"] == "ERROR")
            );
            let startup = records
                .iter()
                .find(|record| record["fields"]["phase"] == "startup")
                .unwrap();
            assert_eq!(startup["fields"]["outcome"], "failed");
            assert!(
                !records
                    .iter()
                    .any(|record| record["fields"]["event"] == "service_initialized")
            );
        }
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
                let format = if signal == "-INT" { "text" } else { "json" };
                let temp = tempdir().unwrap();
                let data_dir = temp.path().join("data");
                let mut child = ChildGuard(
                    Command::new(env!("CARGO_BIN_EXE_sentinel"))
                        .args([
                            role,
                            "--data-dir",
                            data_dir.to_str().unwrap(),
                            "--log-format",
                            format,
                            "--log-level",
                            "debug",
                        ])
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
                let deadline = Instant::now() + Duration::from_secs(10);
                let mut lines = Vec::new();
                loop {
                    let line = receiver
                        .recv_timeout(deadline.saturating_duration_since(Instant::now()))
                        .expect("startup before deadline");
                    let initialized = line.contains(&format!("{role} initialized"));
                    lines.push(line);
                    if initialized {
                        break;
                    }
                }
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
                lines.extend(receiver.try_iter());
                let tail = lines.join("\n");
                assert!(tail.contains("shutdown requested"));
                assert!(tail.contains(&format!("{role} stopped")));
                assert_eq!(fs::read_to_string(marker).unwrap(), "retained");
                if format == "json" {
                    let records: Vec<serde_json::Value> = lines
                        .iter()
                        .map(|line| serde_json::from_str(line).expect("complete JSON event"))
                        .collect();
                    let process = records[0]["spans"][0]["process_id"].as_str().unwrap();
                    process.parse::<sentinel::correlation::ProcessId>().unwrap();
                    for record in &records {
                        assert_eq!(record["spans"][0]["process_id"], process);
                        assert_eq!(record["spans"][0]["schema_version"], 1);
                        assert!(record["spans"][0].get("run_id").is_none());
                        assert_eq!(record["spans"][1]["role"], role);
                        assert!(record["timestamp"].is_string());
                    }
                    for phase in ["configuration", "startup", "shutdown"] {
                        let event = records
                            .iter()
                            .find(|record| record["fields"]["phase"] == phase)
                            .unwrap();
                        assert!(event["fields"]["duration_ns"].is_u64());
                        assert_eq!(event["fields"]["outcome"], "completed");
                    }
                    let initialized = records
                        .iter()
                        .find(|record| record["fields"]["event"] == "service_initialized")
                        .unwrap();
                    assert!(initialized["fields"]["service_startup_ns"].is_u64());
                }
            }
        }
    }
}
