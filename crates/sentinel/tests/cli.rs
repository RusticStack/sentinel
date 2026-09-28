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

/// P02-4: a character device reports length 0, so only a bound on the read
/// itself stops `/dev/zero` (valid UTF-8, no end) from exhausting memory.
#[cfg(unix)]
#[test]
fn pipeline_validate_bounds_the_read_of_an_endless_device() {
    use std::time::{Duration, Instant};
    let mut child = Command::new(env!("CARGO_BIN_EXE_sentinel"))
        .args(["pipeline", "validate", "--json", "/dev/zero"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(20);
    while child.try_wait().unwrap().is_none() {
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("pipeline validate /dev/zero did not stop");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let output = child.wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    let document: serde_json::Value = serde_json::from_slice(output.stderr.trim_ascii()).unwrap();
    assert_eq!(document["code"], "invalid_pipeline", "{document}");
}

/// P09-13: a reader that has gone (`| head -1`) used to make every write
/// panic with exit 101. Now the command stops quietly with exit 0.
#[test]
fn a_closed_stdout_ends_the_command_quietly_with_exit_zero() {
    let file = fixture("valid/full.yml");
    for args in [
        vec!["pipeline", "explain", file.as_str()],
        vec!["pipeline", "explain", "--json", file.as_str()],
    ] {
        let (reader, writer) = std::io::pipe().unwrap();
        drop(reader);
        let output = Command::new(env!("CARGO_BIN_EXE_sentinel"))
            .args(&args)
            .stdout(writer)
            .stderr(std::process::Stdio::piped())
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(0), "{args:?}: {stderr}");
        assert!(stderr.is_empty(), "{args:?}: {stderr}");
    }
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
    fn public_url_is_an_exact_absolute_url_for_the_server_only() {
        let temp = tempdir().unwrap();
        let file = temp.path().join("config.toml");
        let data = temp.path().join("data");
        let check = |role: &str, url: &str| {
            fs::write(
                &file,
                format!("data_dir = '{}'\npublic_url = '{url}'", data.display()),
            )
            .unwrap();
            invoke(&[role, "--config", file.to_str().unwrap(), "--check"])
        };
        if cfg!(feature = "server") {
            for accepted in [
                "https://ci.example.com",
                "https://ci.example.com/sentinel",
                "http://127.0.0.1:7080",
            ] {
                let output = check("server", accepted);
                assert!(output.status.success(), "{accepted}");
                assert!(
                    String::from_utf8_lossy(&output.stdout)
                        .contains(&format!("public_url={accepted}")),
                    "{accepted}"
                );
            }
            for refused in [
                "https://ci.example.com/",
                "https://CI.example.com",
                "https://ci.example.com?x=1",
                "http://ci.example.com",
                "ci.example.com",
                "https://user@ci.example.com",
            ] {
                assert_eq!(check("server", refused).status.code(), Some(2), "{refused}");
            }
        }
        if cfg!(feature = "worker") {
            assert_eq!(
                check("worker", "https://ci.example.com").status.code(),
                Some(2)
            );
        }
        assert!(!data.exists());
    }

    /// The spool's free-space reserve and quota belong to a worker with a
    /// controller; a zero quota would declare every line of output lost
    /// and is refused.
    #[test]
    fn spool_limits_are_worker_link_settings_and_a_zero_quota_is_refused() {
        let temp = tempdir().unwrap();
        let file = temp.path().join("config.toml");
        let data = temp.path().join("data");
        let link = format!(
            "controller = '127.0.0.1:7443'\ncontroller_fingerprint = '{}'\n",
            "ab".repeat(32)
        );
        let check = |role: &str, body: &str| {
            fs::write(&file, format!("data_dir = '{}'\n{body}", data.display())).unwrap();
            invoke(&[role, "--config", file.to_str().unwrap(), "--check"])
                .status
                .code()
        };
        if cfg!(feature = "server") {
            assert_eq!(check("server", "spool_reserve_bytes = 1024"), Some(2));
            assert_eq!(check("server", "spool_quota_bytes = 1024"), Some(2));
        }
        if cfg!(feature = "worker") {
            assert_eq!(check("worker", "spool_quota_bytes = 1024"), Some(2));
            assert_eq!(
                check("worker", &format!("{link}spool_quota_bytes = 0")),
                Some(2)
            );
            assert_eq!(
                check(
                    "worker",
                    &format!("{link}spool_reserve_bytes = 0\nspool_quota_bytes = 1073741824")
                ),
                Some(0)
            );
        }
        assert!(!data.exists());
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
                // The server binds an ephemeral port so parallel tests never collide.
                let config = temp.path().join("config.toml");
                fs::write(
                    &config,
                    if role == "server" {
                        "listen = '127.0.0.1:0'\napi_listen = '127.0.0.1:0'"
                    } else {
                        ""
                    },
                )
                .unwrap();
                let mut child = ChildGuard(
                    Command::new(env!("CARGO_BIN_EXE_sentinel"))
                        .args([
                            role,
                            "--config",
                            config.to_str().unwrap(),
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

    /// A JSON-logging child whose stderr is collected on a thread.
    struct Logged {
        child: ChildGuard,
        lines: mpsc::Receiver<String>,
        seen: Vec<serde_json::Value>,
    }

    impl Logged {
        fn spawn(args: &[&str]) -> Logged {
            let mut child = ChildGuard(
                Command::new(env!("CARGO_BIN_EXE_sentinel"))
                    .args(args)
                    .args(["--log-format", "json", "--log-level", "debug"])
                    .stdout(Stdio::null())
                    .stderr(Stdio::piped())
                    .spawn()
                    .unwrap(),
            );
            let stderr = child.0.stderr.take().unwrap();
            let (sender, lines) = mpsc::channel();
            thread::spawn(move || {
                for line in BufReader::new(stderr).lines() {
                    if sender.send(line.unwrap()).is_err() {
                        break;
                    }
                }
            });
            Logged {
                child,
                lines,
                seen: Vec::new(),
            }
        }

        /// The first record whose `event` field is `event`, waiting up to 15 s.
        fn event(&mut self, event: &str) -> serde_json::Value {
            let deadline = Instant::now() + Duration::from_secs(15);
            loop {
                if let Some(found) = self
                    .seen
                    .iter()
                    .find(|record| record["fields"]["event"] == event)
                {
                    return found.clone();
                }
                let line = self
                    .lines
                    .recv_timeout(deadline.saturating_duration_since(Instant::now()))
                    .unwrap_or_else(|_| panic!("no {event} before the deadline: {:?}", self.seen));
                self.seen
                    .push(serde_json::from_str(&line).expect("complete JSON event"));
            }
        }

        /// The `n`th record (1-based) whose `event` field is `event`,
        /// waiting up to `wait`.
        fn nth_event(&mut self, event: &str, n: usize, wait: Duration) -> serde_json::Value {
            let deadline = Instant::now() + wait;
            loop {
                if let Some(found) = self
                    .seen
                    .iter()
                    .filter(|record| record["fields"]["event"] == event)
                    .nth(n - 1)
                {
                    return found.clone();
                }
                let line = self
                    .lines
                    .recv_timeout(deadline.saturating_duration_since(Instant::now()))
                    .unwrap_or_else(|_| {
                        panic!("no {event} #{n} before the deadline: {:?}", self.seen)
                    });
                self.seen
                    .push(serde_json::from_str(&line).expect("complete JSON event"));
            }
        }

        fn terminate(mut self) {
            assert!(
                Command::new("kill")
                    .args(["-TERM", &self.child.0.id().to_string()])
                    .status()
                    .unwrap()
                    .success()
            );
            let deadline = Instant::now() + Duration::from_secs(10);
            loop {
                if let Some(status) = self.child.0.try_wait().unwrap() {
                    assert!(status.success(), "{status}");
                    return;
                }
                assert!(Instant::now() < deadline, "shutdown timed out");
                thread::sleep(Duration::from_millis(10));
            }
        }
    }

    /// The whole W02 path through the real binaries: an operator prepares a
    /// pool and an enrollment on the controller's host, the server listens,
    /// the worker enrolls on its first hello, and both stop cleanly.
    #[test]
    fn a_worker_process_enrolls_with_a_running_server_process() {
        if !(cfg!(feature = "server") && cfg!(feature = "worker")) {
            return;
        }
        let temp = tempdir().unwrap();
        let controller_dir = temp.path().join("controller");
        let worker_dir = temp.path().join("worker");
        let admin = |args: &[&str]| {
            let mut child = Command::new(env!("CARGO_BIN_EXE_sentinel"))
                .args(["admin"])
                .args(args)
                .args(["--data-dir", controller_dir.to_str().unwrap()])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            // Only bootstrap reads it; the others get EOF.
            std::io::Write::write_all(
                child.stdin.as_mut().unwrap(),
                b"correct horse battery staple",
            )
            .unwrap();
            let output = child.wait_with_output().unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            String::from_utf8(output.stdout).unwrap()
        };
        fs::create_dir_all(&controller_dir).unwrap();
        admin(&["bootstrap", "--username", "root"]);
        admin(&["tenant", "create", "--slug", "acme"]);
        admin(&["pool", "create", "--name", "builders", "--tenant", "acme"]);
        let secret = admin(&["worker", "enroll", "--pool", "builders"]);
        let enrollment = temp.path().join("enrollment");
        fs::write(&enrollment, &secret).unwrap();
        // A credential for the CLI, issued host-locally before the server takes
        // ownership of the database: one controller owns it, and admin
        // commands run beside a stopped server.
        let token_file = temp.path().join("token");
        let issued = Command::new(env!("CARGO_BIN_EXE_sentinel"))
            .args([
                "admin",
                "token",
                "issue",
                "--data-dir",
                controller_dir.to_str().unwrap(),
                "--user",
                "root",
                "--name",
                "cli",
                "--scope",
                "read,run,platform-admin",
                "--expires-in",
                "1h",
            ])
            .output()
            .unwrap();
        assert!(
            issued.status.success(),
            "{}",
            String::from_utf8_lossy(&issued.stderr)
        );
        let credential = issued.stdout.clone();
        fs::write(&token_file, "not-a-token\n").unwrap();

        let server_config = temp.path().join("server.toml");
        fs::write(
            &server_config,
            "listen = '127.0.0.1:0'\napi_listen = '127.0.0.1:0'",
        )
        .unwrap();
        let mut server = Logged::spawn(&[
            "server",
            "--config",
            server_config.to_str().unwrap(),
            "--data-dir",
            controller_dir.to_str().unwrap(),
        ]);
        let listening = server.event("link_listening");
        let api = server.event("api_listening");
        let api_url = format!("http://{}", api["fields"]["addr"].as_str().unwrap());
        let addr = listening["fields"]["addr"].as_str().unwrap().to_owned();
        let fingerprint = listening["fields"]["fingerprint"]
            .as_str()
            .unwrap()
            .to_owned();
        assert_eq!(fingerprint.len(), 64);
        // A second controller on the same data directory is refused.
        let second = invoke(&[
            "server",
            "--config",
            server_config.to_str().unwrap(),
            "--data-dir",
            controller_dir.to_str().unwrap(),
        ]);
        assert_eq!(second.status.code(), Some(1));
        assert!(String::from_utf8_lossy(&second.stderr).contains("one controller"));

        let worker_config = temp.path().join("worker.toml");
        fs::write(
            &worker_config,
            format!(
                "controller = '{addr}'\ncontroller_fingerprint = '{fingerprint}'\nworker_name = 'builder-1'\nenrollment_file = '{}'\ncpu_millis = 2000\nmemory_bytes = 1073741824\n",
                enrollment.display()
            ),
        )
        .unwrap();
        let check = invoke(&[
            "worker",
            "--config",
            worker_config.to_str().unwrap(),
            "--data-dir",
            worker_dir.to_str().unwrap(),
            "--check",
        ]);
        assert!(check.status.success());
        assert!(String::from_utf8_lossy(&check.stdout).contains(&format!("controller={addr}")));
        let mut worker = Logged::spawn(&[
            "worker",
            "--config",
            worker_config.to_str().unwrap(),
            "--data-dir",
            worker_dir.to_str().unwrap(),
        ]);
        let connected = worker.event("link_connected");
        assert_eq!(connected["fields"]["enrolled"], true);
        // The spent enrollment is removed; the identity and id persist.
        assert!(!enrollment.exists());
        assert!(worker_dir.join("worker.key").exists());
        let id = fs::read_to_string(worker_dir.join("worker.id")).unwrap();
        assert!(id.starts_with("wrk_"));
        assert_eq!(connected["fields"]["worker"].as_str().unwrap(), id.trim());

        // The CLI against the running server: a credential issued host-locally,
        // `me`, a dispatch of a pinned pipeline, its status, and worker status
        // showing the connected worker. Text and JSON output both.
        fs::write(&token_file, "not-a-token\n").unwrap();
        let api = |args: &[&str]| {
            Command::new(env!("CARGO_BIN_EXE_sentinel"))
                .args([
                    "api",
                    "--server",
                    &api_url,
                    "--token-file",
                    token_file.to_str().unwrap(),
                ])
                .args(args)
                .output()
                .unwrap()
        };
        let refused = api(&["me"]);
        assert_eq!(refused.status.code(), Some(2));
        fs::write(&token_file, &credential).unwrap();
        let me = api(&["me"]);
        assert!(
            me.status.success(),
            "{}",
            String::from_utf8_lossy(&me.stderr)
        );
        assert!(String::from_utf8_lossy(&me.stdout).contains("via \"bearer\""));
        let pipeline = temp.path().join("pipeline.yml");
        fs::write(&pipeline, "schema: 1\non: [push]\njobs:\n  build:\n    image: docker.io/library/busybox@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662\n    steps: [{ id: s, run: 'true' }]\n").unwrap();
        let no_repo = api(&[
            "run",
            "--tenant",
            "acme",
            "--repo",
            "app",
            "--pipeline",
            pipeline.to_str().unwrap(),
            "--source",
            "/nowhere",
            "--sha",
            "0123456789abcdef0123456789abcdef01234567",
        ]);
        // `root` has no membership in acme yet: the repository is not visible.
        assert_eq!(
            no_repo.status.code(),
            Some(4),
            "{}",
            String::from_utf8_lossy(&no_repo.stderr)
        );
        assert!(String::from_utf8_lossy(&no_repo.stderr).contains("not_found"));
        let workers = api(&["--json", "workers", "--tenant", "acme"]);
        assert!(
            workers.status.success(),
            "{}",
            String::from_utf8_lossy(&workers.stderr)
        );
        let view: serde_json::Value = serde_json::from_slice(&workers.stdout).unwrap();
        assert_eq!(view["pools"][0]["name"], "builders");
        assert_eq!(view["pools"][0]["workers"][0]["connected"], true);
        assert_eq!(view["pools"][0]["workers"][0]["id"], id.trim());

        worker.terminate();
        server.terminate();
        // The worker is enrolled in the pool for good.
        let listed = admin(&["worker", "list", "--pool", "builders"]);
        assert!(listed.contains(id.trim()), "{listed}");
        assert!(listed.contains("builder-1"));
    }

    /// O07 against the real binary pair: `sentinel server` with a
    /// bootstrapped password account, and `sentinel auth login --device`
    /// approved on the server's `/device` page with a password session.
    /// Afterwards `auth status` verifies the grant, `doctor` passes every
    /// check, and no output carries token material.
    #[test]
    fn a_device_login_against_a_running_server_process() {
        if !cfg!(feature = "server") {
            return;
        }
        const PASSWORD: &str = "correct horse battery staple";
        let temp = tempdir().unwrap();
        let data = temp.path().join("controller");
        fs::create_dir_all(&data).unwrap();
        let mut bootstrap = Command::new(env!("CARGO_BIN_EXE_sentinel"))
            .args(["admin", "bootstrap", "--username", "root", "--data-dir"])
            .arg(&data)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        std::io::Write::write_all(bootstrap.stdin.as_mut().unwrap(), PASSWORD.as_bytes()).unwrap();
        let done = bootstrap.wait_with_output().unwrap();
        assert!(
            done.status.success(),
            "{}",
            String::from_utf8_lossy(&done.stderr)
        );
        let config = temp.path().join("server.toml");
        fs::write(
            &config,
            "listen = '127.0.0.1:0'\napi_listen = '127.0.0.1:0'",
        )
        .unwrap();
        let mut server = Logged::spawn(&[
            "server",
            "--config",
            config.to_str().unwrap(),
            "--data-dir",
            data.to_str().unwrap(),
        ]);
        let api = server.event("api_listening");
        let base = format!("http://{}", api["fields"]["addr"].as_str().unwrap());

        let profiles = temp.path().join("cli-config");
        let cli = |args: &[&str]| {
            let mut command = Command::new(env!("CARGO_BIN_EXE_sentinel"));
            command
                .env("SENTINEL_CONFIG_DIR", &profiles)
                .env("SENTINEL_CREDENTIAL_STORE", "file")
                .env_remove("SENTINEL_TOKEN")
                .env_remove("SENTINEL_SERVER")
                .env_remove("SENTINEL_PROFILE")
                .args(args)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            command
        };
        let no_tokens = |text: &str| {
            for kind in ["sntl_at_", "sntl_rt_", "sntl_ac_", "sntl_dc_"] {
                assert!(!text.contains(kind), "{text}");
            }
        };
        let mut login = cli(&["auth", "login", "--device", "--server", &base])
            .spawn()
            .unwrap();
        let stderr = login.stderr.take().unwrap();
        let (sender, lines) = mpsc::channel();
        let reader = thread::spawn(move || {
            let mut all = String::new();
            for line in BufReader::new(stderr).lines() {
                let line = line.unwrap();
                all.push_str(&line);
                all.push('\n');
                let _ = sender.send(line);
            }
            all
        });
        let user_code = loop {
            let line = lines
                .recv_timeout(Duration::from_secs(15))
                .expect("the user code line");
            if let Some(rest) = line.split("enter the code ").nth(1) {
                break rest.split_whitespace().next().unwrap().replace('-', "");
            }
        };
        // The person approves in a browser: a password session, then the page.
        let agent = ureq::Agent::new_with_config(
            ureq::Agent::config_builder()
                .http_status_as_error(false)
                .max_redirects(0)
                .build(),
        );
        let signed_in = agent
            .post(&format!("{base}/api/v1/login"))
            .header("content-type", "application/json")
            .send(
                serde_json::json!({ "username": "root", "password": PASSWORD })
                    .to_string()
                    .as_bytes(),
            )
            .unwrap();
        assert_eq!(signed_in.status().as_u16(), 200);
        let cookie = signed_in.headers()["set-cookie"]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();
        let page = agent
            .get(&format!("{base}/device?user_code={user_code}"))
            .header("cookie", &cookie)
            .call()
            .unwrap()
            .into_body()
            .read_to_string()
            .unwrap();
        no_tokens(&page);
        let at = page.find("name=\"form_token\" value=\"").expect("form") + 25;
        let form_token = &page[at..at + 64];
        let mut form = format!("user_code={user_code}&form_token={form_token}&action=approve");
        for scope in [
            "runs%3Aread",
            "runs%3Awrite",
            "logs%3Aread",
            "artifacts%3Aread",
            "cache%3Aread",
        ] {
            form.push_str(&format!("&scope_{scope}=1"));
        }
        let approved = agent
            .post(&format!("{base}/device"))
            .header("cookie", &cookie)
            .header("origin", &base)
            .header("content-type", "application/x-www-form-urlencoded")
            .send(form.as_bytes())
            .unwrap();
        assert_eq!(approved.status().as_u16(), 200);

        let deadline = Instant::now() + Duration::from_secs(60);
        let status = loop {
            if let Some(status) = login.try_wait().unwrap() {
                break status;
            }
            assert!(Instant::now() < deadline, "the device login did not finish");
            thread::sleep(Duration::from_millis(50));
        };
        let said = reader.join().unwrap();
        assert!(status.success(), "{said}");
        assert!(said.contains("Signed in to"), "{said}");
        no_tokens(&said);

        let out = cli(&["auth", "status", "--json"]).output().unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let doc: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(
            (doc["verified"].as_bool(), doc["username"].as_str()),
            (Some(true), Some("root"))
        );
        let out = cli(&["doctor", "--json"]).output().unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stdout)
        );
        let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(report["ok"], true);
        assert_eq!(report["checks"].as_array().unwrap().len(), 7);
        for text in [&out.stdout, &out.stderr] {
            no_tokens(&String::from_utf8_lossy(text));
        }
        let out = cli(&["auth", "logout"]).output().unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        server.terminate();
    }

    /// R04 through the binary: a running controller with `[backup]` takes a
    /// backup when asked over the API, `admin backup verify` passes it,
    /// `admin restore` rebuilds an empty data directory from it, and a
    /// controller started on that directory serves the same deployment — the
    /// credential issued before the backup still works.
    #[cfg(feature = "server")]
    #[test]
    fn a_backup_taken_online_restores_onto_a_new_data_directory_that_serves() {
        let temp = tempdir().unwrap();
        let data = temp.path().join("controller");
        let backups = temp.path().join("backups");
        let restored = temp.path().join("restored");
        fs::create_dir_all(&data).unwrap();
        let admin = |args: &[&str], dir: &std::path::Path| {
            let mut child = Command::new(env!("CARGO_BIN_EXE_sentinel"))
                .arg("admin")
                .args(args)
                .args(["--data-dir", dir.to_str().unwrap()])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            std::io::Write::write_all(
                child.stdin.as_mut().unwrap(),
                b"correct horse battery staple",
            )
            .unwrap();
            let output = child.wait_with_output().unwrap();
            assert!(
                output.status.success(),
                "{args:?}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            String::from_utf8(output.stdout).unwrap()
        };
        admin(&["bootstrap", "--username", "root"], &data);
        admin(&["tenant", "create", "--slug", "acme"], &data);
        let token = admin(
            &[
                "token",
                "issue",
                "--user",
                "root",
                "--name",
                "ops",
                "--scope",
                "read,platform-admin",
                "--expires-in",
                "1h",
            ],
            &data,
        )
        .trim()
        .to_owned();
        let config = temp.path().join("server.toml");
        fs::write(
            &config,
            format!(
                "listen = '127.0.0.1:0'\napi_listen = '127.0.0.1:0'\n[backup]\ndir = '{}'\ninterval_secs = 3600\nkeep = 3\n",
                backups.display()
            ),
        )
        .unwrap();
        let serve = |dir: &std::path::Path| {
            let mut server = Logged::spawn(&[
                "server",
                "--config",
                config.to_str().unwrap(),
                "--data-dir",
                dir.to_str().unwrap(),
            ]);
            let api = server.event("api_listening");
            let base = format!("http://{}", api["fields"]["addr"].as_str().unwrap());
            (server, base)
        };
        let agent = ureq::Agent::new_with_config(
            ureq::Agent::config_builder()
                .http_status_as_error(false)
                .build(),
        );
        let auth = format!("Bearer {token}");
        let get = |base: &str, path: &str| -> (u16, serde_json::Value) {
            let mut response = agent
                .get(&format!("{base}{path}"))
                .header("authorization", &auth)
                .call()
                .unwrap();
            let status = response.status().as_u16();
            let body = response.body_mut().read_to_string().unwrap();
            (
                status,
                serde_json::from_str(&body).unwrap_or(serde_json::Value::Null),
            )
        };

        let (mut server, base) = serve(&data);
        server.event("backups_scheduled");
        let mut started = agent
            .post(&format!("{base}/api/v1/admin/backups"))
            .header("authorization", &auth)
            .header("content-type", "application/json")
            .send(b"{}".as_slice())
            .unwrap();
        assert_eq!(
            started.status().as_u16(),
            202,
            "{}",
            started.body_mut().read_to_string().unwrap()
        );
        let deadline = Instant::now() + Duration::from_secs(30);
        let listed = loop {
            let (status, body) = get(&base, "/api/v1/admin/backups");
            assert_eq!(status, 200, "{body}");
            if body["backups"].as_array().is_some_and(|b| !b.is_empty())
                && body["scheduler"]["running"] == false
            {
                break body;
            }
            assert!(Instant::now() < deadline, "no backup appeared: {body}");
            thread::sleep(Duration::from_millis(100));
        };
        assert_eq!(listed["configured"], true);
        assert_eq!(listed["backups"][0]["key_required"], false);
        assert!(listed["scheduler"]["last_failure"].is_null(), "{listed}");
        server.terminate();

        let verified: serde_json::Value = serde_json::from_str(
            &Command::new(env!("CARGO_BIN_EXE_sentinel"))
                .args([
                    "admin",
                    "backup",
                    "verify",
                    "--dir",
                    backups.to_str().unwrap(),
                ])
                .output()
                .map(|o| {
                    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
                    String::from_utf8(o.stdout).unwrap()
                })
                .unwrap(),
        )
        .unwrap();
        assert_eq!(verified["ok"], true, "{verified}");
        assert_eq!(verified["integrity"], "ok");

        let restore = Command::new(env!("CARGO_BIN_EXE_sentinel"))
            .args([
                "admin",
                "restore",
                "--from",
                backups.to_str().unwrap(),
                "--data-dir",
                restored.to_str().unwrap(),
            ])
            .output()
            .unwrap();
        assert!(
            restore.status.success(),
            "{}",
            String::from_utf8_lossy(&restore.stderr)
        );
        let report: serde_json::Value = serde_json::from_slice(&restore.stdout).unwrap();
        assert_eq!(report["recovery"]["missing"], 0, "{report}");
        assert!(
            report["config_files"]
                .as_array()
                .unwrap()
                .iter()
                .any(|f| f == "controller.key"),
            "the link identity comes back, so workers keep their pin: {report}"
        );

        // The restored controller serves the same deployment, with the same
        // link identity and the credential issued before the backup.
        let (mut again, base) = serve(&restored);
        let first = server_fingerprint(&data);
        assert_eq!(server_fingerprint(&restored), first);
        let (status, tenants) = get(&base, "/api/v1/admin/tenants");
        assert_eq!(status, 200, "{tenants}");
        assert!(
            tenants["tenants"]
                .as_array()
                .unwrap()
                .iter()
                .any(|t| t["slug"] == "acme")
        );
        again.event("service_initialized");
        again.terminate();

        fn server_fingerprint(dir: &std::path::Path) -> Vec<u8> {
            fs::read(dir.join("controller.crt")).unwrap()
        }
    }

    /// R07: recovery onto a replacement host. A controller with an enrolled,
    /// connected worker is lost; its last backup is restored into a fresh
    /// data directory (the new host's), a controller started there on the
    /// same link address presents the same identity, and the worker — which
    /// kept its pin and never re-enrolls — reconnects on its own.
    #[test]
    fn a_worker_reconnects_to_a_controller_restored_onto_a_new_host() {
        if !(cfg!(feature = "server") && cfg!(feature = "worker")) {
            return;
        }
        let temp = tempdir().unwrap();
        let old_host = temp.path().join("old-host");
        let new_host = temp.path().join("new-host");
        let backups = temp.path().join("backups");
        let worker_dir = temp.path().join("worker");
        fs::create_dir_all(&old_host).unwrap();
        let admin = |args: &[&str]| {
            let mut child = Command::new(env!("CARGO_BIN_EXE_sentinel"))
                .arg("admin")
                .args(args)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            std::io::Write::write_all(
                child.stdin.as_mut().unwrap(),
                b"correct horse battery staple",
            )
            .unwrap();
            let output = child.wait_with_output().unwrap();
            assert!(
                output.status.success(),
                "{args:?}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            String::from_utf8(output.stdout).unwrap()
        };
        let old = old_host.to_str().unwrap();
        admin(&["bootstrap", "--username", "root", "--data-dir", old]);
        admin(&["tenant", "create", "--slug", "acme", "--data-dir", old]);
        admin(&[
            "pool",
            "create",
            "--name",
            "builders",
            "--tenant",
            "acme",
            "--data-dir",
            old,
        ]);
        let secret = admin(&["worker", "enroll", "--pool", "builders", "--data-dir", old]);
        let enrollment = temp.path().join("enrollment");
        fs::write(&enrollment, &secret).unwrap();

        let config = temp.path().join("server.toml");
        fs::write(
            &config,
            "listen = '127.0.0.1:0'\napi_listen = '127.0.0.1:0'",
        )
        .unwrap();
        let mut server = Logged::spawn(&[
            "server",
            "--config",
            config.to_str().unwrap(),
            "--data-dir",
            old,
        ]);
        let listening = server.event("link_listening");
        let addr = listening["fields"]["addr"].as_str().unwrap().to_owned();
        let fingerprint = listening["fields"]["fingerprint"]
            .as_str()
            .unwrap()
            .to_owned();
        let worker_config = temp.path().join("worker.toml");
        fs::write(
            &worker_config,
            format!(
                "controller = '{addr}'\ncontroller_fingerprint = '{fingerprint}'\nworker_name = 'survivor'\nenrollment_file = '{}'\ncpu_millis = 1000\nmemory_bytes = 1073741824\n",
                enrollment.display()
            ),
        )
        .unwrap();
        let mut worker = Logged::spawn(&[
            "worker",
            "--config",
            worker_config.to_str().unwrap(),
            "--data-dir",
            worker_dir.to_str().unwrap(),
        ]);
        assert_eq!(worker.event("link_connected")["fields"]["enrolled"], true);
        let id = fs::read_to_string(worker_dir.join("worker.id")).unwrap();

        // The old host goes: the controller stops, the last backup of its
        // data directory survives elsewhere.
        server.terminate();
        worker.nth_event("link_lost", 1, Duration::from_secs(15));
        let report: serde_json::Value = serde_json::from_str(&admin(&[
            "backup",
            "create",
            "--data-dir",
            old,
            "--to",
            backups.to_str().unwrap(),
        ]))
        .unwrap();
        let backup_id = report["id"].as_str().unwrap().to_owned();
        let verified = Command::new(env!("CARGO_BIN_EXE_sentinel"))
            .args([
                "admin",
                "backup",
                "verify",
                "--dir",
                backups.to_str().unwrap(),
            ])
            .output()
            .unwrap();
        assert!(
            verified.status.success(),
            "{}",
            String::from_utf8_lossy(&verified.stdout)
        );
        fs::remove_dir_all(&old_host).unwrap();

        // The new host: restored, then started on the address workers dial.
        let restore = Command::new(env!("CARGO_BIN_EXE_sentinel"))
            .args([
                "admin",
                "restore",
                "--from",
                backups.to_str().unwrap(),
                "--id",
                &backup_id,
                "--data-dir",
                new_host.to_str().unwrap(),
            ])
            .output()
            .unwrap();
        assert!(
            restore.status.success(),
            "{}",
            String::from_utf8_lossy(&restore.stderr)
        );
        let new_config = temp.path().join("new-server.toml");
        fs::write(
            &new_config,
            format!("listen = '{addr}'\napi_listen = '127.0.0.1:0'"),
        )
        .unwrap();
        let mut replacement = Logged::spawn(&[
            "server",
            "--config",
            new_config.to_str().unwrap(),
            "--data-dir",
            new_host.to_str().unwrap(),
        ]);
        let listening = replacement.event("link_listening");
        assert_eq!(
            listening["fields"]["fingerprint"],
            fingerprint.as_str(),
            "the same identity"
        );

        // The worker comes back by itself, as the worker it was.
        let again = worker.nth_event("link_connected", 2, Duration::from_secs(60));
        assert_eq!(again["fields"]["enrolled"], false, "no second enrollment");
        assert_eq!(again["fields"]["worker"].as_str().unwrap(), id.trim());
        worker.terminate();
        replacement.terminate();
        let listed = admin(&[
            "worker",
            "list",
            "--pool",
            "builders",
            "--data-dir",
            new_host.to_str().unwrap(),
        ]);
        assert!(
            listed.contains(id.trim()) && listed.contains("survivor"),
            "{listed}"
        );
    }
}

/// R01: `admin tenant storage` shows a tenant's policy, effective limits
/// and usage, changes the settings it is given, and `--inherit` drops them.
/// Host-local administration exists only in a server build.
#[cfg(feature = "server")]
#[test]
fn admin_tenant_storage_shows_sets_and_inherits() {
    let temp = tempfile::tempdir().unwrap();
    let data = temp.path().join("controller");
    std::fs::create_dir(&data).unwrap();
    let data = data.to_str().unwrap();
    let admin = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_sentinel"))
            .arg("admin")
            .args(args)
            .args(["--data-dir", data])
            .output()
            .expect("run sentinel")
    };
    let json = |output: Output| -> serde_json::Value {
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice(&output.stdout).unwrap()
    };
    let mut bootstrap = Command::new(env!("CARGO_BIN_EXE_sentinel"))
        .args([
            "admin",
            "bootstrap",
            "--username",
            "root",
            "--data-dir",
            data,
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    std::io::Write::write_all(
        bootstrap.stdin.as_mut().unwrap(),
        b"correct horse battery staple",
    )
    .unwrap();
    drop(bootstrap.stdin.take());
    let booted = bootstrap.wait_with_output().unwrap();
    assert!(
        booted.status.success(),
        "{}",
        String::from_utf8_lossy(&booted.stderr)
    );
    let created = admin(&["tenant", "create", "--slug", "acme"]);
    assert!(
        created.status.success(),
        "{}",
        String::from_utf8_lossy(&created.stderr)
    );
    let day = 86_400_000_i64;

    let shown = json(admin(&["tenant", "storage", "--tenant", "acme"]));
    assert_eq!(shown["policy"]["log_retention_ms"], serde_json::Value::Null);
    assert_eq!(shown["effective"]["log_retention_ms"], 14 * day);
    assert_eq!(shown["effective"]["artifact_retention_ms"], 90 * day);
    assert_eq!(shown["usage"]["log_bytes"], 0);

    let set = json(admin(&[
        "tenant",
        "storage",
        "--tenant",
        "acme",
        "--log-retention",
        "2d",
        "--quota",
        "1000",
    ]));
    assert_eq!(set["policy"]["log_retention_ms"], 2 * day);
    assert_eq!(set["policy"]["quota_bytes"], 1000);
    assert_eq!(set["effective"]["tenant_quota_bytes"], 1000);

    let partly = json(admin(&[
        "tenant",
        "storage",
        "--tenant",
        "acme",
        "--inherit",
        "quota",
    ]));
    assert_eq!(partly["policy"]["quota_bytes"], serde_json::Value::Null);
    assert_eq!(partly["policy"]["log_retention_ms"], 2 * day);
    let all = json(admin(&[
        "tenant",
        "storage",
        "--tenant",
        "acme",
        "--inherit",
        "all",
    ]));
    assert_eq!(all["policy"]["log_retention_ms"], serde_json::Value::Null);

    for refused in [
        vec!["tenant", "storage", "--tenant", "acme", "--inherit", "logs"],
        vec![
            "tenant",
            "storage",
            "--tenant",
            "acme",
            "--log-retention",
            "30",
        ],
        vec![
            "tenant",
            "storage",
            "--tenant",
            "acme",
            "--log-retention",
            "999d",
        ],
        vec!["tenant", "storage", "--tenant", "acme", "--repo", "nope"],
        vec!["tenant", "storage", "--tenant", "nope"],
    ] {
        assert!(!admin(&refused).status.success(), "{refused:?}");
    }
}
