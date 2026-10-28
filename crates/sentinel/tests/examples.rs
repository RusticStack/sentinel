//! The shipped example configurations and deployment files must keep working against the real
//! binary: the TOML files go through the real parser (`--check`), and every flag the units and
//! container files pass to `sentinel` must exist in that role's `--help`.
#![cfg(all(target_os = "linux", any(feature = "server", feature = "worker")))]

use std::{fs, path::PathBuf, process::Command};

fn example(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples")
        .join(name)
}

fn sentinel(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_sentinel"))
        .args(args)
        .output()
        .expect("run sentinel")
}

fn enabled(role: &str) -> bool {
    match role {
        "server" => cfg!(feature = "server"),
        _ => cfg!(feature = "worker"),
    }
}

/// Checks `text` as a configuration for `role` and returns the diagnostic on failure.
fn check(role: &str, text: &str) -> Result<(), String> {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("config.toml");
    fs::write(&file, text).unwrap();
    let output = sentinel(&[role, "--config", file.to_str().unwrap(), "--check"]);
    if output.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).into_owned())
    }
}

/// Removes the leading `# ` from lines that are commented-out settings (`# key = value`,
/// `# [table]`), leaving prose comments alone.
fn enable_commented_settings(text: &str) -> String {
    text.lines()
        .map(|line| {
            let Some(rest) = line.strip_prefix("# ") else {
                return line.to_owned();
            };
            let key = rest.split([' ', '=']).next().unwrap_or("");
            let setting = rest.contains(" = ")
                && !key.is_empty()
                && key.chars().all(|c| c.is_ascii_lowercase() || c == '_');
            let table = rest.starts_with('[') && rest.trim_end().ends_with(']');
            if setting || table {
                rest.to_owned()
            } else {
                line.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn example_configurations_load_through_the_real_parser() {
    for (file, role) in [
        ("server.toml", "server"),
        ("server-container.toml", "server"),
        ("worker.toml", "worker"),
    ] {
        if !enabled(role) {
            continue;
        }
        let text = fs::read_to_string(example(file)).unwrap();
        if let Err(error) = check(role, &text) {
            panic!("examples/{file} is rejected: {error}");
        }
    }
}

#[test]
fn every_commented_setting_in_the_examples_is_a_known_key() {
    // Uncommenting a setting must not hit an unknown key or a type error. Settings that exclude
    // each other (Tailcat versus direct TLS) are not combined by the examples, so a semantic
    // refusal is the only failure tolerated, and it must not be the generic parse error.
    for (file, role) in [("server.toml", "server"), ("worker.toml", "worker")] {
        if !enabled(role) {
            continue;
        }
        let text = enable_commented_settings(&fs::read_to_string(example(file)).unwrap());
        if let Err(error) = check(role, &text) {
            assert!(
                !error.contains("invalid configuration"),
                "examples/{file} has a commented setting the parser rejects: {error}"
            );
        }
    }
}

/// The `--flags` that appear in `words`, a command line after the role name.
fn flags(words: &[String]) -> Vec<String> {
    words
        .iter()
        .filter(|word| word.starts_with("--"))
        .map(|word| word.split('=').next().unwrap().to_owned())
        .collect()
}

fn assert_flags_exist(origin: &str, words: &[String]) {
    let Some(at) = words
        .iter()
        .position(|word| word == "server" || word == "worker")
    else {
        panic!("{origin}: no role in {words:?}");
    };
    let role = words[at].as_str();
    if !enabled(role) {
        return;
    }
    let help = String::from_utf8_lossy(&sentinel(&[role, "--help"]).stdout).into_owned();
    for flag in flags(&words[at + 1..]) {
        assert!(
            help.contains(&flag),
            "{origin}: `sentinel {role}` has no {flag} flag"
        );
    }
}

#[test]
fn unit_and_container_command_lines_use_flags_that_exist() {
    let mut seen = 0;
    for name in ["sentinel-server.service", "sentinel-worker.service"] {
        let text = fs::read_to_string(example(name)).unwrap();
        for line in text.lines() {
            let Some(command) = line.strip_prefix("ExecStart=") else {
                continue;
            };
            let words: Vec<String> = command.split_whitespace().map(str::to_owned).collect();
            assert!(words[0].ends_with("/sentinel"), "{name}: {command}");
            assert_flags_exist(name, &words);
            seen += 1;
        }
    }
    for name in [
        "compose.server.yaml",
        "compose.worker.yaml",
        "Containerfile.server",
        "Containerfile.worker",
    ] {
        let text = fs::read_to_string(example(name)).unwrap();
        for line in text.lines() {
            let line = line.trim();
            let list = line
                .strip_prefix("command:")
                .or_else(|| line.strip_prefix("CMD"))
                .map(str::trim);
            let Some(list) = list.filter(|list| list.starts_with('[')) else {
                continue;
            };
            let words: Vec<String> = list
                .trim_matches(|c| c == '[' || c == ']')
                .split(',')
                .map(|word| word.trim().trim_matches('"').to_owned())
                .collect();
            // Health checks and other lists are not the service's command line.
            if words
                .iter()
                .any(|word| word == "server" || word == "worker")
            {
                assert_flags_exist(name, &words);
                seen += 1;
            }
        }
    }
    assert_eq!(
        seen, 6,
        "expected two units and four container command lines"
    );
}
