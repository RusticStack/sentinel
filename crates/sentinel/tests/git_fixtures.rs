//! The G08 fixtures are the committed form of the generic Git verification matrix, so the page
//! and the scripts must keep naming the same rows and the same hook locations, and a script must
//! fail cleanly where a verification host has no container runtime.
#![cfg(target_os = "linux")]

use std::{fs, path::PathBuf, process::Command};

/// Each fixture script and the hook location its forge requires: a managed `post-receive.d`
/// directory on Gitea and Forgejo, Gitaly's per-repository `custom_hooks`, and a plain
/// `hooks/post-receive` on the bare repository.
const FIXTURES: [(&str, &str); 5] = [
    ("gitea-https", "post-receive.d"),
    ("gitea-ssh", "post-receive.d"),
    ("forgejo-https", "post-receive.d"),
    ("gitlab-ssh", "custom_hooks"),
    ("bare-sshd", "hooks/post-receive"),
];

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read(relative: &str) -> String {
    fs::read_to_string(root().join(relative)).unwrap_or_else(|error| panic!("{relative}: {error}"))
}

#[test]
fn the_fixture_scripts_fail_cleanly_without_a_runtime() {
    let script = root().join("scripts/git-fixtures/selftest.sh");
    let output = Command::new("bash")
        .arg(&script)
        .output()
        .unwrap_or_else(|error| panic!("{}: {error}", script.display()));
    assert!(
        output.status.success(),
        "scripts/git-fixtures/selftest.sh failed:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn the_page_and_the_scripts_name_the_same_fixtures_and_hooks() {
    let page = read("docs/generic-git-verification.md");
    let runner = read("scripts/git-fixtures/run.sh");
    let lib = read("scripts/git-fixtures/lib.sh");
    assert!(
        runner.contains("FX_NAMES"),
        "scripts/git-fixtures/run.sh no longer takes the matrix from lib.sh's FX_NAMES"
    );
    for (name, hook) in FIXTURES {
        let script = format!("scripts/git-fixtures/{name}.sh");
        assert!(
            root().join(&script).is_file(),
            "the matrix names {name} but {script} is missing"
        );
        assert!(
            page.contains(&format!("{name}.sh")),
            "docs/generic-git-verification.md does not name {script}"
        );
        assert!(
            lib.contains(name),
            "scripts/git-fixtures/lib.sh does not list {name} in the matrix"
        );
        // Gitea and Forgejo install their hook through the shared forge flow.
        let source = if name.starts_with("gitea") || name.starts_with("forgejo") {
            lib.clone()
        } else {
            read(&script)
        };
        assert!(
            source.contains(hook),
            "{script} does not install the {hook} hook the page records"
        );
    }
    for hook in ["post-receive.d", "custom_hooks", "hooks/post-receive"] {
        assert!(
            page.contains(hook),
            "the page no longer records the {hook} hook location"
        );
    }
}

#[test]
fn the_fixtures_install_the_shipped_hook() {
    let lib = read("scripts/git-fixtures/lib.sh");
    assert!(
        lib.contains("examples/hooks/post-receive"),
        "the fixtures no longer resolve the shipped post-receive hook"
    );
    assert!(
        root().join("examples/hooks/post-receive").is_file(),
        "examples/hooks/post-receive is missing"
    );
}

#[test]
fn every_image_the_fixtures_pull_is_pinned_by_digest() {
    let lib = read("scripts/git-fixtures/lib.sh");
    let mut seen = 0;
    for line in lib.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        if !key.ends_with("_IMAGE") || key.contains("SSHD") {
            continue;
        }
        seen += 1;
        assert!(
            value.contains("@sha256:"),
            "{key} is not pinned by digest: {value}"
        );
    }
    assert_eq!(seen, 4, "expected four digest-pinned images in lib.sh");
}
