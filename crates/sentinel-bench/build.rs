//! Captured at build time so each record names the build, not the checkout the runner is started
//! from: the compiler (no rustc on PATH at run time), the source commit and tracked-change state
//! the binary was compiled from, the profile and the target. A value git or cargo could not give
//! is the empty string, which the runner records as absent.
//! Cargo reruns this script when the toolchain, the sources (this crate, its sibling crates, the
//! workspace manifest, lock file and Cargo configuration) or the checkout's HEAD, branch ref or
//! index change, so the values cannot go stale.
use std::{env, process::Command};

fn git(args: &[&str]) -> Option<String> {
    let out = Command::new("git")
        .args(args)
        .output()
        .ok()
        .filter(|out| out.status.success())?;
    Some(String::from_utf8_lossy(&out.stdout).trim().to_owned())
}

/// Rebuild when the checked-out commit moves: HEAD itself (a checkout), the branch ref it names
/// (a commit), packed refs and the index (a staged change). A path git does not report is skipped,
/// because a missing watched path would rerun this script, and so rebuild the crate, every time.
fn watch_git() {
    let mut paths = vec![
        git(&["rev-parse", "--git-path", "HEAD"]),
        git(&["rev-parse", "--git-path", "index"]),
        git(&["rev-parse", "--git-path", "packed-refs"]),
    ];
    if let Some(head_ref) = git(&["symbolic-ref", "-q", "HEAD"]) {
        paths.push(git(&["rev-parse", "--git-path", &head_ref]));
    }
    for path in paths.into_iter().flatten() {
        if std::path::Path::new(&path).exists() {
            println!("cargo:rerun-if-changed={path}");
        }
    }
}

/// Rebuild when the rest of the tree the binary is compiled from changes: the sibling crates it depends
/// on, and the workspace manifest (profile, lints), lock file and Cargo configuration. Without these a
/// tracked edit outside this crate would rebuild the runner but leave `dirty` as the last build saw it.
/// A path that does not exist is skipped, because a missing watched path reruns this script every time.
fn watch_workspace() {
    let Some(manifest_dir) = env::var_os("CARGO_MANIFEST_DIR") else {
        return;
    };
    let manifest_dir = std::path::Path::new(&manifest_dir);
    let Some(root) = manifest_dir.parent().and_then(std::path::Path::parent) else {
        return;
    };
    for path in [
        root.join("Cargo.toml"),
        root.join("Cargo.lock"),
        root.join(".cargo").join("config.toml"),
        root.join("crates"),
    ] {
        if path.exists() {
            println!("cargo:rerun-if-changed={}", path.display());
        }
    }
}

fn main() {
    let rustc = env::var("RUSTC").unwrap_or_else(|_| "rustc".into());
    let version = Command::new(rustc)
        .arg("--version")
        .output()
        .ok()
        .filter(|out| out.status.success())
        .map(|out| String::from_utf8_lossy(&out.stdout).trim().to_owned())
        .unwrap_or_default();
    println!("cargo:rustc-env=SENTINEL_BENCH_RUSTC={version}");

    let commit = git(&["rev-parse", "HEAD"]).unwrap_or_default();
    // Tracked changes only: a scratch file next to the sources does not change what is built.
    let dirty = if commit.is_empty() {
        String::new()
    } else {
        git(&["status", "--porcelain", "--untracked-files=no"])
            .map(|status| (!status.is_empty()).to_string())
            .unwrap_or_default()
    };
    println!("cargo:rustc-env=SENTINEL_BENCH_BUILD_COMMIT={commit}");
    println!("cargo:rustc-env=SENTINEL_BENCH_BUILD_DIRTY={dirty}");
    println!(
        "cargo:rustc-env=SENTINEL_BENCH_BUILD_PROFILE={}",
        env::var("PROFILE").unwrap_or_default()
    );
    println!(
        "cargo:rustc-env=SENTINEL_BENCH_BUILD_TARGET={}",
        env::var("TARGET").unwrap_or_default()
    );

    println!("cargo:rerun-if-env-changed=RUSTC");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=Cargo.toml");
    println!("cargo:rerun-if-changed=src");
    watch_workspace();
    watch_git();
}
