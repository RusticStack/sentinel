//! Captured at build time so each record names its compiler without rustc on PATH at run time.
//! Cargo reruns this script when the toolchain changes, so the value cannot go stale.
use std::{env, process::Command};

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
    println!("cargo:rerun-if-env-changed=RUSTC");
    println!("cargo:rerun-if-changed=build.rs");
}
