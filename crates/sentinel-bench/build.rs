//! Records the compiler that built the runner, so every benchmark record
//! names its tool revision even when the runner executes as a user without
//! `rustc` on `PATH` (the F05 baseline's gap). Cargo rebuilds everything,
//! this script included, when the toolchain changes, so the value is never
//! stale.
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
