//! The spawn-cost bench example is a harness, not a test. This runs it with tiny parameters and checks the record's
//! shape; it asserts nothing about speed. The example is built beside the test binaries (`cargo test` builds
//! examples). When it is not there the tests print `skipped:` and pass, unless `SENTINEL_REQUIRE_BENCH_EXAMPLES=1`.
#![cfg(unix)]

use std::{path::PathBuf, process::Command};

fn example() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let path = exe
        .parent()?
        .parent()?
        .join("examples")
        .join("spawn-cost-bench");
    path.is_file().then_some(path)
}

fn available() -> Option<PathBuf> {
    let found = example();
    if found.is_none() {
        assert!(
            std::env::var_os("SENTINEL_REQUIRE_BENCH_EXAMPLES").is_none(),
            "the spawn-cost-bench example is not built"
        );
        println!("skipped: the spawn-cost-bench example is not built beside the test binaries");
    }
    found
}

#[test]
fn the_record_has_every_resident_size_and_variant_and_the_order_reverses() {
    let Some(bin) = available() else { return };
    let out = Command::new(bin)
        .args(["--rounds", "2", "--spawns", "5", "--resident-mib", "0,4"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8(out.stdout).unwrap();
    assert_eq!(text.lines().count(), 1, "exactly one record line");
    let line = text.trim_end();
    assert!(line.starts_with("{\"schema\":\"sentinel-bench/spawn-cost/1\""));
    for variant in ["plain", "pre_exec_noop", "die_with_parent"] {
        assert_eq!(
            line.matches(&format!("\"variant\":\"{variant}\"")).count(),
            2,
            "{variant} once per resident size"
        );
    }
    assert!(line.contains("\"resident_mib\":0,\"variant\""));
    assert!(line.contains("\"resident_mib\":4,\"variant\""));
    assert!(line.contains("\"samples\":10"), "2 rounds x 5 spawns");
    // Round 1 runs the cells in the opposite order of round 0.
    let order = line.split("\"order\":[").nth(1).unwrap();
    let first = order.find("\"0MiB/plain\"").unwrap();
    let last = order.rfind("\"0MiB/plain\"").unwrap();
    assert!(first < last);
}

#[test]
fn a_bad_argument_is_refused_without_a_record() {
    let Some(bin) = available() else { return };
    for args in [
        &["--bogus"][..],
        &["--rounds", "0"][..],
        &["--resident-mib"][..],
    ] {
        let out = Command::new(&bin).args(args).output().unwrap();
        assert!(!out.status.success(), "{args:?}");
        assert!(out.stdout.is_empty(), "{args:?}");
    }
}
