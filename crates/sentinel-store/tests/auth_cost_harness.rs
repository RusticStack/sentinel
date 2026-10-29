//! The auth-cost bench example is a harness, not a test, but a harness that stopped measuring what it names would
//! hand out numbers nobody could trust. This runs it with tiny parameters and checks the record's shape and the
//! outcomes it asserts about itself; it measures nothing and asserts nothing about speed.
//!
//! The example is built beside the test binaries (`cargo test` builds examples). When it is not there the tests
//! print `skipped:` and pass, unless `SENTINEL_REQUIRE_BENCH_EXAMPLES=1`, which makes a missing example a failure.

use std::{path::PathBuf, process::Command};

use serde_json::Value;

fn example() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let name = format!("auth-cost-bench{}", std::env::consts::EXE_SUFFIX);
    let path = exe.parent()?.parent()?.join("examples").join(name);
    path.is_file().then_some(path)
}

fn available() -> Option<PathBuf> {
    let found = example();
    if found.is_none() {
        assert!(
            std::env::var_os("SENTINEL_REQUIRE_BENCH_EXAMPLES").is_none(),
            "the auth-cost-bench example is not built"
        );
        println!("skipped: the auth-cost-bench example is not built beside the test binaries");
    }
    found
}

const TINY: [&str; 11] = [
    "--rounds",
    "2",
    "--iterations",
    "12",
    "--argon-iterations",
    "2",
    "--sessions",
    "8",
    "--tokens",
    "8",
    "--seed",
];

fn run(bin: &PathBuf, dir: &std::path::Path, seed: &str, extra: &[&str]) -> std::process::Output {
    Command::new(bin)
        .arg("--dir")
        .arg(dir)
        .args(TINY)
        .arg(seed)
        .args(extra)
        .output()
        .unwrap()
}

fn record(out: &std::process::Output) -> Value {
    assert!(
        out.status.success(),
        "bench failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8(out.stdout.clone()).unwrap();
    let line = text.lines().next().unwrap();
    assert_eq!(text.lines().count(), 1, "exactly one record line");
    serde_json::from_str(line).unwrap()
}

fn result<'a>(record: &'a Value, op: &str) -> &'a Value {
    record["results"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["op"] == op)
        .unwrap_or_else(|| panic!("no result for {op}"))
}

#[test]
fn the_record_names_every_operation_with_its_samples_and_the_stored_argon2_parameters() {
    let Some(bin) = available() else { return };
    let dir = tempfile::tempdir().unwrap();
    let rec = record(&run(&bin, dir.path(), "7", &[]));
    assert_eq!(rec["schema"], "sentinel-bench/auth-cost/1");
    assert_eq!(rec["seed"], 7);
    assert_eq!(rec["warmups"], 3);
    assert_eq!(rec["argon2"]["algorithm"], "argon2id");
    assert_eq!(rec["argon2"]["m_kib"], 19 * 1024);
    assert_eq!(rec["argon2"]["t"], 2);
    assert_eq!(rec["argon2"]["p"], 1);
    assert!(rec["timer_floor_ns"]["median"].is_u64());

    let results = rec["results"].as_array().unwrap();
    assert_eq!(results.len(), 14);
    for r in results {
        let op = r["op"].as_str().unwrap();
        let per_round = if op.starts_with("argon2_") || op.starts_with("login_") {
            2
        } else {
            12
        };
        assert_eq!(r["calls_per_round"], per_round, "{op}");
        assert_eq!(r["samples"], per_round * 2, "{op}");
        assert_eq!(r["round_median_ns"].as_array().unwrap().len(), 2, "{op}");
        assert!(r["median_ns"].as_u64().unwrap() >= r["min_ns"].as_u64().unwrap());
        assert!(r["max_ns"].as_u64().unwrap() >= r["p99_ns"].as_u64().unwrap());
        assert_eq!(
            r["p95_is_max"].as_bool().unwrap(),
            per_round * 2 < 20,
            "{op}"
        );
    }
    // The hash is the dominant cost, and the cheap lookups are not: an operation that did nothing would show 0.
    for op in [
        "argon2_hash",
        "argon2_verify_accept",
        "argon2_verify_reject",
    ] {
        assert!(
            result(&rec, op)["median_ns"].as_u64().unwrap() > 1_000_000,
            "{op}"
        );
    }
}

#[test]
fn the_operation_order_reverses_every_round() {
    let Some(bin) = available() else { return };
    let dir = tempfile::tempdir().unwrap();
    let rec = record(&run(&bin, dir.path(), "1", &[]));
    let order = rec["order"].as_array().unwrap();
    assert_eq!(order.len(), 2);
    let mut reversed = order[0].as_array().unwrap().clone();
    reversed.reverse();
    assert_eq!(&reversed, order[1].as_array().unwrap());
}

#[test]
fn unknown_and_locked_logins_coalesce_their_audit_rows_and_a_failed_login_writes_one() {
    let Some(bin) = available() else { return };
    let dir = tempfile::tempdir().unwrap();
    let rec = record(&run(
        &bin,
        dir.path(),
        "3",
        &[
            "--ops",
            "login_accepted,login_rejected,login_locked,login_unknown_username,token_issue",
        ],
    ));
    // 2 rounds x 2 calls.
    assert_eq!(result(&rec, "login_accepted")["audit_rows_added"], 4);
    assert_eq!(result(&rec, "login_rejected")["audit_rows_added"], 4);
    assert_eq!(result(&rec, "token_issue")["audit_rows_added"], 24);
    for op in ["login_locked", "login_unknown_username"] {
        let rows = result(&rec, op)["audit_rows_added"].as_i64().unwrap();
        assert!(
            (0..=4).contains(&rows),
            "{op} wrote {rows} rows for 4 calls"
        );
    }
}

#[test]
fn a_subset_runs_only_the_operations_asked_for_and_leaves_nothing_behind() {
    let Some(bin) = available() else { return };
    let dir = tempfile::tempdir().unwrap();
    let rec = record(&run(
        &bin,
        dir.path(),
        "1",
        &["--ops", "session_validate_conn,session_validate_miss"],
    ));
    assert_eq!(rec["results"].as_array().unwrap().len(), 2);
    assert_eq!(
        std::fs::read_dir(dir.path()).unwrap().count(),
        0,
        "the bench removes its scratch"
    );
}

#[test]
fn a_bad_argument_is_refused_without_a_record() {
    let Some(bin) = available() else { return };
    let dir = tempfile::tempdir().unwrap();
    for extra in [&["--ops", "no_such_operation"][..], &["--bogus"][..]] {
        let out = run(&bin, dir.path(), "1", extra);
        assert!(!out.status.success());
        assert!(out.stdout.is_empty(), "a refused run prints no record");
    }
    let out = Command::new(&bin).output().unwrap();
    assert!(!out.status.success(), "--dir is required");
}
