//! The B11 harness on synthetic data only; no result exists or is implied.

use std::{
    path::{Path, PathBuf},
    process::{Command, Output},
};

use serde_json::{Value, json};

const SHA: &str = "0123456789abcdef0123456789abcdef01234567";

fn contract_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../bench/contracts/b11-blacksmith.json")
}

fn contract() -> Value {
    serde_json::from_slice(&std::fs::read(contract_path()).unwrap()).unwrap()
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("sentinel-b11-{name}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn header() -> Value {
    let c = contract();
    json!({ "format": "sentinel.b11-samples/1", "contract": c["id"], "revision": c["revision"] })
}

fn side(ns: u64) -> Value {
    json!({ "sha": SHA, "trigger_to_required_ns": ns, "outcome": "pass" })
}

/// `n` pairs for one series whose Sentinel time is `ratio` of Blacksmith's, with a deterministic wobble.
fn pairs(lane: &str, condition: &str, n: u32, ratio: f64) -> Vec<Value> {
    (0..n)
        .map(|i| {
            let wobble = 1.0 + 0.05 * f64::from((i * 7) % 11) / 10.0;
            let b = 10_000_000_000.0 * (1.0 + 0.1 * f64::from((i * 5) % 13) / 12.0);
            json!({
                "lane": lane,
                "condition": condition,
                "pair": i,
                "order": if i % 2 == 0 { "sentinel-first" } else { "blacksmith-first" },
                "sentinel": side((b * ratio * wobble) as u64),
                "blacksmith": side(b as u64),
            })
        })
        .collect()
}

fn all_series(n: u32, ratio: f64) -> Vec<Value> {
    let c = contract();
    let mut out = Vec::new();
    for lane in c["series"]["lanes"].as_array().unwrap() {
        for condition in c["series"]["conditions"].as_array().unwrap() {
            out.extend(pairs(
                lane.as_str().unwrap(),
                condition.as_str().unwrap(),
                n,
                ratio,
            ));
        }
    }
    out
}

fn write(dir: &Path, header: &Value, lines: &[Value]) -> PathBuf {
    let path = dir.join("samples.jsonl");
    let mut text = header.to_string();
    for l in lines {
        text.push('\n');
        text.push_str(&l.to_string());
    }
    std::fs::write(&path, text).unwrap();
    path
}

fn harness(samples: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sentinel-b11"))
        .arg("--contract")
        .arg(contract_path())
        .arg("--samples")
        .arg(samples)
        .output()
        .unwrap()
}

fn report(out: &Output) -> Value {
    serde_json::from_slice(&out.stdout).unwrap_or_else(|_| {
        panic!("no report: {}", String::from_utf8_lossy(&out.stderr));
    })
}

#[test]
fn the_committed_contract_keeps_the_frozen_gate() {
    let c = contract();
    assert_eq!(c["format"], "sentinel.b11-contract/1");
    let gate = &c["gate"];
    assert_eq!(gate["ratio_limit"], 0.5);
    assert_eq!(gate["percentile"], 95);
    assert_eq!(gate["min_pairs"], 100);
    assert_eq!(gate["confidence"], 0.95);
    assert_eq!(gate["bound"], "one-sided-upper");
    assert_eq!(gate["bootstrap"]["resamples"], 10_000);
    assert_eq!(
        c["series"]["conditions"],
        json!(["cold", "warm", "small-edit"])
    );
    assert_eq!(c["disclosure"]["label"], "hosted-service comparison");
    assert!(
        c["status"].as_str().unwrap().contains("no samples exist"),
        "the contract holds no results"
    );
}

#[test]
fn a_full_set_of_clear_wins_passes_and_is_labelled_a_hosted_comparison() {
    let dir = scratch("pass");
    let out = harness(&write(&dir, &header(), &all_series(100, 0.40)));
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let r = report(&out);
    assert_eq!(r["format"], "sentinel.b11-report/1");
    assert_eq!(r["verdict"], "pass");
    assert_eq!(r["label"], "hosted-service comparison");
    assert_eq!(r["contract"]["id"], "b11-blacksmith");
    assert_eq!(r["contract"]["blake3"].as_str().unwrap().len(), 64);
    assert_eq!(r["missing"], json!([]));
    let series = r["series"].as_array().unwrap();
    assert_eq!(series.len(), 9, "3 lanes x 3 conditions");
    for s in series {
        assert_eq!(s["pairs"], 100);
        assert_eq!(s["paired_ratios"].as_array().unwrap().len(), 100);
        assert!(s["ratio_upper"].as_f64().unwrap() < 0.5);
    }
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn the_report_is_identical_across_runs() {
    let dir = scratch("repeat");
    let samples = write(&dir, &header(), &all_series(100, 0.40));
    assert_eq!(harness(&samples).stdout, harness(&samples).stdout);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn a_missing_series_fails_the_gate() {
    let dir = scratch("missing");
    let mut lines = all_series(100, 0.40);
    lines.retain(|l| !(l["lane"] == "gson" && l["condition"] == "cold"));
    let out = harness(&write(&dir, &header(), &lines));
    assert_eq!(out.status.code(), Some(1));
    let r = report(&out);
    assert_eq!(r["verdict"], "fail");
    assert_eq!(r["missing"], json!(["gson/cold"]));
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn a_failed_required_check_fails_the_gate_without_leaving_the_data() {
    let dir = scratch("failed");
    let mut lines = all_series(100, 0.40);
    let victim = lines
        .iter_mut()
        .find(|l| l["lane"] == "cli" && l["condition"] == "warm" && l["pair"] == 5)
        .unwrap();
    victim["blacksmith"]["outcome"] = json!("fail");
    let out = harness(&write(&dir, &header(), &lines));
    assert_eq!(out.status.code(), Some(1));
    let r = report(&out);
    assert_eq!(r["verdict"], "fail");
    let cli_warm = r["series"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["lane"] == "cli" && s["condition"] == "warm")
        .unwrap();
    assert_eq!(cli_warm["verdict"], "fail");
    assert_eq!(cli_warm["pairs"], 100);
    assert_eq!(cli_warm["non_pass"]["blacksmith_fail"], 1);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn a_short_series_is_insufficient_and_exits_nonzero() {
    let dir = scratch("short");
    let out = harness(&write(&dir, &header(), &all_series(40, 0.40)));
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(report(&out)["verdict"], "insufficient");
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn malformed_input_is_an_error_not_a_verdict() {
    let dir = scratch("bad");
    let one = || pairs("cli", "warm", 1, 0.4);
    let mut zero = one();
    zero[0]["sentinel"]["trigger_to_required_ns"] = json!(0);
    let mut other_revision = header();
    other_revision["revision"] = json!(99);
    let mut duplicate = one();
    duplicate.push(duplicate[0].clone());
    let mut unknown_field = one();
    unknown_field[0]["sentinel"]["note"] = json!("x");
    let mut bad_sha = one();
    bad_sha[0]["sentinel"]["sha"] = json!("abc");
    let cases: Vec<(&str, Value, Vec<Value>)> = vec![
        ("zero duration", header(), zero),
        ("unknown lane", header(), pairs("nope", "warm", 1, 0.4)),
        (
            "unknown condition",
            header(),
            pairs("cli", "lukewarm", 1, 0.4),
        ),
        ("other revision", other_revision, one()),
        ("duplicate pair", header(), duplicate),
        ("unknown field", header(), unknown_field),
        ("bad sha", header(), bad_sha),
    ];
    for (name, head, lines) in cases {
        let out = harness(&write(&dir, &head, &lines));
        assert_eq!(out.status.code(), Some(2), "{name}");
        assert!(
            out.stdout.is_empty(),
            "{name}: no report on malformed input"
        );
        assert!(!out.stderr.is_empty(), "{name}");
    }
    std::fs::remove_dir_all(dir).unwrap();
}

/// Plumbing only: `bench/b11-collect.py replay` turned the committed GitHub self-hosted baselines into
/// pair lines whose two sides are one recorded run. The ratio is 1.0 by construction and the series are
/// short, so the harness must read them and decline to pass; nothing here is a Blacksmith result.
#[test]
fn the_collectors_dry_run_output_is_read_by_the_harness_and_cannot_pass() {
    let samples =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../bench/b11-dryrun-samples.jsonl");
    let out = harness(&samples);
    assert_eq!(
        out.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let r = report(&out);
    assert_eq!(r["verdict"], "fail");
    assert_eq!(
        r["missing"],
        json!([
            "cli/cold",
            "cli/small-edit",
            "ripgrep/cold",
            "ripgrep/small-edit",
            "gson/cold",
            "gson/small-edit"
        ])
    );
    let series = r["series"].as_array().unwrap();
    let warm: Vec<_> = series.iter().filter(|s| s["condition"] == "warm").collect();
    assert_eq!(warm.len(), 3);
    for s in warm {
        assert_eq!(s["pairs"], 5);
        assert_eq!(s["verdict"], "insufficient");
        assert_eq!(s["p95_ratio"], 1.0);
        assert_eq!(s["sha_mismatches"], 0);
        assert_eq!(s["order_violations"], 0);
        let phases = s["phases"].as_object().unwrap();
        assert!(phases.contains_key("queue") && phases.contains_key("run"));
        assert!(s["job"]["sentinel"]["count"].as_u64().unwrap() > 0);
    }
}

#[test]
fn the_contract_leaves_the_resource_envelope_and_hardware_fields_unfilled() {
    let c = contract();
    for side in ["sentinel", "blacksmith"] {
        for (k, v) in c["resource_envelope"][side].as_object().unwrap() {
            assert!(
                v.is_null(),
                "{side}.{k} must stay unfilled until sizes are known"
            );
        }
    }
    assert!(
        c["hosted_hardware_disclosure_fields"]["fields"]
            .as_array()
            .unwrap()
            .len()
            >= 6
    );
    assert!(
        c["freshness"]["rule"]
            .as_str()
            .unwrap()
            .contains("test results never")
    );
    assert!(
        c["failure_counts"]["rule"]
            .as_str()
            .unwrap()
            .contains("censored")
    );
}
