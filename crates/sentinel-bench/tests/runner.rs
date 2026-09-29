use std::process::{Command, Output};

fn bench() -> Command {
    Command::new(env!("CARGO_BIN_EXE_sentinel-bench"))
}

/// Whether git can read the checkout the runner was built from. Where it
/// cannot (for example Linux git on a worktree that Windows git created,
/// whose `.git` names a `D:/` path), the runner must refuse to measure
/// rather than write a record without its source.
fn source_readable() -> bool {
    Command::new("git")
        .args(["-C", env!("CARGO_MANIFEST_DIR"), "rev-parse", "HEAD"])
        .output()
        .is_ok_and(|out| out.status.success())
}

/// The refusal a runner without readable provenance gives: no record.
fn refused_for_provenance(out: &Output) -> bool {
    !out.status.success()
        && out.stdout.is_empty()
        && String::from_utf8_lossy(&out.stderr).contains("cannot read the source commit")
}

#[test]
fn direct_noop_emits_one_machine_readable_record() {
    let out = bench()
        .args([
            "--runtime",
            "direct",
            "--samples",
            "3",
            "--warmup",
            "1",
            "--warm-state",
            "warm",
            "--label",
            "test",
        ])
        .output()
        .unwrap();
    if !source_readable() {
        assert!(refused_for_provenance(&out), "{out:?}");
        return;
    }
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert_eq!(stdout.lines().count(), 1, "exactly one JSON line");
    let record: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(record["schema"], "sentinel-bench/1");
    assert_eq!(record["runtime"], "direct");
    assert_eq!(record["workload"], "noop");
    assert_eq!(record["warm_state"], "warm");
    assert_eq!(record["label"], "test");
    assert_eq!(record["warmup"], 1);
    let samples = record["samples"].as_array().unwrap();
    assert_eq!(samples.len(), 3);
    for (i, s) in samples.iter().enumerate() {
        assert_eq!(s["index"], i as u64);
        assert_eq!(s["exit_code"], 0);
        assert!(s["elapsed_ns"].as_u64().unwrap() > 0);
        if cfg!(unix) {
            assert!(s["max_rss_kib"].as_u64().unwrap() > 0);
        } else {
            assert!(
                s.get("max_rss_kib").is_none(),
                "unmeasured fields are absent, not zero"
            );
        }
    }
    let summary = &record["summary"];
    assert_eq!(summary["count"], 3);
    assert!(summary["min_ns"].as_u64().unwrap() <= summary["median_ns"].as_u64().unwrap());
    assert!(summary["p95_ns"].as_u64().unwrap() <= summary["max_ns"].as_u64().unwrap());
    assert!(record["host"]["cpus_online"].as_u64().unwrap() >= 1);
    assert!(record["image"].is_null());
    assert!(record["limits"]["cpus"].is_null());
}

#[test]
fn a_record_names_its_source_and_compiler_even_outside_the_checkout() {
    // F05: the committed baseline ran outside the checkout as a user without
    // rustc on PATH, and its record carried neither revision.
    // The compiler is recorded at build time, so it no longer depends on
    // PATH at run time; the commit is asked of the build's own checkout.
    let out = bench()
        .current_dir(std::env::temp_dir())
        .args([
            "--runtime",
            "direct",
            "--samples",
            "1",
            "--warmup",
            "0",
            "--warm-state",
            "warm",
        ])
        .output()
        .unwrap();
    if !source_readable() {
        assert!(refused_for_provenance(&out), "{out:?}");
        return;
    }
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let record: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let commit = record["source"]["git_commit"].as_str().unwrap();
    assert_eq!(commit.len(), 40, "{commit}");
    assert!(commit.bytes().all(|b| b.is_ascii_hexdigit()), "{commit}");
    assert!(record["source"]["git_dirty"].is_boolean());
    let rustc = record["tools"]["rustc"].as_str().unwrap();
    assert!(rustc.starts_with("rustc "), "{rustc}");
}

#[test]
fn failing_workload_writes_no_record() {
    let dir = std::env::temp_dir().join(format!("sentinel-bench-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let output = dir.join("out.jsonl");
    let out = bench()
        .args([
            "--workload",
            "nonzero-exit",
            "--samples",
            "1",
            "--warmup",
            "0",
            "--warm-state",
            "warm",
        ])
        .arg("--output")
        .arg(&output)
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(
        refused_for_provenance(&out) || String::from_utf8_lossy(&out.stderr).contains("status 3"),
        "{out:?}"
    );
    assert!(!output.exists(), "no partial record on failure");
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn podman_runtime_requires_image() {
    let out = bench()
        .args(["--runtime", "podman", "--warm-state", "cold"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("--image is required"));
}

/// B01: a contract whose reference host is not this one is refused before
/// anything runs, and nothing is written.
#[test]
fn a_contract_for_another_host_measures_nothing() {
    let dir = std::env::temp_dir().join(format!("sentinel-bench-drift-{}", std::process::id()));
    std::fs::create_dir_all(dir.join("src/repo")).unwrap();
    let contract = dir.join("contract.json");
    std::fs::write(
        &contract,
        serde_json::json!({
            "format": "sentinel.bench-contract/1",
            "id": "drift-test",
            "revision": 1,
            "reference_host": {
                "cpu_model": "no such processor",
                "cpus_online": 100_000,
                "mem_total_kib_min": u64::MAX,
                "podman": "podman version 0.0.0"
            },
            "allocation": { "total": { "cpus": "1", "memory": "256m" } },
            "sources": [{ "name": "repo", "commit": "0000000000000000000000000000000000000000", "path": "src/repo" }],
            "images": { "base": "docker.io/library/busybox@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662" },
            "freshness": { "max_record_age_days": 30 },
            "conditions": { "warm": { "prepare": "true", "samples": 1 } },
            "lanes": [{ "id": "noop", "image": "base", "run": "true" }]
        })
        .to_string(),
    )
    .unwrap();
    let output = dir.join("out.jsonl");
    let out = bench()
        .args([
            "--lane",
            "noop",
            "--condition",
            "warm",
            "--runtime",
            "direct",
        ])
        .arg("--contract")
        .arg(&contract)
        .arg("--root")
        .arg(&dir)
        .arg("--output")
        .arg(&output)
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        refused_for_provenance(&out)
            || (stderr.contains("differ from contract drift-test")
                && stderr.contains("cpu model")
                && stderr.contains("source repo")),
        "{stderr}"
    );
    assert!(!output.exists(), "nothing measured, nothing written");
    let unknown = bench()
        .args(["--lane", "nope", "--condition", "warm"])
        .arg("--contract")
        .arg(&contract)
        .arg("--root")
        .arg(&dir)
        .output()
        .unwrap();
    assert!(!unknown.status.success());
    let stderr = String::from_utf8_lossy(&unknown.stderr);
    assert!(
        refused_for_provenance(&unknown) || stderr.contains("no lane `nope`"),
        "{stderr}"
    );
    std::fs::remove_dir_all(dir).unwrap();
}
