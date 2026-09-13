use std::process::Command;

fn bench() -> Command {
    Command::new(env!("CARGO_BIN_EXE_sentinel-bench"))
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
    assert!(String::from_utf8_lossy(&out.stderr).contains("status 3"));
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
