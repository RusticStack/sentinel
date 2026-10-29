use std::process::{Command, Output};

fn bench() -> Command {
    Command::new(env!("CARGO_BIN_EXE_sentinel-bench"))
}

/// False where git cannot read the checkout (a Windows-created worktree seen from Linux).
fn source_readable() -> bool {
    Command::new("git")
        .args(["-C", env!("CARGO_MANIFEST_DIR"), "rev-parse", "HEAD"])
        .output()
        .is_ok_and(|out| out.status.success())
}

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
    assert!(summary["mean_ns"].as_u64().unwrap() > 0);
    assert!(summary["stddev_ns"].as_u64().is_some());
    assert!(summary["mad_ns"].as_u64().is_some());
    assert_eq!(summary["p95_is_max"], true);
    assert_eq!(record["warm_state_basis"], "warmup-run");
    assert!(record["conditions"].is_object());
    assert!(record.get("interleave").is_none());
    assert!(record["host"]["cpus_online"].as_u64().unwrap() >= 1);
    assert!(record["image"].is_null());
    assert!(record["limits"]["cpus"].is_null());
}

#[test]
fn a_record_names_its_source_and_compiler_even_outside_the_checkout() {
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

/// The record names the build the runner was compiled from, so it stays true when the checkout
/// is no longer readable or has moved on. With `GIT_DIR` pointing nowhere, the run-time `git` the
/// runner used to ask fails and the old code refused to write.
#[test]
fn a_record_names_its_build_not_the_checkout_head() {
    let head = Command::new("git")
        .args(["-C", env!("CARGO_MANIFEST_DIR"), "rev-parse", "HEAD"])
        .output()
        .ok()
        .filter(|out| out.status.success())
        .map(|out| String::from_utf8_lossy(&out.stdout).trim().to_owned());
    let Some(head) = head else {
        return; // built outside a readable checkout: the build has no commit to name
    };
    let out = bench()
        .env(
            "GIT_DIR",
            std::env::temp_dir().join("sentinel-bench-no-such-git-dir"),
        )
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
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let record: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let build = &record["build"];
    assert_eq!(build["commit"], head.as_str(), "the build-time commit");
    assert_eq!(record["source"]["git_commit"], head.as_str());
    assert!(build["dirty"].is_boolean());
    assert_eq!(build["debug_assertions"], cfg!(debug_assertions));
    assert_eq!(
        build["profile"],
        if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        }
    );
    assert!(!build["target"].as_str().unwrap().is_empty());
    let exe = std::fs::read(env!("CARGO_BIN_EXE_sentinel-bench")).unwrap();
    assert_eq!(
        build["binary_blake3"],
        blake3::hash(&exe).to_hex().to_string().as_str(),
        "the digest of the running executable"
    );
}

#[test]
fn an_unwarmed_or_cold_declaration_is_labelled_unverified() {
    let out = bench()
        .args(["--samples", "1", "--warmup", "0", "--warm-state", "warm"])
        .output()
        .unwrap();
    if !source_readable() {
        assert!(refused_for_provenance(&out), "{out:?}");
        return;
    }
    assert!(out.status.success(), "{out:?}");
    let record: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(record["warm_state_basis"], "unverified");
    assert!(record["summary"].get("stddev_ns").is_none());
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

/// A `systemd-run` stand-in that drops its own options and runs the command,
/// so the scoped runtime can be exercised where no user manager exists.
#[cfg(unix)]
fn fake_systemd_run(dir: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    let shim = dir.join("systemd-run");
    std::fs::write(
        &shim,
        "#!/bin/sh\nwhile [ \"$1\" != \"--\" ]; do shift; done\nshift\nexec \"$@\"\n",
    )
    .unwrap();
    std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o755)).unwrap();
}

#[cfg(unix)]
#[test]
fn an_interleaved_group_writes_one_record_per_runtime_in_abba_order() {
    let dir = std::env::temp_dir().join(format!("sentinel-bench-group-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    fake_systemd_run(&dir);
    let path = format!(
        "{}:{}",
        dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let output = dir.join("out.jsonl");
    let out = bench()
        .env("PATH", path)
        .args([
            "--runtime",
            "direct",
            "--interleave",
            "scoped",
            "--samples",
            "4",
            "--warmup",
            "1",
            "--warm-state",
            "warm",
        ])
        .arg("--output")
        .arg(&output)
        .output()
        .unwrap();
    if !source_readable() {
        assert!(refused_for_provenance(&out), "{out:?}");
        std::fs::remove_dir_all(dir).unwrap();
        return;
    }
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(out.stdout.is_empty(), "records go to --output");
    let text = std::fs::read_to_string(&output).unwrap();
    let records: Vec<serde_json::Value> = text
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(records.len(), 2, "one record per runtime");
    assert_eq!(records[0]["runtime"], "direct");
    assert_eq!(records[1]["runtime"], "scoped");
    let seqs = |r: &serde_json::Value| -> Vec<u64> {
        r["samples"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s["seq"].as_u64().unwrap())
            .collect()
    };
    // ABBA: sample 0 runs direct then scoped, sample 1 scoped then direct, ...
    assert_eq!(seqs(&records[0]), [0, 3, 4, 7]);
    assert_eq!(seqs(&records[1]), [1, 2, 5, 6]);
    for r in &records {
        assert_eq!(
            r["interleave"]["runtimes"],
            serde_json::json!(["direct", "scoped"])
        );
        assert_eq!(r["interleave"]["order"], "abba");
        assert_eq!(r["interleave"]["conditions"], "per-runtime");
        assert_eq!(r["summary"]["count"], 4);
        assert!(r["conditions"].is_object());
        for s in r["samples"].as_array().unwrap() {
            assert_eq!(s["exit_code"], 0);
        }
    }
    std::fs::remove_dir_all(dir).unwrap();
}
