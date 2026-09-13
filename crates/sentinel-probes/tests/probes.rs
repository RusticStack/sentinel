use std::{fs, path::PathBuf, process::Command};

fn probe() -> Command {
    Command::new(env!("CARGO_BIN_EXE_sentinel-probes"))
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("sentinel-probes-{}-{name}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn sqlite_probe_reports_commit_and_dispatch_latencies() {
    let dir = scratch("sqlite");
    let out = probe()
        .args([
            "sqlite",
            "--jobs",
            "50",
            "--backlog",
            "500",
            "--synchronous",
            "normal",
        ])
        .arg("--path")
        .arg(dir.join("d.sqlite"))
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let r: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(r["probe"], "sqlite-dispatch/1");
    assert_eq!(r["journal_mode"], "wal");
    assert_eq!(r["enqueue_commit"]["count"], 50);
    assert_eq!(r["dispatch_commit"]["count"], 50);
    assert!(r["dispatch_commit"]["median_ns"].as_u64().unwrap() > 0);
    assert!(r["backlog_batch_insert_rows_per_s"].as_u64().unwrap() > 0);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn clone_copy_reproduces_tree_and_refuses_existing_destination() {
    let dir = scratch("clone");
    let src = dir.join("src");
    let generated = probe()
        .args([
            "generate",
            "--files",
            "40",
            "--bytes-per-file",
            "1000",
            "--fan-out",
            "8",
        ])
        .arg("--dest")
        .arg(&src)
        .output()
        .unwrap();
    assert!(
        generated.status.success(),
        "{}",
        String::from_utf8_lossy(&generated.stderr)
    );
    let dst = dir.join("dst");
    let out = probe()
        .args(["clone", "--mode", "copy", "--verify-read"])
        .arg("--source")
        .arg(&src)
        .arg("--dest")
        .arg(&dst)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let r: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(r["files"], 40);
    assert_eq!(r["bytes"], 40_000);
    assert_eq!(r["dirs"], 6);
    assert!(r["verify_read_ns"].as_u64().unwrap() > 0);
    assert_eq!(
        fs::read(src.join("d0003").join("f25.bin")).unwrap(),
        fs::read(dst.join("d0003").join("f25.bin")).unwrap()
    );
    let again = probe()
        .args(["clone", "--mode", "copy"])
        .arg("--source")
        .arg(&src)
        .arg("--dest")
        .arg(&dst)
        .output()
        .unwrap();
    assert!(!again.status.success());
    assert!(String::from_utf8_lossy(&again.stderr).contains("destination exists"));
    fs::remove_dir_all(dir).unwrap();
}
