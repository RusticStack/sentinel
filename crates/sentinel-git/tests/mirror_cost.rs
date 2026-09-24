//! Measurement, not a check (P07-20): what one mirrored checkout costs on
//! the worker's filesystem — wall time of the materialization phase and
//! the bytes it leaves in the job's `.git` — for a repository with a long
//! history. Ignored by default; run it in release on the filesystem under
//! test:
//!
//! ```sh
//! SENTINEL_MIRROR_COST_DIR=/root/bench cargo test --release -p sentinel-git \
//!     --test mirror_cost -- --ignored --nocapture --test-threads=1
//! ```
//!
//! `SENTINEL_MIRROR_COST_COMMITS`, `_FILES`, `_TOUCH` and `_BYTES` size the
//! synthetic history (defaults 3,000 commits over 2,000 files, 20 files of
//! 4 KiB rewritten per commit — about 240 MiB of history behind an 8 MiB
//! tree). Content is pseudo-random, so neither deltas nor zlib shrink it.
#![cfg(unix)]

use std::{
    fs,
    io::Write,
    path::Path,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

use sentinel_core::RepoId;
use sentinel_git::mirror::Mirrors;
use sentinel_pipeline::PinnedSource;

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn git(dir: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .args(args)
        .current_dir(dir)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .output()
        .unwrap();
    assert!(output.status.success(), "git {args:?}");
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}

/// A bare origin whose `main` carries `commits` commits, built with
/// `git fast-import` in one pass.
fn synthetic_origin(root: &Path, commits: u64, files: u64, touch: u64, bytes: u64) -> String {
    let origin = root.join("origin.git");
    fs::create_dir(&origin).unwrap();
    git(&origin, &["init", "-q", "--bare", "--initial-branch=main"]);
    let mut child = Command::new("git")
        .args(["fast-import", "--quiet"])
        .current_dir(&origin)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    let mut input = std::io::BufWriter::new(child.stdin.take().unwrap());
    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    let mut blob = vec![0u8; bytes as usize];
    for commit in 0..commits {
        writeln!(input, "commit refs/heads/main").unwrap();
        writeln!(
            input,
            "committer t <t@example.com> {} +0000",
            1_700_000_000 + commit
        )
        .unwrap();
        writeln!(input, "data 1\nc").unwrap();
        // The first commit writes every file; later ones rewrite `touch`.
        let (from, count) = if commit == 0 {
            (0, files)
        } else {
            (next() % files, touch)
        };
        for i in 0..count {
            for chunk in blob.chunks_mut(8) {
                let word = next().to_le_bytes();
                chunk.copy_from_slice(&word[..chunk.len()]);
            }
            writeln!(input, "M 100644 inline f/{:05}", (from + i) % files).unwrap();
            writeln!(input, "data {}", blob.len()).unwrap();
            input.write_all(&blob).unwrap();
            writeln!(input).unwrap();
        }
    }
    drop(input);
    assert!(child.wait().unwrap().success());
    git(&origin, &["rev-parse", "refs/heads/main"])
}

fn tree_bytes(dir: &Path) -> u64 {
    let mut total = 0;
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for entry in fs::read_dir(&d).unwrap().flatten() {
            let kind = entry.file_type().unwrap();
            if kind.is_dir() {
                stack.push(entry.path());
            } else if kind.is_file() {
                total += entry.metadata().unwrap().len();
            }
        }
    }
    total
}

#[test]
#[ignore = "measurement; run explicitly in release"]
fn mirrored_checkout_cost() {
    let base = std::env::var_os("SENTINEL_MIRROR_COST_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    fs::create_dir_all(&base).unwrap();
    let temp = tempfile::tempdir_in(&base).unwrap();
    let commits = env_u64("SENTINEL_MIRROR_COST_COMMITS", 3_000);
    let files = env_u64("SENTINEL_MIRROR_COST_FILES", 2_000);
    let touch = env_u64("SENTINEL_MIRROR_COST_TOUCH", 20);
    let bytes = env_u64("SENTINEL_MIRROR_COST_BYTES", 4096);
    let runs = env_u64("SENTINEL_MIRROR_COST_RUNS", 5);
    let started = Instant::now();
    let head = synthetic_origin(temp.path(), commits, files, touch, bytes);
    eprintln!(
        "origin: {commits} commits, {files} files, {touch} x {bytes} B per commit, built in {:?}",
        started.elapsed()
    );
    let origin = temp.path().join("origin.git");
    let mirrors = Mirrors::open(&temp.path().join("mirrors")).unwrap();
    let repo = RepoId::new();
    let source = PinnedSource::new(origin.to_str().unwrap(), &head, None).unwrap();
    // The first checkout fills the mirror; only warm ones are measured.
    let ws = temp.path().join("ws-fill");
    fs::create_dir(&ws).unwrap();
    let fill = mirrors
        .checkout(
            &ws,
            &repo,
            &source,
            None,
            "att_fill",
            Duration::from_secs(600),
        )
        .unwrap();
    eprintln!(
        "reflink={} mirror objects {} B; fill fetch {:.1} ms",
        mirrors.reflink(),
        tree_bytes(&mirrors.path(&repo).join("objects")),
        fill.fetch_ns as f64 / 1e6
    );
    fs::remove_dir_all(&ws).unwrap();
    let mut materialize = Vec::new();
    let mut durable = Vec::new();
    for run in 0..runs {
        let ws = temp.path().join(format!("ws-{run}"));
        fs::create_dir(&ws).unwrap();
        // Cold page cache is not reachable without root; every run reads a
        // mirror the previous one already touched, like a busy worker.
        let out = mirrors
            .checkout(
                &ws,
                &repo,
                &source,
                None,
                &format!("att_{run}"),
                Duration::from_secs(600),
            )
            .unwrap();
        assert_eq!(out.sha, head);
        // What the materialization left dirty still has to reach the disk:
        // `syncfs` right after it charges that write-back to this run.
        let sync_started = Instant::now();
        assert!(
            Command::new("sync")
                .arg("-f")
                .arg(&ws)
                .status()
                .unwrap()
                .success()
        );
        let sync_ns = sync_started.elapsed().as_nanos() as u64;
        let git_bytes = tree_bytes(&ws.join(".git"));
        eprintln!(
            "run {run}: fetch {:.1} ms, materialize {:.1} ms, then syncfs {:.1} ms, job .git {} B",
            out.fetch_ns as f64 / 1e6,
            out.materialize_ns as f64 / 1e6,
            sync_ns as f64 / 1e6,
            git_bytes
        );
        materialize.push(out.materialize_ns);
        durable.push(out.materialize_ns + sync_ns);
        fs::remove_dir_all(&ws).unwrap();
    }
    materialize.sort_unstable();
    durable.sort_unstable();
    eprintln!(
        "materialize median {:.1} ms, materialize + syncfs median {:.1} ms over {runs} runs",
        materialize[materialize.len() / 2] as f64 / 1e6,
        durable[durable.len() / 2] as f64 / 1e6
    );
    if std::env::var_os("SENTINEL_MIRROR_COST_KEEP").is_some() {
        eprintln!("kept {}", temp.keep().display());
    }
}
