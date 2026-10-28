//! Cost of acknowledging log frames per burst instead of per frame.
//!
//! The controller writes each frame with `LogStore::append_deferred` and calls `LogStore::sync` (one
//! `fdatasync` of the segment) before it answers one `LogAck` for the burst. This bench stores the same
//! frames at several burst sizes, through the real `LogStore`, on the file system under `--dir`, and
//! prints one `sentinel-bench/log-ack/1` JSON line (`docs/benchmarking.md#log-ack-batching`).
//! `bench/log-ack.sh` adds the `build` and `host` stamp; run it through that script for a committed record.
//!
//!     cargo run --release -p sentinel-store --example log-ack-bench -- --dir /srv/bench --rounds 5
//!
//! Each round stores `--frames` frames of `--frame-bytes` bytes once per burst size, into a fresh store.
//! The order of the burst sizes reverses every round (ABBA), so drift lands on every size alike. A burst of
//! 1 is the cost of an acknowledgement per frame. `--dir` must sit on the file system under test; the
//! bench removes everything it creates there.

use std::{
    fs,
    path::PathBuf,
    process::ExitCode,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use sentinel_core::{AttemptId, JobId, RunId};
use sentinel_protocol::logs::{Frame, Stream};
use sentinel_store::logs::LogStore;

const DEFAULT_BURSTS: [usize; 4] = [1, 8, 64, 256];

struct Args {
    dir: PathBuf,
    frames: usize,
    frame_bytes: usize,
    rounds: usize,
    bursts: Vec<usize>,
}

fn parse() -> Result<Args, String> {
    let mut args = Args {
        dir: PathBuf::new(),
        frames: 4096,
        frame_bytes: 256,
        rounds: 5,
        bursts: DEFAULT_BURSTS.to_vec(),
    };
    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        let mut value = |name: &str| it.next().ok_or(format!("{name} needs a value"));
        match flag.as_str() {
            "--dir" => args.dir = PathBuf::from(value("--dir")?),
            "--frames" => args.frames = number(&value("--frames")?)?,
            "--frame-bytes" => args.frame_bytes = number(&value("--frame-bytes")?)?,
            "--rounds" => args.rounds = number(&value("--rounds")?)?,
            "--bursts" => {
                args.bursts = value("--bursts")?
                    .split(',')
                    .map(number)
                    .collect::<Result<_, _>>()?;
            }
            other => return Err(format!("unknown argument {other}")),
        }
    }
    if args.dir.as_os_str().is_empty() {
        return Err("--dir is required: it must sit on the file system under test".into());
    }
    if args.frames == 0 || args.rounds == 0 || args.frame_bytes == 0 || args.bursts.is_empty() {
        return Err("--frames, --frame-bytes, --rounds and --bursts must be positive".into());
    }
    if args.bursts.contains(&0) {
        return Err("a burst of 0 frames is not a burst".into());
    }
    Ok(args)
}

fn number<T: std::str::FromStr>(text: &str) -> Result<T, String> {
    text.trim()
        .parse()
        .map_err(|_| format!("{text:?} is not a number"))
}

struct Sample {
    elapsed_ns: u64,
    syncs: usize,
    sync_ns: Vec<u64>,
}

fn store_all(args: &Args, burst: usize, root: &std::path::Path) -> Result<Sample, String> {
    let logs = LogStore::open(root.join("logs")).map_err(|e| format!("open: {e:?}"))?;
    let (run, job, attempt) = (RunId::new(), JobId::new(), AttemptId::new());
    let payload = vec![b'x'; args.frame_bytes];
    let mut sync_ns = Vec::with_capacity(args.frames / burst + 1);
    let started = Instant::now();
    for seq in 1..=args.frames {
        let frame = Frame {
            seq: seq as u64,
            step: 0,
            stream: Stream::Stdout,
            bytes: payload.clone(),
        };
        logs.append_deferred(run, job, attempt, &frame)
            .map_err(|e| format!("append: {e:?}"))?;
        if seq % burst == 0 || seq == args.frames {
            let t = Instant::now();
            logs.sync(attempt).map_err(|e| format!("sync: {e:?}"))?;
            sync_ns.push(t.elapsed().as_nanos() as u64);
        }
    }
    let elapsed_ns = started.elapsed().as_nanos() as u64;
    Ok(Sample {
        elapsed_ns,
        syncs: sync_ns.len(),
        sync_ns,
    })
}

fn median(sorted: &[u64]) -> u64 {
    sorted[sorted.len() / 2]
}

fn percentile(sorted: &[u64], p: f64) -> u64 {
    // Nearest rank.
    let rank = ((p * sorted.len() as f64).ceil() as usize).clamp(1, sorted.len());
    sorted[rank - 1]
}

fn run() -> Result<(), String> {
    let args = parse()?;
    fs::create_dir_all(&args.dir).map_err(|e| format!("--dir: {e}"))?;
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let scratch = args
        .dir
        .join(format!("log-ack-bench-{}-{stamp}", std::process::id()));
    let mut by_burst: Vec<Vec<Sample>> = args.bursts.iter().map(|_| Vec::new()).collect();
    let mut order_log = Vec::new();
    let outcome = (|| -> Result<(), String> {
        for round in 0..args.rounds {
            let mut order: Vec<usize> = (0..args.bursts.len()).collect();
            if round % 2 == 1 {
                order.reverse();
            }
            order_log.push(order.iter().map(|&i| args.bursts[i]).collect::<Vec<_>>());
            for i in order {
                let root = scratch.join(format!("r{round}-b{}", args.bursts[i]));
                fs::create_dir_all(&root).map_err(|e| format!("scratch: {e}"))?;
                let sample = store_all(&args, args.bursts[i], &root)?;
                fs::remove_dir_all(&root).map_err(|e| format!("cleanup: {e}"))?;
                by_burst[i].push(sample);
            }
        }
        Ok(())
    })();
    let _ = fs::remove_dir_all(&scratch);
    outcome?;

    let results: Vec<serde_json::Value> = args
        .bursts
        .iter()
        .zip(&by_burst)
        .map(|(&burst, samples)| {
            let mut elapsed: Vec<u64> = samples.iter().map(|s| s.elapsed_ns).collect();
            elapsed.sort_unstable();
            let mut syncs: Vec<u64> = samples
                .iter()
                .flat_map(|s| s.sync_ns.iter().copied())
                .collect();
            syncs.sort_unstable();
            let med = median(&elapsed);
            serde_json::json!({
                "burst_frames": burst,
                "syncs_per_run": samples.first().map_or(0, |s| s.syncs),
                "elapsed_ns": samples.iter().map(|s| s.elapsed_ns).collect::<Vec<_>>(),
                "median_elapsed_ns": med,
                "min_elapsed_ns": elapsed[0],
                "max_elapsed_ns": elapsed[elapsed.len() - 1],
                "median_ns_per_frame": med / args.frames as u64,
                "frames_per_s_median": (args.frames as f64 / (med as f64 / 1e9)).round(),
                "sync_ns": {
                    "count": syncs.len(),
                    "median": median(&syncs),
                    "p95": percentile(&syncs, 0.95),
                    "p95_is_max": syncs.len() < 20,
                    "max": syncs[syncs.len() - 1],
                },
            })
        })
        .collect();
    let record = serde_json::json!({
        "schema": "sentinel-bench/log-ack/1",
        "workload": "log-ack",
        "started_at_unix_ms": (stamp / 1_000_000) as u64,
        "frames": args.frames,
        "frame_bytes": args.frame_bytes,
        "rounds": args.rounds,
        "order": order_log,
        "results": results,
    });
    println!("{record}");
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("log-ack-bench: {e}");
            ExitCode::FAILURE
        }
    }
}
