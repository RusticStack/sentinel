//! Benchmark runner: runs a fixed workload N times and emits one JSON record.
//! Durations are monotonic; unmeasured fields are omitted, never zero.
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    process::{Child, Command, ExitCode, Stdio},
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use clap::{Parser, ValueEnum};
use serde::Serialize;

#[derive(Parser)]
#[command(version, about)]
struct Cli {
    /// Fixed workload definition; `noop` is the reproducible baseline
    #[arg(long, value_enum, default_value_t = Workload::Noop)]
    workload: Workload,
    /// Execution path under measurement
    #[arg(long, value_enum, default_value_t = Runtime::Direct)]
    runtime: Runtime,
    /// Image reference for the podman runtime; the record stores its digest
    #[arg(long)]
    image: Option<String>,
    /// Podman `--cpus` limit; absent means unlimited
    #[arg(long)]
    cpus: Option<String>,
    /// Podman `--memory` limit; absent means unlimited
    #[arg(long)]
    memory: Option<String>,
    /// Measured samples after warm-up
    #[arg(long, default_value_t = 20)]
    samples: u32,
    /// Unmeasured runs before sampling
    #[arg(long, default_value_t = 2)]
    warmup: u32,
    /// Operator-declared state of image/runtime caches before the first warm-up run
    #[arg(long, value_enum)]
    warm_state: WarmState,
    /// Free-form label identifying the host/cohort
    #[arg(long)]
    label: Option<String>,
    /// Append the JSON record as one line to this file instead of stdout
    #[arg(long)]
    output: Option<PathBuf>,
}

#[derive(Clone, Copy, ValueEnum, Serialize)]
#[serde(rename_all = "kebab-case")]
enum Workload {
    Noop,
    /// Exits with status 3; verifies failure handling of the runner
    NonzeroExit,
}

#[derive(Clone, Copy, PartialEq, ValueEnum, Serialize)]
#[serde(rename_all = "lowercase")]
enum Runtime {
    Direct,
    Podman,
}

#[derive(Clone, Copy, ValueEnum, Serialize)]
#[serde(rename_all = "lowercase")]
enum WarmState {
    Cold,
    Warm,
}

#[derive(Serialize)]
struct Record {
    schema: &'static str,
    bench_version: &'static str,
    started_at_unix_ms: u128,
    label: Option<String>,
    workload: Workload,
    runtime: Runtime,
    warm_state: WarmState,
    argv: Vec<String>,
    limits: Limits,
    source: Source,
    tools: Tools,
    host: Host,
    image: Option<Image>,
    warmup: u32,
    samples: Vec<Sample>,
    summary: Summary,
}

#[derive(Serialize)]
struct Limits {
    cpus: Option<String>,
    memory: Option<String>,
}

#[derive(Serialize)]
struct Source {
    git_commit: Option<String>,
    git_dirty: Option<bool>,
}

#[derive(Serialize)]
struct Tools {
    rustc: Option<String>,
    podman: Option<String>,
}

#[derive(Serialize)]
struct Host {
    hostname: Option<String>,
    os: Option<String>,
    kernel: Option<String>,
    cpu_model: Option<String>,
    cpus_online: Option<usize>,
    mem_total_kib: Option<u64>,
    workdir: String,
    workdir_fs: Option<String>,
    cgroup_controllers: Option<String>,
    user: Option<String>,
}

#[derive(Serialize)]
struct Image {
    reference: String,
    digest: Option<String>,
    id: Option<String>,
}

#[derive(Serialize)]
struct Sample {
    index: u32,
    elapsed_ns: u64,
    exit_code: Option<i32>,
    #[serde(flatten)]
    usage: Usage,
}

/// Resource usage of the direct child only (the podman client for that runtime).
#[derive(Default, Serialize)]
struct Usage {
    #[serde(skip_serializing_if = "Option::is_none")]
    user_cpu_ns: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    system_cpu_ns: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_rss_kib: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    block_in: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    block_out: Option<u64>,
}

#[derive(Serialize)]
struct Summary {
    count: usize,
    min_ns: u64,
    median_ns: u64,
    p95_ns: u64,
    max_ns: u64,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("error: {message}");
            ExitCode::from(1)
        }
    }
}

fn run(cli: Cli) -> Result<(), String> {
    if cli.samples == 0 {
        return Err("samples must be at least 1".into());
    }
    let argv = workload_argv(&cli)?;
    let image = match cli.runtime {
        Runtime::Podman => cli.image.clone().map(inspect_image),
        Runtime::Direct => None,
    };
    let started_at_unix_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);

    for _ in 0..cli.warmup {
        check_exit(&measure(&argv, 0)?)?;
    }
    let mut samples = Vec::with_capacity(cli.samples as usize);
    for index in 0..cli.samples {
        let sample = measure(&argv, index)?;
        check_exit(&sample)?;
        samples.push(sample);
    }
    let summary = summarize(&samples);
    let record = Record {
        schema: "sentinel-bench/1",
        bench_version: env!("CARGO_PKG_VERSION"),
        started_at_unix_ms,
        label: cli.label,
        workload: cli.workload,
        runtime: cli.runtime,
        warm_state: cli.warm_state,
        argv,
        limits: Limits {
            cpus: cli.cpus,
            memory: cli.memory,
        },
        source: Source {
            git_commit: command_line(&["git", "rev-parse", "HEAD"]),
            git_dirty: command_line(&["git", "status", "--porcelain"]).map(|s| !s.is_empty()),
        },
        tools: Tools {
            rustc: command_line(&["rustc", "--version"]),
            podman: (cli.runtime == Runtime::Podman)
                .then(|| command_line(&["podman", "--version"]))
                .flatten(),
        },
        host: host_info(),
        image,
        warmup: cli.warmup,
        samples,
        summary,
    };
    let line = serde_json::to_string(&record).map_err(|e| e.to_string())?;
    match &cli.output {
        Some(path) => {
            let mut file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .map_err(|e| format!("cannot open {}: {e}", path.display()))?;
            writeln!(file, "{line}").map_err(|e| e.to_string())?;
        }
        None => println!("{line}"),
    }
    let s = &record.summary;
    eprintln!(
        "{} samples: min {} us, median {} us, p95 {} us, max {} us",
        s.count,
        s.min_ns / 1000,
        s.median_ns / 1000,
        s.p95_ns / 1000,
        s.max_ns / 1000
    );
    Ok(())
}

fn check_exit(sample: &Sample) -> Result<(), String> {
    match sample.exit_code {
        Some(0) => Ok(()),
        Some(code) => Err(format!(
            "workload exited with status {code}; no record written"
        )),
        None => Err("workload terminated by signal; no record written".into()),
    }
}

fn workload_argv(cli: &Cli) -> Result<Vec<String>, String> {
    let inner: Vec<&str> = match (cli.workload, cfg!(windows)) {
        (Workload::Noop, false) => vec!["true"],
        (Workload::Noop, true) => vec!["cmd", "/c", "exit 0"],
        (Workload::NonzeroExit, false) => vec!["sh", "-c", "exit 3"],
        (Workload::NonzeroExit, true) => vec!["cmd", "/c", "exit 3"],
    };
    match cli.runtime {
        Runtime::Direct => Ok(inner.into_iter().map(String::from).collect()),
        Runtime::Podman => {
            let image = cli
                .image
                .as_deref()
                .ok_or("--image is required for the podman runtime")?;
            let mut argv = vec!["podman".to_string(), "run".into(), "--rm".into()];
            if let Some(cpus) = &cli.cpus {
                argv.push("--cpus".into());
                argv.push(cpus.clone());
            }
            if let Some(memory) = &cli.memory {
                argv.push("--memory".into());
                argv.push(memory.clone());
            }
            argv.push(image.to_string());
            argv.extend(inner.into_iter().map(String::from));
            Ok(argv)
        }
    }
}

fn measure(argv: &[String], index: u32) -> Result<Sample, String> {
    let start = Instant::now();
    let mut child = Command::new(&argv[0])
        .args(&argv[1..])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| format!("cannot spawn {}: {e}", argv[0]))?;
    let (exit_code, usage) = wait_with_usage(&mut child)?;
    let elapsed_ns = start.elapsed().as_nanos().min(u64::MAX as u128) as u64;
    Ok(Sample {
        index,
        elapsed_ns,
        exit_code,
        usage,
    })
}

#[cfg(unix)]
fn wait_with_usage(child: &mut Child) -> Result<(Option<i32>, Usage), String> {
    let mut status: libc::c_int = 0;
    // SAFETY: rusage is plain data; wait4 writes into valid locals for our own child pid.
    let mut rusage: libc::rusage = unsafe { std::mem::zeroed() };
    let pid = child.id() as libc::pid_t;
    // SAFETY: pointers are to live stack locals for the duration of the call.
    let rc = unsafe { libc::wait4(pid, &mut status, 0, &mut rusage) };
    if rc != pid {
        return Err(format!("wait4 failed: {}", std::io::Error::last_os_error()));
    }
    let exit_code = libc::WIFEXITED(status).then(|| libc::WEXITSTATUS(status));
    let tv_ns = |tv: libc::timeval| (tv.tv_sec as u64) * 1_000_000_000 + (tv.tv_usec as u64) * 1000;
    Ok((
        exit_code,
        Usage {
            user_cpu_ns: Some(tv_ns(rusage.ru_utime)),
            system_cpu_ns: Some(tv_ns(rusage.ru_stime)),
            max_rss_kib: Some(rusage.ru_maxrss as u64),
            block_in: Some(rusage.ru_inblock as u64),
            block_out: Some(rusage.ru_oublock as u64),
        },
    ))
}

#[cfg(not(unix))]
fn wait_with_usage(child: &mut Child) -> Result<(Option<i32>, Usage), String> {
    let status = child.wait().map_err(|e| e.to_string())?;
    Ok((status.code(), Usage::default()))
}

fn summarize(samples: &[Sample]) -> Summary {
    let mut sorted: Vec<u64> = samples.iter().map(|s| s.elapsed_ns).collect();
    sorted.sort_unstable();
    let nearest_rank = |p: f64| sorted[((p * sorted.len() as f64).ceil() as usize).max(1) - 1];
    Summary {
        count: sorted.len(),
        min_ns: sorted[0],
        median_ns: nearest_rank(0.5),
        p95_ns: nearest_rank(0.95),
        max_ns: sorted[sorted.len() - 1],
    }
}

fn command_line(argv: &[&str]) -> Option<String> {
    let out = Command::new(argv[0]).args(&argv[1..]).output().ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn inspect_image(reference: String) -> Image {
    let inspected = command_line(&[
        "podman",
        "image",
        "inspect",
        "--format",
        "{{.Digest}} {{.Id}}",
        &reference,
    ]);
    let mut parts = inspected.as_deref().unwrap_or("").split_whitespace();
    Image {
        digest: parts.next().map(String::from),
        id: parts.next().map(String::from),
        reference,
    }
}

fn read_trim(path: &str) -> Option<String> {
    fs::read_to_string(path).ok().map(|s| s.trim().to_string())
}

fn proc_field(path: &str, key: &str) -> Option<String> {
    fs::read_to_string(path).ok()?.lines().find_map(|line| {
        let (k, v) = line.split_once(':')?;
        (k.trim() == key).then(|| v.trim().to_string())
    })
}

fn host_info() -> Host {
    let workdir = std::env::current_dir()
        .map(|p| p.display().to_string())
        .unwrap_or_default();
    Host {
        hostname: read_trim("/etc/hostname").or_else(|| std::env::var("COMPUTERNAME").ok()),
        os: fs::read_to_string("/etc/os-release").ok().and_then(|s| {
            s.lines()
                .find_map(|l| l.strip_prefix("PRETTY_NAME="))
                .map(|v| v.trim_matches('"').to_string())
        }),
        kernel: read_trim("/proc/sys/kernel/osrelease"),
        cpu_model: proc_field("/proc/cpuinfo", "model name"),
        cpus_online: std::thread::available_parallelism().ok().map(|n| n.get()),
        mem_total_kib: proc_field("/proc/meminfo", "MemTotal")
            .and_then(|v| v.split_whitespace().next()?.parse().ok()),
        workdir_fs: mount_fs(Path::new(&workdir)),
        workdir,
        cgroup_controllers: read_trim("/sys/fs/cgroup/cgroup.controllers"),
        user: std::env::var("USER")
            .or_else(|_| std::env::var("USERNAME"))
            .ok(),
    }
}

/// Filesystem type of the longest mount-point prefix of `path` (Linux /proc/self/mounts).
fn mount_fs(path: &Path) -> Option<String> {
    let mounts = fs::read_to_string("/proc/self/mounts").ok()?;
    let path = path.to_str()?;
    mounts
        .lines()
        .filter_map(|l| {
            let mut f = l.split_whitespace();
            let (_, point, fstype) = (f.next()?, f.next()?, f.next()?);
            let matches = point == "/" || path == point || path.starts_with(&format!("{point}/"));
            matches.then(|| (point.len(), format!("{fstype} ({point})")))
        })
        .max_by_key(|(len, _)| *len)
        .map(|(_, v)| v)
}
