//! Benchmark runner: runs a fixed workload N times and emits one JSON record.
//! Durations are monotonic; unmeasured fields are omitted, never zero.
mod contract;

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
    /// Fixed workload definition; `noop` is the reproducible baseline.
    /// Ignored with `--contract`, whose lane is the workload
    #[arg(long, value_enum, default_value_t = Workload::Noop)]
    workload: Workload,
    /// A frozen benchmark contract (`sentinel.bench-contract/1`, B01): the
    /// runner measures its `--lane` under `--condition`, and only when the
    /// host, image and sources match it
    #[arg(long, requires_all = ["lane", "condition"])]
    contract: Option<PathBuf>,
    /// The contract lane to measure
    #[arg(long, requires = "contract")]
    lane: Option<String>,
    /// The contract condition: cold, warm or small-edit
    #[arg(long, requires = "contract")]
    condition: Option<String>,
    /// The bench root the contract's `{root}` names (sources, caches)
    #[arg(long, requires = "contract")]
    root: Option<PathBuf>,
    /// Directories prepended to `PATH` for the direct and scoped runtimes
    /// (a toolchain copied out of the lane's image, so both run the same
    /// binaries)
    #[arg(long)]
    path_prepend: Vec<PathBuf>,
    /// Execution path under measurement
    #[arg(long, value_enum, default_value_t = Runtime::Direct)]
    runtime: Runtime,
    /// Image reference for the podman runtime; the record stores its digest
    #[arg(long)]
    image: Option<String>,
    /// CPU limit: podman `--cpus`, or the scoped runtime's `CPUQuota`;
    /// absent means unlimited (a contract lane defaults to its allocation)
    #[arg(long)]
    cpus: Option<String>,
    /// Memory limit: podman `--memory` (with `--memory-swap` equal, so no
    /// swap), or the scoped runtime's `MemoryMax` with `MemorySwapMax=0`
    #[arg(long)]
    memory: Option<String>,
    /// Measured samples after warm-up (default 20; a contract condition's own)
    #[arg(long)]
    samples: Option<u32>,
    /// Unmeasured runs before sampling (default 2; for a contract lane 0
    /// when cold, 1 otherwise)
    #[arg(long)]
    warmup: Option<u32>,
    /// Operator-declared state of image/runtime caches before the first
    /// warm-up run; a contract condition declares its own
    #[arg(long, value_enum, required_unless_present = "contract")]
    warm_state: Option<WarmState>,
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
    /// A contract lane (set by `--contract`)
    #[value(skip)]
    ContractLane,
}

#[derive(Clone, Copy, PartialEq, ValueEnum, Serialize)]
#[serde(rename_all = "lowercase")]
enum Runtime {
    Direct,
    /// The workload as a direct process in a systemd user scope holding the
    /// same CPU and memory caps a container would get: identical isolation
    /// without a container (B01)
    Scoped,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    contract: Option<contract::Stamp>,
    /// `go version` (or the lane's toolchain) as the measured runtime sees it.
    #[serde(skip_serializing_if = "Option::is_none")]
    toolchain: Option<String>,
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
pub(crate) struct Host {
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

/// What one invocation measures: the argv, its environment and the
/// unmeasured preparation before each run.
struct Plan {
    argv: Vec<String>,
    env: Vec<(String, String)>,
    dir: Option<PathBuf>,
    prepare: Option<(String, String)>,
    samples: u32,
    warmup: u32,
    warm_state: WarmState,
    workload: Workload,
    stamp: Option<contract::Stamp>,
    image: Option<Image>,
    toolchain: Option<String>,
    limits: Limits,
}

fn run(cli: Cli) -> Result<(), String> {
    // Provenance first: a record without its source revision cannot be
    // attributed, so none is written (and nothing is measured) without it.
    let source = source_revision()?;
    let plan = match &cli.contract {
        Some(path) => contract_plan(&cli, path)?,
        None => plain_plan(&cli)?,
    };
    if plan.samples == 0 {
        return Err("samples must be at least 1".into());
    }
    let started_at_unix_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);

    let mut nonce = started_at_unix_ms as u64 * 1000;
    let mut once = |index: u32| -> Result<Sample, String> {
        nonce += 1;
        if let Some((shell, prepare)) = &plan.prepare {
            prepare_run(
                shell,
                &prepare.replace("{sample_nonce}", &nonce.to_string()),
            )?;
        }
        measure(&plan, index)
    };
    for _ in 0..plan.warmup {
        check_exit(&once(0)?)?;
    }
    let mut samples = Vec::with_capacity(plan.samples as usize);
    for index in 0..plan.samples {
        let sample = once(index)?;
        check_exit(&sample)?;
        samples.push(sample);
    }
    let summary = summarize(&samples);
    let record = Record {
        schema: "sentinel-bench/1",
        bench_version: env!("CARGO_PKG_VERSION"),
        started_at_unix_ms,
        label: cli.label.clone(),
        workload: plan.workload,
        runtime: cli.runtime,
        warm_state: plan.warm_state,
        argv: plan.argv.clone(),
        limits: plan.limits,
        source,
        tools: Tools {
            rustc: Some(env!("SENTINEL_BENCH_RUSTC"))
                .filter(|v| !v.is_empty())
                .map(str::to_owned),
            podman: (cli.runtime == Runtime::Podman || cli.contract.is_some())
                .then(|| command_line(&["podman", "--version"]))
                .flatten(),
        },
        host: host_info(),
        image: plan.image,
        contract: plan.stamp,
        toolchain: plan.toolchain,
        warmup: plan.warmup,
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

/// A built-in workload (`noop`, `nonzero-exit`).
fn plain_plan(cli: &Cli) -> Result<Plan, String> {
    let inner: Vec<&str> = match (cli.workload, cfg!(windows)) {
        (Workload::Noop, false) => vec!["true"],
        (Workload::Noop, true) => vec!["cmd", "/c", "exit 0"],
        (Workload::NonzeroExit, false) => vec!["sh", "-c", "exit 3"],
        (Workload::NonzeroExit, true) => vec!["cmd", "/c", "exit 3"],
        (Workload::ContractLane, _) => return Err("a contract lane needs --contract".into()),
    };
    let inner: Vec<String> = inner.into_iter().map(String::from).collect();
    let limits = Limits {
        cpus: cli.cpus.clone(),
        memory: cli.memory.clone(),
    };
    let argv = wrap(cli.runtime, cli.image.as_deref(), &limits, &[], None, inner)?;
    Ok(Plan {
        argv,
        env: path_env(cli)?,
        dir: None,
        prepare: None,
        samples: cli.samples.unwrap_or(20),
        warmup: cli.warmup.unwrap_or(2),
        warm_state: cli.warm_state.unwrap_or(WarmState::Warm),
        workload: cli.workload,
        stamp: None,
        image: match cli.runtime {
            Runtime::Podman => cli.image.clone().map(inspect_image),
            _ => None,
        },
        toolchain: None,
        limits,
    })
}

/// A contract lane: checked against the contract before anything runs.
fn contract_plan(cli: &Cli, path: &Path) -> Result<Plan, String> {
    let loaded = contract::load(path)?;
    let c = &loaded.contract;
    let lane = c.lane(cli.lane.as_deref().unwrap_or_default())?;
    let condition_id = cli.condition.clone().unwrap_or_default();
    let condition = c.condition(&condition_id)?;
    let root = match &cli.root {
        Some(root) => root.clone(),
        None => std::env::current_dir().map_err(|e| e.to_string())?,
    };
    let root =
        fs::canonicalize(&root).map_err(|e| format!("bench root {}: {e}", root.display()))?;
    let root_text = root.display().to_string();
    let pinned = c
        .images
        .get(&lane.image)
        .ok_or_else(|| format!("lane image `{}` is not pinned", lane.image))?
        .clone();
    let image = (cli.runtime == Runtime::Podman).then(|| inspect_image(pinned.clone()));
    let podman = command_line(&["podman", "--version"]);
    let found = contract::drift(
        c,
        &host_info(),
        podman.as_deref(),
        image.as_ref().and_then(|i| i.digest.as_deref()),
        lane,
        &root,
    );
    if !found.is_empty() {
        return Err(format!(
            "the host or inputs differ from contract {} revision {}; nothing measured:\n  {}",
            c.id,
            c.revision,
            found.join("\n  ")
        ));
    }
    if cli.runtime == Runtime::Podman && image.as_ref().is_none_or(|i| i.digest.is_none()) {
        return Err(format!(
            "image {pinned} is not present; pull it first (pulls are measured apart)"
        ));
    }
    let pressure = contract::cpu_pressure();
    if pressure.is_some_and(|p| p >= contract::MAX_START_PRESSURE) {
        return Err(format!(
            "CPU pressure (some, avg60) is {:.2} %, at or over {} %: a contended start is not a baseline; nothing measured",
            pressure.unwrap_or_default(),
            contract::MAX_START_PRESSURE
        ));
    }
    let limits = Limits {
        cpus: Some(
            cli.cpus
                .clone()
                .unwrap_or_else(|| c.allocation.total.cpus.clone()),
        ),
        memory: Some(
            cli.memory
                .clone()
                .unwrap_or_else(|| c.allocation.total.memory.clone()),
        ),
    };
    let env: Vec<(String, String)> = c.env(lane, &root_text).into_iter().collect();
    let dir = root.join(
        &c.sources
            .first()
            .ok_or("a contract names at least one source")?
            .path,
    );
    let inner = vec!["sh".to_string(), "-c".into(), lane.run.clone()];
    let argv = wrap(
        cli.runtime,
        Some(&pinned),
        &limits,
        &env,
        Some((&root, &dir)),
        inner,
    )?;
    let mut all_env = env.clone();
    all_env.extend(path_env(cli)?);
    let is_cold = condition_id == "cold";
    let mut plan = Plan {
        argv,
        env: all_env,
        dir: Some(dir),
        prepare: Some(("sh".into(), c.expand(&condition.prepare, &root_text))),
        samples: cli.samples.unwrap_or(condition.samples),
        warmup: cli.warmup.unwrap_or(if is_cold { 0 } else { 1 }),
        warm_state: if is_cold {
            WarmState::Cold
        } else {
            WarmState::Warm
        },
        workload: Workload::ContractLane,
        stamp: Some(contract::Stamp {
            id: c.id.clone(),
            revision: c.revision,
            blake3: loaded.blake3.clone(),
            lane: lane.id.clone(),
            condition: condition_id.clone(),
            max_record_age_days: c.freshness.max_record_age_days,
            cpu_pressure_avg60: pressure,
            sources: c
                .sources
                .iter()
                .map(|s| (s.name.clone(), s.commit.clone()))
                .collect(),
            image: Some(pinned),
        }),
        image,
        toolchain: None,
        limits,
    };
    // The toolchain the measured runtime actually runs, asked through the
    // same wrapper (unmeasured).
    let probe = Plan {
        argv: wrap(
            cli.runtime,
            plan.stamp.as_ref().and_then(|s| s.image.as_deref()),
            &plan.limits,
            &env,
            Some((&root, plan.dir.as_deref().unwrap_or(&root))),
            vec!["go".into(), "version".into()],
        )?,
        ..Plan {
            argv: Vec::new(),
            env: plan.env.clone(),
            dir: plan.dir.clone(),
            prepare: None,
            samples: 0,
            warmup: 0,
            warm_state: plan.warm_state,
            workload: plan.workload,
            stamp: None,
            image: None,
            toolchain: None,
            limits: Limits {
                cpus: None,
                memory: None,
            },
        }
    };
    plan.toolchain = output_of(&probe);
    Ok(plan)
}

/// `PATH` with `--path-prepend` in front, for the direct and scoped runtimes.
fn path_env(cli: &Cli) -> Result<Vec<(String, String)>, String> {
    if cli.path_prepend.is_empty() || cli.runtime == Runtime::Podman {
        return Ok(Vec::new());
    }
    let mut parts: Vec<PathBuf> = cli.path_prepend.clone();
    if let Some(path) = std::env::var_os("PATH") {
        parts.extend(std::env::split_paths(&path));
    }
    let joined = std::env::join_paths(parts).map_err(|e| e.to_string())?;
    Ok(vec![("PATH".into(), joined.to_string_lossy().into_owned())])
}

/// The argv that runs `inner` under `runtime` with `limits`. For podman the
/// bench root is mounted at the same path and the caller's user is kept, so
/// files, paths and ownership match a direct run.
fn wrap(
    runtime: Runtime,
    image: Option<&str>,
    limits: &Limits,
    env: &[(String, String)],
    mount: Option<(&Path, &Path)>,
    inner: Vec<String>,
) -> Result<Vec<String>, String> {
    Ok(match runtime {
        Runtime::Direct => inner,
        Runtime::Scoped => {
            let mut argv: Vec<String> =
                ["systemd-run", "--user", "--scope", "--quiet", "--collect"]
                    .map(String::from)
                    .to_vec();
            if let Some(cpus) = &limits.cpus {
                argv.push("-p".into());
                argv.push(format!("CPUQuota={}", contract::cpu_quota(cpus)?));
            }
            if let Some(memory) = &limits.memory {
                argv.push("-p".into());
                argv.push(format!("MemoryMax={}", contract::systemd_memory(memory)));
                argv.push("-p".into());
                argv.push("MemorySwapMax=0".into());
            }
            argv.push("--".into());
            argv.extend(inner);
            argv
        }
        Runtime::Podman => {
            let image = image.ok_or("--image is required for the podman runtime")?;
            let mut argv = vec!["podman".to_string(), "run".into(), "--rm".into()];
            if let Some(cpus) = &limits.cpus {
                argv.push("--cpus".into());
                argv.push(cpus.clone());
            }
            if let Some(memory) = &limits.memory {
                argv.push("--memory".into());
                argv.push(memory.clone());
                argv.push("--memory-swap".into());
                argv.push(memory.clone());
            }
            if let Some((root, dir)) = mount {
                let root = root.display().to_string();
                argv.extend([
                    "--userns=keep-id".into(),
                    "--network=host".into(),
                    "-v".into(),
                    format!("{root}:{root}"),
                    "-w".into(),
                    dir.display().to_string(),
                ]);
                for (k, v) in env {
                    argv.push("-e".into());
                    argv.push(format!("{k}={v}"));
                }
            }
            argv.push(image.to_string());
            argv.extend(inner);
            argv
        }
    })
}

/// Run one unmeasured preparation step; its failure stops the record.
fn prepare_run(shell: &str, script: &str) -> Result<(), String> {
    let status = Command::new(shell)
        .args(["-c", script])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .status()
        .map_err(|e| format!("cannot run the condition's preparation: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "the condition's preparation failed ({status}); no record written"
        ))
    }
}

fn output_of(plan: &Plan) -> Option<String> {
    let mut command = Command::new(&plan.argv[0]);
    command.args(&plan.argv[1..]).envs(plan.env.iter().cloned());
    if let Some(dir) = &plan.dir {
        command.current_dir(dir);
    }
    let out = command.stdin(Stdio::null()).output().ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
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

fn measure(plan: &Plan, index: u32) -> Result<Sample, String> {
    let argv = &plan.argv;
    let mut command = Command::new(&argv[0]);
    command.args(&argv[1..]).envs(plan.env.iter().cloned());
    if let Some(dir) = &plan.dir {
        command.current_dir(dir);
    }
    let start = Instant::now();
    let mut child = command
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

/// The commit and dirty state of the checkout this runner was built from,
/// asked of `git` there rather than in the working directory, so a runner
/// started elsewhere (as the F05 baseline was) still names its source.
fn source_revision() -> Result<Source, String> {
    let dir = env!("CARGO_MANIFEST_DIR");
    let git_commit = command_line(&["git", "-C", dir, "rev-parse", "HEAD"]).ok_or_else(|| {
        format!(
            "cannot read the source commit of {dir} with git; no record written \
             (run the runner built from a checkout; a checkout owned by another user \
             needs `git config --global --add safe.directory {dir}`)"
        )
    })?;
    let git_dirty =
        command_line(&["git", "-C", dir, "status", "--porcelain"]).map(|s| !s.is_empty());
    Ok(Source {
        git_commit: Some(git_commit),
        git_dirty,
    })
}

pub(crate) fn command_line(argv: &[&str]) -> Option<String> {
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
