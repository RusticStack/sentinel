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

#[derive(Parser, Clone)]
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
    /// Also measure these runtimes, alternating with `--runtime` sample by
    /// sample in ABBA order (the order reverses every sample), so drift in
    /// host load or caches lands on every runtime alike instead of on
    /// whichever ran last. One record per runtime, each naming the group
    #[arg(long, value_enum)]
    interleave: Vec<Runtime>,
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
    /// warm-up run; a contract condition declares its own. The record's
    /// `warm_state_basis` says how much of it the runner could check
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
    /// How the declared state was established: `contract-prepare` (the
    /// contract's own per-run preparation resets it), `warmup-run` (an
    /// identical unmeasured run completed before the first sample) or
    /// `unverified` (operator-declared; nothing the runner can observe)
    warm_state_basis: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    interleave: Option<Interleave>,
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
    conditions: Conditions,
    samples: Vec<Sample>,
    summary: Summary,
}

/// Runtimes measured alternately in one group; each has its own record.
#[derive(Serialize)]
struct Interleave {
    runtimes: Vec<Runtime>,
    order: &'static str,
}

/// Host state around the measured window, so a sample set taken on a
/// contended, stealing or throttled host says so. Every field is read from
/// the kernel; an absent field was not readable there (a VM often has no
/// cpufreq), never zero.
#[derive(Clone, Default, Serialize)]
struct Conditions {
    /// CPU pressure (`some`, percent) before the first warm-up run
    #[serde(skip_serializing_if = "Option::is_none")]
    cpu_pressure_avg10_start: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cpu_pressure_avg60_start: Option<f64>,
    /// CPU pressure after the last sample; avg10 covers the sampling window
    /// of a short run, avg60 lags it
    #[serde(skip_serializing_if = "Option::is_none")]
    cpu_pressure_avg10_end: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cpu_pressure_avg60_end: Option<f64>,
    /// Time the hypervisor took from this guest over the window, summed over
    /// CPUs (`/proc/stat` steal), in nanoseconds
    #[serde(skip_serializing_if = "Option::is_none")]
    cpu_steal_ns: Option<u64>,
    /// `scaling_governor` of cpu0
    #[serde(skip_serializing_if = "Option::is_none")]
    cpu_governor: Option<String>,
}

/// Kernel counters read at the window's start and again at its end.
struct Probe {
    pressure_avg10: Option<f64>,
    pressure_avg60: Option<f64>,
    steal_ns: Option<u64>,
}

impl Probe {
    fn read() -> Self {
        Probe {
            pressure_avg10: contract::cpu_pressure_field("avg10="),
            pressure_avg60: contract::cpu_pressure_field("avg60="),
            steal_ns: cpu_steal_ns(),
        }
    }
}

fn conditions(start: &Probe, end: &Probe) -> Conditions {
    Conditions {
        cpu_pressure_avg10_start: start.pressure_avg10,
        cpu_pressure_avg60_start: start.pressure_avg60,
        cpu_pressure_avg10_end: end.pressure_avg10,
        cpu_pressure_avg60_end: end.pressure_avg60,
        cpu_steal_ns: start
            .steal_ns
            .zip(end.steal_ns)
            .map(|(a, b)| b.saturating_sub(a)),
        cpu_governor: read_trim("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor"),
    }
}

/// Cumulative steal time of all CPUs in nanoseconds: the eighth `cpu` field
/// of `/proc/stat` is in clock ticks.
#[cfg(unix)]
fn cpu_steal_ns() -> Option<u64> {
    let text = fs::read_to_string("/proc/stat").ok()?;
    let line = text.lines().find(|l| l.starts_with("cpu "))?;
    let ticks: u64 = line.split_whitespace().nth(8)?.parse().ok()?;
    // SAFETY: sysconf takes a constant name and touches no memory of ours.
    let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    (hz > 0).then(|| ticks.saturating_mul(1_000_000_000 / hz as u64))
}

#[cfg(not(unix))]
fn cpu_steal_ns() -> Option<u64> {
    None
}

#[derive(Serialize)]
struct Limits {
    cpus: Option<String>,
    memory: Option<String>,
}

#[derive(Clone, Serialize)]
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
    /// Position in the whole measured sequence of an interleaved group
    #[serde(skip_serializing_if = "Option::is_none")]
    seq: Option<u32>,
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
    mean_ns: u64,
    /// Sample standard deviation (n - 1); absent for a single sample
    #[serde(skip_serializing_if = "Option::is_none")]
    stddev_ns: Option<u64>,
    /// Median absolute deviation from the median: a spread that one slow
    /// outlier cannot move
    mad_ns: u64,
    /// The nearest-rank p95 is the largest sample (fewer than 20 samples),
    /// so it describes one run, not a tail
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    p95_is_max: bool,
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
    runtime: Runtime,
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
    let mut runtimes = vec![cli.runtime];
    for runtime in &cli.interleave {
        if !runtimes.contains(runtime) {
            runtimes.push(*runtime);
        }
    }
    let mut plans = Vec::with_capacity(runtimes.len());
    for runtime in &runtimes {
        let mut one = cli.clone();
        one.runtime = *runtime;
        plans.push(match &cli.contract {
            Some(path) => contract_plan(&one, path)?,
            None => plain_plan(&one)?,
        });
    }
    if plans[0].samples == 0 {
        return Err("samples must be at least 1".into());
    }
    // A declared warm state the runner can contradict is refused before any
    // run; the rest is labelled by how it was established.
    let bases = plans
        .iter()
        .map(warm_state_basis)
        .collect::<Result<Vec<_>, _>>()?;
    let started_at_unix_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);

    let mut nonce = started_at_unix_ms as u64 * 1000;
    let mut once = |plan: &Plan, index: u32| -> Result<Sample, String> {
        nonce += 1;
        if let Some((shell, prepare)) = &plan.prepare {
            prepare_run(
                shell,
                &prepare.replace("{sample_nonce}", &nonce.to_string()),
            )?;
        }
        measure(plan, index)
    };
    let before = Probe::read();
    for _ in 0..plans[0].warmup {
        for plan in &plans {
            check_exit(&once(plan, 0)?)?;
        }
    }
    let grouped = plans.len() > 1;
    let mut samples: Vec<Vec<Sample>> = plans
        .iter()
        .map(|p| Vec::with_capacity(p.samples as usize))
        .collect();
    let mut seq = 0u32;
    for index in 0..plans[0].samples {
        // ABBA: the order reverses every sample, so a drift across the
        // group cannot favour one runtime.
        for k in abba_order(index, plans.len()) {
            let mut sample = once(&plans[k], index)?;
            check_exit(&sample)?;
            if grouped {
                sample.seq = Some(seq);
                seq += 1;
            }
            samples[k].push(sample);
        }
    }
    let conditions_seen = conditions(&before, &Probe::read());
    let mut lines = Vec::with_capacity(plans.len());
    let mut summaries = Vec::with_capacity(plans.len());
    for ((plan, samples), basis) in plans.into_iter().zip(samples).zip(bases) {
        let summary = summarize(&samples);
        summaries.push(summary_line(plan.runtime, &summary));
        let record = Record {
            schema: "sentinel-bench/1",
            bench_version: env!("CARGO_PKG_VERSION"),
            started_at_unix_ms,
            label: cli.label.clone(),
            workload: plan.workload,
            runtime: plan.runtime,
            warm_state: plan.warm_state,
            warm_state_basis: basis,
            interleave: grouped.then(|| Interleave {
                runtimes: runtimes.clone(),
                order: "abba",
            }),
            argv: plan.argv.clone(),
            limits: plan.limits,
            source: source.clone(),
            tools: Tools {
                rustc: Some(env!("SENTINEL_BENCH_RUSTC"))
                    .filter(|v| !v.is_empty())
                    .map(str::to_owned),
                podman: (plan.runtime == Runtime::Podman || cli.contract.is_some())
                    .then(|| command_line(&["podman", "--version"]))
                    .flatten(),
            },
            host: host_info(),
            image: plan.image,
            contract: plan.stamp,
            toolchain: plan.toolchain,
            warmup: plan.warmup,
            conditions: conditions_seen.clone(),
            samples,
            summary,
        };
        lines.push(serde_json::to_string(&record).map_err(|e| e.to_string())?);
    }
    match &cli.output {
        Some(path) => {
            let mut file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .map_err(|e| format!("cannot open {}: {e}", path.display()))?;
            for line in &lines {
                writeln!(file, "{line}").map_err(|e| e.to_string())?;
            }
        }
        None => {
            for line in &lines {
                println!("{line}");
            }
        }
    }
    for line in summaries {
        eprintln!("{line}");
    }
    Ok(())
}

/// The order the plans run within sample `index`: forward on even samples,
/// reversed on odd ones.
fn abba_order(index: u32, plans: usize) -> Vec<usize> {
    if index.is_multiple_of(2) {
        (0..plans).collect()
    } else {
        (0..plans).rev().collect()
    }
}

fn summary_line(runtime: Runtime, s: &Summary) -> String {
    let name = match runtime {
        Runtime::Direct => "direct",
        Runtime::Scoped => "scoped",
        Runtime::Podman => "podman",
    };
    let spread = s
        .stddev_ns
        .map(|d| format!(", stddev {} us", d / 1000))
        .unwrap_or_default();
    let note = if s.p95_is_max {
        " (p95 is the max: fewer than 20 samples)"
    } else {
        ""
    };
    format!(
        "{name}: {} samples: min {} us, median {} us, mean {} us{spread}, mad {} us, p95 {} us, max {} us{note}",
        s.count,
        s.min_ns / 1000,
        s.median_ns / 1000,
        s.mean_ns / 1000,
        s.mad_ns / 1000,
        s.p95_ns / 1000,
        s.max_ns / 1000
    )
}

/// How a plan's declared warm state is established (see `Record`), or an
/// error when the runner can see that it does not hold: a warm podman run
/// whose image is absent would pull inside the first sample.
fn warm_state_basis(plan: &Plan) -> Result<&'static str, String> {
    if matches!(plan.warm_state, WarmState::Warm)
        && plan.runtime == Runtime::Podman
        && plan.image.as_ref().is_some_and(|i| i.digest.is_none())
    {
        return Err(
            "--warm-state warm, but the image is not present locally; pull it first (a pull inside a sample is not warm)"
                .into(),
        );
    }
    Ok(match (plan.warm_state, plan.stamp.is_some()) {
        (WarmState::Cold, true) => "contract-prepare",
        (WarmState::Cold, false) => "unverified",
        (WarmState::Warm, _) if plan.warmup >= 1 => "warmup-run",
        (WarmState::Warm, _) => "unverified",
    })
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
        runtime: cli.runtime,
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
        runtime: cli.runtime,
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
            runtime: cli.runtime,
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
        seq: None,
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
    let n = sorted.len();
    // Nearest rank in integers: rank = ceil(percent * n / 100), one-based.
    let rank = |percent: usize| (percent * n).div_ceil(100).max(1);
    let median = sorted[rank(50) - 1];
    let p95_rank = rank(95);
    let sum: u128 = sorted.iter().map(|&v| u128::from(v)).sum();
    let mean = (sum / n as u128) as u64;
    let stddev_ns = (n > 1).then(|| {
        let m = sum as f64 / n as f64;
        let ss: f64 = sorted.iter().map(|&v| (v as f64 - m).powi(2)).sum();
        (ss / (n - 1) as f64).sqrt().round() as u64
    });
    let mut deviations: Vec<u64> = sorted.iter().map(|&v| v.abs_diff(median)).collect();
    deviations.sort_unstable();
    Summary {
        count: n,
        min_ns: sorted[0],
        median_ns: median,
        p95_ns: sorted[p95_rank - 1],
        max_ns: sorted[n - 1],
        mean_ns: mean,
        stddev_ns,
        mad_ns: deviations[rank(50) - 1],
        p95_is_max: p95_rank == n,
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

#[cfg(test)]
mod tests {
    use super::*;

    fn samples(ns: &[u64]) -> Vec<Sample> {
        ns.iter()
            .enumerate()
            .map(|(i, &elapsed_ns)| Sample {
                index: i as u32,
                seq: None,
                elapsed_ns,
                exit_code: Some(0),
                usage: Usage::default(),
            })
            .collect()
    }

    #[test]
    fn p95_is_flagged_as_the_max_until_there_are_twenty_samples() {
        let few: Vec<u64> = (1..=19).collect();
        let s = summarize(&samples(&few));
        assert!(s.p95_is_max && s.p95_ns == s.max_ns);
        let enough: Vec<u64> = (1..=20).collect();
        let s = summarize(&samples(&enough));
        assert!(!s.p95_is_max && s.p95_ns == 19 && s.max_ns == 20);
    }

    #[test]
    fn spread_is_reported_and_mad_ignores_one_outlier() {
        let mut ns = vec![100u64; 9];
        ns.push(10_000);
        let s = summarize(&samples(&ns));
        assert_eq!(s.median_ns, 100);
        assert_eq!(s.mad_ns, 0);
        assert!(s.stddev_ns.unwrap() > 3_000);
        assert_eq!(s.mean_ns, 1_090);
    }

    #[test]
    fn a_single_sample_has_no_standard_deviation() {
        let s = summarize(&samples(&[42]));
        assert_eq!((s.stddev_ns, s.mad_ns, s.mean_ns), (None, 0, 42));
    }

    #[test]
    fn interleaved_order_reverses_every_sample() {
        assert_eq!(abba_order(0, 2), [0, 1]);
        assert_eq!(abba_order(1, 2), [1, 0]);
        assert_eq!(abba_order(2, 3), [0, 1, 2]);
        assert_eq!(abba_order(0, 1), [0]);
    }
}
