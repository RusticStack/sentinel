//! Cost of asking the kernel to kill a helper with its parent (`sentinel_git::die_with_parent`).
//!
//! The hook is a `pre_exec` closure, and a `Command` with one is spawned by `fork` where one without is spawned by
//! `posix_spawn` (a vfork that shares the parent's address space). So the cost of the hook is mostly the cost of
//! `fork`, which grows with how much memory the parent has resident. This spawns and waits for `true` from a parent
//! with 0, 64 and 512 MiB (`--resident-mib`) resident, three ways, and prints one `sentinel-bench/spawn-cost/1`
//! JSON line (`docs/benchmarking.md#spawn-cost`). `bench/spawn-cost.sh` adds the `build` and `host` stamp.
//!
//!     cargo run --release -p sentinel-git --example spawn-cost-bench -- --rounds 5 --spawns 200
//!
//! - `plain`: no hook; the `posix_spawn` path.
//! - `pre_exec_noop`: a `pre_exec` closure that does nothing; the `fork` path alone.
//! - `die_with_parent`: the real hook, which adds the `prctl` and the `getppid` check to the `fork` path.
//!
//! A round times `--spawns` spawn-and-wait calls for every (resident size, variant) cell; the sizes and the variants
//! reverse their order every round (ABBA). The resident memory is touched page by page before its cells start, so the
//! pages are really there. The child is `true`, from an absolute path, with all three streams on the null device.

#[cfg(unix)]
mod bench {
    use std::{
        hint::black_box,
        os::unix::process::CommandExt,
        path::PathBuf,
        process::{Command, ExitCode, Stdio},
        time::{Instant, SystemTime, UNIX_EPOCH},
    };

    use sentinel_git::die_with_parent;

    const VARIANTS: [&str; 3] = ["plain", "pre_exec_noop", "die_with_parent"];

    struct Args {
        rounds: usize,
        spawns: usize,
        resident_mib: Vec<usize>,
    }

    fn parse() -> Result<Args, String> {
        let mut args = Args {
            rounds: 5,
            spawns: 200,
            resident_mib: vec![0, 64, 512],
        };
        let mut it = std::env::args().skip(1);
        while let Some(flag) = it.next() {
            let mut value = |name: &str| it.next().ok_or(format!("{name} needs a value"));
            match flag.as_str() {
                "--rounds" => args.rounds = number(&value("--rounds")?)?,
                "--spawns" => args.spawns = number(&value("--spawns")?)?,
                "--resident-mib" => {
                    args.resident_mib = value("--resident-mib")?
                        .split(',')
                        .map(number)
                        .collect::<Result<_, _>>()?;
                }
                other => return Err(format!("unknown argument {other}")),
            }
        }
        if args.rounds == 0 || args.spawns == 0 || args.resident_mib.is_empty() {
            return Err("--rounds, --spawns and --resident-mib must be positive lists".into());
        }
        Ok(args)
    }

    fn number<T: std::str::FromStr>(text: &str) -> Result<T, String> {
        text.trim()
            .parse()
            .map_err(|_| format!("{text:?} is not a number"))
    }

    fn child() -> Result<PathBuf, String> {
        ["/bin/true", "/usr/bin/true"]
            .iter()
            .map(PathBuf::from)
            .find(|p| p.is_file())
            .ok_or_else(|| "no true(1) at /bin/true or /usr/bin/true".to_owned())
    }

    fn spawn_wait(variant: &str, program: &PathBuf) -> Result<u64, String> {
        let mut command = Command::new(program);
        command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        match variant {
            "plain" => {}
            "pre_exec_noop" => {
                // SAFETY: the closure runs in the forked child before `exec` and does nothing at all.
                unsafe {
                    command.pre_exec(|| Ok(()));
                }
            }
            _ => die_with_parent(&mut command),
        }
        let started = Instant::now();
        let status = command
            .spawn()
            .and_then(|mut c| c.wait())
            .map_err(|e| format!("spawn: {e}"))?;
        let took = started.elapsed().as_nanos() as u64;
        if !black_box(status).success() {
            return Err("the child did not exit 0".into());
        }
        Ok(took)
    }

    fn resident(mib: usize) -> Vec<u8> {
        let mut bytes = vec![0u8; mib << 20];
        for (i, b) in bytes.iter_mut().enumerate().step_by(4096) {
            *b = (i >> 12) as u8 | 1;
        }
        bytes
    }

    fn median(sorted: &[u64]) -> u64 {
        sorted[sorted.len() / 2]
    }

    fn percentile(sorted: &[u64], p: f64) -> u64 {
        // Nearest rank.
        let rank = ((p * sorted.len() as f64).ceil() as usize).clamp(1, sorted.len());
        sorted[rank - 1]
    }

    fn abba<T: Copy>(round: usize, cases: &[T]) -> Vec<T> {
        let mut order = cases.to_vec();
        if round % 2 == 1 {
            order.reverse();
        }
        order
    }

    fn list<T: std::fmt::Display>(items: &[T]) -> String {
        items
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",")
    }

    fn run() -> Result<(), String> {
        let args = parse()?;
        let program = child()?;
        let started_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_millis());
        let sizes: Vec<usize> = (0..args.resident_mib.len()).collect();
        let variants: Vec<usize> = (0..VARIANTS.len()).collect();
        let mut cells: Vec<Vec<Vec<Vec<u64>>>> = args
            .resident_mib
            .iter()
            .map(|_| VARIANTS.iter().map(|_| Vec::new()).collect())
            .collect();
        let mut order_log = Vec::new();
        // Warm the exec path and the page cache once per variant before anything is timed.
        for variant in VARIANTS {
            for _ in 0..5 {
                spawn_wait(variant, &program)?;
            }
        }
        for round in 0..args.rounds {
            let mut seen = Vec::new();
            for s in abba(round, &sizes) {
                let held = resident(args.resident_mib[s]);
                for v in abba(round, &variants) {
                    let mut ns = Vec::with_capacity(args.spawns);
                    for _ in 0..args.spawns {
                        ns.push(spawn_wait(VARIANTS[v], &program)?);
                    }
                    cells[s][v].push(ns);
                    seen.push(format!("{}MiB/{}", args.resident_mib[s], VARIANTS[v]));
                }
                black_box(&held);
            }
            order_log.push(seen);
        }
        let mut results = Vec::new();
        for (s, mib) in args.resident_mib.iter().enumerate() {
            for (v, variant) in VARIANTS.iter().enumerate() {
                let rounds = &cells[s][v];
                let round_median: Vec<u64> = rounds
                    .iter()
                    .map(|r| {
                        let mut sorted = r.clone();
                        sorted.sort_unstable();
                        median(&sorted)
                    })
                    .collect();
                let mut pooled: Vec<u64> = rounds.iter().flatten().copied().collect();
                pooled.sort_unstable();
                results.push(format!(
                    "{{\"resident_mib\":{mib},\"variant\":\"{variant}\",\"samples\":{},\"round_median_ns\":[{}],\"min_ns\":{},\"median_ns\":{},\"p95_ns\":{},\"p99_ns\":{},\"p99_is_max\":{},\"max_ns\":{}}}",
                    pooled.len(),
                    list(&round_median),
                    pooled[0],
                    median(&pooled),
                    percentile(&pooled, 0.95),
                    percentile(&pooled, 0.99),
                    pooled.len() < 100,
                    pooled[pooled.len() - 1],
                ));
            }
        }
        let order: Vec<String> = order_log
            .iter()
            .map(|r| {
                format!(
                    "[{}]",
                    r.iter()
                        .map(|c| format!("\"{c}\""))
                        .collect::<Vec<_>>()
                        .join(",")
                )
            })
            .collect();
        println!(
            "{{\"schema\":\"sentinel-bench/spawn-cost/1\",\"workload\":\"spawn-cost\",\"started_at_unix_ms\":{started_at},\"rounds\":{},\"spawns\":{},\"resident_mib\":[{}],\"child\":\"{}\",\"order\":[{}],\"results\":[{}]}}",
            args.rounds,
            args.spawns,
            list(&args.resident_mib),
            program.display(),
            order.join(","),
            results.join(","),
        );
        Ok(())
    }

    pub fn main() -> ExitCode {
        match run() {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("spawn-cost-bench: {e}");
                ExitCode::FAILURE
            }
        }
    }
}

#[cfg(unix)]
fn main() -> std::process::ExitCode {
    bench::main()
}

#[cfg(not(unix))]
fn main() -> std::process::ExitCode {
    eprintln!("spawn-cost-bench: Unix only");
    std::process::ExitCode::FAILURE
}
