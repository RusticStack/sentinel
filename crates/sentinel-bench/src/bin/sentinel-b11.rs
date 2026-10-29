//! The B11 paired-sample harness.
//!
//! Reads a frozen `sentinel.b11-contract/1` and a `sentinel.b11-samples/1`
//! file of paired Sentinel/Blacksmith executions and decides the B11 gate:
//! per lane and condition, the nearest-rank p95 ratio, the paired log-duration
//! ratio and its one-sided bootstrap upper bound, with every failed or
//! incorrect execution counted rather than dropped. It measures nothing and
//! holds no results; see `docs/benchmark-contracts.md`.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    process::ExitCode,
};

use clap::Parser;
use serde::{Deserialize, Serialize};

const CONTRACT_FORMAT: &str = "sentinel.b11-contract/1";
const SAMPLES_FORMAT: &str = "sentinel.b11-samples/1";
const REPORT_FORMAT: &str = "sentinel.b11-report/1";
/// Largest contract or samples file read; a release series is a few hundred lines.
const MAX_INPUT_BYTES: u64 = 32 << 20;

#[derive(Parser)]
#[command(version, about)]
struct Cli {
    /// The frozen B11 contract (`bench/contracts/b11-blacksmith.json`)
    #[arg(long)]
    contract: PathBuf,
    /// Paired samples: a `sentinel.b11-samples/1` header line, then one pair per line
    #[arg(long)]
    samples: PathBuf,
    /// Append the JSON report as one line to this file instead of stdout
    #[arg(long)]
    output: Option<PathBuf>,
}

// ---- contract -------------------------------------------------------------

#[derive(Deserialize)]
struct Contract {
    format: String,
    id: String,
    revision: u32,
    gate: Gate,
    series: SeriesSpec,
    disclosure: Disclosure,
}

#[derive(Deserialize)]
struct Gate {
    ratio_limit: f64,
    percentile: usize,
    min_pairs: usize,
    max_pairs: usize,
    confidence: f64,
    bootstrap: Bootstrap,
}

#[derive(Deserialize)]
struct Bootstrap {
    resamples: usize,
    seed: u64,
}

#[derive(Deserialize)]
struct SeriesSpec {
    conditions: Vec<String>,
    lanes: Vec<String>,
}

#[derive(Deserialize)]
struct Disclosure {
    label: String,
}

impl Contract {
    fn check(&self) -> Result<(), String> {
        if self.format != CONTRACT_FORMAT {
            return Err(format!(
                "contract format is not {CONTRACT_FORMAT}; this harness reads only that"
            ));
        }
        let g = &self.gate;
        if !(g.ratio_limit > 0.0 && g.ratio_limit <= 1.0) {
            return Err("gate.ratio_limit must be in (0, 1]".into());
        }
        if !(1..=100).contains(&g.percentile) {
            return Err("gate.percentile must be 1..=100".into());
        }
        if !(g.confidence > 0.5 && g.confidence < 1.0) {
            return Err("gate.confidence must be in (0.5, 1)".into());
        }
        if g.min_pairs == 0 || g.max_pairs < g.min_pairs {
            return Err("gate.min_pairs must be at least 1 and at most gate.max_pairs".into());
        }
        if g.bootstrap.resamples < 1000 {
            return Err("gate.bootstrap.resamples must be at least 1000".into());
        }
        if self.series.lanes.is_empty() || self.series.conditions.is_empty() {
            return Err("the contract names no lanes or no conditions".into());
        }
        Ok(())
    }
}

// ---- samples --------------------------------------------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    format: String,
    contract: String,
    revision: u32,
}

#[derive(Clone, Copy, PartialEq, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum Order {
    SentinelFirst,
    BlacksmithFirst,
}

#[derive(Clone, Copy, PartialEq, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Outcome {
    Pass,
    Fail,
    Incorrect,
}

/// One execution of the checks for one trigger.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Side {
    sha: String,
    /// Trigger to last required check complete, nanoseconds
    trigger_to_required_ns: u64,
    /// First job start to last job finish, nanoseconds
    #[serde(default)]
    job_ns: Option<u64>,
    #[serde(default)]
    phases: BTreeMap<String, u64>,
    outcome: Outcome,
    /// A required check never completed: `outcome` is `fail` and the duration is
    /// the observation window, a lower bound. Counted apart, never dropped.
    #[serde(default)]
    censored: bool,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct PairLine {
    lane: String,
    condition: String,
    pair: u32,
    order: Order,
    sentinel: Side,
    blacksmith: Side,
}

impl Side {
    fn check(&self) -> Result<(), String> {
        let sha_ok = matches!(self.sha.len(), 40 | 64)
            && self
                .sha
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        if !sha_ok {
            return Err("sha must be 40 or 64 lowercase hex digits".into());
        }
        if self.censored && self.outcome != Outcome::Fail {
            return Err("a censored execution never completed, so its outcome is fail".into());
        }
        if self.trigger_to_required_ns == 0 || self.job_ns == Some(0) {
            return Err("durations must be at least 1 ns".into());
        }
        if self.phases.values().any(|&v| v == 0) {
            return Err("a phase of 0 ns is a missing phase; leave it out".into());
        }
        Ok(())
    }
}

/// Parses the samples text into series keyed by lane and condition.
fn parse_samples(
    text: &str,
    contract: &Contract,
) -> Result<BTreeMap<(String, String), Vec<PairLine>>, String> {
    let mut lines = text
        .lines()
        .enumerate()
        .filter(|(_, l)| !l.trim().is_empty());
    let (_, first) = lines.next().ok_or("the samples file is empty")?;
    let header: Header =
        serde_json::from_str(first).map_err(|e| format!("line 1: not a samples header: {e}"))?;
    if header.format != SAMPLES_FORMAT {
        return Err(format!("line 1: samples format is not {SAMPLES_FORMAT}"));
    }
    if header.contract != contract.id || header.revision != contract.revision {
        return Err(format!(
            "samples were taken under {} revision {}, the contract is {} revision {}; records of different revisions are never combined",
            header.contract, header.revision, contract.id, contract.revision
        ));
    }
    let mut seen = BTreeSet::new();
    let mut series: BTreeMap<(String, String), Vec<PairLine>> = BTreeMap::new();
    for (i, line) in lines {
        let n = i + 1;
        let pair: PairLine =
            serde_json::from_str(line).map_err(|e| format!("line {n}: not a pair: {e}"))?;
        if !contract.series.lanes.contains(&pair.lane) {
            return Err(format!(
                "line {n}: lane `{}` is not in the contract",
                pair.lane
            ));
        }
        if !contract.series.conditions.contains(&pair.condition) {
            return Err(format!(
                "line {n}: condition `{}` is not in the contract",
                pair.condition
            ));
        }
        pair.sentinel
            .check()
            .map_err(|e| format!("line {n}: sentinel: {e}"))?;
        pair.blacksmith
            .check()
            .map_err(|e| format!("line {n}: blacksmith: {e}"))?;
        if !seen.insert((pair.lane.clone(), pair.condition.clone(), pair.pair)) {
            return Err(format!(
                "line {n}: pair {} of {}/{} appears twice",
                pair.pair, pair.lane, pair.condition
            ));
        }
        let entry = series
            .entry((pair.lane.clone(), pair.condition.clone()))
            .or_default();
        if entry.len() >= contract.gate.max_pairs {
            return Err(format!(
                "line {n}: {}/{} exceeds the contract's {} pairs",
                pair.lane, pair.condition, contract.gate.max_pairs
            ));
        }
        entry.push(pair);
    }
    Ok(series)
}

// ---- statistics -----------------------------------------------------------

/// xoshiro256** seeded through splitmix64: small, fast, reproducible across hosts.
struct Rng([u64; 4]);

impl Rng {
    fn seeded(seed: u64) -> Self {
        let mut x = seed;
        let mut next = || {
            x = x.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = x;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            z ^ (z >> 31)
        };
        Rng([next(), next(), next(), next()])
    }

    fn next_u64(&mut self) -> u64 {
        let s = &mut self.0;
        let result = s[1].wrapping_mul(5).rotate_left(7).wrapping_mul(9);
        let t = s[1] << 17;
        s[2] ^= s[0];
        s[3] ^= s[1];
        s[1] ^= s[2];
        s[0] ^= s[3];
        s[2] ^= t;
        s[3] = s[3].rotate_left(45);
        result
    }

    /// Uniform in `0..n` without modulo bias.
    fn below(&mut self, n: u64) -> u64 {
        let threshold = n.wrapping_neg() % n;
        loop {
            let x = self.next_u64();
            if x >= threshold {
                return x % n;
            }
        }
    }
}

/// 1-based nearest rank of `percent` over `n` values.
fn rank(percent: usize, n: usize) -> usize {
    (percent * n).div_ceil(100).max(1)
}

fn percentile(sorted: &[u64], percent: usize) -> u64 {
    sorted[rank(percent, sorted.len()) - 1]
}

#[derive(Serialize)]
struct Dist {
    count: usize,
    min_ns: u64,
    median_ns: u64,
    p95_ns: u64,
    max_ns: u64,
    mean_ns: u64,
}

fn dist(mut values: Vec<u64>) -> Option<Dist> {
    if values.is_empty() {
        return None;
    }
    values.sort_unstable();
    let n = values.len();
    let sum: u128 = values.iter().map(|&v| u128::from(v)).sum();
    Some(Dist {
        count: n,
        min_ns: values[0],
        median_ns: percentile(&values, 50),
        p95_ns: percentile(&values, 95),
        max_ns: values[n - 1],
        mean_ns: (sum / n as u128) as u64,
    })
}

struct Bounds {
    /// One-sided upper bound of the mean paired log ratio
    mean_log_upper: f64,
    /// The same bound for the log of the p95 ratio (reported, not gating)
    p95_log_upper: f64,
}

/// Percentile bootstrap over pairs: each resample draws `n` pairs with
/// replacement and keeps the mean of their log ratios and the log of the
/// ratio of the two sides' nearest-rank percentiles. The bound is the
/// nearest-rank `confidence` quantile of each statistic.
fn bootstrap(sentinel: &[u64], blacksmith: &[u64], gate: &Gate) -> Bounds {
    let n = sentinel.len();
    let logs: Vec<f64> = sentinel
        .iter()
        .zip(blacksmith)
        .map(|(&s, &b)| (s as f64 / b as f64).ln())
        .collect();
    let resamples = gate.bootstrap.resamples;
    let mut rng = Rng::seeded(gate.bootstrap.seed);
    let (mut s_buf, mut b_buf) = (vec![0u64; n], vec![0u64; n]);
    let mut means = Vec::with_capacity(resamples);
    let mut p95s = Vec::with_capacity(resamples);
    let at = rank(gate.percentile, n) - 1;
    for _ in 0..resamples {
        let mut sum = 0.0;
        for k in 0..n {
            let i = rng.below(n as u64) as usize;
            s_buf[k] = sentinel[i];
            b_buf[k] = blacksmith[i];
            sum += logs[i];
        }
        means.push(sum / n as f64);
        s_buf.sort_unstable();
        b_buf.sort_unstable();
        p95s.push((s_buf[at] as f64 / b_buf[at] as f64).ln());
    }
    // Integer ppm, so 0.95 * 10_000 is exactly rank 9_500.
    let ppm = (gate.confidence * 1_000_000.0).round() as usize;
    let bound_rank = (ppm * resamples).div_ceil(1_000_000).clamp(1, resamples) - 1;
    means.sort_unstable_by(f64::total_cmp);
    p95s.sort_unstable_by(f64::total_cmp);
    Bounds {
        mean_log_upper: means[bound_rank],
        p95_log_upper: p95s[bound_rank],
    }
}

// ---- evaluation -----------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
enum Verdict {
    Pass,
    Fail,
    /// Fewer than `min_pairs`: guidance for optimization, never a pass
    Insufficient,
}

#[derive(Default, Serialize)]
struct NonPass {
    sentinel_fail: usize,
    sentinel_incorrect: usize,
    blacksmith_fail: usize,
    blacksmith_incorrect: usize,
    /// Of the failures above, the executions that never completed
    sentinel_censored: usize,
    blacksmith_censored: usize,
}

#[derive(Serialize)]
struct SideDists {
    sentinel: Option<Dist>,
    blacksmith: Option<Dist>,
}

#[derive(Serialize)]
struct SeriesReport {
    lane: String,
    condition: String,
    pairs: usize,
    verdict: Verdict,
    reasons: Vec<String>,
    non_pass: NonPass,
    sha_mismatches: usize,
    order_violations: usize,
    sentinel: Dist,
    blacksmith: Dist,
    /// Nearest-rank p95 of Sentinel over that of Blacksmith
    p95_ratio: f64,
    geometric_mean_ratio: f64,
    mean_log_ratio: f64,
    mean_log_ratio_upper: f64,
    /// `exp(mean_log_ratio_upper)`; the gate needs it below the limit
    ratio_upper: f64,
    /// Informational: upper bound of the p95 ratio itself
    p95_ratio_upper: f64,
    confidence: f64,
    resamples: usize,
    seed: u64,
    /// Sentinel over Blacksmith for each pair, in pair order
    paired_ratios: Vec<f64>,
    job: SideDists,
    phases: BTreeMap<String, SideDists>,
}

fn side_dists(pairs: &[PairLine], pick: impl Fn(&Side) -> Option<u64>) -> SideDists {
    SideDists {
        sentinel: dist(pairs.iter().filter_map(|p| pick(&p.sentinel)).collect()),
        blacksmith: dist(pairs.iter().filter_map(|p| pick(&p.blacksmith)).collect()),
    }
}

fn evaluate(lane: &str, condition: &str, mut pairs: Vec<PairLine>, gate: &Gate) -> SeriesReport {
    pairs.sort_by_key(|p| p.pair);
    let n = pairs.len();
    let mut reasons = Vec::new();
    let mut non_pass = NonPass::default();
    let (mut sha_mismatches, mut order_violations) = (0, 0);
    for p in &pairs {
        match p.sentinel.outcome {
            Outcome::Pass => {}
            Outcome::Fail => non_pass.sentinel_fail += 1,
            Outcome::Incorrect => non_pass.sentinel_incorrect += 1,
        }
        match p.blacksmith.outcome {
            Outcome::Pass => {}
            Outcome::Fail => non_pass.blacksmith_fail += 1,
            Outcome::Incorrect => non_pass.blacksmith_incorrect += 1,
        }
        non_pass.sentinel_censored += usize::from(p.sentinel.censored);
        non_pass.blacksmith_censored += usize::from(p.blacksmith.censored);
        sha_mismatches += usize::from(p.sentinel.sha != p.blacksmith.sha);
        let expected = if p.pair.is_multiple_of(2) {
            Order::SentinelFirst
        } else {
            Order::BlacksmithFirst
        };
        order_violations += usize::from(p.order != expected);
    }
    let failed = non_pass.sentinel_fail
        + non_pass.sentinel_incorrect
        + non_pass.blacksmith_fail
        + non_pass.blacksmith_incorrect;
    if failed > 0 {
        reasons.push(format!(
            "{failed} execution(s) failed or were incorrect; the gate fails and none is dropped"
        ));
    }
    if sha_mismatches > 0 {
        reasons.push(format!(
            "{sha_mismatches} pair(s) ran different source SHAs on the two sides"
        ));
    }
    if order_violations > 0 {
        reasons.push(format!(
            "{order_violations} pair(s) break the ABBA order (Sentinel first in even pairs)"
        ));
    }
    if pairs.iter().enumerate().any(|(i, p)| p.pair as usize != i) {
        reasons.push("pairs are not numbered 0..n without gaps: a pair was dropped".into());
    }
    let hard_failure = !reasons.is_empty();

    let s: Vec<u64> = pairs
        .iter()
        .map(|p| p.sentinel.trigger_to_required_ns)
        .collect();
    let b: Vec<u64> = pairs
        .iter()
        .map(|p| p.blacksmith.trigger_to_required_ns)
        .collect();
    let paired_ratios: Vec<f64> = s
        .iter()
        .zip(&b)
        .map(|(&s, &b)| s as f64 / b as f64)
        .collect();
    let mean_log = paired_ratios.iter().map(|r| r.ln()).sum::<f64>() / n as f64;
    let bounds = bootstrap(&s, &b, gate);
    let (mut s_sorted, mut b_sorted) = (s.clone(), b.clone());
    s_sorted.sort_unstable();
    b_sorted.sort_unstable();
    let p95_ratio = percentile(&s_sorted, gate.percentile) as f64
        / percentile(&b_sorted, gate.percentile) as f64;
    let ratio_upper = bounds.mean_log_upper.exp();

    let mut verdict = Verdict::Pass;
    if n < gate.min_pairs {
        reasons.push(format!(
            "{n} pair(s), fewer than the contract's {}: guidance only, not a result",
            gate.min_pairs
        ));
        verdict = Verdict::Insufficient;
    } else {
        if p95_ratio > gate.ratio_limit {
            reasons.push(format!(
                "p95 ratio {p95_ratio:.4} is over the limit {}",
                gate.ratio_limit
            ));
        }
        if ratio_upper >= gate.ratio_limit {
            reasons.push(format!(
                "upper bound {ratio_upper:.4} of the paired ratio is not below {}",
                gate.ratio_limit
            ));
        }
        if !reasons.is_empty() {
            verdict = Verdict::Fail;
        }
    }
    if hard_failure {
        verdict = Verdict::Fail;
    }

    let names: BTreeSet<&String> = pairs
        .iter()
        .flat_map(|p| p.sentinel.phases.keys().chain(p.blacksmith.phases.keys()))
        .collect();
    let phases = names
        .into_iter()
        .map(|name| {
            (
                name.clone(),
                side_dists(&pairs, |side| side.phases.get(name).copied()),
            )
        })
        .collect();
    SeriesReport {
        lane: lane.into(),
        condition: condition.into(),
        pairs: n,
        verdict,
        reasons,
        non_pass,
        sha_mismatches,
        order_violations,
        sentinel: dist(s).unwrap_or_else(empty_dist),
        blacksmith: dist(b).unwrap_or_else(empty_dist),
        p95_ratio,
        geometric_mean_ratio: mean_log.exp(),
        mean_log_ratio: mean_log,
        mean_log_ratio_upper: bounds.mean_log_upper,
        ratio_upper,
        p95_ratio_upper: bounds.p95_log_upper.exp(),
        confidence: gate.confidence,
        resamples: gate.bootstrap.resamples,
        seed: gate.bootstrap.seed,
        paired_ratios,
        job: side_dists(&pairs, |side| side.job_ns),
        phases,
    }
}

/// A series always has at least one pair, so this is never reached.
fn empty_dist() -> Dist {
    Dist {
        count: 0,
        min_ns: 0,
        median_ns: 0,
        p95_ns: 0,
        max_ns: 0,
        mean_ns: 0,
    }
}

#[derive(Serialize)]
struct Stamp {
    id: String,
    revision: u32,
    blake3: String,
}

#[derive(Serialize)]
struct Report {
    format: &'static str,
    contract: Stamp,
    /// How the result must be described; never "same-hardware"
    label: String,
    verdict: Verdict,
    /// Contract series with no samples at all: each fails the gate
    missing: Vec<String>,
    series: Vec<SeriesReport>,
}

fn build_report(
    contract: &Contract,
    blake3: String,
    mut series: BTreeMap<(String, String), Vec<PairLine>>,
) -> Report {
    let mut reports = Vec::new();
    let mut missing = Vec::new();
    for lane in &contract.series.lanes {
        for condition in &contract.series.conditions {
            match series.remove(&(lane.clone(), condition.clone())) {
                Some(pairs) => reports.push(evaluate(lane, condition, pairs, &contract.gate)),
                None => missing.push(format!("{lane}/{condition}")),
            }
        }
    }
    let verdict = if !missing.is_empty() || reports.iter().any(|r| r.verdict == Verdict::Fail) {
        Verdict::Fail
    } else if reports.iter().any(|r| r.verdict == Verdict::Insufficient) {
        Verdict::Insufficient
    } else {
        Verdict::Pass
    };
    Report {
        format: REPORT_FORMAT,
        contract: Stamp {
            id: contract.id.clone(),
            revision: contract.revision,
            blake3,
        },
        label: contract.disclosure.label.clone(),
        verdict,
        missing,
        series: reports,
    }
}

// ---- main -----------------------------------------------------------------

fn read_bounded(path: &Path) -> Result<String, String> {
    let len = fs::metadata(path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?
        .len();
    if len > MAX_INPUT_BYTES {
        return Err(format!(
            "{} is {len} bytes, over the {MAX_INPUT_BYTES} byte limit",
            path.display()
        ));
    }
    fs::read_to_string(path).map_err(|e| format!("cannot read {}: {e}", path.display()))
}

fn run(cli: &Cli) -> Result<Verdict, String> {
    let contract_text = read_bounded(&cli.contract)?;
    let contract: Contract = serde_json::from_str(&contract_text)
        .map_err(|e| format!("{}: not a B11 contract: {e}", cli.contract.display()))?;
    contract.check()?;
    let series = parse_samples(&read_bounded(&cli.samples)?, &contract)?;
    let report = build_report(
        &contract,
        blake3::hash(contract_text.as_bytes()).to_hex().to_string(),
        series,
    );
    let line = serde_json::to_string(&report).map_err(|e| e.to_string())?;
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
    for s in &report.series {
        eprintln!(
            "{}/{}: {} pairs, p95 ratio {:.4}, paired ratio upper bound {:.4}: {}",
            s.lane,
            s.condition,
            s.pairs,
            s.p95_ratio,
            s.ratio_upper,
            match s.verdict {
                Verdict::Pass => "pass",
                Verdict::Fail => "fail",
                Verdict::Insufficient => "insufficient",
            }
        );
        for reason in &s.reasons {
            eprintln!("  - {reason}");
        }
    }
    for m in &report.missing {
        eprintln!("{m}: no samples (fails the gate)");
    }
    Ok(report.verdict)
}

fn main() -> ExitCode {
    match run(&Cli::parse()) {
        Ok(Verdict::Pass) => ExitCode::SUCCESS,
        Ok(_) => ExitCode::from(1),
        Err(message) => {
            eprintln!("error: {message}");
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gate() -> Gate {
        Gate {
            ratio_limit: 0.5,
            percentile: 95,
            min_pairs: 100,
            max_pairs: 10_000,
            confidence: 0.95,
            bootstrap: Bootstrap {
                resamples: 2_000,
                seed: 7,
            },
        }
    }

    const SHA: &str = "0123456789abcdef0123456789abcdef01234567";

    fn side(ns: u64) -> Side {
        Side {
            sha: SHA.into(),
            trigger_to_required_ns: ns,
            job_ns: None,
            phases: BTreeMap::new(),
            outcome: Outcome::Pass,
            censored: false,
        }
    }

    fn pair(i: u32, s: u64, b: u64) -> PairLine {
        PairLine {
            lane: "cli".into(),
            condition: "warm".into(),
            pair: i,
            order: if i.is_multiple_of(2) {
                Order::SentinelFirst
            } else {
                Order::BlacksmithFirst
            },
            sentinel: side(s),
            blacksmith: side(b),
        }
    }

    /// Deterministic noise in [1 - spread, 1 + spread].
    struct Noise(u64);
    impl Noise {
        fn next(&mut self, spread: f64) -> f64 {
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            let unit = (self.0 >> 11) as f64 / (1u64 << 53) as f64;
            1.0 + spread * (2.0 * unit - 1.0)
        }
    }

    fn series(n: u32, ratio: f64) -> Vec<PairLine> {
        let mut noise = Noise(1);
        (0..n)
            .map(|i| {
                let b = 10_000_000_000.0 * noise.next(0.2);
                let s = b * ratio * noise.next(0.1);
                pair(i, s as u64, b as u64)
            })
            .collect()
    }

    fn run_series(pairs: Vec<PairLine>) -> SeriesReport {
        evaluate("cli", "warm", pairs, &gate())
    }

    #[test]
    fn nearest_rank_is_the_ceiling_rank() {
        let v: Vec<u64> = (1..=100).collect();
        assert_eq!(percentile(&v, 95), 95);
        assert_eq!(percentile(&v, 50), 50);
        let v: Vec<u64> = (1..=20).collect();
        assert_eq!(percentile(&v, 95), 19);
        assert_eq!(percentile(&[42], 95), 42);
    }

    #[test]
    fn the_rng_is_reproducible_and_stays_in_range() {
        let (mut a, mut b) = (Rng::seeded(11), Rng::seeded(11));
        let mut counts = [0usize; 7];
        for _ in 0..7_000 {
            let x = a.below(7);
            assert_eq!(x, b.below(7));
            counts[x as usize] += 1;
        }
        assert!(
            counts.iter().all(|&c| (800..1200).contains(&c)),
            "{counts:?}"
        );
        assert_ne!(Rng::seeded(11).next_u64(), Rng::seeded(12).next_u64());
    }

    #[test]
    fn a_clear_win_over_one_hundred_pairs_passes() {
        let r = run_series(series(100, 0.40));
        assert_eq!(r.verdict, Verdict::Pass, "{:?}", r.reasons);
        assert!(r.p95_ratio < 0.5 && r.ratio_upper < 0.5);
        assert!(
            r.mean_log_ratio_upper > r.mean_log_ratio,
            "a bound sits above the estimate"
        );
        assert!((r.geometric_mean_ratio - 0.40).abs() < 0.03);
        assert_eq!(r.paired_ratios.len(), 100);
    }

    #[test]
    fn a_ratio_over_the_limit_fails() {
        let r = run_series(series(100, 0.55));
        assert_eq!(r.verdict, Verdict::Fail);
        assert!(r.reasons.iter().any(|m| m.contains("p95 ratio")));
    }

    #[test]
    fn an_estimate_under_the_limit_fails_when_the_bound_does_not_clear_it() {
        // Half the pairs at 0.25 and half at 0.9: the geometric mean is 0.47,
        // under the limit, but the confidence bound is not.
        let pairs = (0..100)
            .map(|i| pair(i, if i % 2 == 0 { 250 } else { 900 }, 1_000))
            .collect();
        let r = run_series(pairs);
        assert!(r.geometric_mean_ratio < 0.5, "{}", r.geometric_mean_ratio);
        assert!(r.ratio_upper >= 0.5, "{}", r.ratio_upper);
        assert_eq!(r.verdict, Verdict::Fail);
        assert!(r.reasons.iter().any(|m| m.contains("upper bound")));
    }

    #[test]
    fn a_tail_the_p95_ignores_still_fails_the_paired_bound() {
        // 95 pairs at 0.4 and 5 at 100: nearest-rank p95 of Sentinel is the
        // 0.4 value, but the paired mean is 0.53.
        let pairs = (0..100)
            .map(|i| pair(i, if i % 20 == 3 { 100_000 } else { 400 }, 1_000))
            .collect();
        let r = run_series(pairs);
        assert!(r.p95_ratio <= 0.5, "{}", r.p95_ratio);
        assert_eq!(r.verdict, Verdict::Fail);
        assert!(r.reasons.iter().any(|m| m.contains("upper bound")));
        assert!(!r.reasons.iter().any(|m| m.contains("p95 ratio")));
    }

    #[test]
    fn fewer_than_the_required_pairs_never_pass() {
        let r = run_series(series(99, 0.10));
        assert_eq!(r.verdict, Verdict::Insufficient);
        assert!(r.ratio_upper < 0.5, "the figures are still reported");
    }

    #[test]
    fn a_failed_execution_fails_the_gate_and_stays_in_the_data() {
        for (sentinel_side, outcome) in [(true, Outcome::Fail), (false, Outcome::Incorrect)] {
            let mut pairs = series(100, 0.30);
            let slow = &mut pairs[41];
            let side = if sentinel_side {
                &mut slow.sentinel
            } else {
                &mut slow.blacksmith
            };
            side.outcome = outcome;
            let r = run_series(pairs);
            assert_eq!(r.verdict, Verdict::Fail);
            assert_eq!(r.pairs, 100, "the pair is not dropped");
            assert_eq!(r.sentinel.count, 100);
            let total = r.non_pass.sentinel_fail
                + r.non_pass.sentinel_incorrect
                + r.non_pass.blacksmith_fail
                + r.non_pass.blacksmith_incorrect;
            assert_eq!(total, 1);
        }
    }

    #[test]
    fn a_censored_execution_is_a_failure_and_is_counted_as_censored() {
        let mut pairs = series(100, 0.30);
        pairs[5].sentinel.outcome = Outcome::Fail;
        pairs[5].sentinel.censored = true;
        pairs[6].blacksmith.outcome = Outcome::Fail;
        let r = run_series(pairs);
        assert_eq!(r.verdict, Verdict::Fail);
        assert_eq!(r.non_pass.sentinel_fail, 1);
        assert_eq!(r.non_pass.sentinel_censored, 1);
        assert_eq!(r.non_pass.blacksmith_fail, 1);
        assert_eq!(r.non_pass.blacksmith_censored, 0);
    }

    #[test]
    fn a_censored_execution_that_passed_is_an_input_error() {
        let mut s = side(5);
        s.censored = true;
        assert!(s.check().is_err());
        s.outcome = Outcome::Fail;
        assert!(s.check().is_ok());
    }

    #[test]
    fn mismatched_shas_a_dropped_pair_and_broken_order_each_fail() {
        let mut pairs = series(100, 0.30);
        pairs[7].blacksmith.sha = "f".repeat(40);
        let r = run_series(pairs);
        assert_eq!((r.verdict, r.sha_mismatches), (Verdict::Fail, 1));

        let mut pairs = series(101, 0.30);
        pairs.remove(37);
        let r = run_series(pairs);
        assert_eq!(r.verdict, Verdict::Fail);
        assert!(r.reasons.iter().any(|m| m.contains("dropped")));

        let mut pairs = series(100, 0.30);
        pairs[10].order = Order::BlacksmithFirst;
        let r = run_series(pairs);
        assert_eq!((r.verdict, r.order_violations), (Verdict::Fail, 1));
    }

    #[test]
    fn the_bootstrap_is_reproducible_and_narrows_with_more_pairs() {
        let spread = |n: u32| {
            let r = run_series(series(n, 0.40));
            r.mean_log_ratio_upper - r.mean_log_ratio
        };
        let a = run_series(series(100, 0.40));
        let b = run_series(series(100, 0.40));
        assert_eq!(a.mean_log_ratio_upper, b.mean_log_ratio_upper);
        assert!(spread(400) < spread(100));
        let mut other = gate();
        other.bootstrap.seed = 8;
        let c = evaluate("cli", "warm", series(100, 0.40), &other);
        assert_ne!(a.mean_log_ratio_upper, c.mean_log_ratio_upper);
        assert!((a.mean_log_ratio_upper - c.mean_log_ratio_upper).abs() < 0.02);
    }

    #[test]
    fn job_and_phase_costs_are_reported_where_present_and_never_as_zero() {
        let mut pairs = series(100, 0.40);
        for p in &mut pairs {
            p.sentinel.job_ns = Some(4_000_000_000);
            p.sentinel.phases.insert("queue".into(), 300_000_000);
        }
        pairs[0]
            .blacksmith
            .phases
            .insert("queue".into(), 2_000_000_000);
        let r = run_series(pairs);
        assert_eq!(r.job.sentinel.as_ref().map(|d| d.count), Some(100));
        assert!(r.job.blacksmith.is_none(), "no figure, not a zero");
        let queue = &r.phases["queue"];
        assert_eq!(queue.sentinel.as_ref().map(|d| d.count), Some(100));
        assert_eq!(queue.blacksmith.as_ref().map(|d| d.count), Some(1));
    }
}
