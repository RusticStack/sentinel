//! Shadow parity: Sentinel's non-required copy of a migrated job, beside the original GitHub ran on
//! the same commit.
//!
//! A shadow pair is one GitHub job and its copy, both named as their own surface names them: the
//! copy is `sentinel / <original>`, which is what a check Sentinel publishes for a native job is
//! called and what the copied job is named in runner mode. The comparison is per pair and per
//! commit, and it is a read: every probe is keyed (`runs_by_sha`, `jobs_by_run`,
//! `check_publications_run`, the `runner_jobs` primary key), so a week of pushes costs one probe
//! per commit and per job rather than a scan of anything.
//!
//! Both halves of a pair are read from what Sentinel already holds — a native shadow's conclusion
//! is the check it published and its duration is the job's own phase stamps; a runner-mode shadow's
//! is the `runner_jobs` row its `workflow_job` deliveries wrote — beside what the Actions jobs page
//! states about the original. Nothing here writes, and nothing is compared that was not measured:
//! a job that stated no test results is [`Tests::Unreported`], never zero tests, and an unmeasured
//! duration is absent rather than equal.

use std::collections::HashMap;

use rusqlite::{Connection, OptionalExtension, params};
use sentinel_core::{JobId, RepoId, TenantId};
use sentinel_protocol::diagnostics::{ReportFormat, TestCounts};

use crate::{Error, Result, checks};

/// The name a shadow job carries in both modes: `sentinel / <original>`, the same prefix a per-job
/// check is published under.
pub const SHADOW_PREFIX: &str = checks::JOB_PREFIX;

/// One report compares at most this many pairs, over at most this many commits: two Actions pages
/// of jobs, and the commits a week of pushes to one repository names.
pub const MAX_PAIRS: usize = 256;
pub const MAX_SHAS: usize = 64;
/// The longest job or check name a pair may name, matching a check publication's own column.
pub const MAX_NAME: usize = 512;

/// A copy slower than the original by more than this factor, and by more than this much, is a
/// mismatch: a second of noise on a two-minute job is not the same finding as a minute on a
/// ten-second one.
const DURATION_RATIO: u64 = 2;
const DURATION_FLOOR_MS: u64 = 1_000;

/// Whether the repository is this tenant's: the report reads one tenant's rows and no others'.
pub const REPO_SQL: &str = "SELECT 1 FROM repos WHERE id = ?1 AND tenant_id = ?2";

/// The newest run of a repository at one commit, which is the run a shadow of that commit belongs to.
pub const RUN_AT_SHA_SQL: &str =
    "SELECT id FROM runs WHERE tenant_id = ?1 AND repo_id = ?2 AND source_sha = ?3
     ORDER BY created_ms DESC LIMIT 1";

/// One run's jobs: the phase stamps a native shadow's duration is measured between.
pub const RUN_JOBS_SQL: &str = "SELECT id, leased_ms, terminal_ms FROM jobs WHERE run_id = ?1";

/// One run's checks: what Sentinel published for a native shadow, and how the run's aggregate is
/// not a job.
pub const RUN_CHECKS_SQL: &str =
    "SELECT scope, name, conclusion FROM check_publications WHERE run_id = ?1";

/// One GitHub job as runner mode booked it: the class its labels named, its state, and the stamps
/// its deliveries set.
pub const RUNNER_JOB_SQL: &str =
    "SELECT class, state_code, conclusion, queued_ms, started_ms, completed_ms
     FROM runner_jobs WHERE tenant_id = ?1 AND repo_id = ?2 AND job_id = ?3";

/// One job pair to compare: the original GitHub job and Sentinel's copy of it, on one commit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pair<'a> {
    pub sha: &'a str,
    pub original: &'a str,
    pub shadow: &'a str,
}

/// What the Actions jobs page stated about one job.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Origin<'a> {
    pub sha: &'a str,
    pub job: &'a str,
    /// GitHub's job id, which is what names a runner-mode booking; `0` when the page stated none.
    pub job_id: u64,
    pub conclusion: Option<&'a str>,
    pub duration_ms: Option<u64>,
}

/// The test counts one side's report stated, keyed by the name that side is known by.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reported<'a> {
    pub sha: &'a str,
    pub job: &'a str,
    pub format: ReportFormat,
    pub counts: TestCounts,
}

/// Everything one report compares.
pub struct Input<'a> {
    pub pairs: &'a [Pair<'a>],
    pub origins: &'a [Origin<'a>],
    pub reports: &'a [Reported<'a>],
}

/// Test results of one side.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tests {
    /// The job stated no test results at all: not a report of zero tests.
    Unreported,
    Reported {
        format: ReportFormat,
        counts: TestCounts,
    },
}

impl Tests {
    pub const fn counts(self) -> Option<TestCounts> {
        match self {
            Self::Unreported => None,
            Self::Reported { counts, .. } => Some(counts),
        }
    }

    pub const fn format(self) -> Option<ReportFormat> {
        match self {
            Self::Unreported => None,
            Self::Reported { format, .. } => Some(format),
        }
    }
}

/// Where Sentinel's own record of a shadow comes from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// Sentinel ran the copy itself: the conclusion is the check it published and the duration is
    /// the job's own phase stamps.
    Native,
    /// GitHub handed the copy to one of Sentinel's runners: the conclusion and stamps are the
    /// `workflow_job` deliveries.
    Runner,
    /// The copy is a GitHub job Sentinel holds no record of; the page is all there is.
    Actions,
}

impl Mode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Native => "native",
            Self::Runner => "runner",
            Self::Actions => "actions",
        }
    }
}

/// One side of a pair.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Side {
    pub conclusion: Option<String>,
    pub duration_ms: Option<u64>,
    pub tests: Tests,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mismatch {
    /// The page stated nothing about the original: the pair cannot be compared.
    NoOriginal,
    /// Sentinel holds no copy of the job, and the page states none either.
    NoShadow,
    Conclusion,
    Tests,
    /// One or both sides stated no test results, so there is nothing to compare.
    TestsUnreported,
    Duration,
}

impl Mismatch {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NoOriginal => "no_original",
            Self::NoShadow => "no_shadow_run",
            Self::Conclusion => "conclusion",
            Self::Tests => "tests",
            Self::TestsUnreported => "tests_unreported",
            Self::Duration => "duration",
        }
    }
}

/// One pair, compared.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PairReport {
    pub sha: String,
    /// The original's name.
    pub job: String,
    /// The copy's name.
    pub shadow: String,
    pub mode: Option<Mode>,
    pub original: Option<Side>,
    pub shadow_side: Option<Side>,
    /// How long the copy waited for a runner, when the mode that ran it measured that.
    pub queue_ms: Option<u64>,
    pub mismatches: Vec<Mismatch>,
}

impl PairReport {
    pub fn matched(&self) -> bool {
        self.mismatches.is_empty()
    }
}

/// One job's distribution over the commits a report covers.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Spread {
    pub p50_ms: Option<u64>,
    pub p95_ms: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Aggregate {
    pub job: String,
    /// Pairs whose two sides both stated a duration: the sample count behind both spreads.
    pub samples: u32,
    pub matched: u32,
    pub mismatched: u32,
    pub original: Spread,
    pub shadow: Spread,
}

/// A copy Sentinel holds that the report's pairs do not name: listed, so a comparison can never be
/// narrowed to the pairs that suit it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Unpaired {
    pub sha: String,
    pub shadow: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Report {
    /// Sorted by commit, then by the original's name.
    pub pairs: Vec<PairReport>,
    /// One per job name, sorted by name.
    pub aggregates: Vec<Aggregate>,
    pub unpaired: Vec<Unpaired>,
}

/// What one run holds for the shadows of one commit.
#[derive(Default)]
struct RunFacts {
    /// A job's duration, by its id.
    jobs: HashMap<[u8; 16], Option<u64>>,
    /// A published check by its name: its conclusion, and the job its scope holds.
    checks: HashMap<String, (Option<String>, Option<[u8; 16]>)>,
}

/// A `runner_jobs` row as the parity read takes it: class, state, conclusion and its three stamps.
type BookingRow = (String, i64, Option<String>, i64, Option<i64>, Option<i64>);

struct Booking {
    conclusion: Option<String>,
    queue_ms: Option<u64>,
    duration_ms: Option<u64>,
}

/// Compare every pair of one page against what Sentinel holds, and report the copies no pair names.
///
/// `NotFound` when the repository is not this tenant's, `InvalidInput` for a commit id or a name the
/// report cannot hold, and `InvalidInput("pairs")` past [`MAX_PAIRS`].
pub fn report(
    conn: &Connection,
    tenant: TenantId,
    repo: RepoId,
    input: Input<'_>,
) -> Result<Report> {
    let owned: Option<i64> = conn
        .prepare_cached(REPO_SQL)?
        .query_row(params![repo.as_bytes(), tenant.as_bytes()], |row| {
            row.get(0)
        })
        .optional()?;
    if owned.is_none() {
        return Err(Error::NotFound);
    }
    if input.pairs.len() > MAX_PAIRS {
        return Err(Error::InvalidInput("pairs"));
    }
    let mut shas: Vec<&str> = Vec::new();
    for sha in input
        .pairs
        .iter()
        .map(|pair| pair.sha)
        .chain(input.origins.iter().map(|origin| origin.sha))
    {
        if !commit_id(sha) {
            return Err(Error::InvalidInput("commit"));
        }
        if !shas.contains(&sha) {
            if shas.len() == MAX_SHAS {
                return Err(Error::InvalidInput("commits"));
            }
            shas.push(sha);
        }
    }
    for pair in input.pairs {
        if !valid_name(pair.original) || !valid_name(pair.shadow) {
            return Err(Error::InvalidInput("job name"));
        }
    }
    let origins: HashMap<(&str, &str), &Origin<'_>> = input
        .origins
        .iter()
        .map(|origin| ((origin.sha, origin.job), origin))
        .collect();
    let reported: HashMap<(&str, &str), Reported<'_>> = input
        .reports
        .iter()
        .map(|report| ((report.sha, report.job), *report))
        .collect();
    let tests = |sha: &str, job: &str| match reported.get(&(sha, job)) {
        Some(report) => Tests::Reported {
            format: report.format,
            counts: report.counts,
        },
        None => Tests::Unreported,
    };

    let mut facts: HashMap<&str, Option<RunFacts>> = HashMap::with_capacity(shas.len());
    for sha in &shas {
        facts.insert(sha, run_facts(conn, tenant, repo, sha)?);
    }
    let mut bookings: HashMap<u64, Option<Booking>> = HashMap::new();

    let mut pairs = Vec::with_capacity(input.pairs.len());
    for pair in input.pairs {
        let original = origins.get(&(pair.sha, pair.original)).map(|origin| Side {
            conclusion: origin.conclusion.map(str::to_owned),
            duration_ms: origin.duration_ms,
            tests: tests(pair.sha, pair.original),
        });
        let mut queue_ms = None;
        let (mode, shadow_side) = match origins.get(&(pair.sha, pair.shadow)) {
            Some(origin) if origin.job_id > 0 => {
                let booking = match bookings.entry(origin.job_id) {
                    std::collections::hash_map::Entry::Occupied(entry) => entry.into_mut(),
                    std::collections::hash_map::Entry::Vacant(entry) => {
                        entry.insert(booking(conn, tenant, repo, origin.job_id)?)
                    }
                };
                match booking {
                    Some(booking) => {
                        queue_ms = booking.queue_ms;
                        (
                            Some(Mode::Runner),
                            Some(Side {
                                conclusion: booking.conclusion.clone(),
                                duration_ms: booking.duration_ms,
                                tests: tests(pair.sha, pair.shadow),
                            }),
                        )
                    }
                    None => (
                        Some(Mode::Actions),
                        Some(origin_side(origin, tests(pair.sha, pair.shadow))),
                    ),
                }
            }
            // A native shadow is Sentinel's own run of the commit, never a GitHub job of the page.
            _ => match facts.get(pair.sha).and_then(Option::as_ref) {
                Some(run) => match run.checks.get(pair.shadow) {
                    Some((conclusion, scope)) => (
                        Some(Mode::Native),
                        Some(Side {
                            conclusion: conclusion.clone(),
                            duration_ms: scope
                                .and_then(|scope| run.jobs.get(&scope).copied().flatten()),
                            tests: tests(pair.sha, pair.shadow),
                        }),
                    ),
                    None => match origins.get(&(pair.sha, pair.shadow)) {
                        Some(origin) => (
                            Some(Mode::Actions),
                            Some(origin_side(origin, tests(pair.sha, pair.shadow))),
                        ),
                        None => (None, None),
                    },
                },
                None => match origins.get(&(pair.sha, pair.shadow)) {
                    Some(origin) => (
                        Some(Mode::Actions),
                        Some(origin_side(origin, tests(pair.sha, pair.shadow))),
                    ),
                    None => (None, None),
                },
            },
        };
        let mismatches = compare(original.as_ref(), shadow_side.as_ref());
        pairs.push(PairReport {
            sha: pair.sha.to_owned(),
            job: pair.original.to_owned(),
            shadow: pair.shadow.to_owned(),
            mode,
            original,
            shadow_side,
            queue_ms,
            mismatches,
        });
    }
    pairs.sort_by(|a, b| (&a.sha, &a.job).cmp(&(&b.sha, &b.job)));

    let unpaired = unpaired(&shas, &facts, &pairs, &origins);
    let aggregates = aggregate(&pairs);
    Ok(Report {
        pairs,
        aggregates,
        unpaired,
    })
}

fn origin_side(origin: &Origin<'_>, tests: Tests) -> Side {
    Side {
        conclusion: origin.conclusion.map(str::to_owned),
        duration_ms: origin.duration_ms,
        tests,
    }
}

/// The copies Sentinel holds at these commits that no pair names. Both halves count: a check it
/// published for a native job, and a job of the page named as a copy.
fn unpaired(
    shas: &[&str],
    facts: &HashMap<&str, Option<RunFacts>>,
    pairs: &[PairReport],
    origins: &HashMap<(&str, &str), &Origin<'_>>,
) -> Vec<Unpaired> {
    let named: Vec<(&str, &str)> = pairs
        .iter()
        .map(|pair| (pair.sha.as_str(), pair.shadow.as_str()))
        .collect();
    let mut unpaired: Vec<Unpaired> = Vec::new();
    for sha in shas {
        let mut names: Vec<&str> = facts
            .get(sha)
            .and_then(Option::as_ref)
            .map(|run| {
                run.checks
                    .keys()
                    .map(String::as_str)
                    .filter(|name| {
                        name.starts_with(SHADOW_PREFIX) && name.len() > SHADOW_PREFIX.len()
                    })
                    .collect()
            })
            .unwrap_or_default();
        names.extend(
            origins
                .values()
                .filter(|origin| {
                    origin.sha == *sha
                        && origin.job.starts_with(SHADOW_PREFIX)
                        && origin.job.len() > SHADOW_PREFIX.len()
                })
                .map(|origin| origin.job),
        );
        names.sort_unstable();
        names.dedup();
        for name in names {
            if !named.contains(&(*sha, name)) {
                unpaired.push(Unpaired {
                    sha: (*sha).to_owned(),
                    shadow: name.to_owned(),
                });
            }
        }
    }
    unpaired.sort_by(|a, b| (&a.sha, &a.shadow).cmp(&(&b.sha, &b.shadow)));
    unpaired
}

fn compare(original: Option<&Side>, shadow: Option<&Side>) -> Vec<Mismatch> {
    let (Some(original), Some(shadow)) = (original, shadow) else {
        return vec![if original.is_none() {
            Mismatch::NoOriginal
        } else {
            Mismatch::NoShadow
        }];
    };
    let mut mismatches = Vec::new();
    if original.conclusion != shadow.conclusion {
        mismatches.push(Mismatch::Conclusion);
    }
    match (original.tests.counts(), shadow.tests.counts()) {
        (Some(original), Some(shadow)) if original == shadow => {}
        (Some(_), Some(_)) => mismatches.push(Mismatch::Tests),
        _ => mismatches.push(Mismatch::TestsUnreported),
    }
    // A duration one side never stated is not one the pair agrees on: the gate compares measured
    // jobs, so an absentee is named rather than passing as equal.
    match (original.duration_ms, shadow.duration_ms) {
        (Some(original), Some(shadow)) if !duration_differs(original, shadow) => {}
        _ => mismatches.push(Mismatch::Duration),
    }
    mismatches
}

fn duration_differs(original_ms: u64, shadow_ms: u64) -> bool {
    shadow_ms.saturating_sub(original_ms) > DURATION_FLOOR_MS
        && shadow_ms > original_ms.saturating_mul(DURATION_RATIO)
}

fn aggregate(pairs: &[PairReport]) -> Vec<Aggregate> {
    let mut aggregates: Vec<Aggregate> = Vec::new();
    let mut originals: Vec<Vec<u64>> = Vec::new();
    let mut shadows: Vec<Vec<u64>> = Vec::new();
    for pair in pairs {
        let slot = match aggregates.iter().position(|a| a.job == pair.job) {
            Some(slot) => slot,
            None => {
                aggregates.push(Aggregate {
                    job: pair.job.clone(),
                    samples: 0,
                    matched: 0,
                    mismatched: 0,
                    original: Spread::default(),
                    shadow: Spread::default(),
                });
                originals.push(Vec::new());
                shadows.push(Vec::new());
                aggregates.len() - 1
            }
        };
        if pair.matched() {
            aggregates[slot].matched += 1;
        } else {
            aggregates[slot].mismatched += 1;
        }
        if let (Some(original), Some(shadow)) = (&pair.original, &pair.shadow_side)
            && let (Some(original_ms), Some(shadow_ms)) = (original.duration_ms, shadow.duration_ms)
        {
            originals[slot].push(original_ms);
            shadows[slot].push(shadow_ms);
            aggregates[slot].samples += 1;
        }
    }
    for (slot, aggregate) in aggregates.iter_mut().enumerate() {
        aggregate.original = spread(&mut originals[slot]);
        aggregate.shadow = spread(&mut shadows[slot]);
    }
    aggregates.sort_by(|a, b| a.job.cmp(&b.job));
    aggregates
}

/// Nearest-rank percentiles over the samples a report holds, so the count beside them is the whole
/// basis of the figure.
fn spread(values: &mut [u64]) -> Spread {
    if values.is_empty() {
        return Spread::default();
    }
    values.sort_unstable();
    Spread {
        p50_ms: Some(nearest_rank(values, 50)),
        p95_ms: Some(nearest_rank(values, 95)),
    }
}

fn nearest_rank(sorted: &[u64], percent: usize) -> u64 {
    let rank = (percent * sorted.len())
        .div_ceil(100)
        .clamp(1, sorted.len());
    sorted[rank - 1]
}

/// What one commit's run holds, read in three keyed probes: the newest run at the commit, its jobs'
/// phase stamps and its checks.
fn run_facts(
    conn: &Connection,
    tenant: TenantId,
    repo: RepoId,
    sha: &str,
) -> Result<Option<RunFacts>> {
    let run: Option<[u8; 16]> = conn
        .prepare_cached(RUN_AT_SHA_SQL)?
        .query_row(params![tenant.as_bytes(), repo.as_bytes(), sha], |row| {
            row.get(0)
        })
        .optional()?;
    let Some(run) = run else {
        return Ok(None);
    };
    let mut facts = RunFacts::default();
    let mut jobs = conn.prepare_cached(RUN_JOBS_SQL)?;
    let rows = jobs.query_map([run.as_slice()], |row| {
        Ok((
            row.get::<_, [u8; 16]>(0)?,
            row.get::<_, Option<i64>>(1)?,
            row.get::<_, Option<i64>>(2)?,
        ))
    })?;
    for row in rows {
        let (id, leased, terminal) = row?;
        facts.jobs.insert(
            id,
            leased
                .zip(terminal)
                .and_then(|(leased, terminal)| u64::try_from(terminal - leased).ok()),
        );
    }
    let mut checks = conn.prepare_cached(RUN_CHECKS_SQL)?;
    let rows = checks.query_map([run.as_slice()], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, Option<String>>(2)?,
        ))
    })?;
    for row in rows {
        let (scope, name, conclusion) = row?;
        if scope == checks::AGGREGATE_SCOPE {
            continue;
        }
        let job = scope.parse::<JobId>().ok().map(|job| *job.as_bytes());
        facts.checks.insert(name, (conclusion, job));
    }
    Ok(Some(facts))
}

fn booking(
    conn: &Connection,
    tenant: TenantId,
    repo: RepoId,
    job_id: u64,
) -> Result<Option<Booking>> {
    let job_id = i64::try_from(job_id).map_err(|_| Error::InvalidInput("job"))?;
    let row: Option<BookingRow> = conn
        .prepare_cached(RUNNER_JOB_SQL)?
        .query_row(params![tenant.as_bytes(), repo.as_bytes(), job_id], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
            ))
        })
        .optional()?;
    let Some((_class, state, conclusion, queued_ms, started_ms, completed_ms)) = row else {
        return Ok(None);
    };
    Ok(Some(Booking {
        // A job that has not completed states no conclusion, whatever a delivery wrote meanwhile.
        conclusion: if state == 2 { conclusion } else { None },
        queue_ms: started_ms.and_then(|started| u64::try_from(started - queued_ms).ok()),
        duration_ms: started_ms
            .zip(completed_ms)
            .and_then(|(started, completed)| u64::try_from(completed - started).ok()),
    }))
}

fn commit_id(text: &str) -> bool {
    (text.len() == 40 || text.len() == 64)
        && text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn valid_name(name: &str) -> bool {
    !name.is_empty() && name.len() <= MAX_NAME && !name.chars().any(char::is_control)
}
