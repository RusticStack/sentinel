//! What each named test did, attempt by attempt, and the flake a rerun of the same commit proves.
//!
//! A job's captured JUnit XML or Go test JSON states one terminal outcome per test; the controller reads
//! it once, when the attempt finishes, and writes what it found here. The list is deterministic: a test is
//! flaky when it failed on one attempt and passed on a later attempt of the **same** commit, so two
//! failures of the same commit are a broken test and a pass on a different commit says nothing.
//!
//! Everything is keyed. Writing is bounded per repository, oldest first, so one large repository evicts
//! its own oldest rows and never the rows of another; the queue of unread attempts is one row per finished
//! attempt and leaves with the outcomes it produced; a report reads one repository's window through
//! `test_outcomes_by_repo` and expiry walks `test_outcomes_by_age`, so no statement scans anything else.

use rusqlite::{Connection, Transaction, params};
use sentinel_core::{AttemptId, JobId, RepoId, RunId, TenantId};

use crate::Result;

/// A repository's rows. Past this the oldest are evicted on write, so the memory the flaky list reads is a
/// repository's recent history rather than everything it ever ran.
pub const MAX_ROWS_PER_REPO: u64 = 100_000;
/// Rows one report reads: the ceiling is the per-repository cap times the number of repositories a request
/// names, which is one, so a report is bounded by the same figure as the table.
pub const MAX_SCAN_ROWS: u64 = MAX_ROWS_PER_REPO;
/// Tests one report lists, and the default.
pub const MAX_TESTS: usize = 200;
pub const DEFAULT_TESTS: usize = 20;
/// Unread attempts one round handles; the pass repeats while it finds a full batch.
pub const MAX_QUEUE_BATCH: u32 = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    Passed,
    Failed,
    Skipped,
}

impl Status {
    pub const fn code(self) -> i64 {
        match self {
            Self::Passed => 0,
            Self::Failed => 1,
            Self::Skipped => 2,
        }
    }

    pub fn from_code(code: i64) -> Result<Self> {
        match code {
            0 => Ok(Self::Passed),
            1 => Ok(Self::Failed),
            2 => Ok(Self::Skipped),
            _ => Err(crate::Error::Corrupt("test outcome status")),
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Passed => "passed",
            Self::Failed => "failed",
            Self::Skipped => "skipped",
        }
    }
}

/// One test's outcome in one report, as the parser normalised it.
pub struct Outcome<'a> {
    pub identity: &'a str,
    pub suite: Option<&'a str>,
    pub name: &'a str,
    pub status: Status,
}

/// The attempt, repository and commit a report's outcomes belong to.
pub struct Attempt<'a> {
    pub tenant: TenantId,
    pub repo: RepoId,
    pub attempt: AttemptId,
    pub sha: &'a str,
}

/// A finished attempt whose reports have not been read: the job and run name the log and the artifacts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Queued {
    pub attempt: AttemptId,
    pub tenant: TenantId,
    pub repo: RepoId,
    pub run: RunId,
    pub job: JobId,
    /// The commit the attempt ran, which is the whole of what makes a rerun comparable.
    pub at_ms: i64,
}

/// One finished attempt, joined to the run it belongs to.
pub const QUEUED_SQL: &str =
    "SELECT q.attempt_id, j.tenant_id, r.repo_id, r.id, j.id, r.created_ms,
        r.source_sha
    FROM test_outcome_queue q
    JOIN attempts a ON a.id = q.attempt_id
    JOIN jobs j ON j.id = a.job_id
    JOIN runs r ON r.id = j.run_id
    ORDER BY q.queued_ms, q.attempt_id
    LIMIT ?1";

/// The oldest queued attempts, with the run and commit each ran.
pub fn queued(conn: &Connection, limit: u32) -> Result<Vec<(Queued, String)>> {
    let mut stmt = conn.prepare_cached(QUEUED_SQL)?;
    let mut rows = stmt.query([i64::from(limit.clamp(1, MAX_QUEUE_BATCH))])?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        let attempt: [u8; 16] = row.get(0)?;
        let tenant: [u8; 16] = row.get(1)?;
        let repo: [u8; 16] = row.get(2)?;
        let run: [u8; 16] = row.get(3)?;
        let job: [u8; 16] = row.get(4)?;
        out.push((
            Queued {
                attempt: AttemptId::from_bytes(attempt)
                    .map_err(|_| crate::Error::Corrupt("attempt_id"))?,
                tenant: TenantId::from_bytes(tenant)
                    .map_err(|_| crate::Error::Corrupt("tenant_id"))?,
                repo: RepoId::from_bytes(repo).map_err(|_| crate::Error::Corrupt("repo_id"))?,
                run: RunId::from_bytes(run).map_err(|_| crate::Error::Corrupt("run_id"))?,
                job: JobId::from_bytes(job).map_err(|_| crate::Error::Corrupt("job_id"))?,
                at_ms: row.get(5)?,
            },
            row.get(6)?,
        ));
    }
    Ok(out)
}

/// Queue one finished attempt for the reader. Written in the attempt's own terminal transaction, so an
/// attempt whose summary committed is never lost to a restart between the report and the pass. Its stamp is
/// the wall clock, the same clock the retention window is measured on: the attempt's own report carried the
/// monotonic one, which says nothing about when a row should expire.
pub fn enqueue(tx: &Transaction<'_>, attempt: AttemptId) -> Result<()> {
    tx.prepare_cached(
        "INSERT INTO test_outcome_queue(attempt_id, queued_ms) VALUES (?1, ?2)
         ON CONFLICT(attempt_id) DO NOTHING",
    )?
    .execute(params![
        attempt.as_bytes(),
        sentinel_core::UnixMillis::now().0
    ])?;
    Ok(())
}

const COUNT_SQL: &str = "SELECT COUNT(*) FROM test_outcomes WHERE tenant_id = ?1 AND repo_id = ?2";

/// Eviction and expiry name the row by its own key: the table is `WITHOUT ROWID`, so there is no rowid to
/// delete by and the primary key is what the table holds.
const EVICT_SQL: &str = "DELETE FROM test_outcomes WHERE (attempt_id, identity) IN (
    SELECT t.attempt_id, t.identity FROM test_outcomes t
    WHERE t.tenant_id = ?1 AND t.repo_id = ?2 ORDER BY t.at_ms, t.attempt_id LIMIT ?3)";

const INSERT_SQL: &str = "INSERT INTO test_outcomes(
        tenant_id, repo_id, attempt_id, sha, identity, suite, name, status, at_ms)
    VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
    ON CONFLICT(attempt_id, identity) DO UPDATE SET
        status = excluded.status, suite = excluded.suite, name = excluded.name";

/// Write one attempt's outcomes and take its queue row in the same transaction. The repository's oldest
/// rows are evicted first when the insert would pass [`MAX_ROWS_PER_REPO`], so a repository that runs
/// hundreds of thousands of tests keeps its recent history and no other repository's rows move.
pub fn ingest(
    tx: &Transaction<'_>,
    attempt: &Attempt<'_>,
    at_ms: i64,
    outcomes: &[Outcome<'_>],
) -> Result<u32> {
    let kept = u32::try_from(outcomes.len().min(i64::MAX as usize)).unwrap_or(u32::MAX);
    if !outcomes.is_empty() {
        let held: i64 = tx.prepare_cached(COUNT_SQL)?.query_row(
            params![attempt.tenant.as_bytes(), attempt.repo.as_bytes()],
            |r| r.get(0),
        )?;
        let excess = u64::try_from(held)
            .unwrap_or(0)
            .saturating_add(u64::from(kept))
            .saturating_sub(MAX_ROWS_PER_REPO);
        if excess > 0 {
            tx.prepare_cached(EVICT_SQL)?.execute(params![
                attempt.tenant.as_bytes(),
                attempt.repo.as_bytes(),
                i64::try_from(excess).unwrap_or(i64::MAX)
            ])?;
        }
        let mut insert = tx.prepare_cached(INSERT_SQL)?;
        for outcome in outcomes {
            insert.execute(params![
                attempt.tenant.as_bytes(),
                attempt.repo.as_bytes(),
                attempt.attempt.as_bytes(),
                attempt.sha,
                outcome.identity,
                outcome.suite,
                outcome.name,
                outcome.status.code(),
                at_ms
            ])?;
        }
    }
    tx.prepare_cached("DELETE FROM test_outcome_queue WHERE attempt_id = ?1")?
        .execute([attempt.attempt.as_bytes()])?;
    Ok(kept)
}

/// Drop rows older than `before_ms`, in batches so one pass never holds the writer for a whole window.
pub fn expire(conn: &Connection, before_ms: i64, batch: u32) -> Result<usize> {
    let removed = conn
        .prepare_cached(
            "DELETE FROM test_outcomes WHERE (attempt_id, identity) IN (
                 SELECT attempt_id, identity FROM test_outcomes WHERE at_ms < ?1 LIMIT ?2)",
        )?
        .execute(params![before_ms, i64::from(batch.clamp(1, 10_000))])?;
    let queued = conn
        .prepare_cached(
            "DELETE FROM test_outcome_queue WHERE attempt_id IN (
                 SELECT attempt_id FROM test_outcome_queue WHERE queued_ms < ?1 LIMIT ?2)",
        )?
        .execute(params![before_ms, i64::from(batch.clamp(1, 10_000))])?;
    Ok(removed + queued)
}

/// One test over the window.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Flake {
    pub identity: String,
    pub suite: Option<String>,
    pub name: String,
    /// Attempts the test appeared in.
    pub attempts: u32,
    pub failed: u32,
    pub passed: u32,
    pub skipped: u32,
    /// Commits the test ran in: what its flake rate is a share of.
    pub commits: u32,
    /// Commits where it failed and then passed on a later attempt of that same commit.
    pub flakes: u32,
    /// When it last failed, or absent when it never did.
    pub last_failed_ms: Option<i64>,
}

impl Flake {
    /// Flakes per 10,000 commits the test ran in: an integer the API and the page both state exactly.
    pub fn rate_bps(&self) -> u32 {
        if self.commits == 0 {
            return 0;
        }
        u32::try_from(u64::from(self.flakes) * 10_000 / u64::from(self.commits)).unwrap_or(u32::MAX)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Flakes {
    pub tests: Vec<Flake>,
    /// Rows the window held.
    pub rows: u64,
    pub oldest_ms: Option<i64>,
    pub newest_ms: Option<i64>,
    /// Tests that failed on every attempt of the window: broken, not flaky, and never listed.
    pub broken: u32,
    /// The scan stopped at [`MAX_SCAN_ROWS`]: the figures cover the rows read.
    pub truncated: bool,
}

/// The window in identity and commit order, which `test_outcomes_by_test` answers directly: the plan is
/// pinned so a later index cannot quietly turn this read into a sort of every row the repository holds.
pub const SCAN_SQL: &str = "SELECT identity, suite, name, sha, status, at_ms
    FROM test_outcomes INDEXED BY test_outcomes_by_test
    WHERE tenant_id = ?1 AND repo_id = ?2 AND at_ms >= ?3
    ORDER BY identity, sha, at_ms
    LIMIT ?4";

#[derive(Default)]
struct Totals {
    attempts: u32,
    failed: u32,
    passed: u32,
    skipped: u32,
    commits: u32,
    flakes: u32,
    last_failed_ms: Option<i64>,
}

/// What one commit of one test showed: a failure before a pass is the flake, whatever follows it.
#[derive(Default)]
struct Commit {
    failed: bool,
    flaked: bool,
}

impl Totals {
    fn flush(&mut self, commit: &Commit) {
        self.commits = self.commits.saturating_add(1);
        if commit.flaked {
            self.flakes = self.flakes.saturating_add(1);
        }
    }
}

/// The flaky tests of one repository over the window that starts at `since_ms`, worst first. A test is
/// flaky for a commit when an attempt of that commit failed and a later attempt of the same commit passed;
/// a failure on another commit, or after the pass, is not a flake, and a test that failed on every attempt
/// is broken rather than flaky. `rows` is ordered by identity and commit, so each group is contiguous and
/// the scan holds one group at a time.
pub fn flakes(
    conn: &Connection,
    tenant: TenantId,
    repo: RepoId,
    since_ms: i64,
    limit: usize,
) -> Result<Flakes> {
    let mut stmt = conn.prepare_cached(SCAN_SQL)?;
    let mut rows = stmt.query(params![
        tenant.as_bytes(),
        repo.as_bytes(),
        since_ms,
        i64::try_from(MAX_SCAN_ROWS).unwrap_or(i64::MAX)
    ])?;
    let mut tests: Vec<Flake> = Vec::new();
    let mut current: Option<(String, Option<String>, String, Totals)> = None;
    let mut commit_sha = String::new();
    let mut commit = Commit::default();
    let (mut read, mut oldest, mut newest) = (0u64, None::<i64>, None::<i64>);
    while let Some(row) = rows.next()? {
        if read == MAX_SCAN_ROWS {
            break;
        }
        read += 1;
        let at_ms: i64 = row.get(5)?;
        oldest = Some(oldest.map_or(at_ms, |held| held.min(at_ms)));
        newest = Some(newest.map_or(at_ms, |held| held.max(at_ms)));
        let identity: &str = row
            .get_ref(0)?
            .as_str()
            .map_err(|_| crate::Error::Corrupt("test identity"))?;
        let sha: &str = row
            .get_ref(3)?
            .as_str()
            .map_err(|_| crate::Error::Corrupt("source sha"))?;
        if current
            .as_ref()
            .is_none_or(|(held, ..)| held.as_str() != identity)
        {
            if let Some((identity, suite, name, mut totals)) = current.take() {
                totals.flush(&commit);
                tests.push(finish(identity, suite, name, totals));
            }
            commit = Commit::default();
            commit_sha.clear();
            current = Some((
                identity.to_owned(),
                row.get(1)?,
                row.get(2)?,
                Totals::default(),
            ));
        } else if commit_sha != sha {
            if let Some((_, _, _, totals)) = current.as_mut() {
                totals.flush(&commit);
            }
            commit = Commit::default();
        }
        commit_sha.clear();
        commit_sha.push_str(sha);
        let Some((_, _, _, totals)) = current.as_mut() else {
            continue;
        };
        totals.attempts = totals.attempts.saturating_add(1);
        match Status::from_code(row.get(4)?)? {
            Status::Failed => {
                totals.failed = totals.failed.saturating_add(1);
                totals.last_failed_ms =
                    Some(totals.last_failed_ms.map_or(at_ms, |held| held.max(at_ms)));
                commit.failed = true;
            }
            Status::Passed => {
                totals.passed = totals.passed.saturating_add(1);
                if commit.failed {
                    commit.flaked = true;
                }
            }
            Status::Skipped => totals.skipped = totals.skipped.saturating_add(1),
        }
    }
    if let Some((identity, suite, name, mut totals)) = current.take() {
        totals.flush(&commit);
        tests.push(finish(identity, suite, name, totals));
    }
    let truncated = read == MAX_SCAN_ROWS && rows.next()?.is_some();
    let broken = tests
        .iter()
        .filter(|test| test.failed > 0 && test.passed == 0)
        .count();
    let mut flaky: Vec<Flake> = tests.into_iter().filter(|test| test.flakes > 0).collect();
    flaky.sort_unstable_by(|a, b| {
        b.flakes
            .cmp(&a.flakes)
            .then(a.commits.cmp(&b.commits))
            .then(a.identity.cmp(&b.identity))
    });
    flaky.truncate(limit.clamp(1, MAX_TESTS));
    Ok(Flakes {
        tests: flaky,
        rows: read,
        oldest_ms: oldest,
        newest_ms: newest,
        broken: u32::try_from(broken).unwrap_or(u32::MAX),
        truncated,
    })
}

fn finish(identity: String, suite: Option<String>, name: String, totals: Totals) -> Flake {
    Flake {
        identity,
        suite,
        name,
        attempts: totals.attempts,
        failed: totals.failed,
        passed: totals.passed,
        skipped: totals.skipped,
        commits: totals.commits,
        flakes: totals.flakes,
        last_failed_ms: totals.last_failed_ms,
    }
}
