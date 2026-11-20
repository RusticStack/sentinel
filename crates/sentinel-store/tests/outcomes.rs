//! Per-test outcomes: the identity a repository's flaky list is keyed on, the fail-then-pass rule, the
//! per-repository row cap and the expiry that matches the logs' own.

use sentinel_core::{
    AttemptId, JobId, RepoId, RunId, TenantId, UnixMillis, UserId,
    auth::{Namespace, Permissions as P, Principal},
};
use sentinel_store::{
    Durability, Store,
    auth::{self, NamespaceKind, provisioning},
    jobs,
    outcomes::{self, Attempt, MAX_ROWS_PER_REPO, Outcome, Status},
};

const NOW: UnixMillis = UnixMillis(1_000_000_000);
const DAY_MS: i64 = 24 * 3_600_000;

struct Fixture {
    _dir: tempfile::TempDir,
    store: Store,
    tenant: TenantId,
    app: RepoId,
    other: RepoId,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path().join("metadata.sqlite"), Durability::Normal).unwrap();
    let (root, tenant, app, other) = (UserId::new(), TenantId::new(), RepoId::new(), RepoId::new());
    store
        .writer()
        .write(move |tx| {
            provisioning::insert_human(tx, root, "Root", true, NOW)?;
            auth::create_namespace(
                tx,
                Principal::new(root, P::ALL, None, None),
                tenant,
                Namespace::parse("acme").unwrap(),
                NamespaceKind::Organization,
                NOW,
            )?;
            jobs::insert_repo(tx, tenant, app, "app", NOW)?;
            jobs::insert_repo(tx, tenant, other, "other", NOW)
        })
        .unwrap();
    Fixture {
        _dir: dir,
        store,
        tenant,
        app,
        other,
    }
}

/// One run of one job holding one attempt, and the outcome rows that attempt stated.
fn attempt(
    f: &Fixture,
    repo: RepoId,
    sha: &str,
    at_ms: i64,
    outcomes: &[(&str, Status)],
) -> AttemptId {
    let (tenant, run, job, attempt) = (f.tenant, RunId::new(), JobId::new(), AttemptId::new());
    let rows: Vec<(String, Status)> = outcomes
        .iter()
        .map(|(identity, status)| ((*identity).to_owned(), *status))
        .collect();
    let sha = sha.to_owned();
    f.store
        .writer()
        .write(move |tx| {
            tx.execute(
                "INSERT INTO runs(id, tenant_id, repo_id, source_sha, created_ms) VALUES (?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![run.as_bytes(), tenant.as_bytes(), repo.as_bytes(), sha, at_ms],
            )?;
            tx.execute(
                "INSERT INTO jobs(id, tenant_id, run_id, name, state_code, priority, created_seq, repo_id, spec_index)
                 VALUES (?1, ?2, ?3, 'test', 3, 5, 0, ?4, 0)",
                rusqlite::params![job.as_bytes(), tenant.as_bytes(), run.as_bytes(), repo.as_bytes()],
            )?;
            tx.execute(
                "INSERT INTO attempts(id, tenant_id, job_id, fence, worker_id, lease_until_ms, repo_id)
                 VALUES (?1, ?2, ?3, 1, ?4, 0, ?5)",
                rusqlite::params![
                    attempt.as_bytes(),
                    tenant.as_bytes(),
                    job.as_bytes(),
                    [7u8; 16],
                    repo.as_bytes()
                ],
            )?;
            outcomes::enqueue(tx, attempt)?;
            let parsed: Vec<Outcome<'_>> = rows
                .iter()
                .map(|(identity, status)| {
                    let (suite, name) = identity
                        .split_once("::")
                        .map_or((None, identity.as_str()), |(suite, name)| {
                            (Some(suite), name)
                        });
                    Outcome {
                        identity,
                        suite,
                        name,
                        status: *status,
                    }
                })
                .collect();
            outcomes::ingest(
                tx,
                &Attempt {
                    tenant,
                    repo,
                    attempt,
                    sha: &sha,
                },
                at_ms,
                &parsed,
            )?;
            Ok(())
        })
        .unwrap();
    attempt
}

fn flakes(f: &Fixture, repo: RepoId, since_ms: i64) -> outcomes::Flakes {
    f.store
        .read(|c| outcomes::flakes(c, f.tenant, repo, since_ms, outcomes::DEFAULT_TESTS))
        .unwrap()
}

#[test]
fn a_fail_then_pass_on_the_same_commit_is_the_flake_and_a_pass_elsewhere_is_not() {
    let f = fixture();
    let (sha_a, sha_b) = ("a".repeat(40), "b".repeat(40));
    // SHA A: fail, then pass on a rerun of the same commit, then pass again: one flake, not two.
    attempt(&f, f.app, &sha_a, NOW.0, &[("pkg::TestA", Status::Failed)]);
    attempt(
        &f,
        f.app,
        &sha_a,
        NOW.0 + 1,
        &[("pkg::TestA", Status::Passed)],
    );
    attempt(
        &f,
        f.app,
        &sha_a,
        NOW.0 + 2,
        &[("pkg::TestA", Status::Passed)],
    );
    // SHA B: failed once and never rerun on that commit. A pass here would not be a flake either.
    attempt(
        &f,
        f.app,
        &sha_b,
        NOW.0 + 3,
        &[("pkg::TestA", Status::Failed)],
    );

    let report = flakes(&f, f.app, 0);
    assert_eq!(report.rows, 4);
    assert_eq!(report.broken, 0);
    let test = &report.tests[0];
    assert_eq!(test.identity, "pkg::TestA");
    assert_eq!((test.attempts, test.failed, test.passed), (4, 2, 2));
    assert_eq!(test.commits, 2, "two commits, one of them flaked");
    assert_eq!(test.flakes, 1);
    assert_eq!(test.rate_bps(), 5_000);
    assert_eq!(test.last_failed_ms, Some(NOW.0 + 3));
    assert_eq!(report.oldest_ms, Some(NOW.0));
    assert_eq!(report.newest_ms, Some(NOW.0 + 3));

    // The same failure on a different commit, and a pass on yet another commit, are not a flake: the
    // first attempt fails on C, the later one passes on D.
    let sha_c = "c".repeat(40);
    attempt(
        &f,
        f.other,
        &sha_a,
        NOW.0,
        &[("pkg::TestB", Status::Failed)],
    );
    attempt(
        &f,
        f.other,
        &sha_c,
        NOW.0 + 1,
        &[("pkg::TestB", Status::Passed)],
    );
    assert!(
        flakes(&f, f.other, 0).tests.is_empty(),
        "a pass at another commit is not a rerun of the failed one"
    );
}

#[test]
fn a_test_that_failed_on_every_attempt_is_broken_and_never_listed() {
    let f = fixture();
    let sha = "a".repeat(40);
    attempt(&f, f.app, &sha, NOW.0, &[("pkg::TestA", Status::Failed)]);
    attempt(
        &f,
        f.app,
        &sha,
        NOW.0 + 1,
        &[("pkg::TestA", Status::Failed)],
    );
    let report = flakes(&f, f.app, 0);
    assert!(report.tests.is_empty());
    assert_eq!(report.broken, 1);
}

#[test]
fn a_pass_before_the_failure_on_one_commit_is_not_a_flake() {
    let f = fixture();
    let sha = "a".repeat(40);
    attempt(&f, f.app, &sha, NOW.0, &[("pkg::TestA", Status::Passed)]);
    attempt(
        &f,
        f.app,
        &sha,
        NOW.0 + 1,
        &[("pkg::TestA", Status::Failed)],
    );
    let report = flakes(&f, f.app, 0);
    assert!(report.tests.is_empty(), "{report:?}");
    assert_eq!(report.broken, 0, "it did pass, just not after the failure");
}

#[test]
fn the_window_bounds_the_report_and_a_skipped_attempt_is_not_a_pass() {
    let f = fixture();
    let sha = "a".repeat(40);
    attempt(&f, f.app, &sha, NOW.0, &[("pkg::TestA", Status::Failed)]);
    attempt(
        &f,
        f.app,
        &sha,
        NOW.0 + 1,
        &[("pkg::TestA", Status::Skipped)],
    );
    assert!(
        flakes(&f, f.app, 0).tests.is_empty(),
        "a skip never proves a pass"
    );
    attempt(
        &f,
        f.app,
        &sha,
        NOW.0 + 1 + DAY_MS,
        &[("pkg::TestA", Status::Passed)],
    );
    assert_eq!(flakes(&f, f.app, 0).tests[0].flakes, 1);
    // A window that starts after the failure sees only the pass, so nothing flaked inside it.
    let late = flakes(&f, f.app, NOW.0 + 1);
    assert!(late.tests.is_empty());
    assert_eq!(late.rows, 2);
}

#[test]
fn outcomes_are_capped_per_repository_and_another_reports_rows_are_untouched() {
    let f = fixture();
    let sha = "a".repeat(40);
    // One row of the other repository, which the app's writes must never evict.
    attempt(&f, f.other, &sha, NOW.0, &[("pkg::TestB", Status::Failed)]);
    let half = (MAX_ROWS_PER_REPO / 2) as usize;
    let first: Vec<(String, Status)> = (0..half)
        .map(|i| (format!("pkg::Other{i}"), Status::Passed))
        .collect();
    let first_refs: Vec<(&str, Status)> = first
        .iter()
        .map(|(identity, status)| (identity.as_str(), *status))
        .collect();
    attempt(&f, f.app, &sha, NOW.0, &first_refs);
    attempt(&f, f.app, &sha, NOW.0 + 1, &first_refs);
    // More than the cap: the app's oldest rows go first and no more than the cap remains.
    let extra: Vec<(String, Status)> = (0..=half)
        .map(|i| (format!("pkg::Extra{i}"), Status::Failed))
        .collect();
    let extra_refs: Vec<(&str, Status)> = extra
        .iter()
        .map(|(identity, status)| (identity.as_str(), *status))
        .collect();
    attempt(&f, f.app, &sha, NOW.0 + 2, &extra_refs);

    let (app, other) = f
        .store
        .read(|c| {
            let count = |repo: RepoId| -> Result<i64, rusqlite::Error> {
                c.query_row(
                    "SELECT COUNT(*) FROM test_outcomes WHERE tenant_id = ?1 AND repo_id = ?2",
                    rusqlite::params![f.tenant.as_bytes(), repo.as_bytes()],
                    |r| r.get(0),
                )
            };
            Ok((count(f.app)?, count(f.other)?))
        })
        .unwrap();
    assert_eq!(app as u64, MAX_ROWS_PER_REPO);
    assert_eq!(other, 1, "the other repository keeps its own row");
    let oldest = f
        .store
        .read(|c| {
            Ok(c.query_row(
                "SELECT COUNT(*) FROM test_outcomes WHERE tenant_id = ?1 AND repo_id = ?2 AND at_ms = ?3",
                rusqlite::params![f.tenant.as_bytes(), f.app.as_bytes(), NOW.0],
                |r| r.get::<_, i64>(0),
            )?)
        })
        .unwrap();
    assert_eq!(oldest, 0, "the repository's own oldest rows went first");
}

#[test]
fn the_window_scan_is_keyed_and_expiry_takes_the_rows_with_the_queue() {
    let f = fixture();
    let sha = "a".repeat(40);
    attempt(&f, f.app, &sha, NOW.0, &[("pkg::TestA", Status::Failed)]);
    let plan: Vec<String> = f
        .store
        .read(|c| {
            let mut stmt = c.prepare(&format!("EXPLAIN QUERY PLAN {}", outcomes::SCAN_SQL))?;
            let rows = stmt
                .query_map(
                    rusqlite::params![f.tenant.as_bytes(), f.app.as_bytes(), 0i64, 10i64],
                    |r| r.get::<_, String>(3),
                )?
                .collect::<Result<Vec<_>, _>>()?;
            Ok(rows)
        })
        .unwrap();
    assert!(
        plan.iter()
            .any(|line| line.contains("test_outcomes_by_test")),
        "{plan:?}"
    );

    // A queue row the reader never reached (a crashed pass): expiry takes it with the rows it would have
    // produced, so the queue cannot hold an attempt the outcomes no longer cover.
    let unread = AttemptId::new();
    f.store
        .writer()
        .write(move |tx| outcomes::enqueue(tx, unread))
        .unwrap();
    // The queue's stamp is the wall clock, so the boundary that reaches it is a wall-clock one too.
    let before = UnixMillis::now().0 + 1;
    let removed = f
        .store
        .writer()
        .write(move |tx| outcomes::expire(tx, before, 100))
        .unwrap();
    assert_eq!(removed, 2, "the row and the unread queue entry");
    let queued = f.store.read(|c| outcomes::queued(c, 8)).unwrap();
    assert!(queued.is_empty());
}

#[test]
fn a_finished_attempt_is_queued_once_with_the_run_and_commit_it_names() {
    let f = fixture();
    let sha = "a".repeat(40);
    let (tenant, run, job, attempt, repo) = (
        f.tenant,
        RunId::new(),
        JobId::new(),
        AttemptId::new(),
        f.app,
    );
    let owned = sha.clone();
    f.store
        .writer()
        .write(move |tx| {
            tx.execute(
                "INSERT INTO runs(id, tenant_id, repo_id, source_sha, created_ms) VALUES (?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![run.as_bytes(), tenant.as_bytes(), repo.as_bytes(), owned, NOW.0],
            )?;
            tx.execute(
                "INSERT INTO jobs(id, tenant_id, run_id, name, state_code, priority, created_seq, repo_id, spec_index)
                 VALUES (?1, ?2, ?3, 'test', 3, 5, 0, ?4, 0)",
                rusqlite::params![job.as_bytes(), tenant.as_bytes(), run.as_bytes(), repo.as_bytes()],
            )?;
            tx.execute(
                "INSERT INTO attempts(id, tenant_id, job_id, fence, worker_id, lease_until_ms, repo_id)
                 VALUES (?1, ?2, ?3, 1, ?4, 0, ?5)",
                rusqlite::params![
                    attempt.as_bytes(),
                    tenant.as_bytes(),
                    job.as_bytes(),
                    [7u8; 16],
                    repo.as_bytes()
                ],
            )?;
            outcomes::enqueue(tx, attempt)?;
            outcomes::enqueue(tx, attempt)?;
            Ok(())
        })
        .unwrap();
    let queued = f.store.read(|c| outcomes::queued(c, 8)).unwrap();
    assert_eq!(queued.len(), 1, "a repeated enqueue is one row");
    assert_eq!(queued[0].0.attempt, attempt);
    assert_eq!(
        (queued[0].0.run, queued[0].0.job, queued[0].0.repo),
        (run, job, f.app)
    );
    assert_eq!(queued[0].1, sha);
}
