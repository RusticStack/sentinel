//! Shadow parity: each job pair compared at the commit both ran, with the numbers behind every
//! verdict — and the pairs that cannot be compared named rather than passed over.

use rusqlite::Connection;
use sentinel_core::{JobId, RepoId, RunId, TenantId};
use sentinel_protocol::diagnostics::{ReportFormat, TestCounts};
use sentinel_store::{
    Error, checks,
    parity::{self, Input, Mismatch, Mode, Origin, Pair, Reported, Tests},
};

const SHA_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const SHA_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const SHA_C: &str = "cccccccccccccccccccccccccccccccccccccccc";
const SHA_D: &str = "dddddddddddddddddddddddddddddddddddddddd";

struct Fixture {
    conn: Connection,
    tenant: TenantId,
    repo: RepoId,
    /// A repository of another tenant: the reads answer for one tenant's rows only.
    stranger: RepoId,
}

fn fixture() -> Fixture {
    let mut conn = Connection::open_in_memory().unwrap();
    conn.execute_batch("PRAGMA foreign_keys=ON").unwrap();
    sentinel_store::migrate(&mut conn).unwrap();
    let (tenant, repo) = (TenantId::new(), RepoId::new());
    let (stranger, stranger_repo) = (TenantId::new(), RepoId::new());
    conn.execute(
        "INSERT INTO tenants(id, slug, created_ms) VALUES(?1, 'acme', 1000)",
        [tenant.as_bytes()],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO tenants(id, slug, created_ms) VALUES(?1, 'stranger', 1000)",
        [stranger.as_bytes()],
    )
    .unwrap();
    for (id, tenant, name) in [(repo, tenant, "app"), (stranger_repo, stranger, "theirs")] {
        conn.execute(
            "INSERT INTO repos(id, tenant_id, name, created_ms) VALUES(?1, ?2, ?3, 1000)",
            (id.as_bytes(), tenant.as_bytes(), name),
        )
        .unwrap();
    }
    Fixture {
        conn,
        tenant,
        repo,
        stranger: stranger_repo,
    }
}

/// One run of the fixture's repository at a commit.
fn run(f: &Fixture, sha: &str, created_ms: i64) -> RunId {
    let run = RunId::new();
    f.conn
        .execute(
            "INSERT INTO runs(id, tenant_id, repo_id, source_sha, created_ms)
             VALUES(?1, ?2, ?3, ?4, ?5)",
            (
                run.as_bytes(),
                f.tenant.as_bytes(),
                f.repo.as_bytes(),
                sha,
                created_ms,
            ),
        )
        .unwrap();
    run
}

/// One job of a run whose lease and terminal transition are what its duration is.
fn job(
    f: &Fixture,
    run: RunId,
    name: &str,
    leased_ms: Option<i64>,
    terminal_ms: Option<i64>,
) -> JobId {
    let job = JobId::new();
    f.conn
        .execute(
            "INSERT INTO jobs(id, tenant_id, run_id, name, state_code, priority, created_seq, repo_id,
                              spec_index, leased_ms, terminal_ms)
             VALUES(?1, ?2, ?3, ?4, 6, 0, 0, ?5, 0, ?6, ?7)",
            (
                job.as_bytes(),
                f.tenant.as_bytes(),
                run.as_bytes(),
                name,
                f.repo.as_bytes(),
                leased_ms,
                terminal_ms,
            ),
        )
        .unwrap();
    job
}

/// The check Sentinel published for one of a run's jobs, which is the native shadow's record.
fn check(f: &Fixture, run: RunId, sha: &str, job: JobId, job_name: &str, conclusion: Option<&str>) {
    let scope = job.to_string();
    f.conn
        .execute(
            "INSERT INTO check_publications(id, tenant_id, repo_id, run_id, scope, name, head_sha,
                                            external_id, status, conclusion, title, summary, seq,
                                            published_seq, attempts, state, created_ms, updated_ms,
                                            settled_ms)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, 'Passed', 'job running', 1, 1, 0, 1,
                    1000, 1000, 1000)",
            (
                sentinel_core::CheckId::new().as_bytes(),
                f.tenant.as_bytes(),
                f.repo.as_bytes(),
                run.as_bytes(),
                scope.as_str(),
                checks::qualified_name(job_name),
                sha,
                format!("{run}:{scope}"),
                if conclusion.is_some() {
                    "completed"
                } else {
                    "queued"
                },
                conclusion,
            ),
        )
        .unwrap();
}

/// A GitHub job absorbed by runner mode.
fn booked(f: &Fixture, job_id: i64, conclusion: &str, stamps: (i64, i64, i64)) {
    f.conn
        .execute(
            "INSERT INTO runner_jobs(tenant_id, repo_id, job_id, run_id, class, state_code, runner,
                                     conclusion, queued_ms, started_ms, completed_ms)
             VALUES(?1, ?2, ?3, 9000, 'sentinel-4vcpu-ubuntu-2404', 2, 'sentinel-runner-1', ?4,
                    ?5, ?6, ?7)",
            (
                f.tenant.as_bytes(),
                f.repo.as_bytes(),
                job_id,
                conclusion,
                stamps.0,
                stamps.1,
                stamps.2,
            ),
        )
        .unwrap();
}

fn counts(total: u32, failed: u32, skipped: u32) -> TestCounts {
    TestCounts {
        total,
        failed,
        skipped,
    }
}

fn report(f: &Fixture, input: Input<'_>) -> Result<parity::Report, Error> {
    parity::report(&f.conn, f.tenant, f.repo, input)
}

#[test]
fn a_matching_pair_matches_and_a_differing_one_names_every_difference() {
    let f = fixture();
    let run = run(&f, SHA_A, 1_000);
    let build = job(&f, run, "build", Some(1_000), Some(61_000));
    check(&f, run, SHA_A, build, "build", Some("success"));
    let lint = job(&f, run, "lint", Some(2_000), Some(9_000));
    check(&f, run, SHA_A, lint, "lint", Some("failure"));

    let pairs = [
        Pair {
            sha: SHA_A,
            original: "build",
            shadow: "sentinel / build",
        },
        Pair {
            sha: SHA_A,
            original: "lint",
            shadow: "sentinel / lint",
        },
    ];
    let origins = [
        Origin {
            sha: SHA_A,
            job: "build",
            job_id: 11,
            conclusion: Some("success"),
            duration_ms: Some(60_000),
        },
        Origin {
            sha: SHA_A,
            job: "lint",
            job_id: 12,
            conclusion: Some("success"),
            duration_ms: Some(1_000),
        },
    ];
    let reports = [
        Reported {
            sha: SHA_A,
            job: "build",
            format: ReportFormat::JunitXml,
            counts: counts(12, 0, 1),
        },
        Reported {
            sha: SHA_A,
            job: "sentinel / build",
            format: ReportFormat::JunitXml,
            counts: counts(12, 0, 1),
        },
        Reported {
            sha: SHA_A,
            job: "lint",
            format: ReportFormat::GoTestJson,
            counts: counts(4, 0, 0),
        },
        Reported {
            sha: SHA_A,
            job: "sentinel / lint",
            format: ReportFormat::GoTestJson,
            counts: counts(4, 1, 0),
        },
    ];
    let reported = report(
        &f,
        Input {
            pairs: &pairs,
            origins: &origins,
            reports: &reports,
        },
    )
    .unwrap();
    assert_eq!(reported.pairs.len(), 2);
    assert!(reported.unpaired.is_empty(), "{:?}", reported.unpaired);

    let build = &reported.pairs[0];
    assert_eq!(build.mode, Some(Mode::Native));
    assert!(build.matched(), "{:?}", build.mismatches);
    assert_eq!(build.queue_ms, None);
    assert_eq!(build.original.as_ref().unwrap().duration_ms, Some(60_000));
    assert_eq!(
        build.shadow_side.as_ref().unwrap().duration_ms,
        Some(60_000)
    );
    assert_eq!(
        build.shadow_side.as_ref().unwrap().tests,
        Tests::Reported {
            format: ReportFormat::JunitXml,
            counts: counts(12, 0, 1)
        }
    );

    // The copy failed where the original passed, and stated a failing test the original did not.
    let lint = &reported.pairs[1];
    assert!(
        lint.mismatches.contains(&Mismatch::Conclusion),
        "{:?}",
        lint.mismatches
    );
    assert!(
        lint.mismatches.contains(&Mismatch::Tests),
        "{:?}",
        lint.mismatches
    );
    assert!(
        lint.mismatches.contains(&Mismatch::Duration),
        "{:?}",
        lint.mismatches
    );
    assert!(!lint.matched());
    assert_eq!(
        lint.shadow_side.as_ref().unwrap().conclusion.as_deref(),
        Some("failure")
    );
    assert_eq!(
        lint.original.as_ref().unwrap().conclusion.as_deref(),
        Some("success")
    );

    // One row per job, with the count behind each figure.
    assert_eq!(reported.aggregates.len(), 2);
    let build = reported
        .aggregates
        .iter()
        .find(|a| a.job == "build")
        .unwrap();
    assert_eq!((build.samples, build.matched, build.mismatched), (1, 1, 0));
    assert_eq!(build.original.p50_ms, Some(60_000));
    let lint = reported
        .aggregates
        .iter()
        .find(|a| a.job == "lint")
        .unwrap();
    assert_eq!((lint.samples, lint.matched, lint.mismatched), (1, 0, 1));
}

#[test]
fn a_job_that_stated_no_test_results_says_so_instead_of_matching_zero() {
    let f = fixture();
    let run = run(&f, SHA_A, 1_000);
    let build = job(&f, run, "build", Some(1_000), Some(61_000));
    check(&f, run, SHA_A, build, "build", Some("success"));
    let pairs = [Pair {
        sha: SHA_A,
        original: "build",
        shadow: "sentinel / build",
    }];
    let origins = [Origin {
        sha: SHA_A,
        job: "build",
        job_id: 11,
        conclusion: Some("success"),
        duration_ms: Some(60_000),
    }];
    // Neither side reported tests: the conclusion and the duration agree, and the pair still is
    // not a match, because nothing counts zero tests as agreement.
    let reported = report(
        &f,
        Input {
            pairs: &pairs,
            origins: &origins,
            reports: &[],
        },
    )
    .unwrap();
    let pair = &reported.pairs[0];
    assert_eq!(pair.mismatches, vec![Mismatch::TestsUnreported]);
    assert_eq!(pair.original.as_ref().unwrap().tests, Tests::Unreported);
    assert_eq!(pair.shadow_side.as_ref().unwrap().tests, Tests::Unreported);

    // One side reporting and the other not is the same finding, never a pass.
    let half = [Reported {
        sha: SHA_A,
        job: "build",
        format: ReportFormat::JunitXml,
        counts: TestCounts::default(),
    }];
    let reported = report(
        &f,
        Input {
            pairs: &pairs,
            origins: &origins,
            reports: &half,
        },
    )
    .unwrap();
    assert_eq!(
        reported.pairs[0].mismatches,
        vec![Mismatch::TestsUnreported]
    );

    // Both sides stating no tests at all is a stated figure, and it agrees.
    let empty = [
        Reported {
            sha: SHA_A,
            job: "build",
            format: ReportFormat::JunitXml,
            counts: TestCounts::default(),
        },
        Reported {
            sha: SHA_A,
            job: "sentinel / build",
            format: ReportFormat::JunitXml,
            counts: TestCounts::default(),
        },
    ];
    let reported = report(
        &f,
        Input {
            pairs: &pairs,
            origins: &origins,
            reports: &empty,
        },
    )
    .unwrap();
    assert!(reported.pairs[0].matched(), "{:?}", reported.pairs[0]);
}

#[test]
fn a_copy_sentinel_never_ran_is_named_and_a_copy_no_pair_names_is_listed() {
    let f = fixture();
    let run = run(&f, SHA_A, 1_000);
    let build = job(&f, run, "build", Some(1_000), Some(61_000));
    check(&f, run, SHA_A, build, "build", Some("success"));
    // A native job this report's pairs do not name: a narrowed comparison cannot hide it.
    let docs = job(&f, run, "docs", Some(1_000), Some(2_000));
    check(&f, run, SHA_A, docs, "docs", Some("success"));
    // The aggregate is not a job copy.
    assert!(checks::AGGREGATE_SCOPE.eq("aggregate"));

    let pairs = [
        Pair {
            sha: SHA_A,
            original: "build",
            shadow: "sentinel / build",
        },
        // Sentinel holds nothing for this copy and the page states nothing either.
        Pair {
            sha: SHA_A,
            original: "test",
            shadow: "sentinel / test",
        },
        // The page states no original for this one.
        Pair {
            sha: SHA_B,
            original: "clippy",
            shadow: "sentinel / clippy",
        },
    ];
    let origins = [
        Origin {
            sha: SHA_A,
            job: "build",
            job_id: 11,
            conclusion: Some("success"),
            duration_ms: Some(60_000),
        },
        Origin {
            sha: SHA_A,
            job: "test",
            job_id: 13,
            conclusion: Some("success"),
            duration_ms: Some(1_000),
        },
        Origin {
            sha: SHA_B,
            job: "sentinel / clippy",
            job_id: 14,
            conclusion: Some("success"),
            duration_ms: Some(1_000),
        },
    ];
    let reported = report(
        &f,
        Input {
            pairs: &pairs,
            origins: &origins,
            reports: &[],
        },
    )
    .unwrap();
    let test = reported.pairs.iter().find(|p| p.job == "test").unwrap();
    assert_eq!(test.mode, None);
    assert_eq!(test.mismatches, vec![Mismatch::NoShadow]);
    assert!(test.shadow_side.is_none());
    let clippy = reported.pairs.iter().find(|p| p.job == "clippy").unwrap();
    assert_eq!(clippy.mismatches, vec![Mismatch::NoOriginal]);
    assert!(clippy.original.is_none());

    // Sentinel's own check for a job no pair names is listed; the copy the pair does name is not.
    assert_eq!(
        reported.unpaired,
        vec![parity::Unpaired {
            sha: SHA_A.to_owned(),
            shadow: "sentinel / docs".to_owned()
        }]
    );
}

#[test]
fn runner_mode_copies_are_read_from_the_jobs_sentinels_runners_took() {
    let f = fixture();
    // GitHub ran the original and handed the copy to a Sentinel runner; Sentinel holds no run of
    // its own at this commit.
    booked(&f, 500, "success", (1_000, 4_000, 64_000));
    let pairs = [
        Pair {
            sha: SHA_A,
            original: "build",
            shadow: "sentinel / build",
        },
        // The copy the page names but no booking: the page is all there is.
        Pair {
            sha: SHA_A,
            original: "test",
            shadow: "sentinel / test",
        },
    ];
    let origins = [
        Origin {
            sha: SHA_A,
            job: "build",
            job_id: 499,
            conclusion: Some("success"),
            duration_ms: Some(60_000),
        },
        Origin {
            sha: SHA_A,
            job: "sentinel / build",
            job_id: 500,
            conclusion: Some("success"),
            duration_ms: Some(60_000),
        },
        Origin {
            sha: SHA_A,
            job: "test",
            job_id: 501,
            conclusion: Some("failure"),
            duration_ms: Some(5_000),
        },
        Origin {
            sha: SHA_A,
            job: "sentinel / test",
            job_id: 502,
            conclusion: Some("failure"),
            // More than twice the original's time and more than a second longer: a finding, where
            // a second of noise on the same job would not be.
            duration_ms: Some(11_000),
        },
    ];
    let reports = [
        Reported {
            sha: SHA_A,
            job: "build",
            format: ReportFormat::GoTestJson,
            counts: counts(40, 0, 2),
        },
        Reported {
            sha: SHA_A,
            job: "sentinel / build",
            format: ReportFormat::GoTestJson,
            counts: counts(40, 0, 2),
        },
        Reported {
            sha: SHA_A,
            job: "test",
            format: ReportFormat::GoTestJson,
            counts: counts(8, 1, 0),
        },
        Reported {
            sha: SHA_A,
            job: "sentinel / test",
            format: ReportFormat::GoTestJson,
            counts: counts(8, 1, 0),
        },
    ];
    let reported = report(
        &f,
        Input {
            pairs: &pairs,
            origins: &origins,
            reports: &reports,
        },
    )
    .unwrap();
    let build = reported.pairs.iter().find(|p| p.job == "build").unwrap();
    assert_eq!(build.mode, Some(Mode::Runner));
    assert_eq!(build.queue_ms, Some(3_000));
    assert_eq!(
        build.shadow_side.as_ref().unwrap().duration_ms,
        Some(60_000)
    );
    assert!(build.matched(), "{:?}", build.mismatches);
    // The page's copy is the one the pair names, so nothing it ran is left uncompared.
    assert!(reported.unpaired.is_empty(), "{:?}", reported.unpaired);
    let test = reported.pairs.iter().find(|p| p.job == "test").unwrap();
    assert_eq!(test.mode, Some(Mode::Actions));
    assert_eq!(test.shadow_side.as_ref().unwrap().duration_ms, Some(11_000));
    assert_eq!(test.mismatches, vec![Mismatch::Duration]);
}

#[test]
fn the_percentiles_are_nearest_rank_over_the_samples_they_count() {
    let f = fixture();
    let mut pairs = Vec::new();
    let mut origins = Vec::new();
    // Four commits of the same job: 10 s, 20 s, 30 s and one Sentinel never finished.
    for (index, (sha, original_ms, shadow_ms)) in [
        (SHA_A, 10_000u64, Some(10_000u64)),
        (SHA_B, 20_000, Some(20_000)),
        (SHA_C, 30_000, Some(30_000)),
        (SHA_D, 40_000, None),
    ]
    .into_iter()
    .enumerate()
    {
        let run = run(&f, sha, 1_000 + index as i64);
        let build = job(
            &f,
            run,
            "build",
            Some(1_000),
            shadow_ms.map(|ms| 1_000 + ms as i64),
        );
        check(&f, run, sha, build, "build", Some("success"));
        pairs.push(Pair {
            sha,
            original: "build",
            shadow: "sentinel / build",
        });
        origins.push(Origin {
            sha,
            job: "build",
            job_id: 11 + index as u64,
            conclusion: Some("success"),
            duration_ms: Some(original_ms),
        });
    }
    let counts = counts(6, 0, 0);
    let reports = [SHA_A, SHA_B, SHA_C, SHA_D]
        .into_iter()
        .flat_map(|sha| {
            ["build", "sentinel / build"].map(|job| Reported {
                sha,
                job,
                format: ReportFormat::JunitXml,
                counts,
            })
        })
        .collect::<Vec<_>>();
    let reported = report(
        &f,
        Input {
            pairs: &pairs,
            origins: &origins,
            reports: &reports,
        },
    )
    .unwrap();
    assert_eq!(reported.pairs.len(), 4);
    let aggregate = &reported.aggregates[0];
    // The pair whose copy never finished has no sample, and is a mismatch.
    assert_eq!(aggregate.samples, 3);
    assert_eq!((aggregate.matched, aggregate.mismatched), (3, 1));
    assert_eq!(aggregate.original.p50_ms, Some(20_000));
    assert_eq!(aggregate.original.p95_ms, Some(30_000));
    assert_eq!(aggregate.shadow.p50_ms, Some(20_000));
    assert_eq!(aggregate.shadow.p95_ms, Some(30_000));
    // The copy that never finished states no duration: absent, never zero.
    assert_eq!(
        reported.pairs[3].shadow_side.as_ref().unwrap().duration_ms,
        None
    );
}

/// The plan SQLite picks for one statement, with every parameter bound NULL: what the indexes and
/// the sorts in it are, independent of any row.
fn plan(conn: &Connection, sql: &str) -> String {
    let mut stmt = conn
        .prepare(&format!("EXPLAIN QUERY PLAN {sql}"))
        .unwrap_or_else(|e| panic!("SQLite refused {sql}: {e}"));
    let values = vec![rusqlite::types::Value::Null; stmt.parameter_count()];
    stmt.query_map(rusqlite::params_from_iter(values), |row| {
        row.get::<_, String>(3)
    })
    .unwrap()
    .map(|row| row.unwrap())
    .collect::<Vec<_>>()
    .join(" | ")
}

#[test]
fn a_report_reads_each_commit_and_job_through_an_index() {
    let mut conn = Connection::open_in_memory().unwrap();
    sentinel_store::migrate(&mut conn).unwrap();

    let at_sha = plan(&conn, parity::RUN_AT_SHA_SQL);
    assert!(at_sha.contains("runs_by_sha"), "{at_sha}");
    assert!(!at_sha.contains("SCAN runs"), "{at_sha}");
    // The newest run at a commit is read in index order: no sort of the repository's runs.
    assert!(!at_sha.contains("TEMP B-TREE"), "{at_sha}");

    let jobs = plan(&conn, parity::RUN_JOBS_SQL);
    assert!(jobs.contains("jobs_by_run"), "{jobs}");
    assert!(!jobs.contains("SCAN jobs"), "{jobs}");

    let checks = plan(&conn, parity::RUN_CHECKS_SQL);
    assert!(checks.contains("check_publications_run"), "{checks}");
    assert!(!checks.contains("SCAN check_publications"), "{checks}");

    let booking = plan(&conn, parity::RUNNER_JOB_SQL);
    assert!(booking.contains("PRIMARY KEY"), "{booking}");
    assert!(!booking.contains("SCAN runner_jobs"), "{booking}");

    let owned = plan(&conn, parity::REPO_SQL);
    assert!(!owned.contains("SCAN repos"), "{owned}");
}

#[test]
fn a_report_refuses_more_than_it_can_read_and_a_repository_that_is_not_the_tenants() {
    let f = fixture();
    let pairs = vec![
        Pair {
            sha: SHA_A,
            original: "build",
            shadow: "sentinel / build",
        };
        parity::MAX_PAIRS + 1
    ];
    assert!(matches!(
        report(
            &f,
            Input {
                pairs: &pairs,
                origins: &[],
                reports: &[]
            }
        ),
        Err(Error::InvalidInput("pairs"))
    ));
    let pairs = [Pair {
        sha: "main",
        original: "build",
        shadow: "sentinel / build",
    }];
    assert!(matches!(
        report(
            &f,
            Input {
                pairs: &pairs,
                origins: &[],
                reports: &[]
            }
        ),
        Err(Error::InvalidInput("commit"))
    ));
    // Another tenant's repository is not one this reader answers for; this tenant's own is, even
    // when it holds nothing to compare.
    assert!(matches!(
        parity::report(
            &f.conn,
            f.tenant,
            f.stranger,
            Input {
                pairs: &[],
                origins: &[],
                reports: &[]
            }
        ),
        Err(Error::NotFound)
    ));
    assert!(
        report(
            &f,
            Input {
                pairs: &[],
                origins: &[],
                reports: &[]
            }
        )
        .is_ok()
    );
}
