//! The repository history routes: duration percentiles, a two-attempt phase comparison and a bounded log search
//! across recent runs, including the route-latency gate of U16.

#[path = "support/web_fixture.rs"]
mod fixture;

use std::time::{Duration, Instant};

use fixture::{Fixture, call};
use sentinel_core::{
    AttemptId, JobId, JobState, Outcome, RepoId, RunId, UnixMillis, auth::Permissions as P,
};
use sentinel_protocol::{
    logs::{Frame, Stream},
    summary::{AttemptSummary, CacheRecord, StepOutcome, StepRecord},
};
use sentinel_store::{
    codec::encode_state,
    jobs,
    tokens::{self, Grant},
};
use serde_json::Value;

fn get(f: &Fixture, path: &str, auth: &str) -> (u16, Value) {
    let (status, _, body) = call(&f.base, "GET", path, None, &[("authorization", auth)]);
    (status, body)
}

fn phases(checkout: u64, pull: u64, start: u64, steps: u64, finalize: u64) -> AttemptSummary {
    AttemptSummary {
        checkout_ns: Some(checkout),
        image_pull_ns: Some(pull),
        container_start_ns: Some(start),
        steps_ns: Some(steps),
        finalize_ns: Some(finalize),
        ..AttemptSummary::default()
    }
}

fn add_attempt(
    f: &Fixture,
    repo: RepoId,
    job: JobId,
    fence: i64,
    summary: AttemptSummary,
) -> AttemptId {
    let (tenant, id) = (f.acme, AttemptId::new());
    let bytes = summary.encode().unwrap();
    f.store
        .writer()
        .write(move |tx| {
            tx.execute(
                "INSERT INTO attempts(id, tenant_id, job_id, fence, worker_id, lease_until_ms, repo_id, summary)
                 VALUES (?1, ?2, ?3, ?4, ?5, 0, ?6, ?7)",
                (
                    id.as_bytes(),
                    tenant.as_bytes(),
                    job.as_bytes(),
                    fence,
                    [9u8; 16],
                    repo.as_bytes(),
                    bytes
                ),
            )?;
            Ok(())
        })
        .unwrap();
    id
}

/// A run with one passed job holding one summarized attempt, in a repository other than the diamond's.
fn foreign_attempt(f: &Fixture, repo: RepoId) -> (RunId, JobId, AttemptId) {
    let (tenant, run, job) = (f.acme, RunId::new(), JobId::new());
    f.store
        .writer()
        .write(move |tx| {
            jobs::insert_run(tx, tenant, repo, run, "abc", UnixMillis::now())?;
            jobs::insert_job(tx, tenant, run, job, "alpha", 5, 0)
        })
        .unwrap();
    let attempt = add_attempt(f, repo, job, 1, phases(1, 1, 1, 1, 1));
    (run, job, attempt)
}

#[test]
fn percentiles_and_a_comparison_follow_the_stored_phases() {
    let f = Fixture::new(1);
    let (alpha, first_fence) = f.attempts["alpha"];
    assert_eq!(first_fence.0, 1);
    let durations = "/api/v1/tenants/acme/repos/app/durations";

    let (status, body) = get(&f, &format!("{durations}?job=alpha"), &f.auth);
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["window"]["runs"], 4);
    assert_eq!(body["window"]["requested"], 100);
    let alpha_job = &body["jobs"][0];
    assert_eq!(
        (alpha_job["job"].as_str(), alpha_job["attempts"].as_u64()),
        (Some("alpha"), Some(1))
    );
    // The longer of checkout (420 ms) and pull (80 ms), then 150 ms, 12.6 s and 300 ms.
    assert_eq!(alpha_job["total"]["p50_ns"], 13_470_000_000u64);
    assert_eq!(alpha_job["phases"]["steps"]["count"], 1);
    assert!(
        alpha_job["phases"]["checkout_fetch"].is_null(),
        "an unmeasured phase is absent"
    );
    assert_eq!(alpha_job["samples"][0]["attempt"], alpha.to_string());

    // A rerun that was faster replaces the first attempt in the figures: only the newest counts.
    let rerun = add_attempt(
        &f,
        f.app,
        f.jobs["alpha"],
        2,
        phases(
            400_000_000,
            900_000_000,
            100_000_000,
            10_000_000_000,
            200_000_000,
        ),
    );
    let (_, body) = get(&f, &format!("{durations}?job=alpha"), &f.auth);
    assert_eq!(body["jobs"][0]["attempts"], 1);
    assert_eq!(body["jobs"][0]["total"]["p50_ns"], 11_200_000_000u64);
    assert_eq!(body["jobs"][0]["samples"][0]["fence"], 2);

    // Every job with a stored summary; a failed job that never started its container has no duration.
    let (_, all) = get(&f, durations, &f.auth);
    let names: Vec<_> = all["jobs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|j| j["job"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["alpha", "beta", "huge"]);
    let beta = &all["jobs"][1];
    assert!(beta["total"].is_null());
    assert_eq!(beta["phases"]["checkout"]["p95_ns"], 390_000_000u64);
    assert!(beta.get("samples").is_none());

    // Two attempts of the one job, side by side.
    let (status, body) = get(
        &f,
        &format!("/api/v1/tenants/acme/repos/app/compare?base={alpha}&head={rerun}"),
        &f.auth,
    );
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["job"], "alpha");
    assert_eq!(
        (
            body["base"]["fence"].as_u64(),
            body["head"]["fence"].as_u64()
        ),
        (Some(1), Some(2))
    );
    assert_eq!(body["base"]["timings_ns"]["checkout"], 420_000_000u64);
    assert_eq!(body["delta_ns"]["checkout"], -20_000_000i64);
    assert_eq!(body["delta_ns"]["image_pull"], 820_000_000i64);
    assert_eq!(body["delta_ns"]["total"], -2_270_000_000i64);
    assert!(body["delta_ns"].get("checkout_fetch").is_none());

    // Attempts of different jobs are not one job's history.
    let (beta_attempt, _) = f.attempts["beta"];
    let (status, body) = get(
        &f,
        &format!("/api/v1/tenants/acme/repos/app/compare?base={alpha}&head={beta_attempt}"),
        &f.auth,
    );
    assert_eq!(
        (status, body["code"].as_str()),
        (400, Some("invalid_request"))
    );

    for bad in ["runs=abc", "runs=-1", "job=", "job=a&job=b"] {
        let (status, body) = get(&f, &format!("{durations}?{bad}"), &f.auth);
        assert_eq!(
            (status, body["code"].as_str()),
            (400, Some("invalid_request")),
            "{bad}"
        );
    }
    for bad in ["", "?base=att_x&head=att_y", &format!("?base={alpha}")] {
        let (status, body) = get(
            &f,
            &format!("/api/v1/tenants/acme/repos/app/compare{bad}"),
            &f.auth,
        );
        assert_eq!(
            (status, body["code"].as_str()),
            (400, Some("invalid_request")),
            "{bad}"
        );
    }
    let (_, ceiling) = get(&f, &format!("{durations}?runs=60000"), &f.auth);
    assert_eq!(ceiling["window"]["requested"], 500);
}

#[test]
fn one_repository_cannot_read_another_repositorys_history() {
    let f = Fixture::new(1);
    let (alpha, _) = f.attempts["alpha"];
    let (_, _, foreign) = foreign_attempt(&f, f.web);
    let base = "/api/v1/tenants/acme/repos";

    // The other repository's history is its own: the one job just added, with its own figures and none of app's.
    let (status, body) = get(&f, &format!("{base}/web/durations"), &f.auth);
    assert_eq!(status, 200);
    assert_eq!(body["jobs"].as_array().unwrap().len(), 1, "{body}");
    assert_eq!(body["jobs"][0]["total"]["p95_ns"], 4);
    // An attempt of another repository, whichever side it is on, answers as if it did not exist.
    for (b, h) in [(alpha, foreign), (foreign, alpha)] {
        let (status, body) = get(
            &f,
            &format!("{base}/app/compare?base={b}&head={h}"),
            &f.auth,
        );
        assert_eq!((status, body["code"].as_str()), (404, Some("not_found")));
    }
    // A repository of another tenant is no better.
    let (status, _) = get(&f, &format!("{base}/site/durations"), &f.auth);
    assert_eq!(status, 404);
    let (status, _) = get(&f, &format!("{base}/site/logs/search?q=x"), &f.auth);
    assert_eq!(status, 404);
    // A run or attempt of another repository cannot be a search's resume point.
    let (run, _, attempt) = foreign_attempt(&f, f.web);
    let (status, _) = get(
        &f,
        &format!("{base}/app/logs/search?q=x&run={run}&attempt={attempt}"),
        &f.auth,
    );
    assert_eq!(status, 404);

    // A credential narrowed to the web repository reads its history and nobody else's.
    let (acme, web, root) = (f.acme, f.web, f.root);
    let narrow = tokens::provision(
        &f.store,
        Grant {
            tenant: Some(acme),
            repo: Some(web),
            ..Grant::new(root, "narrow", P::ALL)
        },
        UnixMillis::now(),
    )
    .unwrap();
    let narrow = format!("Bearer {}", sentinel_auth::token::format(&narrow.secret));
    let (status, _) = get(&f, &format!("{base}/web/durations"), &narrow);
    assert_eq!(status, 200);
    for path in [
        format!("{base}/app/durations"),
        format!("{base}/app/compare?base={alpha}&head={alpha}"),
        format!("{base}/app/logs/search?q=fetching"),
    ] {
        let (status, body) = get(&f, &path, &narrow);
        assert_eq!(
            (status, body["code"].as_str()),
            (404, Some("not_found")),
            "{path}"
        );
    }
    let (status, _) = get(&f, &format!("{base}/app/durations"), "Bearer sntl_nonsense");
    assert_eq!(status, 401);
}

fn search_all(f: &Fixture, query: &str) -> (Vec<Value>, Vec<Value>) {
    let base = "/api/v1/tenants/acme/repos/app/logs/search";
    let (mut path, mut matches, mut pages) = (format!("{base}?{query}"), Vec::new(), Vec::new());
    for _ in 0..64 {
        let (status, page) = get(f, &path, &f.auth);
        assert_eq!(status, 200, "{page}");
        matches.extend(page["matches"].as_array().unwrap().iter().cloned());
        let next = page["next"].clone();
        pages.push(page);
        if next.is_null() {
            return (matches, pages);
        }
        let mut resume = format!(
            "{base}?{query}&run={}&attempt={}&after={}&runs={}",
            next["run"].as_str().unwrap(),
            next["attempt"].as_str().unwrap(),
            next["after"],
            next["runs"]
        );
        if let Some(carry) = next["carry"].as_str() {
            resume.push_str(&format!("&carry={carry}"));
        }
        path = resume;
    }
    panic!("a search must end");
}

#[test]
fn a_search_across_runs_reports_where_each_line_was_found_and_pages_like_one_scan() {
    let f = Fixture::new(1);
    let base = "/api/v1/tenants/acme/repos/app/logs/search";
    let (status, body) = get(&f, &format!("{base}?q=expected+200"), &f.auth);
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["matches"].as_array().unwrap().len(), 1);
    let hit = &body["matches"][0];
    assert_eq!(hit["run"], f.diamond.to_string());
    assert_eq!(hit["job"], "beta");
    assert_eq!(hit["attempt"], f.attempts["beta"].0.to_string());
    assert!(
        hit["text"]
            .as_str()
            .unwrap()
            .contains("expected 200, got 500")
    );
    assert_eq!(body["complete"], true);
    assert!(body["next"].is_null());
    assert_eq!(body["expired_attempts"], 0);

    // The window is the newest runs: the newest alone holds no logs.
    let (_, narrow) = get(&f, &format!("{base}?q=expected+200&runs=1"), &f.auth);
    assert_eq!(
        (
            narrow["runs_in_window"].as_u64(),
            narrow["matches"].as_array().unwrap().len()
        ),
        (Some(1), 0)
    );
    assert_eq!(narrow["complete"], true);

    // One line at a time or all at once finds the same lines.
    let (whole, _) = search_all(&f, "q=fetch");
    assert_eq!(whole.len(), 2, "{whole:?}");
    let (stepwise, pages) = search_all(&f, "q=fetch&limit=1");
    assert_eq!(stepwise, whole);
    assert!(pages.len() > 1, "a limit of one line must cut the scan");

    // Retention removed alpha's log: it is skipped and counted, as the per-attempt route says it expired.
    let (alpha, _) = f.attempts["alpha"];
    f.store
        .writer()
        .write(move |tx| {
            tx.execute(
                "UPDATE attempts SET log_expired_ms = 5 WHERE id = ?1",
                [alpha.as_bytes()],
            )?;
            Ok(())
        })
        .unwrap();
    let (_, body) = get(&f, &format!("{base}?q=fetch"), &f.auth);
    assert_eq!(body["matches"].as_array().unwrap().len(), 0);
    assert_eq!(body["expired_attempts"], 1);
    assert_eq!(body["complete"], true);
    let (_, single) = get(
        &f,
        &format!("/api/v1/attempts/{alpha}/logs/search?q=fetch"),
        &f.auth,
    );
    assert_eq!(single["expired_ms"], 5);
    let (_, found) = get(&f, &format!("{base}?q=expected+200"), &f.auth);
    assert_eq!(
        found["matches"].as_array().unwrap().len(),
        1,
        "other logs are still searched"
    );

    for bad in [
        "",
        "q=",
        "q=a&q=b",
        "q=x&runs=abc",
        "q=x&limit=abc",
        "q=x&attempt=att_x",
        &format!("q=x&run={}", f.diamond),
        &format!(
            "q=x&carry=zz&run={}&attempt={}",
            f.diamond, f.attempts["beta"].0
        ),
        &format!("q=x&carry=00&run={}", f.diamond),
    ] {
        let (status, body) = get(&f, &format!("{base}?{bad}"), &f.auth);
        let code = body["code"].as_str();
        assert!(
            (status, code) == (400, Some("invalid_request")),
            "{bad}: {status} {body}"
        );
    }
    let long = "x".repeat(257);
    let (status, _) = get(&f, &format!("{base}?q={long}"), &f.auth);
    assert_eq!(status, 400);
}

#[test]
fn a_search_scans_at_most_four_mebibytes_a_request_and_resumes_exactly() {
    let f = Fixture::new(5);
    let base = "/api/v1/tenants/acme/repos/app/logs/search";
    let budget = sentinel_store::logs::SEARCH_SCAN_BYTES;
    let (status, first) = get(&f, &format!("{base}?q=needle-7f3a"), &f.auth);
    assert_eq!(status, 200, "{first}");
    assert!(
        first["scanned_bytes"].as_u64().unwrap() <= budget,
        "{first}"
    );
    assert_eq!(
        first["matches"].as_array().unwrap().len(),
        0,
        "the line is in the last mebibyte"
    );
    assert_eq!(first["complete"], false);
    let next = &first["next"];
    assert_eq!(next["attempt"], f.bulk_attempt.to_string());
    assert_eq!(next["run"], f.bulk.to_string());
    assert!(next["after"].as_u64().unwrap() > 0);

    let (matches, pages) = search_all(&f, "q=needle-7f3a");
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0]["attempt"], f.bulk_attempt.to_string());
    assert_eq!(matches[0]["stream"], "stderr");
    assert!(pages.len() >= 2);
    assert!(
        pages
            .iter()
            .all(|p| p["scanned_bytes"].as_u64().unwrap() <= budget + 32 * 1024)
    );
    assert_eq!(pages.last().unwrap()["complete"], true);
}

fn big_summary(n: u64) -> Vec<u8> {
    let mut s = phases(
        300_000_000 + n % 97,
        80_000_000,
        150_000_000,
        9_000_000_000 + n * 7,
        250_000_000,
    );
    s.steps = (0..4)
        .map(|i| StepRecord {
            index: i,
            id: format!("step-{i}"),
            outcome: StepOutcome::Passed,
            duration_ns: Some(1_000_000_000 + n),
        })
        .collect();
    s.caches = vec![CacheRecord {
        name: "cargo".into(),
        class: 1,
        outcome: "hit".into(),
        lookup_ns: Some(2_000_000),
        lock_wait_ns: None,
        clone_ns: Some(40_000_000),
        first_touch_ns: None,
        files: 1200,
        bytes: 900 << 20,
        copied_bytes: 0,
        reflink: true,
        commit_ns: None,
        staged_bytes: None,
        reused_bytes: None,
        dirty_bytes: None,
        publish: None,
        costly_hit: false,
        remote_ns: None,
        remote_bytes: 0,
        remote_from: None,
    }];
    s.detail = "all steps passed".into();
    s.encode().unwrap()
}

/// The gate of U16: the p95 route latency on a repository of 10,000 runs.
///
/// The gate is 200 ms and is asserted whole. The figure is a nearest-rank p95 of 30 timed calls after 3 discarded
/// warm-ups, so it is the 29th-fastest call: one slow call on a loaded host (a stall, a page fault storm) cannot fail
/// it, two can. Each call is a full loopback HTTP round trip with a new connection, authentication and JSON, and the
/// build is the unoptimized test profile, slower than the release the gate describes; `--no-capture` prints every
/// route's figure beside the bound.
#[test]
fn the_history_routes_answer_within_200_ms_p95_on_ten_thousand_runs() {
    const RUNS: i64 = 10_000;
    const GATE: Duration = Duration::from_millis(200);
    const TIMED: usize = 30;
    let f = Fixture::new(1);
    let (tenant, repo) = (f.acme, RepoId::new());
    let base_ms = UnixMillis::now().0 - RUNS * 1_000;
    let newest: Vec<(RunId, Vec<(JobId, AttemptId)>)> = {
        f.store
            .writer()
            .write(move |tx| {
                let mut newest = Vec::new();
                jobs::insert_repo(tx, tenant, repo, "big", UnixMillis::now())?;
                let mut run_stmt = tx.prepare(
                    "INSERT INTO runs(id, tenant_id, repo_id, source_sha, created_ms) VALUES (?1, ?2, ?3, 'abc', ?4)",
                )?;
                let mut job_stmt = tx.prepare(
                    "INSERT INTO jobs(id, tenant_id, run_id, name, state_code, priority, created_seq, repo_id, spec_index)
                     VALUES (?1, ?2, ?3, ?4, ?5, 5, ?6, ?3, ?6)",
                )?;
                let mut job_stmt_fix = tx.prepare("UPDATE jobs SET repo_id = ?2 WHERE id = ?1")?;
                let mut attempt_stmt = tx.prepare(
                    "INSERT INTO attempts(id, tenant_id, job_id, fence, worker_id, lease_until_ms, repo_id, summary)
                     VALUES (?1, ?2, ?3, ?4, ?5, 0, ?6, ?7)",
                )?;
                let state = encode_state(JobState::Terminal(Outcome::Passed));
                for n in 0..RUNS {
                    let run = RunId::new();
                    run_stmt.execute((run.as_bytes(), tenant.as_bytes(), repo.as_bytes(), base_ms + n * 1_000))?;
                    let mut made = Vec::new();
                    for (index, name) in ["build", "test", "lint"].into_iter().enumerate() {
                        let job = JobId::new();
                        job_stmt.execute((job.as_bytes(), tenant.as_bytes(), run.as_bytes(), name, state, index as i64))?;
                        job_stmt_fix.execute((job.as_bytes(), repo.as_bytes()))?;
                        // One run in twenty reran a job: two attempts, the newest counts.
                        let attempts = if n % 20 == 0 { 2 } else { 1 };
                        let mut last = AttemptId::new();
                        for fence in 1..=attempts {
                            last = AttemptId::new();
                            attempt_stmt.execute((
                                last.as_bytes(),
                                tenant.as_bytes(),
                                job.as_bytes(),
                                fence,
                                [9u8; 16],
                                repo.as_bytes(),
                                big_summary(n as u64 * 3 + index as u64)
                            ))?;
                        }
                        made.push((job, last));
                    }
                    if n >= RUNS - 50 {
                        newest.push((run, made));
                    }
                }
                Ok(newest)
            })
            .unwrap()
    };
    let counted: i64 = f
        .store
        .read(|c| {
            Ok(c.query_row(
                "SELECT COUNT(*) FROM runs WHERE repo_id = ?1",
                [repo.as_bytes()],
                |r| r.get(0),
            )?)
        })
        .unwrap();
    assert_eq!(counted, RUNS);

    // Logs for the newest fifty runs, a frame of 32 KiB per job: more than the 4 MiB a search may scan.
    for (run, jobs) in &newest {
        for (job, attempt) in jobs {
            f.logs
                .append(
                    *run,
                    *job,
                    *attempt,
                    &Frame {
                        seq: 1,
                        step: 0,
                        stream: Stream::Stdout,
                        bytes: b"compiling the quick brown fox\n".repeat(1_100)[..32 * 1024 - 1]
                            .to_vec(),
                    },
                )
                .unwrap();
            f.logs.finish(*run, *job, *attempt, 1, &[]).unwrap();
        }
    }

    let routes = "/api/v1/tenants/acme/repos/big";
    let probe = {
        let (_, one) = get(&f, &format!("{routes}/durations?job=build&runs=2"), &f.auth);
        let samples = one["jobs"][0]["samples"].as_array().unwrap();
        (
            samples[0]["attempt"].as_str().unwrap().to_owned(),
            samples[1]["attempt"].as_str().unwrap().to_owned(),
        )
    };
    let paths = [
        (
            "durations, 100 runs (default)",
            format!("{routes}/durations"),
        ),
        (
            "durations, 500 runs (ceiling)",
            format!("{routes}/durations?runs=500"),
        ),
        (
            "durations, one job, 500 runs",
            format!("{routes}/durations?runs=500&job=test"),
        ),
        (
            "compare",
            format!("{routes}/compare?base={}&head={}", probe.1, probe.0),
        ),
        (
            "search, 20 runs, no match",
            format!("{routes}/logs/search?q=absent-needle"),
        ),
        (
            "search, 100 runs, spends the 4 MiB",
            format!("{routes}/logs/search?q=absent-needle&runs=100"),
        ),
        (
            "search, 100 runs, matches",
            format!("{routes}/logs/search?q=quick+brown&runs=100&limit=500"),
        ),
    ];
    let mut slowest = Duration::ZERO;
    for (what, path) in &paths {
        for _ in 0..3 {
            let (status, body) = get(&f, path, &f.auth);
            assert_eq!(status, 200, "{what}: {body}");
        }
        let mut times = Vec::with_capacity(TIMED);
        for _ in 0..TIMED {
            let started = Instant::now();
            let (status, _) = get(&f, path, &f.auth);
            times.push(started.elapsed());
            assert_eq!(status, 200, "{what}");
        }
        times.sort_unstable();
        let p95 = times[(TIMED * 95).div_ceil(100) - 1];
        println!(
            "{what}: p50 {:?}, p95 {p95:?}, max {:?}",
            times[TIMED / 2 - 1],
            times[TIMED - 1]
        );
        assert!(p95 < GATE, "{what}: p95 {p95:?} is over the {GATE:?} gate");
        slowest = slowest.max(p95);
    }
    println!("slowest p95 {slowest:?} against the {GATE:?} gate on {RUNS} runs");

    // The figures are over the window asked for, from the one repository.
    let (_, body) = get(&f, &format!("{routes}/durations?runs=500"), &f.auth);
    assert_eq!(body["window"]["runs"], 500);
    assert_eq!(body["jobs"].as_array().unwrap().len(), 3);
    assert_eq!(body["jobs"][0]["attempts"], 500);
    let (_, found) = get(
        &f,
        &format!("{routes}/logs/search?q=quick+brown&runs=100&limit=500"),
        &f.auth,
    );
    assert!(!found["matches"].as_array().unwrap().is_empty());
    assert!(
        found["scanned_bytes"].as_u64().unwrap()
            <= sentinel_store::logs::SEARCH_SCAN_BYTES + 32 * 1024
    );
    // The timed worst case really read the whole budget, and says there is more.
    let (_, worst) = get(
        &f,
        &format!("{routes}/logs/search?q=absent-needle&runs=100"),
        &f.auth,
    );
    assert!(
        worst["scanned_bytes"].as_u64().unwrap()
            >= sentinel_store::logs::SEARCH_SCAN_BYTES - 32 * 1024
    );
    assert_eq!(worst["complete"], false);
}

#[test]
fn history_needs_the_scopes_of_the_routes_it_reads() {
    let f = Fixture::new(1);
    let base = "/api/v1/tenants/acme/repos/app";
    let (alpha, _) = f.attempts["alpha"];
    // A credential that may only run pipelines holds neither runs:read nor logs:read.
    let runner = f.bearer(f.root, P::RUN);
    for (path, scope) in [
        (format!("{base}/durations"), "runs:read"),
        (
            format!("{base}/compare?base={alpha}&head={alpha}"),
            "runs:read",
        ),
        (format!("{base}/logs/search?q=fetch"), "logs:read"),
    ] {
        let (status, body) = get(&f, &path, &runner);
        assert_eq!(
            (status, body["code"].as_str()),
            (403, Some("forbidden")),
            "{path}"
        );
        assert_eq!(body["details"]["scope"], scope, "{path}");
    }
    let reader = f.bearer(f.root, P::READ);
    for path in [
        format!("{base}/durations"),
        format!("{base}/logs/search?q=fetch"),
    ] {
        assert_eq!(get(&f, &path, &reader).0, 200, "{path}");
    }
}
