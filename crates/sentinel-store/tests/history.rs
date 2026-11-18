use sentinel_core::{
    AttemptId, JobId, JobState, Outcome, RepoId, RunId, TenantId, UnixMillis, UserId,
    auth::{Namespace, Permissions as P, Principal},
};
use sentinel_protocol::summary::AttemptSummary;
use sentinel_store::{
    Durability, Error, Store,
    auth::{self, NamespaceKind, provisioning},
    codec::encode_state,
    history::{self, MAX_JOB_NAMES, MAX_WINDOW_RUNS},
    jobs,
};

const NOW: UnixMillis = UnixMillis(1_000_000_000);

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

/// What one attempt of a seeded job stored: nothing, or a summary.
type Attempt = Option<AttemptSummary>;

fn summary(checkout: u64, pull: u64, start: u64, steps: u64, finalize: u64) -> Attempt {
    Some(AttemptSummary {
        checkout_ns: Some(checkout),
        image_pull_ns: Some(pull),
        container_start_ns: Some(start),
        steps_ns: Some(steps),
        finalize_ns: Some(finalize),
        ..AttemptSummary::default()
    })
}

/// A run with its jobs, each job holding its attempts by ascending fence; returns each job's attempt ids.
fn seed_run(
    f: &Fixture,
    repo: RepoId,
    created_ms: i64,
    jobs: Vec<(&'static str, Vec<Attempt>)>,
) -> (RunId, Vec<Vec<AttemptId>>) {
    let (tenant, run) = (f.tenant, RunId::new());
    let ids = f
        .store
        .writer()
        .write(move |tx| {
            tx.execute(
                "INSERT INTO runs(id, tenant_id, repo_id, source_sha, created_ms) VALUES (?1, ?2, ?3, 'abc', ?4)",
                rusqlite::params![run.as_bytes(), tenant.as_bytes(), repo.as_bytes(), created_ms],
            )?;
            let mut out = Vec::new();
            for (index, (name, attempts)) in jobs.into_iter().enumerate() {
                let job = JobId::new();
                tx.execute(
                    "INSERT INTO jobs(id, tenant_id, run_id, name, state_code, priority, created_seq, repo_id, spec_index)
                     VALUES (?1, ?2, ?3, ?4, ?5, 5, ?6, ?7, ?6)",
                    rusqlite::params![
                        job.as_bytes(),
                        tenant.as_bytes(),
                        run.as_bytes(),
                        name,
                        encode_state(JobState::Terminal(Outcome::Passed)),
                        index as i64,
                        repo.as_bytes()
                    ],
                )?;
                let mut ids = Vec::new();
                for (fence, attempt) in attempts.into_iter().enumerate() {
                    let id = AttemptId::new();
                    tx.execute(
                        "INSERT INTO attempts(id, tenant_id, job_id, fence, worker_id, lease_until_ms, repo_id, summary)
                         VALUES (?1, ?2, ?3, ?4, ?5, 0, ?6, ?7)",
                        rusqlite::params![
                            id.as_bytes(),
                            tenant.as_bytes(),
                            job.as_bytes(),
                            fence as i64 + 1,
                            [7u8; 16],
                            repo.as_bytes(),
                            attempt.map(|s| s.encode().unwrap())
                        ],
                    )?;
                    ids.push(id);
                }
                out.push(ids);
            }
            Ok(out)
        })
        .unwrap();
    (run, ids)
}

fn plan(conn: &rusqlite::Connection, sql: &str) -> Vec<String> {
    let mut stmt = conn
        .prepare(&format!("EXPLAIN QUERY PLAN {sql}"))
        .unwrap_or_else(|e| panic!("SQLite refused {sql}: {e}"));
    let values = vec![rusqlite::types::Value::Null; stmt.parameter_count()];
    stmt.query_map(rusqlite::params_from_iter(values), |r| r.get(3))
        .unwrap()
        .map(|r| r.unwrap())
        .collect()
}

#[test]
fn percentiles_take_each_runs_newest_summarized_attempt_by_nearest_rank() {
    let f = fixture();
    // Twenty runs; run i takes i * 1000 ns in its steps. The total is the longer of checkout and pull, then start,
    // steps and finalize: 100 + 10 + i * 1000 + 5.
    for i in 1..=20u64 {
        let attempts = if i == 1 {
            // A rerun whose first attempt was far slower: only the newest counts. A newer attempt without a summary
            // (still running) does not hide the one before it.
            vec![
                summary(1, 1, 1, 9_000_000, 1),
                summary(100, 50, 10, 1_000, 5),
                None,
            ]
        } else {
            vec![summary(100, 50, 10, i * 1_000, 5)]
        };
        seed_run(&f, f.app, NOW.0 + i as i64, vec![("build", attempts)]);
    }
    let found = f
        .store
        .read(|c| history::durations(c, f.tenant, f.app, 100, None))
        .unwrap();
    assert_eq!((found.requested, found.runs), (100, 20));
    assert_eq!(found.oldest_ms, Some(NOW.0 + 1));
    assert_eq!(found.newest_ms, Some(NOW.0 + 20));
    assert_eq!(found.jobs.len(), 1);
    let build = &found.jobs[0];
    assert_eq!((build.job.as_str(), build.attempts), ("build", 20));
    assert!(build.samples.is_empty(), "samples are for a named job only");
    let total = build.total.unwrap();
    // Nearest rank over 20 values: p50 is the 10th, p95 the 19th.
    assert_eq!(
        (total.count, total.p50_ns, total.p95_ns),
        (20, 10_115, 19_115)
    );
    let steps = build.phases[5].unwrap();
    assert_eq!((steps.p50_ns, steps.p95_ns), (10_000, 19_000));
    assert!(
        build.phases[1].is_none(),
        "an unmeasured phase has no figures, not zeros"
    );

    // The window is the newest runs, and says how many it holds.
    let five = f
        .store
        .read(|c| history::durations(c, f.tenant, f.app, 5, None))
        .unwrap();
    assert_eq!((five.runs, five.oldest_ms), (5, Some(NOW.0 + 16)));
    let total = five.jobs[0].total.unwrap();
    assert_eq!(
        (total.count, total.p50_ns, total.p95_ns),
        (5, 18_115, 20_115)
    );
    let ceiling = f
        .store
        .read(|c| history::durations(c, f.tenant, f.app, u16::MAX, None))
        .unwrap();
    assert_eq!((ceiling.requested, ceiling.runs), (MAX_WINDOW_RUNS, 20));
}

#[test]
fn an_attempt_that_never_reached_its_steps_counts_but_has_no_duration() {
    let f = fixture();
    let early = Some(AttemptSummary {
        checkout_ns: Some(100),
        ..AttemptSummary::default()
    });
    seed_run(&f, f.app, NOW.0 + 1, vec![("build", vec![early])]);
    seed_run(
        &f,
        f.app,
        NOW.0 + 2,
        vec![("build", vec![summary(100, 50, 10, 1_000, 5)])],
    );
    let found = f
        .store
        .read(|c| history::durations(c, f.tenant, f.app, 10, Some("build")))
        .unwrap();
    let build = &found.jobs[0];
    assert_eq!(build.attempts, 2);
    assert_eq!(build.total.unwrap().count, 1);
    assert_eq!(build.phases[0].unwrap().count, 2);
    // Newest first, the unfinished one without a total.
    assert_eq!(build.samples.len(), 2);
    assert_eq!(build.samples[0].total_ns, Some(1_115));
    assert_eq!(build.samples[1].total_ns, None);
    assert_eq!(build.samples[1].phases[0], Some(100));
}

#[test]
fn a_named_job_gets_its_samples_and_other_jobs_are_left_out() {
    let f = fixture();
    for i in 1..=3u64 {
        seed_run(
            &f,
            f.app,
            NOW.0 + i as i64,
            vec![
                ("build", vec![summary(1, 1, 1, i * 10, 1)]),
                ("lint", vec![summary(1, 1, 1, i * 100, 1)]),
            ],
        );
    }
    let all = f
        .store
        .read(|c| history::durations(c, f.tenant, f.app, 10, None))
        .unwrap();
    assert_eq!(
        all.jobs.iter().map(|j| j.job.as_str()).collect::<Vec<_>>(),
        ["build", "lint"]
    );
    let lint = f
        .store
        .read(|c| history::durations(c, f.tenant, f.app, 10, Some("lint")))
        .unwrap();
    assert_eq!(lint.jobs.len(), 1);
    assert_eq!(
        lint.jobs[0]
            .samples
            .iter()
            .map(|s| s.created_ms - NOW.0)
            .collect::<Vec<_>>(),
        [3, 2, 1]
    );
    let none = f
        .store
        .read(|c| history::durations(c, f.tenant, f.app, 10, Some("nothing")))
        .unwrap();
    assert!(none.jobs.is_empty());
    assert_eq!(
        none.runs, 3,
        "the window is the runs, whether or not the job ran in them"
    );
}

#[test]
fn one_repository_never_reads_another_repositorys_history() {
    let f = fixture();
    let (_, mine) = seed_run(
        &f,
        f.app,
        NOW.0 + 1,
        vec![("build", vec![summary(1, 1, 1, 10, 1)])],
    );
    let (_, theirs) = seed_run(
        &f,
        f.other,
        NOW.0 + 2,
        vec![
            ("build", vec![summary(1, 1, 1, 99_999, 1)]),
            ("secret-job", vec![summary(1, 1, 1, 5, 1)]),
        ],
    );
    let found = f
        .store
        .read(|c| history::durations(c, f.tenant, f.app, 100, None))
        .unwrap();
    assert_eq!(found.runs, 1);
    assert_eq!(found.jobs.len(), 1);
    assert_eq!(found.jobs[0].total.unwrap().p95_ns, 13);

    let (own, foreign) = (mine[0][0], theirs[0][0]);
    for (base, head) in [(own, foreign), (foreign, own), (foreign, foreign)] {
        let refused = f
            .store
            .read(|c| history::compare(c, f.tenant, f.app, base, head))
            .unwrap_err();
        assert!(matches!(refused, Error::NotFound), "{refused:?}");
    }
    // Another tenant's id for the same repository is no better.
    let stranger = TenantId::new();
    let refused = f
        .store
        .read(|c| history::compare(c, stranger, f.app, own, own))
        .unwrap_err();
    assert!(matches!(refused, Error::NotFound));
    let (run, _) = seed_run(&f, f.other, NOW.0 + 3, vec![("build", vec![None])]);
    let refused = f
        .store
        .read(|c| history::search_runs(c, f.tenant, f.app, Some(run), 10))
        .unwrap_err();
    assert!(matches!(refused, Error::NotFound), "{refused:?}");
    let refused = f
        .store
        .read(|c| history::log_target(c, f.tenant, run, own))
        .unwrap_err();
    assert!(matches!(refused, Error::NotFound), "{refused:?}");
}

#[test]
fn two_attempts_of_one_job_compare_phase_by_phase() {
    let f = fixture();
    let (_, old) = seed_run(
        &f,
        f.app,
        NOW.0 + 1,
        vec![(
            "build",
            vec![summary(400, 50, 10, 1_000, 5), summary(100, 50, 10, 900, 5)],
        )],
    );
    let (_, new) = seed_run(
        &f,
        f.app,
        NOW.0 + 2,
        vec![
            ("build", vec![summary(100, 500, 10, 1_500, 5)]),
            ("lint", vec![summary(1, 1, 1, 1, 1)]),
        ],
    );
    let (_, running) = seed_run(&f, f.app, NOW.0 + 3, vec![("build", vec![None])]);
    // Two attempts of the same job in one run compare too.
    let rerun = f
        .store
        .read(|c| history::compare(c, f.tenant, f.app, old[0][0], old[0][1]))
        .unwrap();
    assert_eq!(rerun.base.run, rerun.head.run);
    assert_eq!(
        history::delta(rerun.base.phases.unwrap()[0], rerun.head.phases.unwrap()[0]),
        Some(-300)
    );

    let found = f
        .store
        .read(|c| history::compare(c, f.tenant, f.app, old[0][1], new[0][0]))
        .unwrap();
    assert_eq!(found.job, "build");
    assert_eq!((found.base.fence, found.head.fence), (2, 1));
    let (b, h) = (found.base.phases.unwrap(), found.head.phases.unwrap());
    // image_pull rose by 450, steps by 600, checkout is unchanged; fetch and materialize were never measured.
    assert_eq!(history::delta(b[0], h[0]), Some(0));
    assert_eq!(history::delta(b[3], h[3]), Some(450));
    assert_eq!(history::delta(b[5], h[5]), Some(600));
    assert_eq!(history::delta(b[1], h[1]), None);
    // The pull now outlasts the checkout: 1,015 ns before, 2,015 after.
    assert_eq!(
        history::delta(found.base.total_ns, found.head.total_ns),
        Some(1_000)
    );

    let pending = f
        .store
        .read(|c| history::compare(c, f.tenant, f.app, old[0][1], running[0][0]))
        .unwrap();
    assert!(pending.head.phases.is_none() && pending.head.total_ns.is_none());

    let refused = f
        .store
        .read(|c| history::compare(c, f.tenant, f.app, old[0][0], new[1][0]))
        .unwrap_err();
    assert!(matches!(refused, Error::InvalidInput(_)), "{refused:?}");
}

#[test]
fn a_repository_with_more_job_names_than_the_cap_says_so() {
    let f = fixture();
    let names: Vec<&'static str> = (0..=MAX_JOB_NAMES)
        .map(|n| &*Box::leak(format!("job-{n:03}").into_boxed_str()))
        .collect();
    seed_run(
        &f,
        f.app,
        NOW.0 + 1,
        names
            .iter()
            .map(|n| (*n, vec![summary(1, 1, 1, 1, 1)]))
            .collect(),
    );
    let found = f
        .store
        .read(|c| history::durations(c, f.tenant, f.app, 10, None))
        .unwrap();
    assert_eq!(found.jobs.len(), MAX_JOB_NAMES);
    assert!(found.truncated);
}

#[test]
fn an_unreadable_stored_summary_is_counted_and_left_out() {
    let f = fixture();
    seed_run(
        &f,
        f.app,
        NOW.0 + 1,
        vec![("build", vec![summary(1, 1, 1, 7, 1)])],
    );
    let (_, bad) = seed_run(
        &f,
        f.app,
        NOW.0 + 2,
        vec![("build", vec![summary(1, 1, 1, 9, 1)])],
    );
    let attempt = bad[0][0];
    f.store
        .writer()
        .write(move |tx| {
            // The trigger forbids replacing a summary, so write the garbage by dropping and re-adding it.
            tx.execute("DROP TRIGGER attempt_update", [])?;
            tx.execute(
                "UPDATE attempts SET summary = X'09ff' WHERE id = ?1",
                [attempt.as_bytes()],
            )?;
            Ok(())
        })
        .unwrap();
    let found = f
        .store
        .read(|c| history::durations(c, f.tenant, f.app, 10, None))
        .unwrap();
    assert_eq!((found.jobs[0].attempts, found.unreadable), (1, 1));
    let refused = f
        .store
        .read(|c| history::compare(c, f.tenant, f.app, attempt, attempt))
        .unwrap_err();
    assert!(matches!(refused, Error::Corrupt(_)), "{refused:?}");
}

#[test]
fn log_targets_are_the_newest_attempt_of_each_job_in_pipeline_order() {
    let f = fixture();
    let (run, ids) = seed_run(
        &f,
        f.app,
        NOW.0 + 1,
        vec![
            ("a", vec![None, None]),
            ("b", vec![None]),
            ("c", vec![None]),
        ],
    );
    let all = f
        .store
        .read(|c| history::log_targets(c, f.tenant, run, None))
        .unwrap();
    assert_eq!(
        all.iter()
            .map(|t| (t.name.as_str(), t.attempt))
            .collect::<Vec<_>>(),
        [("a", ids[0][1]), ("b", ids[1][0]), ("c", ids[2][0])]
    );
    let after = f
        .store
        .read(|c| history::log_targets(c, f.tenant, run, Some(all[0].spec_index)))
        .unwrap();
    assert_eq!(
        after.iter().map(|t| t.name.as_str()).collect::<Vec<_>>(),
        ["b", "c"]
    );
    // A continuation may name an attempt that is no longer the newest of its job.
    let older = f
        .store
        .read(|c| history::log_target(c, f.tenant, run, ids[0][0]))
        .unwrap();
    assert_eq!(
        (older.name.as_str(), older.attempt, older.expired_ms),
        ("a", ids[0][0], None)
    );
    f.store
        .writer()
        .write(move |tx| {
            tx.execute(
                "UPDATE attempts SET log_expired_ms = ?2 WHERE id = ?1",
                rusqlite::params![ids[1][0].as_bytes(), NOW.0],
            )?;
            Ok(())
        })
        .unwrap();
    let expired = f
        .store
        .read(|c| history::log_targets(c, f.tenant, run, Some(0)))
        .unwrap();
    assert_eq!(expired[0].expired_ms, Some(NOW.0));
    assert_eq!(expired[1].expired_ms, None);
}

#[test]
fn search_runs_are_the_newest_first_from_the_named_run_and_bounded() {
    let f = fixture();
    let runs: Vec<RunId> = (1..=5)
        .map(|i| seed_run(&f, f.app, NOW.0 + i, vec![("build", vec![None])]).0)
        .collect();
    let newest = f
        .store
        .read(|c| history::search_runs(c, f.tenant, f.app, None, 3))
        .unwrap();
    assert_eq!(newest, [runs[4], runs[3], runs[2]]);
    let from = f
        .store
        .read(|c| history::search_runs(c, f.tenant, f.app, Some(runs[2]), 10))
        .unwrap();
    assert_eq!(from, [runs[2], runs[1], runs[0]]);
}

#[test]
fn the_history_queries_are_keyed_searches_without_a_sort_or_a_scan() {
    let f = fixture();
    seed_run(
        &f,
        f.app,
        NOW.0 + 1,
        vec![("build", vec![summary(1, 1, 1, 1, 1)])],
    );
    let statements = [
        ("window", history::WINDOW_SQL),
        ("durations", history::DURATIONS_SQL),
        ("job durations", history::JOB_DURATIONS_SQL),
        ("compare side", history::SIDE_SQL),
        ("search runs", history::SEARCH_RUNS_SQL),
        ("log targets", history::TARGETS_SQL),
        ("log target", history::TARGET_SQL),
    ];
    for (what, sql) in statements {
        let plan = f.store.read(|c| Ok(plan(c, sql))).unwrap();
        println!("{what}: {plan:#?}");
        assert!(
            // A limited subquery is a co-routine its parent reads whole; every table is searched by key.
            plan.iter().all(|p| {
                let Some(name) = p.strip_prefix("SCAN ") else {
                    return true;
                };
                plan.iter()
                    .any(|q| q.strip_prefix("CO-ROUTINE ") == Some(name))
            }),
            "{what} scans a table: {plan:?}"
        );
        // One run's jobs (at most 64) are put in pipeline order; every other statement reads its index in order.
        assert!(
            what == "log targets" || plan.iter().all(|p| !p.contains("TEMP B-TREE")),
            "{what} sorts: {plan:?}"
        );
    }
    let durations = f
        .store
        .read(|c| Ok(plan(c, history::DURATIONS_SQL)))
        .unwrap();
    let has = |needle: &str| durations.iter().any(|p| p.contains(needle));
    assert!(
        has("USING COVERING INDEX runs_by_repo (tenant_id=? AND repo_id=?)"),
        "{durations:?}"
    );
    assert!(has("INDEX jobs_by_run (run_id=?)"), "{durations:?}");
    assert!(has("(job_id=?)"), "{durations:?}");
    let named = f
        .store
        .read(|c| Ok(plan(c, history::JOB_DURATIONS_SQL)))
        .unwrap();
    assert!(
        named.iter().any(|p| p.contains("(run_id=? AND name=?)")),
        "a named job is one probe of (run_id, name): {named:?}"
    );
}
