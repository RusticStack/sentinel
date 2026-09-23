//! Q09: store-level placement load — 100 worker identities and 10,000 queued
//! jobs, with capacity actually held.
//!
//! What it measures: the scheduler and the SQLite write path alone. No TLS
//! session, container, checkout or step runs; workers are rows. The
//! dispatcher's structure is reproduced: rounds in which every worker that
//! can still take work is offered one job, all in one writer transaction.
//! Offers are acknowledged and **held** — capacity fills exactly as a real
//! fleet's does, so every placement's free-capacity sums, fairness probes
//! and candidate scans run against a loaded fleet. When no worker can take
//! more, the held work completes (a terminal report per attempt, freeing its
//! reservation) and the next wave places. The mix is realistic rather than
//! uniform: four tenants (one noisy, with 70 % of the jobs) over three
//! repositories each, a share of pull-request runs (the PR reserve and its
//! probe are live), label-constrained jobs only half the fleet can run, and
//! identities paired on shared hosts (host-level reservation is live).
//!
//! Reported (one JSON line, also appended to `$SENTINEL_BENCH_OUT` when set):
//! per-placement latency p50/p95/p99/max, queue wait (enqueue to placement)
//! p50/p95/p99/max, throughput, waves and rounds, placement failures, and on
//! Linux the process's CPU time, peak RSS and I/O bytes. What it does not
//! cover: the 100 real TLS sessions — that is `sentinel-link`'s
//! `fleet_sessions.rs`, a separate test (100 sessions × 200 jobs) — and
//! any executor work.

use std::{
    collections::{HashMap, HashSet},
    time::{Duration, Instant},
};

use sentinel_auth::secret::Secret;
use sentinel_core::{
    Event, FailureClass, JobId, PoolId, RepoId, RunId, TenantId, UnixMillis, UserId, WorkerId,
    auth::{Namespace, Permissions as P, Principal},
};
use sentinel_pipeline::{PinnedSource, RunSpec, compile_str};
use sentinel_protocol::negotiate::{Arch, Capabilities, Negotiated, ProtocolVersion};
use sentinel_store::{
    Durability, Store,
    auth::{self, Authority, NamespaceKind, provisioning},
    dispatch,
    provenance::{self, Provenance},
    runs,
    tenancy::{self, PoolKind},
    workers::{self, Presentation},
};

const WORKERS: usize = 100;
const JOBS_PER_RUN: usize = 50;
const RUNS: usize = 200;
/// Two hundred runs of fifty jobs: ten thousand queued jobs.
const JOBS: usize = RUNS * JOBS_PER_RUN;
const TENANTS: usize = 4;
const REPOS_PER_TENANT: usize = 3;
/// Every tenth run is a pull request.
const PR_EVERY: usize = 10;
/// Every eighth run's jobs need the `ssd` label, which half the fleet has.
const LABELED_EVERY: usize = 8;
const NOW: UnixMillis = UnixMillis(1_000);
const SHA: &str = "0123456789abcdef0123456789abcdef01234567";
const DIGEST: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

/// Each identity reports its host's whole capacity (the documented model),
/// and two identities share each host, so a pair holds 32 quarter-core jobs
/// between them, not 64.
const WORKER_CAPACITY: dispatch::Capacity = dispatch::Capacity {
    cpu_millis: 8_000,
    memory_bytes: 16 << 30,
    disk_bytes: 64 << 30,
};

fn run_yaml(labeled: bool) -> String {
    let extra = if labeled {
        "    runs_on: { labels: [ssd] }\n"
    } else {
        ""
    };
    let mut yaml = String::from("schema: 1\non: [push]\njobs:\n");
    for i in 0..JOBS_PER_RUN {
        yaml.push_str(&format!(
            "  j{i:03}:\n    image: alpine:3\n{extra}    resources: {{ cpu: \"0.25\", memory: 128MiB, disk: 1GiB }}\n    steps: [{{ id: s, run: 'true' }}]\n"
        ));
    }
    yaml
}

fn percentile(sorted: &[u64], p: f64) -> u64 {
    let index = (((sorted.len() - 1) as f64) * p).round() as usize;
    sorted[index]
}

/// The process's CPU time (ms), peak RSS (KiB) and read/written bytes from
/// `/proc/self`; absent where unmeasured.
fn process_usage() -> serde_json::Value {
    #[cfg(target_os = "linux")]
    {
        let stat = std::fs::read_to_string("/proc/self/stat").unwrap_or_default();
        // Fields after the parenthesised command: utime is the 12th, stime 13th.
        let cpu_ms = stat.rsplit_once(')').and_then(|(_, rest)| {
            let fields: Vec<&str> = rest.split_whitespace().collect();
            let ticks =
                fields.get(11)?.parse::<u64>().ok()? + fields.get(12)?.parse::<u64>().ok()?;
            Some(ticks * 10)
        });
        let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
        let peak_rss_kib = status
            .lines()
            .find_map(|l| l.strip_prefix("VmHWM:"))
            .and_then(|v| v.trim().trim_end_matches("kB").trim().parse::<u64>().ok());
        let io = std::fs::read_to_string("/proc/self/io").unwrap_or_default();
        let field = |name: &str| {
            io.lines()
                .find_map(|l| l.strip_prefix(name))
                .and_then(|v| v.trim().parse::<u64>().ok())
        };
        serde_json::json!({
            "cpu_ms": cpu_ms,
            "peak_rss_kib": peak_rss_kib,
            "read_bytes": field("read_bytes:"),
            "write_bytes": field("write_bytes:"),
        })
    }
    #[cfg(not(target_os = "linux"))]
    {
        serde_json::json!({})
    }
}

struct Fleet {
    _dir: tempfile::TempDir,
    store: Store,
    pool: PoolId,
    workers: Vec<WorkerId>,
    tenants: Vec<TenantId>,
    /// `(tenant, job)` → when it was enqueued (all at the start).
    jobs: usize,
}

fn fleet() -> Fleet {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path().join("metadata.sqlite"), Durability::Normal).unwrap();
    let (root, pool) = (UserId::new(), PoolId::new());
    let tenants: Vec<TenantId> = (0..TENANTS).map(|_| TenantId::new()).collect();
    let repos: Vec<Vec<RepoId>> = (0..TENANTS)
        .map(|_| (0..REPOS_PER_TENANT).map(|_| RepoId::new()).collect())
        .collect();
    let (setup_tenants, setup_repos) = (tenants.clone(), repos.clone());
    let workers: Vec<WorkerId> = store
        .writer()
        .write(move |tx| {
            provisioning::insert_human(tx, root, "Root", true, NOW)?;
            tenancy::create_pool(
                tx,
                Authority::HostLocal,
                pool,
                "farm",
                PoolKind::Shared,
                NOW,
            )?;
            for (index, tenant) in setup_tenants.iter().enumerate() {
                auth::create_namespace(
                    tx,
                    Principal::new(root, P::ALL, None, None),
                    *tenant,
                    Namespace::parse(&format!("tenant-{index}")).unwrap(),
                    NamespaceKind::Organization,
                    NOW,
                )?;
                tenancy::grant_pool(tx, Authority::HostLocal, pool, *tenant, NOW)?;
                for (r, repo) in setup_repos[index].iter().enumerate() {
                    sentinel_store::jobs::insert_repo(tx, *tenant, *repo, &format!("r{r}"), NOW)?;
                }
            }
            let negotiated = Negotiated {
                protocol: ProtocolVersion(7),
                capabilities: Capabilities::REQUIRED,
                arch: Arch::X86_64,
            };
            let ssd = vec!["ssd".to_owned()];
            let mut workers = Vec::with_capacity(WORKERS);
            for index in 0..WORKERS {
                let worker = WorkerId::new();
                let issued =
                    workers::issue_enrollment(tx, Authority::HostLocal, pool, 60_000, NOW)?;
                let mut text = String::new();
                issued.secret.expose(&mut text);
                workers::enroll(
                    tx,
                    &Secret::parse(&text).unwrap(),
                    Presentation {
                        worker,
                        fingerprint: Secret::generate().digest(),
                        name: "load",
                        negotiated,
                    },
                    NOW,
                )?;
                dispatch::report_capacity(tx, worker, WORKER_CAPACITY)?;
                let mut host = [0u8; 16];
                host[..4].copy_from_slice(&((index / 2) as u32 + 1).to_be_bytes());
                dispatch::report_profile(
                    tx,
                    worker,
                    &dispatch::ReportedProfile {
                        labels: if index % 2 == 0 { &ssd } else { &[] },
                        host_id: Some(host),
                        avail_images: &[],
                        cache_bytes: None,
                        load_ns: Some(((index % 7) as i64) * 10_000_000),
                    },
                )?;
                workers.push(worker);
            }
            Ok(workers)
        })
        .unwrap();

    // Ten thousand jobs: the noisy tenant (0) owns 70 % of the runs, the
    // three quiet tenants 10 % each; runs round-robin over each tenant's
    // repositories.
    let plain = RunSpec::new(
        PinnedSource::new("https://github.com/o/r.git", SHA, Some("refs/heads/main")).unwrap(),
        compile_str(&run_yaml(false)).unwrap(),
    )
    .unwrap();
    let labeled = RunSpec::new(
        PinnedSource::new("https://github.com/o/r.git", SHA, Some("refs/heads/main")).unwrap(),
        compile_str(&run_yaml(true)).unwrap(),
    )
    .unwrap();
    let (create_tenants, create_repos) = (tenants.clone(), repos.clone());
    let jobs = store
        .writer()
        .write(move |tx| {
            let mut jobs = 0;
            for index in 0..RUNS {
                let t = if index % 10 < 7 { 0 } else { 1 + index % 3 };
                let (tenant, repo) = (create_tenants[t], create_repos[t][index % REPOS_PER_TENANT]);
                let spec = if index % LABELED_EVERY == 0 {
                    &labeled
                } else {
                    &plain
                };
                let run = RunId::new();
                let ids = runs::create_run(tx, tenant, repo, run, spec, NOW)?;
                for job in &ids {
                    runs::resolve_image(tx, tenant, *job, DIGEST, "linux/amd64")?;
                }
                if index % PR_EVERY == 0 {
                    provenance::insert(
                        tx,
                        &Provenance {
                            tenant,
                            repo,
                            trigger: "pull_request".to_owned(),
                            delivery: None,
                            provider: None,
                            ref_name: Some("refs/pull/1/merge".to_owned()),
                            old_sha: None,
                            new_sha: None,
                            head_sha: None,
                            base_sha: None,
                            merge_sha: None,
                            pipeline_sha: SHA.to_owned(),
                            pipeline_path: None,
                            pipeline_digest: [0u8; 16],
                            pr_number: Some(1),
                        },
                        run,
                        NOW,
                    )?;
                }
                jobs += ids.len();
            }
            Ok(jobs)
        })
        .unwrap();
    Fleet {
        _dir: dir,
        store,
        pool,
        workers,
        tenants,
        jobs,
    }
}

#[test]
#[ignore = "Q09 10k-job load: cargo test --release -p sentinel-store --test fleet_load -- --ignored --nocapture"]
fn one_hundred_workers_drain_ten_thousand_jobs_with_bounded_runtime() {
    let f = fleet();
    assert_eq!(f.jobs, JOBS);
    let pool = f.pool;
    eprintln!("setup done: {JOBS} jobs queued");

    let started = Instant::now();
    let mut placed: HashSet<JobId> = HashSet::with_capacity(JOBS);
    let mut latencies: Vec<u64> = Vec::with_capacity(JOBS);
    let mut waits: Vec<u64> = Vec::with_capacity(JOBS);
    let mut first_wave: HashMap<TenantId, usize> = HashMap::new();
    let (mut waves, mut rounds) = (0usize, 0usize);
    while placed.len() < JOBS {
        waves += 1;
        assert!(
            waves <= 64,
            "placement stalled at {} of {JOBS}",
            placed.len()
        );
        // Fill: rounds of one placement per still-hungry worker, one writer
        // transaction per round, held — as the controller's pass does.
        let mut active = f.workers.clone();
        let mut held: Vec<(WorkerId, dispatch::Offer)> = Vec::new();
        while !active.is_empty() {
            rounds += 1;
            let round = active.clone();
            let (offers, times) = f
                .store
                .writer()
                .write(move |tx| {
                    let mut offers = Vec::with_capacity(round.len());
                    let mut times = Vec::with_capacity(round.len());
                    for worker in round {
                        let begun = Instant::now();
                        let offer =
                            dispatch::place(tx, worker, pool, dispatch::DEFAULT_LEASE_MS, NOW)?;
                        times.push(begun.elapsed().as_nanos() as u64);
                        if let Some(offer) = &offer {
                            dispatch::acknowledge(tx, worker, offer.attempt, offer.fence, NOW)?;
                        }
                        offers.push((worker, offer));
                    }
                    Ok((offers, times))
                })
                .unwrap();
            latencies.extend(times);
            let wait = started.elapsed().as_nanos() as u64;
            for (worker, offer) in offers {
                match offer {
                    Some(offer) => {
                        assert!(placed.insert(offer.job), "job {:?} placed twice", offer.job);
                        waits.push(wait);
                        if waves == 1 {
                            *first_wave.entry(offer.tenant).or_default() += 1;
                        }
                        held.push((worker, offer));
                    }
                    None => active.retain(|w| *w != worker),
                }
            }
        }
        assert!(
            !held.is_empty(),
            "wave {waves} placed nothing with {} left",
            JOBS - placed.len()
        );
        // Capacity really was held: no host went negative.
        for worker in &f.workers {
            let worker = *worker;
            let free = f
                .store
                .read(move |c| dispatch::free_capacity(c, worker))
                .unwrap();
            assert!(free.cpu_millis >= 0 && free.memory_bytes >= 0, "{free:?}");
        }
        eprintln!(
            "wave {waves}: {} held, {} of {JOBS} placed after {:?}",
            held.len(),
            placed.len(),
            started.elapsed()
        );
        // Complete the wave: every held attempt ends, its reservation frees.
        for chunk in held.chunks(256) {
            let chunk: Vec<(WorkerId, dispatch::Offer)> = chunk.to_vec();
            f.store
                .writer()
                .write(move |tx| {
                    for (worker, offer) in chunk {
                        dispatch::report(
                            tx,
                            worker,
                            offer.attempt,
                            offer.fence,
                            Event::Failed(FailureClass::Preparation),
                            None,
                            NOW,
                            None,
                        )?;
                    }
                    Ok(())
                })
                .unwrap();
        }
    }
    let elapsed = started.elapsed();
    assert_eq!(placed.len(), JOBS);

    // Fairness is observable here because demand exceeds one wave: each
    // quiet tenant (10 % of the jobs) got at least its share of the first.
    let first_total: usize = first_wave.values().sum();
    for tenant in &f.tenants[1..] {
        let share = first_wave.get(tenant).copied().unwrap_or(0);
        assert!(
            share * 10 >= first_total,
            "a quiet tenant got {share} of the first wave's {first_total}"
        );
    }

    latencies.sort_unstable();
    waits.sort_unstable();
    let us = |v: &[u64], p: f64| percentile(v, p) / 1_000;
    let ms = |v: &[u64], p: f64| percentile(v, p) / 1_000_000;
    let report = serde_json::json!({
        "test": "sentinel-store/tests/fleet_load.rs",
        "workers": WORKERS,
        "hosts": WORKERS / 2,
        "tenants": TENANTS,
        "repos": TENANTS * REPOS_PER_TENANT,
        "jobs": JOBS,
        "pull_request_runs": RUNS / PR_EVERY,
        "labeled_runs": RUNS.div_ceil(LABELED_EVERY),
        "placed_jobs": placed.len(),
        "waves": waves,
        "rounds": rounds,
        "placement_calls": latencies.len(),
        "placement_failures": 0,
        "placement_us": {
            "p50": us(&latencies, 0.50), "p95": us(&latencies, 0.95),
            "p99": us(&latencies, 0.99), "max": us(&latencies, 1.0)
        },
        "queue_wait_ms": {
            "p50": ms(&waits, 0.50), "p95": ms(&waits, 0.95),
            "p99": ms(&waits, 0.99), "max": ms(&waits, 1.0)
        },
        "first_wave_by_tenant": f.tenants.iter()
            .map(|t| first_wave.get(t).copied().unwrap_or(0))
            .collect::<Vec<_>>(),
        "throughput_jobs_per_s": (JOBS as f64 / elapsed.as_secs_f64()).round() as u64,
        "elapsed_ms": elapsed.as_millis() as u64,
        "process": process_usage(),
    });
    println!("{report}");
    if let Ok(path) = std::env::var("SENTINEL_BENCH_OUT") {
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .unwrap();
        writeln!(file, "{report}").unwrap();
    }

    // A ceiling to catch a quadratic placement scan or a stalled wave, not
    // a latency claim; measured numbers are in bench/q09-fleet-load.jsonl.
    const BOUND: Duration = Duration::from_secs(180);
    assert!(
        elapsed < BOUND,
        "placement took {elapsed:?} for {JOBS} jobs in {waves} waves: {report}"
    );
}

/// P08-8's measurement: `GET /queue`'s store work for a tenant with 5,000
/// queued jobs and 20 connected 8-core workers, at the route's default and
/// maximum page sizes. Before the fix the listing explained every waiting
/// job before the route cut it (9.5 s here in the audit); now the page is
/// cut in the query and only its jobs are explained.
#[test]
#[ignore = "P08-8 listing cost: cargo test --release -p sentinel-store --test fleet_load -- --ignored --nocapture"]
fn listing_a_five_thousand_job_queue_explains_only_the_page() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path().join("metadata.sqlite"), Durability::Normal).unwrap();
    let (root, tenant, repo, pool) = (UserId::new(), TenantId::new(), RepoId::new(), PoolId::new());
    let spec = RunSpec::new(
        PinnedSource::new("https://github.com/o/r.git", SHA, Some("refs/heads/main")).unwrap(),
        compile_str(&run_yaml(false)).unwrap(),
    )
    .unwrap();
    let connected: Vec<WorkerId> = store
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
            sentinel_store::jobs::insert_repo(tx, tenant, repo, "app", NOW)?;
            tenancy::create_pool(
                tx,
                Authority::HostLocal,
                pool,
                "farm",
                PoolKind::Dedicated(tenant),
                NOW,
            )?;
            let mut workers = Vec::new();
            for _ in 0..20 {
                let worker = WorkerId::new();
                let issued =
                    workers::issue_enrollment(tx, Authority::HostLocal, pool, 60_000, NOW)?;
                let mut text = String::new();
                issued.secret.expose(&mut text);
                workers::enroll(
                    tx,
                    &Secret::parse(&text).unwrap(),
                    Presentation {
                        worker,
                        fingerprint: Secret::generate().digest(),
                        name: "w",
                        negotiated: Negotiated {
                            protocol: ProtocolVersion(7),
                            capabilities: Capabilities::REQUIRED,
                            arch: Arch::X86_64,
                        },
                    },
                    NOW,
                )?;
                dispatch::report_capacity(
                    tx,
                    worker,
                    dispatch::Capacity {
                        cpu_millis: 8_000,
                        memory_bytes: 64 << 30,
                        disk_bytes: 100 << 30,
                    },
                )?;
                workers.push(worker);
            }
            for _ in 0..100 {
                for job in runs::create_run(tx, tenant, repo, RunId::new(), &spec, NOW)? {
                    runs::resolve_image(tx, tenant, job, DIGEST, "linux/amd64")?;
                }
            }
            Ok(workers)
        })
        .unwrap();
    let mut report = serde_json::Map::new();
    for limit in [100usize, 500] {
        let connected = connected.clone();
        let started = Instant::now();
        let page = store
            .read(move |c| dispatch::list_queue(c, tenant, &connected, limit))
            .unwrap();
        let took = started.elapsed();
        assert_eq!((page.jobs.len(), page.total), (limit, 5_000));
        report.insert(
            format!("limit_{limit}_us"),
            serde_json::json!(took.as_micros() as u64),
        );
    }
    let report = serde_json::json!({
        "test": "sentinel-store/tests/fleet_load.rs::listing",
        "queued_jobs": 5_000,
        "connected_workers": 20,
        "list_queue": report,
    });
    println!("{report}");
    if let Ok(path) = std::env::var("SENTINEL_BENCH_OUT") {
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .unwrap();
        writeln!(file, "{report}").unwrap();
    }
}
