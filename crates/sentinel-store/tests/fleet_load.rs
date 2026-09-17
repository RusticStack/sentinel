//! Q09: store-level placement load. One hundred worker rows and ten
//! thousand queued jobs, placed in rounds: each round fills every worker to
//! its free capacity, acknowledges the offers and retires them as
//! preparation failures so the reservation comes back and the next round can
//! place the rest. The test proves no job starves, measures per-placement
//! latency (p50/p95/p99, printed as JSON) and bounds the wall time.
//!
//! Nothing here runs a container, checkout or step: this is the scheduler
//! and the SQLite write path under load, not executor evidence.

use std::{
    collections::HashSet,
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
    dispatch, runs,
    tenancy::{self, PoolKind},
    workers::{self, Presentation},
};

const WORKERS: usize = 100;
const RUNS: usize = 200;
const JOBS_PER_RUN: usize = 50;
/// 200 runs of 50 jobs: ten thousand queued jobs, each a quarter core.
const JOBS: usize = RUNS * JOBS_PER_RUN;
const NOW: UnixMillis = UnixMillis(1_000);
const SHA: &str = "0123456789abcdef0123456789abcdef01234567";
const DIGEST: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

/// A worker big enough for eight jobs at a time by cpu, and 64 by the
/// held-attempt cap; disk is reported so disk-bearing jobs are never soft.
const WORKER_CAPACITY: dispatch::Capacity = dispatch::Capacity {
    cpu_millis: 8_000,
    memory_bytes: 8 << 30,
    disk_bytes: 64 << 30,
};

fn run_yaml() -> String {
    let mut yaml = String::from("schema: 1\non: [push]\njobs:\n");
    for i in 0..JOBS_PER_RUN {
        yaml.push_str(&format!(
            "  j{i:03}:\n    image: alpine:3\n    resources: {{ cpu: \"0.25\", memory: 128MiB, disk: 1GiB }}\n    steps: [{{ id: s, run: 'true' }}]\n"
        ));
    }
    yaml
}

fn percentile(sorted: &[u64], p: f64) -> u64 {
    let index = (((sorted.len() - 1) as f64) * p).round() as usize;
    sorted[index]
}

#[test]
#[ignore = "Q09 10k-job load: cargo test -p sentinel-store --test fleet_load -- --ignored --nocapture"]
fn one_hundred_workers_drain_ten_thousand_jobs_with_bounded_runtime() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path().join("metadata.sqlite"), Durability::Normal).unwrap();
    let (root, tenant, repo, pool) = (UserId::new(), TenantId::new(), RepoId::new(), PoolId::new());
    let workers: Vec<WorkerId> = store
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
            let negotiated = Negotiated {
                protocol: ProtocolVersion(7),
                capabilities: Capabilities::REQUIRED,
                arch: Arch::X86_64,
            };
            let mut workers = Vec::with_capacity(WORKERS);
            for _ in 0..WORKERS {
                let worker = WorkerId::new();
                let fingerprint = Secret::generate().digest();
                let issued =
                    workers::issue_enrollment(tx, Authority::HostLocal, pool, 60_000, NOW)?;
                let mut text = String::new();
                issued.secret.expose(&mut text);
                workers::enroll(
                    tx,
                    &Secret::parse(&text).unwrap(),
                    Presentation {
                        worker,
                        fingerprint,
                        name: "load",
                        negotiated,
                    },
                    NOW,
                )?;
                dispatch::report_capacity(tx, worker, WORKER_CAPACITY)?;
                workers.push(worker);
            }
            Ok(workers)
        })
        .unwrap();
    assert_eq!(workers.len(), WORKERS);

    // Ten thousand jobs in one hundred runs, all queued and image-resolved.
    let spec = RunSpec::new(
        PinnedSource::new("https://github.com/o/r.git", SHA, Some("refs/heads/main")).unwrap(),
        compile_str(&run_yaml()).unwrap(),
    )
    .unwrap();
    let created: Vec<Vec<JobId>> = store
        .writer()
        .write(move |tx| {
            let mut created = Vec::with_capacity(RUNS);
            for _ in 0..RUNS {
                let ids = runs::create_run(tx, tenant, repo, RunId::new(), &spec, NOW)?;
                for job in &ids {
                    runs::resolve_image(tx, tenant, *job, DIGEST, "linux/amd64")?;
                }
                created.push(ids);
            }
            Ok(created)
        })
        .unwrap();
    assert_eq!(created.len(), RUNS);
    assert!(created.iter().all(|ids| ids.len() == JOBS_PER_RUN));

    // Round after round, fill every worker to its free capacity, take the
    // offers and retire the attempts; the reservation returns and the next
    // round places more. Every job placed exactly once is the no-starvation
    // property; a stalled round fails rather than spinning.
    let started = Instant::now();
    let mut placed: HashSet<JobId> = HashSet::with_capacity(JOBS);
    let mut latencies: Vec<u64> = Vec::with_capacity(JOBS);
    let mut rounds = 0usize;
    while placed.len() < JOBS {
        rounds += 1;
        assert!(
            rounds <= 256,
            "placement stalled after {rounds} rounds at {} of {JOBS}",
            placed.len()
        );
        let mut progress = 0usize;
        for worker in &workers {
            let worker = *worker;
            let (jobs, mut times) = store
                .writer()
                .write(move |tx| {
                    let mut jobs = Vec::new();
                    let mut times = Vec::new();
                    for _ in 0..dispatch::MAX_HELD_ATTEMPTS {
                        let begun = Instant::now();
                        let Some(offer) =
                            dispatch::place(tx, worker, pool, dispatch::DEFAULT_LEASE_MS, NOW)?
                        else {
                            break;
                        };
                        times.push(begun.elapsed().as_nanos() as u64);
                        // A real worker acknowledges, then fails preparation:
                        // the one terminal report that frees capacity without
                        // pretending any work ran.
                        dispatch::acknowledge(tx, worker, offer.attempt, offer.fence, NOW)?;
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
                        jobs.push(offer.job);
                    }
                    Ok((jobs, times))
                })
                .unwrap();
            progress += jobs.len();
            latencies.append(&mut times);
            for job in jobs {
                assert!(placed.insert(job), "job {job:?} placed twice");
            }
        }
        assert!(
            progress > 0,
            "round {rounds} placed nothing with {} of {JOBS} jobs left",
            placed.len()
        );
    }
    let elapsed = started.elapsed();
    assert_eq!(placed.len(), JOBS);
    assert_eq!(latencies.len(), JOBS);

    latencies.sort_unstable();
    let us = |p: f64| percentile(&latencies, p) / 1_000;
    let report = serde_json::json!({
        "workers": WORKERS,
        "jobs": JOBS,
        "placed_jobs": placed.len(),
        "rounds": rounds,
        "placement_calls": latencies.len(),
        "placement_us": { "p50": us(0.50), "p95": us(0.95), "p99": us(0.99) },
        "elapsed_ms": elapsed.as_millis() as u64,
    });
    println!("{report}");

    // A generous ceiling for a debug build on a laptop: it is here to catch
    // a quadratic placement scan, a lost wake or a stalled round, not to
    // measure micro-latency.
    assert!(
        elapsed < Duration::from_secs(120),
        "placement took {elapsed:?} for {JOBS} jobs in {rounds} rounds: {report}"
    );
}
