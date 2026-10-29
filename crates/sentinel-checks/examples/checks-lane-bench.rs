//! Latency from enqueueing a run's checks to their delivery by the checks lane.
//!
//! Each sample records a run on a real `Store` (`runs::create_run` plus `checks::record_run`, the writes the
//! controller makes when a run starts), with the real `Lane` and `GithubChecks` publisher running against a
//! fake GitHub endpoint on loopback, and times the gap from the start of that write to the moment the fake
//! endpoint receives the run's queued check-run creations. It prints one `sentinel-bench/checks-lane/1` JSON
//! line (`docs/benchmarking.md#checks-lane-delivery-latency`); `bench/checks-lane.sh` adds the `build` and
//! `host` stamp.
//!
//!     cargo run --release -p sentinel-checks --example checks-lane-bench -- --dir /srv/bench --rounds 5
//!
//! A sample is one burst: `burst` runs recorded back to back, then every run waited for. Each (round, burst)
//! gets a fresh store, fake endpoint and lane; one unmeasured run goes first so the installation lookup and
//! the token mint are reported as `cold_first_run_ns` and not pooled with the steady state. The order of the
//! burst sizes reverses every round (ABBA). The fake endpoint answers at once unless `--github-ms` adds a
//! fixed delay to every reply, so the figures are the Sentinel side of the path; they say nothing of GitHub.

use std::{
    collections::HashMap,
    fs,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::PathBuf,
    process::ExitCode,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use sentinel_auth::sealed::Key;
use sentinel_checks::{Lane, github::GithubChecks, lane::Config};
use sentinel_core::{
    RepoId, RunId, TenantId, UnixMillis, UserId,
    auth::{Namespace, Permissions, Principal},
};
use sentinel_pipeline::{PinnedSource, RunSpec, compile_str};
use sentinel_protocol::source::{Binding, Credential};
use sentinel_store::{
    Durability, Store,
    auth::{self, NamespaceKind, provisioning},
    checks,
    provenance::{self, Provenance},
    registration::{self, Authority},
    runs, sources,
    sources_forge::{self, Snapshot},
};

/// A test-only RSA key generated fresh for this process with the `openssl` CLI; it authenticates nothing and no
/// private key is committed (see `no_committed_keys` in the `sentinel` crate tests).
fn test_key() -> &'static str {
    static KEY: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    KEY.get_or_init(|| {
        let out = std::process::Command::new("openssl")
            .args([
                "genpkey",
                "-algorithm",
                "RSA",
                "-pkeyopt",
                "rsa_keygen_bits:2048",
            ])
            .output()
            .expect("the openssl CLI must be installed to generate the test-only App key");
        assert!(out.status.success(), "openssl genpkey failed");
        String::from_utf8(out.stdout).expect("PEM is ASCII")
    })
}

const REF: &str = "refs/heads/main";
const SHA_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const SHA_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const GITHUB_REPO_ID: u64 = 91;
const INSTALLATION: u64 = 42;
const ACCOUNT: u64 = 73;
const IMAGE: &str = "docker.io/library/busybox@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662";
/// A run of the pipeline below queues an aggregate check and one per job.
const CHECKS_PER_RUN: usize = 2;
const WAIT: Duration = Duration::from_secs(60);

struct Args {
    dir: PathBuf,
    rounds: usize,
    runs: usize,
    bursts: Vec<usize>,
    github_ms: u64,
    idle_ms: Option<u64>,
}

fn parse() -> Result<Args, String> {
    let mut args = Args {
        dir: PathBuf::new(),
        rounds: 5,
        runs: 16,
        bursts: vec![1, 8],
        github_ms: 0,
        idle_ms: None,
    };
    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        let mut value = |name: &str| it.next().ok_or(format!("{name} needs a value"));
        match flag.as_str() {
            "--dir" => args.dir = PathBuf::from(value("--dir")?),
            "--rounds" => args.rounds = number(&value("--rounds")?)?,
            "--runs" => args.runs = number(&value("--runs")?)?,
            "--github-ms" => args.github_ms = number(&value("--github-ms")?)?,
            "--idle-ms" => args.idle_ms = Some(number(&value("--idle-ms")?)?),
            "--bursts" => {
                args.bursts = value("--bursts")?
                    .split(',')
                    .map(number)
                    .collect::<Result<_, _>>()?;
            }
            other => return Err(format!("unknown argument {other}")),
        }
    }
    if args.dir.as_os_str().is_empty() {
        return Err("--dir is required: the store lives on the file system under test".into());
    }
    if args.rounds == 0 || args.runs == 0 || args.bursts.is_empty() || args.bursts.contains(&0) {
        return Err("--rounds, --runs and every burst must be positive".into());
    }
    if args.bursts.iter().any(|&b| b > args.runs) {
        return Err("a burst cannot be larger than --runs".into());
    }
    Ok(args)
}

fn number<T: std::str::FromStr>(text: &str) -> Result<T, String> {
    text.trim()
        .parse()
        .map_err(|_| format!("{text:?} is not a number"))
}

// ---- the fake GitHub endpoint ----------------------------------------------

/// Arrival times of the check-run creations, by the run named in their `external_id`.
type Arrivals = Arc<Mutex<HashMap<String, Vec<Instant>>>>;

struct Stub {
    addr: std::net::SocketAddr,
    arrivals: Arrivals,
    stop: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}

impl Stub {
    fn start(delay: Duration) -> std::io::Result<Stub> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let addr = listener.local_addr()?;
        let arrivals: Arrivals = Arc::default();
        let stop = Arc::new(AtomicBool::new(false));
        let thread = {
            let (arrivals, stop) = (Arc::clone(&arrivals), Arc::clone(&stop));
            thread::spawn(move || {
                let next_id = Arc::new(Mutex::new(500i64));
                while !stop.load(Ordering::Acquire) {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            let _ = stream.set_nonblocking(false);
                            let (arrivals, next_id) = (Arc::clone(&arrivals), Arc::clone(&next_id));
                            thread::spawn(move || serve(stream, &arrivals, &next_id, delay));
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(1));
                        }
                        Err(_) => break,
                    }
                }
            })
        };
        Ok(Stub {
            addr,
            arrivals,
            stop,
            thread: Some(thread),
        })
    }
}

impl Drop for Stub {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn serve(mut stream: TcpStream, arrivals: &Arrivals, next_id: &Mutex<i64>, delay: Duration) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(30)));
    while let Some((method, path, body)) = read_request(&mut stream) {
        let arrived = Instant::now();
        if !delay.is_zero() {
            thread::sleep(delay);
        }
        if method == "POST" && path.contains("/check-runs") {
            let parsed: serde_json::Value =
                serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null);
            if let Some(run) = parsed["external_id"]
                .as_str()
                .and_then(|id| id.split(':').nth(1))
            {
                arrivals
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .entry(run.to_owned())
                    .or_default()
                    .push(arrived);
            }
        }
        let (status, reply) = reply(&method, &path, next_id);
        let text = reply.to_string();
        let head = format!(
            "HTTP/1.1 {status} X\r\ncontent-length: {}\r\nconnection: keep-alive\r\ncontent-type: application/json\r\n\r\n",
            text.len()
        );
        if stream.write_all(head.as_bytes()).is_err() || stream.write_all(text.as_bytes()).is_err()
        {
            return;
        }
    }
}

fn read_request(stream: &mut TcpStream) -> Option<(String, String, Vec<u8>)> {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 4096];
    let header_end = loop {
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => return None,
            Ok(n) => buffer.extend_from_slice(&chunk[..n]),
        }
        if let Some(at) = buffer.windows(4).position(|w| w == b"\r\n\r\n") {
            break at;
        }
    };
    let head = String::from_utf8_lossy(&buffer[..header_end]).to_string();
    let mut lines = head.lines();
    let request = lines.next().unwrap_or_default().to_owned();
    let mut parts = request.split_whitespace();
    let method = parts.next().unwrap_or_default().to_owned();
    let path = parts.next().unwrap_or_default().to_owned();
    let length = lines
        .filter_map(|line| line.split_once(':'))
        .find(|(k, _)| k.trim().eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.trim().parse::<usize>().ok())
        .unwrap_or(0);
    let mut body = buffer[header_end + 4..].to_vec();
    while body.len() < length {
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => body.extend_from_slice(&chunk[..n]),
        }
    }
    Some((method, path, body))
}

fn reply(method: &str, path: &str, next_id: &Mutex<i64>) -> (u16, serde_json::Value) {
    let expires = time_in_an_hour();
    if method == "GET" && path.contains(&format!("/app/installations/{INSTALLATION}")) {
        return (
            200,
            serde_json::json!({
                "id": INSTALLATION,
                "app_id": 1234,
                "account": {"id": ACCOUNT, "login": "account", "type": "Organization"},
                "suspended_at": null,
                "permissions": {"contents": "read", "checks": "write"},
            }),
        );
    }
    if method == "POST" && path.contains("/access_tokens") {
        return (
            201,
            serde_json::json!({
                "token": "ghs_bench",
                "expires_at": expires,
                "permissions": {"checks": "write", "metadata": "read"},
            }),
        );
    }
    if method == "GET" && path.contains(&format!("/repositories/{GITHUB_REPO_ID}")) {
        return (
            200,
            serde_json::json!({
                "id": GITHUB_REPO_ID,
                "owner": {"id": ACCOUNT},
                "clone_url": "https://github.com/account/app.git",
            }),
        );
    }
    if method == "GET" && path.contains("/check-runs") {
        return (200, serde_json::json!({"total_count": 0, "check_runs": []}));
    }
    if method == "POST" && path.contains("/check-runs") {
        let mut id = next_id.lock().unwrap_or_else(|p| p.into_inner());
        *id += 1;
        return (
            201,
            serde_json::json!({"id": *id, "check_suite": {"id": 7001}}),
        );
    }
    if method == "PATCH" && path.contains("/check-runs/") {
        let id: i64 = path
            .rsplit('/')
            .next()
            .and_then(|tail| tail.split('?').next())
            .and_then(|tail| tail.parse().ok())
            .unwrap_or(0);
        return (
            200,
            serde_json::json!({"id": id, "check_suite": {"id": 7002}}),
        );
    }
    (404, serde_json::json!({"message": "not found"}))
}

/// RFC 3339 for one hour from now, without a date library: the token only has to outlive the sample.
fn time_in_an_hour() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
        + 3600;
    let (days, rem) = (secs / 86_400, secs % 86_400);
    // Civil-from-days (Howard Hinnant).
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        (rem / 60) % 60,
        rem % 60
    )
}

// ---- the controller side ----------------------------------------------------

struct Fixture {
    store: Arc<Store>,
    tenant: TenantId,
    repo: RepoId,
}

fn fixture(dir: &std::path::Path, app_endpoint: &str) -> Result<(Fixture, GithubChecks), String> {
    let key_path = dir.join("master.key");
    Key::create(&key_path).map_err(|e| format!("key: {e:?}"))?;
    let key = Key::load(&key_path).map_err(|e| format!("key: {e:?}"))?;
    let store = Arc::new(
        Store::open(dir.join("metadata.sqlite"), Durability::Normal)
            .map_err(|e| format!("store: {e:?}"))?,
    );
    let app = Arc::new(
        sentinel_github::app::App::new(1234, test_key())
            .map_err(|e| format!("app: {e:?}"))?
            .with_endpoint(app_endpoint)
            .map_err(|e| format!("endpoint: {e:?}"))?,
    );
    let (alice, tenant, repo) = (
        Principal::new(UserId::new(), Permissions::ALL, None, None),
        TenantId::new(),
        RepoId::new(),
    );
    let now = UnixMillis::now();
    store
        .writer()
        .write(move |tx| {
            provisioning::insert_human(tx, alice.user, "alice", true, now)?;
            auth::create_namespace(
                tx,
                alice,
                tenant,
                Namespace::parse("acme").unwrap(),
                NamespaceKind::Personal(alice.user),
                now,
            )?;
            auth::create_repo(tx, alice, tenant, repo, "app", now)?;
            let installation = sources_forge::refresh(
                tx,
                Snapshot {
                    external_id: INSTALLATION,
                    account_id: ACCOUNT,
                    login: "account",
                    personal: false,
                    suspended: false,
                    permissions_valid: true,
                    expected: 0,
                },
                now,
            )?;
            registration::bind_installation_trusted(tx, installation, tenant, now)?;
            sources::bind(
                tx,
                Authority::HostLocal,
                Some(alice.user),
                sources::Update {
                    repo,
                    expected: 0,
                    binding: &Binding {
                        remote: "https://github.com/account/app.git".into(),
                        allowed_refs: vec![REF.into()],
                        pipeline_path: ".sentinel.yml".into(),
                        trust: String::new(),
                    },
                    credential: &Credential::Public,
                    forge: Some((installation, GITHUB_REPO_ID)),
                },
                &["https://github.com".into()],
                &key,
                now,
            )?;
            Ok(())
        })
        .map_err(|e| format!("provision: {e:?}"))?;
    let publisher = GithubChecks::new(Arc::clone(&store), app, Some("https://ci.example".into()));
    Ok((
        Fixture {
            store,
            tenant,
            repo,
        },
        publisher,
    ))
}

fn spec() -> Result<RunSpec, String> {
    let yaml = format!(
        "schema: 1\non: [push]\njobs:\n  build:\n    image: {IMAGE}\n    steps: [{{ id: s, run: 'true' }}]\n"
    );
    RunSpec::new(
        PinnedSource::new("https://github.com/account/app.git", SHA_B, Some(REF))
            .map_err(|e| format!("source: {e:?}"))?,
        compile_str(&yaml).map_err(|e| format!("pipeline: {e:?}"))?,
    )
    .map_err(|e| format!("spec: {e:?}"))
}

/// Records one run and its provenance, the way a push event does; returns the run and the write's duration.
fn enqueue(f: &Fixture, spec: &RunSpec) -> Result<(RunId, Instant, Duration), String> {
    let (tenant, repo) = (f.tenant, f.repo);
    let run = RunId::new();
    let spec = spec.clone();
    let started = Instant::now();
    f.store
        .writer()
        .write(move |tx| {
            let now = UnixMillis::now();
            runs::create_run(tx, tenant, repo, run, &spec, now)?;
            provenance::insert(
                tx,
                &Provenance {
                    tenant,
                    repo,
                    trigger: "push".into(),
                    delivery: None,
                    provider: None,
                    ref_name: Some(REF.into()),
                    old_sha: Some(SHA_A.into()),
                    new_sha: Some(SHA_B.into()),
                    head_sha: None,
                    base_sha: None,
                    merge_sha: None,
                    pipeline_sha: SHA_B.into(),
                    pipeline_path: Some(".sentinel.yml".into()),
                    pipeline_digest: spec.pipeline.digest.to_le_bytes(),
                    pr_number: None,
                },
                run,
                now,
            )?;
            checks::record_run(tx, tenant, run, now)?;
            Ok(())
        })
        .map_err(|e| format!("enqueue: {e:?}"))?;
    Ok((run, started, started.elapsed()))
}

/// Waits for the fake endpoint to have received every check of the runs; returns each run's arrivals.
fn await_delivery(stub: &Stub, runs: &[RunId]) -> Result<Vec<Vec<Instant>>, String> {
    let deadline = Instant::now() + WAIT;
    loop {
        let got = {
            let arrivals = stub.arrivals.lock().unwrap_or_else(|p| p.into_inner());
            runs.iter()
                .map(|run| arrivals.get(&run.to_string()).cloned().unwrap_or_default())
                .collect::<Vec<_>>()
        };
        if got.iter().all(|a| a.len() >= CHECKS_PER_RUN) {
            return Ok(got);
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "timed out after {WAIT:?}: runs have {:?} of {CHECKS_PER_RUN} checks delivered",
                got.iter().map(Vec::len).collect::<Vec<_>>()
            ));
        }
        thread::sleep(Duration::from_micros(500));
    }
}

#[derive(Default)]
struct Sample {
    cold_first_run_ns: u64,
    first_ns: Vec<u64>,
    all_ns: Vec<u64>,
    write_ns: Vec<u64>,
}

fn sample(args: &Args, burst: usize, scratch: &std::path::Path) -> Result<Sample, String> {
    fs::create_dir_all(scratch).map_err(|e| format!("scratch: {e}"))?;
    let stub =
        Stub::start(Duration::from_millis(args.github_ms)).map_err(|e| format!("stub: {e}"))?;
    let (f, publisher) = fixture(scratch, &format!("http://{}", stub.addr))?;
    let spec = spec()?;
    let mut config = Config::default();
    if let Some(ms) = args.idle_ms {
        config.idle = Duration::from_millis(ms);
    }
    let lane = Lane::start(Arc::clone(&f.store), Box::new(publisher), config, |_| {});

    let mut out = Sample::default();
    // The unmeasured first run: it pays for the installation lookup and the token mint.
    let (run, started, _) = enqueue(&f, &spec)?;
    let arrivals = await_delivery(&stub, &[run])?;
    out.cold_first_run_ns = ns(arrivals[0][CHECKS_PER_RUN - 1].saturating_duration_since(started));

    for _ in 0..args.runs / burst {
        let mut queued = Vec::with_capacity(burst);
        for _ in 0..burst {
            let (run, started, write) = enqueue(&f, &spec)?;
            out.write_ns.push(ns(write));
            queued.push((run, started));
        }
        let ids: Vec<RunId> = queued.iter().map(|(run, _)| *run).collect();
        let arrivals = await_delivery(&stub, &ids)?;
        for ((_, started), arrived) in queued.iter().zip(&arrivals) {
            let mut arrived = arrived.clone();
            arrived.sort_unstable();
            out.first_ns
                .push(ns(arrived[0].saturating_duration_since(*started)));
            out.all_ns.push(ns(
                arrived[CHECKS_PER_RUN - 1].saturating_duration_since(*started)
            ));
        }
    }
    drop(lane);
    Ok(out)
}

fn ns(d: Duration) -> u64 {
    u64::try_from(d.as_nanos()).unwrap_or(u64::MAX)
}

fn percentile(sorted: &[u64], p: f64) -> u64 {
    // Nearest rank.
    let rank = ((p * sorted.len() as f64).ceil() as usize).clamp(1, sorted.len());
    sorted[rank - 1]
}

fn summary(values: &[u64]) -> serde_json::Value {
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    serde_json::json!({
        "count": sorted.len(),
        "min": sorted[0],
        "median": percentile(&sorted, 0.5),
        "p95": percentile(&sorted, 0.95),
        "max": sorted[sorted.len() - 1],
    })
}

fn run() -> Result<(), String> {
    let args = parse()?;
    fs::create_dir_all(&args.dir).map_err(|e| format!("--dir: {e}"))?;
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let scratch = args
        .dir
        .join(format!("checks-lane-bench-{}-{stamp}", std::process::id()));
    let mut by_burst: Vec<Vec<Sample>> = args.bursts.iter().map(|_| Vec::new()).collect();
    let mut order_log = Vec::new();
    let outcome = (|| -> Result<(), String> {
        for round in 0..args.rounds {
            let mut order: Vec<usize> = (0..args.bursts.len()).collect();
            if round % 2 == 1 {
                order.reverse();
            }
            order_log.push(order.iter().map(|&i| args.bursts[i]).collect::<Vec<_>>());
            for i in order {
                let root = scratch.join(format!("r{round}-b{}", args.bursts[i]));
                let result = sample(&args, args.bursts[i], &root);
                let _ = fs::remove_dir_all(&root);
                by_burst[i].push(result?);
            }
        }
        Ok(())
    })();
    let _ = fs::remove_dir_all(&scratch);
    outcome?;

    let results: Vec<serde_json::Value> = args
        .bursts
        .iter()
        .zip(&by_burst)
        .map(|(&burst, samples)| {
            let pool = |pick: fn(&Sample) -> &Vec<u64>| -> Vec<u64> {
                samples.iter().flat_map(|s| pick(s).iter().copied()).collect()
            };
            serde_json::json!({
                "burst_runs": burst,
                "runs_per_round": (args.runs / burst) * burst,
                "cold_first_run_ns": samples.iter().map(|s| s.cold_first_run_ns).collect::<Vec<_>>(),
                "enqueue_to_first_check_ns": summary(&pool(|s| &s.first_ns)),
                "enqueue_to_all_checks_ns": summary(&pool(|s| &s.all_ns)),
                "enqueue_write_ns": summary(&pool(|s| &s.write_ns)),
            })
        })
        .collect();
    let record = serde_json::json!({
        "schema": "sentinel-bench/checks-lane/1",
        "workload": "checks-lane",
        "started_at_unix_ms": (stamp / 1_000_000) as u64,
        "rounds": args.rounds,
        "runs": args.runs,
        "checks_per_run": CHECKS_PER_RUN,
        "github_delay_ms": args.github_ms,
        "lane_idle_ms": args
            .idle_ms
            .unwrap_or(Config::default().idle.as_millis() as u64),
        "order": order_log,
        "p95_is_max": args.rounds * args.runs < 20,
        "results": results,
    });
    println!("{record}");
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("checks-lane-bench: {e}");
            ExitCode::FAILURE
        }
    }
}
