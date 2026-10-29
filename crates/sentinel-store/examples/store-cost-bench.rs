//! Cost of three store maintenance paths the design leans on: the batched retention re-apply, the WAL
//! checkpoint under readers that hold snapshots, and the free-capacity read beside a long attempt history.
//!
//! Every mode goes through the real `sentinel_store` code on a real `Store` under `--dir`, and the bench prints
//! one `sentinel-bench/store-cost/1` JSON line (`docs/benchmarking.md#store-cost`). `bench/store-cost.sh` adds the
//! `build` and `host` stamp; run it through that script for a committed record.
//!
//!     cargo run --release -p sentinel-store --example store-cost-bench -- --dir /var/tmp/store-cost --modes reapply
//!
//! Modes (`--modes`, comma separated, default all three):
//!
//! - `reapply`: `retention::reapply_step` over `--rows` released attempts, once per batch size in `--batches`
//!   (the last one is the whole table: the unbatched case). Each batch is its own writer transaction, so the longest
//!   step is the longest the single writer is held; the record carries the step count, the total, the longest step
//!   and the `EXPLAIN QUERY PLAN` text of the two statements for each batch size.
//! - `checkpoint`: `Store::checkpoint` after `--wal-rows` rows of writes, with 0 and each of `--readers` read
//!   transactions that began before the writes and stay open. A checkpoint blocked by a reader is `partial` after
//!   the store's own budget; the record counts the outcomes and times each call.
//! - `capacity`: `dispatch::free_capacity` for a worker with one live attempt, beside each of `--history` released
//!   attempts on the same host, to show whether the read grows with history.
//!
//! The table sizes are built from one real attempt per table by copying its row, so the bench stays right when a
//! migration adds a column. A round runs every case once; the case order reverses every round (ABBA). `--max-gib`
//! refuses a combination whose estimated size is above it before anything is written. The bench removes everything
//! it creates under `--dir`.

use std::{
    fs,
    hint::black_box,
    path::{Path, PathBuf},
    process::ExitCode,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use rusqlite::{Connection, params_from_iter, types::Null};
use sentinel_auth::secret::Secret;
use sentinel_core::{
    AttemptId, PoolId, RepoId, RunId, TenantId, UnixMillis, UserId, WorkerId,
    auth::{Namespace, Permissions as P, Principal},
};
use sentinel_pipeline::{PinnedSource, RunSpec, compile_str};
use sentinel_protocol::negotiate::{Arch, Capabilities, Negotiated, ProtocolVersion};
use sentinel_store::{
    Checkpointed, Durability, Store,
    auth::{self, Authority, NamespaceKind, provisioning},
    dispatch::{self, Capacity},
    jobs,
    retention::{self, Deployment, Reapply},
    runs,
    tenancy::{self, PoolKind},
    workers::{self, Presentation},
};

const NOW: UnixMillis = UnixMillis(1_800_000_000_000);
const SHA: &str = "0123456789abcdef0123456789abcdef01234567";
const DIGEST: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
/// What one copied attempt row costs in the database and its indexes, rounded up: the size estimate behind `--max-gib`.
const ROW_BYTES: u64 = 512;
const MODES: [&str; 3] = ["reapply", "checkpoint", "capacity"];

struct Args {
    dir: PathBuf,
    modes: Vec<&'static str>,
    rounds: usize,
    rows: u64,
    batches: Vec<i64>,
    readers: Vec<usize>,
    wal_rows: u64,
    history: Vec<u64>,
    calls: usize,
    seed: u64,
    max_gib: f64,
}

fn parse() -> Result<Args, String> {
    let mut args = Args {
        dir: PathBuf::new(),
        modes: MODES.to_vec(),
        rounds: 5,
        rows: 100_000,
        batches: vec![64, 512, 8192],
        readers: vec![1, 4],
        wal_rows: 2_000,
        history: vec![1_000, 10_000, 100_000],
        calls: 2_000,
        seed: 1,
        max_gib: 4.0,
    };
    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        let mut value = |name: &str| it.next().ok_or(format!("{name} needs a value"));
        match flag.as_str() {
            "--dir" => args.dir = PathBuf::from(value("--dir")?),
            "--modes" => {
                let wanted = value("--modes")?;
                let mut modes = Vec::new();
                for name in wanted.split(',') {
                    modes.push(
                        MODES
                            .iter()
                            .copied()
                            .find(|m| *m == name)
                            .ok_or(format!("unknown mode {name:?}"))?,
                    );
                }
                args.modes = MODES
                    .iter()
                    .copied()
                    .filter(|m| modes.contains(m))
                    .collect();
            }
            "--rounds" => args.rounds = number(&value("--rounds")?)?,
            "--rows" => args.rows = number(&value("--rows")?)?,
            "--batches" => args.batches = list(&value("--batches")?)?,
            "--readers" => args.readers = list(&value("--readers")?)?,
            "--wal-rows" => args.wal_rows = number(&value("--wal-rows")?)?,
            "--history" => args.history = list(&value("--history")?)?,
            "--calls" => args.calls = number(&value("--calls")?)?,
            "--seed" => args.seed = number(&value("--seed")?)?,
            "--max-gib" => args.max_gib = number(&value("--max-gib")?)?,
            other => return Err(format!("unknown argument {other}")),
        }
    }
    if args.dir.as_os_str().is_empty() {
        return Err("--dir is required: it must sit on the file system under test".into());
    }
    if args.modes.is_empty()
        || args.rounds == 0
        || args.rows == 0
        || args.batches.is_empty()
        || args.batches.contains(&0)
        || args.readers.is_empty()
        || args.history.is_empty()
        || args.history.contains(&0)
        || args.calls == 0
        || args.wal_rows == 0
    {
        return Err("--modes, --rounds, --rows, --batches, --readers, --history, --calls and --wal-rows must be positive".into());
    }
    let biggest = args
        .rows
        .max(args.history.iter().copied().max().unwrap_or(0));
    let estimate = biggest.saturating_mul(ROW_BYTES) as f64 / f64::from(1u32 << 30);
    if estimate > args.max_gib {
        return Err(format!(
            "{biggest} rows are about {estimate:.2} GiB, above --max-gib {}",
            args.max_gib
        ));
    }
    Ok(args)
}

fn number<T: std::str::FromStr>(text: &str) -> Result<T, String> {
    text.trim()
        .parse()
        .map_err(|_| format!("{text:?} is not a number"))
}

fn list<T: std::str::FromStr>(text: &str) -> Result<Vec<T>, String> {
    text.split(',').map(number).collect()
}

fn err<E: std::fmt::Debug>(what: &'static str) -> impl FnOnce(E) -> String {
    move |e| format!("{what}: {e:?}")
}

struct World {
    store: Store,
    tenant: TenantId,
    worker: WorkerId,
    /// A released attempt whose log expiry is stamped: the row `grow_history` multiplies.
    template: AttemptId,
}

fn spec() -> Result<RunSpec, String> {
    RunSpec::new(
        PinnedSource::new("https://github.com/o/r.git", SHA, Some("main")).map_err(err("source"))?,
        compile_str(
            "schema: 1\non: [push]\njobs:\n  build:\n    image: alpine:3\n    steps: [{ id: s, run: 'true' }]\n",
        )
        .map_err(err("pipeline"))?,
    )
    .map_err(err("spec"))
}

fn world(path: &Path) -> Result<World, String> {
    let store = Store::open(path.join("metadata.sqlite"), Durability::Full).map_err(err("open"))?;
    let (root, tenant, repo, pool, worker) = (
        UserId::new(),
        TenantId::new(),
        RepoId::new(),
        PoolId::new(),
        WorkerId::new(),
    );
    let d = Deployment::default();
    let (released_run, live_run) = (RunId::new(), RunId::new());
    let (released_spec, live_spec) = (spec()?, spec()?);
    let template = store
        .writer()
        .write(move |tx| {
            provisioning::insert_human(tx, root, "Root", true, NOW)?;
            let platform = Principal::new(root, P::ALL, None, None);
            auth::create_namespace(
                tx,
                platform,
                tenant,
                Namespace::parse("acme").ok_or(sentinel_store::Error::InvalidInput("namespace"))?,
                NamespaceKind::Organization,
                NOW,
            )?;
            jobs::insert_repo(tx, tenant, repo, "app", NOW)?;
            tenancy::create_pool(
                tx,
                Authority::HostLocal,
                pool,
                "builders",
                PoolKind::Dedicated(tenant),
                NOW,
            )?;
            retention::install(tx, &d)?;
            let issued = workers::issue_enrollment(tx, Authority::HostLocal, pool, 60_000, NOW)?;
            let mut text = String::new();
            issued.secret.expose(&mut text);
            workers::enroll(
                tx,
                &Secret::parse(&text).ok_or(sentinel_store::Error::InvalidInput("secret"))?,
                Presentation {
                    worker,
                    fingerprint: Secret::generate().digest(),
                    name: "w",
                    negotiated: Negotiated {
                        protocol: ProtocolVersion(4),
                        capabilities: Capabilities::REQUIRED,
                        arch: Arch::X86_64,
                    },
                },
                NOW,
            )?;
            dispatch::report_capacity(
                tx,
                worker,
                Capacity {
                    cpu_millis: 64_000,
                    memory_bytes: 256 << 30,
                    disk_bytes: 0,
                },
            )?;
            let place = |run: RunId, spec: &RunSpec| -> sentinel_store::Result<AttemptId> {
                let ids = runs::create_run(tx, tenant, repo, run, spec, NOW)?;
                runs::resolve_image(tx, tenant, ids[0], DIGEST, "linux/amd64")?;
                let offer = dispatch::place(tx, worker, pool, dispatch::DEFAULT_LEASE_MS, NOW)?
                    .ok_or(sentinel_store::Error::NotFound)?;
                Ok(offer.attempt)
            };
            let released = place(released_run, &released_spec)?;
            tx.execute(
                "UPDATE attempts SET released_ms = ?2 WHERE id = ?1",
                rusqlite::params![released.as_bytes().as_slice(), NOW.0],
            )?;
            place(live_run, &live_spec)?;
            Ok(released)
        })
        .map_err(err("fixture"))?;
    // Stamp the released attempt so its log expiry is set, the state a re-apply works on.
    let rows = store
        .read(|c| retention::unstamped(c, 16))
        .map_err(err("unstamped"))?
        .into_iter()
        .map(|r| (r, 1_024u64))
        .collect::<Vec<_>>();
    if rows.len() != 1 {
        return Err(format!(
            "expected one released attempt to stamp, found {}",
            rows.len()
        ));
    }
    store
        .writer()
        .write(move |tx| retention::stamp(tx, &d, &rows))
        .map_err(err("stamp"))?;
    Ok(World {
        store,
        tenant,
        worker,
        template,
    })
}

/// Grows the released history to `total` attempts by copying the template row; every column but the id and the
/// fence comes from the template, whatever the schema's columns are today.
fn grow_history(w: &World, total: u64) -> Result<(), String> {
    let template = w.template;
    w.store
        .writer()
        .raw(move |conn| {
            let have: i64 = conn.query_row(
                "SELECT COUNT(*) FROM attempts WHERE released_ms IS NOT NULL",
                [],
                |r| r.get(0),
            )?;
            let need = i64::try_from(total).unwrap_or(i64::MAX) - have;
            if need <= 0 {
                return Ok(());
            }
            let columns: Vec<String> = conn
                .prepare("SELECT name FROM pragma_table_info('attempts')")?
                .query_map([], |r| r.get(0))?
                .collect::<Result<_, _>>()?;
            let target = columns
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
                .join(", ");
            let source = columns
                .iter()
                .map(|c| match c.as_str() {
                    "id" => "randomblob(16)".to_owned(),
                    "fence" => format!("n.i + {have} + 1000000"),
                    other => format!("a.{other}"),
                })
                .collect::<Vec<_>>()
                .join(", ");
            conn.execute(
                &format!(
                    "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < ?1)
                     INSERT INTO attempts({target}) SELECT {source} FROM attempts a, n WHERE a.id = ?2"
                ),
                rusqlite::params![need, template.as_bytes().as_slice()],
            )?;
            Ok(())
        })
        .map_err(err("grow history"))
}

fn median(sorted: &[u64]) -> u64 {
    sorted[sorted.len() / 2]
}

fn percentile(sorted: &[u64], p: f64) -> u64 {
    // Nearest rank.
    let rank = ((p * sorted.len() as f64).ceil() as usize).clamp(1, sorted.len());
    sorted[rank - 1]
}

fn abba<T: Copy>(round: usize, cases: &[T]) -> Vec<T> {
    let mut order = cases.to_vec();
    if round % 2 == 1 {
        order.reverse();
    }
    order
}

fn plans(conn: &Connection, batch: i64) -> Result<serde_json::Value, String> {
    let mut out = serde_json::Map::new();
    for (name, logs) in [("attempts", true), ("artifacts", false)] {
        let column = if logs {
            "log_retention_ms"
        } else {
            "artifact_retention_ms"
        };
        let (bound, update) = retention::reapply_sql(logs, false, column, batch);
        for (kind, sql) in [("bound", bound), ("update", update)] {
            let mut stmt = conn
                .prepare(&format!("EXPLAIN QUERY PLAN {sql}"))
                .map_err(err("explain"))?;
            let nulls = vec![Null; stmt.parameter_count()];
            let rows: Vec<String> = stmt
                .query_map(params_from_iter(nulls), |r| r.get::<_, String>(3))
                .map_err(err("explain"))?
                .collect::<Result<_, _>>()
                .map_err(err("explain"))?;
            out.insert(format!("{name}_{kind}"), serde_json::json!(rows));
        }
    }
    Ok(serde_json::Value::Object(out))
}

fn reapply(args: &Args, w: &World) -> Result<serde_json::Value, String> {
    grow_history(w, args.rows)?;
    let d = Deployment::default();
    let whole = i64::try_from(args.rows).unwrap_or(i64::MAX);
    let mut cases: Vec<i64> = args.batches.clone();
    cases.push(whole);
    let mut samples: Vec<Vec<(u64, u64, usize)>> = cases.iter().map(|_| Vec::new()).collect();
    let mut order_log = Vec::new();
    for round in 0..args.rounds {
        let order = abba(round, &(0..cases.len()).collect::<Vec<_>>());
        order_log.push(order.iter().map(|&i| cases[i]).collect::<Vec<_>>());
        for i in order {
            let (tenant, batch) = (w.tenant, cases[i]);
            let mut at = Reapply::default();
            let (mut longest, mut steps) = (0u64, 0usize);
            let started = Instant::now();
            while !at.done() {
                let step = Instant::now();
                at = w
                    .store
                    .writer()
                    .write(move |tx| retention::reapply_step(tx, &d, tenant, None, at, batch))
                    .map_err(err("reapply"))?;
                longest = longest.max(step.elapsed().as_nanos() as u64);
                steps += 1;
            }
            samples[i].push((started.elapsed().as_nanos() as u64, longest, steps));
        }
    }
    let plan_text = w
        .store
        .read(|c| Ok(plans(c, 512)))
        .map_err(err("plans"))??;
    let results: Vec<serde_json::Value> = cases
        .iter()
        .zip(&samples)
        .map(|(&batch, s)| {
            let mut total: Vec<u64> = s.iter().map(|x| x.0).collect();
            total.sort_unstable();
            let mut longest: Vec<u64> = s.iter().map(|x| x.1).collect();
            longest.sort_unstable();
            serde_json::json!({
                "batch": batch,
                "unbatched": batch == whole,
                "steps": s.first().map_or(0, |x| x.2),
                "total_ns": s.iter().map(|x| x.0).collect::<Vec<_>>(),
                "median_total_ns": median(&total),
                "longest_step_ns": s.iter().map(|x| x.1).collect::<Vec<_>>(),
                "median_longest_step_ns": median(&longest),
                "max_longest_step_ns": longest[longest.len() - 1],
            })
        })
        .collect();
    Ok(serde_json::json!({
        "rows": args.rows,
        "phases": ["logs", "artifacts"],
        "artifact_rows": 0,
        "order": order_log,
        "results": results,
        "plans_batch_512": plan_text,
    }))
}

fn checkpoint(args: &Args, w: &World, dir: &Path) -> Result<serde_json::Value, String> {
    w.store
        .writer()
        .raw(|conn| {
            conn.execute_batch("CREATE TABLE IF NOT EXISTS bench_wal(id INTEGER PRIMARY KEY, payload BLOB NOT NULL)")?;
            Ok(())
        })
        .map_err(err("wal table"))?;
    let path = dir.join("metadata.sqlite");
    let mut cases: Vec<usize> = vec![0];
    cases.extend(args.readers.iter().copied());
    let mut samples: Vec<Vec<(u64, bool)>> = cases.iter().map(|_| Vec::new()).collect();
    let mut order_log = Vec::new();
    let mut rng = args.seed;
    for round in 0..args.rounds {
        let order = abba(round, &(0..cases.len()).collect::<Vec<_>>());
        order_log.push(order.iter().map(|&i| cases[i]).collect::<Vec<_>>());
        for i in order {
            // Settle whatever earlier cases left, then open the snapshots, then write.
            let _ = w.store.checkpoint();
            let mut held = Vec::new();
            for _ in 0..cases[i] {
                let conn = Connection::open(&path).map_err(err("reader"))?;
                conn.execute_batch("BEGIN; SELECT COUNT(*) FROM bench_wal;")
                    .map_err(err("snapshot"))?;
                held.push(conn);
            }
            let rows = args.wal_rows;
            rng = rng
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            let fill = (rng >> 56) as u8;
            w.store
                .writer()
                .write(move |tx| {
                    let payload = vec![fill; 1024];
                    let mut stmt =
                        tx.prepare_cached("INSERT INTO bench_wal(payload) VALUES (?1)")?;
                    for _ in 0..rows {
                        stmt.execute([&payload])?;
                    }
                    Ok(())
                })
                .map_err(err("wal writes"))?;
            let started = Instant::now();
            let outcome = w.store.checkpoint().map_err(err("checkpoint"))?;
            let took = started.elapsed().as_nanos() as u64;
            samples[i].push((took, outcome == Checkpointed::Complete));
            drop(held);
        }
    }
    let results: Vec<serde_json::Value> = cases
        .iter()
        .zip(&samples)
        .map(|(&readers, s)| {
            let mut ns: Vec<u64> = s.iter().map(|x| x.0).collect();
            ns.sort_unstable();
            serde_json::json!({
                "readers_holding_snapshots": readers,
                "checkpoint_ns": s.iter().map(|x| x.0).collect::<Vec<_>>(),
                "median_ns": median(&ns),
                "max_ns": ns[ns.len() - 1],
                "complete": s.iter().filter(|x| x.1).count(),
                "partial": s.iter().filter(|x| !x.1).count(),
            })
        })
        .collect();
    Ok(serde_json::json!({
        "wal_rows_per_checkpoint": args.wal_rows,
        "payload_bytes": 1024,
        "order": order_log,
        "results": results,
    }))
}

fn capacity(args: &Args, w: &World) -> Result<serde_json::Value, String> {
    let mut sizes = args.history.clone();
    sizes.sort_unstable();
    let mut samples: Vec<Vec<u64>> = sizes.iter().map(|_| Vec::new()).collect();
    let mut rows_seen = Vec::new();
    // History only grows, so the cases run smallest first; the round order is still ABBA over the sizes that exist.
    for (i, &size) in sizes.iter().enumerate() {
        grow_history(w, size)?;
        let released: i64 = w
            .store
            .read(|c| {
                Ok(c.query_row(
                    "SELECT COUNT(*) FROM attempts WHERE released_ms IS NOT NULL",
                    [],
                    |r| r.get(0),
                )?)
            })
            .map_err(err("count"))?;
        rows_seen.push(released);
        let worker = w.worker;
        for _ in 0..args.rounds {
            let mut ns = Vec::with_capacity(args.calls);
            w.store
                .read(|conn| {
                    for _ in 0..3 {
                        black_box(dispatch::free_capacity(conn, worker)?);
                    }
                    for _ in 0..args.calls {
                        let started = Instant::now();
                        let free = dispatch::free_capacity(conn, worker);
                        ns.push(started.elapsed().as_nanos() as u64);
                        black_box(free)?;
                    }
                    Ok(())
                })
                .map_err(err("free_capacity"))?;
            samples[i].extend(ns);
        }
    }
    let results: Vec<serde_json::Value> = sizes
        .iter()
        .zip(&samples)
        .zip(&rows_seen)
        .map(|((&size, s), &released)| {
            let mut ns = s.clone();
            ns.sort_unstable();
            serde_json::json!({
                "released_attempts": released,
                "requested_history": size,
                "live_attempts": 1,
                "samples": ns.len(),
                "min_ns": ns[0],
                "median_ns": median(&ns),
                "p95_ns": percentile(&ns, 0.95),
                "p99_ns": percentile(&ns, 0.99),
                "max_ns": ns[ns.len() - 1],
            })
        })
        .collect();
    Ok(serde_json::json!({
        "calls_per_round": args.calls,
        "rounds": args.rounds,
        "order": "history sizes ascending: the table only grows",
        "results": results,
    }))
}

fn run() -> Result<(), String> {
    let args = parse()?;
    fs::create_dir_all(&args.dir).map_err(|e| format!("--dir: {e}"))?;
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let scratch = args
        .dir
        .join(format!("store-cost-bench-{}-{stamp}", std::process::id()));
    let outcome = (|| -> Result<serde_json::Value, String> {
        let mut modes = serde_json::Map::new();
        for mode in &args.modes {
            // A fresh store per mode: one mode's rows never sit under another's timings.
            let dir = scratch.join(mode);
            fs::create_dir_all(&dir).map_err(|e| format!("scratch: {e}"))?;
            let w = world(&dir)?;
            let result = match *mode {
                "reapply" => reapply(&args, &w)?,
                "checkpoint" => checkpoint(&args, &w, &dir)?,
                _ => capacity(&args, &w)?,
            };
            drop(w);
            modes.insert((*mode).to_owned(), result);
        }
        Ok(serde_json::Value::Object(modes))
    })();
    let _ = fs::remove_dir_all(&scratch);
    let modes = outcome?;
    let record = serde_json::json!({
        "schema": "sentinel-bench/store-cost/1",
        "workload": "store-cost",
        "started_at_unix_ms": (stamp / 1_000_000) as u64,
        "seed": args.seed,
        "rounds": args.rounds,
        "durability": "full",
        "modes": modes,
    });
    println!("{record}");
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("store-cost-bench: {e}");
            ExitCode::FAILURE
        }
    }
}
