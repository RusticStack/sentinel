//! Cost of the local-authentication and API-credential paths: Argon2id hash and verify, session validation,
//! the login outcomes and API-credential validation and issuance.
//!
//! The store opens with `Durability::Full`, as the server does. Every operation goes through the real `sentinel_auth::password`, `sentinel_store::local_auth` and
//! `sentinel_store::tokens` code on a real `Store` under `--dir`, and the bench prints one
//! `sentinel-bench/auth-cost/1` JSON line (`docs/benchmarking.md#auth-and-credential-cost`).
//! `bench/auth-cost.sh` adds the `build` and `host` stamp; run it through that script for a committed record.
//!
//!     cargo run --release -p sentinel-store --example auth-cost-bench -- --dir /var/tmp/auth-cost --rounds 5
//!
//! Operations (`--ops` picks a subset, in this order):
//!
//! - `argon2_hash`, `argon2_verify_accept`, `argon2_verify_reject`: the password hash alone.
//! - `session_validate_conn`: `local_auth::authenticate` on a reader connection already checked out, so the
//!   query alone; `session_validate_store_read`: the same through `Store::read`, which adds the reader checkout;
//!   `session_validate_miss`: an unknown session token through `Store::read`.
//! - `login_accepted` (verify, then a writer transaction that resets the failures and issues a session),
//!   `login_rejected` (verify, then a writer transaction that counts the failure), `login_locked` (a locked
//!   credential: equal work for the password, no failure counted) and `login_unknown_username` (equal work, no
//!   credential). The last two coalesce their audit rows; `audit_rows_added` says how many rows each wrote.
//! - `token_validate_hit`, `token_validate_unknown`, `token_validate_expired` (`tokens::authenticate` through
//!   `Store::read`) and `token_issue` (`tokens::provision`: a writer transaction and one audit row).
//!
//! Each round runs every selected operation once, `--iterations` calls for the cheap ones and `--argon-iterations`
//! for the Argon2 ones; the operation order reverses every round (ABBA), so drift lands on every operation alike.
//! The credentials, the picks among them (seeded by `--seed`) and the names are prepared before a timer starts, and
//! every outcome is checked after the timer stops: a run whose operation did not do what it names is an error, never
//! a measurement. Three untimed calls per operation warm the statement caches, the reader pool and the pages first.
//! The clock is `Instant`; its own cost (`timer_floor_ns`) is recorded, because the cheapest operations are only a
//! few timer ticks. The bench removes everything it creates under `--dir`.

use std::{
    fs,
    hint::black_box,
    path::PathBuf,
    process::ExitCode,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use sentinel_auth::{
    password::{self, Verdict},
    secret::Secret,
};
use sentinel_core::{UnixMillis, UserId, auth::Permissions};
use sentinel_store::{
    Durability, Store,
    auth::{Authority, provisioning},
    local_auth::{self, Login, Policy},
    tokens::{self, Grant},
};

const OPS: [&str; 13] = [
    "argon2_hash",
    "argon2_verify_accept",
    "argon2_verify_reject",
    "session_validate_conn",
    "session_validate_store_read",
    "session_validate_miss",
    "login_accepted",
    "login_rejected",
    "login_locked",
    "login_unknown_username",
    "token_validate_hit",
    "token_validate_unknown",
    "token_validate_expired",
];
const TOKEN_ISSUE: &str = "token_issue";
const WARMUPS: usize = 3;
const GHOSTS: usize = 64;
const DAY_MS: i64 = 24 * 60 * 60 * 1000;
/// Wall-clock time is provenance only: the store logic sees this fixed instant, so a run never depends on the date.
const NOW: i64 = 1_800_000_000_000;
const PASSWORD: &[u8] = b"an acceptable operator password";
const OTHER: &[u8] = b"a different operator password";

struct Args {
    dir: PathBuf,
    rounds: usize,
    iterations: usize,
    argon_iterations: usize,
    sessions: usize,
    tokens: usize,
    seed: u64,
    ops: Vec<&'static str>,
}

fn parse() -> Result<Args, String> {
    let mut args = Args {
        dir: PathBuf::new(),
        rounds: 5,
        iterations: 2000,
        argon_iterations: 8,
        sessions: 1000,
        tokens: 1000,
        seed: 1,
        ops: OPS.iter().copied().chain([TOKEN_ISSUE]).collect(),
    };
    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        let mut value = |name: &str| it.next().ok_or(format!("{name} needs a value"));
        match flag.as_str() {
            "--dir" => args.dir = PathBuf::from(value("--dir")?),
            "--rounds" => args.rounds = number(&value("--rounds")?)?,
            "--iterations" => args.iterations = number(&value("--iterations")?)?,
            "--argon-iterations" => args.argon_iterations = number(&value("--argon-iterations")?)?,
            "--sessions" => args.sessions = number(&value("--sessions")?)?,
            "--tokens" => args.tokens = number(&value("--tokens")?)?,
            "--seed" => args.seed = number(&value("--seed")?)?,
            "--ops" => {
                let wanted = value("--ops")?;
                let mut ops = Vec::new();
                for name in wanted.split(',') {
                    let known = OPS
                        .iter()
                        .copied()
                        .chain([TOKEN_ISSUE])
                        .find(|op| *op == name)
                        .ok_or(format!("unknown operation {name:?}"))?;
                    if !ops.contains(&known) {
                        ops.push(known);
                    }
                }
                args.ops = OPS
                    .iter()
                    .copied()
                    .chain([TOKEN_ISSUE])
                    .filter(|op| ops.contains(op))
                    .collect();
            }
            other => return Err(format!("unknown argument {other}")),
        }
    }
    if args.dir.as_os_str().is_empty() {
        return Err("--dir is required: it must sit on the file system under test".into());
    }
    if args.rounds == 0
        || args.iterations == 0
        || args.argon_iterations == 0
        || args.sessions == 0
        || args.tokens == 0
        || args.ops.is_empty()
    {
        return Err("--rounds, --iterations, --argon-iterations, --sessions, --tokens and --ops must be positive".into());
    }
    Ok(args)
}

fn number<T: std::str::FromStr>(text: &str) -> Result<T, String> {
    text.trim()
        .parse()
        .map_err(|_| format!("{text:?} is not a number"))
}

/// splitmix64: a seeded stream that needs no dependency and no allocation.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn picks(&mut self, count: usize, bound: usize) -> Vec<usize> {
        (0..count)
            .map(|_| (self.next() % bound as u64) as usize)
            .collect()
    }
}

fn err<E: std::fmt::Debug>(what: &'static str) -> impl FnOnce(E) -> String {
    move |e| format!("{what}: {e:?}")
}

fn open_policy() -> Policy {
    // A rejected login must never lock the credential the accepted-login operation shares.
    Policy {
        max_failures: i64::MAX / 4,
        ..Policy::default()
    }
}

fn lock_policy() -> Policy {
    Policy {
        max_failures: 1,
        lockout_ms: DAY_MS,
        ..Policy::default()
    }
}

struct World {
    store: Store,
    root: UserId,
    sessions: Vec<Secret>,
    tokens: Vec<Secret>,
    expired: Vec<Secret>,
    unknown: Vec<Secret>,
    ghosts: Vec<String>,
    phc: String,
    issued: usize,
}

fn setup(args: &Args, db: &std::path::Path) -> Result<World, String> {
    let store =
        Store::open(db.join("metadata.sqlite"), Durability::Full).map_err(err("open store"))?;
    let at = UnixMillis(NOW);
    let root = local_auth::bootstrap(&store, "root", "Root Operator", PASSWORD, at)
        .map_err(err("bootstrap"))?;
    let phc = password::hash(PASSWORD).map_err(err("hash"))?;
    // A second credential the locked-login operation can lock without touching the first.
    let locker = UserId::new();
    let locker_phc = phc.clone();
    store
        .writer()
        .write(move |tx| {
            provisioning::insert_human(tx, locker, "Locked Operator", false, at)?;
            local_auth::provision_credential(
                tx,
                Authority::HostLocal,
                locker,
                "locker",
                &locker_phc,
                at,
            )
        })
        .map_err(err("second credential"))?;
    match local_auth::login(&store, "locker", OTHER, lock_policy(), at).map_err(err("lock"))? {
        Login::Rejected => {}
        _ => return Err("the second credential did not take its first failure".into()),
    }
    match local_auth::login(&store, "locker", PASSWORD, lock_policy(), at).map_err(err("lock"))? {
        Login::Locked { .. } => {}
        _ => return Err("the second credential is not locked".into()),
    }

    let sessions = args.sessions;
    let issued = store
        .writer()
        .write(move |tx| {
            let mut out = Vec::with_capacity(sessions);
            for _ in 0..sessions {
                out.push(local_auth::issue_session(tx, root, Policy::default(), at)?.session);
            }
            Ok(out)
        })
        .map_err(err("sessions"))?;

    let grant = |name: &str, lifetime_ms: i64| -> Result<Secret, String> {
        let mut request = Grant::new(root, name, Permissions::READ);
        request.lifetime_ms = lifetime_ms;
        tokens::provision(&store, request, at)
            .map(|g| g.secret)
            .map_err(err("token"))
    };
    let mut live = Vec::with_capacity(args.tokens);
    for n in 0..args.tokens {
        live.push(grant(&format!("live-{n}"), tokens::DEFAULT_LIFETIME_MS)?);
    }
    let mut expired = Vec::with_capacity(64);
    for n in 0..64 {
        expired.push(grant(&format!("expired-{n}"), 1)?);
    }
    Ok(World {
        store,
        root,
        sessions: issued,
        tokens: live,
        expired,
        unknown: (0..64).map(|_| Secret::generate()).collect(),
        ghosts: (0..GHOSTS).map(|n| format!("ghost-{n}")).collect(),
        phc,
        issued: 0,
    })
}

fn audit_rows(world: &World) -> Result<i64, String> {
    world
        .store
        .read(|conn| Ok(conn.query_row("SELECT COUNT(*) FROM auth_audit", [], |r| r.get(0))?))
        .map_err(err("audit count"))
}

fn expect(ok: bool, op: &str) -> Result<(), String> {
    if ok {
        Ok(())
    } else {
        Err(format!(
            "{op}: an outcome was not the one the operation names"
        ))
    }
}

/// One round of one operation: the per-call nanoseconds, in call order. `timed` false is a warm-up.
fn run_op(
    world: &mut World,
    op: &str,
    calls: usize,
    rng: &mut Rng,
    timed: bool,
) -> Result<Vec<u64>, String> {
    let mut ns = Vec::with_capacity(if timed { calls } else { 0 });
    let later = UnixMillis(NOW + 1_000);
    let at = UnixMillis(NOW);
    macro_rules! each {
        ($body:expr) => {{
            for i in 0..calls {
                let started = Instant::now();
                let outcome = $body(i);
                let took = started.elapsed().as_nanos() as u64;
                expect(black_box(outcome), op)?;
                if timed {
                    ns.push(took);
                }
            }
        }};
    }
    match op {
        "argon2_hash" => each!(|_| password::hash(PASSWORD).is_ok()),
        "argon2_verify_accept" => {
            let phc = world.phc.as_str();
            each!(|_| password::verify(phc, PASSWORD) == Verdict::Accepted)
        }
        "argon2_verify_reject" => {
            let phc = world.phc.as_str();
            each!(|_| password::verify(phc, OTHER) == Verdict::Rejected)
        }
        "session_validate_conn" => {
            let picks = rng.picks(calls, world.sessions.len());
            let sessions = &world.sessions;
            // One reader checkout for the whole round: only the query is inside each timer.
            let done = world.store.read(|conn| {
                let mut all_ok = true;
                for &pick in &picks {
                    let started = Instant::now();
                    let found = local_auth::authenticate(conn, &sessions[pick], later);
                    let took = started.elapsed().as_nanos() as u64;
                    all_ok &= black_box(found).is_ok();
                    if timed {
                        ns.push(took);
                    }
                }
                Ok(all_ok)
            });
            expect(done.map_err(err("read"))?, op)?;
        }
        "session_validate_store_read" => {
            let picks = rng.picks(calls, world.sessions.len());
            let (store, sessions) = (&world.store, &world.sessions);
            each!(|i: usize| store
                .read(|conn| local_auth::authenticate(conn, &sessions[picks[i]], later))
                .is_ok())
        }
        "session_validate_miss" => {
            let picks = rng.picks(calls, world.unknown.len());
            let (store, unknown) = (&world.store, &world.unknown);
            each!(|i: usize| store
                .read(|conn| local_auth::authenticate(conn, &unknown[picks[i]], later))
                .is_err())
        }
        "login_accepted" => {
            let store = &world.store;
            each!(|_| matches!(
                local_auth::login(store, "root", PASSWORD, open_policy(), at),
                Ok(Login::Accepted(_))
            ))
        }
        "login_rejected" => {
            let store = &world.store;
            each!(|_| matches!(
                local_auth::login(store, "root", OTHER, open_policy(), at),
                Ok(Login::Rejected)
            ))
        }
        "login_locked" => {
            let store = &world.store;
            each!(|_| matches!(
                local_auth::login(store, "locker", PASSWORD, lock_policy(), at),
                Ok(Login::Locked { .. })
            ))
        }
        "login_unknown_username" => {
            let picks = rng.picks(calls, world.ghosts.len());
            let (store, ghosts) = (&world.store, &world.ghosts);
            each!(|i: usize| matches!(
                local_auth::login(store, &ghosts[picks[i]], PASSWORD, open_policy(), at),
                Ok(Login::Rejected)
            ))
        }
        "token_validate_hit" => {
            let picks = rng.picks(calls, world.tokens.len());
            let (store, secrets) = (&world.store, &world.tokens);
            each!(|i: usize| store
                .read(|conn| tokens::authenticate(conn, &secrets[picks[i]], later))
                .is_ok())
        }
        "token_validate_unknown" => {
            let picks = rng.picks(calls, world.unknown.len());
            let (store, unknown) = (&world.store, &world.unknown);
            each!(|i: usize| store
                .read(|conn| tokens::authenticate(conn, &unknown[picks[i]], later))
                .is_err())
        }
        "token_validate_expired" => {
            let picks = rng.picks(calls, world.expired.len());
            let (store, expired) = (&world.store, &world.expired);
            each!(|i: usize| store
                .read(|conn| tokens::authenticate(conn, &expired[picks[i]], later))
                .is_err())
        }
        "token_issue" => {
            // Names are built before any timer starts.
            let names: Vec<String> = (0..calls)
                .map(|i| format!("issued-{}", world.issued + i))
                .collect();
            world.issued += calls;
            let (store, root) = (&world.store, world.root);
            each!(|i: usize| tokens::provision(
                store,
                Grant::new(root, &names[i], Permissions::READ),
                at
            )
            .is_ok())
        }
        other => return Err(format!("unknown operation {other}")),
    }
    Ok(ns)
}

fn timer_floor() -> (u64, u64) {
    let mut ticks: Vec<u64> = (0..20_000)
        .map(|_| {
            let t = Instant::now();
            black_box(t.elapsed().as_nanos() as u64)
        })
        .collect();
    ticks.sort_unstable();
    (ticks[0], ticks[ticks.len() / 2])
}

fn median(sorted: &[u64]) -> u64 {
    sorted[sorted.len() / 2]
}

fn percentile(sorted: &[u64], p: f64) -> u64 {
    // Nearest rank.
    let rank = ((p * sorted.len() as f64).ceil() as usize).clamp(1, sorted.len());
    sorted[rank - 1]
}

/// The Argon2 parameters as the stored hash states them: `$argon2id$v=19$m=19456,t=2,p=1$salt$hash`.
fn argon_params(phc: &str) -> Result<serde_json::Value, String> {
    let mut parts = phc.split('$').skip(1);
    let algorithm = parts.next().ok_or("hash has no algorithm")?;
    let version = parts.next().and_then(|v| v.strip_prefix("v="));
    let params = parts.next().ok_or("hash has no parameters")?;
    let field = |key: &str| -> Result<u64, String> {
        params
            .split(',')
            .find_map(|kv| kv.strip_prefix(key)?.strip_prefix('='))
            .and_then(|v| v.parse().ok())
            .ok_or(format!("hash has no {key} parameter"))
    };
    Ok(serde_json::json!({
        "algorithm": algorithm,
        "version": version.and_then(|v| v.parse::<u64>().ok()),
        "m_kib": field("m")?,
        "t": field("t")?,
        "p": field("p")?,
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
        .join(format!("auth-cost-bench-{}-{stamp}", std::process::id()));
    fs::create_dir_all(&scratch).map_err(|e| format!("scratch: {e}"))?;
    let outcome = measure(&args, &scratch, stamp);
    let _ = fs::remove_dir_all(&scratch);
    let record = outcome?;
    println!("{record}");
    Ok(())
}

fn measure(
    args: &Args,
    scratch: &std::path::Path,
    stamp: u128,
) -> Result<serde_json::Value, String> {
    let mut world = setup(args, scratch)?;
    let argon = argon_params(&world.phc)?;
    let (floor_min, floor_median) = timer_floor();
    let mut rng = Rng(args.seed);
    let calls_for = |op: &str| {
        // A login costs a hash on top of its query: the same call count as the hash keeps a round short.
        if op.starts_with("argon2_") || op.starts_with("login_") {
            args.argon_iterations
        } else {
            args.iterations
        }
    };
    for op in &args.ops {
        run_op(&mut world, op, WARMUPS, &mut rng, false)?;
    }

    let mut rounds_ns: Vec<Vec<Vec<u64>>> = args.ops.iter().map(|_| Vec::new()).collect();
    let mut audit_added = vec![0i64; args.ops.len()];
    let mut order_log = Vec::new();
    for round in 0..args.rounds {
        let mut order: Vec<usize> = (0..args.ops.len()).collect();
        if round % 2 == 1 {
            order.reverse();
        }
        order_log.push(order.iter().map(|&i| args.ops[i]).collect::<Vec<_>>());
        for i in order {
            let op = args.ops[i];
            let audits = op.starts_with("login_") || op == TOKEN_ISSUE;
            let before = if audits { audit_rows(&world)? } else { 0 };
            let ns = run_op(&mut world, op, calls_for(op), &mut rng, true)?;
            if audits {
                audit_added[i] += audit_rows(&world)? - before;
            }
            rounds_ns[i].push(ns);
        }
    }

    let results: Vec<serde_json::Value> = args
        .ops
        .iter()
        .enumerate()
        .map(|(i, op)| {
            let round_median: Vec<u64> = rounds_ns[i]
                .iter()
                .map(|r| {
                    let mut sorted = r.clone();
                    sorted.sort_unstable();
                    median(&sorted)
                })
                .collect();
            let mut pooled: Vec<u64> = rounds_ns[i].iter().flatten().copied().collect();
            pooled.sort_unstable();
            let mut result = serde_json::json!({
                "op": op,
                "calls_per_round": calls_for(op),
                "samples": pooled.len(),
                "round_median_ns": round_median,
                "min_ns": pooled[0],
                "median_ns": median(&pooled),
                "p95_ns": percentile(&pooled, 0.95),
                "p99_ns": percentile(&pooled, 0.99),
                "p95_is_max": pooled.len() < 20,
                "p99_is_max": pooled.len() < 100,
                "max_ns": pooled[pooled.len() - 1],
            });
            if op.starts_with("login_") || *op == TOKEN_ISSUE {
                result["audit_rows_added"] = serde_json::json!(audit_added[i]);
            }
            result
        })
        .collect();
    Ok(serde_json::json!({
        "schema": "sentinel-bench/auth-cost/1",
        "workload": "auth-cost",
        "started_at_unix_ms": (stamp / 1_000_000) as u64,
        "seed": args.seed,
        "rounds": args.rounds,
        "iterations": args.iterations,
        "argon_iterations": args.argon_iterations,
        "sessions": args.sessions,
        "tokens": args.tokens,
        "warmups": WARMUPS,
        "durability": "full",
        "argon2": argon,
        "timer_floor_ns": { "min": floor_min, "median": floor_median },
        "order": order_log,
        "results": results,
    }))
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("auth-cost-bench: {e}");
            ExitCode::FAILURE
        }
    }
}
