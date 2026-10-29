//! Cost of verifying a backup, which rehashes every object and manifest, at configurable object counts.
//!
//! The bench builds a real store with `--counts` objects of `--object-bytes` bytes (one dataset per count),
//! takes one `backup::create` of each, then times `backup::verify` over `--rounds` rounds and, beside it, a
//! bare BLAKE3 read of the same object files: the floor the rehash cannot beat. The difference is the
//! snapshot hash, `PRAGMA integrity_check` and the per-row bookkeeping. It prints one
//! `sentinel-bench/backup-rehash/1` JSON line (`docs/benchmarking.md#backup-rehash-cost`);
//! `bench/backup-rehash.sh` adds the `build` and `host` stamp.
//!
//!     cargo run --release -p sentinel-store --example backup-rehash-bench -- --dir /srv/bench --counts 100,1000
//!
//! The order of the counts reverses every round (ABBA). Setup (staging, the backup) is not timed. The
//! objects are read from the page cache unless the datasets exceed memory, which the record names
//! (`dataset_bytes`) but cannot check; a cold-cache figure needs a dataset larger than RAM or a cache drop
//! the bench does not do. `--dir` must sit on the file system under test; the bench removes everything it
//! creates there and refuses a dataset above `--max-gib` (default 8).

use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
    process::ExitCode,
    sync::Arc,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use sentinel_core::{
    TenantId, UnixMillis, UserId,
    auth::{Namespace, Permissions, Principal},
};
use sentinel_store::{
    Durability, Store,
    auth::{self, NamespaceKind, provisioning},
    backup,
    objects::{Expect, Objects, object_relpath},
};

struct Args {
    dir: PathBuf,
    counts: Vec<usize>,
    object_bytes: usize,
    rounds: usize,
    max_gib: u64,
}

fn parse() -> Result<Args, String> {
    let mut args = Args {
        dir: PathBuf::new(),
        counts: vec![100, 1000],
        object_bytes: 1 << 20,
        rounds: 5,
        max_gib: 8,
    };
    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        let mut value = |name: &str| it.next().ok_or(format!("{name} needs a value"));
        match flag.as_str() {
            "--dir" => args.dir = PathBuf::from(value("--dir")?),
            "--object-bytes" => args.object_bytes = number(&value("--object-bytes")?)?,
            "--rounds" => args.rounds = number(&value("--rounds")?)?,
            "--max-gib" => args.max_gib = number(&value("--max-gib")?)?,
            "--counts" => {
                args.counts = value("--counts")?
                    .split(',')
                    .map(number)
                    .collect::<Result<_, _>>()?;
            }
            other => return Err(format!("unknown argument {other}")),
        }
    }
    if args.dir.as_os_str().is_empty() {
        return Err("--dir is required: it must sit on the file system under test".into());
    }
    if args.rounds == 0
        || args.object_bytes == 0
        || args.counts.is_empty()
        || args.counts.contains(&0)
    {
        return Err("--rounds, --object-bytes and every count must be positive".into());
    }
    let largest = args.counts.iter().copied().max().unwrap_or(0) as u64;
    // Each dataset exists twice on disk, as objects and as the backup's copy; all datasets coexist.
    let total: u64 = args
        .counts
        .iter()
        .map(|&c| c as u64 * args.object_bytes as u64 * 2)
        .sum();
    if total > args.max_gib << 30 {
        return Err(format!(
            "the datasets need about {} MiB on disk (largest count {largest}); raise --max-gib or lower --counts / --object-bytes",
            total >> 20
        ));
    }
    Ok(args)
}

fn number<T: std::str::FromStr>(text: &str) -> Result<T, String> {
    text.trim()
        .parse()
        .map_err(|_| format!("{text:?} is not a number"))
}

/// Distinct pseudo-random bytes per object; the content is irrelevant to the cost but must differ so
/// that every object is its own file.
fn bytes(seed: u64, len: usize) -> Vec<u8> {
    let mut x = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        })
        .collect()
}

struct Dataset {
    count: usize,
    target: PathBuf,
    backup_id: String,
    object_files: Vec<PathBuf>,
    // Kept open so the store and objects outlive the backup they produced.
    _store: Arc<Store>,
}

fn build(args: &Args, count: usize, root: &Path) -> Result<Dataset, String> {
    let data = root.join("data");
    fs::create_dir_all(&data).map_err(|e| format!("data dir: {e}"))?;
    let store = Arc::new(
        Store::open(data.join("metadata.sqlite"), Durability::Normal)
            .map_err(|e| format!("store: {e:?}"))?,
    );
    let objects = Arc::new(Objects::open(&data).map_err(|e| format!("objects: {e:?}"))?);
    let (user, tenant) = (UserId::new(), TenantId::new());
    let now = UnixMillis::now();
    store
        .writer()
        .write(move |tx| {
            provisioning::insert_human(tx, user, "Root", true, now)?;
            auth::create_namespace(
                tx,
                Principal::new(user, Permissions::ALL, None, None),
                tenant,
                Namespace::parse("acme").unwrap(),
                NamespaceKind::Organization,
                now,
            )
        })
        .map_err(|e| format!("tenant: {e:?}"))?;
    let mut object_files = Vec::with_capacity(count);
    for i in 0..count {
        let body = bytes(i as u64 + 1, args.object_bytes);
        let staged = objects
            .stage(tenant, body.as_slice(), u64::MAX, Expect::default())
            .map_err(|e| format!("stage: {e:?}"))?;
        let rel = object_relpath(tenant, &staged.digest());
        let o = Arc::clone(&objects);
        store
            .writer()
            .write(move |tx| o.commit(tx, &staged))
            .map_err(|e| format!("commit: {e:?}"))?;
        object_files.push(rel);
    }
    let target = root.join("backups");
    let report = backup::create(&store, &objects, &data, &target, "rehash-bench")
        .map_err(|e| format!("backup: {e:?}"))?;
    let object_files = object_files.iter().map(|rel| target.join(rel)).collect();
    Ok(Dataset {
        count,
        target,
        backup_id: report.id,
        object_files,
        _store: store,
    })
}

fn read_hash(path: &Path, buf: &mut [u8]) -> Result<u64, String> {
    let mut file = fs::File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut hasher = blake3::Hasher::new();
    let mut len = 0u64;
    loop {
        let n = file.read(buf).map_err(|e| format!("read: {e}"))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        len += n as u64;
    }
    std::hint::black_box(hasher.finalize());
    Ok(len)
}

struct Sample {
    verify_ns: u64,
    floor_ns: u64,
}

fn measure(d: &Dataset, expect_bytes: u64) -> Result<Sample, String> {
    let started = Instant::now();
    let check = backup::verify(&d.target, &d.backup_id).map_err(|e| format!("verify: {e:?}"))?;
    let verify_ns = started.elapsed().as_nanos() as u64;
    if !check.ok() {
        return Err(format!("the backup did not verify: {check:?}"));
    }
    if check.objects_checked != d.count as u64 {
        return Err(format!(
            "verify checked {} objects, expected {}",
            check.objects_checked, d.count
        ));
    }
    let mut buf = vec![0u8; 256 << 10];
    let started = Instant::now();
    let mut total = 0u64;
    for file in &d.object_files {
        total += read_hash(file, &mut buf)?;
    }
    let floor_ns = started.elapsed().as_nanos() as u64;
    if total != expect_bytes {
        return Err(format!("floor read {total} bytes, expected {expect_bytes}"));
    }
    Ok(Sample {
        verify_ns,
        floor_ns,
    })
}

fn median(sorted: &[u64]) -> u64 {
    sorted[sorted.len() / 2]
}

fn run() -> Result<(), String> {
    let args = parse()?;
    fs::create_dir_all(&args.dir).map_err(|e| format!("--dir: {e}"))?;
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let scratch = args.dir.join(format!(
        "backup-rehash-bench-{}-{stamp}",
        std::process::id()
    ));
    let mut samples: Vec<Vec<Sample>> = args.counts.iter().map(|_| Vec::new()).collect();
    let mut order_log = Vec::new();
    let outcome = (|| -> Result<(), String> {
        let mut datasets = Vec::new();
        for &count in &args.counts {
            datasets.push(build(&args, count, &scratch.join(format!("n{count}")))?);
        }
        for round in 0..args.rounds {
            let mut order: Vec<usize> = (0..datasets.len()).collect();
            if round % 2 == 1 {
                order.reverse();
            }
            order_log.push(order.iter().map(|&i| args.counts[i]).collect::<Vec<_>>());
            for i in order {
                let expect = (datasets[i].count * args.object_bytes) as u64;
                samples[i].push(measure(&datasets[i], expect)?);
            }
        }
        Ok(())
    })();
    let _ = fs::remove_dir_all(&scratch);
    outcome?;

    let results: Vec<serde_json::Value> = args
        .counts
        .iter()
        .zip(&samples)
        .map(|(&count, samples)| {
            let dataset_bytes = (count * args.object_bytes) as u64;
            let mut verify: Vec<u64> = samples.iter().map(|s| s.verify_ns).collect();
            let mut floor: Vec<u64> = samples.iter().map(|s| s.floor_ns).collect();
            let per_round_verify = verify.clone();
            let per_round_floor = floor.clone();
            verify.sort_unstable();
            floor.sort_unstable();
            let (v, f) = (median(&verify), median(&floor));
            serde_json::json!({
                "objects": count,
                "dataset_bytes": dataset_bytes,
                "verify_ns": per_round_verify,
                "floor_ns": per_round_floor,
                "median_verify_ns": v,
                "min_verify_ns": verify[0],
                "max_verify_ns": verify[verify.len() - 1],
                "median_floor_ns": f,
                "median_verify_ns_per_object": v / count as u64,
                "median_overhead_ns": v.saturating_sub(f),
                "verify_mib_per_s_median": (dataset_bytes as f64 / (1u64 << 20) as f64 / (v as f64 / 1e9)).round(),
            })
        })
        .collect();
    let record = serde_json::json!({
        "schema": "sentinel-bench/backup-rehash/1",
        "workload": "backup-rehash",
        "started_at_unix_ms": (stamp / 1_000_000) as u64,
        "object_bytes": args.object_bytes,
        "rounds": args.rounds,
        "order": order_log,
        "cache": "warm-unless-dataset-exceeds-memory",
        "results": results,
    });
    println!("{record}");
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("backup-rehash-bench: {e}");
            ExitCode::FAILURE
        }
    }
}
