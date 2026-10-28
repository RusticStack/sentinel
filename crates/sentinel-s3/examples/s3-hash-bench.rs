//! Cost of hashing an S3 payload and of signing a request, through the code `Client` calls.
//!
//! A put hashes its body with `client::body_hashes` (SHA-256 for the signed payload hash and MD5 for
//! `Content-MD5`, from one walk over the bytes) and signs the request with `sigv4::authorization`. This
//! bench times those, and the single-digest and two-pass alternatives, at several payload sizes, with no
//! network and no service in the loop, and prints one `sentinel-bench/s3-hash/1` JSON line
//! (`docs/benchmarking.md#s3-hashing-and-signing`). `bench/s3-hash.sh` adds the `build` and `host` stamp.
//!
//!     cargo run --release -p sentinel-s3 --example s3-hash-bench -- --rounds 7
//!
//! Each round times every case once per size, and the order of the cases reverses every round (ABBA). A
//! case repeats until it has hashed at least `--sample-mib` MiB (at least once), so a small payload is not
//! a single timer read. The signing case is independent of the payload and repeats `--sign-iterations`
//! times per round.

use std::{
    hint::black_box,
    process::ExitCode,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use sentinel_s3::{client, sigv4};

const DEFAULT_SIZES: [usize; 4] = [4 << 10, 64 << 10, 1 << 20, 16 << 20];

#[derive(Clone, Copy)]
enum Case {
    Sha256,
    Md5,
    BodyHashes,
    TwoPass,
}

impl Case {
    const ALL: [Case; 4] = [Case::Sha256, Case::Md5, Case::BodyHashes, Case::TwoPass];

    fn name(self) -> &'static str {
        match self {
            Case::Sha256 => "sha256",
            Case::Md5 => "md5",
            Case::BodyHashes => "body_hashes",
            Case::TwoPass => "sha256_then_md5",
        }
    }

    fn run(self, body: &[u8]) {
        match self {
            Case::Sha256 => {
                black_box(sigv4::sha256_hex(black_box(body)));
            }
            Case::Md5 => {
                black_box(client::content_md5(black_box(body)));
            }
            Case::BodyHashes => {
                black_box(client::body_hashes(black_box(body)));
            }
            Case::TwoPass => {
                black_box(sigv4::sha256_hex(black_box(body)));
                black_box(client::content_md5(black_box(body)));
            }
        }
    }
}

struct Args {
    rounds: usize,
    sizes: Vec<usize>,
    sample_mib: usize,
    sign_iterations: usize,
}

fn parse() -> Result<Args, String> {
    let mut args = Args {
        rounds: 7,
        sizes: DEFAULT_SIZES.to_vec(),
        sample_mib: 64,
        sign_iterations: 20_000,
    };
    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        let mut value = |name: &str| it.next().ok_or(format!("{name} needs a value"));
        match flag.as_str() {
            "--rounds" => args.rounds = number(&value("--rounds")?)?,
            "--sample-mib" => args.sample_mib = number(&value("--sample-mib")?)?,
            "--sign-iterations" => args.sign_iterations = number(&value("--sign-iterations")?)?,
            "--sizes" => {
                args.sizes = value("--sizes")?
                    .split(',')
                    .map(number)
                    .collect::<Result<_, _>>()?;
            }
            other => return Err(format!("unknown argument {other}")),
        }
    }
    if args.rounds == 0
        || args.sample_mib == 0
        || args.sign_iterations == 0
        || args.sizes.is_empty()
        || args.sizes.contains(&0)
    {
        return Err(
            "--rounds, --sample-mib, --sign-iterations and every size must be positive".into(),
        );
    }
    Ok(args)
}

fn number<T: std::str::FromStr>(text: &str) -> Result<T, String> {
    text.trim()
        .parse()
        .map_err(|_| format!("{text:?} is not a number"))
}

/// Deterministic, incompressible-looking bytes: the digests do not depend on content, but a constant
/// fill would let a future implementation shortcut.
fn payload(len: usize) -> Vec<u8> {
    let mut x = 0x9E37_79B9_7F4A_7C15u64;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        })
        .collect()
}

fn percentile(sorted: &[u64], p: f64) -> u64 {
    // Nearest rank.
    let rank = ((p * sorted.len() as f64).ceil() as usize).clamp(1, sorted.len());
    sorted[rank - 1]
}

/// Nanoseconds per call over enough calls to hash `sample_mib`.
fn time_case(case: Case, body: &[u8], sample_mib: usize) -> u64 {
    let calls = ((sample_mib << 20) / body.len()).max(1);
    let started = Instant::now();
    for _ in 0..calls {
        case.run(body);
    }
    (started.elapsed().as_nanos() / calls as u128) as u64
}

fn time_sign(iterations: usize) -> u64 {
    // The headers a PutObject carries: host, the payload hash, the date, Content-MD5 and one metadata header.
    let payload_sha256 = sigv4::EMPTY_SHA256;
    let headers = [
        ("host", "bucket.s3.example.com"),
        ("x-amz-content-sha256", payload_sha256),
        ("x-amz-date", "20260101T000000Z"),
        ("content-md5", "1B2M2Y8AsgTpgAmY7PhCfg=="),
        ("x-amz-meta-sentinel", "bench"),
    ];
    let started = Instant::now();
    for _ in 0..iterations {
        black_box(sigv4::authorization(
            &sigv4::Request {
                method: "PUT",
                path: black_box(
                    "/tenants/0123456789abcdef/objects/0123456789abcdef0123456789abcdef",
                ),
                query: &[],
                headers: black_box(&headers),
                payload_sha256,
            },
            "20260101T000000Z",
            "us-east-1",
            "AKIDEXAMPLE",
            b"wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        ));
    }
    (started.elapsed().as_nanos() / iterations as u128) as u64
}

fn run() -> Result<(), String> {
    let args = parse()?;
    let started_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis());
    let bodies: Vec<Vec<u8>> = args.sizes.iter().map(|&n| payload(n)).collect();
    // ns per call, by size then case, one entry per round.
    let mut hashed: Vec<Vec<Vec<u64>>> = vec![vec![Vec::new(); Case::ALL.len()]; args.sizes.len()];
    let mut signed = Vec::new();
    let mut order_log = Vec::new();
    // One unmeasured pass so code and the payloads are resident before the first round.
    for body in &bodies {
        for case in Case::ALL {
            case.run(body);
        }
    }
    for round in 0..args.rounds {
        let mut order: Vec<usize> = (0..Case::ALL.len()).collect();
        if round % 2 == 1 {
            order.reverse();
        }
        order_log.push(
            order
                .iter()
                .map(|&i| Case::ALL[i].name())
                .collect::<Vec<_>>(),
        );
        for (s, body) in bodies.iter().enumerate() {
            for &c in &order {
                hashed[s][c].push(time_case(Case::ALL[c], body, args.sample_mib));
            }
        }
        signed.push(time_sign(args.sign_iterations));
    }

    let mut results = Vec::new();
    for (s, &size) in args.sizes.iter().enumerate() {
        for (c, case) in Case::ALL.iter().enumerate() {
            let per_call = &hashed[s][c];
            let mut sorted = per_call.clone();
            sorted.sort_unstable();
            let median = percentile(&sorted, 0.5);
            results.push(serde_json::json!({
                "bytes": size,
                "case": case.name(),
                "ns_per_call": per_call,
                "median_ns_per_call": median,
                "min_ns_per_call": sorted[0],
                "max_ns_per_call": sorted[sorted.len() - 1],
                "mib_per_s_median": (size as f64 / (1u64 << 20) as f64 / (median as f64 / 1e9)).round(),
            }));
        }
    }
    let mut sorted_sign = signed.clone();
    sorted_sign.sort_unstable();
    let record = serde_json::json!({
        "schema": "sentinel-bench/s3-hash/1",
        "workload": "s3-hash",
        "started_at_unix_ms": started_at as u64,
        "rounds": args.rounds,
        "sample_mib": args.sample_mib,
        "order": order_log,
        "results": results,
        "sign": {
            "iterations_per_round": args.sign_iterations,
            "ns_per_call": signed,
            "median_ns_per_call": percentile(&sorted_sign, 0.5),
            "min_ns_per_call": sorted_sign[0],
            "max_ns_per_call": sorted_sign[sorted_sign.len() - 1],
        },
    });
    println!("{record}");
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("s3-hash-bench: {e}");
            ExitCode::FAILURE
        }
    }
}
