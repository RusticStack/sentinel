//! What verifying an archive entry costs while it streams, against the two-pass alternative.
//!
//! The archive route hashes every entry with BLAKE3 as its bytes pass into the response, so a local file and an
//! object fetched back from the external copy are both verified by the same single pass that sends them. The
//! alternative — reading an entry to verify it and then reading it again to send it — costs one extra pass over
//! every byte. This bench times both, beside the plain copy they both contain, with no network and no server in
//! the loop, and prints one `sentinel-bench/archive-hash/1` JSON line.
//!
//!     cargo run --release -p sentinel-api --example archive-hash-bench -- --rounds 7
//!
//! Each round times every case once per size, and the order of the cases reverses every round (ABBA). A case
//! repeats until it has moved at least `--sample-mib` MiB, so a small payload is not a single timer read.

use std::{
    hint::black_box,
    io::{self, Read, Write},
    process::ExitCode,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

const DEFAULT_SIZES: [usize; 3] = [64 << 10, 1 << 20, 16 << 20];
/// The chunk the archive reads an entry into, as `io::copy` and the response writer use.
const CHUNK: usize = 64 << 10;

#[derive(Clone, Copy)]
enum Case {
    /// A copy with no hashing: the floor both other cases contain.
    Copy,
    /// One BLAKE3 pass: what verifying an entry costs on its own.
    Hash,
    /// The pass the route takes: copy and hash in one walk (tar).
    CopyHash,
    /// The same with the zip entry's CRC-32.
    CopyHashCrc,
    /// Verify the whole entry, then copy it: two walks over the bytes.
    HashThenCopy,
}

impl Case {
    const ALL: [Case; 5] = [
        Case::Copy,
        Case::Hash,
        Case::CopyHash,
        Case::CopyHashCrc,
        Case::HashThenCopy,
    ];

    fn name(self) -> &'static str {
        match self {
            Case::Copy => "copy",
            Case::Hash => "hash",
            Case::CopyHash => "copy_hash",
            Case::CopyHashCrc => "copy_hash_crc",
            Case::HashThenCopy => "hash_then_copy",
        }
    }

    fn run(self, body: &[u8]) {
        match self {
            Case::Copy => copy(body, &mut io::sink()),
            Case::Hash => {
                black_box(blake3::hash(black_box(body)));
            }
            Case::CopyHash => {
                let sink = io::sink();
                let mut out = Hashing::new(sink, false);
                copy(body, &mut out);
                black_box(out.finish());
            }
            Case::CopyHashCrc => {
                let sink = io::sink();
                let mut out = Hashing::new(sink, true);
                copy(body, &mut out);
                black_box(out.finish());
            }
            Case::HashThenCopy => {
                black_box(blake3::hash(black_box(body)));
                copy(body, &mut io::sink());
            }
        }
    }
}

struct Hashing<W> {
    inner: W,
    hasher: blake3::Hasher,
    crc: crc32fast::Hasher,
    zip: bool,
}

impl<W> Hashing<W> {
    fn new(inner: W, zip: bool) -> Hashing<W> {
        Hashing {
            inner,
            hasher: blake3::Hasher::new(),
            crc: crc32fast::Hasher::new(),
            zip,
        }
    }

    fn finish(self) -> ([u8; 32], u32) {
        (*self.hasher.finalize().as_bytes(), self.crc.finalize())
    }
}

impl<W: Write> Write for Hashing<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.hasher.update(buf);
        if self.zip {
            self.crc.update(buf);
        }
        self.inner.write_all(buf)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// Reads a body into 64 KiB chunks and writes them out, the way a response body does.
fn copy(body: &[u8], out: &mut impl Write) {
    let mut buffer = [0u8; CHUNK];
    let mut at = 0;
    while at < body.len() {
        let end = (at + CHUNK).min(body.len());
        let got = (&body[at..end]).read(&mut buffer[..]).unwrap();
        out.write_all(&buffer[..got]).unwrap();
        at += got;
    }
}

struct Args {
    rounds: usize,
    sizes: Vec<usize>,
    sample_mib: usize,
}

fn parse() -> Result<Args, String> {
    let mut args = Args {
        rounds: 7,
        sizes: DEFAULT_SIZES.to_vec(),
        sample_mib: 256,
    };
    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        let mut value = |name: &str| it.next().ok_or(format!("{name} needs a value"));
        match flag.as_str() {
            "--rounds" => args.rounds = number(&value("--rounds")?)?,
            "--sample-mib" => args.sample_mib = number(&value("--sample-mib")?)?,
            "--sizes" => {
                args.sizes = value("--sizes")?
                    .split(',')
                    .map(number)
                    .collect::<Result<_, _>>()?;
            }
            other => return Err(format!("unknown argument {other}")),
        }
    }
    if args.rounds == 0 || args.sample_mib == 0 || args.sizes.is_empty() || args.sizes.contains(&0)
    {
        return Err("--rounds, --sample-mib and every size must be positive".into());
    }
    Ok(args)
}

fn number<T: std::str::FromStr>(text: &str) -> Result<T, String> {
    text.trim()
        .parse()
        .map_err(|_| format!("{text:?} is not a number"))
}

/// Deterministic, incompressible-looking bytes: a constant fill would let a future implementation shortcut.
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

/// Nanoseconds per case over enough calls to move `sample_mib`.
fn time_case(case: Case, body: &[u8], sample_mib: usize) -> u64 {
    let calls = ((sample_mib << 20) / body.len()).max(1);
    let started = Instant::now();
    for _ in 0..calls {
        case.run(body);
    }
    (started.elapsed().as_nanos() / calls as u128) as u64
}

fn run() -> Result<(), String> {
    let args = parse()?;
    let started_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis());
    let bodies: Vec<Vec<u8>> = args.sizes.iter().map(|&n| payload(n)).collect();
    let mut seen: Vec<Vec<Vec<u64>>> = vec![vec![Vec::new(); Case::ALL.len()]; args.sizes.len()];
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
        for size in 0..bodies.len() {
            for &at in &order {
                let case = Case::ALL[at];
                let ns = time_case(case, &bodies[size], args.sample_mib);
                seen[size][at].push(ns);
            }
        }
    }
    let cases: Vec<String> = (0..Case::ALL.len())
        .map(|at| {
            let sizes: Vec<String> = (0..bodies.len())
                .map(|size| {
                    let mut ns = seen[size][at].clone();
                    ns.sort_unstable();
                    let bytes = bodies[size].len() as f64;
                    let median = ns[ns.len() / 2] as f64;
                    format!(
                        "{{\"bytes\":{},\"median_ns\":{},\"mib_per_s\":{:.1}}}",
                        bodies[size].len(),
                        ns[ns.len() / 2],
                        bytes / median * 1e3
                    )
                })
                .collect();
            format!("\"{}\":[{}]", Case::ALL[at].name(), sizes.join(","))
        })
        .collect();
    println!(
        "{{\"schema\":\"sentinel-bench/archive-hash/1\",\"probe\":\"archive-hash/1\",\"rounds\":{},\"sample_mib\":{},\"chunk_bytes\":{},\"started_at_unix_ms\":{},\"cases\":{{{}}}}}",
        args.rounds,
        args.sample_mib,
        CHUNK,
        started_at,
        cases.join(",")
    );
    Ok(())
}

fn main() -> ExitCode {
    if let Err(message) = run() {
        eprintln!("archive-hash-bench: {message}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}
