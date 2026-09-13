//! Feasibility probes. Each subcommand prints one JSON line; durations are monotonic.
use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    process::ExitCode,
    time::Instant,
};

mod redb_probe;

use clap::{Parser, Subcommand, ValueEnum};
use serde::Serialize;

#[derive(Parser)]
#[command(version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// SQLite WAL commit and indexed dispatch latency with one writer
    Sqlite(SqliteArgs),
    /// The same dispatch workload on redb (pure-Rust ACID B-tree)
    Redb(redb_probe::RedbArgs),
    /// Generate a file tree fixture of many small files
    Generate(GenerateArgs),
    /// Clone a directory tree by reflink, explicit read/write copy, or std::fs::copy
    Clone(CloneArgs),
}

#[derive(clap::Args)]
struct SqliteArgs {
    /// Database file; created fresh (existing file is removed)
    #[arg(long)]
    path: PathBuf,
    /// Jobs enqueued one per transaction, then dispatched one per transaction
    #[arg(long, default_value_t = 2000)]
    jobs: u64,
    /// Extra ready rows inserted in batches before dispatch, to test index scaling
    #[arg(long, default_value_t = 100_000)]
    backlog: u64,
    #[arg(long, value_enum, default_value_t = Sync::Full)]
    synchronous: Sync,
}

#[derive(Clone, Copy, ValueEnum, Serialize)]
#[serde(rename_all = "lowercase")]
enum Sync {
    Full,
    Normal,
}

#[derive(clap::Args)]
struct GenerateArgs {
    #[arg(long)]
    dest: PathBuf,
    #[arg(long, default_value_t = 20_000)]
    files: u64,
    #[arg(long, default_value_t = 16_384)]
    bytes_per_file: u64,
    /// Files per directory level
    #[arg(long, default_value_t = 256)]
    fan_out: u64,
}

#[derive(clap::Args)]
struct CloneArgs {
    #[arg(long)]
    source: PathBuf,
    #[arg(long)]
    dest: PathBuf,
    #[arg(long, value_enum)]
    mode: CloneMode,
    /// After cloning, read every destination file once and time it (first-touch cost)
    #[arg(long)]
    verify_read: bool,
}

#[derive(Clone, Copy, PartialEq, ValueEnum, Serialize)]
#[serde(rename_all = "kebab-case")]
enum CloneMode {
    /// FICLONE ioctl per file; fails where the filesystem lacks reflinks (Linux only)
    Reflink,
    /// Explicit 1 MiB read/write loop; never shares extents
    Copy,
    /// std::fs::copy (copy_file_range on Linux, which may reflink transparently)
    FsCopy,
}

#[derive(Serialize)]
pub struct Stats {
    count: usize,
    min_ns: u64,
    median_ns: u64,
    p95_ns: u64,
    p99_ns: u64,
    max_ns: u64,
    total_ns: u64,
}

pub fn stats(mut v: Vec<u64>) -> Stats {
    v.sort_unstable();
    let rank = |p: f64| v[((p * v.len() as f64).ceil() as usize).max(1) - 1];
    Stats {
        count: v.len(),
        min_ns: v[0],
        median_ns: rank(0.5),
        p95_ns: rank(0.95),
        p99_ns: rank(0.99),
        max_ns: v[v.len() - 1],
        total_ns: v.iter().sum(),
    }
}

pub fn ns(start: Instant) -> u64 {
    start.elapsed().as_nanos().min(u64::MAX as u128) as u64
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Sqlite(args) => sqlite(args),
        Command::Redb(args) => redb_probe::run(args),
        Command::Generate(args) => generate(args),
        Command::Clone(args) => clone(args),
    };
    match result {
        Ok(json) => {
            println!("{json}");
            ExitCode::SUCCESS
        }
        Err(message) => {
            eprintln!("error: {message}");
            ExitCode::from(1)
        }
    }
}

#[derive(Serialize)]
struct SqliteReport {
    probe: &'static str,
    sqlite_version: String,
    synchronous: Sync,
    journal_mode: String,
    jobs: u64,
    backlog: u64,
    enqueue_commit: Stats,
    backlog_batch_insert_rows_per_s: u64,
    dispatch_commit: Stats,
    ready_query_with_backlog: Stats,
    wal_checkpoint_ns: u64,
    db_bytes: u64,
}

fn sqlite(args: SqliteArgs) -> Result<String, String> {
    use rusqlite::{Connection, params};
    let _ = fs::remove_file(&args.path);
    let _ = fs::remove_file(args.path.with_extension("sqlite-wal"));
    let conn = Connection::open(&args.path).map_err(|e| e.to_string())?;
    let sync = match args.synchronous {
        Sync::Full => "FULL",
        Sync::Normal => "NORMAL",
    };
    conn.execute_batch(&format!(
        "PRAGMA journal_mode=WAL; PRAGMA synchronous={sync}; PRAGMA foreign_keys=ON;
         CREATE TABLE runs(id INTEGER PRIMARY KEY, tenant TEXT NOT NULL);
         CREATE TABLE jobs(
           id INTEGER PRIMARY KEY, run_id INTEGER NOT NULL REFERENCES runs(id),
           state TEXT NOT NULL, priority INTEGER NOT NULL, created_seq INTEGER NOT NULL,
           lease_worker TEXT, lease_until INTEGER, attempt INTEGER NOT NULL DEFAULT 0);
         CREATE INDEX jobs_ready ON jobs(state, priority, created_seq) WHERE state='ready';
         INSERT INTO runs(id, tenant) VALUES (1, 't1');"
    ))
    .map_err(|e| e.to_string())?;
    let journal_mode: String = conn
        .query_row("PRAGMA journal_mode", [], |r| r.get(0))
        .map_err(|e| e.to_string())?;

    // Enqueue: one durable transaction per job, as a webhook-driven intake would do.
    let mut enqueue = Vec::with_capacity(args.jobs as usize);
    let mut insert = conn
        .prepare(
            "INSERT INTO jobs(run_id, state, priority, created_seq) VALUES (1, 'ready', 5, ?1)",
        )
        .map_err(|e| e.to_string())?;
    for i in 0..args.jobs {
        let t = Instant::now();
        conn.execute_batch("BEGIN IMMEDIATE")
            .map_err(|e| e.to_string())?;
        insert
            .execute(params![i as i64])
            .map_err(|e| e.to_string())?;
        conn.execute_batch("COMMIT").map_err(|e| e.to_string())?;
        enqueue.push(ns(t));
    }
    drop(insert);

    // Backlog: batched inserts of older-but-lower-priority ready rows.
    let t = Instant::now();
    {
        let tx = conn.unchecked_transaction().map_err(|e| e.to_string())?;
        let mut insert = tx
            .prepare(
                "INSERT INTO jobs(run_id, state, priority, created_seq) VALUES (1, 'ready', 9, ?1)",
            )
            .map_err(|e| e.to_string())?;
        for i in 0..args.backlog {
            insert
                .execute(params![(args.jobs + i) as i64])
                .map_err(|e| e.to_string())?;
        }
        drop(insert);
        tx.commit().map_err(|e| e.to_string())?;
    }
    let backlog_ns = ns(t).max(1);
    let backlog_rows_per_s = args.backlog * 1_000_000_000 / backlog_ns;

    // Dispatch: pick the best ready job and lease it, one transaction each.
    let mut dispatch = Vec::with_capacity(args.jobs as usize);
    let mut query = Vec::with_capacity(args.jobs as usize);
    let mut pick = conn
        .prepare("SELECT id FROM jobs WHERE state='ready' ORDER BY priority, created_seq LIMIT 1")
        .map_err(|e| e.to_string())?;
    let mut lease = conn
        .prepare("UPDATE jobs SET state='leased', lease_worker=?2, lease_until=?3, attempt=attempt+1 WHERE id=?1 AND state='ready'")
        .map_err(|e| e.to_string())?;
    for i in 0..args.jobs {
        let t = Instant::now();
        conn.execute_batch("BEGIN IMMEDIATE")
            .map_err(|e| e.to_string())?;
        let tq = Instant::now();
        let id: i64 = pick
            .query_row([], |r| r.get(0))
            .map_err(|e| e.to_string())?;
        query.push(ns(tq));
        let changed = lease
            .execute(params![id, "worker-1", i as i64])
            .map_err(|e| e.to_string())?;
        if changed != 1 {
            return Err(format!("dispatch of job {id} changed {changed} rows"));
        }
        conn.execute_batch("COMMIT").map_err(|e| e.to_string())?;
        dispatch.push(ns(t));
    }
    drop(pick);
    drop(lease);

    let t = Instant::now();
    conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
        .map_err(|e| e.to_string())?;
    let wal_checkpoint_ns = ns(t);
    let db_bytes = fs::metadata(&args.path).map(|m| m.len()).unwrap_or(0);

    let report = SqliteReport {
        probe: "sqlite-dispatch/1",
        sqlite_version: rusqlite::version().to_string(),
        synchronous: args.synchronous,
        journal_mode,
        jobs: args.jobs,
        backlog: args.backlog,
        enqueue_commit: stats(enqueue),
        backlog_batch_insert_rows_per_s: backlog_rows_per_s,
        dispatch_commit: stats(dispatch),
        ready_query_with_backlog: stats(query),
        wal_checkpoint_ns,
        db_bytes,
    };
    serde_json::to_string(&report).map_err(|e| e.to_string())
}

#[derive(Serialize)]
struct GenerateReport {
    probe: &'static str,
    dest: String,
    files: u64,
    bytes: u64,
    wall_ns: u64,
}

fn generate(args: GenerateArgs) -> Result<String, String> {
    let t = Instant::now();
    fs::create_dir_all(&args.dest).map_err(|e| e.to_string())?;
    let mut buf = vec![0u8; args.bytes_per_file as usize];
    for i in 0..args.files {
        let dir = args.dest.join(format!("d{:04}", i / args.fan_out));
        if i % args.fan_out == 0 {
            fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        }
        // Distinct content per file so dedup/compression cannot hide copy cost.
        for (j, b) in buf.iter_mut().enumerate() {
            *b = (i as usize ^ j).to_le_bytes()[0];
        }
        fs::write(dir.join(format!("f{i}.bin")), &buf).map_err(|e| e.to_string())?;
    }
    let report = GenerateReport {
        probe: "generate/1",
        dest: args.dest.display().to_string(),
        files: args.files,
        bytes: args.files * args.bytes_per_file,
        wall_ns: ns(t),
    };
    serde_json::to_string(&report).map_err(|e| e.to_string())
}

#[derive(Serialize)]
struct CloneReport {
    probe: &'static str,
    mode: CloneMode,
    source: String,
    dest: String,
    files: u64,
    dirs: u64,
    bytes: u64,
    clone_wall_ns: u64,
    per_file: Stats,
    verify_read_ns: Option<u64>,
}

fn clone(args: CloneArgs) -> Result<String, String> {
    if args.dest.exists() {
        return Err(format!("destination exists: {}", args.dest.display()));
    }
    let mut per_file = Vec::new();
    let mut bytes = 0u64;
    let mut dirs = 0u64;
    // One reusable buffer: allocating per file would dominate small-file copies.
    let mut buf = vec![0u8; 1 << 20];
    let t = Instant::now();
    clone_tree(
        &args.source,
        &args.dest,
        args.mode,
        &mut per_file,
        &mut bytes,
        &mut dirs,
        &mut buf,
    )?;
    let clone_wall_ns = ns(t);
    let verify_read_ns = if args.verify_read {
        let t = Instant::now();
        read_tree(&args.dest)?;
        Some(ns(t))
    } else {
        None
    };
    if per_file.is_empty() {
        return Err("source tree has no files".into());
    }
    let report = CloneReport {
        probe: "clone/1",
        mode: args.mode,
        source: args.source.display().to_string(),
        dest: args.dest.display().to_string(),
        files: per_file.len() as u64,
        dirs,
        bytes,
        clone_wall_ns,
        per_file: stats(per_file),
        verify_read_ns,
    };
    serde_json::to_string(&report).map_err(|e| e.to_string())
}

fn clone_tree(
    src: &Path,
    dst: &Path,
    mode: CloneMode,
    per_file: &mut Vec<u64>,
    bytes: &mut u64,
    dirs: &mut u64,
    buf: &mut [u8],
) -> Result<(), String> {
    fs::create_dir(dst).map_err(|e| format!("{}: {e}", dst.display()))?;
    *dirs += 1;
    let mut entries: Vec<_> = fs::read_dir(src)
        .map_err(|e| format!("{}: {e}", src.display()))?
        .collect::<Result<_, _>>()
        .map_err(|e| e.to_string())?;
    entries.sort_by_key(|e| e.file_name());
    for entry in entries {
        let from = entry.path();
        let to = dst.join(entry.file_name());
        let kind = entry.file_type().map_err(|e| e.to_string())?;
        if kind.is_dir() {
            clone_tree(&from, &to, mode, per_file, bytes, dirs, buf)?;
        } else if kind.is_file() {
            let t = Instant::now();
            let n = match mode {
                CloneMode::Reflink => reflink(&from, &to)?,
                CloneMode::Copy => explicit_copy(&from, &to, buf)?,
                CloneMode::FsCopy => fs::copy(&from, &to).map_err(|e| e.to_string())?,
            };
            per_file.push(ns(t));
            *bytes += n;
        } else {
            return Err(format!(
                "unsupported entry (symlink/special): {}",
                from.display()
            ));
        }
    }
    Ok(())
}

fn explicit_copy(from: &Path, to: &Path, buf: &mut [u8]) -> Result<u64, String> {
    let mut input = fs::File::open(from).map_err(|e| e.to_string())?;
    let mut output = fs::File::create(to).map_err(|e| e.to_string())?;
    let mut total = 0u64;
    loop {
        let n = input.read(buf).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        output.write_all(&buf[..n]).map_err(|e| e.to_string())?;
        total += n as u64;
    }
    Ok(total)
}

#[cfg(target_os = "linux")]
fn reflink(from: &Path, to: &Path) -> Result<u64, String> {
    use std::os::fd::AsRawFd;
    let input = fs::File::open(from).map_err(|e| e.to_string())?;
    let output = fs::File::create(to).map_err(|e| e.to_string())?;
    // SAFETY: both descriptors are open and owned for the duration of the call;
    // FICLONE takes the source fd as its integer argument.
    let rc = unsafe { libc::ioctl(output.as_raw_fd(), libc::FICLONE, input.as_raw_fd()) };
    if rc != 0 {
        return Err(format!(
            "reflink unsupported or failed for {}: {}",
            from.display(),
            std::io::Error::last_os_error()
        ));
    }
    input.metadata().map(|m| m.len()).map_err(|e| e.to_string())
}

#[cfg(not(target_os = "linux"))]
fn reflink(_from: &Path, _to: &Path) -> Result<u64, String> {
    Err("reflink mode is Linux-only".into())
}

fn read_tree(dir: &Path) -> Result<(), String> {
    let mut buf = vec![0u8; 1 << 20];
    for entry in fs::read_dir(dir).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        let path = entry.path();
        if path.is_dir() {
            read_tree(&path)?;
        } else {
            let mut f = fs::File::open(&path).map_err(|e| e.to_string())?;
            while f.read(&mut buf).map_err(|e| e.to_string())? != 0 {}
        }
    }
    Ok(())
}
