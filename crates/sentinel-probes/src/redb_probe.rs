//! Same dispatch workload as the SQLite probe, on redb (pure-Rust, ACID,
//! copy-on-write B-tree). Jobs live in one table keyed by id; the ready
//! queue is a second table keyed by (priority, created_seq) so the pick is a
//! `first()` on an ordered index, matching the SQLite partial index.
use std::{fs, path::PathBuf, time::Instant};

use redb::{
    Database, Durability, ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition,
};
use serde::Serialize;

use crate::{Stats, ns, stats};

const JOBS: TableDefinition<u64, (u8, u8, u64, u64)> = TableDefinition::new("jobs");
const READY: TableDefinition<(u8, u64), u64> = TableDefinition::new("ready");

#[derive(clap::Args)]
pub struct RedbArgs {
    #[arg(long)]
    path: PathBuf,
    #[arg(long, default_value_t = 2000)]
    jobs: u64,
    #[arg(long, default_value_t = 100_000)]
    backlog: u64,
    /// `immediate` fsyncs every commit (durable); `eventual` defers like SQLite NORMAL
    #[arg(long, value_enum, default_value_t = Dur::Immediate)]
    durability: Dur,
}

#[derive(Clone, Copy, clap::ValueEnum, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Dur {
    Immediate,
    Eventual,
}

#[derive(Serialize)]
struct Report {
    probe: &'static str,
    engine: &'static str,
    durability: Dur,
    jobs: u64,
    backlog: u64,
    enqueue_commit: Stats,
    backlog_batch_insert_rows_per_s: u64,
    dispatch_commit: Stats,
    ready_query_with_backlog: Stats,
    db_bytes: u64,
}

fn durability(d: Dur) -> Durability {
    match d {
        Dur::Immediate => Durability::Immediate,
        Dur::Eventual => Durability::None,
    }
}

pub fn run(args: RedbArgs) -> Result<String, String> {
    let _ = fs::remove_file(&args.path);
    let db = Database::create(&args.path).map_err(|e| e.to_string())?;
    let e = |e: redb::Error| e.to_string();
    {
        let tx = db.begin_write().map_err(|x| e(x.into()))?;
        tx.open_table(JOBS).map_err(|x| e(x.into()))?;
        tx.open_table(READY).map_err(|x| e(x.into()))?;
        tx.commit().map_err(|x| e(x.into()))?;
    }

    // Enqueue: one durable transaction per job.
    let mut enqueue = Vec::with_capacity(args.jobs as usize);
    for i in 0..args.jobs {
        let t = Instant::now();
        let mut tx = db.begin_write().map_err(|x| e(x.into()))?;
        tx.set_durability(durability(args.durability))
            .map_err(|x| e(x.into()))?;
        {
            let mut jobs = tx.open_table(JOBS).map_err(|x| e(x.into()))?;
            jobs.insert(i, (1u8, 5u8, i, 0u64))
                .map_err(|x| e(x.into()))?;
            let mut ready = tx.open_table(READY).map_err(|x| e(x.into()))?;
            ready.insert((5u8, i), i).map_err(|x| e(x.into()))?;
        }
        tx.commit().map_err(|x| e(x.into()))?;
        enqueue.push(ns(t));
    }

    // Backlog: one batch of lower-priority rows.
    let t = Instant::now();
    {
        let mut tx = db.begin_write().map_err(|x| e(x.into()))?;
        tx.set_durability(durability(args.durability))
            .map_err(|x| e(x.into()))?;
        {
            let mut jobs = tx.open_table(JOBS).map_err(|x| e(x.into()))?;
            let mut ready = tx.open_table(READY).map_err(|x| e(x.into()))?;
            for i in 0..args.backlog {
                let id = args.jobs + i;
                jobs.insert(id, (1u8, 9u8, id, 0u64))
                    .map_err(|x| e(x.into()))?;
                ready.insert((9u8, id), id).map_err(|x| e(x.into()))?;
            }
        }
        tx.commit().map_err(|x| e(x.into()))?;
    }
    let backlog_rows_per_s = args.backlog * 1_000_000_000 / ns(t).max(1);

    // Dispatch: first ready key, move job to leased with fence, remove index entry.
    let mut dispatch = Vec::with_capacity(args.jobs as usize);
    let mut query = Vec::with_capacity(args.jobs as usize);
    for i in 0..args.jobs {
        let t = Instant::now();
        let mut tx = db.begin_write().map_err(|x| e(x.into()))?;
        tx.set_durability(durability(args.durability))
            .map_err(|x| e(x.into()))?;
        {
            let mut ready = tx.open_table(READY).map_err(|x| e(x.into()))?;
            let tq = Instant::now();
            let (key, id) = {
                let (k, v) = ready
                    .first()
                    .map_err(|x| e(x.into()))?
                    .ok_or("ready queue empty")?;
                (k.value(), v.value())
            };
            query.push(ns(tq));
            ready.remove(key).map_err(|x| e(x.into()))?;
            let mut jobs = tx.open_table(JOBS).map_err(|x| e(x.into()))?;
            let (state, prio, seq, _) = jobs
                .get(id)
                .map_err(|x| e(x.into()))?
                .ok_or("job row missing")?
                .value();
            if state != 1 {
                return Err(format!("job {id} not ready"));
            }
            jobs.insert(id, (2u8, prio, seq, i + 1))
                .map_err(|x| e(x.into()))?;
        }
        tx.commit().map_err(|x| e(x.into()))?;
        dispatch.push(ns(t));
    }
    let remaining = {
        let tx = db.begin_read().map_err(|x| e(x.into()))?;
        tx.open_table(READY)
            .map_err(|x| e(x.into()))?
            .len()
            .map_err(|x| e(x.into()))?
    };
    if remaining != args.backlog {
        return Err(format!(
            "expected {} ready rows left, found {remaining}",
            args.backlog
        ));
    }
    let db_bytes = fs::metadata(&args.path).map(|m| m.len()).unwrap_or(0);
    let report = Report {
        probe: "kv-dispatch/1",
        engine: "redb",
        durability: args.durability,
        jobs: args.jobs,
        backlog: args.backlog,
        enqueue_commit: stats(enqueue),
        backlog_batch_insert_rows_per_s: backlog_rows_per_s,
        dispatch_commit: stats(dispatch),
        ready_query_with_backlog: stats(query),
        db_bytes,
    };
    serde_json::to_string(&report).map_err(|x| x.to_string())
}
