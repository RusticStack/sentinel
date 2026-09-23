//! The O05 command surface over [`crate::client::Client`]: `run`, `status`,
//! `wait`, `job`, `log`, `workers`, `queue`, `artifact` and `cache`, with
//! text, JSON and NDJSON output, pagination and the stable exit codes.
//!
//! Stub: the argument shapes follow the plan and the owning unit (E) may
//! restructure them freely inside this directory; `cli.rs` names only the
//! nine `*Args` types, [`Invocation`] and [`run`].

use clap::{Args, Subcommand};

use crate::client::{self, ClientArgs, Exit};

#[derive(Args, Debug)]
pub struct RunArgs {
    #[command(flatten)]
    pub client: ClientArgs,
    #[command(subcommand)]
    pub command: RunCommand,
}

#[derive(Subcommand, Debug)]
pub enum RunCommand {
    /// Dispatch a pipeline file against a pinned source revision
    Dispatch {
        #[arg(long, value_name = "SLUG")]
        tenant: Option<String>,
        #[arg(long)]
        repo: String,
        #[arg(long, value_name = "FILE")]
        pipeline: std::path::PathBuf,
        #[arg(long)]
        source: String,
        #[arg(long)]
        sha: String,
        #[arg(long)]
        r#ref: Option<String>,
        #[arg(long)]
        idempotency_key: Option<String>,
    },
    /// A run and its jobs
    Status { run: String },
    /// Runs of a repository, newest first
    List {
        #[arg(long, value_name = "SLUG")]
        tenant: Option<String>,
        #[arg(long)]
        repo: String,
        #[arg(long)]
        before: Option<String>,
        #[arg(long)]
        all: bool,
        #[arg(long)]
        limit: Option<u32>,
    },
    /// Record cancellation for a run
    Cancel { run: String },
    /// Wait until a run finishes: exit 0 passed, 8 not passed, 7 deadline
    Wait {
        run: String,
        #[arg(long, value_name = "DURATION")]
        timeout: Option<String>,
    },
}

#[derive(Args, Debug)]
pub struct StatusArgs {
    #[command(flatten)]
    pub client: ClientArgs,
    pub run: String,
}

#[derive(Args, Debug)]
pub struct WaitArgs {
    #[command(flatten)]
    pub client: ClientArgs,
    pub run: String,
    #[arg(long, value_name = "DURATION")]
    pub timeout: Option<String>,
}

#[derive(Args, Debug)]
pub struct JobArgs {
    #[command(flatten)]
    pub client: ClientArgs,
    #[command(subcommand)]
    pub command: JobCommand,
}

#[derive(Subcommand, Debug)]
pub enum JobCommand {
    Cancel { job: String },
    Rerun { job: String },
}

#[derive(Args, Debug)]
pub struct LogArgs {
    #[command(flatten)]
    pub client: ClientArgs,
    #[command(subcommand)]
    pub command: LogCommand,
}

#[derive(Subcommand, Debug)]
pub enum LogCommand {
    /// An attempt's log; --follow waits until it is complete
    Show {
        attempt: String,
        #[arg(long)]
        follow: bool,
        #[arg(long)]
        step: Option<u32>,
    },
    /// Find a literal string in an attempt's log
    Search {
        attempt: String,
        #[arg(long)]
        text: String,
    },
}

#[derive(Args, Debug)]
pub struct WorkersArgs {
    #[command(flatten)]
    pub client: ClientArgs,
    #[command(subcommand)]
    pub command: WorkersCommand,
}

#[derive(Subcommand, Debug)]
pub enum WorkersCommand {
    List {
        #[arg(long, value_name = "SLUG")]
        tenant: Option<String>,
    },
    Drain {
        worker: String,
    },
    Undrain {
        worker: String,
    },
}

#[derive(Args, Debug)]
pub struct QueueArgs {
    #[command(flatten)]
    pub client: ClientArgs,
    #[arg(long, value_name = "SLUG")]
    pub tenant: Option<String>,
    #[arg(long)]
    pub limit: Option<u32>,
}

#[derive(Args, Debug)]
pub struct ArtifactArgs {
    #[command(flatten)]
    pub client: ClientArgs,
    #[command(subcommand)]
    pub command: ArtifactCommand,
}

#[derive(Subcommand, Debug)]
pub enum ArtifactCommand {
    List {
        run: String,
    },
    Show {
        run: String,
        artifact: String,
    },
    Download {
        run: String,
        artifact: String,
        #[arg(long)]
        path: String,
        #[arg(long, value_name = "FILE")]
        out: std::path::PathBuf,
    },
}

#[derive(Args, Debug)]
pub struct CacheArgs {
    #[command(flatten)]
    pub client: ClientArgs,
    #[command(subcommand)]
    pub command: CacheCommand,
}

#[derive(Subcommand, Debug)]
pub enum CacheCommand {
    /// Cache records of one attempt
    Show { attempt: String },
}

/// One of the O05 top-level commands, as parsed.
#[derive(Debug)]
pub enum Invocation {
    Run(RunArgs),
    Status(StatusArgs),
    Wait(WaitArgs),
    Job(JobArgs),
    Log(LogArgs),
    Workers(WorkersArgs),
    Queue(QueueArgs),
    Artifact(ArtifactArgs),
    Cache(CacheArgs),
}

pub fn run(invocation: Invocation) -> Result<(), client::Error> {
    let _ = invocation;
    Err(client::Error::new(
        Exit::Usage,
        "this command is not available yet",
    ))
}
