use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};
use sentinel::{LogFormat, LogLevel};

#[derive(Parser)]
#[command(version, about, propagate_version = true)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Start the Linux controller lifecycle (CI scheduling is not implemented yet)
    Server(ServiceArgs),
    /// Start the separate Linux worker lifecycle (job execution is not implemented yet)
    Worker(ServiceArgs),
    /// Validate or explain a `.sentinel.yml` offline, on any platform
    Pipeline(PipelineArgs),
}

#[derive(Args)]
pub struct PipelineArgs {
    #[command(subcommand)]
    pub command: PipelineCommand,
}

#[derive(Subcommand)]
pub enum PipelineCommand {
    /// Load, decode and compile the file; print nothing on success
    Validate {
        /// Path to the pipeline file
        file: PathBuf,
    },
    /// Show jobs, order, budgets, required grants and unresolved runtime inputs
    Explain {
        file: PathBuf,
        /// Machine-readable output (`sentinel.explain/1`)
        #[arg(long)]
        json: bool,
    },
}

#[derive(Args)]
pub struct ServiceArgs {
    /// Read a strict TOML configuration file; no implicit discovery
    #[arg(long, value_name = "FILE")]
    pub config: Option<PathBuf>,

    /// Absolute role data directory; overrides the configuration file
    #[arg(long, value_name = "PATH")]
    pub data_dir: Option<PathBuf>,

    /// Validate configuration and print the resolved data path without starting
    #[arg(long)]
    pub check: bool,

    /// Internal diagnostic format (text or JSON lines); overrides the config file
    #[arg(long, value_enum)]
    pub log_format: Option<LogFormat>,

    /// Internal diagnostic verbosity; defaults to info
    #[arg(long, value_enum)]
    pub log_level: Option<LogLevel>,
}
