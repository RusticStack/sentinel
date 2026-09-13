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
