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
    /// Host-local administration of local login, on the controller's own host
    Admin(AdminArgs),
}

/// Authorized by access to the controller's data directory, not by a session.
/// Passwords are read from standard input; no subcommand accepts one in argv.
#[derive(Args)]
pub struct AdminArgs {
    #[command(subcommand)]
    pub command: AdminCommand,
}

#[derive(Args)]
pub struct DataDir {
    /// Absolute controller data directory holding the metadata database
    #[arg(long, value_name = "PATH")]
    pub data_dir: PathBuf,
}

#[derive(Subcommand)]
pub enum AdminCommand {
    /// Admit the first super admin; refused once any active super admin exists
    Bootstrap {
        #[command(flatten)]
        data: DataDir,
        /// Canonical login name: lower-case letters, digits, '.', '-' or '_'
        #[arg(long)]
        username: String,
        /// Bounded display metadata, not a login identity
        #[arg(long, default_value = "Administrator")]
        display_name: String,
    },
    /// Reset a local password, clear its lockout and revoke its sessions
    Recover {
        #[command(flatten)]
        data: DataDir,
        #[arg(long)]
        username: String,
    },
    /// Report bootstrap availability, super admins, live sessions and audit
    Status {
        #[command(flatten)]
        data: DataDir,
    },
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
