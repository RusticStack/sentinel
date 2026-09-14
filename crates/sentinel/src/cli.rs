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
    /// Provision, list and revoke scoped, expiring API credentials
    Token(TokenArgs),
    /// Inspect and remove linked external sign-in identities
    Identity(IdentityArgs),
    /// Show or change the deployment admission policy
    Policy(PolicyArgs),
    /// Create, list and revoke one-time invitations
    Invite(InviteArgs),
    /// Review pending applications; approve or reject accounts
    Account(AccountArgs),
}

#[derive(Args)]
pub struct PolicyArgs {
    #[command(subcommand)]
    pub command: PolicyCommand,
}

#[derive(Subcommand)]
pub enum PolicyCommand {
    /// Print the current admission policy
    Show {
        #[command(flatten)]
        data: DataDir,
    },
    /// Change one or more settings; unspecified settings keep their value
    Set {
        #[command(flatten)]
        data: DataDir,
        /// closed, invite-only or approval-required
        #[arg(long)]
        registration: Option<String>,
        /// super-admin-only or approved-users (personal namespaces)
        #[arg(long)]
        tenant_creation: Option<String>,
        /// super-admin-only or tenant-admins
        #[arg(long)]
        installation_binding: Option<String>,
    },
}

#[derive(Args)]
pub struct InviteArgs {
    #[command(subcommand)]
    pub command: InviteCommand,
}

#[derive(Subcommand)]
pub enum InviteCommand {
    /// Issue an invitation and print its secret to stdout, once
    Create {
        #[command(flatten)]
        data: DataDir,
        /// Join this tenant namespace on acceptance; requires --role
        #[arg(long, value_name = "SLUG")]
        tenant: Option<String>,
        /// reader, operator or admin
        #[arg(long)]
        role: Option<String>,
        /// Bind to one verified identity, as `<provider>:<subject>`
        #[arg(long, value_name = "PROVIDER:SUBJECT")]
        identity: Option<String>,
        /// Lifetime such as 7d or 12h; bounded by the deployment maximum
        #[arg(long, value_name = "DURATION", default_value = "7d")]
        expires_in: String,
    },
    /// List invitations as metadata; secrets are never shown
    List {
        #[command(flatten)]
        data: DataDir,
        #[arg(long, value_name = "SLUG")]
        tenant: Option<String>,
    },
    /// Revoke an unspent invitation
    Revoke {
        #[command(flatten)]
        data: DataDir,
        /// The `inv_` identifier printed at creation or by `invite list`
        #[arg(long)]
        id: String,
    },
}

#[derive(Args)]
pub struct AccountArgs {
    #[command(subcommand)]
    pub command: AccountCommand,
}

#[derive(Subcommand)]
pub enum AccountCommand {
    /// List applications waiting for a decision
    Pending {
        #[command(flatten)]
        data: DataDir,
    },
    /// Approve a pending account so it can sign in
    Approve {
        #[command(flatten)]
        data: DataDir,
        #[arg(long)]
        user: String,
    },
    /// Reject an account, ending its access and keeping its identity claimed
    Reject {
        #[command(flatten)]
        data: DataDir,
        #[arg(long)]
        user: String,
    },
}

#[derive(Args)]
pub struct IdentityArgs {
    #[command(subcommand)]
    pub command: IdentityCommand,
}

#[derive(Subcommand)]
pub enum IdentityCommand {
    /// Show which external accounts can sign in as this account
    List {
        #[command(flatten)]
        data: DataDir,
        /// A local username or a `usr_` identifier
        #[arg(long)]
        user: String,
    },
    /// Remove a link, so that external account can no longer sign in as this one
    Unlink {
        #[command(flatten)]
        data: DataDir,
        #[arg(long)]
        user: String,
        /// Configured provider key, such as `github`
        #[arg(long, default_value = "github")]
        provider: String,
    },
}

#[derive(Args)]
pub struct TokenArgs {
    #[command(subcommand)]
    pub command: TokenCommand,
}

#[derive(Subcommand)]
pub enum TokenCommand {
    /// Issue one credential and print its secret to stdout, once
    Issue {
        #[command(flatten)]
        data: DataDir,
        /// Account that will act: a local username or a `usr_` identifier
        #[arg(long)]
        user: String,
        /// Operator-facing label, so the credential can be recognized later
        #[arg(long)]
        name: String,
        /// Comma-separated scope: read, run, secrets, tenant-admin, platform-admin
        #[arg(long, default_value = "read")]
        scope: String,
        /// Narrow to one tenant namespace, by slug
        #[arg(long, value_name = "SLUG")]
        tenant: Option<String>,
        /// Narrow to one repository of that tenant, by name; requires --tenant
        #[arg(long, value_name = "NAME")]
        repo: Option<String>,
        /// Lifetime such as 30d, 12h or 90m; bounded by the deployment maximum
        #[arg(long, value_name = "DURATION", default_value = "30d")]
        expires_in: String,
    },
    /// List an account's credentials as metadata; secrets are never shown
    List {
        #[command(flatten)]
        data: DataDir,
        #[arg(long)]
        user: String,
    },
    /// Revoke one credential immediately and permanently
    Revoke {
        #[command(flatten)]
        data: DataDir,
        /// The `tok_` identifier printed at issuance or by `token list`
        #[arg(long)]
        id: String,
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
