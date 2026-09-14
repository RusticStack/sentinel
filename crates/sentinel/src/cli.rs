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
    /// Start the Linux controller: metadata store, worker link and dispatcher
    Server(ServiceArgs),
    /// Start the separate Linux worker: connects to its controller (execution lands with W03)
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
    /// Create the sealing key that protects second-factor seeds
    Key(KeyArgs),
    /// Inspect or remove an account's second factor
    Mfa(MfaArgs),
    /// List and revoke an account's sessions
    Session(SessionArgs),
    /// Suspend or reactivate a tenant namespace
    Tenant(TenantArgs),
    /// Register worker pools and grant shared ones to tenants
    Pool(PoolArgs),
    /// Enroll, list and revoke workers
    Worker(WorkerArgs),
    /// Print an attempt's log as stored on the controller; --follow waits for more
    Logs {
        #[command(flatten)]
        data: DataDir,
        /// The `att_` identifier of the attempt
        #[arg(long)]
        attempt: String,
        /// Keep printing until the log is complete
        #[arg(long)]
        follow: bool,
    },
}

#[derive(Args)]
pub struct WorkerArgs {
    #[command(subcommand)]
    pub command: WorkerCommand,
}

#[derive(Subcommand)]
pub enum WorkerCommand {
    /// Issue a one-time enrollment for a pool; the secret alone goes to stdout
    Enroll {
        #[command(flatten)]
        data: DataDir,
        #[arg(long)]
        pool: String,
        /// Lifetime such as 1h or 30m; bounded by one day
        #[arg(long, value_name = "DURATION", default_value = "1h")]
        expires_in: String,
    },
    /// Live workers of a pool
    List {
        #[command(flatten)]
        data: DataDir,
        #[arg(long)]
        pool: String,
    },
    /// Revoke a worker; its session is refused at its next authentication
    Revoke {
        #[command(flatten)]
        data: DataDir,
        /// The `wrk_` identifier the worker generated
        #[arg(long)]
        id: String,
    },
}

#[derive(Args)]
pub struct TenantArgs {
    #[command(subcommand)]
    pub command: TenantCommand,
}

#[derive(Subcommand)]
pub enum TenantCommand {
    /// Create an organization namespace and print its identifier
    Create {
        #[command(flatten)]
        data: DataDir,
        /// 1-63 lower-case letters, digits and hyphens, alphanumeric at both ends
        #[arg(long)]
        slug: String,
    },
    /// Stop intake, revoke the tenant's credentials and cancel its live jobs
    Suspend {
        #[command(flatten)]
        data: DataDir,
        #[arg(long, value_name = "SLUG")]
        tenant: String,
    },
    /// Lift a suspension; nothing revoked comes back on its own
    Reactivate {
        #[command(flatten)]
        data: DataDir,
        #[arg(long, value_name = "SLUG")]
        tenant: String,
    },
}

#[derive(Args)]
pub struct PoolArgs {
    #[command(subcommand)]
    pub command: PoolCommand,
}

#[derive(Subcommand)]
pub enum PoolCommand {
    /// Register a pool; dedicated to --tenant, or shared when omitted
    Create {
        #[command(flatten)]
        data: DataDir,
        /// Lower-case letters, digits and hyphens
        #[arg(long)]
        name: String,
        #[arg(long, value_name = "SLUG")]
        tenant: Option<String>,
    },
    /// Admit a tenant to a shared pool
    Grant {
        #[command(flatten)]
        data: DataDir,
        #[arg(long)]
        pool: String,
        #[arg(long, value_name = "SLUG")]
        tenant: String,
    },
    /// Withdraw a tenant from a shared pool
    Revoke {
        #[command(flatten)]
        data: DataDir,
        #[arg(long)]
        pool: String,
        #[arg(long, value_name = "SLUG")]
        tenant: String,
    },
    /// The pools a tenant may use
    List {
        #[command(flatten)]
        data: DataDir,
        #[arg(long, value_name = "SLUG")]
        tenant: String,
    },
}

#[derive(Args)]
pub struct KeyArgs {
    #[command(subcommand)]
    pub command: KeyCommand,
}

#[derive(Subcommand)]
pub enum KeyCommand {
    /// Write a fresh 32-byte key, owner-only; refuses to overwrite one
    Create {
        #[command(flatten)]
        data: DataDir,
        /// Where to write it; defaults to master.key inside the data directory
        #[arg(long, value_name = "FILE")]
        key_file: Option<PathBuf>,
    },
}

#[derive(Args)]
pub struct MfaArgs {
    #[command(subcommand)]
    pub command: MfaCommand,
}

#[derive(Subcommand)]
pub enum MfaCommand {
    /// Whether a second factor is enrolled and how many recovery codes remain
    Status {
        #[command(flatten)]
        data: DataDir,
        #[arg(long)]
        user: String,
    },
    /// Remove the second factor of an account whose device or codes are lost
    Disable {
        #[command(flatten)]
        data: DataDir,
        #[arg(long)]
        user: String,
    },
}

#[derive(Args)]
pub struct SessionArgs {
    #[command(subcommand)]
    pub command: SessionCommand,
}

#[derive(Subcommand)]
pub enum SessionCommand {
    /// List an account's sessions as metadata; no cookie value is ever shown
    List {
        #[command(flatten)]
        data: DataDir,
        #[arg(long)]
        user: String,
    },
    /// Revoke one session by its `ses_` identifier
    Revoke {
        #[command(flatten)]
        data: DataDir,
        #[arg(long)]
        user: String,
        #[arg(long)]
        id: String,
    },
    /// Revoke every session of an account
    LogoutAll {
        #[command(flatten)]
        data: DataDir,
        #[arg(long)]
        user: String,
    },
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
