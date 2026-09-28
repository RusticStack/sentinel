use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};
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
    /// Talk to a controller's API with a credential: dispatch, status, logs, cancel, rerun, workers, queue, drain
    Api(ApiArgs),
    /// Run the local stdio MCP server using a signed-in profile or static credential
    Mcp(sentinel::mcp::McpArgs),
    /// Sign in to a controller (browser or device), show the session, sign out
    Auth(sentinel::auth_cmd::AuthArgs),
    /// Choose or show the profile's default tenant
    Context(sentinel::auth_cmd::ContextArgs),
    /// Check configuration, credentials and connectivity, with a fix for each failure
    Doctor(sentinel::doctor::DoctorArgs),
    /// Create service accounts, allow them repositories, and issue or revoke their grants
    ServiceAccount(sentinel::service_accounts::ServiceAccountArgs),
    /// Dispatch, list, inspect, cancel and wait for runs
    Run(sentinel::commands::RunArgs),
    /// A run and its jobs
    Status(sentinel::commands::StatusArgs),
    /// Wait for a run to finish: exit 0 passed, 8 not passed, 7 deadline reached
    Wait(sentinel::commands::WaitArgs),
    /// Cancel or rerun one job
    Job(sentinel::commands::JobArgs),
    /// Show, follow or search an attempt's log
    Log(sentinel::commands::LogArgs),
    /// Pools and workers a tenant may use; drain and undrain
    Workers(sentinel::commands::WorkersArgs),
    /// Waiting jobs of a tenant and why each is waiting
    Queue(sentinel::commands::QueueArgs),
    /// List, show and download a run's artifacts
    Artifact(sentinel::commands::ArtifactArgs),
    /// Cache records of an attempt
    Cache(sentinel::commands::CacheArgs),
    /// Manage tenant and repository secrets using protected input
    Secret(sentinel::commands::SecretArgs),
}

/// Client options: the controller and the credential come from flags or
/// `SENTINEL_SERVER`/`SENTINEL_TOKEN`; a token file keeps the secret out of
/// the process list.
#[derive(Args)]
pub struct ApiArgs {
    /// Controller URL, such as http://127.0.0.1:7080
    #[arg(long, env = "SENTINEL_SERVER")]
    pub server: Option<String>,
    /// A `sntl_` credential (prefer --token-file)
    #[arg(long, env = "SENTINEL_TOKEN", hide_env_values = true)]
    pub token: Option<String>,
    /// File holding the credential
    #[arg(long, value_name = "PATH")]
    pub token_file: Option<PathBuf>,
    /// Print the server's JSON instead of text
    #[arg(long)]
    pub json: bool,
    #[command(subcommand)]
    pub command: ApiCommand,
}

#[derive(Subcommand)]
pub enum ApiCommand {
    /// Who the credential is
    Me,
    /// Dispatch a run of a pipeline file against a pinned source revision
    Run {
        #[arg(long)]
        tenant: String,
        #[arg(long)]
        repo: String,
        /// The `.sentinel.yml` to run; every image must be pinned by digest
        #[arg(long, value_name = "FILE")]
        pipeline: PathBuf,
        /// Clone URL or path the workers fetch from
        #[arg(long)]
        source: String,
        /// Full commit SHA to check out
        #[arg(long)]
        sha: String,
        /// Ref name kept as provenance
        #[arg(long)]
        r#ref: Option<String>,
        /// Idempotency key so a retried dispatch creates one run
        #[arg(long)]
        idempotency_key: Option<String>,
    },
    /// A run and its jobs
    Status {
        #[arg(value_name = "RUN")]
        run: String,
    },
    /// Recent runs of a repository
    Runs {
        #[arg(long)]
        tenant: String,
        #[arg(long)]
        repo: String,
        #[arg(long, default_value_t = 20)]
        limit: u16,
    },
    /// Record cancellation for a run or a job
    Cancel {
        #[arg(long, conflicts_with = "job")]
        run: Option<String>,
        #[arg(long)]
        job: Option<String>,
    },
    /// A new attempt of a finished job
    Rerun {
        #[arg(value_name = "JOB")]
        job: String,
    },
    /// An attempt's log; --follow waits until it is complete
    Logs {
        #[arg(value_name = "ATTEMPT")]
        attempt: String,
        #[arg(long)]
        follow: bool,
    },
    /// Pools and workers a tenant may use, with connection state
    Workers {
        #[arg(long)]
        tenant: String,
    },
    /// Queued and blocked jobs of a tenant, oldest first, each with its age and why it is waiting
    Queue {
        #[arg(long)]
        tenant: String,
        /// How many waiting jobs to show; the response still reports the total
        #[arg(long, default_value_t = 100)]
        limit: u16,
    },
    /// Stop one worker taking new attempts; it finishes the attempts it already holds
    Drain {
        #[arg(value_name = "WORKER")]
        worker: String,
    },
    /// Offer a drained worker work again
    Undrain {
        #[arg(value_name = "WORKER")]
        worker: String,
    },
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
    /// Bind source repositories, rotate deploy credentials and manage App installations
    Source(SourceArgs),
    /// Inspect and purge durable event intake records
    Intake(IntakeArgs),
    /// Reconcile or verify committed objects and manifests against the filesystem
    Objects(ObjectsArgs),
    /// Take, list, verify and prune backups of a stopped controller
    Backup(BackupArgs),
    /// Rebuild a data directory from a backup (the controller must not run)
    Restore {
        /// Directory holding the backups
        #[arg(long, value_name = "DIR")]
        from: PathBuf,
        /// Which backup; the newest when omitted
        #[arg(long, value_name = "ID")]
        id: Option<String>,
        /// The master key file whose key ids the backup's sealed values need
        #[arg(long, value_name = "FILE")]
        key: Option<PathBuf>,
        /// The empty data directory to rebuild
        #[arg(long, value_name = "PATH")]
        data_dir: PathBuf,
    },
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
    /// List, disable and re-enable registered (DCR/CIMD) OAuth clients
    OauthClient(OauthClientArgs),
    /// Create, list and revoke one-time invitations
    Invite(InviteArgs),
    /// Review pending applications; approve or reject accounts
    Account(AccountArgs),
    /// Create or rotate the sealing key for second factors and source credentials
    Key(KeyArgs),
    /// Inspect or remove an account's second factor
    Mfa(MfaArgs),
    /// List and revoke an account's sessions
    Session(SessionArgs),
    /// Suspend or reactivate a tenant namespace
    Tenant(TenantArgs),
    /// Register worker pools and grant shared ones to tenants
    Pool(PoolArgs),
    /// Enroll, list, drain and revoke workers
    Worker(WorkerArgs),
    /// Rotate Tailcat node keys with an overlap window and edit the controller's allow list
    Tailcat(TailcatArgs),
    /// Record cancellation for a job or a whole run; running attempts are told on their next heartbeat
    Cancel {
        #[command(flatten)]
        data: DataDir,
        /// The `job_` identifier
        #[arg(long, conflicts_with = "run")]
        job: Option<String>,
        /// The `run_` identifier
        #[arg(long)]
        run: Option<String>,
    },
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
pub struct SourceArgs {
    #[command(flatten)]
    pub data: DataDir,
    /// Acting administrator's immutable usr_ ID; live authority is checked
    #[arg(long)]
    pub actor: String,
    #[command(subcommand)]
    pub command: SourceCommand,
}

#[derive(Subcommand)]
pub enum SourceCommand {
    Create {
        #[arg(long)]
        tenant: String,
        #[arg(long)]
        name: String,
    },
    /// Read binding and credential JSON from bounded stdin; expected=0 creates
    Bind {
        #[arg(long)]
        repo: String,
        #[arg(long)]
        expected: u64,
    },
    Show {
        #[arg(long)]
        repo: String,
    },
    Revoke {
        #[arg(long)]
        repo: String,
        #[arg(long)]
        expected: u64,
    },
    /// Issue (or rotate) the repository's intake hook secret; only the secret goes to stdout
    HookToken {
        #[arg(long)]
        repo: String,
        /// Remove the secret instead of issuing one
        #[arg(long)]
        revoke: bool,
    },
    /// Opt this repository into bounded `git ls-remote` ref polling (G07); the
    /// first poll only records the baseline
    Poll {
        #[arg(long)]
        repo: String,
        /// Poll interval such as 60s, 5m or 1h (10s–24h)
        #[arg(long, value_name = "DURATION")]
        interval: Option<String>,
        /// Ref selectors, comma-separated: exact refs or a trailing wildcard (refs/heads/*)
        #[arg(long, value_name = "PATTERNS")]
        refs: Option<String>,
        /// Stop polling this repository
        #[arg(long)]
        disable: bool,
    },
    /// Fetch a fresh authenticated GitHub App installation snapshot
    RefreshInstallation {
        #[arg(long)]
        external_id: u64,
        #[arg(long)]
        expected: u64,
    },
    BindInstallation {
        #[arg(long)]
        installation: String,
        #[arg(long)]
        tenant: String,
    },
    RemoveInstallation {
        #[arg(long)]
        installation: String,
    },
}

#[derive(Args)]
pub struct IntakeArgs {
    #[command(flatten)]
    pub data: DataDir,
    #[command(subcommand)]
    pub command: IntakeCommand,
}

#[derive(Subcommand)]
pub enum IntakeCommand {
    /// Newest event deliveries of one repository, optionally one state
    List {
        /// The `rep_` identifier
        #[arg(long)]
        repo: String,
        /// pending | ready | ignored | failed
        #[arg(long)]
        state: Option<String>,
        #[arg(long, default_value = "50", value_parser = clap::value_parser!(u16).range(1..=100))]
        limit: u16,
    },
    /// Delete settled deliveries older than a retention duration
    Purge {
        /// Retention such as 7d or 24h; settled records older than this go
        #[arg(long, value_name = "DURATION", default_value = "7d")]
        older_than: String,
        #[arg(long, default_value = "1000")]
        limit: u32,
    },
}

#[derive(Args)]
pub struct ObjectsArgs {
    #[command(flatten)]
    pub data: DataDir,
    #[command(subcommand)]
    pub command: ObjectsCommand,
}

#[derive(Args)]
pub struct BackupArgs {
    #[command(subcommand)]
    pub command: BackupCommand,
}

#[derive(Subcommand)]
pub enum BackupCommand {
    /// Back up a stopped controller's data directory now (a running one
    /// backs itself up on its `[backup]` schedule or `POST /admin/backups`)
    Create {
        #[command(flatten)]
        data: DataDir,
        /// Directory to hold the backups (outside the data directory)
        #[arg(long, value_name = "DIR")]
        to: PathBuf,
    },
    /// List the backups in a directory, oldest first
    List {
        #[arg(long, value_name = "DIR")]
        dir: PathBuf,
    },
    /// Rehash a backup end to end: the snapshot's checksum and integrity,
    /// and every object and manifest it names; exit 2 when anything is wrong
    Verify {
        #[arg(long, value_name = "DIR")]
        dir: PathBuf,
        /// Which backup; the newest when omitted
        #[arg(long, value_name = "ID")]
        id: Option<String>,
    },
    /// Keep the newest backups and remove the rest and what only they named
    Prune {
        #[arg(long, value_name = "DIR")]
        dir: PathBuf,
        #[arg(long)]
        keep: usize,
    },
}

#[derive(Subcommand)]
pub enum ObjectsCommand {
    /// Sweep incomplete staged writes and report orphans, corrupt and missing objects
    Recover,
    /// Rehash every committed object and report content that no longer matches
    Verify,
    /// Retire expired resumable uploads and drop their staged bytes
    Sweep,
    /// Run one storage maintenance pass: expire uploads and leases, retire
    /// artifacts past retention, index manifest references, reclaim
    /// unreferenced objects and sweep orphan files
    Reclaim,
    /// Report free space, the metadata database's size, the watermarks this
    /// filesystem sizes and per-tenant usage against quota
    Status,
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
    /// Keep this worker's attempts running but stop offering it new ones
    Drain {
        #[command(flatten)]
        data: DataDir,
        /// The `wrk_` identifier the worker generated
        #[arg(long)]
        id: String,
    },
    /// Offer this worker work again
    Undrain {
        #[command(flatten)]
        data: DataDir,
        /// The `wrk_` identifier the worker generated
        #[arg(long)]
        id: String,
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

/// Host-local Tailcat identity operations. Authorized by access to the role's
/// data directory. Node keys travel on standard input and output, never in
/// argv; diagnostics name files, never keys or addresses.
#[derive(Args)]
pub struct TailcatArgs {
    #[command(subcommand)]
    pub command: TailcatCommand,
}

/// The role whose node key an operation rotates.
#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum TailcatRole {
    Server,
    Worker,
}

/// The role's configuration file, as `sentinel server|worker --config` reads it.
#[derive(Args)]
pub struct TailcatRoleConfig {
    /// Which role's key to rotate
    #[arg(long, value_enum)]
    pub role: TailcatRole,
    /// The role's strict TOML configuration file with `[tailcat] enabled = true`
    #[arg(long, value_name = "FILE")]
    pub config: PathBuf,
    /// Absolute role data directory; overrides the configuration file
    #[arg(long, value_name = "PATH")]
    pub data_dir: Option<PathBuf>,
}

#[derive(Subcommand)]
pub enum TailcatCommand {
    /// Stage a new node key beside the active one; a worker prints its allow-list line
    Rotate(TailcatRoleConfig),
    /// Switch to the staged key once it is admitted (worker) or served (server)
    Commit(TailcatRoleConfig),
    /// Drop a staged key that has not been committed
    Abandon(TailcatRoleConfig),
    /// Add the `nodekey:<hex> wrk_<id>` line on standard input to the controller's allow list
    Allow {
        #[command(flatten)]
        data: DataDir,
    },
    /// Make the line on standard input its worker's only listed key
    Retire {
        #[command(flatten)]
        data: DataDir,
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
    /// Show or change a tenant's storage quota in committed bytes
    Quota {
        #[command(flatten)]
        data: DataDir,
        #[arg(long, value_name = "SLUG")]
        tenant: String,
        /// The cap in bytes; without --bytes or --clear, shows the current value
        #[arg(long, value_name = "BYTES")]
        bytes: Option<u64>,
        /// Remove the tenant's row so the configured default applies again
        #[arg(long)]
        clear: bool,
    },
    /// Show or change a tenant's or repository's storage policy: quota and
    /// log and artifact retention (unset values inherit)
    Storage {
        #[command(flatten)]
        data: DataDir,
        #[arg(long, value_name = "SLUG")]
        tenant: String,
        /// One repository of the tenant; its retention can only be shorter
        /// than the tenant's
        #[arg(long, value_name = "NAME")]
        repo: Option<String>,
        /// Stored-bytes cap
        #[arg(long, value_name = "BYTES")]
        quota: Option<u64>,
        /// How long finished logs are kept, as in 14d
        #[arg(long, value_name = "DURATION")]
        log_retention: Option<String>,
        /// Longest artifact retention a pipeline may ask for, as in 30d
        #[arg(long, value_name = "DURATION")]
        artifact_retention: Option<String>,
        /// Drop the named settings (quota, log-retention, artifact-retention)
        /// so they inherit again; `all` removes the whole policy
        #[arg(long, value_name = "SETTING")]
        inherit: Vec<String>,
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
    /// Write a fresh key to <data-dir>/master.key, owner-only; refuses to overwrite one
    Create {
        #[command(flatten)]
        data: DataDir,
    },
    /// Rotate <data-dir>/master.key offline, retaining old keys and writing an exclusive backup
    Rotate {
        #[command(flatten)]
        data: DataDir,
        /// New owner-only backup file for the pre-rotation key
        #[arg(long, value_name = "FILE")]
        backup: PathBuf,
    },
    /// Re-encrypt every sealed value under the active key, offline and resumable;
    /// --retire then drops every other key
    Reseal {
        #[command(flatten)]
        data: DataDir,
        /// After resealing, remove every retired key from master.key
        #[arg(long, requires = "backup")]
        retire: bool,
        /// New owner-only backup file for the key file before retiring
        #[arg(long, value_name = "FILE")]
        backup: Option<PathBuf>,
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
        /// Which OAuth client registrations to accept: off, metadata
        /// (Client ID Metadata Documents only; the default) or open (also
        /// anonymous RFC 7591 dynamic registration)
        #[arg(long)]
        oauth_client_registration: Option<String>,
    },
}

#[derive(Args)]
pub struct OauthClientArgs {
    #[command(subcommand)]
    pub command: OauthClientCommand,
}

#[derive(Subcommand)]
pub enum OauthClientCommand {
    /// List every DCR/CIMD client with its state and live grants
    List {
        #[command(flatten)]
        data: DataDir,
    },
    /// Disable a client and revoke every grant it holds
    Disable {
        #[command(flatten)]
        data: DataDir,
        /// The client identifier, or a CIMD client's metadata URL
        #[arg(long)]
        client: String,
    },
    /// Re-enable a disabled client; its revoked grants stay revoked
    Enable {
        #[command(flatten)]
        data: DataDir,
        /// The client identifier, or a CIMD client's metadata URL
        #[arg(long)]
        client: String,
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
    /// Load, decode and compile the file; print nothing on success (text)
    Validate {
        /// Path to the pipeline file
        file: PathBuf,
        #[command(flatten)]
        output: PipelineOutputArgs,
    },
    /// Show jobs, order, budgets, required grants and unresolved runtime inputs
    Explain {
        file: PathBuf,
        #[command(flatten)]
        output: PipelineOutputArgs,
    },
}

/// The offline commands' output: text, or one JSON document (there is no
/// list to stream, so `ndjson` is not offered).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, ValueEnum)]
pub enum PipelineOutput {
    #[default]
    Text,
    Json,
}

#[derive(Args)]
pub struct PipelineOutputArgs {
    /// text or json (`explain` json is `sentinel.explain/1`)
    #[arg(long, value_enum, default_value = "text")]
    pub output: PipelineOutput,
    /// Same as --output json
    #[arg(long)]
    pub json: bool,
}

impl PipelineOutputArgs {
    /// The effective mode (`--json` wins).
    pub fn mode(&self) -> sentinel::client::Output {
        if self.json || self.output == PipelineOutput::Json {
            sentinel::client::Output::Json
        } else {
            sentinel::client::Output::Text
        }
    }
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
