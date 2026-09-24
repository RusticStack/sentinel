use std::{
    fs::{self, File},
    io::Read,
    net::SocketAddr,
    path::{Component, Path, PathBuf},
    sync::{Arc, mpsc},
    time::{Duration, Instant},
};

use serde::Deserialize;

use crate::cli::ServiceArgs;
use sentinel::{
    LogFormat, LogLevel,
    correlation::{Correlation, ProcessId},
    diagnostics::Diagnostics,
    timing::{Outcome, Phase, PhaseTimer, elapsed_ns},
    work::{Executor, WorkClass},
};

const MAX_CONFIG_BYTES: u64 = 64 * 1024;
/// Where the controller listens for workers unless configured otherwise:
/// loopback, so exposing it is an explicit decision.
const DEFAULT_LISTEN: &str = "127.0.0.1:7443";
/// Where the API answers unless configured otherwise: loopback; TLS and
/// exposure are the reverse proxy's.
const DEFAULT_API_LISTEN: &str = "127.0.0.1:7080";
/// Bounded drains at shutdown: sessions and dispatcher, then the store.
const LINK_SHUTDOWN: Duration = Duration::from_secs(2);
const STORE_SHUTDOWN: Duration = Duration::from_secs(5);

pub struct Error {
    pub code: u8,
    pub message: String,
    pub reported: bool,
}

impl Error {
    fn config(message: impl Into<String>) -> Self {
        Self {
            code: 2,
            message: message.into(),
            reported: false,
        }
    }

    fn runtime(message: impl Into<String>) -> Self {
        Self {
            code: 1,
            message: message.into(),
            reported: false,
        }
    }
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileConfig {
    data_dir: Option<PathBuf>,
    log_format: Option<LogFormat>,
    log_level: Option<LogLevel>,
    // Server: where workers connect, and where the API answers.
    listen: Option<String>,
    api_listen: Option<String>,
    // Server: the deployment-facing base URL, which is the OAuth issuer (O02).
    public_url: Option<String>,
    // Worker: which controller to reach and how to trust it.
    controller: Option<String>,
    controller_fingerprint: Option<String>,
    worker_name: Option<String>,
    enrollment_file: Option<PathBuf>,
    cpu_millis: Option<u64>,
    memory_bytes: Option<u64>,
    // Worker: what the scheduler may select this machine by (Q01) and the
    // scratch disk it offers jobs. Labels default to none; disk defaults to
    // the free space of the data directory at start.
    labels: Option<Vec<String>>,
    disk_bytes: Option<u64>,
    // Worker: keep per-repository object mirrors under the data directory
    // (default on; `false` checks out every attempt directly).
    git_mirrors: Option<bool>,
    // Server: disk admission watermarks, quotas and retention (D06).
    storage: Option<StorageFile>,
    // Q06: the optional pinned Tailcat helper, for either role.
    tailcat: Option<TailcatFile>,
    // Q08: whether this process participates in remote cache hydration.
    remote_cache: Option<RemoteCacheFile>,
    // Worker: the controller's `tc…` address, as written to its `<data_dir>/tailcat/address`
    // (Q06). Required to dial a controller through the helper.
    tailcat_address: Option<String>,
}

/// The `[tailcat]` section (Q06), resolved into the helper's own
/// `sentinel_link::tailcat::TailcatConfig` in the role that runs it. Kept as
/// a plain mirror here so the portable CLI build — which links no link crate
/// — can still validate the section.
#[derive(Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct TailcatFile {
    enabled: Option<bool>,
    binary: Option<PathBuf>,
    sha256: Option<String>,
    derpmap_url: Option<String>,
    region: Option<String>,
    listen_port: Option<u16>,
}

/// The `[remote_cache]` section (Q08): whether this process participates in
/// remote cache hydration. The controller holds objects workers offer so
/// another worker can hydrate them; the worker fetches and offers. Local
/// cache hits never traverse the link either way.
#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RemoteCacheFile {
    enabled: Option<bool>,
}

impl RemoteCacheFile {
    fn on(&self) -> bool {
        self.enabled.unwrap_or(true)
    }
}

/// One scheduling label: bounded like a name, no control characters.
fn valid_label(label: &str) -> bool {
    !label.is_empty() && label.len() <= 128 && !label.chars().any(char::is_control)
}

/// Labels one worker may advertise; mirrors
/// `sentinel_protocol::negotiate::MAX_PROFILE_LABELS`, kept local so the
/// portable CLI build (which links no protocol crate) validates the same
/// bound.
const MAX_LABELS: usize = 16;

/// The `[storage]` section: all fields optional, resolved to defaults.
#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct StorageFile {
    /// Free bytes held back for metadata and log evidence.
    reserve_bytes: Option<u64>,
    /// Discretionary writes refuse below this free figure...
    low_watermark_bytes: Option<u64>,
    /// ...and admit again above this one (hysteresis).
    high_watermark_bytes: Option<u64>,
    /// Default committed-bytes cap per tenant; 0 is unlimited.
    tenant_quota_bytes: Option<u64>,
    /// Finished attempt logs are kept this long.
    log_retention_secs: Option<u64>,
    /// The maintenance pass rides the dispatch loop at most this often.
    sweep_interval_secs: Option<u64>,
}

/// Resolved storage settings; constructed only for the server role (the
/// worker build links no `sentinel_store`, and refuses `[storage]` at load).
#[cfg(feature = "server")]
#[derive(Clone, Copy)]
struct Storage {
    marks: sentinel_store::space::Watermarks,
    tenant_quota: u64,
    log_retention_ms: i64,
    sweep_interval_ms: i64,
}

#[cfg(feature = "server")]
impl StorageFile {
    fn resolve(&self) -> Result<Storage, Error> {
        let reserve = self.reserve_bytes.unwrap_or(1 << 30);
        let low = self.low_watermark_bytes.unwrap_or(2 << 30);
        let high = self.high_watermark_bytes.unwrap_or(4 << 30);
        let log_retention_secs = self.log_retention_secs.unwrap_or(14 * 86_400);
        let sweep_interval_secs = self.sweep_interval_secs.unwrap_or(300);
        if reserve < (64 << 20) || low < reserve || high < low {
            return Err(Error::config(
                "storage watermarks must satisfy 64 MiB <= reserve_bytes <= low_watermark_bytes <= high_watermark_bytes",
            ));
        }
        if !(5..=86_400).contains(&sweep_interval_secs)
            || !(3_600..=86_400 * 365).contains(&log_retention_secs)
        {
            return Err(Error::config(
                "storage sweep_interval_secs must be 5..=86400 and log_retention_secs 3600..=31536000",
            ));
        }
        Ok(Storage {
            marks: sentinel_store::space::Watermarks {
                reserve,
                low,
                high,
                // Log evidence keeps the top slice of the reserve so the
                // metadata database keeps the rest.
                floor: reserve / 8,
            },
            tenant_quota: self.tenant_quota_bytes.unwrap_or(0),
            log_retention_ms: (log_retention_secs * 1000) as i64,
            sweep_interval_ms: (sweep_interval_secs * 1000) as i64,
        })
    }
}

/// The worker's link settings; absent when no controller is configured, in
/// which case the worker idles (a lifecycle-only process).
#[derive(Clone)]
struct WorkerLink {
    controller: SocketAddr,
    fingerprint: [u8; 32],
    name: String,
    enrollment_file: Option<PathBuf>,
    cpu_millis: Option<u64>,
    memory_bytes: Option<u64>,
    git_mirrors: bool,
    /// Scheduling labels this machine selects work by (protocol 7).
    labels: Vec<String>,
    /// Scratch disk offered to jobs; `None` measures free space at start.
    disk_bytes: Option<u64>,
    /// The helper to run, when the worker dials through Tailcat.
    tailcat: Option<TailcatFile>,
    /// The controller's `tc…` address the helper carries.
    tailcat_address: Option<String>,
    /// Whether this worker exposes the remote cache to its executor (Q08).
    remote_cache: bool,
}

enum Role {
    Server {
        listen: SocketAddr,
        api_listen: SocketAddr,
        /// The OAuth issuer; `None` means `http://{api_listen}`.
        public_url: Option<String>,
        /// The helper the server runs for its link port (Q06), when enabled.
        tailcat: Option<TailcatFile>,
        /// Whether the controller serves remote cache objects (Q08).
        remote_cache: bool,
    },
    Worker(Option<WorkerLink>),
}

struct Config {
    data_dir: PathBuf,
    log_format: LogFormat,
    log_level: LogLevel,
    #[cfg(feature = "server")]
    storage: Storage,
    role: Role,
}

fn parse_hex32(text: &str) -> Option<[u8; 32]> {
    let text = text.as_bytes();
    if text.len() != 64 {
        return None;
    }
    let nibble = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    };
    let mut out = [0u8; 32];
    for (byte, pair) in out.iter_mut().zip(text.chunks_exact(2)) {
        *byte = (nibble(pair[0])? << 4) | nibble(pair[1])?;
    }
    Some(out)
}

fn hex32(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for byte in bytes {
        out.push(HEX[usize::from(byte >> 4)] as char);
        out.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    out
}

impl Config {
    fn load(role: &str, args: &ServiceArgs, io: &Executor, cpu: &Executor) -> Result<Self, Error> {
        let file = match &args.config {
            Some(path) => {
                let path = path.clone();
                let text = bootstrap_work(io, move || read_config(&path))??;
                bootstrap_work(cpu, move || {
                    // Do not echo parser diagnostics: they can contain pasted credentials.
                    toml::from_str::<FileConfig>(&text).map_err(|_| Error::config(
                        "invalid configuration: expected strict TOML with only data_dir, log_format, log_level, [storage] and the role's link keys (no duplicate/unknown keys or invalid values)",
                    ))
                })??
            }
            None => FileConfig::default(),
        };
        let data_dir = args.data_dir.clone().or(file.data_dir).unwrap_or_else(|| {
            PathBuf::from(if role == "server" {
                "/var/lib/sentinel"
            } else {
                "/var/lib/sentinel-worker"
            })
        });
        if !data_dir.is_absolute()
            || !data_dir
                .components()
                .any(|part| matches!(part, Component::Normal(_)))
            || data_dir
                .components()
                .any(|part| matches!(part, Component::ParentDir))
        {
            return Err(Error::config(
                "data_dir must be an absolute, non-root path without '..' components",
            ));
        }
        let path = data_dir.clone();
        let metadata = bootstrap_work(io, move || fs::metadata(path))?;
        match metadata {
            Ok(metadata) if !metadata.is_dir() => {
                return Err(Error::config("data_dir exists but is not a directory"));
            }
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
                return Err(Error::config(format!("cannot inspect data_dir: {error}")));
            }
            _ => {}
        }
        let role = if role == "server" {
            if file.controller.is_some()
                || file.controller_fingerprint.is_some()
                || file.worker_name.is_some()
                || file.enrollment_file.is_some()
                || file.cpu_millis.is_some()
                || file.memory_bytes.is_some()
                || file.git_mirrors.is_some()
                || file.labels.is_some()
                || file.disk_bytes.is_some()
                || file.tailcat_address.is_some()
            {
                return Err(Error::config(
                    "controller, controller_fingerprint, worker_name, enrollment_file, cpu_millis, memory_bytes, git_mirrors, labels, disk_bytes and tailcat_address apply to the worker role only",
                ));
            }
            let listen: SocketAddr = file
                .listen
                .as_deref()
                .unwrap_or(DEFAULT_LISTEN)
                .parse()
                .map_err(|_| {
                    Error::config("listen must be an IP address and port, as in 0.0.0.0:7443")
                })?;
            let api_listen = file
                .api_listen
                .as_deref()
                .unwrap_or(DEFAULT_API_LISTEN)
                .parse()
                .map_err(|_| {
                    Error::config("api_listen must be an IP address and port, as in 127.0.0.1:7080")
                })?;
            if let Some(tailcat) = &file.tailcat
                && tailcat.enabled == Some(true)
                && tailcat.listen_port.unwrap_or(listen.port()) != listen.port()
            {
                return Err(Error::config(
                    "tailcat.listen_port must match listen: the helper carries exactly the link port",
                ));
            }
            let public_url = file
                .public_url
                .as_deref()
                .map(|url| match sentinel::client::normalize_server(url) {
                    Ok(normalized) if normalized == url => Ok(normalized),
                    _ => Err(Error::config(
                        "public_url must be an absolute URL such as https://ci.example.com: lower-case scheme and host, no trailing slash, query or fragment, and http only for a loopback host",
                    )),
                })
                .transpose()?;
            Role::Server {
                listen,
                api_listen,
                public_url,
                tailcat: file.tailcat,
                remote_cache: file
                    .remote_cache
                    .as_ref()
                    .map(RemoteCacheFile::on)
                    .unwrap_or(true),
            }
        } else {
            if file.listen.is_some() || file.api_listen.is_some() || file.public_url.is_some() {
                return Err(Error::config(
                    "listen, api_listen and public_url apply to the server role only",
                ));
            }
            let link = match (file.controller, file.controller_fingerprint) {
                (None, None) => {
                    if file.worker_name.is_some()
                        || file.enrollment_file.is_some()
                        || file.cpu_millis.is_some()
                        || file.memory_bytes.is_some()
                        || file.git_mirrors.is_some()
                        || file.labels.is_some()
                        || file.disk_bytes.is_some()
                        || file.tailcat.is_some()
                        || file.tailcat_address.is_some()
                        || file.remote_cache.is_some()
                    {
                        return Err(Error::config(
                            "worker link settings need controller and controller_fingerprint",
                        ));
                    }
                    None
                }
                (Some(controller), Some(fingerprint)) => {
                    let controller = controller.parse().map_err(|_| {
                        Error::config(
                            "controller must be an IP address and port, as in 10.0.0.5:7443",
                        )
                    })?;
                    let fingerprint = parse_hex32(&fingerprint).ok_or_else(|| {
                        Error::config(
                            "controller_fingerprint must be the 64 lower-case hex characters the controller printed",
                        )
                    })?;
                    let name = file.worker_name.unwrap_or_else(|| "worker".to_owned());
                    if name.is_empty() || name.len() > 128 || name.chars().any(char::is_control) {
                        return Err(Error::config(
                            "worker_name must be 1-128 bytes without control characters",
                        ));
                    }
                    if let Some(path) = &file.enrollment_file
                        && !path.is_absolute()
                    {
                        return Err(Error::config("enrollment_file must be an absolute path"));
                    }
                    if file.cpu_millis == Some(0) || file.memory_bytes == Some(0) {
                        return Err(Error::config(
                            "cpu_millis and memory_bytes must be positive when set",
                        ));
                    }
                    let labels = file.labels.unwrap_or_default();
                    if labels.len() > MAX_LABELS || !labels.iter().all(|label| valid_label(label)) {
                        return Err(Error::config(
                            "labels must be at most 16 entries of 1-128 bytes without control characters",
                        ));
                    }
                    if file.disk_bytes == Some(0) {
                        return Err(Error::config("disk_bytes must be positive when set"));
                    }
                    let tailcat_on = file
                        .tailcat
                        .as_ref()
                        .is_some_and(|tailcat| tailcat.enabled == Some(true));
                    if file.tailcat_address.is_some() && !tailcat_on {
                        return Err(Error::config(
                            "tailcat_address needs [tailcat] enabled = true; without the helper the worker dials the controller directly",
                        ));
                    }
                    if tailcat_on && file.tailcat_address.is_none() {
                        return Err(Error::config(
                            "tailcat_address is required when [tailcat] is enabled: it is the controller's tc… address from its <data_dir>/tailcat/address file",
                        ));
                    }
                    Some(WorkerLink {
                        controller,
                        fingerprint,
                        name,
                        enrollment_file: file.enrollment_file,
                        cpu_millis: file.cpu_millis,
                        memory_bytes: file.memory_bytes,
                        git_mirrors: file.git_mirrors.unwrap_or(true),
                        labels,
                        disk_bytes: file.disk_bytes,
                        tailcat: file.tailcat,
                        tailcat_address: file.tailcat_address,
                        remote_cache: file
                            .remote_cache
                            .as_ref()
                            .map(RemoteCacheFile::on)
                            .unwrap_or(true),
                    })
                }
                _ => {
                    return Err(Error::config(
                        "controller and controller_fingerprint must be set together",
                    ));
                }
            };
            Role::Worker(link)
        };
        #[cfg(feature = "server")]
        let storage = match (&role, file.storage) {
            (Role::Server { .. }, file) => file.unwrap_or_default().resolve()?,
            (Role::Worker(_), Some(_)) => {
                return Err(Error::config("[storage] applies to the server role only"));
            }
            (Role::Worker(_), None) => StorageFile::default().resolve()?,
        };
        #[cfg(not(feature = "server"))]
        if file.storage.is_some() {
            return Err(Error::config("[storage] applies to the server role only"));
        }
        Ok(Self {
            data_dir,
            log_format: args.log_format.or(file.log_format).unwrap_or_default(),
            log_level: args.log_level.or(file.log_level).unwrap_or_default(),
            #[cfg(feature = "server")]
            storage,
            role,
        })
    }

    fn describe(&self) -> String {
        match &self.role {
            Role::Server {
                listen,
                api_listen,
                remote_cache,
                public_url,
                ..
            } => {
                let mut text =
                    format!("listen={listen} api_listen={api_listen} remote_cache={remote_cache}");
                if let Some(url) = public_url {
                    text.push_str(" public_url=");
                    text.push_str(url);
                }
                text
            }
            Role::Worker(None) => "controller=none (idle)".to_owned(),
            Role::Worker(Some(link)) => format!(
                "controller={} controller_fingerprint={} worker_name={}",
                link.controller,
                hex32(&link.fingerprint),
                link.name
            ),
        }
    }
}

fn read_config(path: &Path) -> Result<String, Error> {
    if !fs::metadata(path)
        .map_err(|error| Error::config(format!("cannot inspect configuration file: {error}")))?
        .is_file()
    {
        return Err(Error::config("configuration must be a regular file"));
    }
    let file = File::open(path)
        .map_err(|error| Error::config(format!("cannot open configuration file: {error}")))?;
    if !file
        .metadata()
        .map_err(|error| Error::config(format!("cannot inspect configuration file: {error}")))?
        .is_file()
    {
        return Err(Error::config("configuration must be a regular file"));
    }
    let mut bytes = Vec::new();
    file.take(MAX_CONFIG_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| Error::config(format!("cannot read configuration file: {error}")))?;
    if bytes.len() as u64 > MAX_CONFIG_BYTES {
        return Err(Error::config("configuration exceeds the 64 KiB limit"));
    }
    String::from_utf8(bytes).map_err(|_| Error::config("configuration must be UTF-8"))
}

pub fn run(role: &str, args: ServiceArgs) -> Result<(), Error> {
    let service_started = Instant::now();
    let mut io = Executor::new(WorkClass::BlockingIo, 16)
        .map_err(|error| Error::runtime(format!("cannot start I/O lane: {error}")))?;
    let mut cpu = Executor::new(WorkClass::Cpu, 16)
        .map_err(|error| Error::runtime(format!("cannot start CPU lane: {error}")))?;
    let configuration_started = Instant::now();
    let config = Config::load(role, &args, &io, &cpu)?;
    let configuration_ns = elapsed_ns(configuration_started);
    if args.check {
        sentinel::outln!(
            "{role} configuration valid; data_dir={}; log_format={:?}; log_level={:?}; {}",
            config.data_dir.display(),
            config.log_format,
            config.log_level,
            config.describe()
        );
        return Ok(());
    }

    let mut diagnostics = Diagnostics::stderr(config.log_format, config.log_level)
        .map_err(|error| Error::runtime(format!("cannot initialize diagnostics: {error}")))?;
    let dispatch = diagnostics.dispatch().clone();
    let correlation = Correlation::process(ProcessId::new());
    let mut result = tracing::dispatcher::with_default(&dispatch, || {
        correlation.span().in_scope(|| {
            let service =
                tracing::error_span!("service", role, version = env!("CARGO_PKG_VERSION"));
            service.in_scope(|| {
                tracing::info!(
                    event = "phase_completed",
                    phase = Phase::Configuration.as_str(),
                    outcome = "completed",
                    duration_ns = configuration_ns
                );
                let startup = PhaseTimer::start(Phase::Startup);
                let result = initialize_and_wait(role, &config, &io, startup, service_started);
                if let Err(error) = &result {
                    tracing::error!(event = "runtime_failed", error = %error.message);
                }
                let shutdown = PhaseTimer::start(Phase::Shutdown);
                let io_stopped = io.shutdown(Duration::from_secs(1));
                let cpu_stopped = cpu.shutdown(Duration::from_secs(1));
                let result = if io_stopped && cpu_stopped {
                    result
                } else {
                    tracing::error!(event = "work_shutdown_incomplete", io_stopped, cpu_stopped);
                    Err(Error::runtime(
                        "work lanes did not stop before their deadlines",
                    ))
                };
                let loss = diagnostics.losses();
                if loss.full + loss.oversized + loss.closed + loss.io_errors > 0 {
                    tracing::warn!(
                        event = "diagnostic_loss",
                        queue_full = loss.full,
                        oversized = loss.oversized,
                        closed = loss.closed,
                        io_errors = loss.io_errors
                    );
                }
                shutdown.finish(if result.is_ok() {
                    Outcome::Completed
                } else {
                    Outcome::Failed
                });
                tracing::info!(event = "service_stopped", "{role} stopped");
                result
            })
        })
    });
    // Do not fall back to synchronous stderr if the sink itself is stalled.
    if !diagnostics.shutdown(Duration::from_millis(500)) || diagnostics.losses().io_errors > 0 {
        result = Err(Error::runtime("diagnostic output is incomplete"));
    }
    if let Err(error) = &mut result {
        error.reported = true;
    }
    result
}

/// The helper configuration of an enabled `[tailcat]` section (Q06); `None`
/// leaves the link on direct TLS. `listen_port` is the role's default for the
/// port the helper carries.
fn helper_config(
    file: Option<&TailcatFile>,
    listen_port: u16,
) -> Result<Option<sentinel_link::tailcat::TailcatConfig>, Error> {
    let Some(file) = file.filter(|file| file.enabled == Some(true)) else {
        return Ok(None);
    };
    let binary = file
        .binary
        .clone()
        .ok_or_else(|| Error::config("tailcat.binary is required when tailcat is enabled"))?;
    Ok(Some(sentinel_link::tailcat::TailcatConfig {
        enabled: true,
        binary,
        sha256: file
            .sha256
            .clone()
            .unwrap_or_else(|| sentinel_link::tailcat::PINNED_SHA256.to_owned()),
        derpmap_url: file.derpmap_url.clone(),
        region: file.region.clone(),
        listen_port: file.listen_port.unwrap_or(listen_port),
    }))
}

/// The controller's `tc…` address a worker dials through the helper.
fn tailcat_address(link: &WorkerLink) -> Result<sentinel_link::tailcat::Address, Error> {
    let text = link
        .tailcat_address
        .as_deref()
        .ok_or_else(|| Error::config("tailcat_address is required when tailcat is enabled"))?;
    sentinel_link::tailcat::Address::parse(text).ok_or_else(|| {
        Error::config("tailcat_address must be a tailcat address, as in tc<20+ characters>")
    })
}

/// What `sentinel admin tailcat` needs from a role's configuration file: the
/// data directory, the enabled helper and, for a worker, the controller's
/// address. The file is validated exactly as the role itself would.
pub(crate) struct TailcatSetup {
    pub data_dir: PathBuf,
    pub helper: sentinel_link::tailcat::TailcatConfig,
    pub controller: Option<sentinel_link::tailcat::Address>,
}

pub(crate) fn tailcat_setup(
    role: &str,
    config: PathBuf,
    data_dir: Option<PathBuf>,
) -> Result<TailcatSetup, Error> {
    let args = ServiceArgs {
        config: Some(config),
        data_dir,
        check: true,
        log_format: None,
        log_level: None,
    };
    let mut io = Executor::new(WorkClass::BlockingIo, 1)
        .map_err(|error| Error::runtime(format!("cannot start I/O lane: {error}")))?;
    let mut cpu = Executor::new(WorkClass::Cpu, 1)
        .map_err(|error| Error::runtime(format!("cannot start CPU lane: {error}")))?;
    let loaded = Config::load(role, &args, &io, &cpu);
    io.shutdown(Duration::from_secs(1));
    cpu.shutdown(Duration::from_secs(1));
    let loaded = loaded?;
    let disabled = || Error::config("[tailcat] is not enabled in this configuration");
    let (helper, controller) = match &loaded.role {
        Role::Server {
            listen, tailcat, ..
        } => (
            helper_config(tailcat.as_ref(), listen.port())?.ok_or_else(disabled)?,
            None,
        ),
        Role::Worker(Some(link)) => (
            helper_config(
                link.tailcat.as_ref(),
                sentinel_link::tailcat::DEFAULT_LINK_PORT,
            )?
            .ok_or_else(disabled)?,
            Some(tailcat_address(link)?),
        ),
        Role::Worker(None) => return Err(disabled()),
    };
    Ok(TailcatSetup {
        data_dir: loaded.data_dir,
        helper,
        controller,
    })
}

fn bootstrap_work<T: Send + 'static>(
    executor: &Executor,
    work: impl FnOnce() -> T + Send + 'static,
) -> Result<T, Error> {
    executor
        .try_submit(work)
        .and_then(|task| task.wait(Duration::from_secs(5)))
        .map_err(|error| Error::runtime(error.to_string()))
}

/// Load the role's TLS identity from the data directory, generating it on
/// first start. The key file is the process's secret and stays owner-only.
fn identity(data_dir: &Path, stem: &str) -> Result<sentinel_link::identity::Identity, Error> {
    let (cert, key) = (
        data_dir.join(format!("{stem}.crt")),
        data_dir.join(format!("{stem}.key")),
    );
    if cert.exists() || key.exists() {
        return sentinel_link::identity::Identity::load(&cert, &key)
            .map_err(|error| Error::runtime(format!("cannot load {stem} identity: {error}")));
    }
    let generated = sentinel_link::identity::Identity::generate(stem)
        .map_err(|error| Error::runtime(format!("cannot generate {stem} identity: {error}")))?;
    generated
        .save(&cert, &key)
        .map_err(|error| Error::runtime(format!("cannot save {stem} identity: {error}")))?;
    tracing::info!(
        event = "identity_generated",
        stem,
        "{stem} identity generated"
    );
    Ok(generated)
}

/// What the running role holds until shutdown, drained in order. Constructed
/// once per process and never moved in bulk, so its size is not worth another
/// indirection; both lanes are boxed to keep it from growing further.
#[allow(clippy::large_enum_variant)]
enum Running {
    Idle,
    #[cfg(feature = "server")]
    Server {
        controller: sentinel_link::controller::Controller,
        api: sentinel_api::Server,
        /// The credential purge tick; holds a store handle until stopped.
        maintenance: Maintenance,
        store: Arc<sentinel_store::Store>,
        /// Boxed: the enum is constructed once per process, and this keeps
        /// the variant from dominating its size.
        lane: Box<sentinel_intake::Lane>,
        /// The opt-in ref poller feeding the same intake path.
        poll: Box<sentinel_intake::Poll>,
        /// The Checks outbox lane, when a GitHub App is configured.
        checks: Option<Box<sentinel_checks::Lane>>,
        /// The lifecycle reconcile lane draining `github_refresh`.
        reconcile: Option<Box<sentinel_checks::Reconcile>>,
        /// The Q06 helper carrying the link port; absent with direct TLS.
        tailcat: Option<TailcatServer>,
    },
    #[cfg(feature = "worker")]
    Worker {
        handle: Arc<sentinel_link::worker::Handle>,
        thread: std::thread::JoinHandle<()>,
        /// The Q06 helper the worker dials through; absent with direct TLS.
        /// Shared with the link thread, which replaces it when sessions over
        /// it keep failing.
        tailcat: Option<Arc<sentinel_link::tailcat::Forward>>,
    },
}

/// Q06 for the server: run the helper that carries the link port, keep its
/// `tc…` address in the owner-only `<data_dir>/tailcat/address` (the operator
/// hands that exact string to workers as `tailcat_address`; the log names only
/// the file), and keep the admitted node keys current from
/// `<data_dir>/tailcat-allow` minus every key whose worker is revoked. `None`
/// means direct TLS, unchanged.
#[cfg(feature = "server")]
struct TailcatServer {
    server: Arc<sentinel_link::tailcat::Server>,
    /// Dropping it wakes and ends the allow-list refresher at once.
    stop: mpsc::SyncSender<()>,
    /// The refresher holds a store handle; it is joined before the store
    /// drains.
    refresher: std::thread::JoinHandle<()>,
}

#[cfg(feature = "server")]
impl TailcatServer {
    fn shutdown(self) {
        drop(self.stop);
        let _ = self.refresher.join();
        self.server.shutdown();
    }
}

/// How often the allow list and the workers it names are re-read: a
/// revoked worker's tunnel closes within one tick.
#[cfg(feature = "server")]
const TAILCAT_ALLOW_REFRESH: Duration = Duration::from_secs(10);

/// The keys the helper may admit: every listed key whose worker is not
/// revoked. A worker the store does not know yet stays admitted — it has to
/// reach the controller over the tunnel to enroll at all.
#[cfg(feature = "server")]
fn admitted_keys(
    store: &sentinel_store::Store,
    listed: &[sentinel_link::tailcat::Admission],
) -> sentinel_store::Result<Vec<sentinel_link::tailcat::NodeKey>> {
    store.read(|conn| {
        let mut keys = Vec::with_capacity(listed.len());
        for admission in listed {
            if !sentinel_store::workers::revoked(conn, admission.worker)? {
                keys.push(admission.key.clone());
            }
        }
        Ok(keys)
    })
}

#[cfg(feature = "server")]
fn start_tailcat(
    config: &Config,
    store: &Arc<sentinel_store::Store>,
    file: Option<&TailcatFile>,
    listen: SocketAddr,
) -> Result<Option<TailcatServer>, Error> {
    let Some(helper) = helper_config(file, listen.port())? else {
        return Ok(None);
    };
    let mut listed = sentinel_link::tailcat::allow_list(&config.data_dir)
        .map_err(|error| Error::runtime(format!("cannot read the tailcat allow list: {error}")))?;
    let keys = admitted_keys(store, &listed).map_err(|error| {
        Error::runtime(format!(
            "cannot check the tailcat allow list's workers: {error}"
        ))
    })?;
    let server = sentinel_link::tailcat::start_server(&helper, &config.data_dir, &keys)
        .map_err(|error| Error::runtime(format!("cannot start the tailcat helper: {error}")))?;
    match server.wait_ready(Duration::from_secs(60)) {
        // The address is a credential: it lives in an owner-only file, and
        // the log names only that file.
        Ok(_) => tracing::info!(
            event = "tailcat_listening",
            address_file = %server.address_file().display(),
            admitted = keys.len()
        ),
        Err(problem) => tracing::warn!(
            event = "tailcat_not_ready",
            problem = %problem,
            "the helper did not report an address within 60s; workers cannot dial it yet"
        ),
    }
    // The allow list is an operator file and revocation is a store fact;
    // both are re-read on a slow tick, so a newly admitted key takes effect
    // and a revoked worker's tunnel closes without a restart.
    let server = Arc::new(server);
    let (stop, wake) = mpsc::sync_channel::<()>(0);
    let refresher = {
        let server = Arc::clone(&server);
        let store = Arc::clone(store);
        let data_dir = config.data_dir.clone();
        let dispatch = tracing::dispatcher::get_default(Clone::clone);
        std::thread::Builder::new()
            .name("sentinel-tailcat-allow".into())
            .spawn(move || {
                tracing::dispatcher::with_default(&dispatch, || {
                    let (mut file_warned, mut store_warned) = (false, false);
                    let mut rotation_warned = false;
                    while let Err(mpsc::RecvTimeoutError::Timeout) =
                        wake.recv_timeout(TAILCAT_ALLOW_REFRESH)
                    {
                        // A key rotation staged, committed or abandoned by
                        // `sentinel admin tailcat`: serve the staged key
                        // beside the active one, or switch.
                        match server.reload_keys() {
                            Ok(()) => rotation_warned = false,
                            Err(_) if !rotation_warned => {
                                rotation_warned = true;
                                tracing::warn!(
                                    event = "tailcat_rotation_unreadable",
                                    "keeping the node keys in use"
                                );
                            }
                            Err(_) => {}
                        }
                        match sentinel_link::tailcat::allow_list(&data_dir) {
                            // An empty or absent file is a decision: it
                            // closes every tunnel (`--allow=none`).
                            Ok(read) => {
                                file_warned = false;
                                listed = read;
                            }
                            // An unreadable or malformed file is not: keep the
                            // last good list, still filtered by revocation.
                            Err(_) if !file_warned => {
                                file_warned = true;
                                tracing::warn!(
                                    event = "tailcat_allow_unreadable",
                                    "keeping the last good node-key list"
                                );
                            }
                            Err(_) => {}
                        }
                        match admitted_keys(&store, &listed) {
                            Ok(keys) => {
                                store_warned = false;
                                server.set_allow(&keys);
                            }
                            Err(error) if !store_warned => {
                                store_warned = true;
                                tracing::warn!(
                                    event = "tailcat_allow_unchecked",
                                    error = %error,
                                    "keeping the admitted node keys until the store answers"
                                );
                            }
                            Err(_) => {}
                        }
                    }
                });
            })
            .map_err(|error| {
                Error::runtime(format!(
                    "cannot start the tailcat allow-list thread: {error}"
                ))
            })?
    };
    Ok(Some(TailcatServer {
        server,
        stop,
        refresher,
    }))
}

/// How often expired rows are purged: sessions, API credentials, external
/// sign-in state, OAuth rows and idempotency records. Validation never
/// depends on it — every check tests expiry and revocation itself, and an
/// expired idempotency record already executes afresh — so this only bounds
/// table growth.
#[cfg(feature = "server")]
const MAINTENANCE_INTERVAL: Duration = Duration::from_secs(600);
/// The next tick's delay while some purge still had a full batch to take:
/// a backlog drains a batch per kind per second, releasing the writer
/// between batches, instead of one batch per ten minutes.
#[cfg(feature = "server")]
const BACKLOG_INTERVAL: Duration = Duration::from_secs(1);
/// Rows each purge removes per kind per tick; a backlog drains over
/// several ticks instead of holding the writer.
#[cfg(feature = "server")]
const PURGE_BATCH: u32 = 1000;

/// The maintenance tick: one thread that sleeps on a channel and runs the
/// bounded purges every [`MAINTENANCE_INTERVAL`] (or [`BACKLOG_INTERVAL`]
/// while a backlog remains). Dropping the sender wakes and ends it at once.
#[cfg(feature = "server")]
struct Maintenance {
    stop: mpsc::SyncSender<()>,
    thread: std::thread::JoinHandle<()>,
}

#[cfg(feature = "server")]
impl Maintenance {
    fn start(store: Arc<sentinel_store::Store>) -> std::io::Result<Maintenance> {
        let (stop, wake) = mpsc::sync_channel::<()>(0);
        let dispatch = tracing::dispatcher::get_default(Clone::clone);
        let thread = std::thread::Builder::new()
            .name("sentinel-maintenance".into())
            .spawn(move || {
                tracing::dispatcher::with_default(&dispatch, || {
                    let mut interval = MAINTENANCE_INTERVAL;
                    while let Err(mpsc::RecvTimeoutError::Timeout) = wake.recv_timeout(interval) {
                        interval = if purge_expired(&store, PURGE_BATCH) {
                            BACKLOG_INTERVAL
                        } else {
                            MAINTENANCE_INTERVAL
                        };
                    }
                });
            })?;
        Ok(Maintenance { stop, thread })
    }

    /// Stop the tick and release its store handle before the store drains.
    fn stop(self) {
        drop(self.stop);
        let _ = self.thread.join();
    }
}

/// One bounded purge: the store, "now", and the per-call row budget.
#[cfg(feature = "server")]
type Purge =
    fn(&sentinel_store::Store, sentinel_core::UnixMillis, u32) -> sentinel_store::Result<usize>;

/// One tick: at most `batch` rows of each kind. Returns whether any kind
/// filled its batch, i.e. may have more to purge.
#[cfg(feature = "server")]
fn purge_expired(store: &sentinel_store::Store, batch: u32) -> bool {
    let now = sentinel_core::UnixMillis::now();
    let purges: [(&str, Purge); 5] = [
        ("oauth", sentinel_store::oauth::purge_expired),
        ("api_tokens", sentinel_store::tokens::purge_expired),
        ("sessions", sentinel_store::local_auth::purge_expired),
        ("sign_in", sentinel_store::sign_in::purge_expired),
        ("idempotency", sentinel_store::idempotency::purge_expired),
    ];
    let mut backlog = false;
    for (kind, purge) in purges {
        match purge(store, now, batch) {
            Ok(0) => {}
            Ok(removed) => {
                backlog |= removed >= batch as usize;
                tracing::info!(event = "expired_rows_purged", kind, removed);
            }
            Err(error) => {
                tracing::warn!(event = "expired_rows_purge_failed", kind, error = %error);
            }
        }
    }
    backlog
}

#[cfg(feature = "server")]
fn start_server(
    config: &Config,
    listen: SocketAddr,
    api_listen: SocketAddr,
    public_url: Option<String>,
    tailcat: Option<&TailcatFile>,
    remote_cache: bool,
) -> Result<Running, Error> {
    let path = config.data_dir.join(sentinel_store::METADATA_FILE);
    let store =
        sentinel_store::Store::open(&path, sentinel_store::Durability::Full).map_err(|error| {
            match error {
                sentinel_store::Error::AlreadyOwned => Error::runtime(format!(
                    "another process owns {}; one controller per data directory",
                    path.display()
                )),
                other => Error::runtime(format!("cannot open {}: {other}", path.display())),
            }
        })?;
    let store = Arc::new(store);
    let identity = identity(&config.data_dir, "controller")?;
    let fingerprint = hex32(&identity.fingerprint().0);
    let logs = Arc::new(
        sentinel_store::logs::LogStore::open(config.data_dir.join(sentinel_store::logs::LOGS_DIR))
            .map_err(|error| Error::runtime(format!("cannot open the log store: {error}")))?,
    );
    // Disk admission (D06): one gate over the data directory's filesystem
    // shared by objects and logs; staged writes and uploads charge it.
    let admission = Arc::new(
        sentinel_store::space::Admission::new(config.data_dir.clone(), config.storage.marks)
            .map_err(|error| Error::runtime(format!("invalid storage watermarks: {error}")))?,
    );
    logs.set_admission(Arc::clone(&admission));
    // Reconcile the object tree against committed rows before serving:
    // staged leftovers are swept, orphans/corrupt/missing are reported.
    let objects = sentinel_store::objects::Objects::open(&config.data_dir)
        .map_err(|error| Error::runtime(format!("cannot open the object store: {error}")))?;
    objects.set_admission(Arc::clone(&admission));
    objects.set_default_quota(config.storage.tenant_quota);
    let recovery = store
        .read(|conn| objects.recover(conn))
        .map_err(|error| Error::runtime(format!("cannot recover the object store: {error}")))?;
    if recovery.orphans.is_empty() && recovery.corrupt.is_empty() && recovery.missing.is_empty() {
        tracing::info!(event = "objects_recovered", staged = recovery.staged);
    } else {
        tracing::warn!(
            event = "objects_recovered",
            staged = recovery.staged,
            orphans = recovery.orphans.len(),
            corrupt = recovery.corrupt.len(),
            missing = recovery.missing.len(),
            "object store recovery found inconsistencies"
        );
    }
    // Expired resumable uploads are retired and their staging files dropped;
    // open-but-live ones keep their bytes for the client to resume.
    let objects = Arc::new(objects);
    let swept = store
        .writer()
        .write({
            let objects = Arc::clone(&objects);
            move |tx| objects.sweep_uploads(tx, sentinel_core::UnixMillis::now())
        })
        .map_err(|error| Error::runtime(format!("cannot sweep expired uploads: {error}")))?;
    if swept > 0 {
        tracing::info!(event = "uploads_swept", expired = swept);
    }
    let controller = sentinel_link::controller::Controller::start(
        Arc::clone(&store),
        Arc::clone(&logs),
        Arc::clone(&objects),
        identity,
        listen,
    )
    .map_err(|error| Error::runtime(format!("cannot listen on {listen}: {error}")))?;
    let reconciled = controller.reconciled();
    controller.set_storage_policy(sentinel_link::controller::StoragePolicy {
        log_retention_ms: config.storage.log_retention_ms,
        interval_ms: config.storage.sweep_interval_ms,
    });
    // Remote cache (Q08): the controller holds objects workers offer, so a
    // second worker can hydrate them without the WAN. The directory is
    // created here for operators; uploads create it lazily anyway.
    if remote_cache {
        let root = config.data_dir.join("remote-cache");
        fs::create_dir_all(&root).map_err(|error| {
            Error::runtime(format!(
                "cannot create the remote cache directory {}: {error}",
                root.display()
            ))
        })?;
        controller.set_remote_cache(root);
    }
    let tailcat = start_tailcat(config, &store, tailcat, listen)?;
    // One destination policy for every controller-side fetch: worker spec
    // delivery, intake resolution and ref polling all recheck it.
    let destinations = crate::source_admin::load_destinations(&config.data_dir)
        .map_err(|_| Error::runtime("cannot load source destination policy"))?;
    let intake_destinations: Arc<[String]> = destinations.clone().into();
    controller.set_source_destinations(destinations);
    let app = crate::source_admin::load_app(&config.data_dir)
        .map_err(|_| Error::runtime("cannot load GitHub App configuration"))?;
    if let Some(app) = &app {
        controller.set_source_app(Arc::clone(&app.app));
    }
    let source_key = config.data_dir.join("master.key");
    let key = if source_key.exists() {
        Some(Arc::new(
            sentinel_auth::sealed::Key::load(&source_key)
                .map_err(|_| Error::runtime("cannot load source sealing key"))?,
        ))
    } else {
        None
    };
    if let Some(key) = &key {
        controller.set_source_key(Arc::clone(key));
    }
    // The durable intake lane: accepted deliveries are validated and
    // resolved off the request path, bounded, and woken by the intake route.
    // Its thread is not inside the service's scoped diagnostic dispatcher, so
    // the dispatcher is captured here and installed around each notice,
    // exactly as `work.rs` does for its lanes.
    let resolver = sentinel_intake::Resolver::new(
        Arc::clone(&store),
        key.clone(),
        app.as_ref().map(|app| Arc::clone(&app.app)),
        Arc::clone(&intake_destinations),
        Arc::new(sentinel_intake::resolve::GitFetch),
        config.data_dir.join("intake-work"),
        sentinel_intake::resolve::Config::default(),
    )
    .map_err(|_| Error::runtime("cannot prepare the intake work directory"))?;
    let dispatch_wake: Arc<dyn Fn() + Send + Sync> = {
        let handle = controller.handle();
        Arc::new(move || handle.wake())
    };
    let dispatch = tracing::dispatcher::get_default(Clone::clone);
    let lane = sentinel_intake::Lane::start(
        Arc::clone(&store),
        Some(Arc::new(resolver)),
        Some(dispatch_wake),
        sentinel_intake::lane::Config::default(),
        move |batch| {
            tracing::dispatcher::with_default(&dispatch, || {
                if let Some(error) = &batch.error {
                    tracing::warn!(event = "intake_stalled", error = %error, "intake lane pass failed");
                }
                if batch.failed > 0 {
                    tracing::warn!(
                        event = "intake_failed",
                        failed = batch.failed,
                        "deliveries settled with an explicit failure"
                    );
                }
                if batch.retried > 0 {
                    tracing::info!(event = "intake_retried", retried = batch.retried);
                }
                for settled in &batch.settled {
                    tracing::info!(
                        event = "intake_settled",
                        delivery = %settled.id,
                        outcome = %settled.outcome
                    );
                }
            });
        },
    );
    // The opt-in ref poller (G07): nothing is configured until an operator
    // opts a repository in, but the lane runs so a new configuration takes
    // effect without a restart. Its deliveries ride the intake lane above.
    let poll_dispatch = tracing::dispatcher::get_default(Clone::clone);
    let poll = sentinel_intake::Poll::start(
        Arc::clone(&store),
        key.clone(),
        app.as_ref().map(|app| Arc::clone(&app.app)),
        intake_destinations,
        Arc::new(sentinel_intake::GitLister),
        config.data_dir.join("poll-work"),
        sentinel_intake::poll::Config::default(),
        move |notice| {
            tracing::dispatcher::with_default(&poll_dispatch, || {
                if notice.failed {
                    tracing::warn!(
                        event = "poll_failed",
                        repo = %notice.repo,
                        outcome = %notice.outcome
                    );
                } else {
                    tracing::info!(
                        event = "poll_observed",
                        repo = %notice.repo,
                        outcome = %notice.outcome
                    );
                }
            });
        },
    )
    .map_err(|_| Error::runtime("cannot prepare the poll work directory"))?;
    let github_webhook_secret = crate::source_admin::load_webhook_secret(&config.data_dir)
        .map_err(|_| Error::runtime("cannot load the GitHub webhook secret"))?;
    if github_webhook_secret.is_some() {
        tracing::info!(event = "github_webhook_enabled");
    }
    // The Checks outbox lane and the lifecycle reconcile lane: both need an
    // App, so neither starts without one. The reconcile lane drains durable
    // `github_refresh` work — webhook hints and the periodic pass — and is
    // also where a lost check answer gets found again by external ID.
    let mut reconcile = None;
    let checks = match &app {
        Some(app) => {
            tracing::info!(
                event = "checks_enabled",
                endpoint = %app.app.endpoint(),
                details_url = app.public_url.is_some()
            );
            let reconcile_dispatch = tracing::dispatcher::get_default(Clone::clone);
            reconcile = Some(Box::new(sentinel_checks::Reconcile::start(
                Arc::clone(&store),
                Arc::clone(&app.app),
                sentinel_checks::reconcile::Config::default(),
                move |notice| {
                    tracing::dispatcher::with_default(&reconcile_dispatch, || {
                        tracing::info!(
                            event = "github_reconciled",
                            kind = notice.kind,
                            outcome = %notice.outcome
                        );
                    });
                },
            )));
            let publisher = sentinel_checks::github::GithubChecks::new(
                Arc::clone(&store),
                Arc::clone(&app.app),
                app.public_url.clone(),
            );
            let dispatch = tracing::dispatcher::get_default(Clone::clone);
            Some(Box::new(sentinel_checks::Lane::start(
                Arc::clone(&store),
                Box::new(publisher),
                sentinel_checks::lane::Config::default(),
                move |batch| {
                    tracing::dispatcher::with_default(&dispatch, || {
                        if batch.refused > 0 {
                            tracing::warn!(
                                event = "checks_failed",
                                refused = batch.refused,
                                "publications were refused"
                            );
                        }
                        if let Some(until) = batch.paused_until_ms {
                            tracing::warn!(event = "checks_paused", until_ms = until);
                        }
                        for entry in &batch.entries {
                            tracing::info!(
                                event = "check_settled",
                                check = %entry.id,
                                name = %entry.name,
                                outcome = %entry.outcome
                            );
                        }
                    });
                },
            )))
        }
        None => {
            tracing::info!(event = "checks_disabled", "no GitHub App");
            None
        }
    };
    tracing::info!(
        event = "link_listening",
        addr = %controller.local_addr(),
        fingerprint = %fingerprint,
        expired = reconciled.expired,
        lapsed = reconciled.lapsed,
        orphaned = reconciled.orphaned,
        "workers pin this fingerprint with their enrollment"
    );
    let api = sentinel_api::Server::start(sentinel_api::Config {
        listen: api_listen,
        store: Arc::clone(&store),
        logs: Arc::clone(&logs),
        objects,
        controller: controller.handle(),
        sessions: sentinel_store::local_auth::Policy::default(),
        github_webhook_secret,
        intake: Some(lane.waker()),
        public_url,
    })
    .map_err(|error| Error::runtime(format!("cannot listen on {api_listen}: {error}")))?;
    tracing::info!(event = "api_listening", addr = %api.local_addr(), issuer = %api.issuer());
    let maintenance = Maintenance::start(Arc::clone(&store))
        .map_err(|error| Error::runtime(format!("cannot start maintenance: {error}")))?;
    Ok(Running::Server {
        controller,
        api,
        maintenance,
        store,
        lane: Box::new(lane),
        poll: Box::new(poll),
        checks,
        reconcile,
        tailcat,
    })
}

#[cfg(feature = "worker")]
mod worker_role {
    use super::*;
    use sentinel_core::AttemptId;
    use sentinel_link::session::{Capacity, Executor as LinkExecutor, Offer};

    /// Without a usable rootless runtime there is nothing to run an offer
    /// with: every offer is declined, so the job stays queued instead of
    /// sitting leased on a machine that cannot start it.
    struct NoExecutor;
    impl LinkExecutor for NoExecutor {
        fn offered(&self, offer: &Offer) -> bool {
            tracing::warn!(event = "offer_declined", attempt = %offer.attempt, job = %offer.job, "no executor: rootless Podman is unavailable");
            false
        }
        fn stop(&self, _: AttemptId) {}
        fn cancel(&self, _: AttemptId) {}
        fn held(&self) -> Vec<AttemptId> {
            Vec::new()
        }
        fn renewed(&self, _: sentinel_core::UnixMillis) {}
        fn attached(&self, _: sentinel_link::session::Reporter) {}
        fn detached(&self) {}
        fn spec(&self, _: AttemptId, _: sentinel_link::session::JobContext, _: Vec<u8>) {}
        fn no_spec(&self, _: AttemptId) {}
        fn log_acked(&self, _: AttemptId, _: u64) {}
        fn log_refused(&self, _: AttemptId) {}
    }

    /// The real executor when rootless Podman answers, else the decliner.
    fn executor(
        data_dir: &Path,
        worker: sentinel_core::WorkerId,
        git_mirrors: bool,
    ) -> Box<dyn LinkExecutor> {
        let dispatch = tracing::dispatcher::get_default(Clone::clone);
        let span = tracing::Span::current();
        let notify = move |notice: sentinel_worker::executor::Notice| {
            tracing::dispatcher::with_default(&dispatch, || {
                span.in_scope(|| match notice {
                    sentinel_worker::executor::Notice::Started(attempt) => {
                        tracing::info!(event = "attempt_started", attempt = %attempt);
                    }
                    sentinel_worker::executor::Notice::Finished(attempt, verdict) => {
                        tracing::info!(event = "attempt_finished", attempt = %attempt, verdict = ?verdict);
                    }
                    sentinel_worker::executor::Notice::SpecRefused(attempt) => {
                        tracing::warn!(event = "attempt_spec_refused", attempt = %attempt);
                    }
                    sentinel_worker::executor::Notice::HandedBack(attempt) => {
                        tracing::warn!(event = "attempt_handed_back", attempt = %attempt, "the run spec never arrived; the attempt was returned to the queue unstarted");
                    }
                    sentinel_worker::executor::Notice::Stopped(attempt) => {
                        tracing::info!(event = "attempt_stopped", attempt = %attempt);
                    }
                    sentinel_worker::executor::Notice::Canceled { attempt, forced } => {
                        tracing::info!(event = "attempt_canceled", attempt = %attempt, forced);
                    }
                    sentinel_worker::executor::Notice::Abandoned { attempt, log_delivered } => {
                        tracing::warn!(event = "attempt_abandoned", attempt = %attempt, log_delivered, "left by the previous worker process; reconciled by the controller");
                    }
                    sentinel_worker::executor::Notice::LeaseLost(attempts) => {
                        tracing::warn!(event = "lease_lost", attempts = ?attempts, "no renewal before the deadline; attempts ended without a report");
                    }
                    sentinel_worker::executor::Notice::MirrorsUnavailable(why) => {
                        tracing::warn!(event = "mirrors_unavailable", reason = %why, "checkouts will fetch directly for this process");
                    }
                    sentinel_worker::executor::Notice::CachePublished { attempt, note } => {
                        tracing::info!(event = "cache_published", attempt = %attempt, cache = %note.name, outcome = ?note.outcome);
                    }
                    sentinel_worker::executor::Notice::CacheSwept(stats) => {
                        tracing::info!(event = "cache_swept", stats = ?stats);
                    }
                    sentinel_worker::executor::Notice::CostlyCacheHit { attempt, name, costly, stats } => {
                        tracing::warn!(event = "cache_costly_hit", attempt = %attempt, cache = %name, reason = costly.as_str(), copied_bytes = stats.copied_bytes, bytes = stats.bytes, lock_wait_ns = ?stats.lock_wait_ns, clone_ns = ?stats.clone_ns, "nominal hit paid rebuild-scale restore cost (docs/cache.md)");
                    }
                    sentinel_worker::executor::Notice::Availability(snapshot) => {
                        tracing::info!(event = "availability", images_held = snapshot.images_held.len(), images_in_flight = snapshot.images_in_flight, cache_entries = snapshot.cache_entries, cache_generations = snapshot.cache_generations, cache_bytes = snapshot.cache_bytes, truncated = snapshot.truncated);
                    }
                })
            })
        };
        match sentinel_worker::executor::Executor::start(
            data_dir.to_path_buf(),
            worker,
            notify,
            git_mirrors,
        ) {
            Ok(executor) => {
                let runtime = executor.runtime();
                let recovered = executor.recovered();
                tracing::info!(
                    event = "executor_ready",
                    podman = %runtime.version,
                    oci_runtime = %runtime.oci_runtime,
                    cgroup_manager = %runtime.cgroup_manager,
                    leftovers = recovered.leftovers.len(),
                    containers_removed = recovered.containers_removed,
                    workspaces_removed = recovered.workspaces_removed
                );
                Box::new(executor)
            }
            Err(error) => {
                tracing::warn!(event = "executor_unavailable", error = %error, "offers will be declined");
                Box::new(NoExecutor)
            }
        }
    }

    /// Measured capacity: every core, and total memory less a host reserve of
    /// one eighth (at least 512 MiB, at most 2 GiB). Overridable per key.
    fn capacity(link: &WorkerLink) -> Capacity {
        let cores = std::thread::available_parallelism().map_or(1, |n| n.get() as u64);
        let total = fs::read_to_string("/proc/meminfo")
            .ok()
            .and_then(|text| {
                text.lines()
                    .find_map(|line| line.strip_prefix("MemTotal:"))
                    .and_then(|rest| rest.trim().split(' ').next())
                    .and_then(|kb| kb.parse::<u64>().ok())
            })
            .map_or(1 << 30, |kb| kb * 1024);
        let reserve = (total / 8).clamp(512 << 20, 2 << 30);
        Capacity {
            cpu_millis: link.cpu_millis.unwrap_or(cores * 1000),
            memory_bytes: link
                .memory_bytes
                .unwrap_or_else(|| total.saturating_sub(reserve).max(256 << 20)),
        }
    }

    /// Free bytes on the filesystem holding `path`, or 0 when the platform
    /// cannot say — reported as "not measured", never as "full".
    #[cfg(target_os = "linux")]
    fn disk_free(path: &Path) -> u64 {
        use std::os::unix::ffi::OsStrExt;
        let Ok(cpath) = std::ffi::CString::new(path.as_os_str().as_bytes()) else {
            return 0;
        };
        let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
        // SAFETY: `cpath` is a valid NUL-terminated path and `stat` is a
        // writable, properly aligned statvfs.
        if unsafe { libc::statvfs(cpath.as_ptr(), &mut stat) } != 0 {
            return 0;
        }
        (stat.f_bavail as u64).saturating_mul(stat.f_frsize as u64)
    }

    #[cfg(not(target_os = "linux"))]
    fn disk_free(_path: &Path) -> u64 {
        0
    }

    /// The scratch disk this worker offers jobs: the operator's `disk_bytes`,
    /// or the data directory's free space less a reserve of one eighth
    /// (clamped to 512 MiB–2 GiB) for logs, metadata and artifacts. Zero
    /// means the platform could not measure it, and jobs that require disk
    /// then never place here.
    fn profile_disk(link: &WorkerLink, data_dir: &Path) -> u64 {
        match link.disk_bytes {
            Some(bytes) => bytes,
            None => {
                let free = disk_free(data_dir);
                let reserve = (free / 8).clamp(512 << 20, 2 << 30);
                free.saturating_sub(reserve)
            }
        }
    }

    /// CPU busy time in nanoseconds over a short window: the worker's load
    /// input to placement (Q03). 0 when unmeasurable (not Linux, or
    /// /proc/stat unreadable), never a claim of idleness.
    #[cfg(target_os = "linux")]
    fn load_ns() -> u64 {
        const WINDOW: Duration = Duration::from_millis(100);
        // USER_HZ is 100 on every Linux the executor supports, so one
        // /proc/stat tick is 10 ms.
        const TICK_NS: u64 = 10_000_000;
        fn busy_ticks() -> Option<u64> {
            let text = fs::read_to_string("/proc/stat").ok()?;
            let values: Vec<u64> = text
                .lines()
                .next()?
                .strip_prefix("cpu")?
                .split_whitespace()
                .filter_map(|value| value.parse().ok())
                .collect();
            // user nice system idle iowait irq softirq steal …
            if values.len() < 8 {
                return None;
            }
            Some(values[0] + values[1] + values[2] + values[5] + values[6] + values[7])
        }
        let Some(first) = busy_ticks() else {
            return 0;
        };
        std::thread::sleep(WINDOW);
        let Some(second) = busy_ticks() else {
            return 0;
        };
        second.saturating_sub(first).saturating_mul(TICK_NS)
    }

    #[cfg(not(target_os = "linux"))]
    fn load_ns() -> u64 {
        0
    }

    /// The protocol-7 profile: what the scheduler may select this machine by
    /// and what it can offer jobs. `images`/`cache_bytes` start empty here
    /// and are filled per session from the executor's own record (P07-6,
    /// `Executor::availability`): the held image keys and the cache store's
    /// estimated bytes, refreshed from protocol 8 whenever they change.
    fn profile(link: &WorkerLink, data_dir: &Path) -> sentinel_protocol::negotiate::Profile {
        sentinel_protocol::negotiate::Profile {
            labels: link.labels.clone(),
            host_id: sentinel_link::session::host_id(),
            disk_bytes: profile_disk(link, data_dir),
            availability: sentinel_protocol::negotiate::Availability {
                images: Vec::new(),
                cache_bytes: 0,
                load_ns: load_ns(),
            },
        }
    }

    /// Q06: run the helper the worker dials through, when it is enabled.
    /// Returns the address the link must dial, the transport telemetry the
    /// helper already measured, and the helper itself to shut down later.
    fn tailcat(
        link: &WorkerLink,
        data_dir: &Path,
    ) -> Result<
        (
            SocketAddr,
            sentinel_link::session::TransportStats,
            Option<sentinel_link::tailcat::Forward>,
        ),
        Error,
    > {
        let mut stats = sentinel_link::session::TransportStats {
            path: sentinel_link::session::Path::Direct,
            ..sentinel_link::session::TransportStats::default()
        };
        let Some(config) = helper_config(
            link.tailcat.as_ref(),
            sentinel_link::tailcat::DEFAULT_LINK_PORT,
        )?
        else {
            return Ok((link.controller, stats, None));
        };
        let address = tailcat_address(link)?;
        let forward = sentinel_link::tailcat::start_forward(&config, data_dir, &address)
            .map_err(|error| Error::runtime(format!("cannot start the tailcat helper: {error}")))?;
        stats.helper_version = forward.telemetry().version;
        // The path is what `tailcat ping` reported — a pong via DERP or from
        // an ip:port — and stays Unknown when no probe measured it. The seed
        // RTT is the latency the pong itself reported, never the wall time
        // of the ping process; the first control beat replaces it.
        stats.path = sentinel_link::session::Path::Unknown;
        if let Ok(measured) = forward.probe() {
            stats.path = measured.path;
            stats.rtt_ns = measured
                .rtt
                .map(|rtt| rtt.as_nanos().min(u128::from(u64::MAX)) as u64);
        }
        tracing::info!(
            event = "tailcat_forwarding",
            nodekey_file = %sentinel_link::tailcat::nodekey_file(
                data_dir,
                sentinel_link::tailcat::Role::Worker
            )
            .display(),
            path = ?stats.path
        );
        // The worker dials the helper's loopback forward; the helper carries
        // exactly the link port.
        let local = SocketAddr::from(([127, 0, 0, 1], forward.local_addr().port()));
        Ok((local, stats, Some(forward)))
    }

    /// Control sessions in a row that may fail over a running helper before
    /// the helper is replaced. The session is the data path's health: `ping`
    /// proves the mesh, only a session proves the forward carries the link.
    pub(super) const TUNNEL_SESSION_FAILURES: u32 = 3;

    /// Counts consecutive failed control sessions (a failed dial included);
    /// any welcomed session resets it.
    #[derive(Default)]
    pub(super) struct TunnelWatch {
        failures: std::sync::atomic::AtomicU32,
    }

    impl TunnelWatch {
        pub(super) fn connected(&self) {
            self.failures.store(0, std::sync::atomic::Ordering::Relaxed);
        }

        /// Records a lost or refused session; `true` means replace the helper
        /// now (and the count starts over for its successor).
        pub(super) fn lost(&self) -> bool {
            let failures = self
                .failures
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                + 1;
            if failures >= TUNNEL_SESSION_FAILURES {
                self.failures.store(0, std::sync::atomic::Ordering::Relaxed);
                true
            } else {
                false
            }
        }
    }

    /// The worker's generated identifier, fixed on first start.
    fn worker_id(data_dir: &Path) -> Result<sentinel_core::WorkerId, Error> {
        let path = data_dir.join("worker.id");
        match sentinel::bounded::text(&path, 4 << 10) {
            Ok(text) => text
                .trim()
                .parse()
                .map_err(|_| Error::runtime("worker.id is not a wrk_ identifier")),
            Err(sentinel::bounded::ReadError::Io(error))
                if error.kind() == std::io::ErrorKind::NotFound =>
            {
                let id = sentinel_core::WorkerId::new();
                fs::write(&path, format!("{id}\n"))
                    .map_err(|error| Error::runtime(format!("cannot save worker.id: {error}")))?;
                Ok(id)
            }
            Err(error) => Err(Error::runtime(format!("cannot read worker.id: {error}"))),
        }
    }

    pub(super) fn start(config: &Config, link: &WorkerLink) -> Result<Running, Error> {
        let identity = identity(&config.data_dir, "worker")?;
        let worker = worker_id(&config.data_dir)?;
        let enrollment = match &link.enrollment_file {
            Some(path) => match sentinel::bounded::text(path, 4 << 10) {
                Ok(text) => Some(sentinel_auth::token::parse(text.trim()).ok_or_else(|| {
                    Error::runtime("enrollment_file does not hold an enrollment secret")
                })?),
                Err(sentinel::bounded::ReadError::Io(error))
                    if error.kind() == std::io::ErrorKind::NotFound =>
                {
                    None
                }
                Err(error) => {
                    return Err(Error::runtime(format!(
                        "cannot read enrollment_file: {error}"
                    )));
                }
            },
            None => None,
        };
        let capacity = capacity(link);
        let profile = profile(link, &config.data_dir);
        // The helper, when enabled, is up before the first dial: the link
        // then reaches the controller at its loopback forward.
        let (controller, transport, forward) = tailcat(link, &config.data_dir)?;
        let forward = forward.map(Arc::new);
        // The reflink bit is the cache root's own probe answer, so the
        // advertised capability and the backend restore uses never disagree.
        let mut capabilities = sentinel_protocol::negotiate::Capabilities::REQUIRED;
        if sentinel_worker::cache_reflink(&config.data_dir) {
            capabilities = capabilities.union(sentinel_protocol::negotiate::Capabilities::REFLINK);
        }
        let settings = sentinel_link::worker::Config {
            controller,
            server: sentinel_auth::secret::Digest(link.fingerprint),
            worker,
            name: link.name.clone(),
            hello: sentinel_protocol::negotiate::Hello {
                protocol_min: sentinel_protocol::negotiate::ProtocolVersion(1),
                protocol_max: sentinel_protocol::negotiate::SUPPORTED_MAX,
                capabilities,
                arch: if cfg!(target_arch = "aarch64") {
                    sentinel_protocol::negotiate::Arch::Aarch64
                } else {
                    sentinel_protocol::negotiate::Arch::X86_64
                },
                software: format!("sentinel {}", env!("CARGO_PKG_VERSION")),
            },
            capacity,
            profile,
            transport,
            remote_cache: link.remote_cache,
        };
        tracing::info!(
            event = "link_configured",
            controller = %controller,
            worker = %worker,
            cpu_millis = capacity.cpu_millis,
            memory_bytes = capacity.memory_bytes,
            labels = settings.profile.labels.len(),
            disk_bytes = settings.profile.disk_bytes,
            enrolling = enrollment.is_some(),
            tailcat = forward.is_some()
        );
        let handle = Arc::new(sentinel_link::worker::Handle::new());
        // Q07: with a helper, every session starts from — and every
        // telemetry resend refreshes — the path and latency the helper's
        // latest probe measured, not the probe at process start.
        if let Some(forward) = &forward {
            let forward = Arc::clone(forward);
            handle.set_transport_source(Arc::new(move || {
                let measured = forward.telemetry();
                sentinel_link::session::TransportStats {
                    path: measured.path,
                    rtt_ns: measured
                        .ping_rtt
                        .map(|rtt| rtt.as_nanos().min(u128::from(u64::MAX)) as u64),
                    helper_version: measured.version,
                    ..sentinel_link::session::TransportStats::default()
                }
            }));
        }
        let grip = Arc::clone(&handle);
        let dispatch = tracing::dispatcher::get_default(Clone::clone);
        let span = tracing::Span::current();
        let enrollment_file = link.enrollment_file.clone();
        let executor = executor(&config.data_dir, worker, link.git_mirrors);
        let tunnel = forward.clone();
        let watch = TunnelWatch::default();
        let thread = std::thread::Builder::new()
            .name("sentinel-worker-link".into())
            .spawn(move || {
                tracing::dispatcher::with_default(&dispatch, || {
                    span.in_scope(|| {
                        let outcome = sentinel_link::worker::run(
                            settings,
                            identity,
                            enrollment,
                            &*executor,
                            &grip,
                            &|event| match event {
                                sentinel_link::worker::Event::Connected { worker, enrolled } => {
                                    if enrolled && let Some(path) = &enrollment_file {
                                        // Spent: the secret is refused from now on
                                        // anyway, but a spent secret on disk invites
                                        // confusion at the next start.
                                        let _ = fs::remove_file(path);
                                    }
                                    watch.connected();
                                    tracing::info!(event = "link_connected", worker = %worker, enrolled);
                                }
                                sentinel_link::worker::Event::Disconnected(error) => {
                                    tracing::warn!(event = "link_lost", error = %error);
                                    if let Some(forward) = &tunnel && watch.lost() {
                                        tracing::warn!(
                                            event = "tailcat_replaced",
                                            sessions_failed = TUNNEL_SESSION_FAILURES,
                                            "no control session over the forward; replacing the helper"
                                        );
                                        forward.restart();
                                    }
                                }
                                sentinel_link::worker::Event::Backoff(wait) => {
                                    tracing::info!(event = "link_backoff", wait_ms = wait.as_millis() as u64);
                                }
                            },
                        );
                        if let Err(error) = outcome {
                            tracing::error!(event = "link_failed", error = %error, "the worker will not retry an unchanged hello; fix the configuration and restart");
                        }
                    })
                })
            })
            .map_err(|error| Error::runtime(format!("cannot start the link thread: {error}")))?;
        Ok(Running::Worker {
            handle,
            thread,
            tailcat: forward,
        })
    }
}

fn initialize_and_wait(
    role: &str,
    config: &Config,
    io: &Executor,
    startup: PhaseTimer,
    service_started: Instant,
) -> Result<(), Error> {
    // Register before initialization so shutdown requested during startup is retained.
    // Signal callbacks only enqueue; cleanup and reporting stay on the main thread.
    let (sender, receiver) = mpsc::sync_channel(1);
    let initialized = (|| {
        ctrlc::set_handler(move || {
            let _ = sender.try_send(());
        })
        .map_err(|error| Error::runtime(format!("cannot install shutdown handler: {error}")))?;
        let data_dir = config.data_dir.clone();
        bootstrap_work(io, move || fs::create_dir_all(data_dir))?
            .map_err(|error| Error::runtime(format!("cannot initialize data_dir: {error}")))?;
        match &config.role {
            #[cfg(feature = "server")]
            Role::Server {
                listen,
                api_listen,
                public_url,
                tailcat,
                remote_cache,
            } => start_server(
                config,
                *listen,
                *api_listen,
                public_url.clone(),
                tailcat.as_ref(),
                *remote_cache,
            ),
            #[cfg(feature = "worker")]
            Role::Worker(Some(link)) => worker_role::start(config, link),
            #[allow(unreachable_patterns)]
            _ => Ok(Running::Idle),
        }
    })();
    startup.finish(if initialized.is_ok() {
        Outcome::Completed
    } else {
        Outcome::Failed
    });
    let running = initialized?;

    tracing::info!(event = "service_initialized", data_dir = %config.data_dir.display(), service_startup_ns = elapsed_ns(service_started),
        "{role} initialized"
    );
    receiver
        .recv()
        .map_err(|_| Error::runtime("shutdown channel disconnected"))?;
    tracing::info!(event = "shutdown_requested", "{role} shutdown requested");
    match running {
        Running::Idle => Ok(()),
        #[cfg(feature = "server")]
        Running::Server {
            controller,
            api,
            maintenance,
            store,
            lane,
            poll,
            checks,
            reconcile,
            tailcat,
        } => {
            api.shutdown();
            maintenance.stop();
            if let Some(tailcat) = tailcat {
                tailcat.shutdown();
            }
            drop(reconcile);
            drop(checks);
            drop(poll);
            drop(lane);
            let sessions_drained = controller.shutdown(LINK_SHUTDOWN);
            let store_drained = matches!(
                Arc::try_unwrap(store)
                    .map(|store| store.shutdown(STORE_SHUTDOWN))
                    .map_err(|_| ()),
                Ok(sentinel_store::Shutdown::Drained)
            );
            tracing::info!(event = "link_stopped", sessions_drained, store_drained);
            if store_drained {
                Ok(())
            } else {
                Err(Error::runtime(
                    "the metadata store did not drain before its deadline",
                ))
            }
        }
        #[cfg(feature = "worker")]
        Running::Worker {
            handle,
            thread,
            tailcat,
        } => {
            handle.stop();
            let joined = thread.join().is_ok();
            if let Some(forward) = tailcat {
                forward.shutdown();
            }
            tracing::info!(event = "link_stopped", joined);
            Ok(())
        }
    }
}

#[cfg(all(test, feature = "worker"))]
mod worker_tests {
    use super::worker_role::{TUNNEL_SESSION_FAILURES, TunnelWatch};

    #[test]
    fn the_helper_is_replaced_only_after_consecutive_failed_sessions() {
        let watch = TunnelWatch::default();
        for _ in 1..TUNNEL_SESSION_FAILURES {
            assert!(!watch.lost());
        }
        // A welcomed session in between proves the forward carries the link.
        watch.connected();
        for _ in 1..TUNNEL_SESSION_FAILURES {
            assert!(!watch.lost());
        }
        assert!(
            watch.lost(),
            "the third failure in a row replaces the helper"
        );
        // Its successor gets the full allowance again.
        for _ in 1..TUNNEL_SESSION_FAILURES {
            assert!(!watch.lost());
        }
        assert!(watch.lost());
    }
}

#[cfg(all(test, feature = "server"))]
mod tests {
    use super::*;

    #[test]
    fn a_revoked_worker_loses_every_tailcat_key_and_an_unenrolled_one_keeps_it() {
        use sentinel_auth::secret::Secret;
        use sentinel_core::{PoolId, UnixMillis, WorkerId};
        use sentinel_link::tailcat::{Admission, NodeKey};
        use sentinel_protocol::negotiate::{Arch, Capabilities, Negotiated, ProtocolVersion};
        use sentinel_store::{auth::Authority, tenancy, workers};

        let dir = tempfile::tempdir().unwrap();
        let store = sentinel_store::Store::open(
            dir.path().join("metadata.sqlite"),
            sentinel_store::Durability::Normal,
        )
        .unwrap();
        let now = UnixMillis(1_000);
        let (pool, enrolled, pending) = (PoolId::new(), WorkerId::new(), WorkerId::new());
        store
            .writer()
            .write(move |tx| {
                tenancy::create_pool(
                    tx,
                    Authority::HostLocal,
                    pool,
                    "builders",
                    tenancy::PoolKind::Shared,
                    now,
                )?;
                let issued =
                    workers::issue_enrollment(tx, Authority::HostLocal, pool, 60_000, now)?;
                let mut text = String::new();
                issued.secret.expose(&mut text);
                workers::enroll(
                    tx,
                    &Secret::parse(&text).unwrap(),
                    workers::Presentation {
                        worker: enrolled,
                        fingerprint: Secret::generate().digest(),
                        name: "w",
                        negotiated: Negotiated {
                            protocol: ProtocolVersion(7),
                            capabilities: Capabilities::REQUIRED,
                            arch: Arch::X86_64,
                        },
                    },
                    now,
                )
                .map(|_| ())
            })
            .unwrap();
        let key =
            |digit: char| NodeKey::parse(&format!("nodekey:{}", digit.to_string().repeat(64)));
        let listed = [
            Admission {
                key: key('a').unwrap(),
                worker: enrolled,
            },
            Admission {
                key: key('b').unwrap(),
                worker: pending,
            },
            // The enrolled worker mid-rotation: its new key is listed beside
            // the old one until the old one is retired.
            Admission {
                key: key('c').unwrap(),
                worker: enrolled,
            },
        ];
        assert_eq!(
            admitted_keys(&store, &listed).unwrap(),
            vec![key('a').unwrap(), key('b').unwrap(), key('c').unwrap()]
        );
        store
            .writer()
            .write(move |tx| workers::revoke(tx, Authority::HostLocal, enrolled, UnixMillis(2_000)))
            .unwrap();
        assert_eq!(
            admitted_keys(&store, &listed).unwrap(),
            vec![key('b').unwrap()],
            "revoking the worker withdraws its tunnel keys, the rotated one too"
        );
    }

    fn resolve_ok(file: StorageFile) -> Storage {
        match file.resolve() {
            Ok(s) => s,
            Err(_) => panic!("storage config must resolve"),
        }
    }

    #[test]
    fn the_maintenance_tick_purges_idempotency_records_a_batch_at_a_time() {
        // P02-2: the tick used to leave every idempotency record forever.
        let dir = tempfile::tempdir().unwrap();
        let store = sentinel_store::Store::open(
            dir.path().join("m.sqlite"),
            sentinel_store::Durability::Normal,
        )
        .unwrap();
        let tenant = sentinel_core::TenantId::new();
        let now = sentinel_core::UnixMillis::now().0;
        store
            .writer()
            .write(move |tx| {
                sentinel_store::jobs::insert_tenant(tx, tenant, "acme", sentinel_core::UnixMillis(1))?;
                for (key, created) in [("a", 0), ("b", 0), ("c", 0), ("live", now)] {
                    tx.execute(
                        "INSERT INTO idempotency_keys(tenant_id, principal, route, key, fingerprint, created_ms)
                         VALUES (?1, 'p', 'r', ?2, zeroblob(16), ?3)",
                        (tenant.as_bytes().as_slice(), key, created),
                    )?;
                }
                Ok(())
            })
            .unwrap();
        let keys = || -> Vec<String> {
            store
                .read(|c| {
                    let mut stmt = c.prepare("SELECT key FROM idempotency_keys ORDER BY key")?;
                    let keys = stmt
                        .query_map([], |r| r.get(0))?
                        .collect::<Result<_, _>>()?;
                    Ok(keys)
                })
                .unwrap()
        };
        assert!(purge_expired(&store, 2), "a full batch means a backlog");
        assert_eq!(keys().len(), 2, "one tick removes at most one batch");
        assert!(!purge_expired(&store, 2));
        assert_eq!(keys(), ["live"]);
    }

    #[test]
    fn storage_defaults_and_validation() {
        let resolved = resolve_ok(StorageFile::default());
        assert_eq!(
            resolved.marks,
            sentinel_store::space::Watermarks {
                reserve: 1 << 30,
                low: 2 << 30,
                high: 4 << 30,
                floor: (1 << 30) / 8,
            }
        );
        assert_eq!(resolved.tenant_quota, 0);
        assert_eq!(resolved.log_retention_ms, 14 * 86_400_000);
        assert_eq!(resolved.sweep_interval_ms, 300_000);

        // reserve under 64 MiB, low under reserve, high under low: refused.
        for (reserve, low, high) in [
            (Some(1u64 << 20), None, None),
            (None, Some((1 << 30) - 1), None),
            (None, None, Some(1 << 30)),
        ] {
            let file = StorageFile {
                reserve_bytes: reserve,
                low_watermark_bytes: low,
                high_watermark_bytes: high,
                ..Default::default()
            };
            assert!(file.resolve().is_err(), "{reserve:?} {low:?} {high:?}");
        }
        // Sweep and retention bounds.
        for (sweep, retention) in [
            (Some(4u64), None),
            (Some(86_401), None),
            (None, Some(3_599)),
            (None, Some(31_536_001)),
        ] {
            let file = StorageFile {
                sweep_interval_secs: sweep,
                log_retention_secs: retention,
                ..Default::default()
            };
            assert!(file.resolve().is_err(), "{sweep:?} {retention:?}");
        }
        // A full override resolves.
        let file = StorageFile {
            reserve_bytes: Some(1 << 30),
            low_watermark_bytes: Some(2 << 30),
            high_watermark_bytes: Some(3 << 30),
            tenant_quota_bytes: Some(1 << 40),
            log_retention_secs: Some(7_200),
            sweep_interval_secs: Some(60),
        };
        let resolved = resolve_ok(file);
        assert_eq!(resolved.marks.high, 3 << 30);
        assert_eq!(resolved.tenant_quota, 1 << 40);
        assert_eq!(resolved.log_retention_ms, 7_200_000);
    }
}
