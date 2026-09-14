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
    // Worker: which controller to reach and how to trust it.
    controller: Option<String>,
    controller_fingerprint: Option<String>,
    worker_name: Option<String>,
    enrollment_file: Option<PathBuf>,
    cpu_millis: Option<u64>,
    memory_bytes: Option<u64>,
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
}

enum Role {
    Server {
        listen: SocketAddr,
        api_listen: SocketAddr,
    },
    Worker(Option<WorkerLink>),
}

struct Config {
    data_dir: PathBuf,
    log_format: LogFormat,
    log_level: LogLevel,
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
                        "invalid configuration: expected strict TOML with only data_dir, log_format, log_level and the role's link keys (no duplicate/unknown keys or invalid values)",
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
            {
                return Err(Error::config(
                    "controller, controller_fingerprint, worker_name, enrollment_file, cpu_millis and memory_bytes apply to the worker role only",
                ));
            }
            let listen = file
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
            Role::Server { listen, api_listen }
        } else {
            if file.listen.is_some() || file.api_listen.is_some() {
                return Err(Error::config(
                    "listen and api_listen apply to the server role only",
                ));
            }
            let link = match (file.controller, file.controller_fingerprint) {
                (None, None) => {
                    if file.worker_name.is_some()
                        || file.enrollment_file.is_some()
                        || file.cpu_millis.is_some()
                        || file.memory_bytes.is_some()
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
                    Some(WorkerLink {
                        controller,
                        fingerprint,
                        name,
                        enrollment_file: file.enrollment_file,
                        cpu_millis: file.cpu_millis,
                        memory_bytes: file.memory_bytes,
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
        Ok(Self {
            data_dir,
            log_format: args.log_format.or(file.log_format).unwrap_or_default(),
            log_level: args.log_level.or(file.log_level).unwrap_or_default(),
            role,
        })
    }

    fn describe(&self) -> String {
        match &self.role {
            Role::Server { listen, api_listen } => {
                format!("listen={listen} api_listen={api_listen}")
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
        println!(
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

/// What the running role holds until shutdown, drained in order.
enum Running {
    Idle,
    #[cfg(feature = "server")]
    Server {
        controller: sentinel_link::controller::Controller,
        api: sentinel_api::Server,
        store: Arc<sentinel_store::Store>,
    },
    #[cfg(feature = "worker")]
    Worker {
        handle: Arc<sentinel_link::worker::Handle>,
        thread: std::thread::JoinHandle<()>,
    },
}

#[cfg(feature = "server")]
fn start_server(
    config: &Config,
    listen: SocketAddr,
    api_listen: SocketAddr,
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
    let controller = sentinel_link::controller::Controller::start(
        Arc::clone(&store),
        Arc::clone(&logs),
        identity,
        listen,
    )
    .map_err(|error| Error::runtime(format!("cannot listen on {listen}: {error}")))?;
    let reconciled = controller.reconciled();
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
        controller: controller.handle(),
        sessions: sentinel_store::local_auth::Policy::default(),
    })
    .map_err(|error| Error::runtime(format!("cannot listen on {api_listen}: {error}")))?;
    tracing::info!(event = "api_listening", addr = %api.local_addr());
    Ok(Running::Server {
        controller,
        api,
        store,
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
    fn executor(data_dir: &Path, worker: sentinel_core::WorkerId) -> Box<dyn LinkExecutor> {
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
                })
            })
        };
        match sentinel_worker::executor::Executor::start(data_dir.to_path_buf(), worker, notify) {
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

    /// The worker's generated identifier, fixed on first start.
    fn worker_id(data_dir: &Path) -> Result<sentinel_core::WorkerId, Error> {
        let path = data_dir.join("worker.id");
        match fs::read_to_string(&path) {
            Ok(text) => text
                .trim()
                .parse()
                .map_err(|_| Error::runtime("worker.id is not a wrk_ identifier")),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
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
            Some(path) => match fs::read_to_string(path) {
                Ok(text) => Some(sentinel_auth::token::parse(text.trim()).ok_or_else(|| {
                    Error::runtime("enrollment_file does not hold an enrollment secret")
                })?),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
                Err(error) => {
                    return Err(Error::runtime(format!(
                        "cannot read enrollment_file: {error}"
                    )));
                }
            },
            None => None,
        };
        let capacity = capacity(link);
        let settings = sentinel_link::worker::Config {
            controller: link.controller,
            server: sentinel_auth::secret::Digest(link.fingerprint),
            worker,
            name: link.name.clone(),
            hello: sentinel_protocol::negotiate::Hello {
                protocol_min: sentinel_protocol::negotiate::ProtocolVersion(1),
                protocol_max: sentinel_protocol::negotiate::ProtocolVersion(1),
                capabilities: sentinel_protocol::negotiate::Capabilities::REQUIRED,
                arch: if cfg!(target_arch = "aarch64") {
                    sentinel_protocol::negotiate::Arch::Aarch64
                } else {
                    sentinel_protocol::negotiate::Arch::X86_64
                },
                software: format!("sentinel {}", env!("CARGO_PKG_VERSION")),
            },
            capacity,
        };
        tracing::info!(
            event = "link_configured",
            controller = %link.controller,
            worker = %worker,
            cpu_millis = capacity.cpu_millis,
            memory_bytes = capacity.memory_bytes,
            enrolling = enrollment.is_some()
        );
        let handle = Arc::new(sentinel_link::worker::Handle::new());
        let grip = Arc::clone(&handle);
        let dispatch = tracing::dispatcher::get_default(Clone::clone);
        let span = tracing::Span::current();
        let enrollment_file = link.enrollment_file.clone();
        let executor = executor(&config.data_dir, worker);
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
                                    tracing::info!(event = "link_connected", worker = %worker, enrolled);
                                }
                                sentinel_link::worker::Event::Disconnected(error) => {
                                    tracing::warn!(event = "link_lost", error = %error);
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
        Ok(Running::Worker { handle, thread })
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
            Role::Server { listen, api_listen } => start_server(config, *listen, *api_listen),
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
            store,
        } => {
            api.shutdown();
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
        Running::Worker { handle, thread } => {
            handle.stop();
            let joined = thread.join().is_ok();
            tracing::info!(event = "link_stopped", joined);
            Ok(())
        }
    }
}
