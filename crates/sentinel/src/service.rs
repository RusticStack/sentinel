use std::{
    fs::{self, File},
    io::Read,
    path::{Component, Path, PathBuf},
    sync::mpsc,
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
}

struct Config {
    data_dir: PathBuf,
    log_format: LogFormat,
    log_level: LogLevel,
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
                        "invalid configuration: expected strict TOML with only data_dir, log_format and log_level (no duplicate/unknown keys or invalid values)",
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
        Ok(Self {
            data_dir,
            log_format: args.log_format.or(file.log_format).unwrap_or_default(),
            log_level: args.log_level.or(file.log_level).unwrap_or_default(),
        })
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
            "{role} configuration valid; data_dir={}; log_format={:?}; log_level={:?}",
            config.data_dir.display(),
            config.log_format,
            config.log_level
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
            .map_err(|error| Error::runtime(format!("cannot initialize data_dir: {error}")))
    })();
    startup.finish(if initialized.is_ok() {
        Outcome::Completed
    } else {
        Outcome::Failed
    });
    initialized?;

    tracing::info!(event = "service_initialized", data_dir = %config.data_dir.display(), service_startup_ns = elapsed_ns(service_started),
        "{role} initialized; lifecycle only, CI services are not implemented"
    );
    receiver
        .recv()
        .map_err(|_| Error::runtime("shutdown channel disconnected"))?;
    // No jobs, listeners, or persistent writers exist yet. Their bounded drain/flush
    // operations must be added here as the corresponding subsystems are implemented.
    tracing::info!(event = "shutdown_requested", "{role} shutdown requested");
    Ok(())
}
