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
const DEFAULT_LISTEN: &str = "127.0.0.1:7443";
const DEFAULT_API_LISTEN: &str = "127.0.0.1:7080";
const MAX_TRUSTED_PROXIES: usize = 64;

#[cfg(feature = "server")]
fn trusted_proxy_valid(entry: &str) -> bool {
    sentinel_api::TrustedProxy::parse(entry).is_some()
}

#[cfg(not(feature = "server"))]
fn trusted_proxy_valid(_: &str) -> bool {
    true
}
#[cfg(feature = "server")]
const LINK_SHUTDOWN: Duration = Duration::from_secs(2);
#[cfg(feature = "server")]
const STORE_SHUTDOWN: Duration = Duration::from_secs(5);
#[cfg(feature = "worker")]
const WORKER_SHUTDOWN: Duration = Duration::from_secs(20);

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
    listen: Option<String>,
    api_listen: Option<String>,
    public_url: Option<String>,
    trusted_proxies: Option<Vec<String>>,
    placement_order: Option<String>,
    controller: Option<String>,
    controller_fingerprint: Option<String>,
    controller_fingerprint_also: Option<Vec<String>>,
    worker_name: Option<String>,
    enrollment_file: Option<PathBuf>,
    cpu_millis: Option<u64>,
    memory_bytes: Option<u64>,
    labels: Option<Vec<String>>,
    job_network: Option<String>,
    isolation: Option<String>,
    microvm: Option<MicrovmFile>,
    disk_bytes: Option<u64>,
    spool_reserve_bytes: Option<u64>,
    spool_quota_bytes: Option<u64>,
    cache_budget_bytes: Option<u64>,
    mirror_budget_bytes: Option<u64>,
    image_budget_bytes: Option<u64>,
    git_mirrors: Option<bool>,
    metrics_listen: Option<String>,
    storage: Option<StorageFile>,
    tailcat: Option<TailcatFile>,
    remote_cache: Option<RemoteCacheFile>,
    s3: Option<S3File>,
    backup: Option<BackupFile>,
    mail: Option<MailFile>,
    worker_bootstrap: Option<WorkerBootstrapFile>,
    tailcat_address: Option<String>,
}

/// The microVM executor's setup (plan 16.8): Firecracker, the pinned guest kernel, the static guest agent.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct MicrovmFile {
    firecracker: PathBuf,
    kernel: PathBuf,
    agent: PathBuf,
}

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

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RemoteCacheFile {
    enabled: Option<bool>,
    budget_bytes: Option<u64>,
}

impl RemoteCacheFile {
    fn on(&self) -> bool {
        self.enabled.unwrap_or(true)
    }
}

#[cfg_attr(not(feature = "server"), allow(dead_code))]
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct S3File {
    endpoint: String,
    region: String,
    bucket: String,
    #[serde(default)]
    prefix: String,
    #[serde(default)]
    path_style: bool,
    ca_file: Option<PathBuf>,
    credentials_file: PathBuf,
    part_bytes: Option<u64>,
    local_bytes: Option<u64>,
    backlog_bytes: Option<u64>,
}

impl S3File {
    const MIB: u64 = 1 << 20;

    fn check(&self) -> Result<(), Error> {
        if !self.credentials_file.is_absolute()
            || self.ca_file.as_ref().is_some_and(|p| !p.is_absolute())
        {
            return Err(Error::config(
                "[s3] credentials_file and ca_file must be absolute paths",
            ));
        }
        if self
            .part_bytes
            .is_some_and(|p| !(5 * Self::MIB..=512 * Self::MIB).contains(&p))
        {
            return Err(Error::config("[s3] part_bytes must be 5 MiB..=512 MiB"));
        }
        if self.backlog_bytes == Some(0) {
            return Err(Error::config(
                "[s3] backlog_bytes must be positive when set: 0 would refuse every artifact",
            ));
        }
        if self.endpoint.is_empty() || self.region.is_empty() || self.bucket.is_empty() {
            return Err(Error::config("[s3] needs endpoint, region and bucket"));
        }
        Ok(())
    }
}

#[derive(Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct MailFile {
    api_key_file: Option<PathBuf>,
    from: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct MailSettings {
    api_key_file: PathBuf,
    from: String,
}

impl MailFile {
    fn resolve(self, env: &dyn Fn(&str) -> Option<String>) -> Result<Option<MailSettings>, Error> {
        let set = |name: &str| env(name).filter(|value| !value.is_empty());
        let key_file = set("SENTINEL_RESEND_API_KEY_FILE")
            .map(PathBuf::from)
            .or(self.api_key_file);
        let from = set("SENTINEL_EMAIL_FROM").or(self.from);
        let (key_file, from) = match (key_file, from) {
            (None, None) => return Ok(None),
            (Some(key_file), Some(from)) => (key_file, from),
            _ => {
                return Err(Error::config(
                    "email delivery needs both the Resend API key file and the sender \
                     (SENTINEL_RESEND_API_KEY_FILE and SENTINEL_EMAIL_FROM)",
                ));
            }
        };
        if !key_file.is_absolute() {
            return Err(Error::config(
                "the Resend API key file must be an absolute path",
            ));
        }
        let from_ok =
            from.len() <= 320 && from.contains('@') && !from.chars().any(char::is_control);
        if !from_ok {
            return Err(Error::config(
                "the sender must be `ci@example.com` or `Sentinel <ci@example.com>`",
            ));
        }
        #[cfg(feature = "server")]
        sentinel_mail::Sender::parse(&from).map_err(Error::config)?;
        Ok(Some(MailSettings {
            api_key_file: key_file,
            from,
        }))
    }
}

/// What the controller's worker-enrollment bootstrap script pins: where workers dial, where the release lives and
/// its V01 `SHA256SUMS`, and (for Tailcat enrollments) the pinned helper builds. Server role only.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkerBootstrapFile {
    /// IP address and port workers dial for a direct TLS enrollment (the link listener as workers reach it).
    controller: String,
    /// Directory URL holding the release archives.
    release_url: String,
    /// The release's `SHA256SUMS` file.
    release_sums: PathBuf,
    /// HTTPS base URL workers redeem their enrollment at (`https://`, or `http://` on a loopback host).
    /// Without it the generated script keeps the older flow, in which the secret rides the worker's
    /// first link hello and a Tailcat key is authorized by an administrator.
    api_url: Option<String>,
    tailcat: Option<BootstrapTailcatFile>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct BootstrapTailcatFile {
    /// Defaults to the helper version this build pins.
    version: Option<String>,
    x86_64_url: Option<String>,
    /// Defaults to the pinned build's digest.
    x86_64_sha256: Option<String>,
    aarch64_url: Option<String>,
    aarch64_sha256: Option<String>,
}

impl WorkerBootstrapFile {
    fn check(&self, server_tailcat: Option<&TailcatFile>) -> Result<(), Error> {
        if self.controller.parse::<SocketAddr>().is_err() {
            return Err(Error::config(
                "[worker_bootstrap] controller must be an IP address and port, as in 10.0.0.5:7443",
            ));
        }
        if !self.release_sums.is_absolute() {
            return Err(Error::config(
                "[worker_bootstrap] release_sums must be an absolute path",
            ));
        }
        if let Some(url) = &self.api_url
            && !(url.starts_with("https://") || url.starts_with("http://"))
        {
            return Err(Error::config(
                "[worker_bootstrap] api_url must be an https:// URL (http:// only for a loopback host)",
            ));
        }
        if let Some(tailcat) = &self.tailcat {
            if !server_tailcat.is_some_and(|t| t.enabled == Some(true)) {
                return Err(Error::config(
                    "[worker_bootstrap.tailcat] needs the controller's own [tailcat] enabled = true: the generated script hands workers its address",
                ));
            }
            if tailcat.x86_64_url.is_none() && tailcat.aarch64_url.is_none() {
                return Err(Error::config(
                    "[worker_bootstrap.tailcat] needs x86_64_url or aarch64_url",
                ));
            }
            if tailcat.aarch64_url.is_some() != tailcat.aarch64_sha256.is_some() {
                return Err(Error::config(
                    "[worker_bootstrap.tailcat] aarch64_url and aarch64_sha256 are set together: this build pins no arm64 helper digest",
                ));
            }
            if tailcat.x86_64_url.is_none() && tailcat.x86_64_sha256.is_some() {
                return Err(Error::config(
                    "[worker_bootstrap.tailcat] x86_64_sha256 needs x86_64_url",
                ));
            }
        }
        Ok(())
    }

    #[cfg(feature = "server")]
    fn build(
        &self,
        data_dir: &Path,
        fingerprint: &str,
        server_tailcat: Option<&TailcatFile>,
    ) -> Result<sentinel_api::WorkerBootstrap, Error> {
        let sums = sentinel::bounded::text(&self.release_sums, 1 << 20).map_err(|error| {
            Error::config(format!(
                "cannot read [worker_bootstrap] release_sums {}: {error}",
                self.release_sums.display()
            ))
        })?;
        let tailcat = self.tailcat.as_ref().map(|t| {
            let pin = |url: &Option<String>, sha256: Option<String>| {
                url.clone().map(|url| sentinel_api::Pin {
                    url,
                    sha256: sha256.unwrap_or_default(),
                })
            };
            sentinel_api::TailcatRelease {
                version: t
                    .version
                    .clone()
                    .unwrap_or_else(|| sentinel_link::tailcat::PINNED_VERSION.to_owned()),
                x86_64: pin(
                    &t.x86_64_url,
                    Some(
                        t.x86_64_sha256
                            .clone()
                            .unwrap_or_else(|| sentinel_link::tailcat::PINNED_SHA256.to_owned()),
                    ),
                ),
                aarch64: pin(&t.aarch64_url, t.aarch64_sha256.clone()),
                derpmap_url: server_tailcat.and_then(|s| s.derpmap_url.clone()),
                region: server_tailcat.and_then(|s| s.region.clone()),
            }
        });
        sentinel_api::WorkerBootstrap::new(sentinel_api::WorkerBootstrapSettings {
            controller: self
                .controller
                .parse()
                .map_err(|_| Error::config("[worker_bootstrap] controller is not an address"))?,
            fingerprint: fingerprint.to_owned(),
            release_url: self.release_url.clone(),
            release_sums: sums,
            tailcat_address_file: tailcat.is_some().then(|| {
                data_dir
                    .join("tailcat")
                    .join(sentinel_link::tailcat::ADDRESS_FILE)
            }),
            tailcat,
            api_url: self.api_url.clone(),
        })
        .map_err(|error| Error::config(format!("[worker_bootstrap] {error}")))
    }
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct BackupFile {
    dir: PathBuf,
    interval_secs: Option<u64>,
    keep: Option<usize>,
}

impl BackupFile {
    fn check(&self, data_dir: &Path) -> Result<(), Error> {
        if !self.dir.is_absolute() {
            return Err(Error::config("[backup] dir must be an absolute path"));
        }
        if self.dir.starts_with(data_dir) || data_dir.starts_with(&self.dir) {
            return Err(Error::config(
                "[backup] dir must be outside data_dir (and not contain it): a backup on the disk it protects protects nothing",
            ));
        }
        if self
            .interval_secs
            .is_some_and(|s| !(300..=7 * 86_400).contains(&s))
        {
            return Err(Error::config("[backup] interval_secs must be 300..=604800"));
        }
        if self.keep.is_some_and(|k| !(1..=1_000).contains(&k)) {
            return Err(Error::config("[backup] keep must be 1..=1000"));
        }
        Ok(())
    }
}

fn valid_label(label: &str) -> bool {
    !label.is_empty() && label.len() <= 128 && !label.chars().any(char::is_control)
}

const EGRESS_LABEL: &str = "egress";
const MAX_LABELS: usize = 16;

#[cfg_attr(not(feature = "server"), allow(dead_code))]
#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct StorageFile {
    reserve_bytes: Option<u64>,
    low_watermark_bytes: Option<u64>,
    high_watermark_bytes: Option<u64>,
    quota_bytes: Option<u64>,
    tenant_quota_bytes: Option<u64>,
    log_retention_secs: Option<u64>,
    artifact_retention_secs: Option<u64>,
    run_artifact_bytes: Option<u64>,
    attempt_log_bytes: Option<u64>,
    sweep_interval_secs: Option<u64>,
}

#[cfg(feature = "server")]
#[derive(Clone, Copy)]
struct Storage {
    reserve: Option<u64>,
    low: Option<u64>,
    high: Option<u64>,
    deployment: sentinel_store::retention::Deployment,
    attempt_log_bytes: u64,
    sweep_interval_ms: i64,
}

#[cfg(feature = "server")]
const MIB: u64 = 1 << 20;

#[cfg(feature = "server")]
impl Storage {
    fn marks(&self, total: u64) -> Result<sentinel_store::space::Watermarks, Error> {
        let sized = sentinel_store::space::default_watermarks(total);
        let reserve = self.reserve.unwrap_or(sized.reserve);
        let low = self.low.unwrap_or(sized.low);
        let high = self.high.unwrap_or(sized.high.max(low));
        if reserve < 64 * MIB || low < reserve || high < low {
            return Err(Error::config(
                "storage watermarks must satisfy 64 MiB <= reserve_bytes <= low_watermark_bytes <= high_watermark_bytes",
            ));
        }
        Ok(sentinel_store::space::Watermarks {
            reserve,
            low,
            high,
            floor: reserve / 8,
        })
    }
}

#[cfg(feature = "server")]
impl StorageFile {
    fn resolve(&self) -> Result<Storage, Error> {
        let defaults = sentinel_store::retention::Deployment::default();
        let log_retention_secs = self.log_retention_secs.unwrap_or(14 * 86_400);
        let artifact_retention_secs = self.artifact_retention_secs.unwrap_or(90 * 86_400);
        let sweep_interval_secs = self.sweep_interval_secs.unwrap_or(300);
        let run_artifact_bytes = self
            .run_artifact_bytes
            .unwrap_or(defaults.run_artifact_bytes);
        let attempt_log_bytes = self
            .attempt_log_bytes
            .unwrap_or(sentinel_store::logs::MAX_LOG_BYTES);
        if self.reserve_bytes.is_some_and(|r| r < 64 * MIB)
            || matches!((self.reserve_bytes, self.low_watermark_bytes), (Some(r), Some(l)) if l < r)
            || matches!((self.low_watermark_bytes, self.high_watermark_bytes), (Some(l), Some(h)) if h < l)
        {
            return Err(Error::config(
                "storage watermarks must satisfy 64 MiB <= reserve_bytes <= low_watermark_bytes <= high_watermark_bytes",
            ));
        }
        if !(5..=86_400).contains(&sweep_interval_secs)
            || !(3_600..=86_400 * 366).contains(&log_retention_secs)
            || !(3_600..=86_400 * 366).contains(&artifact_retention_secs)
        {
            return Err(Error::config(
                "storage sweep_interval_secs must be 5..=86400 and log_retention_secs and artifact_retention_secs 3600..=31622400",
            ));
        }
        if !(MIB..=1 << 40).contains(&run_artifact_bytes)
            || !(MIB..=4 << 30).contains(&attempt_log_bytes)
        {
            return Err(Error::config(
                "storage run_artifact_bytes must be 1 MiB..=1 TiB and attempt_log_bytes 1 MiB..=4 GiB",
            ));
        }
        if [self.quota_bytes, self.tenant_quota_bytes]
            .into_iter()
            .flatten()
            .any(|q| q > i64::MAX as u64)
        {
            return Err(Error::config("storage quotas must fit in 63 bits"));
        }
        Ok(Storage {
            reserve: self.reserve_bytes,
            low: self.low_watermark_bytes,
            high: self.high_watermark_bytes,
            deployment: sentinel_store::retention::Deployment {
                quota_bytes: self.quota_bytes.unwrap_or(0),
                tenant_quota_bytes: self.tenant_quota_bytes.unwrap_or(0),
                log_retention_ms: (log_retention_secs * 1000) as i64,
                artifact_retention_ms: (artifact_retention_secs * 1000) as i64,
                run_artifact_bytes,
            },
            attempt_log_bytes,
            sweep_interval_ms: (sweep_interval_secs * 1000) as i64,
        })
    }
}

/// `[microvm]` as the worker reads it; turned into the executor's setup where it is Linux-only.
#[cfg_attr(not(feature = "worker"), allow(dead_code))]
#[derive(Clone)]
struct MicrovmSetup {
    firecracker: PathBuf,
    kernel: PathBuf,
    agent: PathBuf,
}

#[derive(Clone, Copy, PartialEq)]
enum NetworkSetting {
    None,
    Egress,
}

#[derive(Clone, Copy)]
enum IsolationSetting {
    Auto,
    Container,
    Microvm,
}

impl IsolationSetting {
    fn parse(text: &str) -> Option<Self> {
        match text {
            "auto" => Some(Self::Auto),
            "container" => Some(Self::Container),
            "microvm" => Some(Self::Microvm),
            _ => None,
        }
    }
}

#[cfg_attr(not(feature = "worker"), allow(dead_code))]
#[derive(Clone)]
struct WorkerLink {
    controller: SocketAddr,
    fingerprint: [u8; 32],
    also_fingerprints: Vec<[u8; 32]>,
    name: String,
    enrollment_file: Option<PathBuf>,
    cpu_millis: Option<u64>,
    memory_bytes: Option<u64>,
    git_mirrors: bool,
    labels: Vec<String>,
    job_network: NetworkSetting,
    isolation: IsolationSetting,
    microvm: Option<MicrovmSetup>,
    disk_bytes: Option<u64>,
    spool_reserve_bytes: Option<u64>,
    spool_quota_bytes: Option<u64>,
    budgets: [Option<u64>; 3],
    tailcat: Option<TailcatFile>,
    tailcat_address: Option<String>,
    remote_cache: bool,
    metrics_listen: Option<SocketAddr>,
}

// One value per process, built once: the size difference costs nothing, and boxing either side only moves the lint.
#[cfg_attr(not(feature = "server"), allow(dead_code))]
#[allow(clippy::large_enum_variant)]
enum Role {
    Server {
        listen: SocketAddr,
        api_listen: SocketAddr,
        public_url: Option<String>,
        trusted_proxies: Option<Vec<String>>,
        tailcat: Option<TailcatFile>,
        remote_cache: bool,
        remote_cache_budget: Option<u64>,
        /// `placement_order = "priority"`: the operator's host priority orders free workers ahead of
        /// speed (after hard admission). `false` is the default, fastest eligible first.
        priority_placement: bool,
    },
    Worker(Option<WorkerLink>),
}

struct Config {
    data_dir: PathBuf,
    log_format: LogFormat,
    log_level: LogLevel,
    #[cfg(feature = "server")]
    storage: Storage,
    #[cfg(feature = "server")]
    s3: Option<S3File>,
    #[cfg(feature = "server")]
    backup: Option<BackupFile>,
    #[cfg(feature = "server")]
    worker_bootstrap: Option<WorkerBootstrapFile>,
    #[cfg(feature = "server")]
    mail: Option<MailSettings>,
    #[cfg(feature = "server")]
    auto_join: sentinel_store::auto_join::Parsed,
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

/// Reads the auto-join variable's value: unset is no rules, a non-Unicode value is a startup
/// error (it must not silently turn the rules off), and the message never echoes the value.
#[cfg(feature = "server")]
fn auto_join_from_env(
    value: Result<String, std::env::VarError>,
) -> Result<sentinel_store::auto_join::Parsed, Error> {
    match value {
        Ok(text) => Ok(sentinel_store::auto_join::parse(&text)),
        Err(std::env::VarError::NotPresent) => Ok(sentinel_store::auto_join::Parsed::default()),
        Err(std::env::VarError::NotUnicode(_)) => Err(Error::config(
            "SENTINEL_AUTO_JOIN_DOMAINS is not valid Unicode; fix or unset it",
        )),
    }
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
                || file.controller_fingerprint_also.is_some()
                || file.worker_name.is_some()
                || file.enrollment_file.is_some()
                || file.cpu_millis.is_some()
                || file.memory_bytes.is_some()
                || file.git_mirrors.is_some()
                || file.labels.is_some()
                || file.job_network.is_some()
                || file.isolation.is_some()
                || file.microvm.is_some()
                || file.disk_bytes.is_some()
                || file.spool_reserve_bytes.is_some()
                || file.spool_quota_bytes.is_some()
                || file.cache_budget_bytes.is_some()
                || file.mirror_budget_bytes.is_some()
                || file.image_budget_bytes.is_some()
                || file.tailcat_address.is_some()
                || file.metrics_listen.is_some()
            {
                return Err(Error::config(
                    "controller, controller_fingerprint, controller_fingerprint_also, worker_name, enrollment_file, cpu_millis, memory_bytes, git_mirrors, labels, job_network, isolation, microvm, disk_bytes, spool_reserve_bytes, spool_quota_bytes, cache_budget_bytes, mirror_budget_bytes, image_budget_bytes, tailcat_address and metrics_listen apply to the worker role only",
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
            let trusted_proxies = file.trusted_proxies;
            if let Some(proxies) = &trusted_proxies
                && (proxies.len() > MAX_TRUSTED_PROXIES
                    || proxies.iter().any(|proxy| !trusted_proxy_valid(proxy)))
            {
                return Err(Error::config(
                    "trusted_proxies must list at most 64 IP addresses or CIDR networks with zero host bits, as in [\"127.0.0.1\", \"10.0.0.0/24\"]",
                ));
            }
            let priority_placement = match file.placement_order.as_deref() {
                None | Some("fastest") => false,
                Some("priority") => true,
                Some(_) => {
                    return Err(Error::config(
                        "placement_order must be \"fastest\" (the default) or \"priority\"",
                    ));
                }
            };
            Role::Server {
                listen,
                api_listen,
                public_url,
                trusted_proxies,
                priority_placement,
                tailcat: file.tailcat,
                remote_cache: file
                    .remote_cache
                    .as_ref()
                    .map(RemoteCacheFile::on)
                    .unwrap_or(true),
                remote_cache_budget: match file.remote_cache.as_ref().and_then(|r| r.budget_bytes) {
                    Some(bytes) if bytes < (64 << 20) => {
                        return Err(Error::config(
                            "[remote_cache] budget_bytes must be at least 64 MiB when set",
                        ));
                    }
                    budget => budget,
                },
            }
        } else {
            if file
                .remote_cache
                .as_ref()
                .is_some_and(|r| r.budget_bytes.is_some())
            {
                return Err(Error::config(
                    "[remote_cache] budget_bytes applies to the server role only",
                ));
            }
            if file.listen.is_some()
                || file.api_listen.is_some()
                || file.public_url.is_some()
                || file.trusted_proxies.is_some()
                || file.placement_order.is_some()
            {
                return Err(Error::config(
                    "listen, api_listen, public_url, trusted_proxies and placement_order apply to the server role only",
                ));
            }
            let link = match (file.controller, file.controller_fingerprint) {
                (None, None) => {
                    if file.controller_fingerprint_also.is_some()
                        || file.worker_name.is_some()
                        || file.enrollment_file.is_some()
                        || file.cpu_millis.is_some()
                        || file.memory_bytes.is_some()
                        || file.git_mirrors.is_some()
                        || file.labels.is_some()
                        || file.job_network.is_some()
                        || file.isolation.is_some()
                        || file.microvm.is_some()
                        || file.disk_bytes.is_some()
                        || file.spool_reserve_bytes.is_some()
                        || file.spool_quota_bytes.is_some()
                        || file.tailcat.is_some()
                        || file.tailcat_address.is_some()
                        || file.remote_cache.is_some()
                        || file.metrics_listen.is_some()
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
                    let also = file.controller_fingerprint_also.unwrap_or_default();
                    if also.len() >= sentinel_link::tls::MAX_PINS {
                        return Err(Error::config(
                            "controller_fingerprint_also lists too many fingerprints (at most 3)",
                        ));
                    }
                    let also_fingerprints = also
                        .iter()
                        .map(|text| parse_hex32(text))
                        .collect::<Option<Vec<_>>>()
                        .ok_or_else(|| {
                            Error::config(
                                "controller_fingerprint_also entries must be 64 lower-case hex characters",
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
                    let mut labels = file.labels.unwrap_or_default();
                    if labels.len() > MAX_LABELS || !labels.iter().all(|label| valid_label(label)) {
                        return Err(Error::config(
                            "labels must be at most 16 entries of 1-128 bytes without control characters",
                        ));
                    }
                    let job_network = match file.job_network.as_deref() {
                        None | Some("none") => NetworkSetting::None,
                        Some("egress") => NetworkSetting::Egress,
                        Some(_) => {
                            return Err(Error::config(
                                "job_network must be \"none\" or \"egress\"",
                            ));
                        }
                    };
                    // Advertised, so a pipeline that needs the network selects it with `runs_on.labels: [egress]`.
                    if job_network == NetworkSetting::Egress
                        && !labels.iter().any(|label| label == EGRESS_LABEL)
                    {
                        if labels.len() == MAX_LABELS {
                            return Err(Error::config(
                                "job_network = \"egress\" adds the egress label, and labels already holds 16",
                            ));
                        }
                        labels.push(EGRESS_LABEL.to_owned());
                    }
                    let isolation = match file.isolation.as_deref() {
                        None => IsolationSetting::Auto,
                        Some(text) => IsolationSetting::parse(text).ok_or_else(|| {
                            Error::config(
                                "isolation must be \"auto\", \"container\" or \"microvm\"",
                            )
                        })?,
                    };
                    if file.disk_bytes == Some(0) {
                        return Err(Error::config("disk_bytes must be positive when set"));
                    }
                    if [
                        file.cache_budget_bytes,
                        file.mirror_budget_bytes,
                        file.image_budget_bytes,
                    ]
                    .into_iter()
                    .flatten()
                    .any(|b| b < (64 << 20))
                    {
                        return Err(Error::config(
                            "cache_budget_bytes, mirror_budget_bytes and image_budget_bytes must be at least 64 MiB when set",
                        ));
                    }
                    if file.spool_quota_bytes == Some(0) {
                        return Err(Error::config(
                            "spool_quota_bytes must be positive when set: a zero quota would declare every line of output lost",
                        ));
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
                    let metrics_listen = file
                        .metrics_listen
                        .as_deref()
                        .map(|text| {
                            text.parse::<SocketAddr>()
                                .ok()
                                .filter(|a| a.ip().is_loopback())
                                .ok_or_else(|| {
                                    Error::config(
                                        "metrics_listen must be a loopback address and port, as in 127.0.0.1:9464",
                                    )
                                })
                        })
                        .transpose()?;
                    if tailcat_on && file.tailcat_address.is_none() {
                        return Err(Error::config(
                            "tailcat_address is required when [tailcat] is enabled: it is the controller's tc… address from its <data_dir>/tailcat/address file",
                        ));
                    }
                    Some(WorkerLink {
                        controller,
                        fingerprint,
                        also_fingerprints,
                        name,
                        enrollment_file: file.enrollment_file,
                        cpu_millis: file.cpu_millis,
                        memory_bytes: file.memory_bytes,
                        git_mirrors: file.git_mirrors.unwrap_or(true),
                        labels,
                        job_network,
                        isolation,
                        microvm: file.microvm.map(|m| MicrovmSetup {
                            firecracker: m.firecracker,
                            kernel: m.kernel,
                            agent: m.agent,
                        }),
                        disk_bytes: file.disk_bytes,
                        spool_reserve_bytes: file.spool_reserve_bytes,
                        spool_quota_bytes: file.spool_quota_bytes,
                        budgets: [
                            file.cache_budget_bytes,
                            file.mirror_budget_bytes,
                            file.image_budget_bytes,
                        ],
                        tailcat: file.tailcat,
                        tailcat_address: file.tailcat_address,
                        remote_cache: file
                            .remote_cache
                            .as_ref()
                            .map(RemoteCacheFile::on)
                            .unwrap_or(true),
                        metrics_listen,
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
        if let Some(s3) = &file.s3 {
            if matches!(role, Role::Worker(_)) {
                return Err(Error::config("[s3] applies to the server role only"));
            }
            s3.check()?;
        }
        if let Some(backup) = &file.backup {
            if matches!(role, Role::Worker(_)) {
                return Err(Error::config("[backup] applies to the server role only"));
            }
            backup.check(&data_dir)?;
        }
        if let Some(bootstrap) = &file.worker_bootstrap {
            let Role::Server { tailcat, .. } = &role else {
                return Err(Error::config(
                    "[worker_bootstrap] applies to the server role only",
                ));
            };
            bootstrap.check(tailcat.as_ref())?;
        }
        let mail = match &role {
            Role::Server { public_url, .. } => {
                let mail = file
                    .mail
                    .unwrap_or_default()
                    .resolve(&|name| std::env::var(name).ok())?;
                if mail.is_some() && public_url.is_none() {
                    return Err(Error::config(
                        "email delivery needs public_url: the links in messages are built on it",
                    ));
                }
                mail
            }
            Role::Worker(_) => {
                if file.mail.is_some() {
                    return Err(Error::config("[mail] applies to the server role only"));
                }
                None
            }
        };
        #[cfg(not(feature = "server"))]
        let _ = mail;
        #[cfg(feature = "server")]
        let auto_join = match &role {
            Role::Server { .. } => auto_join_from_env(std::env::var("SENTINEL_AUTO_JOIN_DOMAINS"))?,
            Role::Worker(_) => sentinel_store::auto_join::Parsed::default(),
        };
        Ok(Self {
            data_dir,
            log_format: args.log_format.or(file.log_format).unwrap_or_default(),
            log_level: args.log_level.or(file.log_level).unwrap_or_default(),
            #[cfg(feature = "server")]
            storage,
            #[cfg(feature = "server")]
            s3: file.s3,
            #[cfg(feature = "server")]
            backup: file.backup,
            #[cfg(feature = "server")]
            worker_bootstrap: file.worker_bootstrap,
            #[cfg(feature = "server")]
            mail,
            #[cfg(feature = "server")]
            auto_join,
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

#[cfg(target_os = "linux")]
fn keep_memory_out_of_dumps() {
    let none = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: plain syscalls on this process with a valid, owned argument;
    // lowering a limit and clearing the dumpable flag need no privilege.
    unsafe {
        libc::setrlimit(libc::RLIMIT_CORE, &none);
        libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
    }
}

pub fn run(role: &str, args: ServiceArgs) -> Result<(), Error> {
    #[cfg(target_os = "linux")]
    if !args.check {
        keep_memory_out_of_dumps();
    }
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
    if !diagnostics.shutdown(Duration::from_millis(500)) || diagnostics.losses().io_errors > 0 {
        result = Err(Error::runtime("diagnostic output is incomplete"));
    }
    if let Err(error) = &mut result {
        error.reported = true;
    }
    result
}

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

fn tailcat_address(link: &WorkerLink) -> Result<sentinel_link::tailcat::Address, Error> {
    let text = link
        .tailcat_address
        .as_deref()
        .ok_or_else(|| Error::config("tailcat_address is required when tailcat is enabled"))?;
    sentinel_link::tailcat::Address::parse(text).ok_or_else(|| {
        Error::config("tailcat_address must be a tailcat address, as in tc<20+ characters>")
    })
}

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

/// The checks `sentinel worker --check` runs, plus the host's runtime: the configuration must load and the
/// isolation it names must be possible here. Enrollment runs it before it spends the enrollment secret.
#[cfg(feature = "worker")]
pub(crate) fn check_worker(config: PathBuf, data_dir: PathBuf) -> Result<(), Error> {
    let args = ServiceArgs {
        config: Some(config),
        data_dir: Some(data_dir),
        check: true,
        log_format: None,
        log_level: None,
    };
    let mut io = Executor::new(WorkClass::BlockingIo, 1)
        .map_err(|error| Error::runtime(format!("cannot start I/O lane: {error}")))?;
    let mut cpu = Executor::new(WorkClass::Cpu, 1)
        .map_err(|error| Error::runtime(format!("cannot start CPU lane: {error}")))?;
    let loaded = Config::load("worker", &args, &io, &cpu);
    io.shutdown(Duration::from_secs(1));
    cpu.shutdown(Duration::from_secs(1));
    let loaded = loaded?;
    let Role::Worker(Some(link)) = &loaded.role else {
        return Err(Error::config(
            "the worker configuration names no controller",
        ));
    };
    worker_role::check_runtime(link)
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

fn create_data_dir(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(path)?;
        if fs::metadata(path)?.permissions().mode() & 0o077 != 0 {
            tracing::warn!(
                event = "data_dir_permissive",
                "the data directory is open to other accounts; restrict it to its owner (chmod 700)"
            );
        }
        Ok(())
    }
    #[cfg(not(unix))]
    fs::create_dir_all(path)
}

#[cfg(feature = "server")]
fn master_key(
    data_dir: &Path,
    store: &sentinel_store::Store,
) -> Result<Option<Arc<sentinel_auth::sealed::Key>>, Error> {
    let path = data_dir.join(sentinel_store::MASTER_KEY_FILE);
    let missing = matches!(
        fs::symlink_metadata(&path),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound
    );
    if missing {
        let sealed = store
            .read(sentinel_store::reseal::sealed_rows_exist)
            .map_err(|error| Error::runtime(format!("cannot inspect sealed values: {error}")))?;
        if sealed {
            return Err(Error::config(format!(
                "{} is missing, but the database holds sealed secrets, second factors or source credentials; restore the key file that matches this database",
                path.display()
            )));
        }
        return Ok(None);
    }
    let key = sentinel_auth::sealed::Key::load(&path).map_err(|error| {
        let reason = match error {
            sentinel_auth::sealed::SealError::Key(reason) => reason,
            sentinel_auth::sealed::SealError::Unsealable => "invalid key file",
        };
        Error::config(format!("cannot load {}: {reason}", path.display()))
    })?;
    store
        .read(|conn| sentinel_store::reseal::verify_key(conn, &key))
        .map_err(|_| {
            Error::config(format!(
                "{} does not open the sealed values in this database; restore the key file that matches this database snapshot",
                path.display()
            ))
        })?;
    Ok(Some(Arc::new(key)))
}

fn identity(data_dir: &Path, stem: &str) -> Result<sentinel_link::identity::Identity, Error> {
    let (cert, key) = (
        data_dir.join(format!("{stem}.crt")),
        data_dir.join(format!("{stem}.key")),
    );
    use sentinel_link::identity::Origin;
    let (identity, origin) = sentinel_link::identity::Identity::load_or_generate(stem, &cert, &key)
        .map_err(|error| Error::runtime(format!("cannot load {stem} identity: {error}")))?;
    match origin {
        Origin::Loaded => {}
        Origin::Generated => tracing::info!(
            event = "identity_generated",
            stem,
            "{stem} identity generated"
        ),
        Origin::Recovered => tracing::warn!(
            event = "identity_recovered",
            stem,
            "a {stem} private key was found without its certificate, so a new identity was generated; enroll its new fingerprint"
        ),
    }
    Ok(identity)
}

#[allow(clippy::large_enum_variant)]
enum Running {
    Idle,
    #[cfg(feature = "server")]
    Server {
        controller: sentinel_link::controller::Controller,
        api: sentinel_api::Server,
        maintenance: Maintenance,
        store: Arc<sentinel_store::Store>,
        lane: Box<sentinel_intake::Lane>,
        poll: Box<sentinel_intake::Poll>,
        github_lanes: Arc<std::sync::Mutex<Option<GithubLanes>>>,
        mail: Option<Box<sentinel_mail::Lane>>,
        tailcat: Option<TailcatServer>,
        replicator: Option<sentinel::offload::Running>,
        backups: Option<(
            Arc<sentinel_store::backup::Scheduler>,
            std::thread::JoinHandle<()>,
        )>,
    },
    #[cfg(feature = "worker")]
    Worker {
        handle: Arc<sentinel_link::worker::Handle>,
        thread: std::thread::JoinHandle<()>,
        tailcat: Option<Arc<sentinel_link::tailcat::Forward>>,
        metrics: Arc<crate::worker_metrics::Metrics>,
    },
}

/// The lanes that act as the GitHub App: started at boot when an App is configured, or when a
/// one-click setup puts one in force. Fields drop in declaration order: members, reconcile,
/// then the check publisher.
#[cfg(feature = "server")]
struct GithubLanes {
    _members: Box<sentinel_checks::Members>,
    _reconcile: Box<sentinel_checks::Reconcile>,
    _checks: Box<sentinel_checks::Lane>,
}

#[cfg(feature = "server")]
impl GithubLanes {
    fn start(
        store: &Arc<sentinel_store::Store>,
        app: Arc<sentinel_github::app::App>,
        details_url: Option<String>,
        members: sentinel_checks::members::Config,
    ) -> GithubLanes {
        let reconcile_dispatch = tracing::dispatcher::get_default(Clone::clone);
        let reconcile = Box::new(sentinel_checks::Reconcile::start(
            Arc::clone(store),
            Arc::clone(&app),
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
        ));
        let members_dispatch = tracing::dispatcher::get_default(Clone::clone);
        let members = Box::new(sentinel_checks::Members::start(
            Arc::clone(store),
            Arc::clone(&app),
            members,
            move |notice| {
                tracing::dispatcher::with_default(&members_dispatch, || {
                    tracing::info!(event = "github_members_checked", outcome = %notice.outcome);
                });
            },
        ));
        let publisher =
            sentinel_checks::github::GithubChecks::new(Arc::clone(store), app, details_url);
        let dispatch = tracing::dispatcher::get_default(Clone::clone);
        let checks = Box::new(sentinel_checks::Lane::start(
            Arc::clone(store),
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
        ));
        GithubLanes {
            _members: members,
            _reconcile: reconcile,
            _checks: checks,
        }
    }
}

/// What wakes the node-key pass: the periodic tick still catches edits to the operator's allow-list file, but a
/// machine that redeems an enrollment is admitted at once.
#[cfg(feature = "server")]
enum Wake {
    Refresh,
    Stop,
}

#[cfg(feature = "server")]
struct TailcatServer {
    server: Arc<sentinel_link::tailcat::Server>,
    wake: mpsc::SyncSender<Wake>,
    refresher: std::thread::JoinHandle<()>,
}

#[cfg(feature = "server")]
impl TailcatServer {
    /// Run the node-key pass now. A pass already queued covers this request too.
    fn refresh_now(&self) -> sentinel_api::Notify {
        let wake = self.wake.clone();
        sentinel_api::Notify(Arc::new(move || {
            let _ = wake.try_send(Wake::Refresh);
        }))
    }

    fn shutdown(self) {
        let _ = self.wake.send(Wake::Stop);
        let _ = self.refresher.join();
        self.server.shutdown();
    }
}

#[cfg(feature = "server")]
const TAILCAT_ALLOW_REFRESH: Duration = Duration::from_secs(10);

/// Every node key the controller's Tailcat helper admits: the allow-list file's lines for workers that
/// are not revoked, the bound key of every live worker, and the key authorized for each enrollment
/// that can still be redeemed (without it a new worker could not reach the controller to present its
/// secret). A worker revoked or uninstalled drops out of all three on the next pass.
#[cfg(feature = "server")]
fn admitted_keys(
    store: &sentinel_store::Store,
    listed: &[sentinel_link::tailcat::Admission],
) -> sentinel_store::Result<Vec<sentinel_link::tailcat::NodeKey>> {
    admitted_keys_at(store, listed, sentinel_core::UnixMillis::now())
}

#[cfg(feature = "server")]
fn admitted_keys_at(
    store: &sentinel_store::Store,
    listed: &[sentinel_link::tailcat::Admission],
    now: sentinel_core::UnixMillis,
) -> sentinel_store::Result<Vec<sentinel_link::tailcat::NodeKey>> {
    use sentinel_link::tailcat::NodeKey;
    store.read(|conn| {
        let mut keys = Vec::with_capacity(listed.len());
        for admission in listed {
            if !sentinel_store::workers::revoked(conn, admission.worker)? {
                keys.push(admission.key.clone());
            }
        }
        let bound = sentinel_store::workers::admitted_node_keys(conn)?;
        let pending = sentinel_store::workers::pending_node_keys(conn, now)?;
        for (_, key) in bound.into_iter().chain(pending) {
            let text = key.iter().fold(String::from("nodekey:"), |mut text, byte| {
                use std::fmt::Write as _;
                let _ = write!(text, "{byte:02x}");
                text
            });
            if let Some(key) = NodeKey::parse(&text)
                && !keys.contains(&key)
            {
                keys.push(key);
            }
        }
        Ok(keys)
    })
}

/// Take the lines of revoked or uninstalled workers off the allow-list file, so the file the operator
/// reads names only the machines the controller still admits. Returns the workers it dropped.
#[cfg(feature = "server")]
fn prune_revoked(
    store: &sentinel_store::Store,
    data_dir: &Path,
    listed: &[sentinel_link::tailcat::Admission],
) -> Vec<sentinel_core::WorkerId> {
    let revoked: Vec<sentinel_core::WorkerId> = store
        .read(|conn| {
            let mut gone = Vec::new();
            for admission in listed {
                if !gone.contains(&admission.worker)
                    && sentinel_store::workers::revoked(conn, admission.worker)?
                {
                    gone.push(admission.worker);
                }
            }
            Ok(gone)
        })
        .unwrap_or_default();
    if revoked.is_empty()
        || sentinel_link::tailcat::prune(data_dir, |line| revoked.contains(&line.worker)).is_err()
    {
        return Vec::new();
    }
    revoked
}

#[cfg(feature = "server")]
fn start_tailcat(
    config: &Config,
    store: &Arc<sentinel_store::Store>,
    file: Option<&TailcatFile>,
    listen: SocketAddr,
    link: sentinel_link::controller::Handle,
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
        // The address is a credential: log only the owner-only file it is written to.
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
    let server = Arc::new(server);
    let (wake_tx, wake) = mpsc::sync_channel::<Wake>(1);
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
                    while !matches!(
                        wake.recv_timeout(TAILCAT_ALLOW_REFRESH),
                        Ok(Wake::Stop) | Err(mpsc::RecvTimeoutError::Disconnected)
                    ) {
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
                            Ok(read) => {
                                file_warned = false;
                                listed = read;
                            }
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
                                let pruned = prune_revoked(&store, &data_dir, &listed);
                                if !pruned.is_empty() {
                                    tracing::info!(
                                        event = "tailcat_allow_pruned",
                                        workers = pruned.len()
                                    );
                                    listed.retain(|line| !pruned.contains(&line.worker));
                                }
                                if let Some(handoff) = link.hand_off(&server, &keys) {
                                    tracing::info!(
                                        event = "tailcat_allow_changed",
                                        admitted = keys.len(),
                                        tunnelled = handoff.tunnelled,
                                        closed = handoff.closed,
                                        arrivals = handoff.arrivals,
                                        ended = handoff.ended,
                                        waited_ms = handoff.waited.as_millis() as u64
                                    );
                                }
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
        wake: wake_tx,
        refresher,
    }))
}

#[cfg(feature = "server")]
const MAINTENANCE_INTERVAL: Duration = Duration::from_secs(600);
#[cfg(feature = "server")]
const BACKLOG_INTERVAL: Duration = Duration::from_secs(1);
#[cfg(feature = "server")]
const PURGE_BATCH: u32 = 1000;

#[cfg(feature = "server")]
struct Maintenance {
    stop: mpsc::SyncSender<()>,
    thread: std::thread::JoinHandle<()>,
}

#[cfg(feature = "server")]
impl Maintenance {
    fn start(store: Arc<sentinel_store::Store>, data_dir: PathBuf) -> std::io::Result<Maintenance> {
        let (stop, wake) = mpsc::sync_channel::<()>(0);
        let dispatch = tracing::dispatcher::get_default(Clone::clone);
        let thread = std::thread::Builder::new()
            .name("sentinel-maintenance".into())
            .spawn(move || {
                tracing::dispatcher::with_default(&dispatch, || {
                    let mut interval = MAINTENANCE_INTERVAL;
                    while let Err(mpsc::RecvTimeoutError::Timeout) = wake.recv_timeout(interval) {
                        retire_setup_file(&store, &data_dir);
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

    fn stop(self) {
        drop(self.stop);
        let _ = self.thread.join();
    }
}

#[cfg(feature = "server")]
type Purge =
    fn(&sentinel_store::Store, sentinel_core::UnixMillis, u32) -> sentinel_store::Result<usize>;

#[cfg(feature = "server")]
fn purge_expired(store: &sentinel_store::Store, batch: u32) -> bool {
    let wall = sentinel_core::UnixMillis::now();
    // Idempotency keys are stamped by the deadline clock, so their TTL is judged on it.
    let steady = sentinel_core::UnixMillis::steady();
    let purges: [(&str, Purge, sentinel_core::UnixMillis); 9] = [
        ("setup", sentinel_store::setup::purge, wall),
        ("github_app_states", sentinel_store::github_app::purge, wall),
        ("oauth", sentinel_store::oauth::purge_expired, wall),
        ("api_tokens", sentinel_store::tokens::purge_expired, wall),
        ("sessions", sentinel_store::local_auth::purge_expired, wall),
        ("sign_in", sentinel_store::sign_in::purge_expired, wall),
        ("email", sentinel_store::email::purge, wall),
        (
            "unverified_accounts",
            sentinel_store::email::purge_unverified,
            wall,
        ),
        (
            "idempotency",
            sentinel_store::idempotency::purge_expired,
            steady,
        ),
        (
            "secret_idempotency",
            sentinel_store::secrets::purge_idempotency,
            wall,
        ),
    ];
    let mut backlog = false;
    for (kind, purge, now) in purges {
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

/// Raise the soft open-files limit once, at startup, to what the controller's session limit needs and never past the
/// hard limit, which stays as it was. The link library only reads the limit and sizes its session cap from it, so the
/// process-wide change is made here, by the one owner of the process, and a limit that stays too low is reported by
/// `Controller::start` with the numbers instead of being papered over.
#[cfg(all(feature = "server", target_os = "linux"))]
fn raise_descriptor_soft_limit() {
    let need =
        sentinel_link::controller::descriptors_needed(sentinel_link::controller::MAX_SESSIONS)
            as libc::rlim_t;
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `limit` is a valid, writable `rlimit` for the whole call.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } != 0 || limit.rlim_cur >= need {
        return;
    }
    let raised = libc::rlimit {
        rlim_cur: need.min(limit.rlim_max),
        rlim_max: limit.rlim_max,
    };
    // SAFETY: `raised` is a valid `rlimit` that only moves the soft limit up to the hard one; failure leaves the
    // limit as it was.
    let raised_ok = raised.rlim_cur > limit.rlim_cur
        && unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &raised) } == 0;
    tracing::info!(
        event = "descriptor_limit",
        soft = if raised_ok {
            raised.rlim_cur
        } else {
            limit.rlim_cur
        },
        hard = limit.rlim_max,
        needed = need,
        raised = raised_ok,
    );
}

#[cfg(all(feature = "server", not(target_os = "linux")))]
fn raise_descriptor_soft_limit() {}

#[cfg(feature = "server")]
fn start_server(
    config: &Config,
    listen: SocketAddr,
    api_listen: SocketAddr,
    public_url: Option<String>,
    trusted_proxies: Option<&[String]>,
    tailcat: Option<&TailcatFile>,
    (remote_cache, remote_cache_budget, priority_placement): (bool, Option<u64>, bool),
) -> Result<Running, Error> {
    let path = config.data_dir.join(sentinel_store::METADATA_FILE);
    let (store, snapshot) =
        sentinel_store::upgrade::open_upgrading(&path, sentinel_store::Durability::Full).map_err(
            |error| match error {
                sentinel_store::Error::AlreadyOwned => Error::runtime(format!(
                    "another process owns {}; one controller per data directory",
                    path.display()
                )),
                other => Error::runtime(format!("cannot open {}: {other}", path.display())),
            },
        )?;
    if let Some(snapshot) = &snapshot {
        tracing::info!(event = "schema_upgraded", schema = sentinel_store::schema::LATEST, snapshot = %snapshot.display(), "the database before this upgrade is kept for a rollback");
    }
    let database: u32 = store
        .read(|c| {
            Ok(
                c.query_row("SELECT MAX(version) FROM schema_migrations", [], |r| {
                    r.get(0)
                })?,
            )
        })
        .unwrap_or(0);
    if database > sentinel_store::schema::LATEST {
        tracing::warn!(
            event = "schema_newer",
            database,
            binary = sentinel_store::schema::LATEST,
            "running on a database a newer release migrated; it declares itself readable by this one"
        );
    }
    let store = Arc::new(store);
    let key = master_key(&config.data_dir, &store)?;
    let identity = identity(&config.data_dir, "controller")?;
    let fingerprint = hex32(&identity.fingerprint().0);
    let logs = Arc::new(
        sentinel_store::logs::LogStore::open_with_limit(
            config.data_dir.join(sentinel_store::logs::LOGS_DIR),
            config.storage.attempt_log_bytes,
        )
        .map_err(|error| Error::runtime(format!("cannot open the log store: {error}")))?,
    );
    let total = sentinel_store::space::total_bytes(&config.data_dir).unwrap_or(0);
    let marks = config.storage.marks(total)?;
    let admission = Arc::new(
        sentinel_store::space::Admission::new(config.data_dir.clone(), marks)
            .map_err(|error| Error::runtime(format!("invalid storage watermarks: {error}")))?,
    );
    admission.set_metadata_bytes(store.metadata_bytes());
    let deployment = config.storage.deployment;
    store
        .writer()
        .write(move |tx| sentinel_store::retention::install(tx, &deployment))
        .map_err(|error| Error::runtime(format!("cannot record the storage policy: {error}")))?;
    tracing::info!(
        event = "storage_configured",
        filesystem_bytes = total,
        reserve_bytes = marks.reserve,
        low_watermark_bytes = marks.low,
        high_watermark_bytes = marks.high,
        quota_bytes = deployment.quota_bytes,
        tenant_quota_bytes = deployment.tenant_quota_bytes,
        log_retention_ms = deployment.log_retention_ms,
        artifact_retention_ms = deployment.artifact_retention_ms,
    );
    logs.set_admission(Arc::clone(&admission));
    let objects = sentinel_store::objects::Objects::open(&config.data_dir)
        .map_err(|error| Error::runtime(format!("cannot open the object store: {error}")))?;
    objects.set_admission(Arc::clone(&admission));
    objects.set_deployment(config.storage.deployment);
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
    raise_descriptor_soft_limit();
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
        interval_ms: config.storage.sweep_interval_ms,
    });
    if priority_placement {
        controller.set_placement_order(sentinel_link::controller::PlacementOrder::Priority);
    }
    if remote_cache {
        let root = config.data_dir.join("remote-cache");
        fs::create_dir_all(&root).map_err(|error| {
            Error::runtime(format!(
                "cannot create the remote cache directory {}: {error}",
                root.display()
            ))
        })?;
        let budget = remote_cache_budget.unwrap_or_else(|| (total / 10).clamp(1 << 30, 50 << 30));
        controller.set_remote_cache_budget(budget);
        controller.set_remote_cache(root);
    }
    let tailcat_file = tailcat;
    let tailcat = start_tailcat(config, &store, tailcat, listen, controller.handle())?;
    let destinations = crate::source_admin::load_destinations(&config.data_dir)
        .map_err(|_| Error::runtime("cannot load source destination policy"))?;
    let intake_destinations: Arc<[String]> = destinations.clone().into();
    controller.set_source_destinations(destinations);
    let github = crate::source_admin::load_github(
        &config.data_dir,
        &store,
        key.as_deref(),
        public_url.as_deref(),
    )
    .map_err(|error| Error::runtime(error.message))?;
    if github.stored_ignored {
        tracing::warn!(
            event = "github_app_stored_ignored",
            "a GitHub App made with one-click setup is stored, but the GitHub files in the data directory take precedence"
        );
    }
    if let Some(app) = github.current.get() {
        controller.set_source_app(Arc::clone(app));
    }
    if let Some(key) = &key {
        controller.set_source_key(Arc::clone(key));
    }
    let resolver = sentinel_intake::Resolver::new(
        Arc::clone(&store),
        key.clone(),
        github.current.clone(),
        Arc::clone(&intake_destinations),
        Arc::new(sentinel_intake::resolve::GitFetch),
        config.data_dir.join("intake-work"),
        sentinel_intake::resolve::Config::default(),
    )
    .map_err(|_| Error::runtime("cannot prepare the intake work directory"))?;
    let dispatch_wake: Arc<dyn Fn() + Send + Sync> = {
        let handle = controller.handle();
        // A new run can supersede a running one (`cancel_in_progress`), so its cancel is pushed now.
        Arc::new(move || handle.cancel_hint())
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
    let poll_dispatch = tracing::dispatcher::get_default(Clone::clone);
    let poll = sentinel_intake::Poll::start(
        Arc::clone(&store),
        key.clone(),
        github.current.clone(),
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
    let github_webhook_secret = github.webhook_secret.clone();
    if github_webhook_secret.is_some() {
        tracing::info!(event = "github_webhook_enabled");
    }
    let github_lanes: Arc<std::sync::Mutex<Option<GithubLanes>>> =
        Arc::new(std::sync::Mutex::new(None));
    match github.current.get() {
        Some(app) => {
            tracing::info!(
                event = "checks_enabled",
                endpoint = %app.endpoint(),
                details_url = github.details_url.is_some()
            );
            *github_lanes.lock().unwrap_or_else(|p| p.into_inner()) = Some(GithubLanes::start(
                &store,
                Arc::clone(app),
                github.details_url.clone(),
                github.members,
            ));
        }
        None => tracing::info!(event = "checks_disabled", "no GitHub App"),
    }
    let on_activate: sentinel_api::OnActivate = {
        let (store, lanes, link) = (
            Arc::clone(&store),
            Arc::clone(&github_lanes),
            controller.handle(),
        );
        let details_url = public_url.clone();
        let dispatch = tracing::dispatcher::get_default(Clone::clone);
        Arc::new(move |activation: &sentinel_api::Activation| {
            tracing::dispatcher::with_default(&dispatch, || {
                link.set_source_app(Arc::clone(&activation.app));
                let mut slot = lanes.lock().unwrap_or_else(|p| p.into_inner());
                if slot.is_none() {
                    *slot = Some(GithubLanes::start(
                        &store,
                        Arc::clone(&activation.app),
                        details_url.clone(),
                        sentinel_checks::members::Config::default(),
                    ));
                }
                tracing::info!(
                    event = "github_app_activated",
                    app_id = activation.app_id,
                    slug = %activation.slug,
                    "the GitHub App made with one-click setup is in force; no restart needed"
                );
            });
        })
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
    let github_sign_in = github.sign_in;
    if let Some(sign_in) = &github_sign_in {
        tracing::info!(event = "github_sign_in_enabled", client_id = %sign_in.client_id);
    }
    let replicator = match &config.s3 {
        Some(s3) => Some(start_replicator(s3, total, &store, &objects, &logs)?),
        None => None,
    };
    let backups = match &config.backup {
        Some(backup) => {
            let scheduler = sentinel_store::backup::Scheduler::new(
                Arc::clone(&store),
                Arc::clone(&objects),
                config.data_dir.clone(),
                backup.dir.clone(),
                Duration::from_secs(backup.interval_secs.unwrap_or(3_600)),
                backup.keep.unwrap_or(24),
                env!("CARGO_PKG_VERSION").to_owned(),
            );
            objects.set_backups(Arc::clone(&scheduler) as Arc<dyn sentinel_store::backup::Control>);
            let thread = scheduler
                .start()
                .map_err(|error| Error::runtime(format!("cannot start backups: {error}")))?;
            tracing::info!(event = "backups_scheduled", dir = %backup.dir.display(), interval_secs = backup.interval_secs.unwrap_or(3_600), keep = backup.keep.unwrap_or(24));
            Some((scheduler, thread))
        }
        None => None,
    };
    let (mail, mail_sender) = start_mail(config, public_url.as_deref(), &store, key.as_ref())?;
    announce_setup(&config.data_dir, &store)?;
    record_auto_join(&config.auto_join, &store)?;
    let worker_bootstrap = match &config.worker_bootstrap {
        Some(file) => {
            let built = file.build(&config.data_dir, &fingerprint, tailcat_file)?;
            tracing::info!(
                event = "worker_bootstrap_enabled",
                release = built.release_version(),
                tailcat = built.tailcat_configured()
            );
            Some(Arc::new(built))
        }
        None => None,
    };
    let options = sentinel_api::Options {
        worker_bootstrap,
        on_worker_enrolled: tailcat.as_ref().map(TailcatServer::refresh_now),
        mail: mail_sender,
        auto_join: config
            .auto_join
            .rules
            .iter()
            .map(|rule| sentinel_api::AutoJoinRule {
                domain: rule.domain.clone(),
                organization: rule.slug.clone(),
            })
            .collect(),
        github_app: sentinel_api::GithubAppSetup {
            current: github.current.clone(),
            source: github.source,
            on_activate: Some(on_activate),
            ..sentinel_api::GithubAppSetup::default()
        },
    };
    let api = sentinel_api::Server::start_with(
        sentinel_api::Config {
            listen: api_listen,
            store: Arc::clone(&store),
            logs: Arc::clone(&logs),
            objects,
            controller: controller.handle(),
            secret_key: key.clone(),
            sessions: sentinel_store::local_auth::Policy::default(),
            github_webhook_secret,
            intake: Some(lane.waker()),
            public_url,
            github_sign_in,
            trusted_proxies: match trusted_proxies {
                Some(proxies) => proxies
                    .iter()
                    .filter_map(|proxy| sentinel_api::TrustedProxy::parse(proxy))
                    .collect(),
                None => sentinel_api::TrustedProxy::loopback(),
            },
        },
        options,
    )
    .map_err(|error| Error::runtime(format!("cannot listen on {api_listen}: {error}")))?;
    tracing::info!(event = "api_listening", addr = %api.local_addr(), issuer = %api.issuer());
    let maintenance = Maintenance::start(Arc::clone(&store), config.data_dir.clone())
        .map_err(|error| Error::runtime(format!("cannot start maintenance: {error}")))?;
    Ok(Running::Server {
        controller,
        api,
        maintenance,
        store,
        lane: Box::new(lane),
        poll: Box::new(poll),
        github_lanes,
        mail,
        tailcat,
        replicator,
        backups,
    })
}

#[cfg(feature = "server")]
fn announce_setup(data_dir: &Path, store: &sentinel_store::Store) -> Result<(), Error> {
    let path = data_dir.join(sentinel_store::setup::TOKEN_FILE);
    let issued = sentinel_store::setup::issue(store, sentinel_core::UnixMillis::now())
        .map_err(|error| Error::runtime(format!("cannot issue the setup token: {error}")))?;
    let Some(token) = issued else {
        remove_setup_file(&path);
        return Ok(());
    };
    let mut text = String::new();
    token.expose(&mut text);
    write_owner_only(&path, text.as_bytes())
        .map_err(|error| Error::runtime(format!("cannot write {}: {error}", path.display())))?;
    // Logged on purpose: the token is readable only by whoever reads this host's console or data directory.
    tracing::warn!(
        event = "setup_required",
        token = %text,
        file = %path.display(),
        expires_in_secs = sentinel_store::setup::TOKEN_TTL_MS / 1000,
        "first-run setup is open: present this token to the setup wizard, or run `sentinel admin bootstrap` instead"
    );
    sentinel_auth::secret::wipe_string(&mut text);
    Ok(())
}

#[cfg(feature = "server")]
fn write_owner_only(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    match fs::remove_file(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

#[cfg(feature = "server")]
fn remove_setup_file(path: &Path) {
    match fs::remove_file(path) {
        Ok(()) => tracing::info!(event = "setup_token_file_removed"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            tracing::warn!(event = "setup_token_file_remove_failed", error = %error);
        }
    }
}

#[cfg(feature = "server")]
fn retire_setup_file(store: &sentinel_store::Store, data_dir: &Path) {
    let path = data_dir.join(sentinel_store::setup::TOKEN_FILE);
    if fs::symlink_metadata(&path).is_err() {
        return;
    }
    let live = store
        .read(|c| sentinel_store::setup::token_live(c, sentinel_core::UnixMillis::now()))
        .unwrap_or(true);
    if !live {
        remove_setup_file(&path);
    }
}

#[cfg(feature = "server")]
fn record_auto_join(
    parsed: &sentinel_store::auto_join::Parsed,
    store: &Arc<sentinel_store::Store>,
) -> Result<(), Error> {
    for dropped in &parsed.ignored {
        tracing::warn!(
            event = "auto_join_entry_ignored",
            index = dropped.index,
            reason = dropped.reason.as_str()
        );
    }
    let refused = sentinel_store::auto_join::set_rules(store, &parsed.rules)
        .map_err(|error| Error::runtime(format!("cannot record auto-join domains: {error}")))?;
    for dropped in &refused {
        tracing::warn!(
            event = "auto_join_entry_refused",
            index = dropped.index,
            reason = dropped.reason.as_str()
        );
    }
    tracing::info!(
        event = "auto_join_domains",
        active = parsed.rules.len() - refused.len(),
        ignored = parsed.ignored.len() + refused.len()
    );
    Ok(())
}

#[cfg(feature = "server")]
type MailStart = (
    Option<Box<sentinel_mail::Lane>>,
    Option<Arc<sentinel_mail::Resend>>,
);

#[cfg(feature = "server")]
fn start_mail(
    config: &Config,
    public_url: Option<&str>,
    store: &Arc<sentinel_store::Store>,
    key: Option<&Arc<sentinel_auth::sealed::Key>>,
) -> Result<MailStart, Error> {
    let record = |enabled: bool| {
        sentinel_store::email::set_delivery(
            store,
            enabled,
            public_url,
            sentinel_core::UnixMillis::now(),
        )
        .map_err(|error| Error::runtime(format!("cannot record mail delivery: {error}")))
    };
    let Some(mail) = &config.mail else {
        record(false)?;
        tracing::info!(
            event = "mail_disabled",
            "no Resend key configured: verification and invitation links are minted with `sentinel admin`"
        );
        return Ok((None, None));
    };
    let api_key = sentinel_mail::ApiKey::from_file(&mail.api_key_file)
        .map_err(|reason| Error::config(format!("[mail] {reason}")))?;
    let from = sentinel_mail::Sender::parse(&mail.from)
        .map_err(|reason| Error::config(format!("[mail] {reason}")))?;
    let resend = Arc::new(sentinel_mail::Resend::new(api_key, from));
    let Some(key) = key else {
        record(false)?;
        tracing::warn!(
            event = "mail_disabled",
            "Resend is configured but there is no master key to seal queued messages; create one with `sentinel admin key create`"
        );
        return Ok((None, Some(resend)));
    };
    record(true)?;
    tracing::info!(event = "mail_enabled", provider = "resend");
    let dispatch = tracing::dispatcher::get_default(Clone::clone);
    let lane = sentinel_mail::Lane::start(
        Arc::clone(store),
        Arc::clone(key),
        Box::new(Arc::clone(&resend)),
        sentinel_mail::LaneConfig::default(),
        move |batch| {
            tracing::dispatcher::with_default(&dispatch, || {
                if batch.abandoned > 0 {
                    tracing::warn!(
                        event = "mail_abandoned",
                        abandoned = batch.abandoned,
                        "messages were given up on"
                    );
                }
                // Never the recipient: only the message's own identifier.
                for entry in &batch.entries {
                    tracing::info!(
                        event = "mail_settled",
                        mail = %entry.id,
                        kind = entry.kind,
                        outcome = %entry.outcome
                    );
                }
            });
        },
    );
    Ok((Some(Box::new(lane)), Some(resend)))
}

#[cfg(feature = "server")]
fn start_replicator(
    s3: &S3File,
    total: u64,
    store: &Arc<sentinel_store::Store>,
    objects: &Arc<sentinel_store::objects::Objects>,
    logs: &Arc<sentinel_store::logs::LogStore>,
) -> Result<sentinel::offload::Running, Error> {
    let credentials = sentinel_s3::Credentials::from_file(&s3.credentials_file)
        .map_err(|error| Error::config(error.to_string()))?;
    let (connect_timeout, read_timeout) = sentinel_s3::client::default_timeouts();
    let client = sentinel_s3::Client::new(sentinel_s3::Config {
        endpoint: s3.endpoint.clone(),
        region: s3.region.clone(),
        bucket: s3.bucket.clone(),
        prefix: s3.prefix.clone(),
        path_style: s3.path_style,
        ca_file: s3.ca_file.clone(),
        credentials,
        connect_timeout,
        read_timeout,
    })
    .map_err(|error| Error::config(error.to_string()))?;
    match client.check() {
        Ok(()) => {
            tracing::info!(event = "s3_ready", endpoint = %s3.endpoint, bucket = %s3.bucket, prefix = %s3.prefix)
        }
        Err(error) => {
            tracing::warn!(event = "s3_unavailable", endpoint = %s3.endpoint, bucket = %s3.bucket, reason = %error, "starting degraded: local copies are kept until the bucket answers")
        }
    }
    let bucket = Arc::new(sentinel::offload::S3Bucket::new(client));
    objects.set_remote(Arc::clone(&bucket) as Arc<dyn sentinel_store::objects::Remote>);
    let settings = sentinel_store::replicate::Settings {
        part_bytes: s3.part_bytes.unwrap_or(16 << 20),
        local_bytes: s3.local_bytes.unwrap_or(0),
        backlog_bytes: s3
            .backlog_bytes
            .unwrap_or_else(|| (total / 16).clamp(1 << 30, 64 << 30)),
    };
    tracing::info!(
        event = "s3_configured",
        part_bytes = settings.part_bytes,
        local_bytes = settings.local_bytes,
        backlog_bytes = settings.backlog_bytes
    );
    let replicator = sentinel_store::replicate::Replicator::new(
        Arc::clone(store),
        Arc::clone(objects),
        Arc::clone(logs),
        bucket as Arc<dyn sentinel_store::replicate::Bucket>,
        settings,
    );
    objects.set_replication(replicator.status());
    sentinel::offload::Running::start(replicator)
        .map_err(|error| Error::runtime(format!("cannot start the S3 replicator: {error}")))
}

#[cfg(feature = "worker")]
mod worker_role {
    use super::*;
    use sentinel_core::AttemptId;
    use sentinel_link::session::{Capacity, Executor as LinkExecutor, Offer};

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

    #[expect(
        clippy::too_many_arguments,
        reason = "worker assembly receives independent process settings"
    )]
    fn executor(
        data_dir: &Path,
        worker: sentinel_core::WorkerId,
        git_mirrors: bool,
        spool: (Option<u64>, Option<u64>),
        budgets: [Option<u64>; 3],
        measured_disk: bool,
        network: sentinel_worker::podman::Network,
        runtime: sentinel_worker::attempt::Runtime,
        metrics: Arc<crate::worker_metrics::Metrics>,
    ) -> Box<dyn LinkExecutor> {
        let dispatch = tracing::dispatcher::get_default(Clone::clone);
        let span = tracing::Span::current();
        let counted = Arc::clone(&metrics);
        let notify = move |notice: sentinel_worker::executor::Notice| {
            counted.count(&notice);
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
                    sentinel_worker::executor::Notice::SpoolRefused { attempt, refused } => {
                        tracing::warn!(event = "spool_refused", attempt = %attempt, cap = refused.cap, quota = refused.quota, low_space = refused.low_space, failed_writes = refused.failed, gap_limit = refused.gap_limit, "output the spool could not hold is declared as gaps in the attempt's log");
                    }
                    sentinel_worker::executor::Notice::CachePublished { attempt, note } => {
                        tracing::info!(event = "cache_published", attempt = %attempt, cache = %note.name, outcome = ?note.outcome);
                    }
                    sentinel_worker::executor::Notice::CacheSwept(stats) => {
                        tracing::info!(event = "cache_swept", stats = ?stats);
                    }
                    sentinel_worker::executor::Notice::ImagesReclaimed(removed) => {
                        tracing::info!(event = "images_reclaimed", removed);
                    }
                    sentinel_worker::executor::Notice::CostlyCacheHit { attempt, name, costly, stats } => {
                        tracing::warn!(event = "cache_costly_hit", attempt = %attempt, cache = %name, reason = costly.as_str(), copied_bytes = stats.copied_bytes, bytes = stats.bytes, lock_wait_ns = ?stats.lock_wait_ns, clone_ns = ?stats.clone_ns, "nominal hit paid rebuild-scale restore cost (docs/cache.md)");
                    }
                    sentinel_worker::executor::Notice::OfferRefused { attempt, free_bytes, floor_bytes } => {
                        tracing::warn!(event = "offer_refused_low_disk", attempt = %attempt, free_bytes, floor_bytes, "the data directory's disk is below the admission floor; offers are refused until it recovers");
                    }
                    sentinel_worker::executor::Notice::ShutDown { ended, left, handed_back } => {
                        tracing::info!(event = "attempts_shut_down", ended, left, handed_back);
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
                executor.set_spool_limits(
                    spool
                        .0
                        .unwrap_or(sentinel_worker::spool::DEFAULT_SPOOL_RESERVE),
                    spool
                        .1
                        .unwrap_or(sentinel_worker::spool::DEFAULT_SPOOL_QUOTA),
                );
                let sized = sentinel_worker::executor::StorageBudgets::sized(
                    sentinel_worker::spool::filesystem_bytes(data_dir).unwrap_or(0),
                );
                let budgets = sentinel_worker::executor::StorageBudgets {
                    cache_bytes: budgets[0].unwrap_or(sized.cache_bytes),
                    mirror_bytes: budgets[1].unwrap_or(sized.mirror_bytes),
                    image_bytes: budgets[2].unwrap_or(sized.image_bytes),
                };
                tracing::info!(
                    event = "worker_budgets",
                    cache_bytes = budgets.cache_bytes,
                    mirror_bytes = budgets.mirror_bytes,
                    image_bytes = budgets.image_bytes
                );
                executor.set_storage_budgets(budgets);
                executor.set_measured_disk(measured_disk);
                executor.set_job_network(network);
                executor.set_runtime(runtime);
                if network == sentinel_worker::podman::Network::Egress {
                    tracing::warn!(
                        event = "job_egress_enabled",
                        "job containers on this worker have outbound network (job_network = \"egress\")"
                    );
                }
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
                let _ = metrics.executor.set(executor.clone());
                Box::new(executor)
            }
            Err(error) => {
                tracing::warn!(event = "executor_unavailable", error = %error, "offers will be declined");
                Box::new(NoExecutor)
            }
        }
    }

    /// Whether the isolation the configuration asks for can run on this host.
    pub(super) fn check_runtime(link: &WorkerLink) -> Result<(), Error> {
        let setup = link
            .microvm
            .as_ref()
            .map(|m| sentinel_worker::microvm::Setup {
                firecracker: m.firecracker.clone(),
                kernel: m.kernel.clone(),
                agent: m.agent.clone(),
            });
        let preference = match link.isolation {
            IsolationSetting::Auto => sentinel_worker::host::Preference::Auto,
            IsolationSetting::Container => sentinel_worker::host::Preference::Container,
            IsolationSetting::Microvm => sentinel_worker::host::Preference::Microvm,
        };
        runtime_selection(preference, setup.as_ref()).map(drop)
    }

    /// Detects the host's virtualization and picks the default executor (plan 16.8, runtime selection).
    fn runtime_selection(
        preference: sentinel_worker::host::Preference,
        setup: Option<&sentinel_worker::microvm::Setup>,
    ) -> Result<sentinel_worker::host::Selection, Error> {
        let (virtualization, absent) = sentinel_worker::host::detect();
        let microvm_ready = match setup {
            Some(setup) => setup.check(),
            None => Err("no [microvm] section in the worker configuration".to_owned()),
        };
        let selection = sentinel_worker::host::select(
            preference,
            virtualization,
            absent.as_ref(),
            microvm_ready,
        )
        .map_err(Error::config)?;
        tracing::info!(
            event = "runtime_selected",
            default = selection.default.as_str(),
            microvm = selection.microvm,
            kvm = virtualization.kvm,
            nested = virtualization.nested,
            kvm_absent = absent.as_ref().map(|a| a.0.as_str())
        );
        Ok(selection)
    }

    /// What the worker states it can run; a job that states an OS or isolation is placed only where they match.
    fn runtime_capabilities(
        selection: &sentinel_worker::host::Selection,
    ) -> sentinel_protocol::negotiate::Capabilities {
        use sentinel_protocol::negotiate::Capabilities as C;
        let mut bits = C::OS_LINUX.union(C::ISOLATION_CONTAINER);
        if selection.virtualization.kvm {
            bits = bits.union(C::KVM);
        }
        if selection.virtualization.nested {
            bits = bits.union(C::KVM_NESTED);
        }
        if selection.microvm {
            bits = bits.union(C::ISOLATION_MICROVM);
        }
        bits
    }

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

    #[cfg(target_os = "linux")]
    fn disk_free(path: &Path) -> u64 {
        use std::os::unix::ffi::OsStrExt;
        let Ok(cpath) = std::ffi::CString::new(path.as_os_str().as_bytes()) else {
            return 0;
        };
        // SAFETY: `statvfs` is a plain C struct of integers, for which the
        // all-zero bit pattern is valid.
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

    fn profile_disk(link: &WorkerLink, data_dir: &Path) -> u64 {
        match link.disk_bytes {
            Some(bytes) => bytes,
            None => sentinel_worker::executor::job_disk_room(disk_free(data_dir)),
        }
    }

    #[cfg(target_os = "linux")]
    fn load_ns() -> u64 {
        const WINDOW: Duration = Duration::from_millis(100);
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
        let local = SocketAddr::from(([127, 0, 0, 1], forward.local_addr().port()));
        Ok((local, stats, Some(forward)))
    }

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
        let (controller, transport, forward) = tailcat(link, &config.data_dir)?;
        let forward = forward.map(Arc::new);
        let mut capabilities = sentinel_protocol::negotiate::Capabilities::REQUIRED
            .union(sentinel_protocol::negotiate::Capabilities::HANDOFF_ANSWER)
            .union(sentinel_protocol::negotiate::Capabilities::SECRET_DELIVERY);
        if sentinel_worker::cache_reflink(&config.data_dir) {
            capabilities = capabilities.union(sentinel_protocol::negotiate::Capabilities::REFLINK);
        }
        let setup = link
            .microvm
            .as_ref()
            .map(|m| sentinel_worker::microvm::Setup {
                firecracker: m.firecracker.clone(),
                kernel: m.kernel.clone(),
                agent: m.agent.clone(),
            });
        let preference = match link.isolation {
            IsolationSetting::Auto => sentinel_worker::host::Preference::Auto,
            IsolationSetting::Container => sentinel_worker::host::Preference::Container,
            IsolationSetting::Microvm => sentinel_worker::host::Preference::Microvm,
        };
        let selection = runtime_selection(preference, setup.as_ref())?;
        capabilities = capabilities.union(runtime_capabilities(&selection));
        let runtime = sentinel_worker::attempt::Runtime {
            default: Some(selection.default),
            microvm: setup.filter(|_| selection.microvm).map(Arc::new),
        };
        let settings = sentinel_link::worker::Config {
            controller,
            server: sentinel_auth::secret::Digest(link.fingerprint),
            also_pinned: link
                .also_fingerprints
                .iter()
                .map(|f| sentinel_auth::secret::Digest(*f))
                .collect(),
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
        let metrics = Arc::new(crate::worker_metrics::Metrics::default());
        let events = Arc::clone(&metrics);
        let network = match link.job_network {
            NetworkSetting::None => sentinel_worker::podman::Network::None,
            NetworkSetting::Egress => sentinel_worker::podman::Network::Egress,
        };
        let executor = executor(
            &config.data_dir,
            worker,
            link.git_mirrors,
            (link.spool_reserve_bytes, link.spool_quota_bytes),
            link.budgets,
            link.disk_bytes.is_none(),
            network,
            runtime,
            Arc::clone(&metrics),
        );
        if let Some(listen) = link.metrics_listen {
            let bound = crate::worker_metrics::serve(
                listen,
                Arc::clone(&metrics),
                config.data_dir.clone(),
                disk_free,
            )
            .map_err(|error| {
                Error::runtime(format!("cannot listen for metrics on {listen}: {error}"))
            })?;
            tracing::info!(event = "metrics_listening", address = %bound);
        }
        let tunnel = forward.clone();
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
                                    events.connected.store(true, std::sync::atomic::Ordering::Relaxed);
                                    events.connects.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                    if enrolled && let Some(path) = &enrollment_file {
                                        let _ = fs::remove_file(path);
                                    }
                                    tracing::info!(event = "link_connected", worker = %worker, enrolled);
                                }
                                sentinel_link::worker::Event::Disconnected(error) => {
                                    events.connected.store(false, std::sync::atomic::Ordering::Relaxed);
                                    events.disconnects.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                    tracing::warn!(event = "link_lost", error = %error);
                                    if let Some(forward) = &tunnel
                                        && matches!(error, sentinel_link::Error::Closed)
                                    {
                                        forward.session_closed();
                                        tracing::info!(
                                            event = "tailcat_replaced",
                                            "the controller handed the session off; replacing the helper"
                                        );
                                    } else if let Some(forward) = &tunnel && forward.session_lost() {
                                        tracing::warn!(
                                            event = "tailcat_replaced",
                                            "the control session over the forward was lost; replacing the helper"
                                        );
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
            metrics,
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
    // Register before initialization so a shutdown during startup is kept; signal callbacks only enqueue.
    let (sender, receiver) = mpsc::sync_channel(1);
    let initialized = (|| {
        ctrlc::set_handler(move || {
            let _ = sender.try_send(());
        })
        .map_err(|error| Error::runtime(format!("cannot install shutdown handler: {error}")))?;
        let data_dir = config.data_dir.clone();
        bootstrap_work(io, move || create_data_dir(&data_dir))?
            .map_err(|error| Error::runtime(format!("cannot initialize data_dir: {error}")))?;
        match &config.role {
            #[cfg(feature = "server")]
            Role::Server {
                listen,
                api_listen,
                public_url,
                trusted_proxies,
                tailcat,
                remote_cache,
                remote_cache_budget,
                priority_placement,
            } => start_server(
                config,
                *listen,
                *api_listen,
                public_url.clone(),
                trusted_proxies.as_deref(),
                tailcat.as_ref(),
                (*remote_cache, *remote_cache_budget, *priority_placement),
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
            github_lanes,
            mail,
            tailcat,
            replicator,
            backups,
        } => {
            api.shutdown();
            maintenance.stop();
            if let Some((scheduler, thread)) = backups {
                scheduler.stop();
                let _ = thread.join();
            }
            if let Some(replicator) = replicator {
                replicator.shutdown();
            }
            if let Some(tailcat) = tailcat {
                tailcat.shutdown();
            }
            drop(
                github_lanes
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .take(),
            );
            drop(mail);
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
            metrics,
        } => {
            // Stop attempts while the session is up: their containers must be removed before the controller reallocates capacity.
            if let Some(executor) = metrics.executor.get() {
                executor.shutdown(WORKER_SHUTDOWN);
            }
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

#[cfg(all(test, target_os = "linux"))]
mod hardening_tests {
    #[test]
    fn a_service_process_keeps_its_memory_out_of_dumps() {
        // SAFETY: the child only makes raw syscalls (setrlimit, prctl,
        // getrlimit) and `_exit`s; nothing that could need a lock another
        // thread held at fork.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            super::keep_memory_out_of_dumps();
            let mut limit = libc::rlimit {
                rlim_cur: 1,
                rlim_max: 1,
            };
            // SAFETY: as above; `limit` is a valid out-pointer.
            let ok = unsafe {
                libc::getrlimit(libc::RLIMIT_CORE, &mut limit) == 0
                    && limit.rlim_cur == 0
                    && limit.rlim_max == 0
                    && libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) == 0
            };
            // SAFETY: ends the forked child without running the parent's
            // destructors or atexit handlers.
            unsafe { libc::_exit(if ok { 0 } else { 1 }) };
        }
        let mut status = 0;
        // SAFETY: waits for the child forked above.
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert!(libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0);
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

    #[test]
    fn an_authorized_enrollment_key_is_admitted_until_the_worker_is_uninstalled() {
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
        let (pool, worker) = (PoolId::new(), WorkerId::new());
        let hex = "d".repeat(64);
        let node_key = NodeKey::parse(&format!("nodekey:{hex}")).unwrap();
        let raw = [0xdd_u8; 32];
        let issued = store
            .writer()
            .write(move |tx| {
                tenancy::create_pool(
                    tx,
                    Authority::HostLocal,
                    pool,
                    "builders",
                    tenancy::PoolKind::Shared,
                    UnixMillis(1_000),
                )?;
                let issued = workers::issue_enrollment_with(
                    tx,
                    Authority::HostLocal,
                    workers::EnrollmentTerms {
                        pool,
                        lifetime_ms: 60_000,
                        policy: workers::HostPolicy::default(),
                        tailcat: true,
                    },
                    UnixMillis(1_000),
                )?;
                workers::authorize_node_key(
                    tx,
                    Authority::HostLocal,
                    issued.id,
                    worker,
                    raw,
                    UnixMillis(1_100),
                )?;
                Ok(issued)
            })
            .unwrap();

        // Before the worker has connected, its authorized key is all the helper has to go on.
        let at = |ms| admitted_keys_at(&store, &[], UnixMillis(ms)).unwrap();
        assert_eq!(at(2_000), vec![node_key.clone()]);
        assert!(at(61_001).is_empty(), "an expired enrollment admits no one");

        let mut text = String::new();
        issued.secret.expose(&mut text);
        let secret = Secret::parse(&text).unwrap();
        store
            .writer()
            .write(move |tx| {
                workers::redeem_authorized(
                    tx,
                    &secret,
                    workers::Presentation {
                        worker,
                        fingerprint: Secret::generate().digest(),
                        name: "w",
                        negotiated: Negotiated {
                            protocol: ProtocolVersion(7),
                            capabilities: Capabilities::REQUIRED,
                            arch: Arch::X86_64,
                        },
                    },
                    UnixMillis(3_000),
                )
                .map(|_| ())
            })
            .unwrap();
        // Spent: the key is now the worker's own, and it stays admitted past the enrollment's expiry.
        assert_eq!(at(2_000_000), vec![node_key.clone()]);
        // A hand-listed line for the same worker adds nothing.
        let listed = [Admission {
            key: node_key.clone(),
            worker,
        }];
        assert_eq!(
            admitted_keys_at(&store, &listed, UnixMillis(3_500)).unwrap(),
            vec![node_key.clone()]
        );

        // The uninstall settles, the key leaves the helper's list and the file loses its line.
        let allow = dir.path().join(sentinel_link::tailcat::ALLOW_LIST_FILE);
        sentinel_link::tailcat::admit(dir.path(), &listed[0]).unwrap();
        store
            .writer()
            .write(move |tx| {
                workers::request_uninstall(tx, Authority::HostLocal, worker, UnixMillis(4_000))?;
                workers::settle_uninstalls(tx, UnixMillis(4_100)).map(|_| ())
            })
            .unwrap();
        assert!(
            admitted_keys_at(&store, &listed, UnixMillis(4_200))
                .unwrap()
                .is_empty()
        );
        assert_eq!(prune_revoked(&store, dir.path(), &listed), vec![worker]);
        assert_eq!(std::fs::read_to_string(&allow).unwrap(), "");
        assert!(prune_revoked(&store, dir.path(), &[]).is_empty());
    }

    fn marks_ok(storage: &Storage, total: u64) -> sentinel_store::space::Watermarks {
        match storage.marks(total) {
            Ok(marks) => marks,
            Err(_) => panic!("watermarks must resolve for {total}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_non_unicode_auto_join_value_stops_startup_without_echoing_it() {
        use std::os::unix::ffi::OsStringExt;
        let raw = std::ffi::OsString::from_vec(b"secret-\xff.example=org".to_vec());
        let Err(error) = auto_join_from_env(Err(std::env::VarError::NotUnicode(raw))) else {
            panic!("a non-Unicode value must be an error");
        };
        let text = error.message;
        assert!(text.contains("SENTINEL_AUTO_JOIN_DOMAINS"), "{text}");
        assert!(!text.contains("secret"), "{text}");
        assert!(auto_join_from_env(Err(std::env::VarError::NotPresent)).is_ok());
        assert!(auto_join_from_env(Ok("example.com=eng".into())).is_ok());
    }

    fn resolve_ok(file: StorageFile) -> Storage {
        match file.resolve() {
            Ok(s) => s,
            Err(_) => panic!("storage config must resolve"),
        }
    }

    #[test]
    fn the_maintenance_tick_purges_idempotency_records_a_batch_at_a_time() {
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
    fn backup_settings_keep_backups_off_the_disk_they_protect() {
        let data = Path::new("/var/lib/sentinel");
        let parse = |text: &str| toml::from_str::<BackupFile>(text).unwrap();
        assert!(parse("dir = '/mnt/backup'").check(data).is_ok());
        for bad in [
            "dir = 'backup'",
            "dir = '/var/lib/sentinel/backups'",
            "dir = '/var/lib'",
            "dir = '/mnt/backup'\ninterval_secs = 60",
            "dir = '/mnt/backup'\ninterval_secs = 700000",
            "dir = '/mnt/backup'\nkeep = 0",
        ] {
            assert!(parse(bad).check(data).is_err(), "{bad}");
        }
        assert!(toml::from_str::<BackupFile>("dir = '/x'\nextra = 1").is_err());
    }

    #[test]
    fn worker_bootstrap_settings_need_a_dialable_controller_and_the_controllers_own_tailcat() {
        let parse = |text: &str| toml::from_str::<WorkerBootstrapFile>(text).unwrap();
        let tailcat_on = TailcatFile {
            enabled: Some(true),
            ..TailcatFile::default()
        };
        let base = "controller = '10.0.0.5:7443'\nrelease_url = 'https://r.example.test/0.1.0'\nrelease_sums = '/etc/sentinel/SHA256SUMS'\n";
        assert!(parse(base).check(None).is_ok());
        let with_helper =
            format!("{base}[tailcat]\nx86_64_url = 'https://r.example.test/tailcat'\n");
        assert!(parse(&with_helper).check(Some(&tailcat_on)).is_ok());
        // A script that hands out the controller's Tailcat address needs the controller to serve one.
        assert!(parse(&with_helper).check(None).is_err());
        assert!(
            parse(&with_helper)
                .check(Some(&TailcatFile::default()))
                .is_err()
        );
        for bad in [
            "controller = 'ci.example.test:7443'\nrelease_url = 'https://r.example.test'\nrelease_sums = '/s'\n",
            "controller = '10.0.0.5:7443'\nrelease_url = 'https://r.example.test'\nrelease_sums = 'SHA256SUMS'\n",
        ] {
            assert!(parse(bad).check(None).is_err(), "{bad}");
        }
        // No arm64 digest is pinned by this build, so an arm64 helper must state its own.
        let arm_without_digest =
            format!("{base}[tailcat]\naarch64_url = 'https://r.example.test/tailcat-arm'\n");
        assert!(parse(&arm_without_digest).check(Some(&tailcat_on)).is_err());
        let empty_helper = format!("{base}[tailcat]\nversion = '0.6.0'\n");
        assert!(parse(&empty_helper).check(Some(&tailcat_on)).is_err());
        assert!(
            toml::from_str::<WorkerBootstrapFile>(&format!("{base}extra = 1")).is_err(),
            "unknown keys are refused"
        );
    }

    #[test]
    fn s3_settings_are_validated_before_anything_starts() {
        let parse = |text: &str| toml::from_str::<S3File>(text);
        let base = "endpoint = 'https://s3.example.com'
region = 'eu-1'
bucket = 'ci'
credentials_file = '/etc/sentinel/s3'
";
        assert!(parse(base).unwrap().check().is_ok());
        for bad in [
            "part_bytes = 1048576
",
            "part_bytes = 1073741824
",
            "backlog_bytes = 0
",
        ] {
            assert!(
                parse(&format!("{base}{bad}")).unwrap().check().is_err(),
                "{bad}"
            );
        }
        let relative = base.replace("/etc/sentinel/s3", "s3.credentials");
        assert!(parse(&relative).unwrap().check().is_err());
        assert!(
            parse(&format!(
                "{base}ca_file = 'ca.pem'
"
            ))
            .unwrap()
            .check()
            .is_err()
        );
        assert!(
            parse(&format!(
                "{base}unknown = 1
"
            ))
            .is_err(),
            "unknown keys refused"
        );
        assert!(
            parse(
                "endpoint = 'https://x'
"
            )
            .is_err(),
            "credentials are required"
        );
    }

    #[test]
    fn storage_defaults_and_validation() {
        let resolved = resolve_ok(StorageFile::default());
        let marks = marks_ok(&resolved, 64 << 30);
        assert_eq!(
            marks,
            sentinel_store::space::Watermarks {
                reserve: 1 << 30,
                low: 2 << 30,
                high: 4 << 30,
                floor: (1 << 30) / 8,
            }
        );
        let big = marks_ok(&resolved, 1_000_000_000_000);
        assert_eq!(big.reserve, 1_000_000_000_000 / 64);
        assert_eq!(big.low, 1_000_000_000_000 / 32);
        assert_eq!(big.high, 2 * big.low);
        assert_eq!(marks_ok(&resolved, 1 << 30).reserve, 1 << 30);
        assert_eq!(marks_ok(&resolved, 1 << 50).reserve, 16 << 30);
        let d = resolved.deployment;
        assert_eq!(d.quota_bytes, 0);
        assert_eq!(d.tenant_quota_bytes, 0);
        assert_eq!(d.log_retention_ms, 14 * 86_400_000);
        assert_eq!(d.artifact_retention_ms, 90 * 86_400_000);
        assert_eq!(d.run_artifact_bytes, 16 << 30);
        assert_eq!(resolved.attempt_log_bytes, 256 << 20);
        assert_eq!(resolved.sweep_interval_ms, 300_000);

        for (reserve, low, high) in [
            (Some(1u64 << 20), None, None),
            (Some(2 << 30), Some((2 << 30) - 1), None),
            (None, Some(2 << 30), Some(1 << 30)),
        ] {
            let file = StorageFile {
                reserve_bytes: reserve,
                low_watermark_bytes: low,
                high_watermark_bytes: high,
                ..Default::default()
            };
            assert!(file.resolve().is_err(), "{reserve:?} {low:?} {high:?}");
        }
        let low_under_sized = StorageFile {
            low_watermark_bytes: Some((1 << 30) - 1),
            ..Default::default()
        };
        assert!(resolve_ok(low_under_sized).marks(64 << 30).is_err());
        for file in [
            StorageFile {
                sweep_interval_secs: Some(4),
                ..Default::default()
            },
            StorageFile {
                sweep_interval_secs: Some(86_401),
                ..Default::default()
            },
            StorageFile {
                log_retention_secs: Some(3_599),
                ..Default::default()
            },
            StorageFile {
                log_retention_secs: Some(31_622_401),
                ..Default::default()
            },
            StorageFile {
                artifact_retention_secs: Some(3_599),
                ..Default::default()
            },
            StorageFile {
                run_artifact_bytes: Some(1),
                ..Default::default()
            },
            StorageFile {
                attempt_log_bytes: Some(5 << 30),
                ..Default::default()
            },
            StorageFile {
                quota_bytes: Some(u64::MAX),
                ..Default::default()
            },
        ] {
            assert!(file.resolve().is_err());
        }
        let file = StorageFile {
            reserve_bytes: Some(1 << 30),
            low_watermark_bytes: Some(2 << 30),
            high_watermark_bytes: Some(3 << 30),
            quota_bytes: Some(1 << 41),
            tenant_quota_bytes: Some(1 << 40),
            log_retention_secs: Some(7_200),
            artifact_retention_secs: Some(86_400),
            run_artifact_bytes: Some(1 << 30),
            attempt_log_bytes: Some(64 << 20),
            sweep_interval_secs: Some(60),
        };
        let resolved = resolve_ok(file);
        assert_eq!(marks_ok(&resolved, 1 << 50).high, 3 << 30);
        assert_eq!(resolved.deployment.quota_bytes, 1 << 41);
        assert_eq!(resolved.deployment.tenant_quota_bytes, 1 << 40);
        assert_eq!(resolved.deployment.log_retention_ms, 7_200_000);
        assert_eq!(resolved.deployment.artifact_retention_ms, 86_400_000);
        assert_eq!(resolved.deployment.run_artifact_bytes, 1 << 30);
        assert_eq!(resolved.attempt_log_bytes, 64 << 20);
    }

    fn settled(file: MailFile, env: &dyn Fn(&str) -> Option<String>) -> MailSettings {
        match file.resolve(env) {
            Ok(Some(settings)) => settings,
            _ => panic!("expected an email configuration"),
        }
    }

    fn mail(text: &str) -> MailFile {
        toml::from_str(text).unwrap()
    }

    fn no_env(_: &str) -> Option<String> {
        None
    }

    #[test]
    fn email_is_off_without_a_key_and_a_sender_and_half_of_it_is_an_error() {
        assert_eq!(MailFile::default().resolve(&no_env).ok(), Some(None));
        for file in [
            "api_key_file = '/etc/sentinel/resend-key'",
            "from = 'ci@example.com'",
        ] {
            assert!(mail(file).resolve(&no_env).is_err(), "{file}");
        }
        let stray =
            |name: &str| (name == "SENTINEL_EMAIL_FROM").then(|| "ci@example.com".to_owned());
        assert!(MailFile::default().resolve(&stray).is_err());
        let blank = |_: &str| Some(String::new());
        let resolved = settled(
            mail("api_key_file = '/etc/sentinel/resend-key'\nfrom = 'ci@example.com'"),
            &blank,
        );
        assert_eq!(resolved.from, "ci@example.com");
    }

    #[test]
    fn the_environment_wins_and_the_key_is_only_ever_a_file() {
        let base = "api_key_file = '/etc/sentinel/resend-key'\nfrom = 'ci@example.com'\n";
        let env = |name: &str| match name {
            "SENTINEL_RESEND_API_KEY_FILE" => Some("/run/secrets/resend".to_owned()),
            "SENTINEL_EMAIL_FROM" => Some("Sentinel CI <ci@example.org>".to_owned()),
            _ => None,
        };
        let merged = settled(mail(base), &env);
        assert_eq!(
            merged.api_key_file.as_path(),
            Path::new("/run/secrets/resend")
        );
        assert_eq!(merged.from, "Sentinel CI <ci@example.org>");
        assert!(toml::from_str::<MailFile>("api_key = 're_abc'").is_err());
        assert!(toml::from_str::<MailFile>("resend_api_key = 're_abc'").is_err());
    }

    #[test]
    fn a_bad_email_setting_is_refused_without_echoing_it() {
        let key = "api_key_file = '/etc/sentinel/resend-key'\n";
        let error = mail("api_key_file = 'relative/resend-key'\nfrom = 'ci@example.com'")
            .resolve(&no_env)
            .unwrap_err();
        assert!(
            !error.message.contains("relative/resend-key"),
            "{}",
            error.message
        );
        let mut bad = vec!["", "nobody"];
        #[cfg(feature = "server")]
        bad.extend([
            "a@@b.example",
            "@example.com",
            "ci@",
            "c i@example.com",
            "Name <ci@example.com",
            "Evil\\nBcc: x@y.z <ci@example.com>",
        ]);
        for bad_from in bad {
            let file = mail(&format!("{key}from = '{bad_from}'"));
            let error = file.resolve(&no_env).unwrap_err();
            assert!(
                [
                    "the sender must be `ci@example.com` or `Sentinel <ci@example.com>`",
                    "the sender must be `addr@example.com` or `Name <addr@example.com>`",
                ]
                .contains(&error.message.as_str()),
                "{}",
                error.message
            );
        }
        assert!(toml::from_str::<MailFile>("hots = 'x'").is_err());
        assert!(toml::from_str::<MailFile>("host = 'x'").is_err());
    }
}
