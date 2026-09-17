//! The pinned Tailcat helper (Q06): an optional, NAT-traversing transport for
//! exactly one endpoint — this deployment's Sentinel link port.
//!
//! Tailcat's upstream is Go, so the adapter is a **pinned helper process**, not
//! a reimplementation: the executable is hashed against [`PINNED_SHA256`]
//! before *every* execution, and a mismatch refuses to run it rather than
//! running something else. The helper carries only the link port — the server
//! side `serve`s that one port, the worker side `forward`s it to loopback —
//! never a mesh-wide `serve all`, an exit node, or a shell/file mode.
//!
//! Identities are keys on disk, not accounts: [`ensure_key`] creates the
//! helper's key under `<data_dir>/tailcat` (owner-only, persisted across
//! restarts so the address is stable) and records the `nodekey:` the helper
//! prints, which is what the controller's allow list and the enrollment
//! handshake exchange. Key material and `tc…` addresses are credentials:
//! [`NodeKey`] and [`Address`] redact themselves in `Debug`/`Display`, so a
//! diagnostic that prints them cannot leak them; `expose` is the deliberate,
//! operator-facing accessor.
//!
//! Supervision is own-process, not library: [`start_server`] and
//! [`start_forward`] spawn a thread that starts the helper, restarts it when
//! it dies (or exits after failing to connect), and takes it down on
//! [`Server::shutdown`] / [`Forward::shutdown`]. A worker also re-proves the
//! tunnel on an interval — `tailcat ping` plus a connect through the forward —
//! and replaces a helper whose connect path stopped working; an open loopback
//! port by itself is not health. When `tailcat.enabled` is false (or the
//! section is absent) none of this runs and the link uses direct TLS.

use std::{
    fmt, fs, io,
    io::{BufRead, BufReader, Read, Write},
    net::{Ipv4Addr, SocketAddr, TcpStream},
    path::{Component, Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    sync::{
        Arc, Condvar, Mutex,
        mpsc::{self, RecvTimeoutError},
    },
    thread,
    time::{Duration, Instant},
};

use serde::Deserialize;
use sha2::{Digest, Sha256};

/// The upstream helper version this adapter is written against.
pub const PINNED_VERSION: &str = "0.6.0";
/// SHA-256 of the pinned helper build. The executable is hashed before every
/// execution; a mismatch refuses to run it. Operators upgrading the helper
/// change this value deliberately (and re-run the probes), never implicitly.
pub const PINNED_SHA256: &str = "d46582137d21f03d15345e2be425d6317d49e5b8c8bb4f6fc56037f4c08cce73";
/// The link port a helper carries when the configuration says nothing else.
pub const DEFAULT_LINK_PORT: u16 = 7443;
/// The file under the data directory listing the worker node keys the
/// controller's helper accepts, one `nodekey:…` per line (`#` comments and
/// blank lines allowed). Absent means no worker is allowed over Tailcat yet.
pub const ALLOW_LIST_FILE: &str = "tailcat-allow";

/// Keys and the helper's own state live here, under the data directory.
const KEY_DIR: &str = "tailcat";
/// The helper's key name; `HOME` is pointed at [`KEY_DIR`], so this is also
/// which key `serve`/`forward`/`ping` use.
const KEY_NAME: &str = "default";
/// A fresh helper must report readiness (an address, or a working tunnel)
/// within this long; one that never connects is replaced.
const READY_DEADLINE: Duration = Duration::from_secs(60);
/// A worker re-proves the tunnel this often.
const PROBE_EVERY: Duration = Duration::from_secs(30);
/// Reconnect back-off bounds for helper restarts.
const RESTART_MIN: Duration = Duration::from_secs(1);
const RESTART_MAX: Duration = Duration::from_secs(30);
/// `ping` and the loopback connect are both bounded.
const PING_TIMEOUT: Duration = Duration::from_secs(10);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const GENKEY_TIMEOUT: Duration = Duration::from_secs(30);
const VERSION_TIMEOUT: Duration = Duration::from_secs(5);
/// How often a supervising thread looks at its stop flag while reading output.
const POLL: Duration = Duration::from_millis(100);
/// One output line and the total captured output of a bounded run, capped so a
/// helper cannot grow our memory.
const LINE_CAP: u64 = 8 * 1024;
const OUTPUT_CAP: u64 = 64 * 1024;
/// The allow list is operator-managed and small.
const ALLOW_LIST_CAP: u64 = 64 * 1024;

/// Argument words that would widen the helper past "carry this one link port":
/// mesh-wide serving, an exit node, a shell, its file transfer mode, or peer
/// authentication turned off. Refused wherever they appear in an argument.
const FORBIDDEN: [&str; 5] = ["all", "exit-node", "ssh", "files", "no-auth-ssh"];

/// Which side of the link a helper serves.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// The controller: `serve` the link port, `--allow` only enrolled keys.
    Controller,
    /// The worker: `forward` the controller's address to loopback.
    Worker,
}

/// The `[tailcat]` section of a server or worker configuration file.
///
/// The defaults keep an operator who writes a section but forgets a field
/// honest: `enabled` and `binary` have to be stated, the digest defaults to
/// the pinned build, and `listen_port` defaults to the link port.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TailcatConfig {
    /// Start the helper. `false` leaves the link on direct TLS.
    #[serde(default)]
    pub enabled: bool,
    /// Absolute path to the helper executable.
    #[serde(default = "default_binary")]
    pub binary: PathBuf,
    /// SHA-256 of the executable; default is the pinned v0.6.0 build.
    #[serde(default = "default_sha256")]
    pub sha256: String,
    /// Operator-owned DERP map, passed to the helper as `--derpmap-url=…`.
    /// `https` only: the map is trust material and must not arrive in clear.
    #[serde(default)]
    pub derpmap_url: Option<String>,
    /// Name of the region to use in that map (`--region=…`). When unset the
    /// controller asks the helper for a fixed region, so its address survives
    /// restarts.
    #[serde(default)]
    pub region: Option<String>,
    /// The Sentinel link port the helper carries: the controller serves it,
    /// the worker binds it on loopback and forwards the controller's port to
    /// it.
    #[serde(default = "default_link_port")]
    pub listen_port: u16,
}

fn default_binary() -> PathBuf {
    PathBuf::from("tailcat")
}
fn default_sha256() -> String {
    PINNED_SHA256.to_owned()
}
fn default_link_port() -> u16 {
    DEFAULT_LINK_PORT
}

/// A worker's Tailcat public key (`nodekey:` and 64 hex characters).
///
/// Public keys are identity, not secrets, but they select who may connect, so
/// they self-redact: `Debug`/`Display` never show the body. [`expose`] is the
/// deliberate raw accessor for argv and the one operator-facing line.
///
/// [`expose`]: NodeKey::expose
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NodeKey(String);

impl NodeKey {
    /// Parses the helper's printed form; the body is canonicalised to lower
    /// case so comparisons and allow lists are stable.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        let body = text.trim().strip_prefix("nodekey:")?;
        if body.len() != 64 || !body.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return None;
        }
        Some(Self(format!("nodekey:{}", body.to_ascii_lowercase())))
    }

    /// The raw text. Treat what it returns as a credential.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for NodeKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NodeKey(<redacted>)")
    }
}

impl fmt::Display for NodeKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("nodekey:<redacted>")
    }
}

/// A helper address (`tc` and at least 20 address characters).
///
/// The address is how peers find this node, so it is treated like a
/// credential too: redacting `Debug`/`Display`, raw only through [`expose`].
///
/// [`expose`]: Address::expose
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Address(String);

impl Address {
    /// Parses the address token the helper prints on its `listening` line.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        let text = text.trim().trim_end_matches([',', '.', ')', ']']);
        if text.len() > 128 {
            return None;
        }
        let body = text.strip_prefix("tc")?;
        if body.len() < 20
            || !body
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
        {
            return None;
        }
        Some(Self(text.to_owned()))
    }

    /// The raw text. Treat what it returns as a credential.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Address(tc<redacted>)")
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("tc<redacted>")
    }
}

/// What went wrong with the helper. Carries no key material and no `tc…`
/// address: every variant is either static text or a value we produced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// The helper is disabled, missing, misconfigured or not answering.
    Unavailable(String),
    /// The executable is not the pinned build; nothing was executed.
    Checksum { expected: String, found: String },
    /// An argument asked for a mode the helper must never use.
    Refused(&'static str),
    /// The helper could not be started or reaped.
    Spawn(String),
    /// The helper exited on its own; the supervisor restarts it.
    Exited(Option<i32>),
    /// A bounded helper operation did not finish in time.
    Timeout(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable(what) => write!(f, "tailcat: {what}"),
            Self::Checksum { expected, found } => write!(
                f,
                "tailcat: helper sha256 {found} does not match the pin {expected}; refusing to run it"
            ),
            Self::Refused(word) => write!(f, "tailcat: refusing an argument that names '{word}'"),
            Self::Spawn(what) => write!(f, "tailcat: cannot run the helper: {what}"),
            Self::Exited(Some(code)) => write!(f, "tailcat: helper exited with code {code}"),
            Self::Exited(None) => f.write_str("tailcat: helper was terminated"),
            Self::Timeout(what) => write!(f, "tailcat: {what} timed out"),
        }
    }
}

impl std::error::Error for Error {}

/// Module result: helper trouble is reported as [`Error`], not as the link's
/// own [`Error`](crate::Error), because a broken transport must not be
/// confused with a broken session. The error defaults to [`Error`].
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// What a supervisor knows about its helper, safe to print: identities are
/// redacted by their own `Debug`, and nothing else is verbatim helper output.
#[derive(Clone, Debug, Default)]
pub struct Telemetry {
    /// The helper process, while one is running.
    pub pid: Option<u32>,
    /// The helper reported an address (server) or a working tunnel (worker).
    pub ready: bool,
    /// How many times the helper was (re)started after the first attempt.
    pub restarts: u64,
    /// The helper's own version line, if it answered `--version`.
    pub version: Option<String>,
    /// The address the server's helper advertises, once it has one.
    pub address: Option<Address>,
    /// The most recent failure; cleared when the helper is ready again.
    pub problem: Option<Error>,
}

/// Starts the controller's helper: `serve` exactly the link port, `--allow`
/// only the given worker node keys.
///
/// The key and allow list are read once here; call [`Server::set_allow`] when
/// the fleet changes. Returns as soon as supervision runs — the address
/// arrives asynchronously, so [`Server::wait_ready`] is the way to obtain it.
pub fn start_server(config: &TailcatConfig, data_dir: &Path, allow: &[NodeKey]) -> Result<Server> {
    let shared = prepare(config, data_dir, Role::Controller, normalize(allow), None)?;
    Ok(Server {
        run: Runner::spawn(shared, None),
    })
}

/// Starts the worker's helper: `forward` the controller's address to loopback
/// and re-prove the tunnel on its interval (30 s by default).
///
/// The worker connects to [`Forward::local_addr`], not to the address itself.
pub fn start_forward(
    config: &TailcatConfig,
    data_dir: &Path,
    controller: &Address,
) -> Result<Forward> {
    start_forward_every(config, data_dir, controller, PROBE_EVERY)
}

/// As [`start_forward`], with the tunnel probe interval stated. Tests use a
/// short interval; a deployment tuning for a slow relay may use a long one.
pub fn start_forward_every(
    config: &TailcatConfig,
    data_dir: &Path,
    controller: &Address,
    probe_every: Duration,
) -> Result<Forward> {
    let shared = prepare(
        config,
        data_dir,
        Role::Worker,
        Vec::new(),
        Some(controller.clone()),
    )?;
    Ok(Forward {
        run: Runner::spawn(shared, Some(probe_every)),
    })
}

/// Creates the helper's key if it does not exist yet and returns its node key.
///
/// The key persists under `<data_dir>/tailcat` (owner-only) so the address is
/// stable across restarts; `genkey` is not re-run once a key is recorded.
/// The worker needs this before its first hello, so the node key can travel
/// with enrollment; the controller needs it only to have an identity to serve.
pub fn ensure_key(config: &TailcatConfig, data_dir: &Path, role: Role) -> Result<NodeKey> {
    let network = config.network(data_dir)?;
    ensure(&network, role)
}

/// Reads the controller's allow list: one worker node key per line, `#`
/// comments and blank lines allowed. A missing file is an empty list (no
/// worker may use Tailcat yet), not an error; a malformed line names its line
/// number and nothing else.
pub fn allow_list(data_dir: &Path) -> Result<Vec<NodeKey>> {
    let path = data_dir.join(ALLOW_LIST_FILE);
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => {
            return Err(Error::Unavailable(format!(
                "cannot inspect the allow list: {error}"
            )));
        }
    };
    if !metadata.is_file() {
        return Err(Error::Unavailable(
            "the tailcat allow list is not a regular file".to_owned(),
        ));
    }
    if metadata.len() > ALLOW_LIST_CAP {
        return Err(Error::Unavailable(
            "the tailcat allow list is larger than 64 KiB".to_owned(),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(Error::Unavailable(
                "the tailcat allow list is not owner-only".to_owned(),
            ));
        }
    }
    let text = fs::read_to_string(&path).map_err(|error| {
        Error::Unavailable(format!("cannot read the tailcat allow list: {error}"))
    })?;
    let mut keys = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let key = NodeKey::parse(line).ok_or_else(|| {
            Error::Unavailable(format!(
                "tailcat allow list line {} is not a nodekey",
                index + 1
            ))
        })?;
        keys.push(key);
    }
    keys.sort();
    keys.dedup();
    Ok(keys)
}

/// The controller's supervised helper.
pub struct Server {
    run: Runner,
}

impl Server {
    /// The address the helper advertises, once it has reported one.
    #[must_use]
    pub fn address(&self) -> Option<Address> {
        self.run.state().address.clone()
    }

    /// Waits for the advertised address, bounded. The caller logs it (as a
    /// credential) for enrollment.
    pub fn wait_ready(&self, within: Duration) -> Result<Address> {
        let deadline = Instant::now() + within;
        loop {
            if let Some(address) = self.address() {
                return Ok(address);
            }
            if self.run.shared.stopped() {
                return Err(Error::Unavailable(
                    "the tailcat helper was shut down".to_owned(),
                ));
            }
            if Instant::now() >= deadline {
                return Err(Error::Timeout("no address was reported"));
            }
            thread::sleep(POLL);
        }
    }

    /// The link port the helper serves.
    #[must_use]
    pub fn port(&self) -> u16 {
        self.run.shared.port
    }

    /// Replaces the allow list. When the set actually changes the helper is
    /// restarted with the wider (or narrower) list — existing tunnels are
    /// briefly interrupted and the link reconnects on its own.
    pub fn set_allow(&self, allow: &[NodeKey]) {
        let wanted = normalize(allow);
        {
            let mut current = self.run.shared.allow.lock().expect("tailcat allow");
            if *current == wanted {
                return;
            }
            *current = wanted;
        }
        self.run.shared.kill();
    }

    /// A snapshot for diagnostics.
    #[must_use]
    pub fn telemetry(&self) -> Telemetry {
        self.run.telemetry()
    }

    /// Stops the helper and waits for supervision to end. Idempotent.
    pub fn shutdown(&self) {
        self.run.shutdown();
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.shutdown();
    }
}

impl fmt::Debug for Server {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Server")
            .field("port", &self.run.shared.port)
            .field("telemetry", &self.telemetry())
            .finish_non_exhaustive()
    }
}

/// The worker's supervised helper.
pub struct Forward {
    run: Runner,
}

impl Forward {
    /// Where the worker dials the controller: loopback, never a wider bind.
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        SocketAddr::from((Ipv4Addr::LOCALHOST, self.run.shared.port))
    }

    /// Proves the tunnel: a bounded `ping` of the controller's address, then a
    /// connect through the forward. Returns the round trip; a listening
    /// loopback port alone is not health.
    pub fn probe(&self) -> Result<Duration> {
        probe_once(&self.run.shared)
    }

    /// Replaces the helper process now; supervision starts the next one.
    pub fn restart(&self) {
        self.run.shared.kill();
    }

    /// A snapshot for diagnostics.
    #[must_use]
    pub fn telemetry(&self) -> Telemetry {
        self.run.telemetry()
    }

    /// Stops the helper and waits for supervision to end. Idempotent.
    pub fn shutdown(&self) {
        self.run.shutdown();
    }
}

impl Drop for Forward {
    fn drop(&mut self) {
        self.shutdown();
    }
}

impl fmt::Debug for Forward {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Forward")
            .field("local_addr", &self.local_addr())
            .field("telemetry", &self.telemetry())
            .finish_non_exhaustive()
    }
}

/// A validated helper location: what every execution needs.
struct Network {
    binary: PathBuf,
    digest: [u8; 32],
    keydir: PathBuf,
    derpmap: Option<String>,
    region: Option<String>,
}

impl TailcatConfig {
    /// Checks the configuration and prepares the key directory. Refuses to
    /// start anything when the section is disabled: direct TLS is the
    /// fallback, not a silent substitution.
    fn network(&self, data_dir: &Path) -> Result<Network> {
        if !self.enabled {
            return Err(Error::Unavailable(
                "tailcat is disabled; the link uses direct TLS".to_owned(),
            ));
        }
        if !data_dir.is_absolute() {
            return Err(Error::Unavailable(
                "the data directory must be absolute".to_owned(),
            ));
        }
        if !self.binary.is_absolute() {
            return Err(Error::Unavailable(
                "tailcat.binary must be an absolute path".to_owned(),
            ));
        }
        if self
            .binary
            .components()
            .any(|part| matches!(part, Component::ParentDir))
        {
            return Err(Error::Unavailable(
                "tailcat.binary must not contain '..'".to_owned(),
            ));
        }
        let metadata = fs::metadata(&self.binary).map_err(|error| {
            Error::Unavailable(format!("cannot inspect tailcat.binary: {error}"))
        })?;
        if !metadata.is_file() {
            return Err(Error::Unavailable(
                "tailcat.binary is not a regular file".to_owned(),
            ));
        }
        let digest = parse_hex(&self.sha256).ok_or_else(|| {
            Error::Unavailable("tailcat.sha256 must be 64 hexadecimal characters".to_owned())
        })?;
        if let Some(url) = &self.derpmap_url
            && (!url.starts_with("https://")
                || url.len() > 512
                || url
                    .chars()
                    .any(|character| character.is_whitespace() || character.is_control()))
        {
            return Err(Error::Unavailable(
                "tailcat.derpmap_url must be an https URL of at most 512 characters".to_owned(),
            ));
        }
        if let Some(region) = &self.region {
            let shaped = !region.is_empty()
                && region.len() <= 64
                && !region.starts_with('-')
                && region
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'));
            if !shaped {
                return Err(Error::Unavailable(
                    "tailcat.region must be 1-64 characters of letters, digits, '.', '_' or '-'"
                        .to_owned(),
                ));
            }
        }
        if self.listen_port == 0 {
            return Err(Error::Unavailable(
                "tailcat.listen_port must not be zero".to_owned(),
            ));
        }
        let keydir = data_dir.join(KEY_DIR);
        prepare_keydir(&keydir)?;
        Ok(Network {
            binary: self.binary.clone(),
            digest,
            keydir,
            derpmap: self.derpmap_url.clone(),
            region: self.region.clone(),
        })
    }
}

impl Network {
    /// Verifies the pin and builds a helper invocation. Every execution goes
    /// through here, so nothing unverified ever runs.
    fn command(&self, args: &[String]) -> Result<Command> {
        verify(&self.binary, &self.digest)?;
        check_argv(args)?;
        let mut command = Command::new(&self.binary);
        command
            .env("HOME", &self.keydir)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .args(args);
        Ok(command)
    }
}

/// One supervisor: what it shares with its threads, and the threads.
struct Runner {
    shared: Arc<Shared>,
    threads: Mutex<Vec<thread::JoinHandle<()>>>,
}

impl Runner {
    fn spawn(shared: Arc<Shared>, probing: Option<Duration>) -> Self {
        let mut threads = Vec::new();
        threads.push(thread::spawn({
            let shared = Arc::clone(&shared);
            move || supervise(shared)
        }));
        if let Some(every) = probing {
            threads.push(thread::spawn({
                let shared = Arc::clone(&shared);
                move || watch_tunnel(shared, every)
            }));
        }
        Self {
            shared,
            threads: Mutex::new(threads),
        }
    }

    fn state(&self) -> std::sync::MutexGuard<'_, Telemetry> {
        self.shared.state.lock().expect("tailcat state")
    }

    fn telemetry(&self) -> Telemetry {
        self.state().clone()
    }

    fn shutdown(&self) {
        self.shared.halt();
        let threads: Vec<_> = self
            .threads
            .lock()
            .expect("tailcat threads")
            .drain(..)
            .collect();
        for thread in threads {
            let _ = thread.join();
        }
    }
}

/// The stop flag and the live child, under one lock: taking the flag and
/// killing the process is atomic, so a stopping supervisor cannot be missed.
struct Stop {
    stopped: bool,
    child: Option<Child>,
}

struct Shared {
    network: Network,
    role: Role,
    port: u16,
    controller: Option<Address>,
    /// Canonical node keys, sorted and deduplicated.
    allow: Mutex<Vec<String>>,
    state: Mutex<Telemetry>,
    stop: Mutex<Stop>,
    wake: Condvar,
}

impl Shared {
    fn stopped(&self) -> bool {
        self.stop.lock().expect("tailcat stop").stopped
    }

    /// Waits up to `timeout`; `false` means the supervisor was asked to stop.
    fn wait(&self, timeout: Duration) -> bool {
        let stop = self.stop.lock().expect("tailcat stop");
        if stop.stopped {
            return false;
        }
        let (stop, _) = self.wake.wait_timeout(stop, timeout).expect("tailcat wake");
        !stop.stopped
    }

    /// Ask the supervisor to end, killing whatever it is running.
    fn halt(&self) {
        let mut stop = self.stop.lock().expect("tailcat stop");
        stop.stopped = true;
        if let Some(child) = stop.child.as_mut() {
            let _ = child.kill();
        }
        self.wake.notify_all();
    }

    /// Kill the current child without stopping: supervision starts another.
    fn kill(&self) {
        let mut stop = self.stop.lock().expect("tailcat stop");
        if let Some(child) = stop.child.as_mut() {
            let _ = child.kill();
        }
    }

    fn fail(&self, problem: Error) {
        self.state.lock().expect("tailcat state").problem = Some(problem);
    }

    /// The argv for this role. This is the only place a helper mode is chosen,
    /// so it is also where "only the link port" stays true.
    fn args(&self) -> Vec<String> {
        let mut args = Vec::new();
        match self.role {
            Role::Controller => {
                args.push("serve".to_owned());
                for key in self.allow.lock().expect("tailcat allow").iter() {
                    args.push(format!("--allow={key}"));
                }
                if let Some(url) = &self.network.derpmap {
                    args.push(format!("--derpmap-url={url}"));
                }
                args.push(self.port.to_string());
            }
            Role::Worker => {
                args.push("forward".to_owned());
                args.push("--bind=127.0.0.1".to_owned());
                if let Some(url) = &self.network.derpmap {
                    args.push(format!("--derpmap-url={url}"));
                }
                let controller = self
                    .controller
                    .as_ref()
                    .expect("a worker helper has a controller address");
                args.push(controller.expose().to_owned());
                args.push(format!("{}:{}", self.port, self.port));
            }
        }
        args
    }

    /// One line of helper output. Never stored verbatim: only the address, and
    /// only in its redacting form.
    fn observe(&self, line: &str) {
        match self.role {
            Role::Controller => {
                if !contains_ascii_ci(line, "listening") {
                    return;
                }
                let Some(address) = line.split_whitespace().rev().find_map(Address::parse) else {
                    return;
                };
                let mut state = self.state.lock().expect("tailcat state");
                state.address = Some(address);
                state.ready = true;
                state.problem = None;
            }
            Role::Worker => {
                if contains_ascii_ci(line, "forwarding") {
                    let mut state = self.state.lock().expect("tailcat state");
                    state.ready = true;
                    state.problem = None;
                }
            }
        }
    }
}

/// Prepares config + keys + telemetry, then hands the threads their handle.
fn prepare(
    config: &TailcatConfig,
    data_dir: &Path,
    role: Role,
    allow: Vec<String>,
    controller: Option<Address>,
) -> Result<Arc<Shared>> {
    let network = config.network(data_dir)?;
    ensure(&network, role)?;
    let version = version_of(&network);
    Ok(Arc::new(Shared {
        network,
        role,
        port: config.listen_port,
        controller,
        allow: Mutex::new(allow),
        state: Mutex::new(Telemetry {
            version,
            ..Telemetry::default()
        }),
        stop: Mutex::new(Stop {
            stopped: false,
            child: None,
        }),
        wake: Condvar::new(),
    }))
}

/// One helper's lifetime, restarted until stopped: a death (or an exit after a
/// failed connect) is a restart with bounded back-off, not a give-up.
fn supervise(shared: Arc<Shared>) {
    let mut backoff = RESTART_MIN;
    let mut restarted = false;
    loop {
        if !shared.wait(Duration::ZERO) {
            return;
        }
        if restarted {
            let mut state = shared.state.lock().expect("tailcat state");
            state.restarts += 1;
        }
        restarted = true;
        match run_child(&shared) {
            Ok(()) => backoff = RESTART_MIN,
            Err(problem) => {
                if !shared.stopped() {
                    shared.fail(problem);
                }
                backoff = (backoff * 2).min(RESTART_MAX);
            }
        }
        if !shared.wait(backoff) {
            return;
        }
    }
}

/// Spawns the helper once, follows its output until it ends, and reaps it.
fn run_child(shared: &Arc<Shared>) -> Result<()> {
    let args = shared.args();
    let mut command = shared.network.command(&args)?;
    let mut child = command
        .spawn()
        .map_err(|error| Error::Spawn(error.to_string()))?;
    let (Some(stdout), Some(stderr)) = (child.stdout.take(), child.stderr.take()) else {
        return Err(Error::Spawn(
            "the helper's output was not captured".to_owned(),
        ));
    };
    let pid = child.id();
    {
        let mut state = shared.state.lock().expect("tailcat state");
        state.pid = Some(pid);
        state.ready = false;
    }
    shared.stop.lock().expect("tailcat stop").child = Some(child);

    let (lines, received) = mpsc::channel::<String>();
    let readers = [pump(stdout, lines.clone()), pump(stderr, lines)];
    let started = Instant::now();
    let mut expired = false;
    let mut closed = false;
    loop {
        if shared.stopped() {
            break;
        }
        match received.recv_timeout(POLL) {
            Ok(line) => shared.observe(&line),
            Err(RecvTimeoutError::Timeout) => {
                if exited(shared) {
                    break;
                }
                let late = !expired && started.elapsed() >= READY_DEADLINE;
                let ready = shared.state.lock().expect("tailcat state").ready;
                if late && !ready {
                    expired = true;
                    shared.fail(Error::Timeout("the helper never reported readiness"));
                    shared.kill();
                }
            }
            Err(RecvTimeoutError::Disconnected) => {
                closed = true;
                break;
            }
        }
    }

    let status = shared.stop.lock().expect("tailcat stop").child.take();
    // The supervisor never leaves a helper running: a stop may have arrived
    // while the child was being registered, in which case `halt` had nothing
    // to kill. Killing here (harmless once it has exited) closes that race,
    // so the wait below cannot outlast a shutdown.
    let status = status.map(|mut child| {
        let _ = child.kill();
        child.wait()
    });
    // The readers end when the helper's pipes close. When the child closed
    // them that has already happened; on a stop, anything it spawned may still
    // hold a pipe, and a shutdown must not wait that out — the readers are
    // left to end on their own.
    if closed {
        for reader in readers {
            let _ = reader.join();
        }
    }
    {
        let mut state = shared.state.lock().expect("tailcat state");
        state.pid = None;
        state.ready = false;
    }
    match status {
        None => Ok(()),
        Some(Ok(status)) if status.success() => Ok(()),
        Some(Ok(status)) => Err(Error::Exited(status.code())),
        Some(Err(error)) => Err(Error::Spawn(error.to_string())),
    }
}

/// Whether the helper has ended. `try_wait` reaps it, and the teardown's
/// `wait` then returns the same status. Pipes cannot be the only death
/// signal: anything the helper spawned can hold them open.
fn exited(shared: &Shared) -> bool {
    let mut stop = shared.stop.lock().expect("tailcat stop");
    match stop.child.as_mut() {
        Some(child) => !matches!(child.try_wait(), Ok(None)),
        None => true,
    }
}

/// Reads a helper pipe into lines for the supervisor. Capped both per line and
/// overall, and a pipe that cannot be read simply ends the reader.
fn pump<R: Read + Send + 'static>(pipe: R, lines: mpsc::Sender<String>) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let mut reader = BufReader::new(pipe);
        let mut buffer = Vec::new();
        loop {
            buffer.clear();
            match (&mut reader).take(LINE_CAP).read_until(b'\n', &mut buffer) {
                Ok(0) => break,
                Ok(_) => {
                    let line = String::from_utf8_lossy(&buffer).into_owned();
                    if lines.send(line).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    })
}

/// Re-proves a worker's tunnel on an interval; a helper whose connect path
/// stopped working is replaced rather than trusted because its port is bound.
fn watch_tunnel(shared: Arc<Shared>, every: Duration) {
    while shared.wait(every) {
        if probe_once(&shared).is_err() {
            shared.kill();
        }
    }
}

/// `ping` the controller, then connect through the forward. Both bounded.
fn probe_once(shared: &Shared) -> Result<Duration> {
    let started = Instant::now();
    let outcome = probe_tunnel(shared);
    let mut state = shared.state.lock().expect("tailcat state");
    match &outcome {
        Ok(_) => {
            state.ready = true;
            state.problem = None;
        }
        Err(problem) => {
            state.ready = false;
            state.problem = Some(problem.clone());
        }
    }
    outcome.map(|()| started.elapsed())
}

fn probe_tunnel(shared: &Shared) -> Result<()> {
    let controller = shared
        .controller
        .as_ref()
        .ok_or_else(|| Error::Unavailable("this role does not probe the tunnel".to_owned()))?;
    let mut args = vec![
        "ping".to_owned(),
        format!("--timeout={}s", PING_TIMEOUT.as_secs()),
    ];
    if let Some(url) = &shared.network.derpmap {
        args.push(format!("--derpmap-url={url}"));
    }
    args.push(controller.expose().to_owned());
    let captured = output_within(
        shared.network.command(&args)?,
        PING_TIMEOUT + CONNECT_TIMEOUT,
        &|| shared.stopped(),
    )?;
    if !captured.status.success() {
        return Err(Error::Unavailable(
            "ping did not reach the controller".to_owned(),
        ));
    }
    if shared.stopped() {
        return Err(Error::Unavailable("the helper was stopped".to_owned()));
    }
    let local = SocketAddr::from((Ipv4Addr::LOCALHOST, shared.port));
    let mut stream = TcpStream::connect_timeout(&local, CONNECT_TIMEOUT).map_err(|error| {
        Error::Unavailable(format!("the forward does not answer on loopback: {error}"))
    })?;
    // A byte at the TLS listener is not a message; it is proof the forward
    // carries data. The session over the same forward is the real health.
    let _ = stream.write_all(&[0]);
    Ok(())
}

/// Runs a bounded helper invocation and captures its output. A stop request
/// ends the wait at once, so shutting down never waits out a helper timeout.
fn output_within(
    mut command: Command,
    within: Duration,
    stop: &dyn Fn() -> bool,
) -> Result<Captured> {
    let mut child = command
        .spawn()
        .map_err(|error| Error::Spawn(error.to_string()))?;
    let (stdout, stderr) = (child.stdout.take(), child.stderr.take());
    let (Some(stdout), Some(stderr)) = (stdout, stderr) else {
        return Err(Error::Spawn(
            "the helper's output was not captured".to_owned(),
        ));
    };
    let (stdout, stderr) = (drain(stdout), drain(stderr));
    let deadline = Instant::now() + within;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if stop() => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(Error::Unavailable("the helper was stopped".to_owned()));
            }
            Ok(None) if Instant::now() < deadline => thread::sleep(POLL),
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(Error::Timeout("the helper did not finish"));
            }
            Err(error) => return Err(Error::Spawn(error.to_string())),
        }
    };
    Ok(Captured {
        status,
        stdout: stdout.join().unwrap_or_default(),
        stderr: stderr.join().unwrap_or_default(),
    })
}

struct Captured {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

fn drain<R: Read + Send + 'static>(pipe: R) -> thread::JoinHandle<Vec<u8>> {
    thread::spawn(move || {
        let mut buffer = Vec::new();
        let _ = pipe.take(OUTPUT_CAP).read_to_end(&mut buffer);
        buffer
    })
}

/// Creates the helper's key if needed and records the node key it printed.
fn ensure(network: &Network, role: Role) -> Result<NodeKey> {
    let record = network.keydir.join(format!("{KEY_NAME}.nodekey"));
    if let Some(key) = read_key(&record)? {
        return Ok(key);
    }
    let mut args = vec!["genkey".to_owned(), format!("--key={KEY_NAME}")];
    if role == Role::Worker {
        args.push("--client".to_owned());
    }
    match &network.region {
        Some(region) => args.push(format!("--region={region}")),
        // The controller's address has to survive restarts, so its region is
        // fixed unless the operator names one in their own DERP map.
        None if role == Role::Controller => args.push("--fixed-region".to_owned()),
        None => {}
    }
    if let Some(url) = &network.derpmap {
        args.push(format!("--derpmap-url={url}"));
    }
    let captured = output_within(network.command(&args)?, GENKEY_TIMEOUT, &|| false)?;
    if !captured.status.success() {
        return Err(Error::Unavailable(format!(
            "genkey did not create a key ({})",
            describe(&captured.status)
        )));
    }
    let mut text = String::from_utf8_lossy(&captured.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&captured.stderr));
    let key = find_nodekey(&text)
        .ok_or_else(|| Error::Unavailable("genkey printed no nodekey".to_owned()))?;
    tighten(&network.keydir, 0)?;
    record_key(&record, &key)?;
    Ok(key)
}

/// The node key is 64 hex characters after the prefix; nothing else in the
/// helper's output is read, and the output itself is never kept.
fn find_nodekey(text: &str) -> Option<NodeKey> {
    let prefix = "nodekey:";
    let mut rest = text;
    while let Some(index) = rest.find(prefix) {
        let candidate = &rest[index..];
        let end = candidate.len().min(prefix.len() + 64);
        if let Some(window) = candidate.get(..end)
            && let Some(key) = NodeKey::parse(window)
        {
            return Some(key);
        }
        rest = &rest[index + prefix.len()..];
    }
    None
}

fn version_of(network: &Network) -> Option<String> {
    let captured = output_within(
        network.command(&["--version".to_owned()]).ok()?,
        VERSION_TIMEOUT,
        &|| false,
    )
    .ok()?;
    if !captured.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&captured.stdout);
    let line = stdout.lines().next()?.trim();
    let printed: String = line
        .chars()
        .filter(|character| character.is_ascii_graphic() || *character == ' ')
        .take(80)
        .collect();
    if printed.is_empty() {
        None
    } else {
        Some(printed)
    }
}

fn read_key(path: &Path) -> Result<Option<NodeKey>> {
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(Error::Unavailable(format!(
                "cannot read the recorded nodekey: {error}"
            )));
        }
    };
    NodeKey::parse(&text).map(Some).ok_or_else(|| {
        Error::Unavailable(format!(
            "the recorded nodekey at {} is not a nodekey; remove it to generate a new identity",
            path.display()
        ))
    })
}

fn record_key(path: &Path, key: &NodeKey) -> Result<()> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|error| Error::Unavailable(format!("cannot record the nodekey: {error}")))?;
    file.write_all(key.expose().as_bytes())
        .and_then(|()| file.write_all(b"\n"))
        .map_err(|error| Error::Unavailable(format!("cannot record the nodekey: {error}")))?;
    tighten_file(path)
}

/// The key directory is the helper's `HOME`: it is created if needed and its
/// contents are owner-only, because the private key lives among them.
fn prepare_keydir(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return Err(Error::Unavailable(
                "the tailcat key directory is a symlink".to_owned(),
            ));
        }
        Ok(metadata) if !metadata.is_dir() => {
            return Err(Error::Unavailable(
                "the tailcat key path is not a directory".to_owned(),
            ));
        }
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            fs::create_dir_all(path).map_err(|error| {
                Error::Unavailable(format!("cannot create the tailcat key directory: {error}"))
            })?;
        }
        Err(error) => {
            return Err(Error::Unavailable(format!(
                "cannot inspect the tailcat key directory: {error}"
            )));
        }
    }
    tighten(path, 0)
}

/// Owner-only permissions, top-down, never following a symlink.
#[cfg(unix)]
fn tighten(path: &Path, depth: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    if depth > 4 {
        return Ok(());
    }
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        Error::Unavailable(format!("cannot inspect the tailcat key material: {error}"))
    })?;
    let kind = metadata.file_type();
    if kind.is_symlink() {
        return Ok(());
    }
    if kind.is_dir() {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|error| {
            Error::Unavailable(format!(
                "cannot restrict the tailcat key directory: {error}"
            ))
        })?;
        let entries = fs::read_dir(path).map_err(|error| {
            Error::Unavailable(format!("cannot list the tailcat key directory: {error}"))
        })?;
        for entry in entries.flatten() {
            tighten(&entry.path(), depth + 1)?;
        }
    } else if kind.is_file() {
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(|error| {
            Error::Unavailable(format!("cannot restrict the tailcat key material: {error}"))
        })?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn tighten(_path: &Path, _depth: u32) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn tighten_file(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(|error| {
        Error::Unavailable(format!("cannot restrict the recorded nodekey: {error}"))
    })
}

#[cfg(not(unix))]
fn tighten_file(_path: &Path) -> Result<()> {
    Ok(())
}

/// SHA-256 of the helper, streamed and compared before it may run.
fn verify(binary: &Path, expected: &[u8; 32]) -> Result<()> {
    let mut file = fs::File::open(binary)
        .map_err(|error| Error::Unavailable(format!("cannot read tailcat.binary: {error}")))?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| Error::Unavailable(format!("cannot read tailcat.binary: {error}")))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    let found = hasher.finalize();
    if found.as_slice() != expected.as_slice() {
        return Err(Error::Checksum {
            expected: hex(expected),
            found: hex(found.as_slice()),
        });
    }
    Ok(())
}

/// Refuses an argument vector that names a mode the helper must never use.
fn check_argv(args: &[String]) -> Result<()> {
    for arg in args {
        if let Some(word) = refuses(arg) {
            return Err(Error::Refused(word));
        }
    }
    Ok(())
}

fn refuses(arg: &str) -> Option<&'static str> {
    let bare = arg.trim_start_matches('-');
    let head = bare.split('=').next().unwrap_or(bare);
    for whole in [arg, bare, head] {
        if let Some(word) = FORBIDDEN
            .iter()
            .copied()
            .find(|word| whole.eq_ignore_ascii_case(word))
        {
            return Some(word);
        }
    }
    for piece in bare.split(['=', ':', ',', '/']) {
        if let Some(word) = FORBIDDEN
            .iter()
            .copied()
            .find(|word| piece.eq_ignore_ascii_case(word))
        {
            return Some(word);
        }
    }
    None
}

fn normalize(allow: &[NodeKey]) -> Vec<String> {
    let mut keys: Vec<String> = allow.iter().map(|key| key.expose().to_owned()).collect();
    keys.sort();
    keys.dedup();
    keys
}

fn parse_hex(text: &str) -> Option<[u8; 32]> {
    let lowered = text.to_ascii_lowercase();
    if lowered.len() != 64 {
        return None;
    }
    let mut digest = [0u8; 32];
    for (index, pair) in lowered.as_bytes().chunks(2).enumerate() {
        let pair = std::str::from_utf8(pair).ok()?;
        digest[index] = u8::from_str_radix(pair, 16).ok()?;
    }
    Some(digest)
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[usize::from(byte >> 4)] as char);
        out.push(DIGITS[usize::from(byte & 0x0f)] as char);
    }
    out
}

fn contains_ascii_ci(haystack: &str, needle: &str) -> bool {
    let (haystack, needle) = (haystack.as_bytes(), needle.as_bytes());
    !needle.is_empty()
        && haystack.len() >= needle.len()
        && haystack
            .windows(needle.len())
            .any(|window| window.eq_ignore_ascii_case(needle))
}

fn describe(status: &ExitStatus) -> String {
    match status.code() {
        Some(code) => format!("exit code {code}"),
        None => "terminated by a signal".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "nodekey:0123456789abcdeffedcba98765432100123456789abcdeffedcba9876543210";
    const ADDRESS: &str = "tcabcdefghijklmnopqrstuvwxyz0123";

    #[test]
    fn the_pin_is_a_complete_sha256() {
        assert_eq!(PINNED_SHA256.len(), 64);
        assert!(parse_hex(PINNED_SHA256).is_some());
        assert_eq!(hex(&parse_hex(PINNED_SHA256).unwrap()), PINNED_SHA256);
    }

    #[test]
    fn only_the_link_port_arguments_are_allowed() {
        for good in [
            "serve",
            "forward",
            "genkey",
            "ping",
            "--key=default",
            "--fixed-region",
            "--client",
            "--bind=127.0.0.1",
            "--derpmap-url=https://derp.example.com/derp.json",
            "--region=builder-1",
            "--timeout=10s",
            "7443",
            "7443:7443",
            "127.0.0.1:7443",
            "tcabcdefghijklmnopqrstuvwxyz0123",
            "nodekey:0123456789abcdeffedcba98765432100123456789abcdeffedcba9876543210",
        ] {
            assert_eq!(refuses(good), None, "{good}");
        }
        for banned in FORBIDDEN {
            assert_eq!(refuses(banned), Some(banned));
            assert_eq!(refuses(&format!("--{banned}")), Some(banned));
            assert_eq!(refuses(&format!("--mode={banned}")), Some(banned));
        }
        assert!(check_argv(&["serve".to_owned(), "all".to_owned()]).is_err());
    }

    #[test]
    fn keys_and_addresses_accept_only_their_own_shape() {
        assert_eq!(NodeKey::parse(KEY).unwrap().expose(), KEY);
        assert!(NodeKey::parse("0123456789abcdef").is_none());
        assert!(NodeKey::parse(&format!("nodekey:{}", "0".repeat(63))).is_none());
        let upper = format!("nodekey:{}", KEY[8..].to_ascii_uppercase());
        assert_eq!(NodeKey::parse(&upper).unwrap().expose(), KEY);
        assert_eq!(Address::parse(ADDRESS).unwrap().expose(), ADDRESS);
        assert!(Address::parse("tctoo-short").is_none());
        assert!(Address::parse("xxabcdefghijklmnopqrstuvwxyz0123").is_none());
    }

    #[test]
    fn the_nodekey_is_found_in_helper_output_without_keeping_the_output() {
        let text = format!("level=info msg=\"key created\" key={KEY} extra");
        assert_eq!(find_nodekey(&text).unwrap().expose(), KEY);
        assert!(find_nodekey("nodekey:short").is_none());
        assert!(find_nodekey("no key here").is_none());
    }

    #[test]
    fn case_insensitive_matching_does_not_scan_bytes_it_should_not() {
        assert!(contains_ascii_ci("listening on tcAAAA", "listening"));
        assert!(contains_ascii_ci("Forwarding", "forwarding"));
        assert!(!contains_ascii_ci("listen", "listening"));
        assert!(!contains_ascii_ci("", "listening"));
    }
}
