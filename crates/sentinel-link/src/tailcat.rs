//! The pinned Tailcat helper (Q06): an optional, NAT-traversing transport for
//! exactly one endpoint — this deployment's Sentinel link port.
//!
//! Tailcat's upstream is Go, so the adapter is a **pinned helper process**, not
//! a reimplementation: the executable is verified against [`PINNED_SHA256`]
//! before *every* execution, and a mismatch refuses to run it rather than
//! running something else. On Linux the file is opened once without following
//! a symlink, checked for a trustworthy owner and mode, hashed from that open
//! descriptor and executed through the same descriptor, so what runs is what
//! was hashed; an unchanged file (same device, inode, size, mtime and ctime)
//! is not re-hashed. The helper carries only the link port — the server side
//! `serve`s that one port, the worker side `forward`s it to loopback — never a
//! mesh-wide `serve all`, an exit node, or a shell/file mode. It runs with an
//! empty environment apart from `HOME` (its key directory) and the operator's
//! TLS trust overrides, and on Linux it dies with the thread that started it.
//!
//! Identities are keys on disk, not accounts: [`ensure_key`] creates the
//! helper's key under `<data_dir>/tailcat` (owner-only, persisted across
//! restarts so the address is stable) and records the `nodekey:` the helper
//! prints, which is what the controller's allow list names. Key material and
//! `tc…` addresses are credentials: [`NodeKey`] and [`Address`] redact
//! themselves in `Debug`/`Display`, so a diagnostic that prints them cannot
//! leak them; `expose` is the deliberate accessor for argv and owner-only
//! files.
//!
//! Supervision is own-process, not library: [`start_server`] and
//! [`start_forward`] spawn a thread that starts the helper, restarts it when
//! it dies (or exits after failing to connect), and takes it down on
//! [`Server::shutdown`] / [`Forward::shutdown`]. A controller with no admitted
//! worker still runs its helper, with `--allow=none`: it has an address to
//! hand out and admits nobody — an empty allow list never means "any peer".
//! A worker re-proves mesh reachability on an interval with `tailcat ping`
//! (which also measures the direct/relay path) and replaces a helper that
//! stopped reaching the controller; the data path's health is the Sentinel
//! session running over the forward, which the process layer watches. When
//! `tailcat.enabled` is false (or the section is absent) none of this runs and
//! the link uses direct TLS.

use std::{
    fmt, fs, io,
    io::{BufRead, BufReader, Read, Write},
    net::{Ipv4Addr, SocketAddr},
    path::{Component, Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    sync::{
        Arc, Condvar, Mutex,
        mpsc::{self, RecvTimeoutError},
    },
    thread,
    time::{Duration, Instant},
};

use sentinel_core::WorkerId;
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::session::Path as Route;

/// The upstream helper version this adapter is written against.
pub const PINNED_VERSION: &str = "0.6.0";
/// SHA-256 of the pinned helper build. The executable is hashed before every
/// execution; a mismatch refuses to run it. Operators upgrading the helper
/// change this value deliberately (and re-run the probes), never implicitly.
pub const PINNED_SHA256: &str = "d46582137d21f03d15345e2be425d6317d49e5b8c8bb4f6fc56037f4c08cce73";
/// The link port a helper carries when the configuration says nothing else.
pub const DEFAULT_LINK_PORT: u16 = 7443;
/// The file under the data directory listing the workers the controller's
/// helper admits, one `nodekey:<64 hex> wrk_<id>` per line (`#` comments and
/// blank lines allowed): the worker's Tailcat node key and the Sentinel worker
/// it belongs to, so revoking the worker also closes its tunnel. A bare key
/// with no worker id is refused. An absent or empty file admits no worker —
/// the helper then serves with `--allow=none`, never with no `--allow` at all
/// (which upstream treats as "any peer").
pub const ALLOW_LIST_FILE: &str = "tailcat-allow";
/// Under the key directory: the controller's own `tc…` address, written
/// owner-only once the helper reports it, for the operator to hand to workers.
pub const ADDRESS_FILE: &str = "address";

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
/// `ping` is bounded by its own flag, and its process by that plus a margin.
const PING_TIMEOUT: Duration = Duration::from_secs(10);
const PING_MARGIN: Duration = Duration::from_secs(5);
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
/// authentication turned off. Refused as a mode, a flag name, or any piece of
/// a flag's value — except an `https://` URL, whose path segments are data.
const FORBIDDEN: [&str; 5] = ["all", "exit-node", "ssh", "files", "no-auth-ssh"];
/// The environment a helper may inherit besides `HOME`: the operator's TLS
/// trust overrides, which a self-hosted DERP map or relay behind a private CA
/// needs. Nothing else in Sentinel's environment reaches the helper.
const INHERITED_ENV: [&str; 2] = ["SSL_CERT_FILE", "SSL_CERT_DIR"];

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
    /// Addresses embed the node's key *and* its DERP region information, so a
    /// real `serve` address runs well past a hundred characters; the cap only
    /// exists so a malformed line cannot grow memory.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        let text = text.trim().trim_end_matches([',', '.', ')', ']']);
        if text.len() > 256 {
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
    /// How the worker's last successful probe reached the controller, as
    /// `tailcat ping` reported it: `Relay` for a pong via DERP, `Direct` for a
    /// pong from an `ip:port`. `Unknown` before a probe measured it, after a
    /// failed probe, and always on the controller.
    pub path: Route,
    /// The round trip `tailcat ping` itself reported on that probe; absent
    /// whenever `path` is `Unknown` or the pong carried no latency.
    pub ping_rtt: Option<Duration>,
    /// The most recent failure; cleared when the helper is ready again.
    pub problem: Option<Error>,
}

/// One line of the controller's allow list: a worker's Tailcat node key and
/// the Sentinel worker it was issued to. The worker id is what that worker
/// records in `<data_dir>/worker.id`; the controller drops the key once that
/// worker is revoked.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Admission {
    pub key: NodeKey,
    pub worker: WorkerId,
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

/// Where [`ensure_key`] records this role's node key: the worker's is
/// `<data_dir>/tailcat/client-default.nodekey`, the line an operator copies
/// into the controller's allow list (with the worker's id).
#[must_use]
pub fn nodekey_file(data_dir: &Path, role: Role) -> PathBuf {
    data_dir
        .join(KEY_DIR)
        .join(format!("{}.nodekey", key_name(role)))
}

fn key_name(role: Role) -> &'static str {
    match role {
        Role::Controller => KEY_NAME,
        Role::Worker => "client-default",
    }
}

/// Reads the controller's allow list: one `nodekey:<64 hex> wrk_<id>` per
/// line, `#` comments and blank lines allowed. A missing file is an empty list
/// (no worker may use Tailcat), not an error. A malformed line — including a
/// bare key without its worker, or one key named for two different workers —
/// fails the whole read and names its line number and nothing else, so the
/// caller keeps its last good list rather than guessing.
pub fn allow_list(data_dir: &Path) -> Result<Vec<Admission>> {
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
    let mut admitted = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let malformed = || {
            Error::Unavailable(format!(
                "tailcat allow list line {} is not 'nodekey:<64 hex> wrk_<worker id>'",
                index + 1
            ))
        };
        let mut fields = line.split_whitespace();
        let (Some(key), Some(worker), None) = (fields.next(), fields.next(), fields.next()) else {
            return Err(malformed());
        };
        let key = NodeKey::parse(key).ok_or_else(malformed)?;
        let worker = worker.parse::<WorkerId>().map_err(|_| malformed())?;
        admitted.push((Admission { key, worker }, index + 1));
    }
    admitted.sort_unstable_by(|a, b| a.0.cmp(&b.0));
    admitted.dedup_by(|a, b| a.0 == b.0);
    // One tunnel identity belongs to one worker: a key named for two workers
    // would survive revoking either, so it is refused, not guessed at.
    if let Some(pair) = admitted
        .windows(2)
        .find(|pair| pair[0].0.key == pair[1].0.key)
    {
        return Err(Error::Unavailable(format!(
            "tailcat allow list line {} names a nodekey already listed for another worker",
            pair[0].1.max(pair[1].1)
        )));
    }
    Ok(admitted
        .into_iter()
        .map(|(admission, _)| admission)
        .collect())
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

    /// Waits for the advertised address, bounded. The supervisor has written
    /// it to [`Server::address_file`] by then; it is a credential, so callers
    /// log that path, never the address.
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

    /// The owner-only file (`<data_dir>/tailcat/address`) holding the
    /// address once the helper reported it, replaced atomically.
    #[must_use]
    pub fn address_file(&self) -> PathBuf {
        self.run.shared.network.keydir.join(ADDRESS_FILE)
    }

    /// Replaces the allow list. When the set actually changes the helper is
    /// restarted at once with the wider (or narrower) list — existing tunnels
    /// are briefly interrupted and the link reconnects on its own. An empty
    /// list restarts it with `--allow=none`: every tunnel closes and no peer
    /// is admitted until a key is listed again.
    pub fn set_allow(&self, allow: &[NodeKey]) {
        let wanted = normalize(allow);
        {
            let mut current = self.run.shared.allow.lock().expect("tailcat allow");
            if *current == wanted {
                return;
            }
            *current = wanted;
        }
        self.run.shared.replace();
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

    /// Proves the controller is reachable over the mesh: a bounded `tailcat
    /// ping` of its address, which also reports whether the pong came direct
    /// or via DERP. Sends nothing through the forward — the Sentinel session
    /// carried by the forward is the data path's own health, so a probe never
    /// puts a stray connection on the controller's link listener.
    pub fn probe(&self) -> Result<Measured> {
        probe_once(&self.run.shared)
    }

    /// Replaces the helper process now; supervision starts the next one at
    /// once, without back-off (this is a decision, not a failure).
    pub fn restart(&self) {
        self.run.shared.replace();
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

/// What one successful probe measured, both straight from `tailcat ping`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Measured {
    /// `Relay` for a pong via DERP, `Direct` for one from an `ip:port`,
    /// `Unknown` when the helper's output said neither.
    pub path: Route,
    /// The latency the pong reported, when it printed one.
    pub rtt: Option<Duration>,
}

/// A validated helper location: what every execution needs.
struct Network {
    binary: PathBuf,
    digest: [u8; 32],
    keydir: PathBuf,
    derpmap: Option<String>,
    region: Option<String>,
    /// The file identity last hashed and found to match the pin; an
    /// unchanged file is not hashed again.
    verified: Mutex<Option<Stamp>>,
}

/// What identifies one version of the helper file: any write, rename-over or
/// `touch` changes at least one field (`ctime` cannot be set by a writer).
#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(unix), allow(dead_code))]
struct Stamp {
    dev: u64,
    ino: u64,
    size: u64,
    mtime: (i64, i64),
    ctime: (i64, i64),
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
        let network = Network {
            binary: self.binary.clone(),
            digest,
            keydir,
            derpmap: self.derpmap_url.clone(),
            region: self.region.clone(),
            verified: Mutex::new(None),
        };
        // Fail at start, not at the first spawn: a missing or wrong helper is
        // a configuration error.
        network.open_verified()?;
        Ok(network)
    }
}

impl Network {
    /// Verifies the pin and starts one helper invocation. Every execution
    /// goes through here, so nothing unverified ever runs.
    ///
    /// On Linux the child executes `/proc/self/fd/<n>` — the very descriptor
    /// that was checked and hashed — so replacing the file between the check
    /// and the exec cannot run anything else. The descriptor is close-on-exec
    /// in this process; only the forked child clears that flag, just before
    /// it executes, so no other child ever inherits it.
    fn spawn(&self, args: &[String]) -> Result<Child> {
        check_argv(args)?;
        let binary = self.open_verified()?;
        #[cfg(target_os = "linux")]
        let mut command = {
            use std::os::{fd::AsRawFd, unix::process::CommandExt};
            let fd = binary.as_raw_fd();
            let mut command = Command::new(format!("/proc/self/fd/{fd}"));
            command.arg0("tailcat");
            let parent = std::process::id();
            // SAFETY: the closure runs in the forked child before exec, so it
            // may only make async-signal-safe calls: `getppid`, `prctl` and
            // `fcntl` are, and it allocates nothing, takes no lock and touches
            // only `fd` and `parent` (integers copied in). `io::Error` values
            // built from a raw OS code do not allocate.
            unsafe {
                command.pre_exec(move || {
                    // Die with the thread that started us: a SIGKILLed
                    // Sentinel must not leave a helper holding the tunnel.
                    if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) != 0 {
                        return Err(io::Error::last_os_error());
                    }
                    // The parent may have died before the prctl took effect.
                    if libc::getppid() as u32 != parent {
                        return Err(io::Error::from_raw_os_error(libc::ESRCH));
                    }
                    // Keep the verified descriptor open across this exec: a
                    // `#!` helper's interpreter reopens it by the same path.
                    if libc::fcntl(fd, libc::F_SETFD, 0) != 0 {
                        return Err(io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
            command
        };
        #[cfg(not(target_os = "linux"))]
        let mut command = Command::new(&self.binary);
        command
            .env_clear()
            .env("HOME", &self.keydir)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .args(args);
        for name in INHERITED_ENV {
            if let Some(value) = std::env::var_os(name) {
                command.env(name, value);
            }
        }
        let child = command
            .spawn()
            .map_err(|error| Error::Spawn(error.to_string()))?;
        // The child has exec'd (or failed to); the descriptor has done its job.
        drop(binary);
        Ok(child)
    }

    /// Opens the helper and proves it is the pinned build: owner and mode
    /// first (a file someone else can rewrite is not trusted however it
    /// hashes), then the digest — read from this same open file, and skipped
    /// when the file's identity is the one already found to match.
    fn open_verified(&self) -> Result<fs::File> {
        let file = open_helper(&self.binary)?;
        let metadata = file.metadata().map_err(|error| {
            Error::Unavailable(format!("cannot inspect tailcat.binary: {error}"))
        })?;
        if !metadata.is_file() {
            return Err(Error::Unavailable(
                "tailcat.binary is not a regular file".to_owned(),
            ));
        }
        trusted_owner(&metadata)?;
        let stamp = stamp(&metadata);
        let mut verified = self.verified.lock().expect("tailcat verified");
        if stamp.is_some() && *verified == stamp {
            return Ok(file);
        }
        *verified = None;
        verify(&file, &self.digest)?;
        *verified = stamp;
        drop(verified);
        Ok(file)
    }
}

/// Opens the helper read-only without following a final symlink (the target
/// of a link can be swapped by whoever owns the link's directory entry).
#[cfg(unix)]
fn open_helper(path: &Path) -> Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| Error::Unavailable(format!("cannot open tailcat.binary: {error}")))
}

#[cfg(not(unix))]
fn open_helper(path: &Path) -> Result<fs::File> {
    fs::File::open(path)
        .map_err(|error| Error::Unavailable(format!("cannot open tailcat.binary: {error}")))
}

/// Only this user or root may be able to change the helper: a file owned by
/// anyone else, or writable by group or others, is refused.
#[cfg(unix)]
fn trusted_owner(metadata: &fs::Metadata) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    // SAFETY: `geteuid` has no preconditions and cannot fail.
    let me = unsafe { libc::geteuid() };
    if metadata.uid() != me && metadata.uid() != 0 {
        return Err(Error::Unavailable(
            "tailcat.binary is owned by another user; it must be owned by root or by this user"
                .to_owned(),
        ));
    }
    if metadata.mode() & 0o022 != 0 {
        return Err(Error::Unavailable(
            "tailcat.binary is writable by group or others".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn trusted_owner(_metadata: &fs::Metadata) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn stamp(metadata: &fs::Metadata) -> Option<Stamp> {
    use std::os::unix::fs::MetadataExt;
    Some(Stamp {
        dev: metadata.dev(),
        ino: metadata.ino(),
        size: metadata.size(),
        mtime: (metadata.mtime(), metadata.mtime_nsec()),
        ctime: (metadata.ctime(), metadata.ctime_nsec()),
    })
}

/// Without an inode identity the file is hashed on every execution.
#[cfg(not(unix))]
fn stamp(_metadata: &fs::Metadata) -> Option<Stamp> {
    None
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
    /// The live child was killed on purpose (a new allow list, a failed
    /// probe, an explicit restart): its successor starts at once, and its
    /// death is not recorded as a helper failure.
    replacing: bool,
    child: Option<Child>,
    /// Counts registered children, so the tunnel prober replaces only the
    /// child it probed, never a successor that started meanwhile.
    generation: u64,
    /// When the live child was registered (`None` between children).
    born: Option<Instant>,
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

    /// Kill the current child because it failed (it never became ready):
    /// supervision starts another after its back-off.
    fn kill(&self) {
        let mut stop = self.stop.lock().expect("tailcat stop");
        if let Some(child) = stop.child.as_mut() {
            let _ = child.kill();
        }
    }

    /// Kill the current child on purpose: supervision starts its successor
    /// at once. Also wakes a supervisor waiting out a back-off, so a new
    /// allow list never waits behind an earlier failure.
    fn replace(&self) {
        let mut stop = self.stop.lock().expect("tailcat stop");
        stop.replacing = true;
        if let Some(child) = stop.child.as_mut() {
            let _ = child.kill();
        }
        self.wake.notify_all();
    }

    /// The live child's generation and registration instant, if one runs.
    fn current_child(&self) -> Option<(u64, Instant)> {
        let stop = self.stop.lock().expect("tailcat stop");
        stop.born.map(|born| (stop.generation, born))
    }

    /// [`Shared::replace`], but only while `generation` is still the live
    /// child: a probe's verdict is about the child it probed, and a
    /// successor that started while the probe ran has not been judged.
    fn replace_probed(&self, generation: u64) {
        let mut stop = self.stop.lock().expect("tailcat stop");
        if stop.generation != generation || stop.born.is_none() {
            return;
        }
        stop.replacing = true;
        if let Some(child) = stop.child.as_mut() {
            let _ = child.kill();
        }
        self.wake.notify_all();
    }

    /// Whether the last child was replaced on purpose; clears the mark.
    fn take_replacing(&self) -> bool {
        std::mem::take(&mut self.stop.lock().expect("tailcat stop").replacing)
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
                // Upstream reads one `--allow` (a repeated flag keeps only
                // the last), takes a comma-separated list, and treats an
                // absent or empty one as "every peer". An empty list is
                // therefore the explicit `none`, never an omitted flag.
                let allow = self.allow.lock().expect("tailcat allow");
                if allow.is_empty() {
                    args.push("--allow=none".to_owned());
                } else {
                    args.push(format!("--allow={}", allow.join(",")));
                }
                drop(allow);
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

    /// One line of helper output. Never stored verbatim: only the address, in
    /// its redacting form and in the owner-only address file.
    fn observe(&self, line: &str) {
        match self.role {
            Role::Controller => {
                if !contains_ascii_ci(line, "listening") {
                    return;
                }
                let Some(address) = line.split_whitespace().rev().find_map(Address::parse) else {
                    return;
                };
                let changed =
                    self.state.lock().expect("tailcat state").address.as_ref() != Some(&address);
                // Written before the address is published in telemetry, so a
                // caller that saw `wait_ready` succeed finds the file.
                let recorded = if changed {
                    record_address(&self.network.keydir, &address)
                } else {
                    Ok(())
                };
                let mut state = self.state.lock().expect("tailcat state");
                state.address = Some(address);
                state.ready = true;
                state.problem = recorded.err();
            }
            Role::Worker => {
                // A bound listener is not a tunnel: it counts as ready only
                // while no probe has failed, and only a probe clears one.
                if contains_ascii_ci(line, "forwarding") {
                    let mut state = self.state.lock().expect("tailcat state");
                    state.ready = state.problem.is_none();
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
            replacing: false,
            child: None,
            generation: 0,
            born: None,
        }),
        wake: Condvar::new(),
    }))
}

/// One helper's lifetime, restarted until stopped: a death (or an exit after a
/// failed connect) is a restart with bounded back-off, not a give-up. The
/// back-off doubles only across consecutive failures — a helper that became
/// ready, or ran past [`READY_DEADLINE`], resets it — and a child killed on
/// purpose is replaced at once, without a back-off or a recorded problem.
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
        let (outcome, healthy) = run_child(&shared);
        if shared.take_replacing() {
            continue;
        }
        if healthy {
            backoff = RESTART_MIN;
        }
        let wait = match outcome {
            Ok(()) => RESTART_MIN,
            Err(problem) => {
                if !shared.stopped() {
                    shared.fail(problem);
                }
                let wait = backoff;
                backoff = (backoff * 2).min(RESTART_MAX);
                wait
            }
        };
        if !shared.wait(wait) {
            return;
        }
    }
}

/// Spawns the helper once, follows its output until it ends, and reaps it.
/// The flag says whether this child counted as healthy: it reported
/// readiness, or it stayed up past [`READY_DEADLINE`].
fn run_child(shared: &Arc<Shared>) -> (Result<()>, bool) {
    // A replacement asked for from here on applies to this child: the mark is
    // cleared before the argv is built, so a newer allow list that arrives
    // before the child is registered kills it straight away.
    shared.take_replacing();
    let args = shared.args();
    let mut child = match shared.network.spawn(&args) {
        Ok(child) => child,
        Err(error) => return (Err(error), false),
    };
    let (Some(stdout), Some(stderr)) = (child.stdout.take(), child.stderr.take()) else {
        let _ = child.kill();
        let _ = child.wait();
        return (
            Err(Error::Spawn(
                "the helper's output was not captured".to_owned(),
            )),
            false,
        );
    };
    let pid = child.id();
    {
        let mut state = shared.state.lock().expect("tailcat state");
        state.pid = Some(pid);
        state.ready = false;
    }
    {
        let mut stop = shared.stop.lock().expect("tailcat stop");
        if stop.replacing {
            let _ = child.kill();
        }
        stop.child = Some(child);
        stop.generation += 1;
        stop.born = Some(Instant::now());
    }
    let mut became_ready = false;

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
            Ok(line) => {
                shared.observe(&line);
                became_ready |= shared.state.lock().expect("tailcat state").ready;
            }
            Err(RecvTimeoutError::Timeout) => {
                if exited(shared) {
                    break;
                }
                let late = !expired && started.elapsed() >= READY_DEADLINE;
                let ready = shared.state.lock().expect("tailcat state").ready;
                became_ready |= ready;
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

    let status = {
        let mut stop = shared.stop.lock().expect("tailcat stop");
        stop.born = None;
        stop.child.take()
    };
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
        state.path = Route::Unknown;
        state.ping_rtt = None;
    }
    let healthy = became_ready || (!expired && started.elapsed() >= READY_DEADLINE);
    let outcome = match status {
        // The readiness deadline killed it: that, not the kill, is the problem.
        _ if expired => Err(Error::Timeout("the helper never reported readiness")),
        None => Ok(()),
        Some(Ok(status)) if status.success() => Ok(()),
        Some(Ok(status)) => Err(Error::Exited(status.code())),
        Some(Err(error)) => Err(Error::Spawn(error.to_string())),
    };
    (outcome, healthy)
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

/// Re-proves a worker's mesh path on an interval; a helper that can no longer
/// reach the controller is replaced rather than trusted because its port is
/// bound. The probe's own problem stays recorded; the replacement is not a
/// second failure and does not wait out a back-off.
///
/// The interval is a deadline, not a wait that any wake-up ends: a
/// replacement (or a new allow list) notifies the same condition, and
/// probing then would judge a helper that has had no time to connect,
/// fail, and kill it again — on a slow host before it ever ran. A helper
/// is judged only once it has lived a full interval, and a failed probe
/// replaces only the child it probed.
fn watch_tunnel(shared: Arc<Shared>, every: Duration) {
    let mut next = Instant::now() + every;
    loop {
        let left = next.saturating_duration_since(Instant::now());
        if !left.is_zero() {
            if !shared.wait(left) {
                return;
            }
            continue;
        }
        next = Instant::now() + every;
        let Some((generation, born)) = shared.current_child() else {
            continue;
        };
        if born.elapsed() < every {
            next = born + every;
            continue;
        }
        if probe_once(&shared).is_err() && !shared.stopped() {
            shared.replace_probed(generation);
        }
    }
}

/// `ping` the controller, bounded, and record what it measured.
fn probe_once(shared: &Shared) -> Result<Measured> {
    let outcome = probe_tunnel(shared);
    let mut state = shared.state.lock().expect("tailcat state");
    match &outcome {
        Ok(measured) => {
            state.ready = true;
            state.problem = None;
            state.path = measured.path;
            state.ping_rtt = measured.rtt;
        }
        Err(problem) => {
            state.ready = false;
            state.problem = Some(problem.clone());
            state.path = Route::Unknown;
            state.ping_rtt = None;
        }
    }
    outcome
}

fn probe_tunnel(shared: &Shared) -> Result<Measured> {
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
        shared.network.spawn(&args)?,
        PING_TIMEOUT + PING_MARGIN,
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
    Ok(measure_pong(&captured.stdout)
        .or_else(|| measure_pong(&captured.stderr))
        .unwrap_or(Measured {
            path: Route::Unknown,
            rtt: None,
        }))
}

/// Reads the last `pong in <latency> via <DERP(region)|ip:port>` line from
/// `tailcat ping` output (already capped at [`OUTPUT_CAP`]). Nothing of the
/// text is kept: only the path class and the latency number.
fn measure_pong(output: &[u8]) -> Option<Measured> {
    let text = std::str::from_utf8(output).ok()?;
    text.lines().rev().find_map(|line| {
        let rest = line.trim().strip_prefix("pong in ")?;
        let (latency, via) = rest.split_once(" via ")?;
        let via = via.trim();
        let path = if via.starts_with("DERP") {
            Route::Relay
        } else if via.parse::<SocketAddr>().is_ok() {
            Route::Direct
        } else {
            return None;
        };
        Some(Measured {
            path,
            rtt: parse_latency(latency.trim()),
        })
    })
}

/// Go's `time.Duration` text for sub-minute values: `740µs`, `42.1ms`,
/// `1.2s`, `900ns`. Anything else is not a measurement.
fn parse_latency(text: &str) -> Option<Duration> {
    let split = text.find(|c: char| !(c.is_ascii_digit() || c == '.'))?;
    let (number, unit) = text.split_at(split);
    let scale: f64 = match unit {
        "ns" => 1.0,
        "µs" | "us" | "μs" => 1e3,
        "ms" => 1e6,
        "s" => 1e9,
        _ => return None,
    };
    let value: f64 = number.parse().ok()?;
    let nanos = value * scale;
    (0.0..3.6e12)
        .contains(&nanos)
        .then(|| Duration::from_nanos(nanos as u64))
}

/// Runs a bounded helper invocation and captures its output. A stop request
/// ends the wait at once, so shutting down never waits out a helper timeout.
fn output_within(mut child: Child, within: Duration, stop: &dyn Fn() -> bool) -> Result<Captured> {
    let (stdout, stderr) = (child.stdout.take(), child.stderr.take());
    let (Some(stdout), Some(stderr)) = (stdout, stderr) else {
        let _ = child.kill();
        let _ = child.wait();
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
/// The helper's own naming rule applies: a server key is `default`, a client
/// key is `client-default` — `genkey --client --key=default` is refused.
fn ensure(network: &Network, role: Role) -> Result<NodeKey> {
    let name = key_name(role);
    let record = network.keydir.join(format!("{name}.nodekey"));
    if let Some(key) = read_key(&record)? {
        return Ok(key);
    }
    let mut args = vec!["genkey".to_owned(), format!("--key={name}")];
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
    let captured = output_within(network.spawn(&args)?, GENKEY_TIMEOUT, &|| false)?;
    if !captured.status.success() {
        return Err(Error::Unavailable(format!(
            "genkey did not create a key ({})",
            describe(&captured.status)
        )));
    }
    let mut text = String::from_utf8_lossy(&captured.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&captured.stderr));
    let key = match role {
        // A client key's genkey prints its public key.
        Role::Worker => find_nodekey(&text),
        // A server key's genkey prints its address instead; the public key
        // inside it is what `tailcat parse` reports as `ServerPublic`.
        Role::Controller => match text.split_whitespace().find_map(Address::parse) {
            Some(address) => server_public(network, &address)?,
            None => None,
        },
    }
    .ok_or_else(|| Error::Unavailable("genkey printed no nodekey".to_owned()))?;
    tighten(&network.keydir, 0)?;
    record_key(&record, &key)?;
    Ok(key)
}

/// The server's public key, decoded from its own address by `tailcat parse`.
fn server_public(network: &Network, address: &Address) -> Result<Option<NodeKey>> {
    let args = ["parse".to_owned(), address.expose().to_owned()];
    let captured = output_within(network.spawn(&args)?, VERSION_TIMEOUT, &|| false)?;
    if !captured.status.success() {
        return Ok(None);
    }
    Ok(find_nodekey(&String::from_utf8_lossy(&captured.stdout)))
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
        network.spawn(&["--version".to_owned()]).ok()?,
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

/// Replaces `<keydir>/address` atomically with the controller's address,
/// owner-only from creation: a temporary file opened `0600` is written,
/// synced and renamed over the old one.
fn record_address(keydir: &Path, address: &Address) -> Result<()> {
    let target = keydir.join(ADDRESS_FILE);
    let staging = keydir.join(".address.tmp");
    let failed = |error: io::Error| {
        Error::Unavailable(format!("cannot record the tailcat address: {error}"))
    };
    let _ = fs::remove_file(&staging);
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options.open(&staging).map_err(failed)?;
    file.write_all(address.expose().as_bytes())
        .and_then(|()| file.write_all(b"\n"))
        .and_then(|()| file.sync_all())
        .map_err(failed)?;
    drop(file);
    fs::rename(&staging, &target).map_err(failed)
}

/// SHA-256 of the helper, streamed from the open file and compared before it
/// may run.
fn verify(mut file: &fs::File, expected: &[u8; 32]) -> Result<()> {
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

/// The forbidden word an argument names, if any: as a flag name
/// (`--files=…`), a mode or service (`all`, `80,ssh`), or a piece of a flag's
/// value (`--serve=all`). An `https://` value is a URL — the DERP map — and
/// its path segments (`/files/`, `/all/`) are data, not modes.
fn refuses(arg: &str) -> Option<&'static str> {
    let forbidden = |piece: &str| {
        FORBIDDEN
            .iter()
            .copied()
            .find(|word| piece.eq_ignore_ascii_case(word))
    };
    let bare = arg.trim_start_matches('-');
    let (name, value) = match bare.split_once('=') {
        Some((name, value)) if bare.len() != arg.len() => (Some(name), value),
        _ => (None, bare),
    };
    if let Some(word) = name.and_then(forbidden) {
        return Some(word);
    }
    if value
        .get(..8)
        .is_some_and(|scheme| scheme.eq_ignore_ascii_case("https://"))
    {
        return None;
    }
    forbidden(value).or_else(|| value.split(['=', ':', ',', '/']).find_map(forbidden))
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
        for banned in [
            "80,all",
            "--serve=7443,files",
            "--files=/pub:rw",
            "7443,no-auth-ssh",
        ] {
            assert!(refuses(banned).is_some(), "{banned}");
        }
    }

    #[test]
    fn a_derp_map_url_is_data_not_a_mode() {
        for url in [
            "--derpmap-url=https://derp.example.com/files/derp.json",
            "--derpmap-url=https://example.com/all/map.json",
            "--derpmap-url=HTTPS://example.com/ssh/exit-node.json",
        ] {
            assert_eq!(refuses(url), None, "{url}");
        }
        // The flag name is still checked, and a non-URL value still is too.
        assert_eq!(refuses("--files=https://example.com/x"), Some("files"));
        assert_eq!(refuses("--derpmap-url=http://x/all"), Some("all"));
    }

    #[test]
    fn the_ping_path_and_latency_come_from_the_pong_line_only() {
        let relayed = measure_pong(b"pinging...\npong in 42.1ms via DERP(sfo)\n").unwrap();
        assert_eq!(relayed.path, Route::Relay);
        assert_eq!(relayed.rtt, Some(Duration::from_micros(42_100)));
        let direct = measure_pong("pong in 740\u{b5}s via 172.17.0.1:51223\n".as_bytes()).unwrap();
        assert_eq!(direct.path, Route::Direct);
        assert_eq!(direct.rtt, Some(Duration::from_micros(740)));
        let v6 = measure_pong(b"pong in 1.2s via [2001:db8::1]:41641").unwrap();
        assert_eq!(v6.path, Route::Direct);
        assert_eq!(v6.rtt, Some(Duration::from_millis(1200)));
        // The last pong wins; a pong without a readable latency keeps the path.
        let last = measure_pong(b"pong in 9ms via DERP(fra)\npong in soon via 10.0.0.1:1\n");
        assert_eq!(last.unwrap().path, Route::Direct);
        assert_eq!(last.unwrap().rtt, None);
        assert!(measure_pong(b"ping: context deadline exceeded\n").is_none());
        assert!(measure_pong(b"pong in 1ms via somewhere\n").is_none());
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
