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
//! Identities rotate without a gap: [`stage_rotation`] generates a second key
//! beside the active one; the controller serves a staged key *alongside* the
//! active one (same port, same allow list) until [`commit_rotation`] switches,
//! and a worker's staged key is committed only after a `ping` with it proves
//! the controller admits it. The allow list names each key with its worker
//! ([`admit`], [`retire`]), so a rotating worker is listed twice during the
//! overlap and revoking it withdraws both keys.
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
/// Under the key directory: during a controller key rotation, the address
/// the staged key is served at (owner-only), for the operator to hand to
/// workers before the rotation commits.
pub const STAGED_ADDRESS_FILE: &str = "address.next";

/// Keys and the helper's own state live here, under the data directory.
const KEY_DIR: &str = "tailcat";
/// The helper's key name; `HOME` is pointed at [`KEY_DIR`], so this is also
/// which key `serve`/`forward`/`ping` use when no `--key` is passed.
const KEY_NAME: &str = "default";
/// The second helper key name of each role. A rotation stages a key under
/// whichever of the two names is not active and commits by switching.
const ROTATED_SERVER_KEY: &str = "rotated";
const ROTATED_CLIENT_KEY: &str = "client-rotated";
/// Under the key directory, owner-only: the helper key name in use when it is
/// not the role's magic default. Absent means the default name.
const ACTIVE_FILE: &str = "active-key";
/// Under the key directory, owner-only: a staged rotation, as the staged
/// helper key name and its node key on one line.
const STAGED_FILE: &str = "staged.nodekey";
/// Bound on reading the two small rotation files above.
const SMALL_FILE_CAP: u64 = 256;
/// A fresh helper must report readiness (an address, or a working tunnel)
/// within this long; one that never connects is replaced.
const READY_DEADLINE: Duration = Duration::from_secs(60);
/// A worker re-proves the tunnel this often.
const PROBE_EVERY: Duration = Duration::from_secs(30);
/// A lost session replaces a worker's helper only once the helper has run
/// this long: well past the 1.0-1.4 s a fresh helper took to carry a session
/// in the live suite, so a successor is never judged before it could connect.
pub const SESSION_SETTLE: Duration = Duration::from_secs(10);
/// How long [`Forward::session_closed`] leaves the forward running after a
/// clean close, for the worker's own end to reach the controller. Below the
/// worker's shortest back-off (750 ms), so its next dial meets a fresh
/// forward.
pub const CLOSE_GRACE: Duration = Duration::from_millis(200);
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
    let server = Server {
        keydir: shared.network.keydir.clone(),
        port: shared.port,
        helpers: Mutex::new(Helpers {
            main: Runner::spawn(shared, None),
            staged: None,
        }),
    };
    // A rotation staged while the controller was down is served at once.
    server.reload_keys()?;
    Ok(server)
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
    key_names(role)[0]
}

/// The role's two helper key names: the magic default the helper loads on
/// its own, and the name a rotation alternates with it.
fn key_names(role: Role) -> [&'static str; 2] {
    match role {
        Role::Controller => [KEY_NAME, ROTATED_SERVER_KEY],
        Role::Worker => ["client-default", ROTATED_CLIENT_KEY],
    }
}

/// The owner-only file where the controller's helper writes the address of a
/// staged key while a rotation is in its overlap window.
#[must_use]
pub fn staged_address_file(data_dir: &Path) -> PathBuf {
    data_dir.join(KEY_DIR).join(STAGED_ADDRESS_FILE)
}

/// Stages a node-key rotation: generates a second key beside the active one
/// and records its node key, which is returned. Nothing that runs changes:
/// the running controller starts serving the staged key *as well* on its next
/// allow-list tick (writing its address to [`staged_address_file`]); a
/// worker's staged key is only used once [`commit_rotation`] proves the
/// controller admits it. Idempotent: a rotation already staged returns its
/// key without generating another.
pub fn stage_rotation(config: &TailcatConfig, data_dir: &Path, role: Role) -> Result<NodeKey> {
    let network = config.network(data_dir)?;
    ensure(&network, role)?;
    if let Some((_, key)) = read_staged(&network.keydir, role)? {
        return Ok(key);
    }
    let active = active_name(&network.keydir, role)?;
    let next = other_name(role, active);
    let key = generate(&network, role, next, true)?;
    write_private(
        &network.keydir,
        STAGED_FILE,
        format!("{next} {}\n", key.expose()).as_bytes(),
    )?;
    Ok(key)
}

/// The node key of the rotation staged for this role, if one is.
pub fn staged_rotation(data_dir: &Path, role: Role) -> Result<Option<NodeKey>> {
    Ok(read_staged(&data_dir.join(KEY_DIR), role)?.map(|(_, key)| key))
}

/// Commits a staged rotation and returns the node key now in use.
///
/// The old key is dropped only once the new one is known to be admitted: a
/// worker first `ping`s the controller with the staged key (the controller's
/// `--allow` must already list it — `controller` is required), and a
/// controller requires [`staged_address_file`], which only its running helper
/// writes once it serves the staged key. The switch itself is one atomic file
/// replacement; the running process follows it on its next tick: a worker
/// within one probe interval, restarting its helper on the new key, and the
/// controller within one allow-list tick ([`Server::reload_keys`]), keeping
/// the helper that already serves the new key and stopping the old one. The
/// old private key is then deleted
/// through the helper; `Committed::previous_deleted` says whether that
/// worked. A commit interrupted after the switch finishes on a retry.
pub fn commit_rotation(
    config: &TailcatConfig,
    data_dir: &Path,
    role: Role,
    controller: Option<&Address>,
) -> Result<Committed> {
    let network = config.network(data_dir)?;
    let keydir = &network.keydir;
    let (next, key) = read_staged(keydir, role)?
        .ok_or_else(|| Error::Unavailable("no key rotation is staged".to_owned()))?;
    let active = active_name(keydir, role)?;
    if active != next {
        match role {
            Role::Worker => {
                let controller = controller.ok_or_else(|| {
                    Error::Unavailable(
                        "a worker rotation needs the controller's address".to_owned(),
                    )
                })?;
                admitted_as(&network, next, controller)?;
            }
            Role::Controller => {
                if !keydir.join(STAGED_ADDRESS_FILE).is_file() {
                    return Err(Error::Unavailable(
                        "the running controller has not served the staged key yet; workers \
                         cannot have its address"
                            .to_owned(),
                    ));
                }
            }
        }
        write_private(keydir, ACTIVE_FILE, format!("{next}\n").as_bytes())?;
    }
    // From here the rotation is committed; every step below is idempotent.
    record_key(&keydir.join(format!("{}.nodekey", key_name(role))), &key)?;
    if role == Role::Controller {
        match fs::rename(keydir.join(STAGED_ADDRESS_FILE), keydir.join(ADDRESS_FILE)) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(Error::Unavailable(format!(
                    "cannot record the rotated address: {error}"
                )));
            }
        }
    }
    remove_if_present(&keydir.join(STAGED_FILE))?;
    sync_dir(keydir)?;
    let previous_deleted = delete_key(&network, other_name(role, next)).is_ok();
    Ok(Committed {
        key,
        previous_deleted,
    })
}

/// Drops a staged rotation that has not committed: its key is deleted and
/// nothing that runs changes (the controller stops serving it on its next
/// tick). `false` when nothing was staged.
pub fn abandon_rotation(config: &TailcatConfig, data_dir: &Path, role: Role) -> Result<bool> {
    let network = config.network(data_dir)?;
    let keydir = &network.keydir;
    let Some((next, _)) = read_staged(keydir, role)? else {
        return Ok(false);
    };
    if active_name(keydir, role)? == next {
        return Err(Error::Unavailable(
            "the rotation already switched keys; run commit to finish it".to_owned(),
        ));
    }
    delete_key(&network, next)?;
    remove_if_present(&keydir.join(STAGED_FILE))?;
    if role == Role::Controller {
        remove_if_present(&keydir.join(STAGED_ADDRESS_FILE))?;
    }
    Ok(true)
}

/// A committed rotation: the node key now in use, and whether the previous
/// private key was deleted (a failure leaves it on disk, unused).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Committed {
    pub key: NodeKey,
    pub previous_deleted: bool,
}

/// Adds `admission` to the controller's allow list, keeping every other line
/// (and the worker's other keys: a rotating worker is listed twice until
/// [`retire`]). `false` when that exact line was already listed. The file is
/// replaced atomically and owner-only; a key listed for another worker is
/// refused and leaves the file unchanged.
pub fn admit(data_dir: &Path, admission: &Admission) -> Result<bool> {
    let listed = allow_list(data_dir)?;
    match listed.iter().find(|line| line.key == admission.key) {
        Some(line) if line.worker == admission.worker => return Ok(false),
        Some(_) => {
            return Err(Error::Unavailable(
                "that nodekey is already listed for another worker".to_owned(),
            ));
        }
        None => {}
    }
    let mut text = read_allow_text(data_dir)?;
    if !text.is_empty() && !text.ends_with('\n') {
        text.push('\n');
    }
    text.push_str(admission.key.expose());
    text.push(' ');
    text.push_str(&admission.worker.to_string());
    text.push('\n');
    if text.len() as u64 > ALLOW_LIST_CAP {
        return Err(Error::Unavailable(
            "the tailcat allow list would exceed 64 KiB".to_owned(),
        ));
    }
    write_private(data_dir, ALLOW_LIST_FILE, text.as_bytes())?;
    Ok(true)
}

/// Makes `keep` its worker's only listed key: every other line naming that
/// worker is removed, every other worker's line and every comment is kept.
/// Returns how many lines were removed. `keep` must already be listed, so a
/// retire can never leave a rotating worker with no admitted key by mistake.
pub fn retire(data_dir: &Path, keep: &Admission) -> Result<usize> {
    if !allow_list(data_dir)?.contains(keep) {
        return Err(Error::Unavailable(
            "that nodekey is not listed for that worker; admit it first".to_owned(),
        ));
    }
    let text = read_allow_text(data_dir)?;
    let mut kept = String::with_capacity(text.len());
    let mut removed = 0;
    for line in text.lines() {
        let retired = parse_admission(line)
            .is_some_and(|listed| listed.worker == keep.worker && listed.key != keep.key);
        if retired {
            removed += 1;
        } else {
            kept.push_str(line);
            kept.push('\n');
        }
    }
    if removed > 0 {
        write_private(data_dir, ALLOW_LIST_FILE, kept.as_bytes())?;
    }
    Ok(removed)
}

/// One allow-list line as an admission; `None` for a comment, a blank line
/// or anything malformed (callers validate the file with [`allow_list`]).
fn parse_admission(line: &str) -> Option<Admission> {
    let mut fields = line.split_whitespace();
    let (Some(key), Some(worker), None) = (fields.next(), fields.next(), fields.next()) else {
        return None;
    };
    Some(Admission {
        key: NodeKey::parse(key)?,
        worker: worker.parse().ok()?,
    })
}

/// The allow list's text, already validated by [`allow_list`]; empty when
/// the file does not exist.
fn read_allow_text(data_dir: &Path) -> Result<String> {
    match fs::read_to_string(data_dir.join(ALLOW_LIST_FILE)) {
        Ok(text) => Ok(text),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(String::new()),
        Err(error) => Err(Error::Unavailable(format!(
            "cannot read the tailcat allow list: {error}"
        ))),
    }
}

/// The name of the role's key pair that is not `name`.
fn other_name(role: Role, name: &str) -> &'static str {
    let [first, second] = key_names(role);
    if name == first { second } else { first }
}

/// The helper key name in use: the role's default unless a committed
/// rotation switched to the other one. Anything else in the file is refused
/// rather than guessed at.
fn active_name(keydir: &Path, role: Role) -> Result<&'static str> {
    let names = key_names(role);
    let Some(text) = read_small(keydir, ACTIVE_FILE)? else {
        return Ok(names[0]);
    };
    let text = text.trim();
    names.into_iter().find(|name| *name == text).ok_or_else(|| {
        Error::Unavailable("the tailcat active-key file names no key of this role".to_owned())
    })
}

/// The staged rotation: its helper key name and node key.
fn read_staged(keydir: &Path, role: Role) -> Result<Option<(&'static str, NodeKey)>> {
    let Some(text) = read_small(keydir, STAGED_FILE)? else {
        return Ok(None);
    };
    let malformed =
        || Error::Unavailable("the staged tailcat rotation record is malformed".to_owned());
    let (name, key) = text.trim().split_once(' ').ok_or_else(malformed)?;
    let name = key_names(role)
        .into_iter()
        .find(|candidate| *candidate == name)
        .ok_or_else(malformed)?;
    Ok(Some((name, NodeKey::parse(key).ok_or_else(malformed)?)))
}

/// A small Sentinel-owned file under the key directory, bounded.
fn read_small(keydir: &Path, name: &str) -> Result<Option<String>> {
    let file = match fs::File::open(keydir.join(name)) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(Error::Unavailable(format!(
                "cannot read the tailcat {name} file: {error}"
            )));
        }
    };
    let mut text = String::new();
    file.take(SMALL_FILE_CAP)
        .read_to_string(&mut text)
        .map_err(|error| {
            Error::Unavailable(format!("cannot read the tailcat {name} file: {error}"))
        })?;
    Ok(Some(text))
}

/// Proves the controller admits the worker key `name`: a bounded `ping` of
/// its address with that key. A refused key cannot complete the handshake.
fn admitted_as(network: &Network, name: &str, controller: &Address) -> Result<()> {
    let mut args = vec![
        "ping".to_owned(),
        format!("--timeout={}s", PING_TIMEOUT.as_secs()),
        format!("--key={name}"),
    ];
    if let Some(url) = &network.derpmap {
        args.push(format!("--derpmap-url={url}"));
    }
    args.push(controller.expose().to_owned());
    let captured = output_within(network.spawn(&args)?, PING_TIMEOUT + PING_MARGIN, &|| false)?;
    if captured.status.success() {
        Ok(())
    } else {
        Err(Error::Unavailable(
            "the controller does not admit the staged key yet; list it in the controller's \
             allow list and retry"
                .to_owned(),
        ))
    }
}

/// Deletes a saved helper key through the helper itself (its key store is
/// its own layout, not Sentinel's).
fn delete_key(network: &Network, name: &str) -> Result<()> {
    let args = [
        "genkey".to_owned(),
        "--delete".to_owned(),
        format!("--key={name}"),
    ];
    let captured = output_within(network.spawn(&args)?, GENKEY_TIMEOUT, &|| false)?;
    if captured.status.success() {
        Ok(())
    } else {
        Err(Error::Unavailable(format!(
            "genkey did not delete the key ({})",
            describe(&captured.status)
        )))
    }
}

fn remove_if_present(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(Error::Unavailable(format!(
            "cannot remove tailcat rotation state: {error}"
        ))),
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
    keydir: PathBuf,
    port: u16,
    helpers: Mutex<Helpers>,
}

/// The helpers a controller runs: the one serving the active key and, during
/// a rotation's overlap window, a second one serving the staged key (the
/// same port and allow list) with that key.
struct Helpers {
    main: Runner,
    staged: Option<(NodeKey, Runner)>,
}

impl Server {
    fn helpers(&self) -> std::sync::MutexGuard<'_, Helpers> {
        self.helpers.lock().expect("tailcat helpers")
    }

    /// The address the helper advertises, once it has reported one.
    #[must_use]
    pub fn address(&self) -> Option<Address> {
        self.helpers().main.state().address.clone()
    }

    /// Waits for the advertised address, bounded. The supervisor has written
    /// it to [`Server::address_file`] by then; it is a credential, so callers
    /// log that path, never the address.
    pub fn wait_ready(&self, within: Duration) -> Result<Address> {
        let deadline = Instant::now() + within;
        loop {
            {
                let helpers = self.helpers();
                if let Some(address) = helpers.main.state().address.clone() {
                    return Ok(address);
                }
                if helpers.main.shared.stopped() {
                    return Err(Error::Unavailable(
                        "the tailcat helper was shut down".to_owned(),
                    ));
                }
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
        self.port
    }

    /// The owner-only file (`<data_dir>/tailcat/address`) holding the
    /// address once the helper reported it, replaced atomically.
    #[must_use]
    pub fn address_file(&self) -> PathBuf {
        self.keydir.join(ADDRESS_FILE)
    }

    /// Replaces the allow list. When the set actually changes the helper is
    /// restarted at once with the wider (or narrower) list — existing tunnels
    /// are briefly interrupted and the link reconnects on its own. An empty
    /// list restarts it with `--allow=none`: every tunnel closes and no peer
    /// is admitted until a key is listed again. A staged key's helper gets
    /// the same list.
    pub fn set_allow(&self, allow: &[NodeKey]) {
        let wanted = normalize(allow);
        let helpers = self.helpers();
        if let Some((_, runner)) = &helpers.staged {
            runner.shared.set_allow(wanted.clone());
        }
        helpers.main.shared.set_allow(wanted);
    }

    /// [`Server::set_allow`], with a hand-off: when the list really changes,
    /// `drain` is first called while the running helpers still run, and they
    /// are replaced only once it returns. It is given a reader of the local
    /// addresses of the connections those helpers carry into the link port
    /// (sorted, read from `/proc` at each call), so it can look again when
    /// new connections arrive while it waits. A connection counts as carried
    /// when the helper process owns its other end, so a direct-TLS peer,
    /// even one on loopback, is never among them. `false`, without calling
    /// `drain`, when the list is unchanged.
    pub fn set_allow_draining(
        &self,
        allow: &[NodeKey],
        drain: impl FnOnce(&dyn Fn() -> Vec<SocketAddr>),
    ) -> bool {
        let wanted = normalize(allow);
        let helpers = self.helpers();
        let runners = std::iter::once(&helpers.main).chain(helpers.staged.as_ref().map(|(_, r)| r));
        let mut pids = Vec::with_capacity(2);
        let mut changed = false;
        for runner in runners {
            changed |= *runner.shared.allow.lock().expect("tailcat allow") != wanted;
            pids.extend(runner.state().pid);
        }
        if !changed {
            return false;
        }
        drain(&|| carried_connections(&pids, self.port));
        if let Some((_, runner)) = &helpers.staged {
            runner.shared.set_allow(wanted.clone());
        }
        helpers.main.shared.set_allow(wanted);
        true
    }

    /// Follows the key files an operator's rotation changed (two small reads
    /// when nothing did). A staged key gets a second helper serving it beside
    /// the active one, with the same allow list — the overlap window in which
    /// workers move to its address; an abandoned one loses it. On a commit
    /// the helper already serving the new key becomes the main one, without
    /// a restart, so workers already on the new address keep their tunnel;
    /// the old key's helper stops, and workers still dialing the old address
    /// lose theirs. Two helpers never serve one identity.
    pub fn reload_keys(&self) -> Result<()> {
        let mut helpers = self.helpers();
        let active = active_name(&self.keydir, Role::Controller)?;
        let staged =
            read_staged(&self.keydir, Role::Controller)?.filter(|(name, _)| *name != active);
        if helpers.main.shared.key() != active && self.promotable(&helpers, active)? {
            let (_, runner) = helpers.staged.take().expect("a promotable staged helper");
            runner.shared.promote();
            std::mem::replace(&mut helpers.main, runner).shutdown();
        }
        let current = matches!(
            (&staged, &helpers.staged),
            (Some((_, wanted)), Some((serving, _))) if wanted == serving
        );
        if !current && let Some((_, runner)) = helpers.staged.take() {
            runner.shutdown();
        }
        helpers.main.shared.use_key(active);
        match staged {
            Some((name, key)) if helpers.staged.is_none() => {
                let runner = Runner::spawn(Arc::new(helpers.main.shared.staged(name)), None);
                helpers.staged = Some((key, runner));
            }
            Some(_) => {}
            None => remove_if_present(&self.keydir.join(STAGED_ADDRESS_FILE))?,
        }
        Ok(())
    }

    /// Whether the staged helper serves exactly the key a commit made active:
    /// the same name, and the node key the active record now names.
    fn promotable(&self, helpers: &Helpers, active: &'static str) -> Result<bool> {
        let Some((key, runner)) = &helpers.staged else {
            return Ok(false);
        };
        if runner.shared.key() != active {
            return Ok(false);
        }
        let record = self
            .keydir
            .join(format!("{}.nodekey", key_name(Role::Controller)));
        Ok(read_key(&record)?.as_ref() == Some(key))
    }

    /// The address the staged key is served at, once its helper reported it.
    #[must_use]
    pub fn staged_address(&self) -> Option<Address> {
        let helpers = self.helpers();
        helpers
            .staged
            .as_ref()
            .and_then(|(_, runner)| runner.state().address.clone())
    }

    /// The staged key's helper, while a rotation is in its overlap window.
    #[must_use]
    pub fn staged_telemetry(&self) -> Option<Telemetry> {
        let helpers = self.helpers();
        helpers
            .staged
            .as_ref()
            .map(|(_, runner)| runner.telemetry())
    }

    /// A snapshot for diagnostics.
    #[must_use]
    pub fn telemetry(&self) -> Telemetry {
        self.helpers().main.telemetry()
    }

    /// Stops the helpers and waits for supervision to end. Idempotent.
    pub fn shutdown(&self) {
        let mut helpers = self.helpers();
        if let Some((_, runner)) = helpers.staged.take() {
            runner.shutdown();
        }
        helpers.main.shutdown();
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
            .field("port", &self.port)
            .field("telemetry", &self.telemetry())
            .field("staged", &self.staged_telemetry())
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

    /// A Sentinel session over this forward was lost or refused (a failed
    /// dial included). The helper is replaced at once unless it started less
    /// than [`SESSION_SETTLE`] ago; `true` when it was.
    ///
    /// The controller's helper restarts on every allow-list change, and a
    /// session it carried ends without a close reaching the worker. The same
    /// forward then took 0.9-30.4 s after the lost session to carry a new
    /// one (live suite, sixteen changes), where a fresh helper carried one in
    /// 1.0-1.4 s. `tailcat ping` cannot see the difference (it is a fresh
    /// process each time), so the lost session is the signal. A young helper
    /// is spared so that a controller which is down does not make the worker
    /// kill each successor before it could connect; the probe still judges
    /// it.
    pub fn session_lost(&self) -> bool {
        self.session_lost_after(SESSION_SETTLE)
    }

    /// The controller closed a session (or a connection still in its
    /// handshake) over this forward on purpose, with a TLS `close_notify`:
    /// a hand-off before its helper restarts. The forward carried that
    /// connection through the helper now going away, so it is replaced
    /// whatever its age (a close is authenticated, so a controller that is
    /// down cannot trigger it). Not at once, though: the worker's own end
    /// of the connection must first get through, or the controller never
    /// learns its close was delivered. Live, killing the forward in the same
    /// millisecond left the controller unanswered on most changes. The
    /// replacement therefore waits [`CLOSE_GRACE`], well inside the worker's
    /// shortest back-off, on a thread of its own.
    pub fn session_closed(&self) {
        let Some((generation, _)) = self.run.shared.current_child() else {
            return;
        };
        let shared = Arc::clone(&self.run.shared);
        let spawned = thread::Builder::new()
            .name("tailcat-close-grace".into())
            .spawn(move || {
                thread::sleep(CLOSE_GRACE);
                if !shared.stopped() {
                    shared.replace_probed(generation);
                }
            });
        if spawned.is_err() {
            // No thread to wait on: a late answer beats a stale forward.
            self.run.shared.replace_probed(generation);
        }
    }

    /// As [`Forward::session_lost`], with the settle time stated (tests use
    /// a short one).
    pub fn session_lost_after(&self, settle: Duration) -> bool {
        let Some((generation, born)) = self.run.shared.current_child() else {
            return false;
        };
        if born.elapsed() < settle {
            return false;
        }
        self.run.shared.replace_probed(generation);
        true
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
#[derive(Default)]
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
    network: Arc<Network>,
    role: Role,
    port: u16,
    controller: Option<Address>,
    /// The helper key name this supervisor runs with; `--key` is passed only
    /// when it is not the role's magic default.
    key: Mutex<&'static str>,
    /// Where a controller's helper records its address, under the key
    /// directory: [`ADDRESS_FILE`], or [`STAGED_ADDRESS_FILE`] for the staged
    /// key's helper until a commit promotes it.
    address_file: Mutex<&'static str>,
    /// Canonical node keys, sorted and deduplicated.
    allow: Mutex<Vec<String>>,
    state: Mutex<Telemetry>,
    stop: Mutex<Stop>,
    wake: Condvar,
}

impl Shared {
    /// A supervisor for the controller's staged key: the same helper, port
    /// and allow list, its own key name and address file.
    fn staged(&self, key: &'static str) -> Self {
        let version = self.state.lock().expect("tailcat state").version.clone();
        Self {
            network: Arc::clone(&self.network),
            role: self.role,
            port: self.port,
            controller: None,
            key: Mutex::new(key),
            address_file: Mutex::new(STAGED_ADDRESS_FILE),
            allow: Mutex::new(self.allow.lock().expect("tailcat allow").clone()),
            state: Mutex::new(Telemetry {
                version,
                ..Telemetry::default()
            }),
            stop: Mutex::new(Stop::default()),
            wake: Condvar::new(),
        }
    }

    /// Replaces the allow list; the helper restarts only on a real change.
    fn set_allow(&self, wanted: Vec<String>) {
        {
            let mut current = self.allow.lock().expect("tailcat allow");
            if *current == wanted {
                return;
            }
            *current = wanted;
        }
        self.replace();
    }

    /// The helper key name this supervisor runs with.
    fn key(&self) -> &'static str {
        *self.key.lock().expect("tailcat key")
    }

    /// A staged key's helper becomes the controller's main one: it records
    /// its address in [`ADDRESS_FILE`] from now on (the commit already moved
    /// the file there; this rewrites it only if the address is known).
    fn promote(&self) {
        *self.address_file.lock().expect("tailcat address file") = ADDRESS_FILE;
        let mut state = self.state.lock().expect("tailcat state");
        if let Some(address) = state.address.clone()
            && let Err(problem) = record_address(&self.network.keydir, ADDRESS_FILE, &address)
        {
            state.problem = Some(problem);
        }
    }

    /// Runs the helper with key `name` from now on, replacing it at once if
    /// it used another. `true` when that happened.
    fn use_key(&self, name: &'static str) -> bool {
        {
            let mut key = self.key.lock().expect("tailcat key");
            if *key == name {
                return false;
            }
            *key = name;
        }
        self.replace();
        true
    }

    /// Follows a rotation committed by the operator: a worker's helper
    /// switches to the key the active-key file names.
    fn follow_active_key(&self) -> bool {
        match active_name(&self.network.keydir, self.role) {
            Ok(active) => self.use_key(active),
            // An unreadable file changes nothing; commit writes it atomically.
            Err(_) => false,
        }
    }

    /// `--key=<name>` when this supervisor's key is not the role's default.
    fn key_arg(&self) -> Option<String> {
        let key = self.key();
        (key != key_name(self.role)).then(|| format!("--key={key}"))
    }

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
                args.extend(self.key_arg());
                if let Some(url) = &self.network.derpmap {
                    args.push(format!("--derpmap-url={url}"));
                }
                args.push(self.port.to_string());
            }
            Role::Worker => {
                args.push("forward".to_owned());
                args.push("--bind=127.0.0.1".to_owned());
                args.extend(self.key_arg());
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
                    let file = *self.address_file.lock().expect("tailcat address file");
                    record_address(&self.network.keydir, file, &address)
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
    let key = active_name(&network.keydir, role)?;
    let version = version_of(&network);
    Ok(Arc::new(Shared {
        network: Arc::new(network),
        role,
        port: config.listen_port,
        controller,
        key: Mutex::new(key),
        address_file: Mutex::new(ADDRESS_FILE),
        allow: Mutex::new(allow),
        state: Mutex::new(Telemetry {
            version,
            ..Telemetry::default()
        }),
        stop: Mutex::new(Stop::default()),
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
        // A rotation the operator committed: the helper restarts on the new
        // key, and that successor is judged only after its own interval.
        if shared.follow_active_key() {
            continue;
        }
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
    // The probe proves the identity the forward uses is still admitted.
    args.extend(shared.key_arg());
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
    let record = network.keydir.join(format!("{}.nodekey", key_name(role)));
    if let Some(key) = read_key(&record)? {
        return Ok(key);
    }
    let key = generate(network, role, active_name(&network.keydir, role)?, false)?;
    record_key(&record, &key)?;
    Ok(key)
}

/// Runs `genkey` for the helper key `name` (`force` replaces a leftover one)
/// and returns the node key it printed; the key material stays owner-only.
fn generate(network: &Network, role: Role, name: &str, force: bool) -> Result<NodeKey> {
    let mut args = vec!["genkey".to_owned(), format!("--key={name}")];
    if force {
        args.push("--force".to_owned());
    }
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
    let (Some(dir), Some(name)) = (
        path.parent(),
        path.file_name().and_then(|name| name.to_str()),
    ) else {
        return Err(Error::Unavailable(
            "the nodekey record path has no directory".to_owned(),
        ));
    };
    write_private(dir, name, format!("{}\n", key.expose()).as_bytes())
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

/// Replaces `<keydir>/<name>` atomically with the controller's address.
fn record_address(keydir: &Path, name: &str, address: &Address) -> Result<()> {
    write_private(keydir, name, format!("{}\n", address.expose()).as_bytes())
}

/// Replaces `<dir>/<name>` atomically, owner-only from creation: a temporary
/// file opened `0600` (never through a symlink) is written, synced and
/// renamed over the old one, so a reader sees the old or the new content and
/// nothing in between. Errors name the file, never its content.
fn write_private(dir: &Path, name: &str, bytes: &[u8]) -> Result<()> {
    let target = dir.join(name);
    let staging = dir.join(format!(".{name}.tmp"));
    let failed = |error: io::Error| {
        Error::Unavailable(format!("cannot write the tailcat {name} file: {error}"))
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
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(failed)?;
    drop(file);
    fs::rename(&staging, &target).map_err(failed)
}

/// Makes the renames in `dir` durable before a step that depends on them.
#[cfg(unix)]
fn sync_dir(dir: &Path) -> Result<()> {
    fs::File::open(dir)
        .and_then(|dir| dir.sync_all())
        .map_err(|error| {
            Error::Unavailable(format!("cannot sync the tailcat key directory: {error}"))
        })
}

#[cfg(not(unix))]
fn sync_dir(_dir: &Path) -> Result<()> {
    Ok(())
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

/// The local addresses of the loopback connections into `port` whose other
/// end the processes `pids` own: the controller's view of the sessions a
/// helper carries. Read from `/proc` once per allow-list change: each
/// helper's descriptors give its socket inodes, and the TCP tables map an
/// inode to its addresses. Sorted. Unreadable entries count as not carried,
/// so a failure here only means a session is cut as it was before.
#[cfg(target_os = "linux")]
fn carried_connections(pids: &[u32], port: u16) -> Vec<SocketAddr> {
    let mut inodes = Vec::new();
    for pid in pids {
        let Ok(fds) = fs::read_dir(format!("/proc/{pid}/fd")) else {
            continue;
        };
        for fd in fds.flatten() {
            let Ok(target) = fs::read_link(fd.path()) else {
                continue;
            };
            if let Some(inode) = target
                .to_str()
                .and_then(|text| text.strip_prefix("socket:["))
                .and_then(|text| text.strip_suffix(']'))
                .and_then(|text| text.parse::<u64>().ok())
            {
                inodes.push(inode);
            }
        }
    }
    let Some(pid) = pids.first() else {
        return Vec::new();
    };
    if inodes.is_empty() {
        return Vec::new();
    }
    inodes.sort_unstable();
    let mut carried = Vec::new();
    for table in ["tcp", "tcp6"] {
        let Ok(text) = fs::read_to_string(format!("/proc/{pid}/net/{table}")) else {
            continue;
        };
        for line in text.lines().skip(1) {
            let mut fields = line.split_whitespace();
            let (Some(local), Some(remote), Some(inode)) =
                (fields.nth(1), fields.next(), fields.nth(6))
            else {
                continue;
            };
            let (Some(local), Some(remote), Ok(inode)) =
                (proc_addr(local), proc_addr(remote), inode.parse::<u64>())
            else {
                continue;
            };
            if remote.port() == port && loopback(remote) && inodes.binary_search(&inode).is_ok() {
                carried.push(canonical(local));
            }
        }
    }
    carried.sort_unstable();
    carried
}

/// `addr` with an IPv4-mapped IPv6 address written as IPv4: a dual-stack
/// listener sees an IPv4 peer as mapped, the peer's own table does not.
#[cfg(any(target_os = "linux", feature = "controller"))]
pub(crate) fn canonical(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V6(v6) => match v6.ip().to_ipv4_mapped() {
            Some(ip) => SocketAddr::from((ip, v6.port())),
            None => addr,
        },
        SocketAddr::V4(_) => addr,
    }
}

#[cfg(not(target_os = "linux"))]
fn carried_connections(_pids: &[u32], _port: u16) -> Vec<SocketAddr> {
    Vec::new()
}

/// An address as `/proc/net/tcp{,6}` prints it: the IP as 32-bit words in
/// host byte order, `:`, the port in hex.
#[cfg(target_os = "linux")]
fn proc_addr(text: &str) -> Option<SocketAddr> {
    let (ip, port) = text.split_once(':')?;
    let port = u16::from_str_radix(port, 16).ok()?;
    let word = |index: usize| -> Option<[u8; 4]> {
        let hex = ip.get(index * 8..index * 8 + 8)?;
        Some(u32::from_str_radix(hex, 16).ok()?.to_ne_bytes())
    };
    match ip.len() {
        8 => Some(SocketAddr::from((word(0)?, port))),
        32 => {
            let mut bytes = [0u8; 16];
            for index in 0..4 {
                bytes[index * 4..index * 4 + 4].copy_from_slice(&word(index)?);
            }
            Some(SocketAddr::from((std::net::Ipv6Addr::from(bytes), port)))
        }
        _ => None,
    }
}

#[cfg(target_os = "linux")]
fn loopback(addr: SocketAddr) -> bool {
    match addr.ip() {
        std::net::IpAddr::V4(ip) => ip.is_loopback(),
        std::net::IpAddr::V6(ip) => {
            ip.is_loopback() || ip.to_ipv4_mapped().is_some_and(|ip| ip.is_loopback())
        }
    }
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

    /// The connections a process carries into the link port are the ones it
    /// dialled there, told apart by owner: the same loopback connection is
    /// not carried by a process that does not own its dialling end, and the
    /// accepting end (remote port ephemeral) never is.
    #[cfg(target_os = "linux")]
    #[test]
    fn carried_connections_are_the_owners_dials_into_the_port() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let dialled = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        let (accepted, peer) = listener.accept().unwrap();
        assert_eq!(peer, dialled.local_addr().unwrap());

        let carried = carried_connections(&[std::process::id()], port);
        assert_eq!(carried, vec![peer]);
        // Another process (init) owns neither end.
        assert!(carried_connections(&[1], port).is_empty());
        // Another port is not the link port.
        assert!(carried_connections(&[std::process::id()], port.wrapping_add(1)).is_empty());
        drop((dialled, accepted));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn proc_tcp_addresses_parse_in_host_order() {
        let v4 = proc_addr("0100007F:1F90").unwrap();
        assert_eq!(v4, "127.0.0.1:8080".parse().unwrap());
        let v6 = proc_addr("00000000000000000000000001000000:0050").unwrap();
        assert_eq!(v6, "[::1]:80".parse().unwrap());
        let mapped = proc_addr("0000000000000000FFFF00000100007F:0050").unwrap();
        assert_eq!(canonical(mapped), "127.0.0.1:80".parse().unwrap());
        assert!(loopback(mapped));
        assert!(proc_addr("0100007F").is_none());
        assert!(proc_addr("7F:0050").is_none());
    }
}
