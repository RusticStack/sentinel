use std::{
    fmt, fs, io,
    io::{BufRead, BufReader, Read, Write},
    net::{Ipv4Addr, SocketAddr},
    path::{Component, Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicU64, Ordering},
        mpsc::{self, RecvTimeoutError},
    },
    thread,
    time::{Duration, Instant},
};

use sentinel_core::WorkerId;
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::session::Path as Route;

pub const PINNED_VERSION: &str = "0.6.0";
pub const PINNED_SHA256: &str = "d46582137d21f03d15345e2be425d6317d49e5b8c8bb4f6fc56037f4c08cce73";
pub const DEFAULT_LINK_PORT: u16 = 7443;
pub const ALLOW_LIST_FILE: &str = "tailcat-allow";
/// Owner-only, empty and never removed: its exclusive lock serializes every edit of the allow list.
pub const ALLOW_LIST_LOCK_FILE: &str = "tailcat-allow.lock";
pub const ADDRESS_FILE: &str = "address";
pub const STAGED_ADDRESS_FILE: &str = "address.next";

const KEY_DIR: &str = "tailcat";
const KEY_NAME: &str = "default";
const ROTATED_SERVER_KEY: &str = "rotated";
const ROTATED_CLIENT_KEY: &str = "client-rotated";
const ACTIVE_FILE: &str = "active-key";
const STAGED_FILE: &str = "staged.nodekey";
const SMALL_FILE_CAP: u64 = 256;
const READY_DEADLINE: Duration = Duration::from_secs(60);
const PROBE_EVERY: Duration = Duration::from_secs(30);
pub const SESSION_SETTLE: Duration = Duration::from_secs(10);
// Below the worker's shortest back-off (750 ms), so its next dial meets a fresh forward.
pub const CLOSE_GRACE: Duration = Duration::from_millis(200);
const RESTART_MIN: Duration = Duration::from_secs(1);
const RESTART_MAX: Duration = Duration::from_secs(30);
const PING_TIMEOUT: Duration = Duration::from_secs(10);
const PING_MARGIN: Duration = Duration::from_secs(5);
const GENKEY_TIMEOUT: Duration = Duration::from_secs(30);
const VERSION_TIMEOUT: Duration = Duration::from_secs(5);
const POLL: Duration = Duration::from_millis(100);
const LINE_CAP: u64 = 8 * 1024;
const OUTPUT_CAP: u64 = 64 * 1024;
const ALLOW_LIST_CAP: u64 = 64 * 1024;
const ALLOW_LOCK_DEADLINE: Duration = Duration::from_secs(10);

const FORBIDDEN: [&str; 5] = ["all", "exit-node", "ssh", "files", "no-auth-ssh"];
const INHERITED_ENV: [&str; 2] = ["SSL_CERT_FILE", "SSL_CERT_DIR"];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Controller,
    Worker,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TailcatConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_binary")]
    pub binary: PathBuf,
    #[serde(default = "default_sha256")]
    pub sha256: String,
    #[serde(default)]
    pub derpmap_url: Option<String>,
    #[serde(default)]
    pub region: Option<String>,
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

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NodeKey(String);

impl NodeKey {
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        let body = text.trim().strip_prefix("nodekey:")?;
        if body.len() != 64 || !body.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return None;
        }
        Some(Self(format!("nodekey:{}", body.to_ascii_lowercase())))
    }

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

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Address(String);

impl Address {
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Unavailable(String),
    Checksum { expected: String, found: String },
    Refused(&'static str),
    Spawn(String),
    Exited(Option<i32>),
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

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Clone, Debug, Default)]
pub struct Telemetry {
    pub pid: Option<u32>,
    pub ready: bool,
    pub restarts: u64,
    pub version: Option<String>,
    pub address: Option<Address>,
    pub path: Route,
    pub ping_rtt: Option<Duration>,
    pub problem: Option<Error>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Admission {
    pub key: NodeKey,
    pub worker: WorkerId,
}

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
    server.reload_keys()?;
    Ok(server)
}

pub fn start_forward(
    config: &TailcatConfig,
    data_dir: &Path,
    controller: &Address,
) -> Result<Forward> {
    start_forward_every(config, data_dir, controller, PROBE_EVERY)
}

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

pub fn ensure_key(config: &TailcatConfig, data_dir: &Path, role: Role) -> Result<NodeKey> {
    let network = config.network(data_dir)?;
    ensure(&network, role)
}

#[must_use]
pub fn nodekey_file(data_dir: &Path, role: Role) -> PathBuf {
    data_dir
        .join(KEY_DIR)
        .join(format!("{}.nodekey", key_name(role)))
}

fn key_name(role: Role) -> &'static str {
    key_names(role)[0]
}

fn key_names(role: Role) -> [&'static str; 2] {
    match role {
        Role::Controller => [KEY_NAME, ROTATED_SERVER_KEY],
        Role::Worker => ["client-default", ROTATED_CLIENT_KEY],
    }
}

#[must_use]
pub fn staged_address_file(data_dir: &Path) -> PathBuf {
    data_dir.join(KEY_DIR).join(STAGED_ADDRESS_FILE)
}

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

pub fn staged_rotation(data_dir: &Path, role: Role) -> Result<Option<NodeKey>> {
    Ok(read_staged(&data_dir.join(KEY_DIR), role)?.map(|(_, key)| key))
}

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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Committed {
    pub key: NodeKey,
    pub previous_deleted: bool,
}

/// Hold the allow list's edit lock until the returned file is dropped. Admit, retire, prune and
/// revoke each read, edit and replace the file, from separate processes (the admin commands and the
/// controller's tick), so the whole sequence runs under it or a later writer would erase an earlier
/// one's change. Readers need no lock: the replacement is atomic.
fn lock_allow_list(data_dir: &Path) -> Result<fs::File> {
    let path = data_dir.join(ALLOW_LIST_LOCK_FILE);
    let failed = |error: io::Error| {
        Error::Unavailable(format!("cannot lock the tailcat allow list: {error}"))
    };
    let mut options = fs::OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let file = options.open(&path).map_err(failed)?;
    let deadline = Instant::now() + ALLOW_LOCK_DEADLINE;
    let mut pause = Duration::from_millis(1);
    loop {
        match file.try_lock() {
            Ok(()) => return Ok(file),
            Err(fs::TryLockError::WouldBlock) => {
                let now = Instant::now();
                if now >= deadline {
                    return Err(Error::Unavailable(
                        "another process has held the tailcat allow list lock for 10 s".to_owned(),
                    ));
                }
                thread::sleep(pause.min(deadline - now));
                pause = (pause * 2).min(Duration::from_millis(25));
            }
            Err(fs::TryLockError::Error(error)) => return Err(failed(error)),
        }
    }
}

pub fn admit(data_dir: &Path, admission: &Admission) -> Result<bool> {
    let _lock = lock_allow_list(data_dir)?;
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

pub fn retire(data_dir: &Path, keep: &Admission) -> Result<usize> {
    let _lock = lock_allow_list(data_dir)?;
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

/// Remove every listed line `drop_line` answers true for, and report how many went. The file is
/// replaced atomically and stays owner-only; comments, blank lines and the other lines are kept
/// byte for byte, and nothing is written when no line matches.
pub fn prune(data_dir: &Path, mut drop_line: impl FnMut(&Admission) -> bool) -> Result<usize> {
    let _lock = lock_allow_list(data_dir)?;
    // Refuse a file `allow_list` would refuse (not a regular owner-only file, malformed, too big).
    allow_list(data_dir)?;
    let text = read_allow_text(data_dir)?;
    let mut kept = String::with_capacity(text.len());
    let mut removed = 0;
    for line in text.lines() {
        if parse_admission(line.trim()).is_some_and(|listed| drop_line(&listed)) {
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

/// Take every key of one worker off the allow list (its uninstall or revocation), the overlap-window
/// key of a rotation included. Reports how many lines went.
pub fn revoke(data_dir: &Path, worker: WorkerId) -> Result<usize> {
    prune(data_dir, |listed| listed.worker == worker)
}

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

fn read_allow_text(data_dir: &Path) -> Result<String> {
    match fs::read_to_string(data_dir.join(ALLOW_LIST_FILE)) {
        Ok(text) => Ok(text),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(String::new()),
        Err(error) => Err(Error::Unavailable(format!(
            "cannot read the tailcat allow list: {error}"
        ))),
    }
}

fn other_name(role: Role, name: &str) -> &'static str {
    let [first, second] = key_names(role);
    if name == first { second } else { first }
}

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

pub struct Server {
    keydir: PathBuf,
    port: u16,
    helpers: Mutex<Helpers>,
}

struct Helpers {
    main: Runner,
    staged: Option<(NodeKey, Runner)>,
}

impl Server {
    fn helpers(&self) -> std::sync::MutexGuard<'_, Helpers> {
        self.helpers.lock().expect("tailcat helpers")
    }

    #[must_use]
    pub fn address(&self) -> Option<Address> {
        self.helpers().main.state().address.clone()
    }

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

    #[must_use]
    pub fn port(&self) -> u16 {
        self.port
    }

    #[must_use]
    pub fn address_file(&self) -> PathBuf {
        self.keydir.join(ADDRESS_FILE)
    }

    pub fn set_allow(&self, allow: &[NodeKey]) {
        let wanted = normalize(allow);
        let helpers = self.helpers();
        if let Some((_, runner)) = &helpers.staged {
            runner.shared.set_allow(wanted.clone());
        }
        helpers.main.shared.set_allow(wanted);
    }

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

    #[must_use]
    pub fn staged_address(&self) -> Option<Address> {
        let helpers = self.helpers();
        helpers
            .staged
            .as_ref()
            .and_then(|(_, runner)| runner.state().address.clone())
    }

    #[must_use]
    pub fn staged_telemetry(&self) -> Option<Telemetry> {
        let helpers = self.helpers();
        helpers
            .staged
            .as_ref()
            .map(|(_, runner)| runner.telemetry())
    }

    #[must_use]
    pub fn telemetry(&self) -> Telemetry {
        self.helpers().main.telemetry()
    }

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

pub struct Forward {
    run: Runner,
}

impl Forward {
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        SocketAddr::from((Ipv4Addr::LOCALHOST, self.run.shared.port))
    }

    pub fn probe(&self) -> Result<Measured> {
        probe_once(&self.run.shared)
    }

    pub fn restart(&self) {
        self.run.shared.replace();
    }

    pub fn session_lost(&self) -> bool {
        self.session_lost_after(SESSION_SETTLE)
    }

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
            self.run.shared.replace_probed(generation);
        }
    }

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

    #[must_use]
    pub fn telemetry(&self) -> Telemetry {
        self.run.telemetry()
    }

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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Measured {
    pub path: Route,
    pub rtt: Option<Duration>,
}

struct Network {
    binary: PathBuf,
    digest: [u8; 32],
    keydir: PathBuf,
    derpmap: Option<String>,
    region: Option<String>,
    verified: Mutex<Option<Stamp>>,
}

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
        network.open_verified()?;
        Ok(network)
    }
}

impl Network {
    // The child execs the verified descriptor, so a file swapped after the check cannot run.
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
                    // A SIGKILLed Sentinel must not leave a helper holding the tunnel.
                    if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) != 0 {
                        return Err(io::Error::last_os_error());
                    }
                    if libc::getppid() as u32 != parent {
                        return Err(io::Error::from_raw_os_error(libc::ESRCH));
                    }
                    // Keep the verified descriptor open across exec: a #! helper reopens it by path.
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
        drop(binary);
        Ok(child)
    }

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

#[cfg(not(unix))]
fn stamp(_metadata: &fs::Metadata) -> Option<Stamp> {
    None
}

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

#[derive(Default)]
struct Stop {
    stopped: bool,
    replacing: bool,
    child: Option<Child>,
    generation: u64,
    born: Option<Instant>,
}

struct Shared {
    network: Arc<Network>,
    role: Role,
    port: u16,
    controller: Option<Address>,
    key: Mutex<&'static str>,
    address_file: Mutex<&'static str>,
    allow: Mutex<Vec<String>>,
    state: Mutex<Telemetry>,
    stop: Mutex<Stop>,
    wake: Condvar,
}

impl Shared {
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

    fn key(&self) -> &'static str {
        *self.key.lock().expect("tailcat key")
    }

    fn promote(&self) {
        *self.address_file.lock().expect("tailcat address file") = ADDRESS_FILE;
        let mut state = self.state.lock().expect("tailcat state");
        if let Some(address) = state.address.clone()
            && let Err(problem) = record_address(&self.network.keydir, ADDRESS_FILE, &address)
        {
            state.problem = Some(problem);
        }
    }

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

    fn follow_active_key(&self) -> bool {
        match active_name(&self.network.keydir, self.role) {
            Ok(active) => self.use_key(active),
            Err(_) => false,
        }
    }

    fn key_arg(&self) -> Option<String> {
        let key = self.key();
        (key != key_name(self.role)).then(|| format!("--key={key}"))
    }

    fn stopped(&self) -> bool {
        self.stop.lock().expect("tailcat stop").stopped
    }

    fn wait(&self, timeout: Duration) -> bool {
        let stop = self.stop.lock().expect("tailcat stop");
        if stop.stopped {
            return false;
        }
        let (stop, _) = self.wake.wait_timeout(stop, timeout).expect("tailcat wake");
        !stop.stopped
    }

    fn halt(&self) {
        let mut stop = self.stop.lock().expect("tailcat stop");
        stop.stopped = true;
        if let Some(child) = stop.child.as_mut() {
            let _ = child.kill();
        }
        self.wake.notify_all();
    }

    fn kill(&self) {
        let mut stop = self.stop.lock().expect("tailcat stop");
        if let Some(child) = stop.child.as_mut() {
            let _ = child.kill();
        }
    }

    fn replace(&self) {
        let mut stop = self.stop.lock().expect("tailcat stop");
        stop.replacing = true;
        if let Some(child) = stop.child.as_mut() {
            let _ = child.kill();
        }
        self.wake.notify_all();
    }

    fn current_child(&self) -> Option<(u64, Instant)> {
        let stop = self.stop.lock().expect("tailcat stop");
        stop.born.map(|born| (stop.generation, born))
    }

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

    fn take_replacing(&self) -> bool {
        std::mem::take(&mut self.stop.lock().expect("tailcat stop").replacing)
    }

    fn fail(&self, problem: Error) {
        self.state.lock().expect("tailcat state").problem = Some(problem);
    }

    fn args(&self) -> Vec<String> {
        let mut args = Vec::new();
        match self.role {
            Role::Controller => {
                args.push("serve".to_owned());
                // Upstream treats an absent or empty --allow as every peer, so an empty list must be
                // the explicit `none`, never an omitted flag.
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
                // Written before telemetry publishes the address, so a caller that saw `wait_ready` finds the file.
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
                if contains_ascii_ci(line, "forwarding") {
                    let mut state = self.state.lock().expect("tailcat state");
                    state.ready = state.problem.is_none();
                }
            }
        }
    }
}

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

fn run_child(shared: &Arc<Shared>) -> (Result<()>, bool) {
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
    let status = status.map(|mut child| {
        let _ = child.kill();
        child.wait()
    });
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
        _ if expired => Err(Error::Timeout("the helper never reported readiness")),
        None => Ok(()),
        Some(Ok(status)) if status.success() => Ok(()),
        Some(Ok(status)) => Err(Error::Exited(status.code())),
        Some(Err(error)) => Err(Error::Spawn(error.to_string())),
    };
    (outcome, healthy)
}

fn exited(shared: &Shared) -> bool {
    let mut stop = shared.stop.lock().expect("tailcat stop");
    match stop.child.as_mut() {
        Some(child) => !matches!(child.try_wait(), Ok(None)),
        None => true,
    }
}

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

fn ensure(network: &Network, role: Role) -> Result<NodeKey> {
    let record = network.keydir.join(format!("{}.nodekey", key_name(role)));
    if let Some(key) = read_key(&record)? {
        return Ok(key);
    }
    let key = generate(network, role, active_name(&network.keydir, role)?, false)?;
    record_key(&record, &key)?;
    Ok(key)
}

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
        Role::Worker => find_nodekey(&text),
        Role::Controller => match text.split_whitespace().find_map(Address::parse) {
            Some(address) => server_public(network, &address)?,
            None => None,
        },
    }
    .ok_or_else(|| Error::Unavailable("genkey printed no nodekey".to_owned()))?;
    tighten(&network.keydir, 0)?;
    Ok(key)
}

fn server_public(network: &Network, address: &Address) -> Result<Option<NodeKey>> {
    let args = ["parse".to_owned(), address.expose().to_owned()];
    let captured = output_within(network.spawn(&args)?, VERSION_TIMEOUT, &|| false)?;
    if !captured.status.success() {
        return Ok(None);
    }
    Ok(find_nodekey(&String::from_utf8_lossy(&captured.stdout)))
}

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

fn record_address(keydir: &Path, name: &str, address: &Address) -> Result<()> {
    write_private(keydir, name, format!("{}\n", address.expose()).as_bytes())
}

fn write_private(dir: &Path, name: &str, bytes: &[u8]) -> Result<()> {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let target = dir.join(name);
    // A name of its own, so no writer removes or renames another's staging file.
    let staging = dir.join(format!(
        ".{name}.{}.{}.tmp",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let failed = |error: io::Error| {
        let _ = fs::remove_file(&staging);
        Error::Unavailable(format!("cannot write the tailcat {name} file: {error}"))
    };
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

fn check_argv(args: &[String]) -> Result<()> {
    for arg in args {
        if let Some(word) = refuses(arg) {
            return Err(Error::Refused(word));
        }
    }
    Ok(())
}

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
        assert!(carried_connections(&[1], port).is_empty());
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
