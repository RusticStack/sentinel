//! Named sign-in profiles (O04): `profiles.json` (schema
//! `sentinel.profiles/1`, no secrets) in the configuration directory, the
//! credential blob in the OS store or an owner-only file ([`crate::keystore`]),
//! and access-token refresh serialized across processes by a lock file.
//!
//! Configuration directory: `SENTINEL_CONFIG_DIR`, else `%APPDATA%\Sentinel`
//! (Windows), `$HOME/Library/Application Support/Sentinel` (macOS) or
//! `${XDG_CONFIG_HOME:-$HOME/.config}/sentinel`. A directory inside a Git
//! work tree (any ancestor holding `.git`) is refused, so a credential can
//! never be committed by accident.
//!
//! Refresh: [`Handle::access_token`] answers from memory while more than 30 s
//! of the access token remain; otherwise it takes `locks/<profile>.lock`
//! (an OS file lock, polled for at most 30 s), re-reads the stored
//! credential — another process may have refreshed meanwhile — and only
//! then spends the refresh token. One machine therefore never presents one
//! refresh token twice, which the server would treat as replay.

use std::{
    collections::BTreeMap,
    fmt,
    fs::{File, TryLockError},
    path::{Path, PathBuf},
    sync::Mutex,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use sentinel_auth::oauth::{self as tokens, Kind};
use sentinel_protocol::oauth::{
    GRANT_REFRESH_TOKEN, OAuthError, OAuthErrorCode, TOKEN_PATH, TokenResponse,
};
use serde::{Deserialize, Serialize};

use crate::{
    client::{self, Error, Exit},
    keystore::{self, Backend, file},
};

/// The `schema` of `profiles.json`.
pub const SCHEMA: &str = "sentinel.profiles/1";
/// The profile `sentinel auth login` writes without `--profile`.
pub const DEFAULT_PROFILE: &str = "default";
/// Refresh when fewer than this many milliseconds of the access token remain.
pub const REFRESH_MARGIN_MS: u64 = 30_000;
/// How long a process waits for another's refresh before giving up (exit 6).
pub const LOCK_DEADLINE: Duration = Duration::from_secs(30);
/// Largest OAuth answer read back.
const MAX_ANSWER: u64 = 64 << 10;

/// Milliseconds since the Unix epoch (token expiry is wall-clock time).
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

/// Profile names are file names: 1–64 of `A-Z a-z 0-9 . _ -`, not
/// starting with `.`.
pub fn validate_name(name: &str) -> Result<(), Error> {
    let ok = (1..=64).contains(&name.len())
        && !name.starts_with('.')
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
    if ok {
        Ok(())
    } else {
        Err(Error::usage(
            "a profile name is 1-64 letters, digits, '.', '_' or '-' and does not start with '.'",
        ))
    }
}

/// One entry of `profiles.json`. Never holds a secret.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Profile {
    /// The normalized controller URL.
    pub server: String,
    /// The issuer the server's metadata named at sign-in (equal to `server`).
    pub issuer: String,
    pub client_id: String,
    /// `usr_…` of the signed-in account.
    pub user: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// `grt_…` of the grant.
    pub grant: String,
    /// Space-separated granted scopes.
    pub scopes: String,
    /// Default tenant slug (`sentinel context use`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant: Option<String>,
    /// Where the credential is stored.
    pub store: Backend,
    /// The OS-store key the credential was stored under
    /// ([`keystore::scoped_key`]). Absent for the file store, and for
    /// profiles signed in before keys named their configuration directory,
    /// which keep the legacy per-user [`keystore::key`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    pub created_ms: u64,
}

impl Profile {
    /// The OS-store key of this profile's credential.
    pub fn os_key(&self, name: &str) -> String {
        match &self.key {
            Some(key) => key.clone(),
            None => keystore::key(&self.issuer, name),
        }
    }
}

/// `profiles.json`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Profiles {
    pub schema: String,
    #[serde(default)]
    pub current: Option<String>,
    #[serde(default)]
    pub profiles: BTreeMap<String, Profile>,
}

impl Default for Profiles {
    fn default() -> Self {
        Profiles {
            schema: SCHEMA.to_owned(),
            current: None,
            profiles: BTreeMap::new(),
        }
    }
}

/// The stored credential blob (JSON), kept in the OS store or the
/// owner-only file. `Debug` redacts both tokens.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Credentials {
    /// `sntl_rt_…`
    pub refresh: String,
    /// `sntl_at_…`
    pub access: String,
    pub access_expires_ms: u64,
    pub refresh_expires_ms: u64,
}

impl fmt::Debug for Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credentials")
            .field("refresh", &"redacted")
            .field("access", &"redacted")
            .field("access_expires_ms", &self.access_expires_ms)
            .field("refresh_expires_ms", &self.refresh_expires_ms)
            .finish()
    }
}

impl Credentials {
    /// From a token-endpoint answer received after `sent_ms` (expiry is
    /// counted from the request, never later than the server meant).
    pub fn from_response(response: &TokenResponse, sent_ms: u64) -> Result<Credentials, Error> {
        if tokens::parse(Kind::Access, &response.access_token).is_none()
            || tokens::parse(Kind::Refresh, &response.refresh_token).is_none()
            || !response.token_type.eq_ignore_ascii_case("bearer")
        {
            return Err(Error::remote("the server answered a malformed token"));
        }
        Ok(Credentials {
            refresh: response.refresh_token.clone(),
            access: response.access_token.clone(),
            access_expires_ms: sent_ms.saturating_add(response.expires_in.saturating_mul(1000)),
            refresh_expires_ms: sent_ms
                .saturating_add(response.sentinel_refresh_expires_in.saturating_mul(1000)),
        })
    }

    fn parse(blob: &[u8]) -> Result<Credentials, Error> {
        serde_json::from_slice(blob)
            .map_err(|_| Error::usage("the stored credential is damaged; sign in again"))
    }
}

/// The configuration directory and everything in it.
#[derive(Clone, Debug)]
pub struct Config {
    dir: PathBuf,
}

/// Held while a profile (or `profiles.json`) is being changed; the OS lock
/// is released when the file closes.
pub struct Lock(#[allow(dead_code)] File);

fn env_path(name: &str) -> Option<PathBuf> {
    std::env::var_os(name)
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
}

fn default_dir() -> Result<PathBuf, Error> {
    let missing = |var: &str| {
        Error::usage(format!(
            "cannot locate the configuration directory ({var} is not set); set SENTINEL_CONFIG_DIR"
        ))
    };
    if cfg!(windows) {
        return Ok(env_path("APPDATA")
            .ok_or_else(|| missing("APPDATA"))?
            .join("Sentinel"));
    }
    let home = || env_path("HOME").ok_or_else(|| missing("HOME"));
    if cfg!(target_os = "macos") {
        return Ok(home()?.join("Library/Application Support/Sentinel"));
    }
    match env_path("XDG_CONFIG_HOME").filter(|p| p.is_absolute()) {
        Some(base) => Ok(base.join("sentinel")),
        None => Ok(home()?.join(".config/sentinel")),
    }
}

impl Config {
    /// The directory from the environment (see the module docs).
    pub fn from_env() -> Result<Config, Error> {
        let dir = match env_path("SENTINEL_CONFIG_DIR") {
            Some(dir) => dir,
            None => default_dir()?,
        };
        Config::at(dir)
    }

    /// A configuration directory at `dir`; refused inside a Git work tree.
    pub fn at(dir: impl Into<PathBuf>) -> Result<Config, Error> {
        let dir = std::path::absolute(dir.into())
            .map_err(|e| Error::usage(format!("bad configuration directory: {e}")))?;
        if let Some(repo) = dir
            .ancestors()
            .find(|a| a.join(".git").symlink_metadata().is_ok())
        {
            return Err(Error::usage(format!(
                "the configuration directory {} is inside the Git work tree {}; credentials must \
                 never be committed: set SENTINEL_CONFIG_DIR to a directory outside any repository",
                dir.display(),
                repo.display()
            )));
        }
        Ok(Config { dir })
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn profiles_path(&self) -> PathBuf {
        self.dir.join("profiles.json")
    }

    /// `profiles.json`, or an empty set when there is none.
    pub fn load(&self) -> Result<Profiles, Error> {
        if !self.dir.exists() {
            return Ok(Profiles::default());
        }
        file::check_private(&self.dir)?;
        let Some(data) = file::read_private(&self.profiles_path())? else {
            return Ok(Profiles::default());
        };
        let profiles: Profiles = serde_json::from_slice(&data).map_err(|e| {
            Error::usage(format!(
                "{} is not valid: {e}",
                self.profiles_path().display()
            ))
        })?;
        if profiles.schema != SCHEMA {
            return Err(Error::usage(format!(
                "{} has schema {:?}; this sentinel reads {SCHEMA}",
                self.profiles_path().display(),
                profiles.schema
            )));
        }
        Ok(profiles)
    }

    /// Read-modify-write `profiles.json` under its lock, replaced atomically.
    pub fn update<T>(
        &self,
        change: impl FnOnce(&mut Profiles) -> Result<T, Error>,
    ) -> Result<T, Error> {
        // A name no profile can take (profile names never start with `.`):
        // signing in holds the profile's own lock while updating, and a
        // profile called `profiles` must not wait on itself.
        let _lock = self.lock_path(".profiles")?;
        let mut profiles = self.load()?;
        let out = change(&mut profiles)?;
        let data = serde_json::to_vec_pretty(&profiles).expect("profiles serialize");
        file::write_private(&self.profiles_path(), &data)?;
        Ok(out)
    }

    /// The per-profile lock that serializes refresh, sign-in and sign-out.
    pub fn lock(&self, profile: &str) -> Result<Lock, Error> {
        validate_name(profile)?;
        self.lock_path(profile)
    }

    fn lock_path(&self, name: &str) -> Result<Lock, Error> {
        let dir = self.dir.join("locks");
        file::ensure_private_dir(&self.dir)?;
        file::ensure_private_dir(&dir)?;
        let path = dir.join(format!("{name}.lock"));
        let lock = file::open_lock(&path)?;
        let deadline = Instant::now() + LOCK_DEADLINE;
        let mut pause = Duration::from_millis(2);
        loop {
            match lock.try_lock() {
                Ok(()) => return Ok(Lock(lock)),
                Err(TryLockError::WouldBlock) => {
                    let now = Instant::now();
                    if now >= deadline {
                        return Err(Error::new(
                            Exit::Busy,
                            format!(
                                "another sentinel process has held {} for {} s",
                                path.display(),
                                LOCK_DEADLINE.as_secs()
                            ),
                        ));
                    }
                    std::thread::sleep(pause.min(deadline - now));
                    pause = (pause * 2).min(Duration::from_millis(50));
                }
                Err(TryLockError::Error(e)) => {
                    return Err(Error::usage(format!("cannot lock {}: {e}", path.display())));
                }
            }
        }
    }

    /// The named profile, or the current one; `Ok(None)` when no profile is
    /// configured at all.
    pub fn handle(&self, name: Option<&str>) -> Result<Option<Handle>, Error> {
        let mut profiles = self.load()?;
        let name = match name {
            Some(name) => name.to_owned(),
            None => match profiles.current.take() {
                Some(current) => current,
                None => return Ok(None),
            },
        };
        validate_name(&name)?;
        let Some(profile) = profiles.profiles.remove(&name) else {
            return Err(Error::usage(format!(
                "there is no profile {name}; run: sentinel auth login --server URL --profile {name}"
            )));
        };
        Ok(Some(Handle(Box::new(Inner {
            config: self.clone(),
            name,
            profile,
            cached: Mutex::new(None),
        }))))
    }

    /// The stored credential of `name`, from the backend its profile records.
    pub fn read_credentials(
        &self,
        name: &str,
        profile: &Profile,
    ) -> Result<Option<Credentials>, Error> {
        validate_name(name)?;
        keystore::read(profile.store, &self.dir, &profile.os_key(name), name)?
            .map(|blob| Credentials::parse(&blob))
            .transpose()
    }

    /// Replace the stored credential of `name` in its recorded backend.
    pub fn write_credentials(
        &self,
        name: &str,
        profile: &Profile,
        credentials: &Credentials,
    ) -> Result<(), Error> {
        validate_name(name)?;
        let blob = serde_json::to_vec(credentials).expect("credentials serialize");
        keystore::write(profile.store, &self.dir, &profile.os_key(name), name, &blob)
    }

    /// Store a new credential in `preferred`; when the OS store fails, fall
    /// back to the owner-only file with a notice on stderr. Returns the
    /// backend used and, for the OS store, the key used
    /// ([`keystore::scoped_key`]), for the profile to record.
    pub fn store_credentials(
        &self,
        name: &str,
        issuer: &str,
        preferred: Backend,
        credentials: &Credentials,
    ) -> Result<(Backend, Option<String>), Error> {
        validate_name(name)?;
        let blob = serde_json::to_vec(credentials).expect("credentials serialize");
        let key = keystore::scoped_key(&self.dir, issuer, name);
        match keystore::write(preferred, &self.dir, &key, name, &blob) {
            Ok(()) => Ok((preferred, (preferred == Backend::Os).then_some(key))),
            Err(error) if preferred == Backend::Os => {
                eprintln!(
                    "notice: {}; storing it in an owner-only file under {} instead",
                    error.message,
                    file::credentials_dir(&self.dir).display()
                );
                keystore::write(Backend::File, &self.dir, &key, name, &blob)?;
                Ok((Backend::File, None))
            }
            Err(error) => Err(error),
        }
    }

    /// Remove the stored credential of `name` (absent is fine).
    pub fn delete_credentials(&self, name: &str, profile: &Profile) -> Result<(), Error> {
        validate_name(name)?;
        keystore::delete(profile.store, &self.dir, &profile.os_key(name), name)
    }
}

/// Resolve `name`, or the `current` profile when `None`. `Ok(None)` means
/// no profile is configured at all.
pub fn resolve(name: Option<&str>) -> Result<Option<Handle>, client::Error> {
    Config::from_env()?.handle(name)
}

/// One resolved profile: its name, the normalized server it belongs to, the
/// default tenant, and access to its stored credential.
/// Boxed so a client credential holding it stays pointer-sized.
pub struct Handle(Box<Inner>);

struct Inner {
    config: Config,
    name: String,
    profile: Profile,
    /// The access token last read or minted and its expiry, so a command
    /// making many requests reads the store once.
    cached: Mutex<Option<(String, u64)>>,
}

impl fmt::Debug for Handle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Handle")
            .field("name", &self.0.name)
            .field("server", &self.0.profile.server)
            .finish_non_exhaustive()
    }
}

impl Handle {
    pub fn name(&self) -> &str {
        &self.0.name
    }

    /// The profile's server (normalized when the profile was written).
    pub fn server(&self) -> &str {
        &self.0.profile.server
    }

    /// The default tenant chosen with `sentinel context use`.
    pub fn tenant(&self) -> Option<&str> {
        self.0.profile.tenant.as_deref()
    }

    /// The whole profile entry.
    pub fn profile(&self) -> &Profile {
        &self.0.profile
    }

    fn not_signed_in(&self, why: &str) -> Error {
        Error::new(
            Exit::Auth,
            format!(
                "{why}: not signed in to {server} (profile {profile}); run: sentinel auth login --server {server} --profile {profile}",
                server = self.0.profile.server,
                profile = self.0.name
            ),
        )
    }

    fn remember(&self, credentials: &Credentials) -> String {
        let access = credentials.access.clone();
        *self.0.cached.lock().unwrap_or_else(|e| e.into_inner()) =
            Some((access.clone(), credentials.access_expires_ms));
        access
    }

    fn stored(&self) -> Result<Credentials, Error> {
        self.0
            .config
            .read_credentials(&self.0.name, &self.0.profile)?
            .ok_or_else(|| self.not_signed_in("no stored credential"))
    }

    /// A usable access token, refreshed under the profile lock when fewer
    /// than 30 seconds remain.
    pub fn access_token(&self, agent: &ureq::Agent) -> Result<String, client::Error> {
        let now = now_ms();
        if let Some((token, expires)) = &*self.0.cached.lock().unwrap_or_else(|e| e.into_inner())
            && *expires > now + REFRESH_MARGIN_MS
        {
            return Ok(token.clone());
        }
        let stored = self.stored()?;
        if stored.access_expires_ms > now + REFRESH_MARGIN_MS {
            return Ok(self.remember(&stored));
        }
        // Another process may refresh while this one waits for the lock;
        // whatever is stored then with time left is used as is.
        self.refresh(agent, |_| true)
    }

    /// Refresh after the server rejected `rejected`; if another process has
    /// already replaced it, use the newer token instead of refreshing again.
    pub fn force_refresh(
        &self,
        agent: &ureq::Agent,
        rejected: &str,
    ) -> Result<String, client::Error> {
        self.refresh(agent, |stored| stored.access != rejected)
    }

    /// Under the profile lock: re-read, reuse a token another process minted
    /// when `newer` accepts it and it has time left, else spend the refresh
    /// token and store the successor before anything else can read.
    fn refresh(
        &self,
        agent: &ureq::Agent,
        newer: impl Fn(&Credentials) -> bool,
    ) -> Result<String, Error> {
        let _lock = self.0.config.lock(&self.0.name)?;
        let stored = self.stored()?;
        let now = now_ms();
        if stored.access_expires_ms > now + REFRESH_MARGIN_MS && newer(&stored) {
            return Ok(self.remember(&stored));
        }
        if stored.refresh_expires_ms <= now {
            return Err(self.not_signed_in("the sign-in expired"));
        }
        let form = form(&[
            ("grant_type", GRANT_REFRESH_TOKEN),
            ("refresh_token", &stored.refresh),
            ("client_id", &self.0.profile.client_id),
        ]);
        let url = format!("{}{TOKEN_PATH}", self.0.profile.issuer);
        let mut answer = token_call(agent, &url, &form)?;
        // A busy authorization server spent nothing (or, if the rotation
        // committed after all, a second presentation within the grace
        // window recovers it once), so one retry after the server's
        // `retry-after: 1` is safe and rides out a brief overload.
        if matches!(&answer, Err(e) if e.error == OAuthErrorCode::TemporarilyUnavailable) {
            std::thread::sleep(Duration::from_secs(1));
            answer = token_call(agent, &url, &form)?;
        }
        let response = match answer {
            Ok(response) => response,
            Err(oauth) if oauth_exit(oauth.error) == Exit::Auth => {
                return Err(self.not_signed_in(&format!(
                    "the server refused the refresh ({})",
                    oauth.error.as_str()
                )));
            }
            Err(oauth) => return Err(oauth_failure(&oauth)),
        };
        let fresh = Credentials::from_response(&response, now)?;
        self.0
            .config
            .write_credentials(&self.0.name, &self.0.profile, &fresh)?;
        Ok(self.remember(&fresh))
    }
}

/// An HTTP agent for the OAuth endpoints: statuses are answers, redirects
/// are not followed, 60 s bound.
pub fn agent() -> ureq::Agent {
    ureq::Agent::new_with_config(
        ureq::Agent::config_builder()
            .http_status_as_error(false)
            .max_redirects(0)
            .timeout_global(Some(Duration::from_secs(60)))
            .build(),
    )
}

/// `application/x-www-form-urlencoded` from pairs.
pub fn form(pairs: &[(&str, &str)]) -> String {
    let mut out = form_urlencoded::Serializer::new(String::with_capacity(256));
    for (name, value) in pairs {
        out.append_pair(name, value);
    }
    out.finish()
}

/// The exit for an RFC 6749 error from the token, device or revocation
/// endpoint.
pub fn oauth_exit(code: OAuthErrorCode) -> Exit {
    match code {
        OAuthErrorCode::InvalidGrant
        | OAuthErrorCode::InvalidClient
        | OAuthErrorCode::UnauthorizedClient
        | OAuthErrorCode::AccessDenied
        | OAuthErrorCode::ExpiredToken => Exit::Auth,
        OAuthErrorCode::InvalidScope | OAuthErrorCode::InvalidTarget => Exit::Usage,
        OAuthErrorCode::ServerError
        | OAuthErrorCode::TemporarilyUnavailable
        | OAuthErrorCode::SlowDown => Exit::Busy,
        _ => Exit::Remote,
    }
}

/// An [`Error`] for an OAuth refusal (the description never echoes a
/// submitted value, so it is safe to show).
pub fn oauth_failure(error: &OAuthError) -> Error {
    Error::new(
        oauth_exit(error.error),
        format!("the server refused: {error}"),
    )
}

fn transport(url: &str, error: &ureq::Error) -> Error {
    let origin = url.split('/').take(3).collect::<Vec<_>>().join("/");
    Error::new(Exit::Busy, format!("cannot reach {origin}: {error}"))
}

/// Status and body (at most 64 KiB) of a POST of `form` to `url`.
pub fn post_form(agent: &ureq::Agent, url: &str, form: &str) -> Result<(u16, String), Error> {
    let response = agent
        .post(url)
        .header("content-type", "application/x-www-form-urlencoded")
        .header("accept", "application/json")
        .send(form.as_bytes())
        .map_err(|e| transport(url, &e))?;
    read_answer(url, response)
}

/// Status and body (at most 64 KiB) of a GET, with an optional bearer.
pub fn get(agent: &ureq::Agent, url: &str, bearer: Option<&str>) -> Result<(u16, String), Error> {
    let mut request = agent.get(url).header("accept", "application/json");
    let auth;
    if let Some(token) = bearer {
        auth = format!("Bearer {token}");
        request = request.header("authorization", &auth);
    }
    let response = request.call().map_err(|e| transport(url, &e))?;
    read_answer(url, response)
}

fn read_answer(
    url: &str,
    response: ureq::http::Response<ureq::Body>,
) -> Result<(u16, String), Error> {
    let status = response.status().as_u16();
    let body = response
        .into_body()
        .into_with_config()
        .limit(MAX_ANSWER)
        .read_to_string()
        .map_err(|e| transport(url, &e))?;
    Ok((status, body))
}

/// POST to the token endpoint: `Ok(Ok(tokens))`, `Ok(Err(oauth error))`, or
/// `Err` for transport failures and malformed answers.
pub fn token_call(
    agent: &ureq::Agent,
    url: &str,
    form: &str,
) -> Result<Result<TokenResponse, OAuthError>, Error> {
    let (status, body) = post_form(agent, url, form)?;
    if status == 200 {
        return serde_json::from_str(&body)
            .map(Ok)
            .map_err(|_| Error::remote("the token endpoint answered malformed JSON"));
    }
    match serde_json::from_str::<OAuthError>(&body) {
        Ok(error) => Ok(Err(error)),
        Err(_) if status >= 500 => Err(Error::new(
            Exit::Busy,
            format!("the token endpoint answered HTTP {status}"),
        )),
        Err(_) => Err(Error::remote(format!(
            "the token endpoint answered HTTP {status}"
        ))),
    }
}
