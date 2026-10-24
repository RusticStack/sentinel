//! Refresh is serialized by the profile lock and re-reads the store first: presenting one refresh token twice counts as replay.

use std::{
    collections::BTreeMap,
    fmt,
    fs::{File, TryLockError},
    path::{Path, PathBuf},
    sync::{Mutex, OnceLock},
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

pub const SCHEMA: &str = "sentinel.profiles/1";
pub const DEFAULT_PROFILE: &str = "default";
pub const REFRESH_MARGIN_MS: u64 = 30_000;
pub const LOCK_DEADLINE: Duration = Duration::from_secs(30);
const MAX_ANSWER: u64 = 64 << 10;

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Profile {
    pub server: String,
    pub issuer: String,
    pub client_id: String,
    pub user: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    pub grant: String,
    pub scopes: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant: Option<String>,
    pub store: Backend,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    pub created_ms: u64,
}

impl Profile {
    pub fn os_key(&self, name: &str) -> String {
        match &self.key {
            Some(key) => key.clone(),
            None => keystore::key(&self.issuer, name),
        }
    }

    pub fn is_legacy(&self) -> bool {
        self.store == Backend::Os && self.key.is_none()
    }

    // profiles.json chooses where refresh tokens go and which OS-store entry is deleted, so a changed file must not steer either.
    pub fn check(&self, name: &str) -> Result<(), Error> {
        let tampered = |what: &str| {
            Error::usage(format!(
                "profile {name} in profiles.json has {what}, which no sign-in writes; nothing was \
                 sent. Sign in again: sentinel auth login --server {} --profile {name}",
                self.server
            ))
        };
        if client::normalize_server(&self.server).ok().as_deref() != Some(self.server.as_str())
            || self.issuer != self.server
        {
            return Err(tampered("an issuer that is not its server"));
        }
        if let Some(key) = &self.key {
            let scoped = key
                .strip_prefix(&keystore::key(&self.issuer, name))
                .and_then(|rest| rest.strip_prefix(':'))
                .is_some_and(|digest| {
                    digest.len() == 16
                        && digest
                            .bytes()
                            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                });
            if !scoped {
                return Err(tampered("a credential-store key of another profile"));
            }
        }
        Ok(())
    }
}

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

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Credentials {
    pub refresh: String,
    pub access: String,
    pub access_expires_ms: u64,
    pub refresh_expires_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant: Option<String>,
}

impl fmt::Debug for Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credentials")
            .field("refresh", &"redacted")
            .field("access", &"redacted")
            .field("access_expires_ms", &self.access_expires_ms)
            .field("refresh_expires_ms", &self.refresh_expires_ms)
            .field("grant", &self.grant)
            .finish()
    }
}

impl Credentials {
    // Expiry counts from the send time, so the client never trusts a token past the server's expiry.
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
            grant: Some(response.sentinel_grant.clone()),
        })
    }

    fn parse(blob: &[u8]) -> Result<Credentials, Error> {
        serde_json::from_slice(blob)
            .map_err(|_| Error::usage("the stored credential is damaged; sign in again"))
    }
}

#[derive(Clone, Debug)]
pub struct Config {
    dir: PathBuf,
}

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
    match env_path("XDG_CONFIG_HOME").filter(|p| p.is_absolute()) {
        Some(base) => Ok(base.join("sentinel")),
        None => Ok(home()?.join(".config/sentinel")),
    }
}

impl Config {
    pub fn from_env() -> Result<Config, Error> {
        let dir = match env_path("SENTINEL_CONFIG_DIR") {
            Some(dir) => dir,
            None => default_dir()?,
        };
        Config::at(dir)
    }

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

    pub fn update<T>(
        &self,
        change: impl FnOnce(&mut Profiles) -> Result<T, Error>,
    ) -> Result<T, Error> {
        // Profile names never start with '.', so this lock cannot be a profile's own lock.
        let _lock = self.lock_path(".profiles")?;
        let mut profiles = self.load()?;
        let out = change(&mut profiles)?;
        let data = serde_json::to_vec_pretty(&profiles).expect("profiles serialize");
        file::write_private(&self.profiles_path(), &data)?;
        Ok(out)
    }

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
        profile.check(&name)?;
        Ok(Some(Handle(Box::new(Inner {
            config: self.clone(),
            name,
            profile,
            cached: Mutex::new(None),
            migrated: OnceLock::new(),
        }))))
    }

    pub fn legacy_owner(&self, agent: &ureq::Agent, name: &str, profile: &Profile) -> Owner {
        let stored = match self.read_credentials(name, profile) {
            Ok(Some(stored)) => stored,
            Ok(None) => return Owner::Absent,
            Err(_) => return Owner::Unknown,
        };
        let ours = |grant: &str| grant == profile.grant;
        if let Some(grant) = &stored.grant {
            return if ours(grant) {
                Owner::Ours(stored)
            } else {
                Owner::Theirs
            };
        }
        let now = now_ms();
        if stored.access_expires_ms > now + REFRESH_MARGIN_MS {
            let url = format!("{}/api/v1/me", profile.server);
            if let Ok((200, body)) = get(agent, &url, Some(&stored.access)) {
                let me: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();
                return match me["grant"].as_str() {
                    Some(grant) if ours(grant) => Owner::Ours(stored),
                    Some(_) => Owner::Theirs,
                    None => Owner::Unknown,
                };
            }
        }
        if stored.refresh_expires_ms <= now {
            return Owner::Ours(stored);
        }
        let form = form(&[
            ("grant_type", GRANT_REFRESH_TOKEN),
            ("refresh_token", &stored.refresh),
            ("client_id", &profile.client_id),
        ]);
        let answer = token_call(agent, &format!("{}{TOKEN_PATH}", profile.issuer), &form);
        let Ok(Ok(response)) = answer else {
            return Owner::Unknown;
        };
        let Ok(fresh) = Credentials::from_response(&response, now) else {
            return Owner::Unknown;
        };
        if ours(&response.sentinel_grant) {
            Owner::Ours(fresh)
        } else {
            let _ = self.write_credentials(name, profile, &fresh);
            Owner::Theirs
        }
    }

    pub fn read_credentials(
        &self,
        name: &str,
        profile: &Profile,
    ) -> Result<Option<Credentials>, Error> {
        validate_name(name)?;
        profile.check(name)?;
        keystore::read(profile.store, &self.dir, &profile.os_key(name), name)?
            .map(|blob| Credentials::parse(&blob))
            .transpose()
    }

    pub fn write_credentials(
        &self,
        name: &str,
        profile: &Profile,
        credentials: &Credentials,
    ) -> Result<(), Error> {
        validate_name(name)?;
        profile.check(name)?;
        let blob = serde_json::to_vec(credentials).expect("credentials serialize");
        keystore::write(profile.store, &self.dir, &profile.os_key(name), name, &blob)
    }

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

    pub fn delete_credentials(&self, name: &str, profile: &Profile) -> Result<(), Error> {
        validate_name(name)?;
        profile.check(name)?;
        keystore::delete(profile.store, &self.dir, &profile.os_key(name), name)
    }
}

#[derive(Debug)]
pub enum Owner {
    Absent,
    Ours(Credentials),
    Theirs,
    Unknown,
}

pub fn resolve(name: Option<&str>) -> Result<Option<Handle>, client::Error> {
    Config::from_env()?.handle(name)
}

pub struct Handle(Box<Inner>);

struct Inner {
    config: Config,
    name: String,
    profile: Profile,
    cached: Mutex<Option<(String, u64)>>,
    migrated: OnceLock<String>,
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

    pub fn server(&self) -> &str {
        &self.0.profile.server
    }

    pub fn tenant(&self) -> Option<&str> {
        self.0.profile.tenant.as_deref()
    }

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

    fn location(&self) -> std::borrow::Cow<'_, Profile> {
        match self.0.migrated.get() {
            Some(key) => std::borrow::Cow::Owned(Profile {
                key: Some(key.clone()),
                ..self.0.profile.clone()
            }),
            None => std::borrow::Cow::Borrowed(&self.0.profile),
        }
    }

    fn legacy(&self) -> bool {
        self.0.profile.is_legacy() && self.0.migrated.get().is_none()
    }

    fn stored(&self) -> Result<Credentials, Error> {
        let config = &self.0.config;
        let mut stored = config.read_credentials(&self.0.name, &self.location())?;
        if stored.is_none() && self.legacy() {
            let moved = config
                .load()?
                .profiles
                .remove(&self.0.name)
                .filter(|p| p.grant == self.0.profile.grant && p.store == Backend::Os)
                .and_then(|p| p.check(&self.0.name).ok().and(p.key));
            if let Some(key) = moved {
                let _ = self.0.migrated.set(key);
                stored = config.read_credentials(&self.0.name, &self.location())?;
            }
        }
        let stored = stored.ok_or_else(|| self.not_signed_in("no stored credential"))?;
        if self.legacy()
            && stored
                .grant
                .as_ref()
                .is_some_and(|g| *g != self.0.profile.grant)
        {
            return Err(self.not_signed_in(
                "the shared credential entry now holds another configuration directory's sign-in",
            ));
        }
        Ok(stored)
    }

    fn migrate(&self, fresh: &Credentials) -> Result<(), Error> {
        let (config, name, profile) = (&self.0.config, &self.0.name, &self.0.profile);
        config.write_credentials(name, profile, fresh)?;
        if fresh.grant.as_deref() != Some(profile.grant.as_str()) {
            return Err(self.not_signed_in(
                "the shared credential entry held another configuration directory's sign-in",
            ));
        }
        let key = keystore::scoped_key(config.dir(), &profile.issuer, name);
        let moved = Profile {
            key: Some(key.clone()),
            ..profile.clone()
        };
        config.write_credentials(name, &moved, fresh)?;
        config.update(|profiles| {
            if let Some(entry) = profiles.profiles.get_mut(name)
                && entry.is_legacy()
                && entry.grant == profile.grant
            {
                entry.key = Some(key.clone());
            }
            Ok(())
        })?;
        let _ = self.0.migrated.set(key);
        let _ = config.delete_credentials(name, profile);
        Ok(())
    }

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
        self.refresh(agent, |_| true)
    }

    pub fn force_refresh(
        &self,
        agent: &ureq::Agent,
        rejected: &str,
    ) -> Result<String, client::Error> {
        self.refresh(agent, |stored| stored.access != rejected)
    }

    fn refresh(
        &self,
        agent: &ureq::Agent,
        newer: impl Fn(&Credentials) -> bool,
    ) -> Result<String, Error> {
        let _lock = self.0.config.lock(&self.0.name)?;
        #[cfg(windows)]
        let _legacy = if self.legacy() {
            let key = keystore::key(&self.0.profile.issuer, &self.0.name);
            Some(
                keystore::windows::LegacyLock::acquire(&key, LOCK_DEADLINE).map_err(|e| {
                    Error::new(
                        Exit::Busy,
                        format!("another sentinel process holds the shared credential entry: {e}"),
                    )
                })?,
            )
        } else {
            None
        };
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
        if self.legacy() {
            self.migrate(&fresh)?;
        } else {
            self.0
                .config
                .write_credentials(&self.0.name, &self.location(), &fresh)?;
        }
        Ok(self.remember(&fresh))
    }
}

pub fn agent() -> ureq::Agent {
    ureq::Agent::new_with_config(
        ureq::Agent::config_builder()
            .http_status_as_error(false)
            .max_redirects(0)
            .timeout_global(Some(Duration::from_secs(60)))
            .build(),
    )
}

pub fn form(pairs: &[(&str, &str)]) -> String {
    let mut out = form_urlencoded::Serializer::new(String::with_capacity(256));
    for (name, value) in pairs {
        out.append_pair(name, value);
    }
    out.finish()
}

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

pub fn post_form(agent: &ureq::Agent, url: &str, form: &str) -> Result<(u16, String), Error> {
    let response = agent
        .post(url)
        .header("content-type", "application/x-www-form-urlencoded")
        .header("accept", "application/json")
        .send(form.as_bytes())
        .map_err(|e| transport(url, &e))?;
    read_answer(url, response)
}

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
