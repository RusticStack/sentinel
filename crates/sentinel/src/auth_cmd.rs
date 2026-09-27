//! `sentinel auth login|status|logout` and `sentinel context use|show` (O04):
//! browser (loopback + PKCE) and device sign-in, grant import for agents,
//! status without token material, logout with server revocation.
//!
//! Every sign-in starts from the server's metadata: its `issuer` must be the
//! normalized `--server` exactly and every endpoint must share its origin,
//! so a credential is only ever sent where it was issued. Token material
//! never reaches stdout or stderr; the device code stays in memory.

use std::{
    io::Read,
    path::{Path, PathBuf},
    thread,
    time::{Duration, Instant},
};

use clap::{Args, Subcommand};
use sentinel_auth::{
    oauth::{self as tokens, Kind, pkce},
    secret::Secret,
};
use sentinel_protocol::oauth::{
    API_RESOURCE_SUFFIX, CLI_CLIENT_ID, DeviceAuthorization, GRANT_AUTHORIZATION_CODE,
    GRANT_DEVICE_CODE, GRANT_REFRESH_TOKEN, METADATA_PATH, Metadata, OAuthErrorCode, REVOKE_PATH,
    TokenResponse,
};
use serde_json::{Value, json};

use crate::{
    browser,
    client::{self, ClientArgs, Error, Exit, emit, normalize_server},
    keystore,
    loopback::{self, Listener},
    profile::{self, Config, Credentials, DEFAULT_PROFILE, Profile, now_ms},
};

/// The scopes a sign-in asks for without `--scope` (`Scopes::CLI_DEFAULT`).
pub const DEFAULT_SCOPE: &str = "runs:read runs:write logs:read artifacts:read cache:read";
/// The schema of `sentinel auth status --json`.
pub const STATUS_SCHEMA: &str = "sentinel.auth-status/1";
/// Bound on best-effort revocations that must not hold a command up.
const QUICK: Duration = Duration::from_secs(5);
/// Largest grant file read.
const MAX_GRANT_FILE: u64 = 4 << 10;

#[derive(Args, Debug)]
pub struct AuthArgs {
    #[command(subcommand)]
    pub command: AuthCommand,
}

#[derive(Subcommand, Debug)]
pub enum AuthCommand {
    /// Sign in through the browser (or --device, or --grant-file) and store the grant in a profile
    Login(LoginArgs),
    /// Show the profile, account, scopes and expiry; never token material
    Status(StatusArgs),
    /// Revoke the grant on the server and delete the stored credential
    Logout(LogoutArgs),
}

#[derive(Args, Debug)]
pub struct LoginArgs {
    /// Controller URL (also SENTINEL_SERVER; default: the profile's server)
    #[arg(long)]
    pub server: Option<String>,
    /// Profile to write (default: "default")
    #[arg(long, env = "SENTINEL_PROFILE")]
    pub profile: Option<String>,
    /// Use the device flow: approve a short code on another device
    #[arg(long, conflicts_with = "grant_file")]
    pub device: bool,
    /// Print the sign-in URL instead of opening a browser
    #[arg(long)]
    pub no_browser: bool,
    /// Space-separated scopes to request (default: runs:read runs:write logs:read artifacts:read cache:read)
    #[arg(long, conflicts_with = "grant_file")]
    pub scope: Option<String>,
    /// Import a provisioned sntl_rt_ refresh token from a file, or - for stdin
    #[arg(long, value_name = "PATH")]
    pub grant_file: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub struct StatusArgs {
    #[command(flatten)]
    pub client: ClientArgs,
    /// Do not contact the server
    #[arg(long)]
    pub offline: bool,
}

#[derive(Args, Debug)]
pub struct LogoutArgs {
    /// Profile to sign out (default: the current profile)
    #[arg(long, env = "SENTINEL_PROFILE")]
    pub profile: Option<String>,
    /// Every profile
    #[arg(long, conflicts_with = "profile")]
    pub all: bool,
    /// Also remove the profile entry
    #[arg(long)]
    pub forget: bool,
}

#[derive(Args, Debug)]
pub struct ContextArgs {
    #[command(subcommand)]
    pub command: ContextCommand,
}

#[derive(Subcommand, Debug)]
pub enum ContextCommand {
    /// Make a tenant the profile's default for commands that take --tenant
    Use {
        /// Tenant slug
        tenant: String,
        #[arg(long, env = "SENTINEL_PROFILE")]
        profile: Option<String>,
    },
    /// Show the profile's default tenant
    Show {
        #[command(flatten)]
        client: ClientArgs,
    },
}

pub fn run(args: AuthArgs) -> Result<(), client::Error> {
    match args.command {
        AuthCommand::Login(login) => run_login(login),
        AuthCommand::Status(status) => run_status(&status),
        AuthCommand::Logout(logout) => run_logout(&logout),
    }
}

pub fn run_context(args: ContextArgs) -> Result<(), client::Error> {
    match args.command {
        ContextCommand::Use { tenant, profile } => context_use(&tenant, profile.as_deref()),
        ContextCommand::Show { client } => context_show(&client),
    }
}

fn quick_agent() -> ureq::Agent {
    ureq::Agent::new_with_config(
        ureq::Agent::config_builder()
            .http_status_as_error(false)
            .max_redirects(0)
            .timeout_global(Some(QUICK))
            .build(),
    )
}

/// `scheme://authority` of a normalized URL.
fn origin(url: &str) -> &str {
    let after = url.find("://").map_or(0, |at| at + 3);
    match url[after..].find('/') {
        Some(at) => &url[..after + at],
        None => url,
    }
}

/// Printable ASCII without spaces or quotes: safe to print and to hand to a
/// browser launcher.
fn plain(text: &str) -> bool {
    !text.is_empty()
        && text
            .bytes()
            .all(|b| b.is_ascii_graphic() && b != b'"' && b != b'\\')
}

/// An endpoint the metadata named, accepted only on the issuer's origin.
fn same_origin(endpoint: &str, issuer: &str) -> bool {
    let origin = origin(issuer);
    plain(endpoint)
        && endpoint
            .strip_prefix(origin)
            .is_some_and(|rest| rest.starts_with('/'))
}

/// Fetch and check the server's metadata: `issuer` must equal `server`
/// (already normalized) exactly, and every endpoint must be on its origin.
pub fn discover(agent: &ureq::Agent, server: &str) -> Result<Metadata, Error> {
    let (status, body) = profile::get(agent, &format!("{server}{METADATA_PATH}"), None)?;
    if status != 200 {
        return Err(Error::remote(format!(
            "{server} does not publish OAuth metadata (HTTP {status}); is it a Sentinel controller?"
        )));
    }
    let meta: Metadata = serde_json::from_str(&body)
        .map_err(|_| Error::remote(format!("{server} answered malformed OAuth metadata")))?;
    if meta.issuer != server {
        let named = if plain(&meta.issuer) {
            meta.issuer.as_str()
        } else {
            "another issuer"
        };
        return Err(Error::usage(format!(
            "{server} names its issuer {named}, not {server}; refusing to sign in (use the controller's public URL as --server)"
        )));
    }
    for endpoint in [
        &meta.authorization_endpoint,
        &meta.token_endpoint,
        &meta.revocation_endpoint,
        &meta.device_authorization_endpoint,
    ] {
        if !same_origin(endpoint, &meta.issuer) {
            return Err(Error::remote(format!(
                "{server} published an OAuth endpoint outside its own origin; refusing to sign in"
            )));
        }
    }
    Ok(meta)
}

/// The scopes to request, each one the server offers.
pub fn requested_scope(scope: Option<&str>, meta: &Metadata) -> Result<String, Error> {
    let mut out = String::with_capacity(96);
    for name in scope.unwrap_or(DEFAULT_SCOPE).split_ascii_whitespace() {
        if !meta.scopes_supported.iter().any(|s| s == name) {
            return Err(Error::usage(format!(
                "unknown scope {name:?}; the server offers: {}",
                meta.scopes_supported.join(" ")
            )));
        }
        if !out.split(' ').any(|s| s == name) {
            if !out.is_empty() {
                out.push(' ');
            }
            out.push_str(name);
        }
    }
    if out.is_empty() {
        return Err(Error::usage("--scope names no scope"));
    }
    Ok(out)
}

fn run_login(args: LoginArgs) -> Result<(), Error> {
    let config = Config::from_env()?;
    let name = args
        .profile
        .as_deref()
        .unwrap_or(DEFAULT_PROFILE)
        .to_owned();
    profile::validate_name(&name)?;
    let previous = config.load()?.profiles.remove(&name);
    let server = match args.server.clone().or_else(|| {
        std::env::var("SENTINEL_SERVER")
            .ok()
            .filter(|s| !s.is_empty())
    }) {
        Some(server) => normalize_server(&server)?,
        None => match &previous {
            Some(p) => p.server.clone(),
            None => {
                return Err(Error::usage(
                    "sentinel auth login needs --server URL (or SENTINEL_SERVER)",
                ));
            }
        },
    };
    let agent = profile::agent();
    let meta = discover(&agent, &server)?;
    let (response, sent) = if let Some(path) = &args.grant_file {
        import_grant(&agent, &meta, path)?
    } else {
        let scope = requested_scope(args.scope.as_deref(), &meta)?;
        if args.device {
            device_login(&agent, &meta, &scope, Duration::from_secs(1))?
        } else {
            browser_login(&agent, &meta, &scope, !args.no_browser)?
        }
    };
    save_login(&config, &agent, &name, &meta, &response, sent, previous)
}

fn browser_login(
    agent: &ureq::Agent,
    meta: &Metadata,
    scope: &str,
    launch: bool,
) -> Result<(TokenResponse, u64), Error> {
    let listener = Listener::bind()?;
    let redirect = listener.redirect_uri();
    let mut state = String::with_capacity(Secret::TEXT_LEN);
    Secret::generate().expose(&mut state);
    let verifier = pkce::verifier();
    let challenge = pkce::challenge(&verifier);
    let resource = format!("{}{API_RESOURCE_SUFFIX}", meta.issuer);
    let query = profile::form(&[
        ("response_type", "code"),
        ("client_id", CLI_CLIENT_ID),
        ("redirect_uri", &redirect),
        ("state", &state),
        ("code_challenge", &challenge),
        ("code_challenge_method", "S256"),
        ("scope", scope),
        ("resource", &resource),
    ]);
    let url = format!("{}?{query}", meta.authorization_endpoint);
    browser::open(&url, launch);
    let code = listener.wait(&state, &meta.issuer, loopback::WAIT)?;
    let sent = now_ms();
    let form = profile::form(&[
        ("grant_type", GRANT_AUTHORIZATION_CODE),
        ("code", &code),
        ("redirect_uri", &redirect),
        ("client_id", CLI_CLIENT_ID),
        ("code_verifier", &verifier),
    ]);
    match profile::token_call(agent, &meta.token_endpoint, &form)? {
        Ok(response) => Ok((response, sent)),
        Err(oauth) => Err(profile::oauth_failure(&oauth)),
    }
}

/// The device flow (RFC 8628): print the verification URI and user code on
/// stderr, then poll every `interval` (`slow_down` adds 5), until approval,
/// denial or expiry. `unit` is one second in production; a smaller unit lets
/// tests run the schedule quickly. Ctrl-C ends the process with nothing
/// written.
pub fn device_login(
    agent: &ureq::Agent,
    meta: &Metadata,
    scope: &str,
    unit: Duration,
) -> Result<(TokenResponse, u64), Error> {
    let resource = format!("{}{API_RESOURCE_SUFFIX}", meta.issuer);
    let form = profile::form(&[
        ("client_id", CLI_CLIENT_ID),
        ("scope", scope),
        ("resource", &resource),
    ]);
    let (status, body) = profile::post_form(agent, &meta.device_authorization_endpoint, &form)?;
    if status != 200 {
        return Err(match serde_json::from_str(&body) {
            Ok(oauth) => profile::oauth_failure(&oauth),
            Err(_) => Error::remote(format!(
                "the device authorization endpoint answered HTTP {status}"
            )),
        });
    }
    let device: DeviceAuthorization = serde_json::from_str(&body)
        .map_err(|_| Error::remote("the server answered a malformed device authorization"))?;
    if tokens::parse(Kind::Device, &device.device_code).is_none()
        || !plain(&device.user_code)
        || device.user_code.len() > 16
        || !same_origin(&device.verification_uri, &meta.issuer)
        || !same_origin(&device.verification_uri_complete, &meta.issuer)
    {
        return Err(Error::remote(
            "the server answered a malformed device authorization",
        ));
    }
    eprintln!(
        "To sign in, open {} and enter the code {}\n(or open {})\nWaiting for approval… (Ctrl-C cancels)",
        device.verification_uri, device.user_code, device.verification_uri_complete
    );
    let poll = profile::form(&[
        ("grant_type", GRANT_DEVICE_CODE),
        ("device_code", &device.device_code),
        ("client_id", CLI_CLIENT_ID),
    ]);
    let started = Instant::now();
    let lifetime = unit.saturating_mul(u32::try_from(device.expires_in).unwrap_or(u32::MAX));
    let mut interval = device.interval.clamp(1, 600);
    loop {
        thread::sleep(unit.saturating_mul(interval as u32));
        if started.elapsed() >= lifetime {
            return Err(Error::new(
                Exit::Auth,
                "the device code expired before it was approved; run the login again",
            ));
        }
        let sent = now_ms();
        match profile::token_call(agent, &meta.token_endpoint, &poll)? {
            Ok(response) => return Ok((response, sent)),
            Err(oauth) => match oauth.error {
                OAuthErrorCode::AuthorizationPending => {}
                OAuthErrorCode::SlowDown => interval = (interval + 5).min(600),
                OAuthErrorCode::AccessDenied => {
                    return Err(Error::new(
                        Exit::Auth,
                        "the sign-in was denied on the device page",
                    ));
                }
                OAuthErrorCode::ExpiredToken => {
                    return Err(Error::new(
                        Exit::Auth,
                        "the device code expired before it was approved; run the login again",
                    ));
                }
                _ => return Err(profile::oauth_failure(&oauth)),
            },
        }
    }
}

/// Read a provisioned refresh token (a file, or `-` for stdin) and spend it
/// at once: the provisioned text is dead afterwards, only the stored
/// successor works.
fn import_grant(
    agent: &ureq::Agent,
    meta: &Metadata,
    path: &Path,
) -> Result<(TokenResponse, u64), Error> {
    let mut text = String::with_capacity(128);
    let read = if path.as_os_str() == "-" {
        std::io::stdin()
            .take(MAX_GRANT_FILE)
            .read_to_string(&mut text)
    } else {
        std::fs::File::open(path).and_then(|f| f.take(MAX_GRANT_FILE).read_to_string(&mut text))
    };
    read.map_err(|e| Error::usage(format!("cannot read the grant file: {e}")))?;
    let refresh = text.trim();
    if tokens::parse(Kind::Refresh, refresh).is_none() {
        return Err(Error::usage(
            "the grant file does not hold a sntl_rt_ refresh token",
        ));
    }
    let sent = now_ms();
    let form = profile::form(&[
        ("grant_type", GRANT_REFRESH_TOKEN),
        ("refresh_token", refresh),
        ("client_id", CLI_CLIENT_ID),
    ]);
    match profile::token_call(agent, &meta.token_endpoint, &form)? {
        Ok(response) => Ok((response, sent)),
        Err(oauth) => Err(profile::oauth_failure(&oauth)),
    }
}

/// `GET /api/v1/me` with an access token: status and parsed body.
fn whoami(agent: &ureq::Agent, server: &str, access: &str) -> Result<(u16, Value), Error> {
    let (status, body) = profile::get(agent, &format!("{server}/api/v1/me"), Some(access))?;
    let value = serde_json::from_str(&body).unwrap_or(Value::Null);
    Ok((status, value))
}

/// Revoke a grant by one of its tokens (RFC 7009).
fn revoke(agent: &ureq::Agent, issuer: &str, token: &str) -> Result<(), Error> {
    let form = profile::form(&[("client_id", CLI_CLIENT_ID), ("token", token)]);
    let (status, _) = profile::post_form(agent, &format!("{issuer}{REVOKE_PATH}"), &form)?;
    if status == 200 {
        Ok(())
    } else {
        Err(Error::remote(format!(
            "the revocation endpoint answered HTTP {status}"
        )))
    }
}

/// Store a fresh grant: learn the account, then under the profile lock
/// replace any previous credential and write the credential before the
/// profile that points at it.
fn save_login(
    config: &Config,
    agent: &ureq::Agent,
    name: &str,
    meta: &Metadata,
    response: &TokenResponse,
    sent: u64,
    previous: Option<Profile>,
) -> Result<(), Error> {
    let server = &meta.issuer;
    let credentials = Credentials::from_response(response, sent)?;
    let me = match whoami(agent, server, &credentials.access) {
        Ok((200, me)) if me["user"].as_str().is_some_and(|u| u.starts_with("usr_")) => me,
        outcome => {
            let _ = revoke(&quick_agent(), server, &credentials.refresh);
            return Err(match outcome {
                Err(e) => e,
                Ok((401 | 403, _)) => {
                    Error::new(Exit::Auth, "the server did not accept the new access token")
                }
                Ok((status, _)) => {
                    Error::remote(format!("{server}/api/v1/me answered HTTP {status}"))
                }
            });
        }
    };
    let _lock = config.lock(name)?;
    if let Some(old) = &previous {
        // A legacy shared OS-store entry may hold another configuration
        // directory's sign-in by now; only this profile's own is revoked
        // and deleted (P09C-8).
        let (stored, ours) = if old.is_legacy() {
            match config.legacy_owner(&quick_agent(), name, old) {
                profile::Owner::Ours(stored) => (Some(stored), true),
                profile::Owner::Absent => (None, false),
                profile::Owner::Theirs => {
                    eprintln!(
                        "notice: the previous sign-in's shared credential entry now belongs to another configuration directory; it is left alone"
                    );
                    (None, false)
                }
                profile::Owner::Unknown => {
                    eprintln!(
                        "notice: could not tell whose sign-in the previous shared credential entry holds; it is left in place and expires on its own"
                    );
                    (None, false)
                }
            }
        } else {
            (config.read_credentials(name, old).ok().flatten(), true)
        };
        if let Some(stored) = stored
            && old.grant != response.sentinel_grant
        {
            let _ = revoke(&quick_agent(), &old.issuer, &stored.refresh);
        }
        if ours {
            let _ = config.delete_credentials(name, old);
        }
    }
    let (store, key) =
        config.store_credentials(name, server, keystore::preferred()?, &credentials)?;
    let username = me["username"].as_str().map(str::to_owned);
    let entry = Profile {
        server: server.clone(),
        issuer: meta.issuer.clone(),
        client_id: CLI_CLIENT_ID.to_owned(),
        user: me["user"].as_str().unwrap_or_default().to_owned(),
        username: username.clone(),
        grant: response.sentinel_grant.clone(),
        scopes: response.scope.clone(),
        tenant: previous
            .filter(|p| p.server == *server)
            .and_then(|p| p.tenant),
        store,
        key,
        created_ms: sent,
    };
    config.update(|profiles| {
        profiles.profiles.insert(name.to_owned(), entry);
        profiles.current = Some(name.to_owned());
        Ok(())
    })?;
    eprintln!(
        "Signed in to {server} as {} (profile {name}, grant {}); scopes: {}; credential in the {} store",
        username
            .as_deref()
            .unwrap_or(me["user"].as_str().unwrap_or("?")),
        response.sentinel_grant,
        response.scope,
        store.as_str()
    );
    Ok(())
}

/// The profile a command addresses: `--profile`/`SENTINEL_PROFILE`, else
/// the current one; exit 3 with the login hint when there is none.
fn pick(
    config: &Config,
    name: Option<&str>,
) -> Result<(String, Profile, profile::Profiles), Error> {
    let mut profiles = config.load()?;
    let name = match name.map(str::to_owned).or_else(|| profiles.current.clone()) {
        Some(name) => name,
        None => {
            return Err(Error::new(
                Exit::Auth,
                "not signed in; run: sentinel auth login --server URL",
            ));
        }
    };
    profile::validate_name(&name)?;
    let Some(entry) = profiles.profiles.remove(&name) else {
        return Err(Error::usage(format!(
            "there is no profile {name}; run: sentinel auth login --server URL --profile {name}"
        )));
    };
    Ok((name, entry, profiles))
}

/// A `--server`/`SENTINEL_SERVER` given with a profile must be its server.
fn check_server(client: &ClientArgs, name: &str, entry: &Profile) -> Result<(), Error> {
    let explicit = client.server.clone().or_else(|| {
        std::env::var("SENTINEL_SERVER")
            .ok()
            .filter(|s| !s.is_empty())
    });
    if let Some(explicit) = explicit
        && normalize_server(&explicit)? != entry.server
    {
        return Err(Error::usage(format!(
            "--server/SENTINEL_SERVER {explicit} does not match profile {name} ({})",
            entry.server
        )));
    }
    Ok(())
}

/// `5d 3h`, `2h 10m`, `4m 5s`, `12s`, or `expired`.
fn remaining(expires_ms: u64, now: u64) -> String {
    if expires_ms <= now {
        return "expired".to_owned();
    }
    let s = (expires_ms - now) / 1000;
    let (d, h, m) = (s / 86_400, s / 3600 % 24, s / 60 % 60);
    match (d, h, m) {
        (0, 0, 0) => format!("{s}s"),
        (0, 0, _) => format!("{m}m {}s", s % 60),
        (0, _, _) => format!("{h}h {m}m"),
        _ => format!("{d}d {h}h"),
    }
}

fn run_status(args: &StatusArgs) -> Result<(), Error> {
    let output = args.client.output();
    let config = Config::from_env()?;
    let (name, entry, profiles) = pick(&config, args.client.profile.as_deref())?;
    check_server(&args.client, &name, &entry)?;
    let mut credentials = config.read_credentials(&name, &entry)?;
    let now = now_ms();
    let mut signed_in = credentials
        .as_ref()
        .is_some_and(|c| c.refresh_expires_ms > now || c.access_expires_ms > now);
    let mut verified = false;
    let mut narrowing = Value::Null;
    let mut failure = None;
    if !args.offline && signed_in {
        match verify(&config, &name, &profile::agent()) {
            Ok(me) => {
                verified = true;
                narrowing = json!({ "tenant": me["tenant"], "repo": me["repo"] });
                credentials = config.read_credentials(&name, &entry)?;
            }
            Err(e) if e.exit == Exit::Auth => {
                signed_in = false;
                failure = Some(e);
            }
            Err(e) => return Err(e),
        }
    }
    let scopes: Vec<&str> = entry.scopes.split_ascii_whitespace().collect();
    let doc = json!({
        "schema": STATUS_SCHEMA,
        "profile": name,
        "current": profiles.current.as_deref() == Some(name.as_str()),
        "server": entry.server,
        "issuer": entry.issuer,
        "user": entry.user,
        "username": entry.username,
        "grant": entry.grant,
        "scopes": scopes,
        "tenant": entry.tenant,
        "narrowing": narrowing,
        "access_expires_ms": credentials.as_ref().map(|c| c.access_expires_ms),
        "refresh_expires_ms": credentials.as_ref().map(|c| c.refresh_expires_ms),
        "store": entry.store.as_str(),
        "signed_in": signed_in,
        "verified": verified,
    });
    emit(output, &doc, || {
        let now = now_ms();
        let mut text = String::with_capacity(512);
        let mut row = |label: &str, value: &str| {
            text.push_str(&format!("{label:<10}{value}\n"));
        };
        let current = if doc["current"] == true {
            " (current)"
        } else {
            ""
        };
        row("Profile", &format!("{name}{current}"));
        row("Server", &entry.server);
        row(
            "Account",
            &format!(
                "{} ({})",
                entry.username.as_deref().unwrap_or("?"),
                entry.user
            ),
        );
        row("Grant", &entry.grant);
        row("Scopes", &entry.scopes);
        if !args.offline {
            let narrowed = match (narrowing["tenant"].as_str(), narrowing["repo"].as_str()) {
                (None, None) if verified => "none".to_owned(),
                (None, None) => "unknown (not verified)".to_owned(),
                (tenant, repo) => format!(
                    "tenant {}, repository {}",
                    tenant.unwrap_or("any"),
                    repo.unwrap_or("any")
                ),
            };
            row("Narrowed", &narrowed);
        }
        row("Tenant", entry.tenant.as_deref().unwrap_or("(none)"));
        match &credentials {
            Some(c) => {
                row("Access", &remaining(c.access_expires_ms, now));
                row("Refresh", &remaining(c.refresh_expires_ms, now));
            }
            None => row("Access", "no stored credential"),
        }
        row("Store", entry.store.as_str());
        let state = match (signed_in, verified, args.offline) {
            (true, true, _) => "signed in (verified with the server)",
            (true, _, true) => "signed in (not checked: --offline)",
            (true, _, _) => "signed in",
            (false, _, _) => "not signed in",
        };
        row("Status", state);
        text
    });
    if let Some(failure) = failure {
        return Err(failure);
    }
    if !signed_in {
        return Err(Error::new(
            Exit::Auth,
            format!(
                "not signed in to {server} (profile {name}); run: sentinel auth login --server {server} --profile {name}",
                server = entry.server
            ),
        ));
    }
    Ok(())
}

/// `GET /api/v1/me` through the profile, refreshing once on `401`.
pub(crate) fn verify(config: &Config, name: &str, agent: &ureq::Agent) -> Result<Value, Error> {
    let handle = config
        .handle(Some(name))?
        .ok_or_else(|| Error::usage("no profile"))?;
    let mut token = handle.access_token(agent)?;
    for attempt in 0..2 {
        let (status, me) = whoami(agent, handle.server(), &token)?;
        match status {
            200 => return Ok(me),
            401 if attempt == 0 => token = handle.force_refresh(agent, &token)?,
            401 | 403 => break,
            status => {
                return Err(Error::remote(format!(
                    "{}/api/v1/me answered HTTP {status}",
                    handle.server()
                )));
            }
        }
    }
    Err(Error::new(
        Exit::Auth,
        format!(
            "not signed in to {server} (profile {name}); run: sentinel auth login --server {server} --profile {name}",
            server = handle.server()
        ),
    ))
}

fn run_logout(args: &LogoutArgs) -> Result<(), Error> {
    let config = Config::from_env()?;
    let profiles = config.load()?;
    let names: Vec<String> = if args.all {
        profiles.profiles.keys().cloned().collect()
    } else {
        vec![pick(&config, args.profile.as_deref())?.0]
    };
    let agent = profile::agent();
    let mut unrevoked = Vec::new();
    let mut undecided: Vec<String> = Vec::new();
    for name in &names {
        let _lock = config.lock(name)?;
        let Some(entry) = config.load()?.profiles.remove(name) else {
            continue;
        };
        // A legacy shared OS-store entry is revoked and deleted only when it
        // still holds this profile's own grant (P09C-8).
        let stored = if entry.is_legacy() {
            match config.legacy_owner(&agent, name, &entry) {
                profile::Owner::Ours(stored) => Some(stored),
                profile::Owner::Absent => None,
                profile::Owner::Theirs => {
                    eprintln!(
                        "Signed out of {} (profile {name}); the shared credential entry holds another configuration directory's sign-in and is left alone",
                        entry.server
                    );
                    continue;
                }
                profile::Owner::Unknown => {
                    eprintln!(
                        "warning: could not tell whose sign-in the shared credential entry of profile {name} holds ({} is unreachable); nothing was deleted",
                        entry.server
                    );
                    undecided.push(name.clone());
                    continue;
                }
            }
        } else {
            match config.read_credentials(name, &entry) {
                Ok(stored) => stored,
                Err(e) => {
                    eprintln!("warning: {}", e.message);
                    None
                }
            }
        };
        if let Some(stored) = stored
            && let Err(e) = revoke(&agent, &entry.issuer, &stored.refresh)
        {
            eprintln!(
                "warning: could not revoke the grant of profile {name} on {} ({}); the local credential is deleted anyway, but the grant stays valid on the server until it expires",
                entry.server, e.message
            );
            unrevoked.push(name.clone());
        }
        config.delete_credentials(name, &entry)?;
        eprintln!("Signed out of {} (profile {name})", entry.server);
    }
    if args.forget && !names.is_empty() {
        config.update(|profiles| {
            for name in &names {
                profiles.profiles.remove(name);
            }
            if profiles.current.as_ref().is_some_and(|c| names.contains(c)) {
                profiles.current = None;
            }
            Ok(())
        })?;
    }
    if !undecided.is_empty() {
        return Err(Error::new(
            Exit::Busy,
            format!(
                "not signed out of {}: run sentinel auth logout again when the controller is reachable",
                undecided.join(", ")
            ),
        ));
    }
    if unrevoked.is_empty() {
        Ok(())
    } else {
        Err(Error::remote(format!(
            "signed out locally, but the server did not revoke {}; run sentinel auth logout again when it is reachable, or revoke the grant from another session",
            unrevoked.join(", ")
        )))
    }
}

fn context_use(tenant: &str, profile_name: Option<&str>) -> Result<(), Error> {
    if tenant.is_empty()
        || tenant.len() > 64
        || !tenant
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(Error::usage(
            "a tenant slug is 1-64 letters, digits, '-' or '_'",
        ));
    }
    let config = Config::from_env()?;
    let (name, entry, _) = pick(&config, profile_name)?;
    config.update(|profiles| {
        let Some(stored) = profiles.profiles.get_mut(&name) else {
            return Err(Error::usage(format!("there is no profile {name}")));
        };
        stored.tenant = Some(tenant.to_owned());
        Ok(())
    })?;
    eprintln!(
        "Profile {name} ({}) now defaults to tenant {tenant}",
        entry.server
    );
    Ok(())
}

fn context_show(client: &ClientArgs) -> Result<(), Error> {
    let output = client.output();
    let config = Config::from_env()?;
    let (name, entry, _) = pick(&config, client.profile.as_deref())?;
    let doc = json!({ "profile": name, "server": entry.server, "tenant": entry.tenant });
    emit(output, &doc, || match &entry.tenant {
        Some(tenant) => format!("{tenant}\n"),
        None => "(no default tenant; set one with: sentinel context use TENANT)\n".to_owned(),
    });
    Ok(())
}
