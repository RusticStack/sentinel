//! `sentinel doctor` (O06): diagnose how this machine signs in to a
//! controller. Seven checks, in order — the configuration directory, the
//! profile, reachability, the issuer, the credential store, the access token
//! and a refresh — each with the exact command that fixes a failure. Nothing
//! printed ever holds token material. `--json` (or `--output json|ndjson`)
//! prints `sentinel.doctor/1`:
//!
//! ```json
//! { "schema": "sentinel.doctor/1", "profile": "default", "server": "https://ci.example.com",
//!   "ok": false,
//!   "checks": [ { "name": "health", "ok": false, "detail": "…", "fix": "…" }, … ] }
//! ```
//!
//! A check that could not run because an earlier one failed is `ok: false`
//! with `"skipped": true` and the earlier failure's fix. Exit 0 when every
//! check passed; otherwise the exit of the first failure from the stable
//! table (`docs/cli.md#doctor`), after the report.
//!
//! The refresh check spends the stored refresh token once, under the
//! profile lock, exactly as any command would when its access token runs
//! low: the profile keeps working with the successor.

use std::{fmt::Write as _, time::Duration};

use clap::Args;
use serde::Serialize;
use serde_json::{Value, json};

use crate::{
    auth_cmd,
    client::{ClientArgs, Error, Exit, emit, normalize_server},
    keystore::{Backend, file, key},
    profile::{self, Config, Credentials, Profile, now_ms},
};

/// The `schema` of `sentinel doctor --json`.
pub const SCHEMA: &str = "sentinel.doctor/1";
/// Bound on each network check, so an unreachable controller is reported
/// in seconds rather than after the client's minute.
const CHECK_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Args, Debug)]
pub struct DoctorArgs {
    #[command(flatten)]
    pub client: ClientArgs,
}

/// One line of the report.
#[derive(Debug, Serialize)]
pub struct Check {
    pub name: &'static str,
    pub ok: bool,
    pub detail: String,
    /// The command (or change) that fixes a failure; `null` when it passed.
    pub fix: Option<String>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub skipped: bool,
    #[serde(skip)]
    exit: Exit,
}

/// The whole report, in check order.
#[derive(Debug, Default)]
pub struct Report {
    pub checks: Vec<Check>,
    pub profile: Option<String>,
    pub server: Option<String>,
}

impl Report {
    fn pass(&mut self, name: &'static str, detail: String) {
        self.checks.push(Check {
            name,
            ok: true,
            detail,
            fix: None,
            skipped: false,
            exit: Exit::Ok,
        });
    }

    fn fail(&mut self, name: &'static str, exit: Exit, detail: String, fix: String) {
        self.checks.push(Check {
            name,
            ok: false,
            detail,
            fix: Some(fix),
            skipped: false,
            exit,
        });
    }

    /// Mark `names` as not run because `cause` failed; they repeat its fix.
    fn skip(&mut self, names: &[&'static str], cause: &'static str) {
        let fix = self
            .checks
            .iter()
            .find(|c| c.name == cause)
            .and_then(|c| c.fix.clone());
        for name in names {
            self.checks.push(Check {
                name,
                ok: false,
                detail: format!("not checked: the {cause} check failed"),
                fix: fix.clone(),
                skipped: true,
                exit: Exit::Ok,
            });
        }
    }

    fn failed(&self, name: &str) -> bool {
        self.checks.iter().any(|c| c.name == name && !c.ok)
    }

    /// The first failure that is not a consequence of an earlier one.
    pub fn first_failure(&self) -> Option<&Check> {
        self.checks.iter().find(|c| !c.ok && !c.skipped)
    }

    pub fn document(&self) -> Value {
        json!({
            "schema": SCHEMA,
            "profile": self.profile,
            "server": self.server,
            "ok": self.first_failure().is_none(),
            "checks": self.checks,
        })
    }

    pub fn text(&self) -> String {
        let mut out = String::with_capacity(128 * self.checks.len());
        for check in &self.checks {
            let mark = match (check.ok, check.skipped) {
                (true, _) => "ok",
                (false, true) => "skip",
                (false, false) => "FAIL",
            };
            let _ = writeln!(out, "{mark:<5} {:<17} {}", check.name, check.detail);
            if let (false, false, Some(fix)) = (check.ok, check.skipped, &check.fix) {
                let _ = writeln!(out, "      fix: {fix}");
            }
        }
        out
    }
}

pub fn run(args: DoctorArgs) -> Result<(), Error> {
    let output = args.client.output();
    let report = diagnose(&args.client);
    emit(output, &report.document(), || report.text());
    match report.first_failure() {
        None => Ok(()),
        Some(check) => Err(Error::new(
            check.exit,
            format!(
                "doctor: the {} check failed; fix: {}",
                check.name,
                check.fix.as_deref().unwrap_or("see the report")
            ),
        )),
    }
}

/// Split a message carrying its own `…; fix: COMMAND` into both halves.
fn split_fix(message: &str) -> (String, Option<String>) {
    match message.split_once("; fix: ") {
        Some((detail, fix)) => (detail.to_owned(), Some(fix.to_owned())),
        None => (message.to_owned(), None),
    }
}

fn login(server: &str, profile: &str) -> String {
    format!("sentinel auth login --server {server} --profile {profile}")
}

fn remaining(expires_ms: u64, now: u64) -> String {
    if expires_ms <= now {
        return "expired".to_owned();
    }
    let s = (expires_ms - now) / 1000;
    match (s / 86_400, s / 3600 % 24, s / 60 % 60) {
        (0, 0, 0) => format!("{s}s"),
        (0, 0, m) => format!("{m}m"),
        (0, h, m) => format!("{h}h {m}m"),
        (d, h, _) => format!("{d}d {h}h"),
    }
}

fn check_agent() -> ureq::Agent {
    ureq::Agent::new_with_config(
        ureq::Agent::config_builder()
            .http_status_as_error(false)
            .max_redirects(0)
            .timeout_global(Some(CHECK_TIMEOUT))
            .build(),
    )
}

/// Run every check. Never fails itself: each problem is a failed check.
pub fn diagnose(args: &ClientArgs) -> Report {
    let mut report = Report::default();

    // 1. The configuration directory: locatable, outside Git, owner-only.
    let Some(config) = config_dir(&mut report) else {
        report.skip(
            &[
                "profile",
                "health",
                "issuer",
                "credential_store",
                "access_token",
                "refresh",
            ],
            "config_dir",
        );
        return report;
    };

    // 2. The profile, and that an explicit server is its server.
    let Some((name, entry)) = profile(&mut report, &config, args) else {
        report.skip(
            &[
                "health",
                "issuer",
                "credential_store",
                "access_token",
                "refresh",
            ],
            "profile",
        );
        return report;
    };
    report.profile = Some(name.clone());
    report.server = Some(entry.server.clone());
    let agent = check_agent();

    // 3. Reachability.
    health(&mut report, &agent, &name, &entry);
    // 4. The issuer, once the server answers.
    if report.failed("health") {
        report.skip(&["issuer"], "health");
    } else {
        issuer(&mut report, &agent, &name, &entry);
    }
    // 5. The credential store is local: always checked.
    let stored = credential_store(&mut report, &config, &name, &entry).is_some();
    // 6 and 7. The access token, then a refresh.
    match ["health", "issuer", "credential_store"]
        .into_iter()
        .find(|c| report.failed(c))
    {
        Some(cause) => report.skip(&["access_token", "refresh"], cause),
        None if stored && access_token(&mut report, &config, &agent, &name, &entry) => {
            refresh(&mut report, &config, &agent, &name, &entry);
        }
        None => report.skip(&["refresh"], "access_token"),
    }
    report
}

fn config_dir(report: &mut Report) -> Option<Config> {
    const NAME: &str = "config_dir";
    let config = match Config::from_env() {
        Ok(config) => config,
        Err(error) => {
            let (detail, fix) = split_fix(&error.message);
            report.fail(
                NAME,
                Exit::Usage,
                detail,
                fix.unwrap_or_else(|| {
                    "set SENTINEL_CONFIG_DIR to a directory outside any Git work tree, e.g. SENTINEL_CONFIG_DIR=\"$HOME/.sentinel\"".to_owned()
                }),
            );
            return None;
        }
    };
    let dir = config.dir();
    if !dir.exists() {
        report.pass(
            NAME,
            format!(
                "{} does not exist yet; sign-in creates it owner-only",
                dir.display()
            ),
        );
        return Some(config);
    }
    let mut checked = vec![dir.to_path_buf()];
    for extra in [file::credentials_dir(dir), dir.join("profiles.json")] {
        if extra.exists() {
            checked.push(extra);
        }
    }
    for path in &checked {
        if let Err(error) = file::check_private(path) {
            let (detail, fix) = split_fix(&error.message);
            report.fail(
                NAME,
                Exit::Usage,
                detail,
                fix.unwrap_or_else(|| format!("remove or repair {}", path.display())),
            );
            return None;
        }
    }
    let access = if cfg!(unix) {
        "owner-only, outside any Git work tree"
    } else {
        "outside any Git work tree; the per-user ACL of its parent applies"
    };
    report.pass(NAME, format!("{} ({access})", dir.display()));
    Some(config)
}

fn profile(report: &mut Report, config: &Config, args: &ClientArgs) -> Option<(String, Profile)> {
    const NAME: &str = "profile";
    let explicit = args.server.clone().or_else(|| {
        std::env::var("SENTINEL_SERVER")
            .ok()
            .filter(|s| !s.is_empty())
    });
    let hint = explicit.as_deref().unwrap_or("URL");
    let mut profiles = match config.load() {
        Ok(profiles) => profiles,
        Err(error) => {
            let (detail, fix) = split_fix(&error.message);
            let path = config.dir().join("profiles.json");
            report.fail(
                NAME,
                Exit::Usage,
                detail,
                fix.unwrap_or_else(|| {
                    format!(
                        "move {} aside, then sign in again: sentinel auth login --server {hint}",
                        path.display()
                    )
                }),
            );
            return None;
        }
    };
    let Some(name) = args.profile.clone().or_else(|| profiles.current.take()) else {
        report.fail(
            NAME,
            Exit::Auth,
            "no profile is configured (profiles.json names no current profile)".to_owned(),
            format!("sentinel auth login --server {hint}"),
        );
        return None;
    };
    if let Err(error) = profile::validate_name(&name) {
        report.fail(
            NAME,
            Exit::Usage,
            error.message,
            "choose a profile name of letters, digits, '.', '_' or '-'".to_owned(),
        );
        return None;
    }
    let Some(entry) = profiles.profiles.remove(&name) else {
        report.fail(
            NAME,
            Exit::Usage,
            format!("there is no profile {name}"),
            format!("sentinel auth login --server {hint} --profile {name}"),
        );
        return None;
    };
    if let Some(explicit) = &explicit {
        let matches = normalize_server(explicit).map(|s| s == entry.server);
        if !matches!(matches, Ok(true)) {
            report.fail(
                NAME,
                Exit::Usage,
                format!(
                    "--server/SENTINEL_SERVER {explicit} is not the server of profile {name} ({}); no request was sent",
                    entry.server
                ),
                format!(
                    "drop --server (or unset SENTINEL_SERVER) to use profile {name}, or sign in to that controller under another profile: sentinel auth login --server {explicit} --profile OTHER"
                ),
            );
            return None;
        }
    }
    let mut detail = format!(
        "{name} -> {} as {} ({}), grant {}",
        entry.server,
        entry.username.as_deref().unwrap_or("?"),
        entry.user,
        entry.grant
    );
    if args.token_file.is_some() || std::env::var("SENTINEL_TOKEN").is_ok_and(|t| !t.is_empty()) {
        detail.push_str(
            "; note: a static credential (--token-file or SENTINEL_TOKEN) is set, and other commands use it instead of this profile",
        );
    }
    report.pass(NAME, detail);
    Some((name, entry))
}

fn health(report: &mut Report, agent: &ureq::Agent, name: &str, entry: &Profile) {
    const NAME: &str = "health";
    let url = format!("{}/api/v1/health", entry.server);
    let fix = format!(
        "start the controller or check the network; it must answer GET {url} (if it moved: {})",
        login("NEW_URL", name)
    );
    match profile::get(agent, &url, None) {
        Ok((200, body)) if serde_json::from_str::<Value>(&body).is_ok_and(|v| v["ok"] == true) => {
            report.pass(NAME, format!("GET {url} answered ok"));
        }
        Ok((status, _)) => report.fail(
            NAME,
            Exit::Remote,
            format!("GET {url} answered HTTP {status}, not a Sentinel health answer"),
            fix,
        ),
        Err(error) => report.fail(NAME, Exit::Busy, error.message, fix),
    }
}

fn issuer(report: &mut Report, agent: &ureq::Agent, name: &str, entry: &Profile) {
    const NAME: &str = "issuer";
    let fix = format!(
        "set the controller's public_url to its public address (docs/configuration.md), then sign in with it: {}",
        login("PUBLIC_URL", name)
    );
    match auth_cmd::discover(agent, &entry.server) {
        Ok(meta) if meta.issuer == entry.issuer => report.pass(
            NAME,
            format!(
                "the metadata names {} as issuer, as the profile does",
                meta.issuer
            ),
        ),
        Ok(meta) => report.fail(
            NAME,
            Exit::Usage,
            format!(
                "the profile was issued by {} but the server now names {}",
                entry.issuer, meta.issuer
            ),
            login(&meta.issuer, name),
        ),
        Err(error) if error.exit == Exit::Busy => report.fail(
            NAME,
            Exit::Busy,
            error.message,
            format!(
                "retry; the controller must answer {}/.well-known/oauth-authorization-server",
                entry.server
            ),
        ),
        Err(error) => report.fail(NAME, error.exit, error.message, fix),
    }
}

fn credential_store(
    report: &mut Report,
    config: &Config,
    name: &str,
    entry: &Profile,
) -> Option<Credentials> {
    const NAME: &str = "credential_store";
    let relogin = login(&entry.server, name);
    let place = match entry.store {
        Backend::File => format!(
            "the file store ({})",
            file::path(config.dir(), name).display()
        ),
        Backend::Os => format!("the OS store (key {})", key(&entry.issuer, name)),
    };
    match config.read_credentials(name, entry) {
        Ok(Some(stored)) => {
            let now = now_ms();
            if stored.refresh_expires_ms <= now {
                report.fail(
                    NAME,
                    Exit::Auth,
                    format!("the credential in {place} has expired: the sign-in ended"),
                    relogin,
                );
                return None;
            }
            report.pass(
                NAME,
                format!(
                    "readable in {place}; access token {}, sign-in {}",
                    remaining(stored.access_expires_ms, now),
                    remaining(stored.refresh_expires_ms, now)
                ),
            );
            Some(stored)
        }
        Ok(None) => {
            report.fail(
                NAME,
                Exit::Auth,
                format!("no credential is stored in {place} (signed out, or removed)"),
                relogin,
            );
            None
        }
        Err(error) => {
            let (detail, fix) = split_fix(&error.message);
            let fix = fix.unwrap_or_else(|| match entry.store {
                Backend::Os => format!(
                    "sign in again, or store the credential in an owner-only file instead: SENTINEL_CREDENTIAL_STORE=file {relogin}"
                ),
                Backend::File => relogin,
            });
            report.fail(NAME, Exit::Usage, detail, fix);
            None
        }
    }
}

/// What a failed token check should say to do, by exit.
fn token_fix(error: &Error, name: &str, entry: &Profile) -> String {
    match error.exit {
        Exit::Auth => login(&entry.server, name),
        Exit::Busy => format!(
            "retry once the controller at {} answers (another sentinel process may hold the profile lock)",
            entry.server
        ),
        _ => format!(
            "sign in again if it persists: {}",
            login(&entry.server, name)
        ),
    }
}

fn access_token(
    report: &mut Report,
    config: &Config,
    agent: &ureq::Agent,
    name: &str,
    entry: &Profile,
) -> bool {
    const NAME: &str = "access_token";
    match auth_cmd::verify(config, name, agent) {
        Ok(me) => {
            let scopes: Vec<&str> = me["scopes"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .collect();
            report.pass(
                NAME,
                format!(
                    "GET /api/v1/me accepted it: {} via {}, scopes {}",
                    me["username"]
                        .as_str()
                        .or(me["user"].as_str())
                        .unwrap_or("?"),
                    me["via"].as_str().unwrap_or("?"),
                    scopes.join(" ")
                ),
            );
            true
        }
        Err(error) => {
            let fix = token_fix(&error, name, entry);
            report.fail(NAME, error.exit, error.message, fix);
            false
        }
    }
}

fn refresh(report: &mut Report, config: &Config, agent: &ureq::Agent, name: &str, entry: &Profile) {
    const NAME: &str = "refresh";
    let outcome = (|| {
        let handle = config
            .handle(Some(name))?
            .ok_or_else(|| Error::usage("the profile disappeared"))?;
        let current = config
            .read_credentials(name, entry)?
            .ok_or_else(|| Error::new(Exit::Auth, "no stored credential"))?;
        // Rejecting the stored token forces a real refresh under the lock.
        handle.force_refresh(agent, &current.access)?;
        config
            .read_credentials(name, entry)?
            .ok_or_else(|| Error::new(Exit::Auth, "no stored credential"))
    })();
    match outcome {
        Ok(fresh) => report.pass(
            NAME,
            format!(
                "the refresh token rotated; the new access token is good for {}",
                remaining(fresh.access_expires_ms, now_ms())
            ),
        ),
        Err(error) => {
            let fix = token_fix(&error, name, entry);
            report.fail(NAME, error.exit, error.message, fix);
        }
    }
}
