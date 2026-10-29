//! `sentinel worker enroll` (Q11): the worker side of an enrollment. The generated bootstrap script runs
//! it as the worker's service account, with the enrollment secret on standard input.
//!
//! The steps, in the order that keeps a refusal cheap and a failure clean:
//!
//! 1. Read the secret from an owner-only file or from standard input, never from an argument or the
//!    environment, and check it is shaped like one.
//! 2. Refuse a host or configuration the worker could not run, using the same checks as
//!    `sentinel worker --check` plus the runtime the configuration asks for. This happens before the
//!    network is touched, so a refusal never spends the single-use secret.
//! 3. Generate the TLS identity, the worker identifier and, for Tailcat, the node key, on this host.
//!    No private key leaves it.
//! 4. Redeem the secret over HTTPS: one request, secret in the body, carrying the public halves of
//!    those identities. The controller binds both to the pool in one transaction and answers with its
//!    trust data (link fingerprint, address, Tailcat address).
//! 5. Write the worker configuration with that trust data and check it again.
//!
//! Nothing is persisted that holds the secret. If any step fails, every file this run created is
//! removed (the identities, the Tailcat keys, the configuration), so the host is as it was; a failure
//! after step 4 also names the worker identifier so an administrator can uninstall it on the controller.

use std::{
    fs,
    io::{self, IsTerminal, Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    time::Duration,
};

use sentinel_auth::secret::{Secret, wipe_string};
use sentinel_core::WorkerId;
use serde::Deserialize;
use serde_json::json;

use crate::{cli::EnrollArgs, service, worker_install::Failure};

const SECRET_INPUT_MAX: u64 = 4096;
const RESPONSE_MAX: u64 = 16 << 10;
const ATTEMPTS: u32 = 3;
const RETRY_WAIT: Duration = Duration::from_secs(1);
const CALL_TIMEOUT: Duration = Duration::from_secs(30);
const REDEEM_PATH: &str = "/api/v1/worker-enrollments/redeem";
/// A well-formed Tailcat address used only while checking the configuration before the real one is known.
const PLACEHOLDER_ADDRESS: &str = "tcplaceholderplaceholder0000";
const PLACEHOLDER_FINGERPRINT: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

pub fn run(args: &EnrollArgs) -> Result<(), Failure> {
    let plan = Plan::new(args)?;
    let secret = read_secret(args)?;
    plan.preflight()?;
    let mut journal = Journal::default();
    match plan.enroll(&secret, &mut journal) {
        Ok(summary) => {
            journal.commit();
            eprintln!("sentinel-worker: {summary}");
            Ok(())
        }
        Err(failure) => {
            drop(journal);
            Err(failure)
        }
    }
}

struct Helper {
    binary: PathBuf,
    sha256: String,
    derpmap_url: Option<String>,
    region: Option<String>,
    port: u16,
}

struct Plan {
    api: String,
    config: PathBuf,
    data_dir: PathBuf,
    name: String,
    helper: Option<Helper>,
}

impl Plan {
    fn new(args: &EnrollArgs) -> Result<Plan, Failure> {
        let api = redeem_url(&args.api_url)?;
        for (what, path) in [("--config", &args.config), ("--data-dir", &args.data_dir)] {
            if !path.is_absolute() || !toml_safe(&path.to_string_lossy()) {
                return Err(Failure::refused(format!(
                    "{what} must be an absolute path without quotes, backslashes or control characters"
                )));
            }
        }
        if args
            .data_dir
            .components()
            .any(|part| matches!(part, std::path::Component::ParentDir))
        {
            return Err(Failure::refused("--data-dir must not contain '..'"));
        }
        let name = match args.name.as_deref() {
            Some(name) => name.to_owned(),
            None => host_name(),
        };
        let name = clean_name(&name);
        let helper = match (&args.tailcat_binary, &args.tailcat_sha256) {
            (Some(binary), Some(sha256)) => {
                let valid_hash = sha256.len() == 64
                    && sha256
                        .bytes()
                        .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
                if !valid_hash || !binary.is_absolute() || !toml_safe(&binary.to_string_lossy()) {
                    return Err(Failure::refused(
                        "--tailcat-binary must be an absolute path and --tailcat-sha256 64 lower-case hex characters",
                    ));
                }
                for text in [&args.derpmap_url, &args.region].into_iter().flatten() {
                    if text.is_empty() || text.len() > 256 || !toml_safe(text) {
                        return Err(Failure::refused(
                            "--derpmap-url and --region must be short and free of quotes and control characters",
                        ));
                    }
                }
                Some(Helper {
                    binary: binary.clone(),
                    sha256: sha256.clone(),
                    derpmap_url: args.derpmap_url.clone(),
                    region: args.region.clone(),
                    port: args
                        .tailcat_port
                        .unwrap_or(sentinel_link::tailcat::DEFAULT_LINK_PORT),
                })
            }
            _ => None,
        };
        Ok(Plan {
            api,
            config: args.config.clone(),
            data_dir: args.data_dir.clone(),
            name,
            helper,
        })
    }

    fn identity_files(&self) -> [PathBuf; 4] {
        [
            self.data_dir.join("worker.id"),
            self.data_dir.join("worker.crt"),
            self.data_dir.join("worker.key"),
            self.data_dir.join("tailcat"),
        ]
    }

    /// An existing identity belongs to a worker that may already be enrolled: never replace it.
    fn preflight(&self) -> Result<(), Failure> {
        for path in self
            .identity_files()
            .iter()
            .chain(std::iter::once(&self.config))
        {
            if path.symlink_metadata().is_ok() {
                return Err(Failure::refused(format!(
                    "{} already exists; this host looks enrolled. Uninstall the worker (and its data directory) before enrolling again",
                    path.display()
                )));
            }
        }
        Ok(())
    }

    fn enroll(&self, secret: &Secret, journal: &mut Journal) -> Result<String, Failure> {
        // Step 2: refuse an unsupported setup before anything is created or spent.
        let provisional = self.render(&Trust::placeholder(self.helper.is_some()), None);
        let provisional_path = sibling(&self.config, "check");
        write_new(&provisional_path, provisional.as_bytes(), journal)?;
        let checked = service::check_worker(provisional_path.clone(), self.data_dir.clone());
        remove_quietly(&provisional_path);
        checked.map_err(|error| {
            Failure::refused(format!(
                "this host cannot run the worker as configured: {}",
                error.message
            ))
        })?;

        // Step 3: identities, generated here and kept here.
        if !self.data_dir.exists() {
            fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(&self.data_dir)
                .map_err(|error| {
                    Failure::failed(format!(
                        "cannot create {}: {error}",
                        self.data_dir.display()
                    ))
                })?;
            journal.created_dir(&self.data_dir);
        }
        let (cert, key) = (
            self.data_dir.join("worker.crt"),
            self.data_dir.join("worker.key"),
        );
        journal.created_file(&cert);
        journal.created_file(&key);
        let (identity, _) = sentinel_link::identity::Identity::load_or_generate(
            "worker", &cert, &key,
        )
        .map_err(|error| Failure::failed(format!("cannot generate the TLS identity: {error}")))?;
        let worker = WorkerId::new();
        write_new(
            &self.data_dir.join("worker.id"),
            format!("{worker}\n").as_bytes(),
            journal,
        )?;
        let node_key = match &self.helper {
            Some(helper) => {
                journal.created_tree(&self.data_dir.join("tailcat"));
                let config = sentinel_link::tailcat::TailcatConfig {
                    enabled: true,
                    binary: helper.binary.clone(),
                    sha256: helper.sha256.clone(),
                    derpmap_url: helper.derpmap_url.clone(),
                    region: helper.region.clone(),
                    listen_port: helper.port,
                };
                let key = sentinel_link::tailcat::ensure_key(
                    &config,
                    &self.data_dir,
                    sentinel_link::tailcat::Role::Worker,
                )
                .map_err(|error| {
                    Failure::failed(format!("cannot generate the Tailcat node key: {error}"))
                })?;
                Some(key.expose().to_owned())
            }
            None => None,
        };

        // Step 4: the one remote step.
        let fingerprint = hex(&identity.fingerprint().0);
        let arch = if cfg!(target_arch = "aarch64") {
            "aarch64"
        } else {
            "x86_64"
        };
        let mut request = json!({
            "worker": worker.to_string(),
            "name": self.name,
            "fingerprint": fingerprint,
            "arch": arch,
        });
        if let Some(key) = &node_key {
            request["node_key"] = json!(key);
        }
        // The secret is spliced into the text rather than into a JSON value, so the only copies of it
        // are two strings this function wipes. Its alphabet (sntl_ and hex) needs no escaping.
        let rest = request.to_string();
        let mut text = sentinel_auth::token::format(secret);
        let mut body = String::with_capacity(rest.len() + text.len() + 16);
        body.push_str("{\"secret\":\"");
        body.push_str(&text);
        body.push_str("\",");
        body.push_str(&rest[1..]);
        wipe_string(&mut text);
        let answer = redeem(&self.api, body.as_bytes());
        wipe_string(&mut body);
        let reply = answer?;

        // Step 5: from here the controller knows this worker, so a failure must say so.
        let mut finish = || -> Result<String, Failure> {
            let trust = reply.verify(worker, self.helper.is_some())?;
            let text = self.render(&trust, Some(&reply));
            write_atomic(&self.config, text.as_bytes(), journal)?;
            service::check_worker(self.config.clone(), self.data_dir.clone()).map_err(|error| {
                Failure::failed(format!(
                    "the written configuration does not check out: {}",
                    error.message
                ))
            })?;
            Ok(format!(
                "enrolled {worker} in pool {} over {}; wrote {}",
                reply.pool,
                if self.helper.is_some() {
                    "Tailcat"
                } else {
                    "direct TLS"
                },
                self.config.display()
            ))
        };
        finish().map_err(|failure| Failure {
            code: failure.code,
            message: format!(
                "{}. The controller has already enrolled worker {worker}, but this host could not finish and was restored; ask a platform administrator to uninstall that worker (POST /api/v1/admin/workers/{worker}/uninstall) and enroll again with a new enrollment",
                failure.message
            ),
        })
    }

    fn render(&self, trust: &Trust, reply: Option<&Reply>) -> String {
        let mut text = String::new();
        text.push_str("# Written by `sentinel worker enroll`. Ceilings and priority are set on the controller.\n");
        if let Some(reply) = reply {
            text.push_str(&format!(
                "# Approved by the controller for pool {}: cpu_millis={}, memory_bytes={}, disk_bytes={}, priority={}.\n",
                reply.pool,
                limit(reply.host.cpu_millis),
                limit(reply.host.memory_bytes),
                limit(reply.host.disk_bytes),
                reply.host.priority
            ));
            text.push_str("# They are recorded here for the operator; the controller enforces them and a change there needs no edit here.\n");
        }
        text.push_str(&format!("data_dir = \"{}\"\n", self.data_dir.display()));
        text.push_str("log_format = \"text\"\nlog_level = \"info\"\n");
        match &self.helper {
            Some(helper) => text.push_str(&format!("controller = \"127.0.0.1:{}\"\n", helper.port)),
            None => text.push_str(&format!("controller = \"{}\"\n", trust.controller)),
        }
        text.push_str(&format!(
            "controller_fingerprint = \"{}\"\n",
            trust.fingerprint
        ));
        text.push_str(&format!("worker_name = \"{}\"\n", self.name));
        if let Some(helper) = &self.helper {
            text.push_str(&format!(
                "tailcat_address = \"{}\"\n",
                trust.tailcat_address
            ));
            text.push_str("\n[tailcat]\nenabled = true\n");
            text.push_str(&format!("binary = \"{}\"\n", helper.binary.display()));
            text.push_str(&format!("sha256 = \"{}\"\n", helper.sha256));
            text.push_str(&format!("listen_port = {}\n", helper.port));
            if let Some(url) = &helper.derpmap_url {
                text.push_str(&format!("derpmap_url = \"{url}\"\n"));
            }
            if let Some(region) = &helper.region {
                text.push_str(&format!("region = \"{region}\"\n"));
            }
        }
        text
    }
}

fn limit(value: Option<i64>) -> String {
    value.map_or_else(|| "none".to_owned(), |v| v.to_string())
}

/// What the configuration needs from the controller's answer.
struct Trust {
    controller: String,
    fingerprint: String,
    tailcat_address: String,
}

impl Trust {
    fn placeholder(tailcat: bool) -> Trust {
        Trust {
            controller: "127.0.0.1:7443".to_owned(),
            fingerprint: PLACEHOLDER_FINGERPRINT.to_owned(),
            tailcat_address: if tailcat {
                PLACEHOLDER_ADDRESS.to_owned()
            } else {
                String::new()
            },
        }
    }
}

#[derive(Deserialize)]
struct Host {
    cpu_millis: Option<i64>,
    memory_bytes: Option<i64>,
    disk_bytes: Option<i64>,
    priority: i64,
}

#[derive(Deserialize)]
struct Reply {
    worker: String,
    pool: String,
    transport: String,
    controller: String,
    controller_fingerprint: String,
    tailcat_address: Option<String>,
    host: Host,
}

impl Reply {
    /// The controller's answer must be about this worker, over the transport this host used, and carry
    /// trust data of the right shape; anything else is not written into a configuration.
    fn verify(&self, worker: WorkerId, tailcat: bool) -> Result<Trust, Failure> {
        let wrong =
            |what: &str| Failure::failed(format!("the controller's answer is unusable: {what}"));
        if self.worker != worker.to_string() {
            return Err(wrong("it names another worker"));
        }
        if self.transport != if tailcat { "tailcat" } else { "direct" } {
            return Err(wrong("it names another transport"));
        }
        let fingerprint = &self.controller_fingerprint;
        if fingerprint.len() != 64
            || !fingerprint
                .bytes()
                .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        {
            return Err(wrong("its link fingerprint is malformed"));
        }
        if self.controller.parse::<std::net::SocketAddr>().is_err() {
            return Err(wrong("its link address is malformed"));
        }
        let tailcat_address = match (&self.tailcat_address, tailcat) {
            (Some(address), true)
                if sentinel_link::tailcat::Address::parse(address)
                    .is_some_and(|a| a.expose() == address) =>
            {
                address.clone()
            }
            (None, false) => String::new(),
            _ => {
                return Err(wrong(
                    "its Tailcat address is missing, unexpected or malformed",
                ));
            }
        };
        Ok(Trust {
            controller: self.controller.clone(),
            fingerprint: fingerprint.clone(),
            tailcat_address,
        })
    }
}

// ---- the secret --------------------------------------------------------------

fn read_secret(args: &EnrollArgs) -> Result<Secret, Failure> {
    let mut text = match (&args.secret_file, args.secret_stdin) {
        (Some(path), false) => read_secret_file(path)?,
        (None, true) => {
            if io::stdin().is_terminal() {
                return Err(Failure::refused(
                    "standard input is a terminal; pipe the enrollment secret in (the bootstrap script does)",
                ));
            }
            read_limited(io::stdin().lock())?
        }
        _ => {
            return Err(Failure::refused(
                "give the enrollment secret with exactly one of --secret-file and --secret-stdin",
            ));
        }
    };
    let line = text.lines().next().unwrap_or("").trim().to_owned();
    wipe_string(&mut text);
    let mut line = line;
    let parsed = sentinel_auth::token::parse(&line);
    wipe_string(&mut line);
    parsed.ok_or_else(|| {
        Failure::refused(
            "the first line of the secret input is not an enrollment secret (sntl_ and 64 hex characters)",
        )
    })
}

fn read_secret_file(path: &Path) -> Result<String, Failure> {
    let meta = fs::symlink_metadata(path)
        .map_err(|error| Failure::refused(format!("cannot read --secret-file: {error}")))?;
    if !meta.file_type().is_file() {
        return Err(Failure::refused(
            "--secret-file must be a regular file, not a link or a directory",
        ));
    }
    if meta.mode() & 0o077 != 0 {
        return Err(Failure::refused(
            "--secret-file is readable by other accounts; make it owner-only (chmod 600)",
        ));
    }
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| Failure::refused(format!("cannot read --secret-file: {error}")))?;
    read_limited(file)
}

fn read_limited(reader: impl Read) -> Result<String, Failure> {
    let mut bytes = Vec::new();
    reader
        .take(SECRET_INPUT_MAX + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| Failure::refused(format!("cannot read the secret input: {error}")))?;
    if bytes.len() as u64 > SECRET_INPUT_MAX {
        return Err(Failure::refused("the secret input is too long"));
    }
    String::from_utf8(bytes).map_err(|_| Failure::refused("the secret input is not text"))
}

// ---- the controller ----------------------------------------------------------

/// The redemption URL for a base URL: `https://`, or `http://` for a loopback host, with no user
/// information, query or fragment, so a URL never carries a credential.
fn redeem_url(base: &str) -> Result<String, Failure> {
    let bad = |why: &str| Failure::refused(format!("--api-url {why}"));
    let (secure, rest) = match (base.strip_prefix("https://"), base.strip_prefix("http://")) {
        (Some(rest), _) => (true, rest),
        (None, Some(rest)) => (false, rest),
        _ => {
            return Err(bad(
                "must start with https:// (or http:// for a loopback host)",
            ));
        }
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if authority.is_empty()
        || authority.contains('@')
        || rest.contains(['?', '#'])
        || base.bytes().any(|b| !(0x21..=0x7e).contains(&b))
    {
        return Err(bad(
            "must be a plain URL without user information, query, fragment or spaces",
        ));
    }
    let host = match authority.strip_prefix('[') {
        Some(v6) => v6.split(']').next().unwrap_or(""),
        None => authority.split(':').next().unwrap_or(""),
    };
    let loopback = host == "localhost" || host == "::1" || host.starts_with("127.");
    if !secure && !loopback {
        return Err(bad("must be https:// unless the host is loopback"));
    }
    Ok(format!("{}{REDEEM_PATH}", base.trim_end_matches('/')))
}

fn redeem(url: &str, body: &[u8]) -> Result<Reply, Failure> {
    let agent = ureq::Agent::new_with_config(
        ureq::Agent::config_builder()
            .http_status_as_error(false)
            .max_redirects(0)
            .timeout_global(Some(CALL_TIMEOUT))
            .build(),
    );
    let mut last = String::new();
    for attempt in 0..ATTEMPTS {
        if attempt > 0 {
            std::thread::sleep(RETRY_WAIT * attempt);
        }
        let sent = agent
            .post(url)
            .header("content-type", "application/json")
            .send(body);
        let mut response = match sent {
            Ok(response) => response,
            Err(error) => {
                // The error text can name the URL but never the body.
                last = format!("cannot reach the controller: {error}");
                continue;
            }
        };
        let status = response.status().as_u16();
        let mut text = Vec::new();
        let _ = response
            .body_mut()
            .as_reader()
            .take(RESPONSE_MAX)
            .read_to_end(&mut text);
        match status {
            200 => {
                return serde_json::from_slice(&text).map_err(|_| {
                    Failure::failed("the controller's answer is not a redemption answer")
                });
            }
            403 => {
                return Err(Failure::failed(
                    "the controller refused the enrollment secret: it is not valid, was already used or has expired. Issue a new enrollment",
                ));
            }
            409 => {
                return Err(Failure::failed(
                    "the controller already knows this worker identity or node key; the enrollment was not spent. Remove the earlier worker first",
                ));
            }
            404 => {
                return Err(Failure::failed(
                    "this controller does not accept enrollment over HTTPS (no api_url in its [worker_bootstrap])",
                ));
            }
            429 | 500..=599 => {
                last = format!("the controller asked to retry later (HTTP {status})");
            }
            _ => {
                return Err(Failure::failed(format!(
                    "the controller refused the request (HTTP {status})"
                )));
            }
        }
    }
    Err(Failure::failed(format!("{last}; tried {ATTEMPTS} times")))
}

// ---- files and rollback ------------------------------------------------------

/// Everything this run created, removed in reverse if it does not finish.
#[derive(Default)]
struct Journal {
    files: Vec<PathBuf>,
    trees: Vec<PathBuf>,
    dirs: Vec<PathBuf>,
    done: bool,
}

impl Journal {
    fn created_file(&mut self, path: &Path) {
        self.files.push(path.to_owned());
    }

    fn created_tree(&mut self, path: &Path) {
        self.trees.push(path.to_owned());
    }

    fn created_dir(&mut self, path: &Path) {
        self.dirs.push(path.to_owned());
    }

    fn commit(&mut self) {
        self.done = true;
    }
}

impl Drop for Journal {
    fn drop(&mut self) {
        if self.done {
            return;
        }
        for path in self.files.iter().rev() {
            remove_quietly(path);
        }
        for path in self.trees.iter().rev() {
            let _ = fs::remove_dir_all(path);
        }
        for path in self.dirs.iter().rev() {
            let _ = fs::remove_dir(path);
        }
    }
}

fn remove_quietly(path: &Path) {
    let _ = fs::remove_file(path);
}

fn sibling(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(".");
    name.push(suffix);
    PathBuf::from(name)
}

/// Create a file that must not exist yet, owner-only, and remember it for rollback.
fn write_new(path: &Path, bytes: &[u8], journal: &mut Journal) -> Result<(), Failure> {
    let failed =
        |error: io::Error| Failure::failed(format!("cannot write {}: {error}", path.display()));
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(failed)?;
    journal.created_file(path);
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(failed)
}

/// Write the final file beside its name and rename it into place, so a reader never sees half of it.
fn write_atomic(path: &Path, bytes: &[u8], journal: &mut Journal) -> Result<(), Failure> {
    let staged = sibling(path, "new");
    remove_quietly(&staged);
    write_new(&staged, bytes, journal)?;
    journal.created_file(path);
    fs::rename(&staged, path)
        .map_err(|error| Failure::failed(format!("cannot write {}: {error}", path.display())))
}

// ---- small helpers -----------------------------------------------------------

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::with_capacity(64), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

/// A value safe inside a TOML basic string and a shell word.
fn toml_safe(text: &str) -> bool {
    !text.is_empty()
        && text
            .bytes()
            .all(|b| (0x20..0x7f).contains(&b) && !matches!(b, b'"' | b'\\'))
}

fn host_name() -> String {
    fs::read_to_string("/proc/sys/kernel/hostname")
        .map(|name| name.trim().to_owned())
        .unwrap_or_default()
}

/// The name the controller lists: letters, digits, dots, dashes and underscores, at most 128.
fn clean_name(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '-'
            }
        })
        .take(128)
        .collect();
    if cleaned.is_empty() {
        "worker".to_owned()
    } else {
        cleaned
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_redemption_url_is_https_or_loopback_and_never_carries_a_credential() {
        assert_eq!(
            redeem_url("https://ci.example.com").unwrap(),
            "https://ci.example.com/api/v1/worker-enrollments/redeem"
        );
        assert_eq!(
            redeem_url("https://ci.example.com:8443/base/").unwrap(),
            "https://ci.example.com:8443/base/api/v1/worker-enrollments/redeem"
        );
        for local in [
            "http://127.0.0.1:8080",
            "http://localhost",
            "http://[::1]:9",
        ] {
            assert!(redeem_url(local).is_ok(), "{local}");
        }
        for bad in [
            "http://ci.example.com",
            "ftp://ci.example.com",
            "ci.example.com",
            "https://",
            "https://user:pw@ci.example.com",
            "https://ci.example.com/?token=sntl_x",
            "https://ci.example.com/#frag",
            "https://ci.example.com/a b",
        ] {
            let refused = redeem_url(bad).unwrap_err();
            assert_eq!(refused.code, 2, "{bad}");
            assert!(!refused.message.contains("pw@"), "{}", refused.message);
        }
    }

    #[test]
    fn worker_names_are_reduced_to_a_listing_safe_alphabet() {
        assert_eq!(clean_name("build box/1"), "build-box-1");
        assert_eq!(clean_name(""), "worker");
        assert_eq!(clean_name(&"a".repeat(300)).len(), 128);
    }

    #[test]
    fn config_values_that_could_break_out_of_a_string_are_refused() {
        assert!(toml_safe("/var/lib/sentinel-worker"));
        for bad in ["", "a\"b", "a\\b", "a\nb", "é"] {
            assert!(!toml_safe(bad), "{bad:?}");
        }
    }

    #[test]
    fn a_secret_file_must_be_an_owner_only_regular_file() {
        let dir = tempfile::tempdir().unwrap();
        let secret = format!("sntl_{}\n", "ab".repeat(32));
        let open = dir.path().join("open");
        fs::write(&open, &secret).unwrap();
        fs::set_permissions(&open, std::os::unix::fs::PermissionsExt::from_mode(0o644)).unwrap();
        assert!(
            read_secret_file(&open)
                .unwrap_err()
                .message
                .contains("owner-only")
        );
        let closed = dir.path().join("closed");
        fs::write(&closed, &secret).unwrap();
        fs::set_permissions(&closed, std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();
        assert!(read_secret_file(&closed).unwrap().starts_with("sntl_"));
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&closed, &link).unwrap();
        assert!(
            read_secret_file(&link)
                .unwrap_err()
                .message
                .contains("regular file")
        );
        assert!(read_secret_file(dir.path()).is_err());
        let huge = dir.path().join("huge");
        fs::write(&huge, "x".repeat(5000)).unwrap();
        fs::set_permissions(&huge, std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();
        assert!(
            read_secret_file(&huge)
                .unwrap_err()
                .message
                .contains("too long")
        );
    }

    #[test]
    fn a_failed_run_removes_what_it_created_and_nothing_else() {
        let dir = tempfile::tempdir().unwrap();
        let kept = dir.path().join("kept");
        fs::write(&kept, "mine").unwrap();
        let data = dir.path().join("data");
        {
            let mut journal = Journal::default();
            fs::create_dir(&data).unwrap();
            journal.created_dir(&data);
            write_new(&data.join("worker.id"), b"wrk_x\n", &mut journal).unwrap();
            fs::create_dir(data.join("tailcat")).unwrap();
            journal.created_tree(&data.join("tailcat"));
            fs::write(data.join("tailcat").join("key"), "k").unwrap();
            write_atomic(&data.join("worker.toml"), b"x = 1\n", &mut journal).unwrap();
        }
        assert!(!data.exists(), "everything this run made is gone");
        assert!(kept.exists());

        let mut journal = Journal::default();
        fs::create_dir(&data).unwrap();
        write_atomic(&data.join("worker.toml"), b"x = 1\n", &mut journal).unwrap();
        journal.commit();
        drop(journal);
        assert!(
            data.join("worker.toml").is_file(),
            "a finished run keeps its files"
        );
    }

    #[test]
    fn a_reply_must_be_about_this_worker_over_this_transport_with_well_formed_trust_data() {
        let worker = WorkerId::new();
        let reply = |worker: &str, transport: &str, print: &str, address: Option<&str>| Reply {
            worker: worker.to_owned(),
            pool: "pool_x".to_owned(),
            transport: transport.to_owned(),
            controller: "10.0.0.5:7443".to_owned(),
            controller_fingerprint: print.to_owned(),
            tailcat_address: address.map(str::to_owned),
            host: Host {
                cpu_millis: None,
                memory_bytes: None,
                disk_bytes: None,
                priority: 0,
            },
        };
        let print = "ab".repeat(32);
        let address = "tcabcdefghijklmnopqrstuvwxyz0123";
        let id = worker.to_string();
        assert!(
            reply(&id, "tailcat", &print, Some(address))
                .verify(worker, true)
                .is_ok()
        );
        assert!(
            reply(&id, "direct", &print, None)
                .verify(worker, false)
                .is_ok()
        );
        for bad in [
            reply(&WorkerId::new().to_string(), "direct", &print, None),
            reply(&id, "tailcat", &print, None),
            reply(&id, "direct", "XYZ", None),
            reply(&id, "direct", &print.to_uppercase(), None),
            reply(&id, "direct", &print, Some(address)),
        ] {
            assert!(bad.verify(worker, false).is_err());
        }
        assert!(
            reply(&id, "tailcat", &print, Some("not-an-address"))
                .verify(worker, true)
                .is_err()
        );
        assert!(
            reply(&id, "tailcat", &print, None)
                .verify(worker, true)
                .is_err()
        );
    }
}
