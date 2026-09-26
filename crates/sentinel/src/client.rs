//! The shared API client every networked command uses (O04–O06): where the
//! controller is, which credential to present, how answers become output,
//! and how failures become stable exit codes.
//!
//! Credential precedence: (1) `--token-file`, then `SENTINEL_TOKEN` — a
//! static `sntl_` credential or `sntl_at_` access token, which needs
//! `--server`/`SENTINEL_SERVER` and is never refreshed; (2) otherwise a
//! profile: `--profile`, then `SENTINEL_PROFILE`, then the `current` one in
//! `profiles.json` ([`crate::profile`]). A `--server`/`SENTINEL_SERVER`
//! given with a profile must name the profile's own server after
//! normalization, or the command stops with exit 2 before any request.
//!
//! Exit codes are a compatibility surface ([`Exit`], `docs/cli.md`). In
//! JSON and NDJSON modes a failure is one `sentinel.error/1` line on stderr
//! and stdout stays clean.

use std::{
    fmt,
    io::Read,
    path::PathBuf,
    sync::atomic::{AtomicU8, Ordering},
    time::Duration,
};

use serde_json::{Value, json};

use crate::profile;

/// Process exit codes. Stable: scripts and agents switch on them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Exit {
    /// Success (`wait`: the run passed).
    Ok = 0,
    /// Remote fault, transport failure the client could not classify, or a
    /// malformed answer.
    Remote = 1,
    /// Usage, local configuration or profile error, server/profile mismatch.
    Usage = 2,
    /// Unauthenticated or forbidden, including an expired or revoked grant.
    Auth = 3,
    NotFound = 4,
    /// Conflict or idempotency-key mismatch.
    Conflict = 5,
    /// Busy or rate limited after the client's retries, unreachable, or a
    /// write whose outcome the controller could not confirm (`outcome_unknown`).
    Busy = 6,
    /// `wait`: the deadline passed first.
    Timeout = 7,
    /// `wait`: the run finished but did not pass.
    RunFailed = 8,
}

impl Exit {
    /// The `code` of a client-side `sentinel.error/1` document.
    pub const fn client_code(self) -> &'static str {
        match self {
            Exit::Ok => "client_ok",
            Exit::Remote => "client_remote",
            Exit::Usage => "client_usage",
            Exit::Auth => "client_unauthenticated",
            Exit::NotFound => "client_not_found",
            Exit::Conflict => "client_conflict",
            Exit::Busy => "client_unavailable",
            Exit::Timeout => "client_timeout",
            Exit::RunFailed => "client_run_failed",
        }
    }

    /// The exit for a `sentinel.error/1` code (after retries were spent).
    pub fn for_code(code: &str) -> Exit {
        match code {
            "unauthenticated" | "forbidden" => Exit::Auth,
            "not_found" => Exit::NotFound,
            "conflict" | "idempotency_mismatch" => Exit::Conflict,
            "rate_limited" | "storage_full" | "internal" | "outcome_unknown" => Exit::Busy,
            _ => Exit::Remote,
        }
    }
}

/// A failed command: a message for humans, the exit, and the server's
/// `sentinel.error/1` document when there was one.
#[derive(Debug)]
pub struct Error {
    pub message: String,
    pub exit: Exit,
    pub api: Option<Value>,
}

impl Error {
    pub fn new(exit: Exit, message: impl Into<String>) -> Error {
        Error {
            message: message.into(),
            exit,
            api: None,
        }
    }
    pub fn usage(message: impl Into<String>) -> Error {
        Error::new(Exit::Usage, message)
    }
    pub fn remote(message: impl Into<String>) -> Error {
        Error::new(Exit::Remote, message)
    }

    /// The single-line JSON document JSON/NDJSON modes print on stderr.
    pub fn document(&self) -> Value {
        match &self.api {
            Some(api) => api.clone(),
            None => json!({
                "schema": "sentinel.error/1",
                "code": self.exit.client_code(),
                "message": self.message,
                "retryable": false,
            }),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}
impl std::error::Error for Error {}

/// How a command prints results.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum)]
pub enum Output {
    /// Human-readable text.
    #[default]
    Text,
    /// One JSON document (pretty-printed).
    Json,
    /// One compact JSON document per line, one line per item for lists.
    Ndjson,
}

/// The mode failures are reported in; set when a command resolves its
/// [`ClientArgs::output`], read by [`report`].
static MODE: AtomicU8 = AtomicU8::new(0);

fn set_mode(output: Output) {
    MODE.store(output as u8, Ordering::Relaxed);
}

fn mode() -> Output {
    match MODE.load(Ordering::Relaxed) {
        1 => Output::Json,
        2 => Output::Ndjson,
        _ => Output::Text,
    }
}

/// Options every networked command accepts, anywhere after its name.
#[derive(Clone, Debug, Default, clap::Args)]
pub struct ClientArgs {
    /// Profile to use (default: SENTINEL_PROFILE, then the current profile)
    #[arg(long, env = "SENTINEL_PROFILE", global = true)]
    pub profile: Option<String>,
    /// Controller URL; with a profile it must match the profile's server
    /// (also SENTINEL_SERVER)
    #[arg(long, global = true)]
    pub server: Option<String>,
    /// File holding a static credential (`sntl_…` or `sntl_at_…`); also SENTINEL_TOKEN
    #[arg(long, value_name = "PATH", global = true)]
    pub token_file: Option<PathBuf>,
    /// text, json or ndjson
    #[arg(long, value_enum, default_value = "text", global = true)]
    pub output: Output,
    /// Same as --output json
    #[arg(long, global = true)]
    pub json: bool,
}

impl ClientArgs {
    /// The effective output mode (`--json` wins), recorded for [`report`].
    pub fn output(&self) -> Output {
        let output = if self.json { Output::Json } else { self.output };
        set_mode(output);
        output
    }
}

/// Write to standard output; every command's stdout goes through here (or
/// the [`crate::out!`]/[`crate::outln!`] macros), never `print!`, which
/// panics with exit 101 when the reader has gone. A closed stdout — the
/// reader of a pipe exited, as `| head -1` does — ends the process at once,
/// quietly, with exit 0: the reader chose to stop, and nothing failed. Any
/// other write failure (a full disk behind a redirect) is reported in the
/// current mode and exits 1.
pub fn stdout_fmt(args: fmt::Arguments<'_>) {
    use std::io::Write;
    if let Err(error) = std::io::stdout().lock().write_fmt(args) {
        stdout_failed(&error);
    }
}

/// [`stdout_fmt`] for raw bytes (log frames).
pub fn stdout_bytes(bytes: &[u8]) {
    use std::io::Write;
    if let Err(error) = std::io::stdout().lock().write_all(bytes) {
        stdout_failed(&error);
    }
}

/// Push buffered output to the reader now (a followed log between polls).
pub fn stdout_flush() {
    use std::io::Write;
    if let Err(error) = std::io::stdout().lock().flush() {
        stdout_failed(&error);
    }
}

#[cold]
fn stdout_failed(error: &std::io::Error) -> ! {
    if error.kind() == std::io::ErrorKind::BrokenPipe {
        std::process::exit(Exit::Ok as i32);
    }
    report(&Error::remote(format!(
        "cannot write to standard output: {error}"
    )));
    std::process::exit(Exit::Remote as i32)
}

/// Print one result: text, pretty JSON, or one compact line.
pub fn emit(output: Output, value: &Value, text: impl FnOnce() -> String) {
    match output {
        Output::Text => crate::out!("{}", text()),
        Output::Json => crate::outln!("{:#}", value),
        Output::Ndjson => crate::outln!("{value}"),
    }
}

/// Print one item of a list as it arrives: text, or one JSON line per item
/// in both JSON modes (a list in `--output json` is emitted whole by the
/// caller with [`emit`] instead).
pub fn emit_item(output: Output, value: &Value, text: impl FnOnce() -> String) {
    match output {
        Output::Text => crate::out!("{}", text()),
        Output::Json | Output::Ndjson => crate::outln!("{value}"),
    }
}

/// Append one worker of a `GET /workers` pool as a text line:
/// `  {id} {name} {arch} connected|offline {transport}`. The transport is
/// `{path} {rtt}ms`, with `rtt=-` for a round trip nothing measured and
/// `transport=-` for a worker that never reported one, so an absent
/// measurement never reads as a direct link with no latency.
pub fn push_worker_line(out: &mut String, worker: &Value) {
    use fmt::Write as _;
    let str_of = |key: &str| worker[key].as_str().unwrap_or("");
    let state = if worker["connected"] == true {
        "connected"
    } else {
        "offline"
    };
    // Writing into a String cannot fail.
    let _ = write!(
        out,
        "  {} {} {} {state} ",
        str_of("id"),
        str_of("name"),
        str_of("arch")
    );
    let _ = match worker["transport"].as_object() {
        Some(t) => {
            let path = t.get("path").and_then(Value::as_str).unwrap_or("unknown");
            match t.get("rtt_ns").and_then(Value::as_u64) {
                Some(ns) => writeln!(out, "{path} {:.1}ms", ns as f64 / 1_000_000.0),
                None => writeln!(out, "{path} rtt=-"),
            }
        }
        None => writeln!(out, "transport=-"),
    };
}

/// Report a failure on stderr in the current mode: `error: …` for text,
/// one `sentinel.error/1` line for JSON and NDJSON.
pub fn report(error: &Error) {
    match mode() {
        Output::Text => eprintln!("error: {}", error.message),
        Output::Json | Output::Ndjson => {
            eprintln!(
                "{}",
                serde_json::to_string(&error.document()).expect("json")
            );
        }
    }
}

/// Normalize a controller URL: lower-case scheme and host, default port
/// and trailing `/` dropped; userinfo, query and fragment refused; plain
/// `http` only for loopback (`127.0.0.0/8`, `[::1]`, `localhost`).
pub fn normalize_server(url: &str) -> Result<String, Error> {
    let invalid = |why: &str| Error::usage(format!("invalid server URL: {why}"));
    let (scheme, rest) = url
        .split_once("://")
        .ok_or_else(|| invalid("expected http:// or https://"))?;
    let scheme = scheme.to_ascii_lowercase();
    if scheme != "http" && scheme != "https" {
        return Err(invalid("expected http:// or https://"));
    }
    if rest.contains(['?', '#']) {
        return Err(invalid("no query or fragment"));
    }
    let (authority, path) = match rest.find('/') {
        Some(at) => rest.split_at(at),
        None => (rest, ""),
    };
    if authority.is_empty() || authority.contains('@') {
        return Err(invalid("no user information"));
    }
    let (host, port) = if let Some(v6) = authority.strip_prefix('[') {
        let (inner, after) = v6.split_once(']').ok_or_else(|| invalid("bad IPv6 host"))?;
        let port = match after {
            "" => None,
            p => Some(p.strip_prefix(':').ok_or_else(|| invalid("bad port"))?),
        };
        (format!("[{}]", inner.to_ascii_lowercase()), port)
    } else {
        match authority.rsplit_once(':') {
            Some((h, p)) => (h.to_ascii_lowercase(), Some(p)),
            None => (authority.to_ascii_lowercase(), None),
        }
    };
    if host.is_empty() || host == "[]" {
        return Err(invalid("no host"));
    }
    let port = match port {
        None => None,
        Some(p) => {
            let n: u16 = p
                .parse()
                .ok()
                .filter(|n| *n != 0 && !p.starts_with('+'))
                .ok_or_else(|| invalid("bad port"))?;
            let default = if scheme == "http" { 80 } else { 443 };
            (n != default).then_some(n)
        }
    };
    if scheme == "http" && !loopback(&host) {
        return Err(invalid(
            "plain http is only for loopback; use https for a remote controller",
        ));
    }
    let mut out = format!("{scheme}://{host}");
    if let Some(port) = port {
        out.push(':');
        out.push_str(&port.to_string());
    }
    out.push_str(path.trim_end_matches('/'));
    Ok(out)
}

fn loopback(host: &str) -> bool {
    host == "localhost"
        || host == "[::1]"
        || host
            .parse::<std::net::Ipv4Addr>()
            .is_ok_and(|ip| ip.is_loopback())
}

enum Credential {
    Static(String),
    Profile(profile::Handle),
}

/// A connected client: base URL, HTTP agent and credential.
pub struct Client {
    base: String,
    agent: ureq::Agent,
    credential: Credential,
    tenant: Option<String>,
}

/// Attempts for a retryable answer (`rate_limited`, `storage_full`,
/// `internal`, transport) on a request that is safe to repeat.
const ATTEMPTS: u32 = 3;
const BACKOFF: Duration = Duration::from_millis(200);
const MAX_BACKOFF: Duration = Duration::from_secs(2);

#[derive(Clone, Copy)]
enum Method {
    Get,
    Post,
    Put,
    Delete,
}

type Response = ureq::http::Response<ureq::Body>;

struct BytesRequest<'a> {
    method: Method,
    path: &'a str,
    payload: &'a [u8],
    content_type: &'a str,
    headers: &'a [(&'a str, &'a str)],
    idempotency: Option<&'a str>,
}

/// A download: status (200 or 206), declared length, and the body.
pub type Download = (u16, Option<u64>, Box<dyn Read>);

fn agent() -> ureq::Agent {
    ureq::Agent::new_with_config(
        ureq::Agent::config_builder()
            .http_status_as_error(false)
            .max_redirects(0)
            .timeout_global(Some(Duration::from_secs(60)))
            .build(),
    )
}

/// A static credential must be a Sentinel bearer: `sntl_` or `sntl_at_`.
fn static_credential(text: &str) -> Result<String, Error> {
    let text = text.trim();
    if sentinel_auth::oauth::bearer(&format!("Bearer {text}")).is_none() {
        return Err(Error::usage(
            "the credential is not a sntl_ API credential or sntl_at_ access token",
        ));
    }
    Ok(text.to_owned())
}

/// The most a token file may hold: a credential is under 100 bytes.
pub const MAX_TOKEN_FILE_BYTES: u64 = 4 << 10;
/// Bound API JSON responses before they are parsed into a `Value`. A log
/// page is limited by the server to 1 MiB of frame payload; JSON escaping
/// can expand that payload several times.
const MAX_JSON_RESPONSE_BYTES: u64 = 8 << 20;
const MAX_ERROR_RESPONSE_BYTES: u64 = 64 << 10;

/// A `--token-file`, read with a bound on the bytes actually read.
pub fn read_token_file(path: &std::path::Path) -> Result<String, Error> {
    crate::bounded::text(path, MAX_TOKEN_FILE_BYTES)
        .map_err(|e| Error::usage(format!("cannot read the token file: {e}")))
}

fn env_nonempty(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

impl Client {
    /// Resolve server and credential by the documented precedence. Nothing
    /// touches the network here.
    pub fn connect(args: &ClientArgs) -> Result<Client, Error> {
        args.output();
        let server = args
            .server
            .clone()
            .or_else(|| env_nonempty("SENTINEL_SERVER"));
        let token = match &args.token_file {
            Some(path) => Some(read_token_file(path)?),
            None => env_nonempty("SENTINEL_TOKEN"),
        };
        if let Some(token) = token {
            let server = server.ok_or_else(|| {
                Error::usage("a static credential needs --server URL or SENTINEL_SERVER")
            })?;
            return Ok(Client {
                base: normalize_server(&server)?,
                agent: agent(),
                credential: Credential::Static(static_credential(&token)?),
                tenant: None,
            });
        }
        let Some(handle) = profile::resolve(args.profile.as_deref())? else {
            let hint = server.as_deref().unwrap_or("URL");
            return Err(Error::new(
                Exit::Auth,
                format!("not signed in; run: sentinel auth login --server {hint}"),
            ));
        };
        let base = normalize_server(handle.server())?;
        if let Some(explicit) = &server
            && normalize_server(explicit)? != base
        {
            return Err(Error::usage(format!(
                "--server/SENTINEL_SERVER {explicit} does not match profile {name} ({base}); nothing was sent. \
                 Drop --server (or unset SENTINEL_SERVER) to use {base}, pick that controller's profile with \
                 --profile NAME, or sign in to it: sentinel auth login --server {explicit} --profile NAME",
                name = handle.name()
            )));
        }
        Ok(Client {
            base,
            agent: agent(),
            tenant: handle.tenant().map(str::to_owned),
            credential: Credential::Profile(handle),
        })
    }

    /// A client for the legacy `sentinel api` commands: a static credential
    /// and the server exactly as given (only a trailing `/` is dropped),
    /// as those commands always accepted.
    pub fn with_token(server: &str, token: &str) -> Result<Client, Error> {
        Ok(Client {
            base: server.trim_end_matches('/').to_owned(),
            agent: agent(),
            credential: Credential::Static(static_credential(token)?),
            tenant: None,
        })
    }

    /// The normalized controller URL.
    pub fn server(&self) -> &str {
        &self.base
    }

    /// The profile's default tenant (`sentinel context use`), if any.
    pub fn default_tenant(&self) -> Option<&str> {
        self.tenant.as_deref()
    }

    /// The HTTP agent, for flows that talk to the server outside `/api/v1`.
    pub fn agent(&self) -> &ureq::Agent {
        &self.agent
    }

    pub fn get(&self, path: &str) -> Result<Value, Error> {
        self.json(Method::Get, path, None, None)
    }

    pub fn post(
        &self,
        path: &str,
        body: &Value,
        idempotency: Option<&str>,
    ) -> Result<Value, Error> {
        self.json(Method::Post, path, Some(body), idempotency)
    }

    pub fn put(&self, path: &str, body: &Value) -> Result<Value, Error> {
        self.json(Method::Put, path, Some(body), None)
    }

    pub fn delete(&self, path: &str) -> Result<Value, Error> {
        self.json(Method::Delete, path, None, None)
    }

    /// Send an explicitly bounded secret value as raw bytes. The payload is
    /// never converted to text or included in a local diagnostic.
    pub fn put_bytes(
        &self,
        path: &str,
        bytes: &[u8],
        content_type: &str,
        headers: &[(&str, &str)],
        idempotency: &str,
    ) -> Result<Value, Error> {
        self.bytes_json(
            Method::Put,
            path,
            bytes,
            content_type,
            headers,
            Some(idempotency),
        )
    }

    /// Idempotent raw-byte request used by the atomic env-file importer.
    pub fn post_bytes(
        &self,
        path: &str,
        bytes: &[u8],
        content_type: &str,
        headers: &[(&str, &str)],
        idempotency: &str,
    ) -> Result<Value, Error> {
        self.bytes_json(
            Method::Post,
            path,
            bytes,
            content_type,
            headers,
            Some(idempotency),
        )
    }

    /// A version-checked deletion with an idempotency key.
    pub fn delete_with(
        &self,
        path: &str,
        headers: &[(&str, &str)],
        idempotency: &str,
    ) -> Result<Value, Error> {
        self.bytes_json(
            Method::Delete,
            path,
            &[],
            "application/octet-stream",
            headers,
            Some(idempotency),
        )
    }

    /// Stream a body (an object download). `range` is `[start, end)` in
    /// bytes. Returns the status (200 or 206), the declared length and the
    /// reader; any other status is an error.
    pub fn download(&self, path: &str, range: Option<(u64, u64)>) -> Result<Download, Error> {
        if let Some((start, end)) = range
            && end <= start
        {
            return Err(Error::usage("empty download range"));
        }
        let response = self.exchange(&Method::Get, path, None, None, range)?;
        let status = response.status().as_u16();
        if status != 200 && status != 206 {
            return Err(self.failure(response));
        }
        let len = response
            .headers()
            .get("content-length")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse().ok());
        Ok((status, len, Box::new(response.into_body().into_reader())))
    }

    fn json(
        &self,
        method: Method,
        path: &str,
        body: Option<&Value>,
        idempotency: Option<&str>,
    ) -> Result<Value, Error> {
        let response = self.exchange(&method, path, body, idempotency, None)?;
        if !response.status().is_success() {
            return Err(self.failure(response));
        }
        let text = response
            .into_body()
            .into_with_config()
            .limit(MAX_JSON_RESPONSE_BYTES)
            .read_to_string()
            .map_err(|e| Error::remote(format!("cannot read the response: {e}")))?;
        if text.is_empty() {
            return Ok(Value::Null);
        }
        serde_json::from_str(&text).map_err(|_| {
            Error::remote(format!(
                "{} did not answer JSON; is it a Sentinel controller (and not a proxy's page)?",
                self.base
            ))
        })
    }

    fn bytes_json(
        &self,
        method: Method,
        path: &str,
        payload: &[u8],
        content_type: &str,
        headers: &[(&str, &str)],
        idempotency: Option<&str>,
    ) -> Result<Value, Error> {
        let repeatable = idempotency.is_some();
        let mut token = self.bearer()?;
        let mut refreshed = false;
        let mut attempt = 1;
        loop {
            let outcome = self.send_bytes_once(
                BytesRequest {
                    method,
                    path,
                    payload,
                    content_type,
                    headers,
                    idempotency,
                },
                &token,
            );
            let outcome: Result<Response, (Error, Option<Duration>)> = match outcome {
                Ok(response) if response.status().as_u16() == 401 => {
                    if let (Credential::Profile(handle), false) = (&self.credential, refreshed) {
                        refreshed = true;
                        token = handle.force_refresh(&self.agent, &token)?;
                        continue;
                    }
                    return self.json_response(response);
                }
                Ok(response) if response.status().as_u16() == 429 => {
                    let error = self.failure(response);
                    if server_backoff(&error).is_some() {
                        return Err(error);
                    }
                    Err((error, None))
                }
                Ok(response) if retryable_status(response.status().as_u16()) => {
                    let hint = retry_hint(&response);
                    Err((self.failure(response), hint))
                }
                Ok(response) => return self.json_response(response),
                Err(error) => Err((self.transport(error), None)),
            };
            let (error, retry_after) = match outcome {
                Err(pair) => pair,
                Ok(_) => unreachable!("successful responses return above"),
            };
            if !repeatable || attempt >= ATTEMPTS {
                return Err(error);
            }
            let backoff = retry_after
                .unwrap_or(BACKOFF * (1 << (attempt - 1)))
                .min(MAX_BACKOFF);
            std::thread::sleep(backoff);
            attempt += 1;
        }
    }

    fn send_bytes_once(
        &self,
        request: BytesRequest<'_>,
        token: &str,
    ) -> Result<Response, ureq::Error> {
        let BytesRequest {
            method,
            path,
            payload,
            content_type,
            headers,
            idempotency,
        } = request;
        let url = format!("{}{path}", self.base);
        let auth = format!("Bearer {token}");
        let mut request = match method {
            Method::Post => self.agent.post(&url),
            Method::Put => self.agent.put(&url),
            Method::Delete => self.agent.delete(&url).force_send_body(),
            Method::Get => self.agent.get(&url).force_send_body(),
        }
        .header("authorization", &auth)
        .header("accept", "application/json")
        .header("content-type", content_type);
        if let Some(key) = idempotency {
            request = request.header("idempotency-key", key);
        }
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        request.send(payload)
    }

    fn json_response(&self, response: Response) -> Result<Value, Error> {
        if !response.status().is_success() {
            return Err(self.failure(response));
        }
        let text = response
            .into_body()
            .into_with_config()
            .limit(MAX_JSON_RESPONSE_BYTES)
            .read_to_string()
            .map_err(|e| Error::remote(format!("cannot read the response: {e}")))?;
        if text.is_empty() {
            return Ok(Value::Null);
        }
        serde_json::from_str(&text).map_err(|_| {
            Error::remote(format!(
                "{} did not answer JSON; is it a Sentinel controller (and not a proxy's page)?",
                self.base
            ))
        })
    }

    /// Turn a non-success answer into an [`Error`].
    fn failure(&self, response: Response) -> Error {
        let status = response.status().as_u16();
        let text = response
            .into_body()
            .into_with_config()
            .limit(MAX_ERROR_RESPONSE_BYTES)
            .read_to_string()
            .unwrap_or_default();
        match serde_json::from_str::<Value>(&text) {
            Ok(api) if api["schema"] == "sentinel.error/1" => {
                let code = api["code"].as_str().unwrap_or("error").to_owned();
                let message = api["message"].as_str().unwrap_or("").to_owned();
                let exit = Exit::for_code(&code);
                let message = match code.as_str() {
                    "unauthenticated" => self.not_signed_in(&message),
                    "forbidden" => self.forbidden(&message, api["details"]["scope"].as_str()),
                    "outcome_unknown" => format!(
                        "outcome_unknown: {message}; the change may have been applied, so check \
                         (for example with `sentinel run list`) before repeating it"
                    ),
                    _ => format!("{code}: {message}"),
                };
                Error {
                    message,
                    exit,
                    api: Some(api),
                }
            }
            _ => Error::remote(format!("{} answered HTTP {status}", self.base)),
        }
    }

    fn not_signed_in(&self, message: &str) -> String {
        match &self.credential {
            Credential::Profile(handle) => format!(
                "not signed in to {server} (profile {profile}); run: sentinel auth login --server {server} --profile {profile}",
                server = self.base,
                profile = handle.name()
            ),
            Credential::Static(_) => format!("unauthenticated: {message}"),
        }
    }

    /// A refusal, with what to do: a missing scope names the sign-in that
    /// asks for it; anything else is the account's own permission.
    fn forbidden(&self, message: &str, scope: Option<&str>) -> String {
        match (scope, &self.credential) {
            (Some(scope), Credential::Profile(handle)) => {
                let mut granted: Vec<&str> =
                    handle.profile().scopes.split_ascii_whitespace().collect();
                for name in scope.split_ascii_whitespace() {
                    if !granted.contains(&name) {
                        granted.push(name);
                    }
                }
                format!(
                    "forbidden: the sign-in of profile {profile} lacks the {scope} scope; sign in again asking for it: \
                     sentinel auth login --server {server} --profile {profile} --scope \"{scopes}\"",
                    profile = handle.name(),
                    server = self.base,
                    scopes = granted.join(" ")
                )
            }
            (Some(scope), Credential::Static(_)) => {
                format!(
                    "forbidden: this credential lacks the {scope} scope; use one that carries it"
                )
            }
            (None, _) => format!(
                "forbidden: {message} (the account lacks the permission; ask a tenant administrator)"
            ),
        }
    }

    fn bearer(&self) -> Result<String, Error> {
        match &self.credential {
            Credential::Static(token) => Ok(token.clone()),
            Credential::Profile(handle) => handle.access_token(&self.agent),
        }
    }

    /// Send with the credential, retrying where it is safe: a profile's
    /// rejected access token is refreshed once; `rate_limited`,
    /// `storage_full`, `internal`, `outcome_unknown`, a proxy's 502/503/504
    /// and transport failures are retried with back-off for idempotent
    /// methods and keyed POSTs. A `rate_limited` answer that carries
    /// `details.retry_after_ms` is returned at once: the server named its own
    /// back-off, which the caller (`wait`, `log show --follow`) applies with
    /// jitter, so the client does not add lockstep retries of its own.
    fn exchange(
        &self,
        method: &Method,
        path: &str,
        body: Option<&Value>,
        idempotency: Option<&str>,
        range: Option<(u64, u64)>,
    ) -> Result<Response, Error> {
        let repeatable = !matches!(method, Method::Post) || idempotency.is_some();
        let payload = body.map(Value::to_string);
        let mut token = self.bearer()?;
        let mut refreshed = false;
        let mut attempt = 1;
        loop {
            let outcome =
                self.send_once(method, path, payload.as_deref(), idempotency, range, &token);
            let (last, retry_after) = match outcome {
                Ok(response) if response.status().as_u16() == 401 => {
                    if let (Credential::Profile(handle), false) = (&self.credential, refreshed) {
                        refreshed = true;
                        token = handle.force_refresh(&self.agent, &token)?;
                        continue;
                    }
                    return Ok(response);
                }
                Ok(response) if response.status().as_u16() == 429 => {
                    // The hint is in the error document, so read it now; it
                    // is small and bounded by the agent's body limit.
                    let error = self.failure(response);
                    if server_backoff(&error).is_some() {
                        return Err(error);
                    }
                    (Err(error), None)
                }
                Ok(response) if retryable_status(response.status().as_u16()) => {
                    let hint = retry_hint(&response);
                    (Ok(response), hint)
                }
                Ok(response) => return Ok(response),
                Err(e) => (Err(self.transport(e)), None),
            };
            if !repeatable || attempt >= ATTEMPTS {
                return last;
            }
            let backoff = retry_after
                .unwrap_or(BACKOFF * (1 << (attempt - 1)))
                .min(MAX_BACKOFF);
            std::thread::sleep(backoff);
            attempt += 1;
        }
    }

    fn send_once(
        &self,
        method: &Method,
        path: &str,
        payload: Option<&str>,
        idempotency: Option<&str>,
        range: Option<(u64, u64)>,
        token: &str,
    ) -> Result<Response, ureq::Error> {
        let url = format!("{}{path}", self.base);
        let auth = format!("Bearer {token}");
        let range = range.map(|(start, end)| format!("bytes={start}-{}", end - 1));
        match method {
            Method::Get | Method::Delete => {
                let mut request = match method {
                    Method::Get => self.agent.get(&url),
                    _ => self.agent.delete(&url),
                }
                .header("authorization", &auth)
                .header("accept", "application/json");
                if let Some(range) = &range {
                    request = request.header("range", range);
                }
                request.call()
            }
            Method::Post | Method::Put => {
                let mut request = match method {
                    Method::Post => self.agent.post(&url),
                    _ => self.agent.put(&url),
                }
                .header("authorization", &auth)
                .header("accept", "application/json")
                .header("content-type", "application/json");
                if let Some(key) = idempotency {
                    request = request.header("idempotency-key", key);
                }
                request.send(payload.unwrap_or("{}").as_bytes())
            }
        }
    }

    fn transport(&self, error: ureq::Error) -> Error {
        Error::new(
            Exit::Busy,
            format!(
                "cannot reach {}: {error}; check that the controller is running \
                 (sentinel doctor diagnoses the profile)",
                self.base
            ),
        )
    }
}

/// Answers worth another attempt on a request that is safe to repeat:
/// `rate_limited` (429), `internal` (500), `outcome_unknown` (503, only
/// ever repeated with the same idempotency key or on an idempotent method),
/// `storage_full` (507), and a proxy's 502/503/504.
fn retryable_status(status: u16) -> bool {
    matches!(status, 429 | 500 | 502 | 503 | 504 | 507)
}

/// The back-off a `rate_limited` answer names in `details.retry_after_ms`.
fn server_backoff(error: &Error) -> Option<u64> {
    let api = error.api.as_ref()?;
    if api["code"] != "rate_limited" {
        return None;
    }
    api["details"]["retry_after_ms"].as_u64()
}

/// A `retry-after` header in seconds, when an answer (typically a proxy's)
/// carries one. The controller names its back-off in the error document
/// instead, which [`server_backoff`] reads.
fn retry_hint(response: &Response) -> Option<Duration> {
    response
        .headers()
        .get("retry-after")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
        .map(Duration::from_secs)
}

impl fmt::Debug for Client {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Client")
            .field("server", &self.base)
            .field("credential", &"redacted")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_urls_normalize_to_one_spelling() {
        for (given, expected) in [
            ("https://CI.Example.com/", "https://ci.example.com"),
            ("HTTPS://ci.example.com:443", "https://ci.example.com"),
            (
                "https://ci.example.com:8443/",
                "https://ci.example.com:8443",
            ),
            (
                "https://ci.example.com/sentinel/",
                "https://ci.example.com/sentinel",
            ),
            ("http://127.0.0.1:7080", "http://127.0.0.1:7080"),
            ("http://127.9.9.9:80/", "http://127.9.9.9"),
            ("http://LOCALHOST:7080", "http://localhost:7080"),
            ("http://[::1]:7080/", "http://[::1]:7080"),
        ] {
            assert_eq!(normalize_server(given).unwrap(), expected, "{given}");
        }
        for refused in [
            "ci.example.com",
            "ftp://ci.example.com",
            "http://ci.example.com",
            "http://10.0.0.5:7080",
            "https://user@ci.example.com",
            "https://ci.example.com/?x=1",
            "https://ci.example.com/#top",
            "https://ci.example.com:0",
            "https://ci.example.com:99999",
            "https://ci.example.com:+80",
            "https://",
            "http://[::1",
        ] {
            let error = normalize_server(refused).unwrap_err();
            assert_eq!(error.exit, Exit::Usage, "{refused}");
        }
    }

    #[test]
    fn error_codes_map_to_stable_exits() {
        for (code, exit) in [
            ("unauthenticated", Exit::Auth),
            ("forbidden", Exit::Auth),
            ("not_found", Exit::NotFound),
            ("conflict", Exit::Conflict),
            ("idempotency_mismatch", Exit::Conflict),
            ("rate_limited", Exit::Busy),
            ("storage_full", Exit::Busy),
            ("internal", Exit::Busy),
            ("outcome_unknown", Exit::Busy),
            ("invalid_request", Exit::Remote),
            ("quota_exceeded", Exit::Remote),
            ("something_new", Exit::Remote),
        ] {
            assert_eq!(Exit::for_code(code), exit, "{code}");
        }
        let local = Error::usage("bad flag").document();
        assert_eq!(local["schema"], "sentinel.error/1");
        assert_eq!(local["code"], "client_usage");
    }
}
