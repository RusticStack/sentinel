# Developer CLI (Part 09, O04–O07)

`sentinel` is one binary: the offline `pipeline` commands, the host-local `admin` commands and the Linux `server`/`worker` roles, plus the networked commands that talk to a controller's [API](api.md) with an [OAuth](oauth.md) grant or a static credential. This page is the contract for the networked half.

| Command | What |
|---|---|
| `sentinel auth login\|status\|logout` | sign in (browser or `--device`), inspect, sign out ([below](#authentication-and-profiles)) |
| `sentinel context use\|show` | the profile's default tenant |
| `sentinel run dispatch\|status\|list\|cancel\|wait`, `status`, `wait`, `job`, `log`, `workers`, `queue`, `artifact`, `cache` | the O05 command surface ([below](#commands)) |
| `sentinel service-account create\|allow\|grant\|grants\|revoke` | service principals and their grants ([below](#service-accounts)) |
| `sentinel doctor` | configuration and connectivity checks with fixes ([below](#doctor)) |
| `sentinel api …` | the W08 commands with a static credential ([below](#legacy-sentinel-api)) |

## The shared client

Every networked command goes through `sentinel::client::Client` and accepts, anywhere after its name:

| Flag | Meaning |
|---|---|
| `--profile NAME` | the profile to use (also `SENTINEL_PROFILE`; default: `current` in `profiles.json`) |
| `--server URL` | the controller (also `SENTINEL_SERVER`); with a profile it must be the profile's own server |
| `--token-file PATH` | a static credential: an `sntl_` API credential or an `sntl_at_` access token (also `SENTINEL_TOKEN`) |
| `--output text\|json\|ndjson` | output mode (default `text`); `--json` is `--output json` |

**Credential precedence.** (1) `--token-file`, then `SENTINEL_TOKEN`: a static credential, which needs `--server` or `SENTINEL_SERVER` and is never refreshed. (2) Otherwise a profile: `--profile`, then `SENTINEL_PROFILE`, then the `current` profile. Without either the command exits 3 and names `sentinel auth login --server …`.

**Server/profile mismatch.** A `--server` or `SENTINEL_SERVER` given together with a profile must equal the profile's server after normalization; otherwise the command exits 2 **before any request**, so a credential is never sent to a server it was not issued by.

**Server URLs** are normalized to one spelling: lower-case scheme and host, default port and trailing `/` dropped, a path prefix kept. Userinfo, query and fragment are refused, and plain `http://` is accepted only for loopback (`127.0.0.0/8`, `[::1]`, `localhost`).

**Refresh.** With a profile, a `401` makes the client refresh the access token once (under the profile lock) and retry once; if that still fails the command exits 3 with `not signed in to {server} (profile {p}); run: sentinel auth login --server {server} --profile {p}`.

## Exit codes

Stable; scripts and agents switch on them (`sentinel::client::Exit`).

| Exit | Meaning |
|---|---|
| 0 | success (`wait`: the run passed) |
| 1 | remote fault, an unclassified error code, or a malformed answer |
| 2 | usage, local configuration or profile error, server/profile mismatch |
| 3 | unauthenticated or forbidden, including an expired or revoked grant; the message names the login command |
| 4 | not found |
| 5 | conflict or idempotency-key mismatch |
| 6 | busy (`rate_limited`, `storage_full`, `internal`) or unreachable, after the client's retries |
| 7 | `wait`: the deadline passed first |
| 8 | `wait`: the run finished but did not pass |

Retries: a `rate_limited`, `storage_full` or `internal` answer, a proxy's 502/503/504 and a transport failure are retried up to three attempts with back-off (200 ms, 400 ms, or the server's `retry-after`, at most 2 s) when the request is safe to repeat — GET, PUT, DELETE, and a POST that carries an `Idempotency-Key`. A POST without a key is never repeated, since the outcome of a busy write can be unknown.

## Authentication and profiles

_Placeholder: Unit D documents `sentinel auth`, `sentinel context`, `profiles.json`, credential storage and the refresh lock here._

## Implementing a command

The module layout the command units fill in (all in the `sentinel` library, so integration tests can call them):

```rust
// client.rs (Units A and F only)
#[repr(u8)] pub enum Exit { Ok = 0, Remote = 1, Usage = 2, Auth = 3, NotFound = 4, Conflict = 5, Busy = 6, Timeout = 7, RunFailed = 8 }
pub struct Error { pub message: String, pub exit: Exit, pub api: Option<serde_json::Value> } // new, usage, remote, document
#[derive(clap::Args)] pub struct ClientArgs { profile, server, token_file, output: Output, json: bool } // global flags
impl ClientArgs { pub fn output(&self) -> Output }       // --json wins; also sets how failures are reported
pub enum Output { Text, Json, Ndjson }
pub struct Client;
impl Client {
  pub fn connect(args: &ClientArgs) -> Result<Client, Error>;          // precedence and mismatch; no network
  pub fn with_token(server: &str, token: &str) -> Result<Client, Error>; // legacy `api`: server as given
  pub fn get(&self, path: &str) -> Result<Value, Error>;
  pub fn post(&self, path: &str, body: &Value, idempotency: Option<&str>) -> Result<Value, Error>;
  pub fn put(&self, path: &str, body: &Value) -> Result<Value, Error>;
  pub fn delete(&self, path: &str) -> Result<Value, Error>;
  pub fn download(&self, path: &str, range: Option<(u64, u64)>) -> Result<Download, Error>; // range = [start, end)
  pub fn server(&self) -> &str; pub fn default_tenant(&self) -> Option<&str>; pub fn agent(&self) -> &ureq::Agent;
}
pub type Download = (u16, Option<u64>, Box<dyn std::io::Read>);  // status 200/206, content-length, body
pub fn emit(output: Output, value: &Value, text: impl FnOnce() -> String);      // text / pretty JSON / one line
pub fn emit_item(output: Output, value: &Value, text: impl FnOnce() -> String); // text / one JSON line per item
pub fn report(error: &Error);                          // stderr: `error: …`, or one sentinel.error/1 line
pub fn normalize_server(url: &str) -> Result<String, Error>;
// profile.rs (Unit D)
pub struct Handle;  pub fn resolve(name: Option<&str>) -> Result<Option<Handle>, client::Error>;
impl Handle { pub fn name(&self) -> &str; pub fn server(&self) -> &str; pub fn tenant(&self) -> Option<&str>;
  pub fn access_token(&self, agent: &ureq::Agent) -> Result<String, client::Error>;
  pub fn force_refresh(&self, agent: &ureq::Agent, rejected: &str) -> Result<String, client::Error>; }
// entry points `cli.rs`/`main.rs` call; each module may reshape its Args freely
auth_cmd::{AuthArgs, ContextArgs, run(AuthArgs), run_context(ContextArgs)}          // Unit D
service_accounts::{ServiceAccountArgs, run(ServiceAccountArgs)}                    // Unit C
commands::{RunArgs, StatusArgs, WaitArgs, JobArgs, LogArgs, WorkersArgs, QueueArgs,
           ArtifactArgs, CacheArgs, Invocation, run(Invocation)}                  // Unit E (commands/)
doctor::{DoctorArgs, run(DoctorArgs)}                                              // Unit F
// pre-declared empty modules for Unit D: keystore/ (mod.rs), loopback.rs, browser.rs
```

Every `run` returns `Result<(), client::Error>`; `main.rs` reports the error in the command's output mode and exits with `error.exit as u8`. A command should call `args.client.output()` (or `Client::connect`) before it can fail, so a failure is reported in the mode the user asked for.

## Service accounts

_Placeholder: Unit C documents `sentinel service-account` here._

## Failure output

In text mode a failure is `error: <message>` on stderr. In JSON and NDJSON modes it is exactly one line on stderr — the server's `sentinel.error/1` document when there was one, otherwise `{"schema":"sentinel.error/1","code":"client_…","message":…,"retryable":false}` with `client_usage`, `client_unauthenticated`, `client_unavailable`, `client_remote`, `client_not_found`, `client_conflict`, `client_timeout` or `client_run_failed` — and stdout stays clean, so a pipeline never mistakes an error for data.

## Commands

_Placeholder: Unit E documents the O05 command surface here._

## Legacy `sentinel api`

The W08 commands keep their flags and output (`me`, `run`, `status`, `runs`, `cancel`, `rerun`, `logs`, `workers`, `queue`, `drain`, `undrain`; see [API](api.md#the-cli)) and now run on the shared client: `--token-file`, `--token` or `SENTINEL_TOKEN` may hold an `sntl_` credential or an `sntl_at_` access token, the server is taken as given (a trailing `/` dropped), and exits follow the table above — so `conflict` now exits 5 and a busy or unreachable controller 6, where both used to be 1.

## Output

_Placeholder: Unit E documents text, JSON and NDJSON output, pagination and `--all` here._

## Security notes

No command prints token material except the one that issues it (`service-account grant` prints only the refresh token, on stdout). A static credential is read from a file so it stays out of the process list. `profiles.json` never holds a secret.

## Doctor

_Placeholder: Unit F documents `sentinel doctor` and `sentinel.doctor/1` here._

## Verification

`crates/sentinel/tests/client.rs` (portable, a fake HTTP server on loopback): each `sentinel.error/1` code and a proxy's non-JSON answer map to their exit; busy answers are retried three times before exit 6; an unreachable controller exits 6; `--json` failures are one error document on stderr with stdout empty; a malformed credential is exit 2 with nothing sent; a static credential needs a Sentinel shape and a loopback-or-https server, and connecting sends nothing. The server/profile mismatch (exit 2 with zero connections) needs real profiles and is covered once they exist (O07). `crates/sentinel/tests/cli.rs` (Linux) runs the legacy commands against a real `sentinel server`.
