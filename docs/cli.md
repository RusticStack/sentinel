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

Every command below takes the [shared client flags](#the-shared-client). `--tenant SLUG` defaults to the profile's context (`sentinel context use`); with a static credential and no context it is required (exit 2 names it). Identifiers, slugs and names that go into a request path must be `[A-Za-z0-9._-]`; anything else is refused locally (exit 2) rather than escaped into a different request.

| Command | Route | Prints |
|---|---|---|
| `sentinel run dispatch [--tenant] --repo NAME --pipeline FILE --source URL --sha SHA [--ref] [--idempotency-key]` | `POST /tenants/{slug}/repos/{name}/runs` | the new run and its jobs; a retried dispatch with the same key is the same run |
| `sentinel run status RUN`, `sentinel status RUN` | `GET /runs/{id}` | the run and its jobs |
| `sentinel run list [--tenant] --repo NAME [--limit N \| --all] [--before RUN]` | `GET …/runs?limit&before` | runs newest first ([paging](#output)) |
| `sentinel run cancel RUN` | `POST /runs/{id}/cancel` | how many jobs were cancelled |
| `sentinel run wait RUN [--timeout DUR]`, `sentinel wait RUN [--timeout DUR]` | `GET /runs/{id}/wait` | progress, then the final run; exit 0 passed (or skipped), 8 finished otherwise, 7 deadline |
| `sentinel job cancel JOB`, `sentinel job rerun JOB` | `POST /jobs/{id}/cancel\|rerun` | the cancel outcome, or the rerun job's state |
| `sentinel log show ATTEMPT [--follow] [--step N]` | `GET /attempts/{id}/logs` | the log as the job wrote it; `--follow` waits until it is complete |
| `sentinel log search ATTEMPT --text TEXT [--limit N]` | `GET /attempts/{id}/logs/search` | matching lines (`seq`, step, stream, text), default 100, at most 10,000 |
| `sentinel workers list [--tenant]` | `GET /workers?tenant` | pools and their workers with connection state |
| `sentinel workers drain\|undrain WORKER` | `POST /workers/{id}/drain\|undrain` | the new drain state (platform admin) |
| `sentinel queue [--tenant] [--limit N]` | `GET /queue?tenant&limit` | waiting jobs, oldest first, with age and reason; the total when cut (`--limit` 1–500, default 100) |
| `sentinel artifact list RUN`, `sentinel artifact show RUN ARTIFACT` | `GET /runs/{id}/artifacts[/{arf}]` | artifact rows; one row with its manifest entries |
| `sentinel artifact download RUN ARTIFACT --path ENTRY --out FILE [--tenant]` | the manifest, then `GET /tenants/{slug}/objects/{digest}` | the entry's bytes in `FILE`, verified |
| `sentinel cache show ATTEMPT` | `GET /attempts/{id}/summary` | the attempt's cache records (hit or miss reason, files, bytes, publish verdict, costly hits), or that it has not reported yet |

**`wait`** is a loop of long polls, not a stream: each request parks on the server for at most 25 s (or what is left of `--timeout`: `90s`, `500ms`, `10m`, `2h`; default no deadline) and returns as soon as anything a status reader can see changes, so an idle wait costs one request per 25 s and a change is seen within milliseconds. The server parks at most four subscribers at once; when all are taken the poll is `rate_limited`, and `wait` (like `log show --follow`) sleeps the server's `retry_after_ms` plus up to half of it again of jitter and polls again, so a crowd of waiters does not return in lockstep and is never reported as exit 6. Text prints `RUN STATE (done/total jobs finished)` per change and the job table at the end; NDJSON prints each `{version, changed, finished, run}` answer that changed something; JSON prints the final run once. A run that finished without passing exits 8 with its state on stderr; the deadline exits 7.

**`artifact download`** looks the entry up in the artifact's manifest, streams the object into `FILE.sentinel-part` beside `FILE` while hashing it (BLAKE3, the object store's digest) and counting bytes, and renames it over `FILE` only when the declared length, the byte count and the digest all match; any mismatch removes the partial file, leaves `FILE` untouched and exits 1. An entry the manifest does not list exits 4.

**`log search`** follows the server's bounded scans: each request reads at most 4 MiB of log, so a 256 MiB log is at most 64 short requests, resumed at `next_after`. A literal split across two frames is not found; text mode says on stderr when the log is still being written (later lines were not searched) or when `--limit` cut the matches.

**`cache`** reports per-attempt records only (K08 `cache:` entries of that attempt); there is no tenant-wide cache browser.

`sentinel pipeline validate|explain` stay offline; `explain --json` prints `sentinel.explain/1`, and in that mode a failure is one `sentinel.error/1` line on stderr (`invalid_pipeline`, or `client_usage` for an unreadable file) with stdout empty, like the networked commands.

## Legacy `sentinel api`

The W08 commands keep their flags and output (`me`, `run`, `status`, `runs`, `cancel`, `rerun`, `logs`, `workers`, `queue`, `drain`, `undrain`; see [API](api.md#the-cli)) and now run on the shared client: `--token-file`, `--token` or `SENTINEL_TOKEN` may hold an `sntl_` credential or an `sntl_at_` access token, the server is taken as given (a trailing `/` dropped), and exits follow the table above — so `conflict` now exits 5 and a busy or unreachable controller 6, where both used to be 1.

## Output

`--output text|json|ndjson` (`--json` is `--output json`) chooses one of three shapes; stdout carries only results and stderr only notes and failures, in every mode.

| Mode | One object (`status`, `artifact show`, `cache show`, …) | A list (`run list`, `log show`, `log search`, `artifact list`, `workers list`, `queue`) |
|---|---|---|
| `text` | lines for people; not a contract | one line (or block) per item as each page arrives; notes such as `more runs: continue with --before run_…` on stderr |
| `json` | the server's document, pretty-printed | one document once the listing ends: `{"runs": [...], "next": …}`, `{"frames": [...], "attempt", "complete", "gaps", "next_after"}`, `{"matches": [...], "attempt", "next_after", "complete"}`, `{"artifacts": [...]}`, `{"pools": [...]}`, `{"jobs": [...], "total", "truncated"}` |
| `ndjson` | the document as one compact line | one compact line per item, printed as each page arrives, nothing else |

**Paging.** A listing prints at most `--limit N` items (default 20 for `run list`) or, with `--all`, every item up to a hard cap of **10,000**; it asks the server for pages of at most 500 and prints each page before asking for the next, so memory stays one page in text and NDJSON modes (JSON collects the listing it prints, bounded by the same cap). `--before CURSOR` starts after an item — for `run list` the `next` a previous listing returned, which JSON carries as `"next"` and text names on stderr whenever items remain; the cursor is a run id, so pages stay stable while new runs arrive. `log show --output json` stops at 10,000 frames with `complete:false` and `next_after`; `log show --output ndjson` and text stream the whole log.

Exit codes and failure output are the same in every mode ([exit codes](#exit-codes), [failure output](#failure-output)).

## Security notes

No command prints token material except the one that issues it (`service-account grant` prints only the refresh token, on stdout). A static credential is read from a file so it stays out of the process list. `profiles.json` never holds a secret.

## Doctor

_Placeholder: Unit F documents `sentinel doctor` and `sentinel.doctor/1` here._

## Verification

`crates/sentinel/tests/client.rs` (portable, a fake HTTP server on loopback): each `sentinel.error/1` code and a proxy's non-JSON answer map to their exit; busy answers are retried three times before exit 6; an unreachable controller exits 6; `--json` failures are one error document on stderr with stdout empty; a malformed credential is exit 2 with nothing sent; a static credential needs a Sentinel shape and a loopback-or-https server, and connecting sends nothing. The server/profile mismatch (exit 2 with zero connections) needs real profiles and is covered once they exist (O07). `crates/sentinel/tests/cli.rs` (Linux) runs the legacy commands against a real `sentinel server`.
