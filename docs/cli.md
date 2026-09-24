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
| 6 | busy (`rate_limited`, `storage_full`, `internal`) or unreachable, after the client's retries; or `outcome_unknown`, a write the controller could not confirm — it may have been applied, so check before repeating it |
| 7 | `wait`: the deadline passed first |
| 8 | `wait`: the run finished but did not pass |

Retries: a `rate_limited`, `storage_full`, `internal` or `outcome_unknown` answer, a proxy's 502/503/504 and a transport failure are retried up to three attempts with back-off (200 ms, then 400 ms, or a `retry-after` header's seconds when the answer carries one, at most 2 s) when the request is safe to repeat — GET, PUT, DELETE, and a POST that carries an `Idempotency-Key`, which the controller replays instead of executing again. A POST without a key is never repeated, since the outcome of a busy write can be unknown. The controller names its own back-off in the error document rather than a header: a `rate_limited` answer with `details.retry_after_ms` (a refused long poll) is not retried by the client at all but returned to the command, and `wait` and `log show --follow` wait that long plus jitter before polling again; any other command exits 6.

A closed standard output — the reader of a pipe exited, as `sentinel run list --all --output ndjson | head -1` does — ends the command at once, quietly, with **exit 0**: nothing failed on Sentinel's side and there is no one left to tell. (It used to panic with exit 101.) Any other failure to write standard output (for example a full disk behind a redirect) is reported and exits 1. Files the CLI reads — pipelines, token and grant files, the admin password on standard input — are bounded by the bytes actually read, so a device such as `/dev/zero` or an endless pipe is refused at the limit instead of exhausting memory.

## Authentication and profiles

Implemented in `crates/sentinel/src/{auth_cmd.rs, profile.rs, keystore/, loopback.rs, browser.rs}`.

| Command | What |
|---|---|
| `sentinel auth login --server URL [--profile P] [--scope "…"] [--no-browser]` | browser sign-in (authorization code + PKCE, loopback redirect) |
| `sentinel auth login --device …` | device sign-in: approve a short code on another device |
| `sentinel auth login --grant-file PATH\|- …` | import a provisioned service grant (`sntl_rt_…`, see [service accounts](#service-accounts)) |
| `sentinel auth status [--offline] [--json]` | profile, account, grant, scopes, narrowing, expiry, store; never token material |
| `sentinel auth logout [--profile P \| --all] [--forget]` | revoke on the server, delete the local credential |
| `sentinel context use TENANT [--profile P]`, `sentinel context show [--json]` | the profile's default tenant for commands that take `--tenant` |

**Every sign-in starts from the server's metadata** (`/.well-known/oauth-authorization-server`). Its `issuer` must equal the normalized `--server` exactly, and every endpoint it names must be on the issuer's origin; otherwise login stops (issuer mismatch exits 2, a foreign endpoint 1) before anything is sent. `--server` defaults to `SENTINEL_SERVER`, then to the profile's existing server. Scopes default to `runs:read runs:write logs:read artifacts:read cache:read`; each `--scope` name must be one the server offers. A successful login writes the profile, makes it `current`, and — when it replaced an older grant of the same profile — revokes that grant (best effort, 5 s bound).

- **Browser.** A listener on `127.0.0.1:0` receives the redirect (`http://127.0.0.1:{port}/callback`). The URL — with `state` (32 random bytes, hex), an S256 `code_challenge`, `scope` and `resource={issuer}/api/v1` — is always printed on stderr and, unless `--no-browser`, handed to `rundll32 url.dll,FileProtocolHandler` (Windows) or `xdg-open` (Linux) as one argv element with no shell. The listener waits at most 5 minutes, reads at most 8 KiB of each request head, answers any other path `404` and keeps waiting; the first `/callback` decides: `state` must match (constant time) and `iss` must equal the issuer (RFC 9207), else the login stops with exit 3. The browser only ever sees a static "you can close this window" page. The code is exchanged with the verifier at the token endpoint.
- **Device.** The verification URI and user code are printed on stderr (the device code never is); polling honours `interval`, adds 5 s on `slow_down`, continues on `authorization_pending`, and stops with exit 3 on `access_denied`, `expired_token` or when `expires_in` passes. Ctrl-C ends the process with the platform's default signal behaviour — no handler is installed — and nothing has been written by then; the pending request simply expires on the server after 10 minutes.
- **Grant import.** `--grant-file` reads a `sntl_rt_` refresh token (at most 4 KiB, from a file or stdin with `-`) and spends it at once: the provisioned text is dead afterwards and only its stored successor works, so the file can be deleted. `--scope` and `--device` do not combine with it.

After tokens arrive, `GET /api/v1/me` names the account (a failure here revokes the new grant and nothing is stored). Then, under the profile lock, the credential is stored first and the profile that points at it second. stderr reports `Signed in to {server} as {user} (profile p, grant grt_…)`; stdout stays empty.

**Status.** `auth status` reads the profile (`--profile`, `SENTINEL_PROFILE` or the current one); without `--offline` it also calls `/api/v1/me` through the profile (refreshing if needed, once more on `401`) to verify the grant and report its tenant/repository narrowing. `--json` prints `sentinel.auth-status/1`:

```json
{ "schema": "sentinel.auth-status/1", "profile": "default", "current": true,
  "server": "https://ci.example.com", "issuer": "https://ci.example.com",
  "user": "usr_…", "username": "alice", "grant": "grt_…", "scopes": ["runs:read", "…"],
  "tenant": "acme", "narrowing": { "tenant": null, "repo": null },
  "access_expires_ms": 0, "refresh_expires_ms": 0, "store": "os",
  "signed_in": true, "verified": true }
```

`narrowing` is `null` with `--offline`; `tenant` is the `context use` default. Exit 0 when signed in, 3 when not (no credential, expired, or refused by the server — the document is still printed), 2 for a `--server` that is not the profile's.

**Logout.** For the chosen profile (or `--all`), under its lock: `POST /oauth/revoke` with the refresh token (which revokes the whole grant), then delete the stored credential. When the server cannot be reached or does not answer 200, the local credential is deleted anyway, a warning goes to stderr and the command exits 1 — the grant then stays valid on the server until it expires or is revoked from elsewhere. `--forget` also removes the profile entry (and clears `current` if it pointed there); without it the profile stays and commands say "not signed in" (exit 3).

### Configuration directory and `profiles.json`

The directory is `SENTINEL_CONFIG_DIR`, else `%APPDATA%\Sentinel` (Windows) or `${XDG_CONFIG_HOME:-$HOME/.config}/sentinel` (Linux). A directory inside a Git work tree — any ancestor holding a `.git` directory or file — is refused (exit 2) so a credential is never committed by accident; this includes a home directory kept in Git, which then needs `SENTINEL_CONFIG_DIR`.

```json
{ "schema": "sentinel.profiles/1", "current": "default",
  "profiles": { "default": { "server": "https://ci.example.com", "issuer": "https://ci.example.com",
    "client_id": "sentinel-cli", "user": "usr_…", "username": "alice", "grant": "grt_…",
    "scopes": "runs:read runs:write logs:read artifacts:read cache:read", "tenant": "acme",
    "store": "os", "key": "sentinel:https://ci.example.com:default:0f3a…", "created_ms": 1790000000000 } } }
```

It never holds a secret and is replaced atomically (write a sibling, `fsync`, rename) under `locks/.profiles.lock` — a name no profile can take, so signing in to a profile called `profiles` (which holds `locks/profiles.lock` while it updates the file) does not wait on itself. Profile names are 1–64 of `A-Z a-z 0-9 . _ -`, not starting with `.`. A schema other than `sentinel.profiles/1` is refused.

### Credential storage

The credential is one JSON blob per profile, `{"refresh":"sntl_rt_…","access":"sntl_at_…","access_expires_ms":…,"refresh_expires_ms":…}`:

| Store | Where | Default on |
|---|---|---|
| `os` | Windows Credential Manager (`CRED_TYPE_GENERIC`, `CRED_PERSIST_LOCAL_MACHINE`, target = the key). The key is `sentinel:{issuer}:{profile}:{d}`, `{d}` the first 16 hex digits of BLAKE3 over the configuration directory's canonical path, recorded in the profile as `key` at sign-in: the OS store is per user, so without `{d}` two configuration directories (a project's, a CI runner's, a test's) with the same profile for the same server would share one credential under two different refresh locks. Profiles signed in before keys named their directory have no `key` and keep the old `sentinel:{issuer}:{profile}` until their next sign-in | Windows |
| `file` | `credentials/<profile>.json` in the configuration directory | Linux (Secret Service is not implemented) |

`SENTINEL_CREDENTIAL_STORE=file|os` forces the store for a new sign-in. When the OS store fails, the credential goes to the file store with a notice on stderr, and the profile records `"store": "file"`; a profile is only ever read from the store it records. On Unix every directory Sentinel creates is `0700` and every file `0600`; a configuration directory, `profiles.json`, credentials directory or credential file that another user can reach (`mode & 0o077`) or that another user owns is refused (exit 2) with the `chmod`/`chown` that fixes it. On Windows every directory Sentinel creates, and the credentials directory before every credential write, gets a protected DACL granting only the current user and SYSTEM (inherited by the files inside) — the equivalent of `0700`, wherever `SENTINEL_CONFIG_DIR` points, not only under the per-user `%APPDATA%`. A directory that existed before (the configuration directory itself, if someone else made it) keeps its own ACL; only the credentials directory is always brought to owner-only. Credential files are replaced atomically and `fsync`ed (file and directory) before the rename, so a crash never loses a rotated refresh token that was reported stored.

### Refresh and the profile lock

A profile's access token is used from memory while more than 30 s of it remain. Otherwise the command takes `locks/<profile>.lock` — an OS file lock (`File::try_lock`, polled with back-off for at most 30 s, then exit 6) — re-reads the stored credential, and uses it as is when another process refreshed meanwhile; only if not does it spend the refresh token (`grant_type=refresh_token` at `{issuer}/oauth/token`) and store the successor before releasing the lock. After a `401`, `force_refresh(rejected)` does the same but reuses the stored token only if it differs from the rejected one. So concurrent commands on one machine present each refresh token once, which the server's rotation requires ([OAuth](oauth.md#refresh-and-rotation)); two machines sharing one profile's credential would trip replay detection and revoke the grant. A refused refresh (`invalid_grant`, expired sign-in) is exit 3 naming `sentinel auth login --server … --profile …`; an unreachable token endpoint is exit 6. A busy one (`temporarily_unavailable`) is retried once after the server's one-second `retry-after` — safe, because a refused refresh spent nothing and a rotation that committed anyway is recovered by the second presentation within the grace window — and exit 6 if it is still busy. The API itself never answers `401` for an overloaded store ([OAuth](oauth.md#access-tokens-on-the-api)), so overload does not make the client spend its refresh token.

Tests: `crates/sentinel/tests/profile.rs` (portable, a scripted fake OAuth server on loopback, temporary `SENTINEL_CONFIG_DIR`, file store): profile round trip with no `sntl_` in `profiles.json`; Git-work-tree refusal; Unix modes and the loose/foreign refusals; eight concurrent callers on a nearly expired profile observe exactly one refresh; `force_refresh` with a stale rejected token reuses the newer one; refused and unreachable refreshes; the loopback listener's state, `iss`, repeated-parameter, denial, oversized-head, other-path and timeout cases; device polling timing under `slow_down`, denial and expiry; browser login end to end through the binary (PKCE verified by the fake); device login printing the user code but no token; grant import; issuer mismatch and foreign-origin endpoints refused; logout online, offline (exit 1) and `--all --forget`; status offline/online/mismatch/signed-out; `context use/show`; a profile named `profiles` signing in without waiting on itself; a busy token endpoint retried once; and on Windows a real Credential Manager round trip under a unique key with cleanup, two configuration directories holding independent credentials for the same profile and server, and the file store owner-only (`icacls`) outside `%APPDATA%`. Every CLI output is scanned for token material.

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

For a tenant administrator (the credential needs `tenant:admin`; see [OAuth](oauth.md#service-account-grants-o06)). `--tenant SLUG` defaults to the profile's context (`sentinel context use`); without either the command exits 2 before any request. Tenant, account, repository and grant arguments must be plain path segments (`A-Z a-z 0-9 - . _ ~`), checked locally.

| Command | Does |
|---|---|
| `sentinel service-account create --name NAME [--role reader\|operator] [--tenant SLUG]` | creates a service principal (default role operator); prints `usr_…`, name and role |
| `sentinel service-account allow USR --repo NAME [--access read,run] [--tenant SLUG]` | sets its access to one repository (default `read,run`; `--access ""` withdraws) |
| `sentinel service-account grant USR --name LABEL --scope "SCOPES" [--repo NAME] [--expires-in 30d] [--tenant SLUG]` | issues a service grant; `--expires-in` takes `s`, `m`, `h` or `d`, 1h..90d (server-checked), default 30d |
| `sentinel service-account grants USR [--tenant SLUG]` | lists its grants as metadata (text: one line each; `--output ndjson`: one JSON object per grant; `--json`: the whole answer) |
| `sentinel service-account revoke GRT` | revokes a grant (`DELETE /api/v1/grants/{grt}`) |

`grant` prints **only the refresh token** (`sntl_rt_…`) and a newline on stdout, so `sentinel service-account grant … > agent.token` captures exactly it; the grant handle, scope and expiry go to stderr (one JSON line in `--json`/`--output ndjson` mode), with the import command. The token is shown this once; the server keeps only its digest. On the agent's machine, `sentinel auth login --server URL --grant-file agent.token` spends it for the agent's own profile (then delete the file).

Exits follow the table above: a non-administrator is 3, an unknown account, repository or grant 4, a refused scope or lifetime (`invalid_request`) 1, a bad argument 2.

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

**`log search`** follows the server's bounded scans: each request reads at most 4 MiB of log, so a 256 MiB log is at most 64 short requests, resumed at `next_after` with the server's `next_carry`. A literal split across frames of the same step and stream is found exactly once (reported with the frame it ends in), including across a sealed segment and across the cut between two requests; text mode says on stderr when the log is still being written (later lines were not searched) or when `--limit` cut the matches.

**`cache`** reports per-attempt records only (K08 `cache:` entries of that attempt); there is no tenant-wide cache browser.

`sentinel pipeline validate|explain` stay offline and take `--output text|json` (`--json` is `--output json`; there is no list to stream, so no `ndjson`). In JSON mode `explain` prints `sentinel.explain/1` and `validate` prints `{"file", "valid": true, "jobs"}` (text `validate` prints nothing on success), each as one line; a failure is one `sentinel.error/1` line on stderr (`invalid_pipeline`, including a file over the 256 KiB limit, or `client_usage` for an unreadable file) with stdout empty, like the networked commands. The limit bounds the bytes read, not a reported size, so `validate /dev/zero` fails at 256 KiB.

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

`sentinel doctor [--profile P] [--server URL] [--json | --output text|json|ndjson]` diagnoses how this machine signs in, in `crates/sentinel/src/doctor.rs`. It runs seven checks in order; each failure names the exact command or change that fixes it, and no output ever holds token material.

| Check | Passes when | A failure's fix |
|---|---|---|
| `config_dir` | the configuration directory can be located, is outside every Git work tree, and it, `credentials/` and `profiles.json` are owner-only (Unix) — a directory that does not exist yet passes | `SENTINEL_CONFIG_DIR=…` outside the repository, or the `chmod`/`chown` the refusal names |
| `profile` | `--profile`, `SENTINEL_PROFILE` or the current profile exists, and a `--server`/`SENTINEL_SERVER` is that profile's server (checked before any request) | `sentinel auth login --server URL [--profile P]`, or drop the foreign `--server` |
| `health` | `GET {server}/api/v1/health` answers `{ok: true}` within 10 s | start the controller / check the network; `sentinel auth login --server NEW_URL --profile P` if it moved |
| `issuer` | the metadata's `issuer` equals the server and the issuer the profile recorded | set the controller's `public_url`, then `sentinel auth login --server PUBLIC_URL --profile P` |
| `credential_store` | the stored credential is readable from the store the profile records and the sign-in has not expired | `sentinel auth login …`; for an OS store failure, `SENTINEL_CREDENTIAL_STORE=file sentinel auth login …` |
| `access_token` | `GET /api/v1/me` accepts the profile's access token (refreshed first when it is about to lapse, once more after a `401`) | `sentinel auth login --server S --profile P` |
| `refresh` | a forced refresh under the profile lock rotates the refresh token | `sentinel auth login --server S --profile P`, or retry when the controller answers |

A check that cannot run because an earlier one failed is reported as skipped (`ok: false`, `"skipped": true`) with that failure's fix: the network checks need `health`, the token checks need `health`, `issuer` and `credential_store`; the local `credential_store` check always runs. The refresh check really spends the stored refresh token once — exactly what any command does when its access token runs low — so the profile continues with the successor.

`--json` (and `--output ndjson`, as one line) prints `sentinel.doctor/1` on stdout, whether or not the checks passed:

```json
{ "schema": "sentinel.doctor/1", "profile": "default", "server": "https://ci.example.com", "ok": false,
  "checks": [
    { "name": "config_dir", "ok": true, "detail": "/home/alice/.config/sentinel (owner-only, outside any Git work tree)", "fix": null },
    { "name": "health", "ok": false, "detail": "cannot reach https://ci.example.com: …",
      "fix": "start the controller or check the network; it must answer GET https://ci.example.com/api/v1/health (…)" },
    { "name": "issuer", "ok": false, "detail": "not checked: the health check failed", "fix": "…", "skipped": true } ] }
```

Text mode prints one `ok`/`FAIL`/`skip` line per check and a `fix:` line under each failure. **Exit:** 0 when every check passed; otherwise the exit of the first failed check from the [table](#exit-codes) — 2 for the configuration directory, an unknown profile, a server/profile mismatch or an issuer mismatch; 3 when no profile is configured, no credential is stored, the sign-in expired or the server refuses the grant; 6 when the controller or its token endpoint cannot be reached; 1 for an answer that is not Sentinel's — after the report, with one `sentinel.error/1` line on stderr in the JSON modes (`error: doctor: the … check failed; fix: …` in text).

**Actionable failures elsewhere.** The shared client names the next step in its messages: a missing scope (`403` with `details.scope`) becomes `forbidden: the sign-in of profile P lacks the logs:read scope; sign in again asking for it: sentinel auth login --server S --profile P --scope "…"` with the profile's scopes plus the missing ones; a transport failure suggests `sentinel doctor`; a server/profile mismatch lists its three ways out; an answer that is not JSON names the server that sent it.

## Verification

`crates/sentinel/tests/client.rs` (portable, a fake HTTP server on loopback): each `sentinel.error/1` code and a proxy's non-JSON answer map to their exit; busy answers are retried three times before exit 6; an unreachable controller exits 6; `--json` failures are one error document on stderr with stdout empty; a malformed credential is exit 2 with nothing sent; a static credential needs a Sentinel shape and a loopback-or-https server, and connecting sends nothing. `crates/sentinel/tests/oauth_e2e.rs` (O07, portable — Windows natively and Linux) runs the real binary against an in-process controller with a temporary `SENTINEL_CONFIG_DIR` and the file store, and scans every stdout and stderr for token material (`sntl_…` followed by 16 or more hex digits, or any `sntl_dc_`):

- browser login with `--no-browser` (the test reads the URL from stderr, consents with a password session and follows the `303` to the CLI's loopback listener), then `auth status --json` and `run list`;
- device login approved on `/device`;
- untrusted redirects (no `location`), `plain` PKCE, a foreign `resource`, a wrong verifier (which spends the code), a refresh token as bearer and an access token as refresh token are refused, and the CLI refuses a callback with the wrong `state` or `iss` (exit 3, nothing saved, no grant created);
- four CLI processes on a nearly expired profile all succeed with exactly one successor refresh token and the grant intact;
- a lost refresh response recovers inside the 60 s grace window, and the same token after the window (a store call with the clock 61 s ahead, since the server's clock cannot be moved) is replay that revokes the grant; a superseded or twice-used token revokes at once over HTTP;
- removed membership exits 3 or 4, suspension exits 3 with `not signed in to S (profile P); run: sentinel auth login --server S --profile P`;
- `--server B` or `SENTINEL_SERVER=B` with profile A (for `run list`, `auth status` and `doctor`) exits 2 and B's listener sees zero connections; a server whose metadata names another issuer is refused at login;
- logout revokes on the server (old access token `401`, refresh token `invalid_grant`, local credential gone, later commands exit 3 with the login hint), and offline logout deletes locally and exits 1;
- a service grant imported with `--grant-file` runs commands with stdin closed;
- a missing scope names the login that asks for it;
- `doctor`: all seven checks pass for a working profile (and rotate the refresh token once), a removed credential exits 3, a stopped controller exits 6 with local checks still run, no profile exits 3, and a configuration directory inside a Git work tree exits 2 without creating anything.

`crates/sentinel/tests/cli.rs` (Linux, `--features server`) runs the legacy commands against a real `sentinel server` process, and one real-server `auth login --device` approved on that server's `/device` page, followed by `auth status`, `doctor` (all checks pass) and `auth logout`. The sign-in flow itself is exercised through `--no-browser`.

`crates/sentinel/tests/browser.rs` (portable; Windows natively and Linux) runs the real opener path, `browser::open` unchanged, without opening a browser. The test binary has no libtest harness: it copies itself as a runner and as a stand-in under the launcher's name (`rundll32.exe`, `open` or `xdg-open`). The stand-in sits where the real launcher is looked up first. On Windows that is the launching program's own directory, which process creation searches before the system directory; elsewhere it is the first `PATH` entry. The stand-in records its argv and exits. The runner opens a URL with `;`, `&`, `|`, `^`, `$(…)`, backticks, single and double quotes, a backslash-quote, spaces, `%PATH%` and `$HOME`, plus shell canaries. On Windows the stand-in receives exactly `url.dll,FileProtocolHandler` and the URL; elsewhere it receives the URL alone. Either way the URL is one argv element, byte for byte, and no canary file appears. A `file:`, `javascript:` or bare URL is printed but never launched, and without launch nothing starts. A pure test also pins the command construction per platform.
