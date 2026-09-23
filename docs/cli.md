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

- **Browser.** A listener on `127.0.0.1:0` receives the redirect (`http://127.0.0.1:{port}/callback`). The URL — with `state` (32 random bytes, hex), an S256 `code_challenge`, `scope` and `resource={issuer}/api/v1` — is always printed on stderr and, unless `--no-browser`, handed to `rundll32 url.dll,FileProtocolHandler` (Windows), `open` (macOS) or `xdg-open` as one argv element with no shell. The listener waits at most 5 minutes, reads at most 8 KiB of each request head, answers any other path `404` and keeps waiting; the first `/callback` decides: `state` must match (constant time) and `iss` must equal the issuer (RFC 9207), else the login stops with exit 3. The browser only ever sees a static "you can close this window" page. The code is exchanged with the verifier at the token endpoint.
- **Device.** The verification URI and user code are printed on stderr (the device code never is); polling honours `interval`, adds 5 s on `slow_down`, continues on `authorization_pending`, and stops with exit 3 on `access_denied`, `expired_token` or when `expires_in` passes. Ctrl-C ends the process; nothing has been written by then.
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

The directory is `SENTINEL_CONFIG_DIR`, else `%APPDATA%\Sentinel` (Windows), `$HOME/Library/Application Support/Sentinel` (macOS), or `${XDG_CONFIG_HOME:-$HOME/.config}/sentinel`. A directory inside a Git work tree — any ancestor holding a `.git` directory or file — is refused (exit 2) so a credential is never committed by accident; this includes a home directory kept in Git, which then needs `SENTINEL_CONFIG_DIR`.

```json
{ "schema": "sentinel.profiles/1", "current": "default",
  "profiles": { "default": { "server": "https://ci.example.com", "issuer": "https://ci.example.com",
    "client_id": "sentinel-cli", "user": "usr_…", "username": "alice", "grant": "grt_…",
    "scopes": "runs:read runs:write logs:read artifacts:read cache:read", "tenant": "acme",
    "store": "os", "created_ms": 1790000000000 } } }
```

It never holds a secret and is replaced atomically (write a sibling, `fsync`, rename) under `locks/profiles.lock`. Profile names are 1–64 of `A-Z a-z 0-9 . _ -`, not starting with `.`. A schema other than `sentinel.profiles/1` is refused.

### Credential storage

The credential is one JSON blob per profile, `{"refresh":"sntl_rt_…","access":"sntl_at_…","access_expires_ms":…,"refresh_expires_ms":…}`:

| Store | Where | Default on |
|---|---|---|
| `os` | Windows Credential Manager (`CRED_TYPE_GENERIC`, `CRED_PERSIST_LOCAL_MACHINE`, target `sentinel:{issuer}:{profile}`); macOS Keychain (generic password, service `sentinel`, account `sentinel:{issuer}:{profile}`) | Windows, macOS |
| `file` | `credentials/<profile>.json` in the configuration directory | Linux and other Unixes (Secret Service is not implemented) |

`SENTINEL_CREDENTIAL_STORE=file|os` forces the store for a new sign-in. When the OS store fails, the credential goes to the file store with a notice on stderr, and the profile records `"store": "file"`; a profile is only ever read from the store it records. On Unix every directory Sentinel creates is `0700` and every file `0600`; a configuration directory, `profiles.json`, credentials directory or credential file that another user can reach (`mode & 0o077`) or that another user owns is refused (exit 2) with the `chmod`/`chown` that fixes it. On Windows the files inherit the per-user ACL of `%APPDATA%`. Credential files are replaced atomically and `fsync`ed (file and directory) before the rename, so a crash never loses a rotated refresh token that was reported stored.

### Refresh and the profile lock

A profile's access token is used from memory while more than 30 s of it remain. Otherwise the command takes `locks/<profile>.lock` — an OS file lock (`File::try_lock`, polled with back-off for at most 30 s, then exit 6) — re-reads the stored credential, and uses it as is when another process refreshed meanwhile; only if not does it spend the refresh token (`grant_type=refresh_token` at `{issuer}/oauth/token`) and store the successor before releasing the lock. After a `401`, `force_refresh(rejected)` does the same but reuses the stored token only if it differs from the rejected one. So concurrent commands on one machine present each refresh token once, which the server's rotation requires ([OAuth](oauth.md#refresh-and-rotation)); two machines sharing one profile's credential would trip replay detection and revoke the grant. A refused refresh (`invalid_grant`, expired sign-in) is exit 3 naming `sentinel auth login --server … --profile …`; an unreachable token endpoint is exit 6.

Tests: `crates/sentinel/tests/profile.rs` (portable, a scripted fake OAuth server on loopback, temporary `SENTINEL_CONFIG_DIR`, file store): profile round trip with no `sntl_` in `profiles.json`; Git-work-tree refusal; Unix modes and the loose/foreign refusals; eight concurrent callers on a nearly expired profile observe exactly one refresh; `force_refresh` with a stale rejected token reuses the newer one; refused and unreachable refreshes; the loopback listener's state, `iss`, repeated-parameter, denial, oversized-head, other-path and timeout cases; device polling timing under `slow_down`, denial and expiry; browser login end to end through the binary (PKCE verified by the fake); device login printing the user code but no token; grant import; issuer mismatch and foreign-origin endpoints refused; logout online, offline (exit 1) and `--all --forget`; status offline/online/mismatch/signed-out; `context use/show`; and on Windows a real Credential Manager round trip under a unique key with cleanup. Every CLI output is scanned for token material.

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
