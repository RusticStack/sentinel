# OAuth authorization server (Part 09, O01–O07)

Sentinel is its own OAuth 2.0 authorization server for its API. The CLI (`sentinel auth login`) and agents sign in through it instead of pasting long-lived `sntl_` credentials; the result is a **grant** — one refresh-token family bound to an account, a client, a scope set, an optional tenant/repository narrowing and an audience — from which short-lived access tokens are minted. Service accounts receive grants the same way (O06).

Implemented in `sentinel-core::auth` (`Scopes`, `Audience`), `sentinel-auth::oauth` (token text forms, PKCE, user codes, loopback redirects), `sentinel-protocol::oauth` (wire types), `sentinel-store::oauth` (migration 30, grants and tokens) and `sentinel-api` (`oauth/` router, bearer authentication and scope checks). The API routes it protects are in [API](api.md); the CLI side is in [CLI](cli.md).

## Issuer and metadata

The issuer is `public_url` from the server configuration ([configuration](configuration.md)), or `http://{api_listen}` without it — correct only for direct loopback use. Every endpoint is the issuer plus a fixed path:

| Path | Method | Auth | Answers |
|---|---|---|---|
| `/.well-known/oauth-authorization-server` | GET | none | RFC 8414 metadata: `issuer`, the four endpoints, `response_types_supported ["code"]`, `response_modes_supported ["query"]`, the three grant types, `code_challenge_methods_supported ["S256"]`, `token_endpoint_auth_methods_supported ["none"]`, `revocation_endpoint_auth_methods_supported ["none"]`, the ten scopes, `authorization_response_iss_parameter_supported: true` |
| `/.well-known/oauth-protected-resource/api/v1` | GET | none | RFC 9728: `resource` = `{issuer}/api/v1`, `authorization_servers [issuer]`, the scopes, `bearer_methods_supported ["header"]` |
| `/oauth/token` | POST | public client (`client_id`) | `refresh_token` grant (below); `authorization_code` (O01) and `urn:ietf:params:oauth:grant-type:device_code` (O03) |
| `/oauth/revoke` | POST | public client | RFC 7009: either token kind revokes its whole grant; always `200` |
| `/oauth/authorize` | GET, POST | session cookie | consent (O01) |
| `/oauth/device_authorization` | POST | public client | device request (O03) |
| `/device` | GET, POST | session cookie | enter and approve a user code (O03) |

Only public clients exist; there are no client secrets. Migration 30 seeds the first-party client `sentinel-cli` (loopback redirects to `/callback`, device flow allowed, every scope).

The `/oauth/*` endpoints take `application/x-www-form-urlencoded` bodies of at most 8 KiB (`MAX_OAUTH_FORM_BYTES`; larger is `413 invalid_request`); a repeated parameter is `invalid_request`, an empty value counts as absent (RFC 6749 §3.1). They answer the RFC 6749 error shape `{"error", "error_description"}` — `invalid_client` is 401, `server_error` 500, `temporarily_unavailable` 503, everything else 400 — never `sentinel.error/1`, and every answer carries `cache-control: no-store` and `pragma: no-cache`. A `resource` parameter, when present, must equal `{issuer}/api/v1` (`invalid_target`). Unauthenticated OAuth POSTs share one token bucket (20 per second, burst 40); beyond it the answer is `503 temporarily_unavailable` with `retry-after: 1`.

## Tokens, scopes and lifetimes

Every token is a 256-bit opaque secret stored only as its BLAKE3 digest, behind a kind prefix; none has the 69-character shape of a `sntl_` API credential, so each kind is refused wherever another is expected before any lookup:

| Kind | Text | Presented to | Life |
|---|---|---|---|
| access token | `sntl_at_` + 64 hex (72) | `Authorization: Bearer` on `/api/v1` | 10 min (`ACCESS_LIFETIME_MS`), capped by the grant |
| refresh token | `sntl_rt_` + 64 hex | `/oauth/token`, `/oauth/revoke` only | 30 days idle (`REFRESH_IDLE_MS`), capped by the grant; a service grant's lives as long as the grant |
| authorization code | `sntl_ac_` + 64 hex | the token endpoint, once | 60 s (`CODE_LIFETIME_MS`) |
| device code | `sntl_dc_` + 64 hex | the token endpoint, by the polling client | 10 min (`DEVICE_LIFETIME_MS`); poll interval 5 s, `slow_down` adds 5 s |
| user code | 8 of `BCDFGHJKLMNPQRSTVWXZ`, shown `XXXX-XXXX` | a person, on `/device` | the device request's |

A grant's absolute life is at most 90 days (`GRANT_MAX_MS`; browser and device logins get exactly that, service grants default to 30 days within 1 hour..90 days). The database refuses a longer one.

Scopes are stored bits (`sentinel_core::auth::Scopes`) and a ceiling on the account's permissions, never authority of their own:

| Bit | Scope | Permission ceiling |
|---|---|---|
| 1 | `runs:read` | read |
| 2 | `runs:write` | run |
| 4 | `logs:read` | read |
| 8 | `artifacts:read` | read |
| 16 | `cache:read` | read |
| 32 | `cache:write` | run |
| 64 | `secrets:metadata` | read |
| 128 | `secrets:write` | write secrets |
| 256 | `tenant:admin` | tenant admin (never for a service principal) |
| 512 | `platform:admin` | platform admin (only a super admin; dropped at authentication once demoted; a bearer never steps up) |

The CLI asks for `runs:read runs:write logs:read artifacts:read cache:read` by default (`Scopes::CLI_DEFAULT`). The audience (`Audience::Api` = 1, `{issuer}/api/v1`) is stored with every grant, code and device request; code 2 is reserved for MCP (X05).

## Access tokens on the API

`sentinel-api::auth::identify` classifies the `Authorization` header by shape (`sentinel_auth::oauth::bearer`): `sntl_` goes to `tokens::authenticate`, `sntl_at_` to `oauth::authenticate_access`, anything else — refresh tokens, codes, `gho_…`/`ghp_…`/`github_pat_…`, bare hex — is `401` without a lookup. `authenticate_access` is ONE statement: a primary-key probe on the token, the grant by its key and the account by its key; expiry, revocation, the audience, the account's live state and a service principal's home tenant are its predicates, and nothing is written per request. The effective scopes are the token's ∩ the grant's (minus `platform:admin` unless the account is still a super admin), the principal's permissions are their ceiling, and the grant's tenant/repository narrowing becomes the principal's. Every repository and tenant decision stays the live store check it is for sessions.

Every `/api/v1` route requires a scope ([API](api.md#routes)); a missing one is `403 forbidden` with `details.scope` and `WWW-Authenticate: Bearer error="insufficient_scope", scope="…"`. Every `401` carries `WWW-Authenticate: Bearer realm="sentinel", resource_metadata="{issuer}/.well-known/oauth-protected-resource/api/v1"`, plus `error="invalid_token"` when a token was presented. Sessions and `sntl_` credentials carry the scopes their permissions imply, so their authority is unchanged. `GET /api/v1/me` reports `via: "oauth"`, the `scopes`, the `grant` and the token's `expires_ms`.

## Refresh and rotation

`grant_type=refresh_token` with `client_id`, `refresh_token` and optionally `scope` (a narrowing for this access token; widening is `invalid_scope` and spends nothing). One writer transaction:

1. The presented token is looked up with its grant and account. Unknown, revoked or expired grant, inactive account or another client's token: `invalid_grant`, nothing written.
2. A live token (not rotated, not superseded, idle expiry ahead) rotates: it is marked rotated, generation `g+1` is minted with `parent = g`, and the grant's `last_used_ms` moves.
3. **Lost response.** A token rotated at most 60 s ago (`ROTATION_GRACE_MS`) whose single live successor was never used recovers once: the successor is superseded and its access token deleted, and a new successor is minted.
4. **Replay.** Any other reuse — after the grace window, after the successor was used, or of a superseded token — revokes the whole grant (reason 2), audits `OAuthRefreshReplay`, and answers `invalid_grant`.

Two machines sharing one profile will therefore revoke it; the CLI serializes refresh across processes on one machine with a lock ([CLI](cli.md)). A rotated token is kept a day (`ROTATED_RETENTION_MS`) so a replay is recognized; after that it is merely unknown.

The answer is `{access_token, token_type: "Bearer", expires_in, refresh_token, scope, sentinel_grant: "grt_…", sentinel_refresh_expires_in}` (`TokenResponse`, whose `Debug` redacts both tokens).

## Authorization code flow (O01)

Browser sign-in for public clients (RFC 6749 §4.1 with PKCE, RFC 8252 loopback redirects, RFC 9207 `iss`). Implemented in `sentinel-store::oauth::code` and `sentinel-api::oauth::code` (the page in `code/consent.rs`).

**`GET /oauth/authorize`** takes a percent-encoded query (a repeated parameter is malformed). It is checked in this order:

1. `client_id` must name an enabled client and `redirect_uri` must be one it may use: `http://127.0.0.1:PORT/callback` or `http://[::1]:PORT/callback` for the loopback CLI client (explicit port; no `localhost`, `https`, userinfo, query or fragment), or an exact registered URI. Otherwise the answer is a `400` **error page with no `location`** — an untrusted redirect is never followed.
2. From here every refusal is a `303` to `redirect_uri` with `error`, `error_description`, `iss` (the issuer) and `state` (when one was given): `response_type` must be `code` (`unsupported_response_type`); `state` is required, 1–512 bytes; `code_challenge_method` must be `S256` (`plain` and absence are refused) and `code_challenge` a 43-character S256 challenge (`invalid_request`); `scope` defaults to `CLI_DEFAULT` ∩ the client's ceiling, and an unknown scope, an empty set or one beyond the ceiling is `invalid_scope`; `resource`, when given, must be `{issuer}/api/v1` (`invalid_target`).
3. Without a browser session the page offers the embedded password sign-in (it posts to `/api/v1/login` and reloads the same URL); nothing is stored and no cookie is set by the authorize endpoint itself. Bearer credentials never drive consent.
4. `platform:admin` from an account that is not a super admin is `invalid_scope`.
5. The consent page names the client, the deployment's issuer, the signed-in account, each requested scope in plain words (a warning on `tenant:admin` and `platform:admin`) and the redirect target, and offers a tenant selector (all tenants, or one of the account's active memberships, at most 100) and an optional repository name within it.

Consent is stateless: every request parameter rides in hidden fields with a form token (`cookie::form_token`, BLAKE3 keyed by a per-process key over the session's CSRF digest). **`POST /oauth/authorize`** refuses a present `Origin` other than the issuer's origin (`403` page), a missing session (`401` page) and a missing or foreign form token (`403` page) before anything else, then re-validates every parameter exactly as `GET` does. `decision=deny` audits `OAuthConsentDenied` and redirects `error=access_denied`. `decision=approve` resolves the optional tenant and repository (a repository without a tenant, or an unknown name, re-renders the page with a notice) and calls `approve`, which re-checks every term in one statement inside the writer: the account is an active human, `platform:admin` only for a super admin, the tenant an active membership, the repository owned by it, the scopes within the client's ceiling, the redirect still allowed. A refusal there redirects `access_denied` (eligibility) or `invalid_request`. Success is `303` to `redirect_uri?code=sntl_ac_…&state=…&iss=…`. Restarting the controller invalidates open consent pages (the form key is per process).

**Codes** are 256-bit secrets stored as their digest with the client, the exact redirect URI, the challenge, the account, scopes, narrowing and audience; they live 60 s. **`grant_type=authorization_code`** at `/oauth/token` takes `client_id`, `code`, `redirect_uri` and `code_verifier` (a missing one is `invalid_request`). The code is consumed by the same statement that reads it (`UPDATE … RETURNING`), so only the first presentation can succeed; every failure after the lookup — expired, another client, another redirect URI, a wrong or malformed verifier, an account suspended since approval — still spends it. Success inserts a kind-1 grant (`LOGIN_GRANT_MS`, the code's terms; the grant trigger re-checks the account), mints generation 1, links the code to the grant and audits `OAuthGrantIssued`; the answer is the ordinary `TokenResponse`. Presenting a spent code again is a **replay**: the grant it produced is revoked (reason 3, so its access and refresh tokens stop working at once), `OAuthCodeReplay` is audited, and the answer is `invalid_grant` like every other failure. No separate client capability gates this grant: a client can only hold a code issued to a redirect it may use.

```rust
// sentinel_store::oauth::code (beyond the stub contract)
pub const MAX_CONSENT_CHOICES: u32 = 100;
pub fn consent_choices(conn: &Connection, user: UserId) -> Result<Vec<ConsentChoice>>  // active tenants, by slug
pub fn repo_named(conn: &Connection, tenant: TenantId, name: &str) -> Result<RepoId>   // NotFound
pub fn approve(store: &Store, a: &Approval<'_>, now: UnixMillis) -> Result<Secret>
    // NotFound: unknown/disabled client or account; Forbidden: eligibility; InvalidInput: scope/redirect/challenge
pub fn deny(store: &Store, client_id: &str, user: UserId) -> Result<()>               // audits OAuthConsentDenied
pub fn exchange(store, client_id, code, redirect_uri, verifier, now) -> Result<Minted, CodeError> // Invalid | Replay | Store
```

Tests: `crates/sentinel-store/tests/oauth_code.rs` (approval and exchange mint a kind-1 grant with its narrowing; expiry; replay revokes and audits; wrong verifier, redirect or client are invalid and spend the code; tenant, repository, platform, ceiling and redirect refusals; pending and suspended accounts can neither approve nor redeem; denial audited), the query-plan unit test in `sentinel-store::oauth::code`, and `crates/sentinel-api/tests/oauth_code.rs` (a ureq "browser" with a password session: sign-in page without a cookie, error pages without `location`, error redirects with `state` and `iss`, form-token/session/`Origin` refusals, tampered hidden fields re-validated, deny, approve with tenant and repository narrowing, one exchange then `invalid_grant` and a dead access token, page security headers).

## Revocation

`POST /oauth/revoke` with `client_id` and `token` (either kind; `token_type_hint` is ignored) revokes the token's grant (reason 1) and answers `200 {}` whether or not the token was known, malformed or another client's. Grants are also revoked in the same transaction as the decisions that end their authority: account suspension (`local_auth::set_active`), rejection (`registration::reject`), password change and host-local recovery (reason 4); removal of a membership revokes the grants narrowed to that tenant (reason 5); tenant suspension revokes every grant narrowed to the tenant, service grants included (reason 6, counted in `Suspension::tokens_revoked`); an owner or administrator revoking by handle is reason 7. Revocation is final: the database refuses to clear or rewrite it.

Expired and revoked rows are purged in bounded batches by the server's ten-minute maintenance tick (`oauth::purge_expired`, beside the session, API-credential and sign-in purges); nothing depends on the purge for correctness.

## Store API (`sentinel_store::oauth`)

The contract Units B and C build on. `pub(crate)` items are for the sibling modules `code.rs`, `device.rs` and `service.rs`.

```rust
// constants: ACCESS_LIFETIME_MS, REFRESH_IDLE_MS, GRANT_MAX_MS, LOGIN_GRANT_MS (= GRANT_MAX_MS),
// CODE_LIFETIME_MS, DEVICE_LIFETIME_MS, DEVICE_INTERVAL_MS, SLOW_DOWN_STEP_MS, ROTATION_GRACE_MS,
// SERVICE_DEFAULT_MS, SERVICE_MIN_MS, SERVICE_MAX_MS, MAX_PENDING_DEVICE: usize, ROTATED_RETENTION_MS
pub mod reason { LOGOUT = 1, REFRESH_REPLAY = 2, CODE_REPLAY = 3, ACCOUNT = 4, MEMBERSHIP = 5, TENANT = 6, ADMIN = 7 } // u8 consts
#[repr(u8)] pub enum GrantKind { Code = 1, Device = 2, Service = 3 }   // from_code, as_str
pub struct Client { pub id: String, pub name: String, pub first_party: bool, pub loopback: bool,
                    pub redirect_path: Option<String>, pub device: bool, pub max_scopes: Scopes }
pub struct ClientSpec<'a> { pub id: &'a str, pub name: &'a str, pub first_party: bool, pub loopback: bool,
                            pub redirect_path: Option<&'a str>, pub device: bool, pub max_scopes: Scopes }
pub fn client(conn: &Connection, client_id: &str) -> Result<Client>                 // NotFound: unknown/disabled
pub fn redirect_allowed(conn: &Connection, client: &Client, uri: &str) -> Result<bool> // loopback rule or exact row
pub fn register_client(store: &Store, spec: &ClientSpec<'_>, redirects: &[&str]) -> Result<()> // trusted
pub struct NewGrant<'a> { pub user: UserId, pub client_id: &'a str, pub kind: GrantKind, pub scopes: Scopes,
  pub tenant: Option<TenantId>, pub repo: Option<RepoId>, pub audience: Audience,
  pub name: Option<&'a str>, pub lifetime_ms: i64, pub created_by: Option<UserId> }   // Clone + Copy
pub(crate) fn insert_grant(tx: &Transaction<'_>, g: &NewGrant<'_>, now: UnixMillis) -> Result<GrantId>
    // validates shape (InvalidInput), the insert trigger refuses ineligible terms as Forbidden; does NOT audit
#[derive(Debug)] pub struct Minted { pub grant: GrantId, pub access: Secret, pub access_expires: UnixMillis,
  pub refresh: Secret, pub refresh_expires: UnixMillis, pub scopes: Scopes }
pub(crate) fn mint(tx: &Transaction<'_>, grant: GrantId, scopes: Scopes, now: UnixMillis) -> Result<Minted>
    // generation 1; NotFound if the grant is revoked/expired; InvalidInput("scope") unless ∅ ≠ scopes ⊆ grant
pub struct Authenticated { pub grant: GrantId, pub principal: Principal, pub scopes: Scopes, pub expires: UnixMillis }
pub fn authenticate_access(conn: &Connection, presented: &Secret, audience: Audience, now: UnixMillis) -> Result<Authenticated>
#[derive(Debug)] pub enum RefreshError { Invalid, Replay, InvalidScope, Store(Error) }
pub fn refresh(store: &Store, client_id: &str, presented: &Secret, narrow: Option<Scopes>, now: UnixMillis)
    -> std::result::Result<Minted, RefreshError>
pub fn revoke_presented(store: &Store, client_id: &str, token_text: &str, now: UnixMillis) -> Result<()> // unknown => Ok
pub(crate) fn revoke_row(tx: &Transaction<'_>, grant: GrantId, reason: u8, now: UnixMillis) -> Result<bool> // was live
pub fn revoke_grant(tx: &Transaction<'_>, authority: Authority, grant: GrantId, now: UnixMillis) -> Result<()>
    // owner, platform admin, or (service principal's grant) its home tenant's admin; else NotFound; reason 7; audited
pub fn revoke_all_for_user(tx: &Transaction<'_>, user: UserId, reason: u8, now: UnixMillis) -> Result<usize>
pub(crate) fn revoke_for_tenant(tx: &Transaction<'_>, tenant: TenantId, now: UnixMillis) -> Result<usize>
pub(crate) fn revoke_for_membership(tx: &Transaction<'_>, user: UserId, tenant: TenantId, now: UnixMillis) -> Result<usize>
#[derive(Clone, Debug, PartialEq, Eq)] pub struct GrantRecord { pub id: GrantId, pub user: UserId, pub client_id: String,
  pub kind: GrantKind, pub scopes: Scopes, pub tenant: Option<TenantId>, pub repo: Option<RepoId>,
  pub name: Option<String>, pub created: UnixMillis, pub expires: UnixMillis,
  pub last_used: Option<UnixMillis>, pub revoked: bool }
pub(crate) const GRANT_COLUMNS: &str;  pub(crate) fn raw_grant(&Row) -> rusqlite::Result<RawGrant>;
pub(crate) fn grant_record(RawGrant) -> Result<GrantRecord>   // SELECT {GRANT_COLUMNS} FROM oauth_grants … → GrantRecord
pub fn grants(conn: &Connection, authority: Authority, user: UserId, limit: u16) -> Result<Vec<GrantRecord>> // self or platform; 1..=100
pub fn issue_grant_trusted(store: &Store, g: NewGrant<'_>, now: UnixMillis) -> Result<Minted> // tests / host-local; audits OAuthGrantIssued
pub fn purge_expired(store: &Store, now: UnixMillis, limit: u32) -> Result<usize>
// also: sentinel_store::local_auth::username_of(conn, user) -> Result<Option<String>>
// audit: crate::local_auth::audit(tx, Event::…, actor, subject, host_local, detail) — events 48–55
```

Stub signatures the owning units implement (bodies currently `Err(Error::InvalidInput("not implemented"))`):

```rust
// oauth/code.rs (B)
pub struct ConsentChoice { pub tenant: TenantId, pub slug: String, pub role: Role }
pub fn consent_choices(conn: &Connection, user: UserId) -> Result<Vec<ConsentChoice>>
pub struct Approval<'a> { pub client_id: &'a str, pub redirect_uri: &'a str, pub code_challenge: &'a str,
  pub user: UserId, pub scopes: Scopes, pub tenant: Option<TenantId>, pub repo: Option<RepoId>, pub audience: Audience }
pub fn approve(store: &Store, a: &Approval<'_>, now: UnixMillis) -> Result<Secret>
#[derive(Debug)] pub enum CodeError { Invalid, Replay, Store(Error) }
pub fn exchange(store: &Store, client_id: &str, code: &Secret, redirect_uri: &str, verifier: &str, now: UnixMillis)
  -> std::result::Result<Minted, CodeError>
// oauth/device.rs (C)
#[derive(Debug)] pub struct DeviceStart { pub device: Secret, pub user_code: String, pub expires: UnixMillis, pub interval_ms: i64 }
pub fn begin(store: &Store, client_id: &str, scopes: Scopes, audience: Audience, now: UnixMillis) -> Result<DeviceStart>
pub struct DeviceView { pub client_name: String, pub scopes: Scopes, pub expires: UnixMillis }
pub fn view(conn: &Connection, user_code: &str, now: UnixMillis) -> Result<DeviceView>
#[derive(Clone, Copy, Debug)] pub enum Decision { Approve { scopes: Scopes, tenant: Option<TenantId>, repo: Option<RepoId> }, Deny }
pub fn decide(store: &Store, user_code: &str, user: UserId, d: Decision, now: UnixMillis) -> Result<()>
#[derive(Debug)] pub enum Poll { Pending, Denied, Expired, Issued(Minted) }
pub fn poll(store: &Store, client_id: &str, device: &Secret, now: UnixMillis) -> Result<Poll>
// oauth/service.rs (C)
pub fn issue_service_grant(tx: &Transaction<'_>, principal: Principal, tenant: TenantId, account: UserId, name: &str,
  scopes: Scopes, repo: Option<RepoId>, lifetime_ms: i64, now: UnixMillis) -> Result<(GrantId, Secret, UnixMillis)>
pub fn service_grants(conn: &Connection, principal: Principal, tenant: TenantId, account: UserId) -> Result<Vec<GrantRecord>>
```

Migration 30 details the flows rely on: `oauth_device_codes.status` moves only 0→1|2 and 1→3, the approver may narrow `scopes` once in the 0→1 update, and `user_id`/`tenant_id`/`repo_id`/`decided_ms` are written once; `oauth_codes.consumed_ms` and `grant_id` are set once; the partial index `oauth_device_pending(expires_ms) WHERE status = 0` serves the pending cap; `oauth_codes_by_grant` and `oauth_device_by_grant` index the grant links.

## Device authorization (O03)

_Placeholder: Unit C documents `/oauth/device_authorization`, polling and `/device` here._

## HTTP plumbing (`sentinel-api`, crate-private)

`routes::route` first calls `oauth::route(state, request, method, &parts, query) -> Option<Route>`, which owns `/.well-known/*`, `/oauth/*`, `/device`, `/api/v1/grants*` and `/api/v1/tenants/{slug}/service-accounts*`. `routes::Reply` is `pub(crate)` with `Json(u16, Value, Vec<Header>)`, `Stream(…)` and `Html(u16, String, Vec<Header>)`; every `Html` reply is sent with `content-type: text/html; charset=utf-8` and `html::SECURITY_HEADERS` (`content-security-policy: default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'` — deliberately no `form-action` — `x-frame-options: DENY`, `referrer-policy: no-referrer`, `cache-control: no-store`). `pub(crate) type Route = Result<Reply, ApiError>`.

Helpers for the flows:

```rust
// routes.rs (pub(crate)): header(name, value) -> Header; ok(Value) -> Route; err(ErrorCode, msg) -> ApiError;
//   store_error(StoreError) -> ApiError; header_value(&Request, &'static str) -> Option<&str>;
//   body(&mut Request) / body_limit(&mut Request, usize) -> Result<Vec<u8>, ApiError>; parse::<T>(&[u8]);
//   query_param(query, name) (NOT percent-decoded; use form_urlencoded::parse for OAuth queries);
//   identify(state, &Request, mutation) -> Result<Identity, ApiError>; id::<T>(text, what)
// auth.rs: Identity { principal, user, super_admin, via: Via::{Bearer, Session, OAuth}, csrf, scopes: Scopes,
//   grant: Option<GrantId>, expires: Option<UnixMillis> }; require_scope(&Identity, Scopes) -> Result<(), ApiError>
// oauth/mod.rs:
pub(crate) struct OAuthState { pub issuer: String, pub origin: String /* scheme://host[:port] of the issuer */,
  pub api_resource: String /* {issuer}/api/v1 */, pub form_key: [u8; 32],
  pub unauth: Mutex<TokenBucket>, pub device_polls: Mutex<HashMap<[u8; 32], (Instant, u32)>>,
  pub user_code_failures: Mutex<HashMap<UserId, (u8, Instant)>> }   // State.oauth; State.subscribers: AtomicUsize
pub(crate) struct Form;  Form::parse(&[u8]) -> Result<Form, OAuthError>;  form.get(name) -> Option<&str>
pub(crate) fn read_form(&mut Request) -> Result<Form, Reply>     // content type, 8 KiB bound, duplicates
pub(crate) fn error(OAuthErrorCode, &str) -> Reply;  error_status(u16, OAuthErrorCode, &str) -> Reply
pub(crate) fn store_failure(sentinel_store::Error) -> Reply      // busy -> temporarily_unavailable, else server_error
pub(crate) fn token_reply(&Minted, now: UnixMillis) -> Reply     // TokenResponse + no-cache headers
pub(crate) fn admit(state) -> Result<(), Reply>                  // the shared unauthenticated bucket
pub(crate) fn session(state, &Request) -> Option<Identity>       // a session cookie identity, never a bearer
// oauth/html.rs: SECURITY_HEADERS; escape_into(&mut String, &str); escape(&str) -> String;
//   document(title, body) -> String; page(status, title, body) -> Reply; error_page(status, message) -> Reply;
//   redirect(location) -> Reply /* 303, empty body */; SIGN_IN: &str; sign_in_page(title, message) -> Reply
// stubs the router calls (bodies answer "not available yet"):
// code.rs:    pub(crate) fn authorize(state: &State, request: &mut Request, method: &str, query: &str) -> Route
//             pub(crate) fn token(state: &State, client: &Client, form: &Form) -> Reply
// device.rs:  pub(crate) fn authorization(state: &State, request: &mut Request) -> Route
//             pub(crate) fn page(state: &State, request: &mut Request, method: &str, query: &str) -> Route
//             pub(crate) fn token(state: &State, client: &Client, form: &Form) -> Reply
// service.rs: pub(crate) fn grants(state: &State, request: &mut Request, method: &str, rest: &[&str]) -> Route
//             pub(crate) fn accounts(state: &State, request: &mut Request, method: &str, slug: &str,
//                                    rest: &[&str], query: &str) -> Route
```

The token endpoint has already checked `grant_type`, `client_id` (unknown is `invalid_client`), `resource` and the rate limit before `code::token`/`device::token` run; those check the client's own capability (`unauthorized_client`). `sentinel_auth::cookie::{form_key, form_token, form_token_accepted}` key consent and device forms to the session's CSRF digest.

## Service-account grants (O06)

_Placeholder: Unit C documents service accounts, their grants and `sentinel service-account` here._

## Tests and harness

`crates/sentinel-store/tests/oauth_tokens.rs` (store), `crates/sentinel-api/tests/oauth_core.rs` (HTTP) and the unit tests in `sentinel-core::auth`, `sentinel-auth::oauth`/`cookie`, `sentinel-protocol::oauth` and `sentinel-store::oauth` (query plans). `oauth_core.rs` holds the harness the other OAuth suites copy: `deployment()` (a bootstrapped super admin `root` with password `PASSWORD` administering tenant `acme` with repository `app`, an operator `dev` with read and run on it, an `sntl_` credential for root, a real server on `127.0.0.1:0` whose issuer is its base URL), `send(d, method, path, Body::{None, Json, Form}, headers) -> Reply { status, headers, body }` (redirects are returned, not followed), `get`, `grant(d, user, scopes) -> Minted` (`issue_grant_trusted`) and `bearer(&access)`.
