# API, CLI and the first page (W08)

Implemented in `crates/sentinel-api` (HTTP/1.1 on the crate's own bounded acceptor — 64 connections, 8 handler permits of which at most 3 go to transfer bodies and at most 3 to parked long polls, so 2 always serve everything else; deadline-bounded heads/bodies/writes), `sentinel api …` (the CLI client in `crates/sentinel`), and one static page the server serves at `/`. `sentinel server` opens the API on `api_listen` (default `127.0.0.1:7080`) beside the worker link.

## One surface

Everything a person, the CLI, the page or later an agent does goes through the same routes, authenticated the same way and authorized by the same store predicates. The page is not a second path into the controller: it is HTML that calls `/api/v1/…` with a session cookie.

Plain HTTP on loopback by default; TLS and exposure are a reverse proxy's job. The session cookie is `__Host-sentinel_session` (Secure, HttpOnly, SameSite=Strict), which a browser accepts from `localhost` or over HTTPS only — deliberately.

## Authentication and authorization

| Credential | How | Mutations |
|---|---|---|
| `Authorization: Bearer sntl_…` ([API credentials](api-credentials.md)) | `tokens::authenticate`: one digest lookup; scope is a ceiling on the account's live membership | allowed; no CSRF (nothing sends a bearer ambiently) |
| session cookie ([local authentication](local-authentication.md)) | `local_auth::authenticate` | require the `x-sentinel-csrf` header with the session's CSRF secret, else `forbidden` |
| `Authorization: Bearer sntl_at_…` ([OAuth](oauth.md)) | `oauth::authenticate_access`: one statement (token, grant and account by key); the grant's scopes are the ceiling | allowed; no CSRF |

The credential yields a `Principal`; every route then asks the store — `auth::require_repo` for anything under a run, `auth::list_repos`, `tenancy::pools_for_tenant` and `workers::in_pool` under an `Authority` — so a resource the caller may not see is `not_found`, never revealed. A bearer credential can never step up. Every route also requires the **scope** in its row below: an OAuth access token carries exactly its grant's scopes, while a session or `sntl_` credential carries the scopes its permissions imply (`read` → every `:read` scope and `secrets:metadata`, `run` → `runs:write` and `cache:write`, the administrative bits one to one), so their authority is unchanged. A missing scope is `403 forbidden` with `details.scope` and `WWW-Authenticate: Bearer error="insufficient_scope", scope="…"`; every `401` from `/api/v1` carries `WWW-Authenticate: Bearer realm="sentinel", resource_metadata="…"` naming the RFC 9728 location of `{issuer}/api/v1` ([OAuth](oauth.md#access-tokens-on-the-api)), plus `error="invalid_token"` when a token was presented (the login and hook routes excepted). A credential the store is too busy to check is `rate_limited` (`429`, `details.retry_after_ms`), never `401`, so a client does not take overload for a dead credential. A session's idle deadline slides (one write per session per five minutes) as it is used.

## Routes

All under `/api/v1`, JSON in and out, errors as `sentinel.error/1` ([protocol](protocol.md)); bodies bounded at 1 MiB before they are read, with the intake routes bounding their own bodies ([intake](intake.md)).

| Route | Auth | Scope | Does |
|---|---|---|---|
| `GET /health` | none | — | `{ok:true}` |
| `POST /login` `{username,password}` | none | — | password login → `Set-Cookie` session (`Max-Age` is the session's absolute life; the idle deadline is enforced and slid by the server), body `{user, csrf}`; every non-accepted outcome is one `unauthenticated`. Against login CSRF the body must be `content-type: application/json` (else `invalid_request`) and a present `Origin` must be the issuer's origin (else `forbidden`) |
| `POST /logout` | session + CSRF | — | ends the session, clears the cookie |
| `GET /me` | any | — | who the credential is and how: `user`, `username` (local login name or `null`), `via` (`bearer`, `session`, `oauth`), `super_admin`, `tenant`/`repo` narrowing, `scopes` (names), and for an OAuth token its `grant` and `expires_ms` |
| `GET /grants` | any | — | the caller's own OAuth grants as metadata (`{grants:[{id, user, client_id, kind, scope, tenant, repo, name, created_ms, expires_ms, last_used_ms, revoked}]}`, newest first, at most 100); never a token ([OAuth](oauth.md#service-account-grants-o06)) |
| `DELETE /grants/{grt}` | owner, the home tenant's admin for a service grant, or platform admin | — | revoke the grant (reason 7, audited) → `{grant, revoked:true}`; anyone else `not_found`; its access tokens are then `401` and refresh tokens `invalid_grant` |
| `POST /tenants/{slug}/service-accounts` `{name, role?}` | tenant admin | `tenant:admin` | create a service principal confined to the tenant (role `reader` or `operator`, default operator) → `201 {user, name, role}`; audited `ServiceAccountCreated` |
| `PUT /tenants/{slug}/service-accounts/{usr}/repos/{name}` `{access:["read","run"]}` | tenant admin | `tenant:admin` | set the account's access to one repository of the tenant (`[]` withdraws) → `{user, repo, access}` |
| `POST /tenants/{slug}/service-accounts/{usr}/grants` `{name, scope, repo?, expires_in_ms?}` | tenant admin | `tenant:admin` | issue a service grant (1 h..90 d, default 30 d; never `tenant:admin`/`platform:admin`) → `201 {grant, refresh_token, expires_ms, scope}`; the `sntl_rt_` token is shown this once |
| `GET /tenants/{slug}/service-accounts/{usr}/grants` | tenant admin | `tenant:admin` | the account's grants as metadata; a revoked grant stays listed until the next maintenance purge (about ten minutes) |
| `POST /hooks/github` | App webhook signature | — | GitHub webhooks ([intake](intake.md)): raw-body HMAC-SHA256, delivery dedup, `push` and `pull_request` intake, `ping` probe. `not_found` until `<data_dir>/github-webhook.json` exists |
| `POST /intake/{repo}` | repository hook secret | — | generic ref updates ([intake](intake.md)): bounded JSON, dedup, durable acceptance → `202` with the delivery id |
| `GET /tenants/{slug}/repos` | member | `runs:read` | repositories visible to the caller; a tenant the caller has no part in is `not_found`, exactly like one that does not exist |
| `GET /tenants/{slug}/repos/{name}/runs?limit&before` | `read` | `runs:read` | newest runs first, a keyset page over `(created_ms, id)` (`limit` default 100, max 500): `before=run_…` continues after that run of the same repository (another repository's run is `not_found`), and `next` is the cursor for the following page — `null` on the last one, so no empty follow-up request is needed. Pages stay stable when runs share a millisecond or new runs arrive meanwhile |
| `POST /tenants/{slug}/repos/{name}/runs` `{pipeline, source:{repo,sha,ref}}` | `run` | `runs:write` | compile, pin, create the run and its jobs, resolve every digest-pinned image, record manual provenance, wake the dispatcher → `201` run status. `Idempotency-Key` replays the same run (`200`) and refuses a different body (`idempotency_mismatch`). A write the controller stopped waiting for is `503 outcome_unknown` (not retryable as is: the run may still be created); repeat it only with the same key, or list runs first. Every image must be pinned by digest until a resolver exists |
| `GET /runs/{id}` | `read` | `runs:read` | the run and its jobs: state, failure class, trigger (`push`, `tag`, `pull_request`, `manual`), cancel flag, newest attempt, `log_state` (`pending`/`incomplete`/`complete` of that attempt's durable log end, `null` until an attempt exists), fence, phase timestamps |
| `GET /runs/{id}/wait?since&timeout_ms` | `read` | `runs:read` | long poll for a change (O05) → `{version, changed, finished, run}` with `run` the same document as `GET /runs/{id}`. `version` is 16 hex digits (64-bit FNV-1a over the run's cancel flag and each job's id, state, fence, cancel flag and newest attempt's log state). Answers at once without `since`, when `since` differs, or when every job is terminal; otherwise parks on the store's commit notifier — re-reading only the version, at most every 10 ms — until something visible changes or `timeout_ms` (1–25000, default 25000) passes (`changed:false`). At most three subscribers (run waits and `logs?wait=1` together) park at once; beyond that the poll is `rate_limited` with `details.retry_after_ms` |
| `POST /runs/{id}/cancel` | `run` | `runs:write` | `cancel_run` ([cancellation](cancellation.md)) |
| `POST /jobs/{id}/cancel` | `run` | `runs:write` | `cancel` → `terminal`, `requested` or `alreadyterminal` |
| `POST /jobs/{id}/rerun` | `run` | `runs:write` | a new attempt of a finished job; `conflict` for a running or cancelled one |
| `GET /attempts/{id}/logs?after\|cursor&limit&wait=1&step` | `read` | `logs:read` | frames after a position from the segmented store the controller writes ([logs](logs.md)) → `{attempt, frames:[{seq, step, stream, text}], complete, gaps, next_after, next}`. The position is `after` (a sequence number) or `cursor` (the versioned `c1` cursor of [protocol](protocol.md#event-sequences-and-cursors), bound to the tenant and the attempt — the answer's `next`); not both. A malformed `after`, `limit` or `step` is `invalid_request`; a malformed, foreign-tenant or other-attempt cursor is `invalid_cursor`. A page holds at most `limit` frames (default 100, max 500) and 1 MiB of frame payload, and decodes at most 16 MiB past the position; a page cut by any bound carries `next_after` (continue from it — `next` is the same position as a cursor), `null` when the page reached the end of what is stored. `step` serves one step only; `wait=1` parks up to 25 s for more — on the log store's append notifier, re-reading only when this attempt's log grew — holding one of the three subscriber slots it shares with run waits (beyond them a parked poll is `rate_limited` with `details.retry_after_ms`); a poll with frames to return, a complete log or a finished step never parks; `complete` and `gaps` say when the log is closed (a live log's gaps include the holes stored so far); pre-D04 flat logs still read |
| `GET /attempts/{id}/logs/search?q&after&limit&carry` | `read` | `logs:read` | bounded literal search (O05): `q` is 1–256 bytes, percent-decoded (`+` is a space), matched byte for byte with `memmem`, one report per line. A string split across consecutive frames of the same step and stream is found too, once, and reported with the frame it ends in — whatever lies between the pieces: other frames, a sealed log segment, or the cut between two requests (the scan keeps each stream's open line as its last `len(q) − 1` bytes). Frames past `after` are scanned in stored order, at most 4 MiB of payload (a frame that would pass it waits for the next request) and `limit` matching lines (default 100, max 500; checked between frames) per request → `{attempt, matches:[{seq, step, stream, text}], next_after, next_carry, complete}`; `text` is the matching line, at most 512 bytes around the match (from the match itself when it began in an earlier frame). When a bound stopped the request, `next_after` and `next_carry` (opaque hex, at most 1,066 characters) are where it resumes: pass them back as `after` and `carry` with the same `q`. A `carry` for another `after` or `q` length, or malformed, is `invalid_request`. Without `carry` the state is rebuilt from the segment holding `after` (the sealed one when `after` ends it), so a line begun before that segment can be missed or repeated — older clients only. `complete` means the log is finished and was scanned to its end |
| `GET /attempts/{id}/summary` | `read` | `cache:read` | the attempt's cache records (K08) from its terminal summary → `{attempt, present:true, image_present, caches:[{name, class, outcome, lookup_ns, lock_wait_ns, clone_ns, first_touch_ns, files, bytes, copied_bytes, reflink, commit_ns, staged_bytes, reused_bytes, dirty_bytes, publish, costly_hit}]}`, or `{attempt, present:false}` before the attempt reported |
| `GET /runs/{id}/artifacts` | `read` | `artifacts:read` | `{tenant, artifacts}`: the owning tenant's slug (for the objects route) and every artifact row of the run: name, job, attempt, `captured`/`absent`/`failed`, entries, bytes, retention and creation ([storage](storage.md#artifact-records-d03)) |
| `GET /runs/{id}/artifacts/{arf}` | `read` | `artifacts:read` | one row with the owning `tenant` slug plus, when captured, its immutable manifest: version, digest, payload length and each entry's path/digest/len/mode; entry bytes download via `GET /tenants/{slug}/objects/{digest}` |
| `GET /workers?tenant=slug` | member | `runs:read` | the pools the tenant may use and their workers, each with `connected` from the live fleet and, for a connected protocol-7 worker, `transport` (Q07): `path` (`unknown`, `direct` or `relay`), `reconnects`, `bytes_in`, `bytes_out`, and `rtt_ns` and `helper_version` only when measured — never an address or a key |
| `GET /queue?tenant=slug&limit` | member | `runs:read` | the tenant's waiting jobs, oldest first, each with its `run`, `repo`, `age_ms` and the `reason` it is not running: `dependency`, `policy` (with its detail), `no_matching_worker` (with `cpu_short`/`memory_short`), `worker_offline`, `capacity`, and the fleet constraints `disk_short`, `arch_mismatch`, `label_missing`, `drain`, `concurrency_limit`, `fairness_hold` and `locality_wait`, and `ready` (nothing holds it and a connected worker has the room now; the next dispatch pass places it unless older work takes that room first). Bounded to `limit` (default 100, max 500): the limit is applied in the store query and only the returned jobs are explained, `total` is the number of the tenant's waiting jobs (an index count) and `truncated` marks `total` exceeding the page, so a ten-thousand-job queue is neither a ten-thousand-job document nor ten thousand explanations |
| `POST /workers/{wrk}/drain` | platform admin | `platform:admin` | the worker keeps the attempts it already holds and takes no new offers → `{worker, draining:true}`; work it could have taken stays queued with reason `drain` |
| `POST /workers/{wrk}/undrain` | platform admin | `platform:admin` | the worker is offered work again → `{worker, draining:false}` |
| `POST /tenants/{slug}/uploads` `{len, digest?, ttl_ms?}` | member (operator+) | `runs:write` | open a resumable upload session → `201` `{upload, received, ranges, expires_ms}` ([storage](storage.md#resumable-uploads-reads-and-materialization-d02)); `len` is at most 4 GiB (`invalid_request` beyond); `quota_exceeded` when the tenant's budget cannot take the declared length, `storage_full` below the disk watermarks |
| `GET /uploads/{upl}` | member (operator+) | `runs:write` | the durable resume state: held byte ranges and expiry |
| `PUT /uploads/{upl}?offset=N` | member (operator+) | `runs:write` | one chunk, raw body ≤ 8 MiB; re-sent ranges merge, so retries are safe. A chunk (or commit) for a session past its expiry retires the session durably and answers `invalid_request` |
| `POST /uploads/{upl}/commit` | member (operator+) | `runs:write` | tile check + digest verification → publish the object → `{digest}`; repeating returns the same digest |
| `DELETE /uploads/{upl}` | member (operator+) | `runs:write` | abort and drop the staged bytes |
| `GET /tenants/{slug}/objects/{digest}` | `read` on a repository with an artifact referencing the digest, or member (operator+) with `RUN` for an uploaded object | `artifacts:read` | stream a committed object; `Range: bytes=a-b`/`a-`/`-n` → `206` with `Content-Range`; invalid ranges are `invalid_request`. Anyone else — a reader without a grant on the referencing repositories, a platform admin who is no member — gets the same `not_found` as for an unknown digest. A whole-object body is rehashed while it streams and ends short of its `content-length` (the connection closes) if the stored bytes no longer match the digest; range reads are not verified. At most three transfer bodies are in flight at once, counted until the body is written — the next is `rate_limited` |

The OAuth authorization server's endpoints are at the deployment's root, not under `/api/v1`, and answer the RFC 6749 error shape `{error, error_description}` instead of `sentinel.error/1` ([OAuth](oauth.md)):

| Route | Auth | Does |
|---|---|---|
| `GET /.well-known/oauth-authorization-server` | none | RFC 8414 metadata: the issuer, the endpoints below, grant types, `S256`, the scopes |
| `GET /.well-known/oauth-protected-resource/api/v1` | none | RFC 9728: `resource` `{issuer}/api/v1`, its authorization server and scopes |
| `GET, POST /oauth/authorize` | session cookie (else the embedded password sign-in) | authorization code + PKCE consent (O01); approve or deny → `303` to the loopback redirect with `code`/`error`, `state`, `iss` |
| `POST /oauth/token` | public client (`client_id`) | `authorization_code`, `refresh_token` (rotation with a 60 s lost-response grace, replay revokes the grant) and `urn:ietf:params:oauth:grant-type:device_code` grants → `TokenResponse`; `cache-control: no-store` |
| `POST /oauth/revoke` | public client | RFC 7009: either token kind revokes its whole grant; always `200` |
| `POST /oauth/device_authorization` | public client | RFC 8628 device request → `{device_code, user_code, verification_uri, verification_uri_complete, expires_in, interval}`; `429 slow_down` at 1024 pending |
| `GET, POST /device` | session cookie (else the embedded password sign-in) | enter a user code, then approve (narrowing scopes, tenant, repository) or deny; five wrong codes in ten minutes lock the account out of the page for the rest of the window |

The first page (`GET /`) is a single static document; it accepts a
`#/runs/<run id>` fragment and opens that run, which is what a check's
`details_url` points at ([checks](checks.md)). Signing in with a fragment
present opens the run immediately afterwards.

## The CLI

```sh
export SENTINEL_SERVER=http://127.0.0.1:7080
sentinel api --token-file ~/.sentinel/token me
sentinel api --token-file ~/.sentinel/token run --tenant acme --repo app \
    --pipeline .sentinel.yml --source https://github.com/acme/app.git --sha <full sha> --ref main --idempotency-key push-1
sentinel api --token-file ~/.sentinel/token status run_…
sentinel api --token-file ~/.sentinel/token logs att_… --follow
sentinel api --token-file ~/.sentinel/token cancel --run run_…
sentinel api --token-file ~/.sentinel/token rerun job_…
sentinel api --token-file ~/.sentinel/token workers --tenant acme --json
sentinel api --token-file ~/.sentinel/token queue --tenant acme --limit 50
sentinel api --token-file ~/.sentinel/token drain wrk_…
sentinel api --token-file ~/.sentinel/token undrain wrk_…
```

`--json` prints the server's document, and a failure as one `sentinel.error/1` line on stderr; text output is for people. `--token-file`/`--token`/`SENTINEL_TOKEN` accept an `sntl_` credential or an `sntl_at_` access token. Exit codes are the shared table in [CLI](cli.md#exit-codes): 0 success, 1 remote fault or malformed answer, 2 usage, 3 `unauthenticated`/`forbidden`, 4 `not_found`, 5 `conflict`/`idempotency_mismatch`, 6 busy or unreachable after retries. `--token-file` keeps the secret out of the process list; `--token` and `SENTINEL_TOKEN` exist for tooling that already protects its environment.

Draining needs a platform-admin credential on the API; on the controller's own host the same change is `sentinel admin worker drain --id wrk_… --data-dir …` (and `undrain`), which acts on the store directly like the rest of `sentinel admin`.

## The page

`GET /` serves one document: sign in (password login through `/login`), list a repository's runs, open a run's jobs with cancel and rerun, follow an attempt's log. It stores the CSRF secret the login returned and sends it on every mutation. Its requests are relative to the path it was served at, so it also works mounted under a path-carrying `public_url`. No framework, no build step, no request the CLI could not make.

## What is not here yet

GitHub Checks (G03–G06) are the other way runs *finish* externally; webhook
intake and the resolution lane exist ([intake](intake.md)), while the
policy-selected pipeline resolution and run creation are G03. MCP is the
M-tasks over these same routes. TLS in the server itself is deliberately
absent. The run list pages with a `before` keyset cursor (O05); the
attempt log route issues and accepts the protocol's versioned `c1` cursors. Step-up over the API (second
factor for privileged mutations) arrives with the routes that need it.

## Verification

`crates/sentinel-api/tests/api.rs`, over loopback HTTP against a controller and a store: no credential and a wrong credential are `unauthenticated` with the error schema; an unknown route is `not_found`; the page is served without a credential; an unpinned image and a malformed pipeline are `invalid_request` without echoing the input; dispatch returns the run with its jobs (`queued`, `blocked`), replays under the same idempotency key and refuses a different body; the repository's run list and the run are readable, a random run and a malformed id are refused, a credential narrowed to another tenant sees nothing; cancelling a queued job is `terminal` and marks it `canceled`, rerunning a cancelled job is `conflict`, cancelling the run ends it; an attempt's log is `not_found` before any frame, tails by sequence with stream and step, a `wait=1` request returns as soon as a frame lands and reports completion; worker status lists the tenant's pool. A password login sets a `__Host-` HttpOnly cookie and returns the CSRF secret; the cookie alone reads, a mutation without the header is `forbidden`, with it dispatch succeeds; logout kills the session.

`crates/sentinel-api/tests/oauth_core.rs` covers OAuth access tokens on these routes, per-route scopes and the `WWW-Authenticate` challenges ([OAuth](oauth.md#tests-and-harness)).

`crates/sentinel/tests/cli.rs` (Linux, both role features), against the real `sentinel server` with its `api_listening` address and a credential issued by `admin token issue`: a bad token file exits 2; `api me` shows the bearer identity; `api run` for a repository the account is not a member of exits 4 with `not_found`; `api workers --json` lists the pool with the enrolled worker `connected`.
