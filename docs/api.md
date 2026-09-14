# API, CLI and the first page (W08)

Implemented in `crates/sentinel-api` (HTTP/1.1 on a bounded thread pool, `tiny_http`), `sentinel api …` (the CLI client in `crates/sentinel`), and one static page the server serves at `/`. `sentinel server` opens the API on `api_listen` (default `127.0.0.1:7080`) beside the worker link.

## One surface

Everything a person, the CLI, the page or later an agent does goes through the same routes, authenticated the same way and authorized by the same store predicates. The page is not a second path into the controller: it is HTML that calls `/api/v1/…` with a session cookie.

Plain HTTP on loopback by default; TLS and exposure are a reverse proxy's job. The session cookie is `__Host-sentinel_session` (Secure, HttpOnly, SameSite=Strict), which a browser accepts from `localhost` or over HTTPS only — deliberately.

## Authentication and authorization

| Credential | How | Mutations |
|---|---|---|
| `Authorization: Bearer sntl_…` ([API credentials](api-credentials.md)) | `tokens::authenticate`: one digest lookup; scope is a ceiling on the account's live membership | allowed; no CSRF (nothing sends a bearer ambiently) |
| session cookie ([local authentication](local-authentication.md)) | `local_auth::authenticate` | require the `x-sentinel-csrf` header with the session's CSRF secret, else `forbidden` |

The credential yields a `Principal`; every route then asks the store — `auth::require_repo` for anything under a run, `auth::list_repos`, `tenancy::pools_for_tenant` and `workers::in_pool` under an `Authority` — so a resource the caller may not see is `not_found`, never revealed. A bearer credential can never step up.

## Routes

All under `/api/v1`, JSON in and out, errors as `sentinel.error/1` ([protocol](protocol.md)); bodies bounded at 1 MiB before they are read.

| Route | Auth | Does |
|---|---|---|
| `GET /health` | none | `{ok:true}` |
| `POST /login` `{username,password}` | none | password login → `Set-Cookie` session, body `{user, csrf}`; every non-accepted outcome is one `unauthenticated` |
| `POST /logout` | session + CSRF | ends the session, clears the cookie |
| `GET /me` | any | who the credential is and how |
| `GET /tenants/{slug}/repos` | member | repositories visible to the caller |
| `GET /tenants/{slug}/repos/{name}/runs?limit` | `read` | newest runs first |
| `POST /tenants/{slug}/repos/{name}/runs` `{pipeline, source:{repo,sha,ref}}` | `run` | compile, pin, create the run and its jobs, resolve every digest-pinned image, wake the dispatcher → `201` run status. `Idempotency-Key` replays the same run (`200`) and refuses a different body (`idempotency_mismatch`). Every image must be pinned by digest until a resolver exists |
| `GET /runs/{id}` | `read` | the run and its jobs: state, failure class, cancel flag, newest attempt, fence, phase timestamps |
| `POST /runs/{id}/cancel` | `run` | `cancel_run` ([cancellation](cancellation.md)) |
| `POST /jobs/{id}/cancel` | `run` | `cancel` → `terminal`, `requested` or `alreadyterminal` |
| `POST /jobs/{id}/rerun` | `run` | a new attempt of a finished job; `conflict` for a running or cancelled one |
| `GET /attempts/{id}/logs?after&limit&wait=1` | `read` | frames after a sequence from the same files the controller writes ([logs](logs.md)); `wait=1` parks up to 25 s for more; `complete` and `gaps` say when the log is closed |
| `GET /workers?tenant=slug` | member | the pools the tenant may use and their workers, each with `connected` from the live fleet |

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
```

`--json` prints the server's document; text output is for people. Exit codes: 0 success, 1 remote or transport fault, 2 usage, 3 `unauthenticated`/`forbidden`, 4 `not_found`. `--token-file` keeps the secret out of the process list; `--token` and `SENTINEL_TOKEN` exist for tooling that already protects its environment.

## The page

`GET /` serves one document: sign in (password login through `/login`), list a repository's runs, open a run's jobs with cancel and rerun, follow an attempt's log. It stores the CSRF secret the login returned and sends it on every mutation. No framework, no build step, no request the CLI could not make.

## What is not here yet

Webhook intake and GitHub Checks (G-tasks) are the other way runs start; the API dispatch is the manual one. MCP is the M-tasks over these same routes. TLS in the server itself is deliberately absent. Pagination cursors exist in the protocol and are not yet used by `runs` (a limit suffices for the first page). Step-up over the API (second factor for privileged mutations) arrives with the routes that need it.

## Verification

`crates/sentinel-api/tests/api.rs`, over loopback HTTP against a controller and a store: no credential and a wrong credential are `unauthenticated` with the error schema; an unknown route is `not_found`; the page is served without a credential; an unpinned image and a malformed pipeline are `invalid_request` without echoing the input; dispatch returns the run with its jobs (`queued`, `blocked`), replays under the same idempotency key and refuses a different body; the repository's run list and the run are readable, a random run and a malformed id are refused, a credential narrowed to another tenant sees nothing; cancelling a queued job is `terminal` and marks it `canceled`, rerunning a cancelled job is `conflict`, cancelling the run ends it; an attempt's log is `not_found` before any frame, tails by sequence with stream and step, a `wait=1` request returns as soon as a frame lands and reports completion; worker status lists the tenant's pool. A password login sets a `__Host-` HttpOnly cookie and returns the CSRF secret; the cookie alone reads, a mutation without the header is `forbidden`, with it dispatch succeeds; logout kills the session.

`crates/sentinel/tests/cli.rs` (Linux, both role features), against the real `sentinel server` with its `api_listening` address and a credential issued by `admin token issue`: a bad token file exits 2; `api me` shows the bearer identity; `api run` for a repository the account is not a member of exits 4 with `not_found`; `api workers --json` lists the pool with the enrolled worker `connected`.
