# GitHub sign-in and identity linking (A04)

Implemented in `sentinel-github` (bounded HTTPS client, authorization-code exchange, verified identity), `sentinel-store::sign_in` (pending state, linking, sign-in resolution) and `sentinel admin identity`, with append-only metadata migration **7**.

## Three things kept apart

1. **A sign-in identity** — proof from GitHub that a browser controls a particular GitHub account. `sentinel-github` establishes this and nothing else.
2. **A Sentinel session** — issued by `sentinel-store` only once that identity resolves to an admitted account. Authenticating at GitHub admits nobody; see [local authentication](local-authentication.md) for the session contract itself, which is identical whichever way you signed in.
3. **A GitHub App installation token** — repository access for running jobs (Part 05). A user login token is never used as one, never persisted and never handed to a workload: it is read once, used for a single identity request, and dropped.

## The flow

1. **Begin.** `sign_in::begin` mints a 256-bit state secret, stores only its digest with a 10-minute expiry, and records an optional destination. The secret goes into the `state` parameter *and* into the browser's `__Host-sentinel_signin` cookie.
2. **Authorize.** `App::authorize_url` sends the browser to GitHub with the client ID, the exact redirect URI, the state, and **no scopes** — signing in needs identity, not repository access.
3. **Callback.** `oauth::callback` parses the query before any database or network work: bounded lengths, strict percent-decoding, GitHub's `error` reported as a denial, and duplicated parameters rejected rather than resolved, because a repeated `state` is parameter smuggling. The handler then requires the cookie and the parameter to agree, so a stolen or guessed callback URL alone completes nothing.
4. **Spend the state.** `sign_in::consume` succeeds at most once per attempt, and only for the provider and before the expiry it was created with. The database refuses to un-spend one.
5. **Exchange.** A server-to-server POST carrying the client secret in the body, with the redirect URI repeated so GitHub rejects a code minted for another registration. Sentinel is a confidential client here, so there is no PKCE — GitHub's web flow does not offer it. (Sentinel's *own* OAuth server, for the CLI, does use PKCE; that is [A09](auth-and-secrets.md).)
6. **Verify.** One authenticated `GET /user`. The account's **immutable numeric ID** is required and is the only thing treated as identity. Logins and display names are renameable and reusable, so they are metadata.
7. **Resolve.** `sign_in::complete` looks the subject up in the external identity table and either issues an ordinary session or answers `NoAccount`.

## What is and is not admission

`NoAccount` is the honest answer, not an error: an unknown identity is not registered, is not given a placeholder account and does not become a tenant. Turning one into an account is [admission](admission.md): an invitation bound to that verified identity, or an application awaiting approval. Linking an existing account to a GitHub identity is the other path — be admitted, sign in, and link.

Linking requires an authenticated session — that *is* the authenticated intent. A provider identity belongs to at most one account and is never silently moved: claiming one another account holds fails, and the link row is immutable, so there is no re-verification side effect to exploit. Unlinking is available to the account itself, a platform admin, or a host-local operator repairing a wrong link, and both directions are audited. A suspended account cannot sign in through its provider, because session issuance checks the account's live state.

There is deliberately no host-local *link* command: an operator who could type a subject could sign in as anybody. Linking only ever follows a verified provider sign-in.

```sh
sentinel admin identity list --data-dir <PATH> --user root
sentinel admin identity unlink --data-dir <PATH> --user root --provider github
```

## Bounds and configuration

- The outbound client is bounded on every axis a remote server controls: 10-second global timeout, 16 KiB of headers, a 64 KiB body limit, and **no redirects** — a redirect from a token endpoint is a misconfiguration or an attack, not something to follow with a secret in hand. Transport failures are reported by kind, never with the URL, so a token-endpoint error cannot put a credential in a log line.
- `App::new` requires one exact, absolute HTTPS redirect URI: no wildcard, query or fragment. GitHub compares it too, but a deployment must not register a pattern here and rely on the other side to be strict.
- `App::load` reads the client secret from an operator-controlled file, dropping one trailing newline. The secret never reaches a command line, an environment variable or the database; `Debug` for `App` omits it, and `LoginToken` prints as `LoginToken(redacted)` and overwrites its buffer on drop.
- `Endpoints::github()` and `Endpoints::enterprise()` are the two configuration paths and both require HTTPS. `Endpoints::loopback()` exists for tests and local fakes and can only ever address `127.0.0.1`, so it cannot reach a real provider without TLS.
- Sign-in destinations are same-site paths only (`/...`, never `//` or a scheme), enforced in the API and by a database check: an open redirect after a successful login is a phishing primitive.
- `sign_in::purge_expired` deletes spent and expired attempts in bounded batches; single use and expiry are already enforced by `consume`.

## Verification

`crates/sentinel-github/src/oauth.rs` unit tests drive the real HTTP client against a GitHub-shaped server on loopback: a code becoming a verified account ID, the secret travelling in the body rather than the URL, the login token presented once as a header, denials and malformed user records (missing, zero, stringified or absent-login) refused, strict application/endpoint configuration, secret-file loading, and callback parsing including duplicates, bad escapes and oversized queries.

`crates/sentinel-github/tests/flow.rs` runs the whole path across both crates as the eventual route will: link, begin, authorize, callback, exchange, verify, session. It also covers a callback with no sign-in cookie and one whose cookie disagrees with the parameter — neither reaches the exchange, and neither spends the pending attempt — and a verified but unlinked account, which produces no session at all.

`crates/sentinel-store/tests/sign_in.rs` covers single-use, expiring, provider-bound state and its raw-SQL un-spend refusal; same-site destination validation; proof without admission; sign-in by immutable subject rather than login; one identity per account with no silent move; suspension; authorized listing and unlinking; audit records that name the provider but never the subject; and bounded purging. The `sentinel admin identity` surface was exercised end to end on Linux.

See [TODO.md](../TODO.md) for commands and results, and [authorization](authorization.md) for what the resulting `Principal` may do.
