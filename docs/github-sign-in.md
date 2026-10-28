# GitHub sign-in and identity linking

Implemented in `sentinel-github` (bounded HTTPS client, authorization-code exchange, verified identity), `sentinel-store::sign_in` (pending state, linking, sign-in resolution), `sentinel-api` (browser routes) and `sentinel admin identity`, with metadata migration **7**.

## Three things kept apart

1. **A sign-in identity** — proof from GitHub that a browser controls a particular GitHub account. `sentinel-github` establishes this and nothing else.
2. **A Sentinel session** — issued by `sentinel-store` only once that identity resolves to an admitted account. Authenticating at GitHub admits nobody; see [local authentication](local-authentication.md) for the session contract itself, which is identical whichever way you signed in.
3. **A GitHub App installation token** — repository access for running jobs. A user login token is never used as one, never persisted and never handed to a workload: it is read once, used for a single identity request, and dropped.

## The flow

1. **Begin.** `sign_in::begin` mints a 256-bit state secret, stores only its digest with a 10-minute expiry, and records an optional destination. The secret goes into the `state` parameter *and* into the browser's `__Host-sentinel_signin` cookie.
2. **Authorize.** `App::authorize_url` sends the browser to GitHub with the client ID, the exact redirect URI, the state, and **no scopes** — signing in needs identity, not repository access.
3. **Callback.** `oauth::callback` parses the query before any database or network work: bounded lengths, strict percent-decoding, GitHub's `error` reported as a denial, and duplicated parameters rejected rather than resolved, because a repeated `state` is parameter smuggling. The handler then requires the cookie and the parameter to agree, so a stolen or guessed callback URL alone completes nothing.
4. **Spend the state.** `sign_in::consume` succeeds at most once per attempt, and only for the provider and before the expiry it was created with. The database refuses to un-spend one.
5. **Exchange.** A server-to-server POST carrying the client secret in the body, with the redirect URI repeated so GitHub rejects a code minted for another registration. Sentinel is a confidential client here, so there is no PKCE — GitHub's web flow does not offer it. (Sentinel's *own* OAuth server, for the CLI, does use PKCE; see [auth and secrets](auth-and-secrets.md).)
6. **Verify.** One authenticated `GET /user`. The account's **immutable numeric ID** is required and is the only thing treated as identity. Logins and display names are renameable and reusable, so they are metadata.
7. **Resolve.** `sign_in::complete` looks the subject up in the external identity table and either issues an ordinary session or answers `NoAccount`.

## Browser routes

`sentinel-api` routes the flow above through the browser pages (`crates/sentinel-api/src/github.rs`), so an account that exists only through GitHub — admitted by an invitation bound to its GitHub account, with no password — can sign in on the OAuth consent page (`/oauth/authorize`), the device page (`/device`) and the web interface (`/login`, returning to `/`; [web interface](web-ui.md)). Each offers "Sign in with GitHub" as a plain `GET` link beside the password form, only when GitHub sign-in is configured ([configuration](configuration.md)).

- **`GET /auth/github/start?return_to=<path>`** runs *Begin* and *Authorize*. `return_to` is the page to come back to, as an issuer-relative path: only `/`, `/oauth/authorize?…` or `/device[?…]`, only URL-safe characters (`A–Z a–z 0–9 - . _ ~ % / ? & = + : @ ! $ , * ( )`), at most 2048 bytes. Anything else — an absolute URL, `//host`, a backslash, another route, a fragment, quotes — is refused before any state exists, so a finished sign-in cannot be an open redirect. The route is rate-limited per client (burst 10, then one per 2 s; 20/s for the deployment), which also bounds the pending table: states live ten minutes, so it holds at most about 12,000 rows, and the maintenance tick purges spent and expired ones in batches of 1,000.
- **`GET /auth/github/callback`** runs *Callback* through *Resolve*. The sign-in cookie must equal the `state` parameter (digest comparison), so a stolen, guessed or foreign callback URL completes nothing and spends nothing. Only then is the state spent, the code exchanged and `/user` read; identity is `github` plus the immutable numeric ID, and it resolves only through a linked identity of an **active** account. Pending, rejected and suspended accounts, and a GitHub account nobody linked, get one answer — "no active Sentinel account" — and no session. Nothing is ever linked here: a local account with the same login, name or email is not touched.
- **The hand-off.** A verified callback issues nothing. GitHub's redirect back is a cross-site navigation, on which browsers never send the `SameSite=Strict` session cookie, so the session this browser already holds cannot be seen there. The callback parks a hand-off in the controller's memory — the resolved account and destination, keyed by the digest of the browser's sign-in cookie, for at most 60 seconds, at most 1,024 at once (the oldest is dropped past that, and that browser starts again; a restart drops them all) — and answers a small page (under the pages' unchanged CSP) whose `meta refresh` and link continue to `GET /auth/github/finish`. That navigation is started by a Sentinel page, so it is same-origin and carries the Strict cookie.
- **`GET /auth/github/finish`** takes the hand-off of the presented sign-in cookie once, then in one writer transaction revokes the session cookie the browser sent (whoever it belongs to; audited as a logout) and issues the new session. A request a browser labels anything but `Sec-Fetch-Site: same-origin` is refused with `403` and spends nothing, so another site cannot complete the sign-in without the old session; a request without this browser's sign-in cookie finds no hand-off (`400`), so nobody can complete another browser's; a second request finds nothing. A non-browser client that sends no `Sec-Fetch-Site` label is served as a same-origin one.
- **The session** is the one password login issues: `__Host-sentinel_session`, `Path=/; Secure; HttpOnly; SameSite=Strict`, the absolute life as `Max-Age`, a fresh secret and CSRF secret. The fresh cookie replaces whatever `__Host-` session cookie the browser held, and the session that cookie named is revoked in the same transaction, so neither a planted cookie nor the previous session survives the sign-in (fixation; `__Host-` also keeps a sibling host from planting one). The finish page's `meta refresh` and link continue to the recorded destination, rather than a `303`, like the callback's; the destination therefore loads with the new session, and the consent page mints its form token from that session's CSRF digest. For `/` the page also hands the web interface its CSRF secret through `localStorage` (so every tab of the browser can act), as the password login's JSON response does; OAuth pages need no copy.
- **The sign-in cookie** is `SameSite=Lax` (`cookie::issue_sign_in`), not `Strict`: GitHub's redirect back is a top-level cross-site `GET`, which a `Strict` cookie misses. It is still `__Host-`, `HttpOnly`, `Secure` and ten minutes long, it never authenticates a request, and it is cleared once the attempt ends (at the finish hop after a successful callback).
- **Bounds.** The exchange and the identity read are outbound calls of up to ten seconds each, so at most one runs at a time, under a slot of its own (`sentinel_api::OUTBOUND` per kind of call; OAuth client metadata fetches have theirs, so a signed-in account fetching metadata cannot make sign-in busy); another is told to reload, with its state still pending. No GitHub code or token, and no client secret, appears in a page or a log line: the token is dropped after one `/user` request, and refusal pages name no provider detail.
- **Redirect URI.** Always `{issuer}/auth/github/callback`, derived from `public_url` (or the bound loopback address); the GitHub OAuth app must register exactly that. `App::new` also accepts plain HTTP to a loopback host (`127.0.0.1`, `[::1]`, `localhost`) for a controller used directly on its own machine, and refuses userinfo (`@`).
- **Organizations.** Sign-in has no organization allow-list: admission is the linked identity (an invitation or an approved application), never GitHub membership. Membership of a GitHub-backed tenant is a separate mechanism, below.

`sign_in_states.redirect_to` holds up to 2048 bytes (`sign_in::MAX_REDIRECT_BYTES`, migration **37**), because a consent request's whole query can pass 512 bytes.

## What is and is not admission

`NoAccount` is the honest answer, not an error: an unknown identity is not registered, is not given a placeholder account and does not become a tenant. Turning one into an account is [admission](admission.md): an invitation bound to that verified identity, or an application awaiting approval. Linking an existing account to a GitHub identity is the other path — be admitted, sign in, and link.

Linking requires an authenticated session with a recent [step-up](step-up.md) — attaching an external account is a change to who can authenticate, and a stolen cookie alone must not be able to make it. The route is `POST /api/v1/identities/github/link` ([below](#linking-from-a-signed-in-session)). An account that exists only through GitHub is already linked and has no password to step up with: it enrolls an authenticator app first ([step-up](step-up.md#enrolling-a-second-factor)). A provider identity belongs to at most one account and is never silently moved: claiming one another account holds fails, and the link row is immutable, so there is no re-verification side effect to exploit. Unlinking is available to the account itself, a platform admin, or a host-local operator repairing a wrong link, and both directions are audited. A suspended account cannot sign in through its provider, because session issuance checks the account's live state.

There is deliberately no host-local *link* command: an operator who could type a subject could sign in as anybody. Linking only ever follows a verified provider sign-in.

### Linking from a signed-in session

The same round trip as sign-in, started by a browser that already holds a session:

1. `POST /api/v1/identities/github/link` (session cookie and CSRF header; a bearer or OAuth token is `invalid_request`). A session without a fresh step-up gets `forbidden` with `details.step_up`; the start draws on the per-client GitHub budget. The answer is `{authorize_url, expires_in}` and the `__Host-sentinel_signin` cookie. The attempt (the state's digest, the account, the digest of the session that asked) is held **in memory** for ten minutes — nothing in it is secret, and one lost to a restart is started again — and bounded: at most four per account (a fifth start drops that account's own oldest, so one stepped-up user retrying or scripting the route displaces only itself) and 256 in all, where a full table drops the oldest attempt of the account holding the most, so a user with one attempt is never the one that is dropped.
2. The browser navigates to `authorize_url`. The callback (cross-site, so the Strict session cookie is withheld) requires the cookie and the `state` parameter to agree, spends the attempt once, exchanges the code and reads the immutable account ID exactly as for sign-in, then parks a hand-off carrying the **verified subject** and the starting session's digest and answers the page that moves on to `/auth/github/finish`.
3. The same-origin hop (`Sec-Fetch-Site` checked, hand-off bound to the sign-in cookie) links only if the session cookie presented **is the session that began the attempt**, is still live and belongs to the same account, and the step-up is still fresh when `sign_in::link` runs in the writer. Then it audits `identity-linked`, answers a page that moves to `/`, and clears the sign-in cookie. No session is issued or ended. A different session, none, or an expired step-up is a `403` page and links nothing; an identity another account already holds is a `409` page and stays where it was.

Because the link is made on the hop and never from the callback, another site cannot link its own GitHub account to a victim's session: it can neither start the attempt (CSRF header) nor complete it (the hop needs the sign-in cookie, the victim's session and a same-origin navigation).

```sh
sentinel admin identity list --data-dir <PATH> --user root
sentinel admin identity unlink --data-dir <PATH> --user root --provider github
```

## GitHub-backed organizations

A tenant is **app-managed** (membership by invitation or administrator) or **GitHub-backed** (`tenants.membership_source = 1`). Nothing is inferred: a tenant stays app-managed until an administrator converts it (migration **51** added the column). Implemented in `sentinel-store::github_members` (every decision, in the writer), the lane `sentinel-checks::members` (observes GitHub, never decides) and `sentinel-github::app` (the bounded reads).

### Converting a tenant

`PUT /api/v1/tenants/{slug}/membership-source {"source":"github"|"app","reason"?}` (tenant administration, fresh [step-up](step-up.md)) or, on the host, `sentinel admin source github-backing --tenant ten_… [--off]`. Converting needs an installation of a **GitHub organization** bound to the tenant (`account_personal = 0` from a fresh installation snapshot; otherwise `conflict`) and an organization tenant (never a personal namespace). The administrator making the change must already have a GitHub account linked if they are a member, so the change cannot lock them out.

On conversion the tenant's existing human members start a grace clock (`memberships.synced_ms = now`) and are queued for a check: GitHub confirms them, or they are removed once the grace period passes. Service accounts stay app-managed. Converting back (or unbinding the tenant's last organization installation) leaves the derived access in place as ordinary, locally managed access. Both directions are audited (`tenant-backing-changed`).

### Who is a member

Identity is **only** the immutable numeric GitHub account id of a linked identity (the `external_identities` row the verified link flow wrote), never a login name and never an email. A GitHub-backed tenant admits a person only when that id belongs to an **active** member of the installation's organization:

| GitHub says | Sentinel role |
|---|---|
| organization owner (`role: admin`, `state: active`) | tenant administrator |
| any other active member | **operator** (the ceiling under which the repository permissions below apply; a reader ceiling would make GitHub's `write` meaningless) |
| pending invitation, not a member, deleted account | no membership; an existing derived one is removed |

Role changes follow GitHub in both directions: an owner demoted on GitHub is demoted here on the next check, and the keep-an-administrator rule does not apply to derived rows — GitHub, not Sentinel, decides who administers the organization.

### Repository access

Eligibility is the installation's repository list: only a repository with a live source binding to the tenant's installation can carry a derived grant, and a binding the reconcile lane revokes (the repository left the installation) takes its grants with it at the member's next check. Within that set GitHub's per-repository permission for the *same account id* decides, mapped and **never above what the person holds there**:

| GitHub repository role | Sentinel permissions |
|---|---|
| `admin` | read, run, write secrets |
| `maintain`, `write` | read, run |
| `triage`, `read` | read |
| `none`, a role this table does not name | none |

`maintain` and `triage` are told apart from `write` and `read` by `role_name` (GitHub's legacy `permission` field folds them); a custom role keeps its base. Organization owners reach every repository of the tenant already and carry no derived grants. A member's grants are walked in steps of 25 repositories, resuming from a stored cursor, so a large installation costs bounded work per step. Hand-written grants, role changes, additions and removals of people, and invitations to the tenant are **refused** for a GitHub-backed tenant (`forbidden`; email-domain auto-join ([admission](admission.md#domain-auto-join)) does not apply either: it refuses a tenant that `github_members::is_github_backed` reports or that has a bound GitHub installation, at start and again when joining), and an invitation minted before the conversion is `invitation unusable` when redeemed: membership comes from GitHub or nowhere. Service accounts are still managed here.

### How GitHub is asked

Never on the request path. A sign-in, a link, a signed webhook or the periodic pass queues a `(tenant, person)` check (`github_member_checks`); the lane drains it:

1. Mint a token for the installation with `members: read` and `metadata: read` and nothing else (`App::membership_token`; metadata read is what the per-repository collaborator permission read needs, and it grants no content or write access), only for an installation whose fresh snapshot is an organization, not suspended and not permission-invalid, and whose account id still equals the one the tenant was bound to. **The App must be granted the organization permission "Members: read"**; without it the token request is refused, which is an *unknown* answer (below), never a removal.
2. `GET /user/{id}` for the current login of the stored numeric id (the login is only a path segment for the next request).
3. `GET /orgs/{org}/memberships/{login}`. The reply must name the **same account id and the same organization id** as were asked about; anything else (a renamed login whose old name now belongs to someone else, a transferred organization) proves nothing.
4. For a plain member, `GET /repos/{owner}/{name}/collaborators/{login}/permission` for the next 25 bound repositories, again requiring the same account id. One repository's answer never decides the others':

   - *known*: the grant is written, changed or (for `none`) withdrawn;
   - *404*: the installation token cannot see that repository (removed, transferred, renamed or no longer installed). It is believed, as a membership 404 is, only after the installation snapshot is fetched again and still names the same organization (id and login); then the person has no access there and that grant is withdrawn. If the organization changed, the pass is unreachable and withdraws nothing;
   - *unknown* (a 5xx, an unreadable reply, a missing permission on that repository): that repository's grant is left exactly as it is, and the walk goes on to the next repository, so one repository that cannot be read does not hold back the rest. A grant that GitHub never confirms again lapses with the grace period. Unknown repositories are asked again on the next full walk (the hourly recheck);
   - *rate limited* (a reply that carries GitHub's own wait): the walk stops there, keeps what it settled, and resumes after the cursor under back-off.

Each pass commits under the queue row's sequence fence: if a signed event, a sign-in or an administrator asked for a check while the pass was on the wire, the pass is `superseded` and writes nothing — its observation may predate the event, and applying it could undo a removal — and the row is due again at once. A suspended tenant's members are still checked, so their clocks stay honest and expiry keeps working.

A 404 for the membership is believed only after the installation snapshot is fetched again and still reports the same organization (id and login): a renamed organization answers 404 for everybody under its old name and must not remove anyone.

### Unknown is not absent

A rate limit (429, or 403 with a rate-limit header), a 5xx, an unreachable network, a missing App permission, an unverifiable or mismatching reply and a suspended installation are all **unknown**. Unknown keeps what exists until the grace period since GitHub last confirmed it (`memberships.synced_ms`; `repo_grants.synced_ms`) is over, **grants nothing new**, retries under bounded back-off (doubling to five minutes), and pauses the installation for as long as GitHub asked (at most an hour). A first-time candidate that stays unknown is dropped after five tries; the next sign-in or signed event asks again. After the grace period the lane removes the row. A member sees their own standing on the organization's settings page (`GET /tenants/{slug}/settings` `github_sync`: when GitHub last confirmed them, whether a check is due, and how many passes in a row went unanswered). A pass whose pair has no target at all (a GitHub-backed tenant whose organization installation lost its account, or was removed without the tenant being converted back) is an unanswered pass, not a finished one: the grace clock starts if it never did, derived access lapses when the grace period since the last confirmation is over, and a candidate who never was a member is dropped after five tries, all without a call to GitHub. Only a tenant that is no longer GitHub-backed has its queue row deleted, because it owes nothing. Deleting the row for a GitHub-backed tenant would leave its derived members with access and no expiry. A pass that has nothing left to ask (a person who is not a member, a candidate that gave up, a removal) parks its queue row instead of deleting it (`next_ms` at its maximum, `checked_ms` set to the pass time). The on-demand gap (`MIN_ON_DEMAND_GAP_MS`, 60 s) is measured from `checked_ms`, so repeated sign-ins of a person GitHub just answered about queue nothing, even though the pass is over. Nothing selects a parked row as due; a signed event for the pair wakes it at once, a tenant-wide hint leaves it asleep, and each on-demand enqueue sweeps a few parked rows whose gap has passed, so they do not pile up. Authorization queries never read `synced_ms`: derived rows are ordinary memberships and grants, and expiry is the lane's job.

Configuration (`<data_dir>/github-app.json`, [configuration](configuration.md)): `member_recheck_secs` (60–86,400, default 3,600), the interval between confirmations of a settled member, and `member_grace_secs` (300–2,592,000, default 86,400, at least twice the recheck interval). Request budget per hour is roughly `members × (2 + bound repositories) / recheck`: with signed webhooks the common change is seen at once, so the recheck interval is the safety net and may stay long.

### Keeping access in sync

| Trigger | Effect |
|---|---|
| sign-in, any method (`issue_session`), and a new link | queue a check of the person in every GitHub-backed tenant, at most 256, skipped for a pair checked within the last 60 s |
| a member opening the tenant (`GET /tenants/{slug}/repos`) whose last confirmation is older than five minutes | queue a check, best effort: the request is served from reader connections only and never waits for GitHub or for the store's writer. It files the member with a background thread (`crates/sentinel-api/src/refresh.rs`) that enqueues the filed members in one transaction; a member is filed once per 60 s, at most 64 members wait, and a request that finds the queue full is simply not filed (the hourly recheck still reaches the member). The 60 s per-pair floor above applies |
| `organization` `member_removed` (signed) | the linked account's derived access is **removed at once** (membership, grants, tenant-scoped API credentials, OAuth grants, epoch bump) and a check is queued so a stale or replayed delivery heals |
| `organization` `member_added`, `membership`, `member` | queue a check of that account; nothing is granted from the body |
| `team` changes | queue a check of everyone in the tenant |
| periodic pass | every derived member is re-confirmed each recheck interval |
| unlinking GitHub | every derived membership of the person ends in the same transaction as the unlink; app-managed memberships stay; leaving one organization on GitHub affects only that organization's access |
| a person's account renamed on GitHub | nothing: the id is the identity |

The webhook's installation id (inside the verified signature) picks the tenant, never the body; a replay of the same delivery returns the recorded outcome without acting again, and the same delivery id with a different body is a `conflict`. Subscribe the App to `organization`, `membership`, `member` and `team` events to get the near-instant path. All of it is audited as `github-member-joined`, `github-member-role-changed` and `github-member-removed` (the detail names the role or reason; no GitHub id or login is recorded).

### Verification

`crates/sentinel-store/tests/github_members.rs` drives every decision with hand-written observations: conversion preconditions, owner/member mapping and demotion, the permission table and derivation, removal revoking access and moving the epoch, unknown keeping within grace and expiring, a reply about another account discarded (forged identity, reused login, relink in flight), unlinking, the refused manual paths including a pre-conversion invitation, a signed removal and its replay, foreign installations, the sign-in queue's rate limit, unbinding, a backed tenant without a target still expiring derived access, and the resumable repository walk. `crates/sentinel-checks/tests/members.rs` runs the lane against a loopback GitHub: join, owner demotion, renamed login, reused login, pending invitation, removal, organization rename, 429/5xx/403 and a missing App permission. `crates/sentinel-github/src/webhook.rs` unit tests cover the membership events.

## Bounds and configuration

- The outbound client is bounded on every axis a remote server controls: 10-second global timeout, 16 KiB of headers, a 64 KiB body limit, and **no redirects** — a redirect from a token endpoint is a misconfiguration or an attack, not something to follow with a secret in hand. Transport failures are reported by kind, never with the URL, so a token-endpoint error cannot put a credential in a log line.
- `App::new` requires one exact, absolute HTTPS redirect URI: no wildcard, query or fragment. GitHub compares it too, but a deployment must not register a pattern here and rely on the other side to be strict.
- `App::load` reads the client secret from an operator-controlled file, dropping one trailing newline. The secret never reaches a command line, an environment variable or the database; `Debug` for `App` omits it, and `LoginToken` prints as `LoginToken(redacted)` and overwrites its buffer on drop.
- `Endpoints::github()` and `Endpoints::enterprise()` are the two configuration paths and both require HTTPS. `Endpoints::loopback()` exists for tests and local fakes and can only ever address `127.0.0.1`, so it cannot reach a real provider without TLS.
- Sign-in destinations are same-site paths only (`/...`, never `//` or a scheme), enforced in the API and by a database check: an open redirect after a successful login is a phishing primitive.
- `sign_in::purge_expired` deletes spent and expired attempts in bounded batches; single use and expiry are already enforced by `consume`.

## Verification

`crates/sentinel-github/src/oauth.rs` unit tests drive the real HTTP client against a GitHub-shaped server on loopback: a code becoming a verified account ID, the secret travelling in the body rather than the URL, the login token presented once as a header, denials and malformed user records (missing, zero, stringified or absent-login) refused, strict application/endpoint configuration, secret-file loading, and callback parsing including duplicates, bad escapes and oversized queries.

`crates/sentinel-github/tests/flow.rs` runs the whole path across both crates: link, begin, authorize, callback, exchange, verify, session. It also covers a callback with no sign-in cookie and one whose cookie disagrees with the parameter — neither reaches the exchange, and neither spends the pending attempt — and a verified but unlinked account, which produces no session at all.

`crates/sentinel-api/tests/github_sign_in.rs` drives the browser routes, with a browser model that keeps the SameSite rules (Strict cookies withheld from the cross-site callback, sent on the same-origin finish hop) and the `Sec-Fetch-Site` labels, over loopback HTTP against `sentinel_github::fake`, a GitHub-shaped server (feature `fake`) whose authorize endpoint plays the browser's GitHub session: the previous session revoked only by the same-origin hop, a cross-site finish refused without spending the hand-off, a stranger's sign-in cookie finding none, and the hand-off taken once; a GitHub-only account approving an OAuth consent and a device code and landing on the exact page it started from; replayed, foreign and cookie-less state refused without spending anything, and a GitHub denial; open redirects in `return_to` refused with no state; a pending account and a local account matching the GitHub login and email getting no session and no link; cookie attributes and the revocation of a prior session; the per-client start limit; no GitHub code or token, client secret or Sentinel token in any page; and no button or route without configuration. `crates/sentinel/tests/oauth_e2e.rs::a_github_only_account_signs_the_cli_in_through_github` runs the real CLI's browser login end to end this way.

`crates/sentinel-store/tests/sign_in.rs` covers single-use, expiring, provider-bound state and its raw-SQL un-spend refusal; same-site destination validation; proof without admission; sign-in by immutable subject rather than login; one identity per account with no silent move; suspension; authorized listing and unlinking; audit records that name the provider but never the subject; and bounded purging.

See [authorization](authorization.md) for what the resulting `Principal` may do.
