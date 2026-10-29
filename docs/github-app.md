# One-click GitHub App setup

Implemented in `sentinel-github::manifest` (the manifest, the conversion, webhook reachability), `sentinel-store::github_app` (one-time states, the sealed App, installation binding), `sentinel-api` (`crates/sentinel-api/src/github_app.rs`, the routes below) and the controller's start-up (`crates/sentinel/src/source_admin.rs`, `service.rs`), with metadata migration **56**. The web interface's pages `/setup/github/created` and `/setup/github/installed` relay GitHub's redirects to these routes ([web interface](web-ui.md)).

A self-hosted operator never writes `.env` entries or creates the GitHub App by hand: a platform administrator asks the controller for a [GitHub App manifest](https://docs.github.com/en/apps/sharing-github-apps/registering-a-github-app-from-a-manifest), GitHub registers the App from it, and the controller exchanges the code GitHub hands back for the App's identity and credentials, seals them in the database and puts the App in force at once — checks, installation tokens, source access, membership checks, the webhook and GitHub sign-in — without a restart. Each organization's administrator then installs the App and binds the installation to their organization from the web interface.

## Before you start

| Needs | Why | Without it |
|---|---|---|
| `public_url` set, as the web interface's origin with no path ([configuration](configuration.md)) | GitHub sends the browser back to `{public_url}/setup/github/created` and `/setup/github/installed`, and delivers webhooks to `{public_url}/api/v1/hooks/github` | `can_create: false`, `create_refusal: "no_public_url"` or `"public_url_has_path"`; the manifest route answers `409` |
| `<data_dir>/master.key` (`sentinel admin key create`) | the App's private key, client secret and webhook secret are sealed with it ([sealed storage](sealed-storage.md)) | `create_refusal: "no_master_key"`, `409` |
| none of `github-app.json`, `github-webhook.json`, `github-sign-in.json` in the data directory | files take precedence (below) | `create_refusal: "files"`, `409` |
| a platform administrator's browser session with a recent [step-up](step-up.md) | creating the deployment's GitHub identity is a privileged platform change | `403` (`details.step_up` when only the step-up is missing) |

GitHub Enterprise Server is not supported by one-click setup yet: the routes always address `github.com` and `api.github.com`. A GHES deployment keeps configuring the App by files (`api_url` in `github-app.json`, `web_url`/`api_url` in `github-sign-in.json`).

## The flow

1. **Ask for a manifest.** `POST /api/v1/github/app/manifest` with `{"owner": {"kind": "user"}}` (the administrator's own GitHub account) or `{"owner": {"kind": "organization", "login": "<org>"}}`, and optionally `"public": true` (default `false`). The controller mints a state (below) and answers `{action_url, manifest, state, expires_ms}`. `action_url` is `https://github.com/settings/apps/new?state=S` or `https://github.com/organizations/<org>/settings/apps/new?state=S`; the web page posts a form there whose field `manifest` is the `manifest` text. The manifest names the App `<instance name> <6 hex>` (the instance name from first-run setup reduced to letters, digits and spaces, `Sentinel` without one; at most 34 characters, GitHub's limit; the suffix keeps it unique on GitHub), and sets:

   | Field | Value |
   |---|---|
   | `url` | `public_url` |
   | `hook_attributes` | `{"url": "{public_url}/api/v1/hooks/github", "active": <webhook reachable>}` |
   | `redirect_url` | `{public_url}/setup/github/created` |
   | `callback_urls` | `["{public_url}/auth/github/callback"]` — sign-in through the App's OAuth client ([GitHub sign-in](github-sign-in.md#browser-routes)) |
   | `setup_url`, `setup_on_update` | `{public_url}/setup/github/installed`, `true` |
   | `public` | `false` unless asked; a private App can be installed only on the account that owns it, so a deployment serving several GitHub accounts asks for `true` (or flips it later in the App's settings) |
   | `default_permissions`, `default_events` | the table below; events only with an active webhook |

2. **GitHub registers the App** under the chosen account after the person confirms, and redirects the browser to `{public_url}/setup/github/created?code=C&state=S`. That navigation comes from github.com, so the browser withholds the `SameSite=Strict` session cookie; the page is sentinel-web's, and it calls the controller same-origin, where the cookie and the CSRF header are sent.
3. **Convert.** `POST /api/v1/github/app/conversion {"code": C, "state": S}` (optionally `"tenant": "<slug>"` and `"reason"`, below). The controller spends the state, then — and only the controller, never sentinel-web — calls `POST https://api.github.com/app-manifests/{code}/conversions` through the bounded GitHub client (10 s, 64 KiB, no redirects, unauthenticated as GitHub requires). GitHub returns the App's id, slug, name, owner, page, OAuth client id and secret, webhook secret and private key, once. The controller validates them, seals the three secrets and stores the row in one writer transaction (audited `github-app-created`, detail `app <id> <slug>`), then puts the App in force (below). The answer is `{"app": {id, slug, name, html_url, owner}, "install_url"}`: public facts only.
4. **Install.** `install_url` is `https://github.com/apps/<slug>/installations/new`; with `"tenant"` in the conversion body, or from `POST /api/v1/tenants/{slug}/github/installation-url {}` (optionally `{"reason"}`), it carries a state minted for that tenant: `…/installations/new?state=S2`, `{install_url, expires_ms}`. The person picks the account and repositories on GitHub; GitHub redirects to `{public_url}/setup/github/installed?installation_id=I&setup_action=install&state=S2` (`update` when an installation's settings change).
5. **Bind.** The page posts `POST /api/v1/github/app/installation {"installation_id": I, "state": S2, "setup_action": "install"|"update"}`. The controller spends S2, reads `GET /app/installations/I` **as the App** (its JWT), proves the person may bind it (below), records the fresh snapshot and binds the installation to the tenant S2 was minted for through the existing binding rule ([admission](admission.md)): `{"tenant": "<slug>", "account": "<GitHub login>"}`. Repositories are then bound to sources as before ([sources](sources.md)).

## Who may do each step

| Step | Who | Notes |
|---|---|---|
| `GET /github/app` | anyone signed in | a platform administrator also sees `public_url`, `webhook_url` and `create_refusal`; everyone else gets them as `null` and `can_create: false`. No secret is in either view |
| manifest | platform administrator, browser session, fresh step-up | the step-up is checked in the writer transaction that mints the state (`Authority::require_privileged`) |
| conversion | platform administrator, browser session, **the same session** that asked for the manifest | the state carries the step-up forward: a person who stepped up and was sent to GitHub is not asked again on return |
| installation link | the tenant's administrator; a platform administrator outside the tenant gives a `reason` and a fresh step-up (`platform-override`, as for membership changes) | `installation_binding = super-admin-only` ([admission](admission.md)) leaves only platform administrators able to bind |
| binding | the person who minted S2, in the same session | plus the account proof below |

A bearer credential or OAuth token gets `invalid_request` from every mutation here: the states are bound to a browser session.

### Proving the installation

GitHub's redirect names an installation, but anyone can type `installation_id=I` into that URL. The controller believes nothing from it:

- `GET /app/installations/I` must answer for **this** App (another App's installation, or none, is `403` `details.reason: "foreign_installation"`);
- an installation on a **personal** account binds only for a person whose linked GitHub identity ([GitHub sign-in](github-sign-in.md#linking-from-a-signed-in-session)) has that account's numeric id (`cross_account`);
- an installation on an **organization** binds only for an active **owner** of that organization, asked through the installation with the same membership token, login and organization-id checks the membership lane uses (`not_org_owner`; `link_github` when the person has no linked GitHub identity), and only to an organization tenant, never a personal namespace (`tenant_mismatch`);
- an installation already bound to another tenant stays there (`409`, `bound_elsewhere`): unbind it first; the same tenant again (`setup_action=update`) is `200` and changes nothing.

A platform administrator is exempt from the GitHub-account proof (they may already bind any installation host-locally), not from the tenant rules. The tenant always comes from the state, never from the request, so a state minted for one organization cannot bind into another.

## States

| Rule | Value |
|---|---|
| Entropy | 256 bits (`Secret::generate`, the OS generator; panics rather than falling back) |
| Stored | its BLAKE3 digest only (`github_app_states`), with the purpose, account, session id, tenant (installations), creation and expiry |
| Lifetime | 10 minutes. Enough to read GitHub's form and confirm it; short enough that a state left in a browser history is dead soon after. GitHub's own code lives an hour, so the state is the tighter bound |
| Use | once: spending sets `used_ms` in the writer, and a trigger refuses to clear it or change anything else |
| Bound to | the purpose (manifest or installation), the account, the session that minted it and, for an installation, the tenant |
| Bounds | at most 16 per account (minting more drops the oldest); expired rows are purged by the maintenance tick, 1,000 per pass |

Every refusal — unknown, malformed, spent, expired, another purpose, another account or another session — is the same `404 not_found` with one message, and is audited as `github-app-state-refused` with the detail `<manifest|installation> <unknown|foreign|replayed|expired>` (at most five rows per account in ten seconds). A refused state never reaches GitHub. The outbound slot is taken before the state is spent, so a `rate_limited` answer (another GitHub call in flight) never burns one; a GitHub failure after the state was spent does, and the person starts again.

## What is stored where

`github_app` (one row, migration 56): `app_id`, `slug`, `name`, `owner`, `owner_id`, `html_url`, `client_id`, `created_by`, `created_ms` in plain columns, and `sealed_key`, `sealed_client_secret`, `sealed_webhook_secret` sealed with `master.key` under a context naming the column and the App id, so a value moved to another column or another App does not open. The secrets are sealed before they reach the writer thread. A trigger refuses any change except a forward reseal. `admin key rotate|reseal|retire`, the start-up key check (the controller refuses to start when `master.key` is missing or does not open them) and backups' key-id check include the three columns ([sealed storage](sealed-storage.md)).

The private key, client secret and webhook secret never appear in an HTTP answer, an error message, a log line, an audit row or the diagnostic bundle; GitHub's error bodies are never echoed (a failed call is `502 upstream_failed` with a fixed message). The conversion's response text is wiped once parsed, and the in-memory copies are wiped when dropped. `crates/sentinel-api/tests/github_app.rs` asserts it with canary values.

## Precedence and activation

**Files win.** When any of `github-app.json`, `github-webhook.json` or `github-sign-in.json` exists in the data directory, the deployment is configured by files exactly as before: every component reads the files at start, `GET /github/app` reports `source: "files"`, and the manifest and conversion routes answer `409 conflict` with `details.reason: "files"`. A stored App is then not used (start-up logs `github_app_stored_ignored`). To move from files to one-click setup, stop the controller, remove the three files and start it again. A fresh install without files uses the manifest flow.

**In force without a restart.** The App lives in one shared holder (`sentinel_github::app::Current`, set at most once, read with one atomic load), which installation tokens, source access for intake and polling, and the controller's spec resolution read on every use. A conversion sets it, the webhook secret (the hook route reads it with one atomic load per delivery; no database round trip) and sign-in through the App's OAuth client, then starts the check publisher, the reconciliation lane and the membership lane, and logs `github_app_activated` (the App id and slug). Membership timing uses the defaults (`member_recheck_secs` 3,600, `member_grace_secs` 86,400). On the next start the controller opens the stored App with `master.key` and puts it in force the same way. Check links (`details_url`) use the controller's `public_url`.

There is no route to replace or delete a stored App: a second manifest is `409` (`configured`). Rotating the App's private key or webhook secret is done on GitHub and, today, needs the files path.

## Webhook reachability

GitHub delivers webhooks from the internet, so it must reach `{public_url}/api/v1/hooks/github` over HTTPS. `GET /github/app` reports `webhook_reachable` and, when false, `reason`, judged from `public_url` alone (no name is resolved):

| `reason` | When |
|---|---|
| `no_public_url` | `public_url` is not set (`webhook_url` is `null`; the manifest is refused) |
| `not_https` | `public_url` is `http://` (only allowed for a loopback host) |
| `private_address` | a loopback, private (RFC 1918, IPv6 unique-local), link-local or unspecified address; `localhost`, `*.localhost`, `*.local`, `*.internal`, `*.lan`, `*.home.arpa` |
| `tailnet_only` | a Tailscale name (`*.ts.net`) or address (`100.64.0.0/10`, `fd7a:115c:a1e0::/48`). Tailcat addresses name worker links, never an HTTP origin, so they never appear in `public_url` |
| `single_label_host` | a host name without a dot |

A public name that resolves to a private address is not caught here; GitHub's delivery log for the App shows those failures.

An unreachable controller can still create the App: everything outbound works — check runs publish, installation tokens and source access work, sign-in works, membership is re-checked on its schedule. The manifest then registers the webhook **inactive** and subscribes to no events (GitHub offers events only with an active webhook), and the web page must say plainly that GitHub cannot deliver events: pushes and pull requests will not trigger runs, rerequested checks and membership changes are not seen at once. Bind repositories with [ref polling](intake.md#ref-polling) instead (`sentinel admin source poll`), or put the controller behind a public HTTPS origin and then, in the App's settings on GitHub, enable the webhook (its URL and secret are already set) and subscribe to the events below. GitHub's form takes an `http://` webhook URL, but Sentinel never registers one: `not_https` only arises for a loopback host, which GitHub cannot reach either.

## Permissions and events

Exactly what the controller uses today ([AGENTS.md](../AGENTS.md): a feature that needs more asks for it only when a tenant turns it on, so nothing for runner mode or migration):

| Permission | Access | Why |
|---|---|---|
| `checks` | write | publish check runs and suites ([checks](checks.md)); also what `check_run`/`check_suite` events need |
| `contents` | read | source tokens for resolution, jobs and polling, and reconciliation ([intake](intake.md), [sources](sources.md)); also what `push` events need |
| `metadata` | read | GitHub's mandatory baseline; the repository and collaborator-permission reads of membership derivation |
| `pull_requests` | read | required to receive `pull_request` events (intake) |
| `members` (organization) | read | membership of GitHub-backed organizations ([GitHub sign-in](github-sign-in.md#github-backed-organizations)) and the owner proof when binding an organization's installation |

Sign-in reads only the numeric account id (`GET /user`) and asks no scope or account permission; email is never an identity.

Events: `push`, `pull_request` (intake), `check_run`, `check_suite` (rerequests), `repository` (renames, transfers, archival), `organization`, `membership`, `member`, `team` (membership). `installation` and `installation_repositories` reach every App without a subscription.

## Failure modes and recovery

| What happened | What the person sees | Recovery |
|---|---|---|
| The person closed GitHub's page, or waited past ten minutes | the page's call answers `404` | start again; nothing was created |
| GitHub created the App, but the conversion failed (network, GitHub error) | `502 upstream_failed` | delete the half-created App in its settings on GitHub (Settings → Developer settings → GitHub Apps, or the organization's), then start again |
| GitHub returned a key Sentinel cannot use | `502 upstream_failed` | delete the new App on GitHub, start again |
| Two administrators converted at once | the second gets `409` (`configured`) | delete the second App on GitHub |
| The controller restarted between manifest and conversion | nothing: states are durable | continue |
| `master.key` lost | the controller refuses to start (sealed values present) | restore the key; or restore a backup taken before setup; or, on a fresh deployment, delete the App on GitHub and the database row with the controller stopped |
| The webhook is unreachable | `webhook_reachable: false` and a `reason` | see above |
| An installation was requested by a member and awaits an owner's approval (`setup_action=request`) | `400` | the owner approves on GitHub, then binds from the organization's settings |

## HTTP contract

All under `/api/v1`, JSON, session cookie; `POST`s need the CSRF header. Errors use the uniform body ([protocol](protocol.md#structured-errors)).

| Route | Body | Answer |
|---|---|---|
| `GET /github/app` | — | `{"configured": bool, "source": "files"\|"manifest"\|null, "app": null\|{"id", "slug", "name", "html_url", "owner"}, "public_url": string\|null, "webhook_url": string\|null, "webhook_reachable": bool, "reason": null\|"no_public_url"\|"not_https"\|"private_address"\|"tailnet_only"\|"single_label_host", "can_create": bool, "create_refusal": null\|"files"\|"configured"\|"no_public_url"\|"public_url_has_path"\|"no_master_key"\|"forbidden", "install_url": string\|null}`. For a file-configured App, `app` names only `id` (the rest `null`) until an installation link has read the App from GitHub; `install_url` carries no state |
| `POST /github/app/manifest` | `{"owner": {"kind": "user"} \| {"kind": "organization", "login"}, "public"?: bool}` | `{"action_url", "manifest", "state", "expires_ms"}`; `409` (`details.reason` as `create_refusal`), `403` (+`details.step_up`), `400` |
| `POST /github/app/conversion` | `{"code", "state", "tenant"?, "reason"?}` | `{"app": {...}, "install_url"}`; `404` refused state, `409`, `502 upstream_failed` |
| `POST /tenants/{slug}/github/installation-url` | `{}` or `{"reason"}` | `{"install_url", "expires_ms"}`; `404` unknown tenant, `403`, `400` reason missing, `409` (`not_configured`) |
| `POST /github/app/installation` | `{"installation_id", "state", "setup_action"}` | `{"tenant", "account"}`; `404` refused state, `403` with `details.reason` (`foreign_installation`, `cross_account`, `not_org_owner`, `link_github`, `tenant_mismatch`), `409` (`bound_elsewhere`, `not_configured`), `502 upstream_failed` |

Calls to GitHub from these routes take one outbound slot of their own (`rate_limited` with `details.retry_after_ms` when busy), so they never hold more than one handler permit.

## Verification

- `crates/sentinel-github/src/manifest.rs` unit tests: reachability for every reason, the manifest's exact permissions, events and URLs (active and inactive webhook), name length and state encoding, a conversion that never prints its secrets and refuses malformed ones.
- `crates/sentinel-store/tests/github_app.rs`: states single-use, expiring and bound to account, session and purpose; refusals audited and flood-bounded; the per-account bound and the purge; the App stored once, sealed (the canaries absent from the database file), opening only under its own column context; immutability triggers; rotation, `stale`, `reseal_all` and key ids; binding rules (organization installation never into a personal namespace, bound elsewhere refused, same tenant idempotent, non-administrator refused).
- `crates/sentinel-api/tests/github_app.rs`, over loopback HTTP against `sentinel_github::fake` (manifest conversions, App installation reads and tokens, users and organization memberships): the whole flow with the App in force at once (a webhook signed with the new secret accepted, sign-in enabled, the activation hook called once); replayed, wrong, malformed, other-session, other-administrator and expired states refused uniformly, audited, and never sent to GitHub; a GitHub failure after the state was spent; non-administrator and missing step-up; installation binding for an organization owner, refusals for a member, another account, a foreign installation, an installation bound elsewhere, another person's state, a non-administrator, a platform administrator without a reason or step-up, and an organization installation into a personal namespace; a file configuration that keeps working and blocks one-click setup with `409`; a Tailscale-only and an unset `public_url`; and a canary scan of every answer's status line, headers and body, the audit log and the database files.
