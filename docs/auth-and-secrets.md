# OAuth, CLI/MCP access, and secret management

Status: OAuth/secrets implementation contract; A01's [durable identity/authorization layer](authorization.md) exists, but there is no running login/token service yet. This extends the multi-tenant roles/registration policy in [plan.md](../plan.md). Built for humans and coding agents to use the same scoped operations with little repeated setup.

## 1. Identities and tokens

Keep three relationships separate:

1. **Sign-in identity:** GitHub or local account authenticates a human to Sentinel.
2. **Sentinel authorization:** a CLI/MCP client receives a token for Sentinel, limited to approved tenants/repos/actions.
3. **Forge/workload credentials:** GitHub App installation tokens, registry tokens, deployment keys, and other job secrets are separately managed. A GitHub login token is not a Sentinel access token, and a Sentinel token is not passed through to GitHub.

Sentinel exposes its own OAuth authorization service as an integrated server module, built using maintained protocol/crypto libraries. No mandatory external auth server. An external compatible authorization server can be added through a provider boundary later. Admission/invite policy still applies after OAuth sign-in; authenticating must not bypass super-admin registration controls.

Scopes include `runs:read`, `runs:write`, `logs:read`, `artifacts:read`, `cache:read`, `cache:write`, `secrets:metadata`, `secrets:write`, and administrative scopes. Effective authority is scope intersected with current membership, tenant/repo grants, client policy, and resource ownership. Holding `secrets:write` for one repo grants no authority in another.

## 2. CLI OAuth

Proposed commands:

```text
sentinel auth login --server https://ci.example
sentinel auth login --device --server https://ci.example
sentinel auth status --json
sentinel auth logout
sentinel context use rusticstack
```

- Normal login: system browser, authorization code with PKCE S256 and state, loopback IP redirect on an ephemeral port. CLI is a public client with no embedded client secret. Validate redirects/code verifier; bind state to server/client/request. Do not collect the user's GitHub password in CLI or an embedded webview.
- Headless/remote login: device authorization grant, with a verification URL and short user code on another device. Never print the private device code. Respect server polling interval, `authorization_pending`, `slow_down`, expiry, denial, and cancellation. This polling is only the standardized login flow, not job monitoring.
- Consent shows deployment, client, requested scopes, and tenant/repo grants. Existing authorized agent sessions can reuse a grant; there is no login or confirmation ceremony per CI command.
- Short-lived access tokens, rotating refresh tokens with replay detection and revocation. Bound absolute/idle lifetimes; logout and account suspension revoke relevant grants. Refresh is serialized locally to avoid concurrent CLI processes invalidating each other's tokens; retry ambiguous failures conservatively.
- Store refresh credentials in OS credential storage when available; otherwise an owner-only credentials file outside repositories, with an explicit deployment/profile namespace. Access tokens and secret values never appear in `auth status`, shell completion, debug logs, or errors.
- Noninteractive agents use a previously authorized local profile or an explicitly provisioned expiring service-account grant. OAuth cannot create unattended authority without an initial authorization or service identity. The agent need not read the credential material to invoke authorized CLI operations.

Support authorization-server metadata, token/revocation endpoints, PKCE, and device authorization with release conformance fixtures. Use opaque high-entropy access/refresh tokens hashed at rest initially for simple server-side revocation. Fast indexed validation/short bounded auth caching must still honor revocation versions; do not call GitHub membership APIs for every log frame.

## 3. Remote MCP OAuth

Pin an MCP protocol version during implementation; current research used the **2025-11-25** authorization specification. Implement:

- OAuth Protected Resource Metadata (RFC 9728) advertising authorization server(s); useful HTTP 401 `WWW-Authenticate` discovery.
- Authorization server discovery/metadata; authorization code + PKCE for public clients.
- Resource indicators and token audience validation for the intended MCP endpoint. Reject a token intended for another API/resource even if issued by the same deployment. No upstream token passthrough.
- Pre-registered clients for first-party CLI/test clients. Support Client ID Metadata Documents where target clients use them, with bounded HTTPS fetch/redirect behavior and SSRF protection; permit dynamic registration only when required by selected clients and instance policy. Client registration does not register users or approve tenants.
- Exact permitted redirect URI validation, explicit consent/grants, scope errors, refresh/revocation, origin/session handling, and per-resource tenant authorization.
- Compatibility tests against at least two actual target MCP clients: discovery, login, refresh, insufficient scopes, denied registration, changed roles, expired grants, wrong audience, and reconnect. A generic bearer-token endpoint alone is not “MCP OAuth support.”

Stdio is different: `sentinel mcp` retrieves the local CLI credential profile and talks to the API. It does not implement OAuth redirects over stdio. Environment-based credentials may be supported for explicit automation, but prefer local credential handles to copying tokens into MCP configuration or model messages.

## 4. Secrets through CLI and API

The AI can add/update secrets using CLI once authorized. Give it a protected file/input stream or an existing credential-source handle; do not require the plaintext to be pasted into a conversation or command argument.

Proposed interface:

```text
sentinel secret set REGISTRY_TOKEN --tenant rusticstack --repo RusticStack/app --stdin
sentinel secret set SIGNING_KEY --repo RusticStack/app --file <protected-path>
sentinel secret import --repo RusticStack/app --env-file <protected-path>
sentinel secret list --repo RusticStack/app --json
sentinel secret describe REGISTRY_TOKEN --repo RusticStack/app --json
sentinel secret delete REGISTRY_TOKEN --repo RusticStack/app --if-version <version>
```

- `set` creates or rotates a version; default interactive input is hidden. Reject conflicting sources. Values do not appear in argv, output, HTTP request logs, audit, telemetry, or exception text. Return only name/scope/version/timestamps.
- Support multiline/binary secrets with explicit transport encoding, size limits, and newline semantics: file/stdin preserve bytes; interactive input strips its prompt terminator. Validate formats without printing content. File input does not delete or rewrite the supplied file.
- Bulk env import is explicitly parsed data, never `source`/`eval`; define quoting/duplicate/name errors, preview names only, and commit all-or-nothing. No silent dotenv expansion or shell execution. Conflict control uses versions/idempotency so agent retries do not rotate twice unexpectedly.
- Secret visibility scopes: tenant secret with repo allowlist, repository secret, and explicitly granted job/step usage. Clear precedence: repo binding overrides tenant binding only when configured; ambiguous names fail validation. No implicit distribution of every secret to every job.
- `list`/`describe` return metadata only. No general plaintext read-back API. `secrets:write` is delegable independently of deployment administration; tenant owners/admins can grant repo-bound secret-writer authority to a user/service account. Existing repo operator permissions do not automatically include it.
- Metadata-only MCP tools can list required/missing bindings and secret versions. Value ingestion uses CLI secure input; no requirement to expose an unrestricted secret-value field to the model. Ordinary CLI writes are authorized operations, not gated by an extra artificial confirmation flag.

## 5. Storage and job injection

- Authenticated encryption with a maintained AEAD implementation; versioned ciphertext, unique nonces, and authenticated tenant/repo/name/version context. Master key outside SQLite under operator-controlled permissions; document rotation, backup, and restore. Never build our own cryptography.
- Resolve allowed bindings at job preparation and record version IDs, not values. A rerun specifies whether it uses still-authorized original versions or current versions; unavailable/revoked versions fail explicitly rather than silently changing provenance.
- Prefer job-local read-only mounted files for multiline/large secrets; allow explicit step environment bindings when a tool requires them. Short-lived delivery over authenticated worker sessions, scoped to attempt and worker identity. Prevent later unrelated steps from inheriting undeclared secrets.
- Register dynamic redaction before execution/output, including per-run generated credentials where scripts request it. Handle boundary-spanning values, and redact before all persistence. Arbitrary encodings/exfiltration cannot be solved by a log filter; repository code allowed to use a secret is within that secret's trust policy.
- Exclude secret files/configs from workspace caches/artifacts by default; output allowlists and validations protect common mistakes. No secrets in image layers, build arguments, shared compiler caches, or public cache-key hashes. Tools requiring build secrets use their secret-mount mechanisms.
- Remove injection files/processes during finalization/cancel/restart recovery. Minimize lifetime/copies and best-effort clear owned buffers; do not promise perfect RAM erasure across child processes or the OS.
- Audit who created/rotated/deleted/bound/used each version, tenant/repo/attempt, and result; no values or value-derived public fingerprints. Permission tests cover cross-tenant writes, path/body/log leakage, revoked grants, bulk retry, scope confusion, and cancellation cleanup.

## 6. Developer and agent experience

`pipeline validate` explains missing bindings by name and scope. `secret set --stdin --json` returns compact metadata suitable for agent verification. `auth status` explains deployment/identity/scopes/expiry and the exact login command when renewal is needed. `doctor` diagnoses auth/connectivity without dumping credentials. Existing grants make routine status/log/secret commands fast; step-up is limited to genuinely privileged auth/platform policy changes.

Examples/cookbooks must show credential files/handles and stdin, never real values in shell history. All surfaces use the same authorization rules; a browser role restriction cannot be bypassed through CLI/MCP.

## Sources

- [OAuth native apps, RFC 8252](https://www.rfc-editor.org/rfc/rfc8252): external browser, public clients, PKCE and loopback redirects; fetched during research.
- [Device authorization, RFC 8628](https://www.rfc-editor.org/rfc/rfc8628): separate verification/user and device codes, polling interval, slowdown and expiration; retrieved with targeted source excerpts.
- [MCP authorization 2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization): discovery, protected resource metadata, client metadata/registration, PKCE, resource audience, no token passthrough; consulted through Context7.
- [MCP base protocol](https://modelcontextprotocol.io/specification/2025-11-25/basic): HTTP authorization versus local stdio credential handling. Recheck exact client/provider conformance at implementation; this document does not claim implemented OAuth certification.
