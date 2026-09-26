# MCP integration (X04–X08)

`sentinel mcp` runs the MCP stdio transport as a child process. It implements
the `2025-11-25` protocol revision using newline-delimited UTF-8 JSON-RPC on
stdin and stdout. Diagnostics go to stderr; stdout contains only MCP messages.
The selected revision follows the project's [MCP authorization contract](auth-and-secrets.md#3-remote-mcp)
and the official [lifecycle](https://modelcontextprotocol.io/specification/2025-11-25/basic/lifecycle),
[tools](https://modelcontextprotocol.io/specification/2025-11-25/server/tools),
[resources](https://modelcontextprotocol.io/specification/2025-11-25/server/resources),
and [stdio transport](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports)
specification pages.

Start it after signing in to the target deployment:

```text
sentinel auth login --server https://ci.example.com --scope "runs:read runs:write logs:read secrets:metadata"
sentinel mcp
```

`--profile`, `--server`, `--token-file`, and `SENTINEL_TOKEN` use the shared
CLI client rules. Profiles keep refresh tokens in the OS store or owner-only
configuration files, refresh under the profile lock, and restrict an explicit
server to the profile's issuer. Stdio does not start an OAuth browser/device
redirect flow and does not forward credentials to an upstream model provider.
The shared client presents the Sentinel credential directly to Sentinel's
API; the API checks current scopes, membership, tenant status, and repository
ownership on each request.

## Tools

| Tool | Operation | Required scope |
|---|---|---|
| `list_runs` | Keyset page of repository runs | `runs:read` plus repository read |
| `get_run`, `wait_run` | Current run/job state; one bounded long poll | `runs:read` plus repository read |
| `get_pipeline` | `sentinel.explain/1` from the run's immutable compiled spec | `runs:read` plus repository read |
| `get_failure` | Bounded diagnostics and log excerpt | `logs:read` plus repository read |
| `get_logs` | At most 10 frames from one log page | `logs:read` plus repository read |
| `explain_queue` | Bounded tenant queue and placement reasons | `runs:read` plus tenant membership |
| `validate_pipeline` | Local bounded YAML decode and compile | Local; no credential scope |
| `dispatch` | Compile, pin and dispatch an exact source revision | `runs:write` plus repository run permission |
| `rerun_job`, `cancel` | Start an attempt or request cancellation | `runs:write` plus repository run permission |
| `list_secret_metadata`, `get_secret_metadata` | Secret names, active state and version only | `secrets:metadata` plus tenant/repository authorization |

Read operations return structured JSON alongside JSON text for older clients.
The pipeline resources are `sentinel://pipeline/schema`,
`sentinel://pipeline/recipes`, and `sentinel://pipeline/expressions`; they
contain the checked-in schema, recipes and expression documentation. Tool
inputs reject unknown fields. Dispatch requires a caller-chosen
`idempotency_key`, and `wait_run` accepts a version from an earlier result so
the controller can park until the run changes. Logs and source-derived
pipeline data are untrusted evidence. Secret-value tools are not exposed.

The stdio request and response lines are each capped at 2 MiB and 8 MiB. API
JSON responses are capped at 8 MiB before parsing. `get_logs` deliberately
limits each tool call to a small frame page; use `get_failure` first when
diagnosing a failed attempt.

`GET /api/v1/runs/{id}/pipeline` is the API-backed `get_pipeline` source. It
authorizes the run's repository with the normal `runs:read` and repository
read checks, decodes the immutable stored run spec, and returns the existing
`sentinel.explain/1` contract. It reports secret names and requirements only;
it never returns secret values.

Stdio support does not imply HTTP MCP authentication. The HTTP transport is a
separate OAuth resource and uses the same tool schemas and authorization checks.

## Streamable HTTP (X05)

Configure an MCP client with the deployment's `{issuer}/mcp` endpoint. Sentinel
implements the `2025-11-25` Streamable HTTP revision with JSON responses; it
does not open an event stream. The authorization-server metadata is at
`{issuer}/.well-known/oauth-authorization-server`; the protected-resource
metadata is at
`{origin}/.well-known/oauth-protected-resource{issuer-path}/mcp`. For an issuer
mounted at `/sentinel`, the latter is
`https://ci.example.com/.well-known/oauth-protected-resource/sentinel/mcp`.
Reverse proxies must forward the host-root well-known path. The 401 challenge
names the same protected-resource metadata URL.

The client uses authorization code + PKCE S256 and sends the exact resource
indicator `{issuer}/mcp` through authorization, code exchange, and refresh.
Sentinel issues an MCP-audience access token; an API token cannot access this
endpoint, and an MCP token cannot access `/api/v1`. The token remains between
the MCP client and Sentinel and is never forwarded to a model provider or
another server. OAuth refresh, revocation, and account/membership/tenant
changes retain the normal grant behavior.

Every request needs `Authorization: Bearer` with a live MCP-audience token.
Browser cookies, static API credentials, and API-audience tokens do not
authenticate MCP requests. The server checks an optional `Origin` against the
configured issuer origin. `POST` requires `Content-Type: application/json` and
an `Accept` header containing both `application/json` and `text/event-stream`.
Messages are limited to 2 MiB and serialized responses to 8 MiB. `GET` returns
405 because server-initiated event streams are not enabled; `DELETE` ends the
session.

Initialization creates a random session identifier. The server stores only
its digest, binds it to the authenticated user, caps the table at 1,024
sessions, and expires it after 60 minutes idle. Every follow-up still needs a
valid bearer token and the pinned `MCP-Protocol-Version`; a session ID is not
an authentication credential. Tool calls pass through Sentinel's API scope,
tenant, repository, and ownership checks. See [OAuth](oauth.md) for audience
and grant details. Client registration and metadata-document retrieval are
implemented under X06; conformance coverage is described below.

## Client registration and conformance (X06–X07)

Authorization-server metadata advertises `registration_endpoint` at
`{issuer}/oauth/register` and `client_id_metadata_document_supported: true`.
Sentinel supports RFC 7591 DCR and MCP Client ID Metadata Documents. Both
create only public MCP client records. They do not create Sentinel accounts,
membership, or grants. Every user completes the ordinary sign-in and explicit
consent flow. The client is limited to the MCP audience and the four MCP
scopes; it cannot use device authorization. DCR allows at most 16 exact
redirect URIs and accepts HTTPS domain callbacks or HTTP IP-loopback
callbacks. Registration body, persistent client count, rate, and metadata
retrieval are bounded; the details are in [OAuth](oauth.md#mcp-client-registration-and-metadata-discovery-x06).

The selected client profiles are Visual Studio Code's loopback callback
(`http://127.0.0.1:33418`) and Claude's remote callback
(`https://claude.ai/api/mcp/auth_callback`). The API integration test runs each
through DCR, sign-in and consent, authorization-code exchange, an out-of-ceiling
scope refusal, MCP initialization, insufficient-scope refusal, refresh,
reconnect with the same session, and revocation. The callback URLs are from
the clients' published MCP setup guidance: [VS Code MCP extension guide](https://code.visualstudio.com/api/extension-guides/ai/mcp)
and [Claude remote MCP integration guide](https://support.anthropic.com/en/articles/11503834-building-custom-integrations-via-remote-mcp-servers).
These are deterministic HTTP conformance fixtures; the desktop/web client
applications and their browser windows are not launched by the test.

The CLI end-to-end test runs the actual `sentinel mcp` binary over stdio with
a local credential that lacks `runs:read`. Its tool call returns the normal
structured scope error, produces no OAuth grant, and does not start an HTTP
redirect flow. Stdio remains an API client with local credentials; remote
HTTP MCP authentication is a separate transport.

## Bounded diagnosis and rerun (X08)

An API integration test writes a 100 MiB attempt log with a Go test failure at
the beginning, prompt-like instructions, malformed/non-report text and a
binary final frame. A deterministic MCP agent calls `get_failure`, checks the
failed test, source location and stable frame evidence, then calls
`rerun_job`. The scan is capped at 4 MiB, the default text at 8 KiB, and the
serialized failure view at 64 KiB; the report marks the partial scan
incomplete. The command's recorded `command_failed` result remains
authoritative until the explicit rerun creates a new attempt. Malformed custom
reports are rejected by the versioned report decoder; report or log contents
cannot request a state transition.
