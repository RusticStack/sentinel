# MCP integration (X04–X05)

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
tracked by X06; actual-client conformance is tracked by X07.
