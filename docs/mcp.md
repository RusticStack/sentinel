# MCP integration (X04)

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

Streamable HTTP MCP authorization and client compatibility are tracked by
X05–X07; stdio support does not imply HTTP MCP authentication.
