# Protocol contracts (C03)

`crates/sentinel-protocol` holds the shapes every transport shares: the HTTP API used by the CLI, MCP and web UI, and the worker session. It is pure types and functions; no transport code lives here. Everything is bounded and fixed-size where possible so parsing never allocates on the hot path.

## Structured errors

Every error response is one JSON object with `schema: "sentinel.error/1"`, a stable `code`, a human `message`, `retryable`, and optional `request_id` and `details`. Clients switch on `code`; the HTTP status is derived from it and never carries information the code does not. The schema value is a zero-sized marker type: a response with any other schema fails to parse rather than being half-understood.

| Code | Status | Retry unchanged? | Meaning |
|---|---|---|---|
| `invalid_request` | 400 | no | Malformed or semantically invalid |
| `invalid_cursor` | 400 | no | Malformed, expired, or another tenant's cursor (reported identically) |
| `unauthenticated` | 401 | no | Missing or invalid credentials |
| `forbidden` | 403 | no | Authenticated, not permitted |
| `not_found` | 404 | no | Also returned for other tenants' resources |
| `conflict` | 409 | no | Concurrent change or transition not allowed from current state |
| `payload_too_large` | 413 | no | A protocol limit was exceeded; `details.limit_bytes` says which |
| `idempotency_mismatch` | 422 | no | Same key, different body |
| `unsupported_version` | 426 | no | Version or capability set cannot be served |
| `rate_limited` | 429 | yes | Client rate or writer queue full; back off |
| `internal` | 500 | yes | Server fault; `request_id` locates the log record |

`message` and `details` never echo request payloads, secrets or parser fragments.

## Idempotency

Mutations accept an `Idempotency-Key`: 1 to 64 printable ASCII bytes without spaces, stored inline (65 bytes, no allocation). The server scopes the key to (tenant, principal, route) and records the 128-bit FNV-1a fingerprint of the request body with the first response. Decision table, evaluated in the same transaction as the mutation:

| Stored record | Decision |
|---|---|
| none, or older than 24 hours | execute and store |
| same fingerprint, completed | replay stored response, do not execute |
| same fingerprint, first execution still in flight | tell the client to retry shortly |
| different fingerprint | `idempotency_mismatch` |

The fingerprint is not cryptographic: only the caller can collide it, against their own earlier request, and the scope is per authenticated principal.

## Event sequences and cursors

Each event stream (run events, an attempt's log frames, a tenant's audit feed) is numbered by a dense per-stream `Seq` assigned by the writer in commit order, so resuming is one indexed range scan. A `Cursor` is an opaque fixed-size token: 42 bytes (version, tenant, stream kind, stream ID, sequence) encoded as `c1` plus 84 lowercase hex characters. Parsing takes the caller's tenant and rejects a cursor issued for another tenant; that rejection is reported to the client as `invalid_cursor`, indistinguishable from a malformed one. Pages report `next` (absent when exhausted) separately from `complete`, which tells log readers whether upstream truncation or gaps occurred.

## Size limits

Enforced from declared lengths before any body is read; exceeding one is `payload_too_large`.

| Limit | Value |
|---|---|
| API JSON body | 1 MiB |
| GitHub webhook body | 25 MiB (GitHub's own cap) |
| `.sentinel.yml` file | 256 KiB |
| Worker control message | 64 KiB |
| Log frame payload | 32 KiB; larger output is split, never dropped |
| Unacknowledged log frames per worker | 256 |
| List page | default 100, maximum 500 |
| Idempotency key | 64 bytes |
| Agent diagnostic text | default 8 KiB, ceiling 64 KiB |
| Names and labels | 128 bytes |
| Items in any list field | 64 |

Invariants between limits are compile-time assertions. Raise a limit only with a measured need and a note here.

## Worker negotiation

A session opens with `Hello { protocol_min, protocol_max, capabilities, arch, software }`. The controller supports protocol versions in an inclusive range (currently 1 to 1) and answers with the highest version both sides share and the worker's capability bits it recognises. Capabilities are a `u64` bit set so storing, comparing and intersecting is one instruction; bits the controller does not know are masked, never rejected, so newer workers stay compatible.

| Bit | Capability |
|---|---|
| 0 | `OCI_ROOTLESS`: rootless Podman with user namespaces |
| 1–3 | `CGROUP_CPU`, `CGROUP_MEMORY`, `CGROUP_PIDS` |
| 4 | `CGROUP_IO` |
| 5 | `REFLINK` on the cache volume |
| 6 | `TAILCAT` helper available |
| 7 | `NETWORK_NONE` supported |

Bits 0 to 3 are required (the set the F07 probe proved enforceable); a hello without them is rejected. Rejections are typed and final for that hello: `unsupported_version` names the supported range and whether the worker is the side that must upgrade, `missing_capabilities` names the missing bits, `invalid_range` flags `protocol_min > protocol_max`. A worker must not retry an unchanged rejected hello. `software` is a diagnostic string only and never a compatibility input.

## Versioning policy

The protocol version bumps on any incompatible change to messages, framing or semantics. Adding optional fields does not bump it. Error schema, cursor version byte and protocol version are independent so each can move alone. The JSON shapes of `ApiError`, `Hello` and `Rejected` are pinned by tests.

## Verification

Thirteen unit tests: error wire shape and foreign-schema rejection, status and retry mapping, idempotency key bounds and size, fingerprint stability, decision table, cursor round trip with tenant binding and malformed/uppercase/version/kind rejection, sequence saturation, page-size clamping, declared-length checks, version selection with unknown-bit masking, mismatch direction, missing-capability naming, and `Hello`/`Rejected` JSON stability. All pass on Windows and Linux.
