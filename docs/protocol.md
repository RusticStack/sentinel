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
| `rate_limited` | 429 | yes | Client rate, a full queue, or a busy writer that attempted nothing; back off. `details.retry_after_ms`, when present, is the server's own back-off |
| `internal` | 500 | yes | Server fault; `request_id` locates the log record |
| `outcome_unknown` | 503 | no | The controller stopped waiting for a write that is still queued or running and **may yet commit** (the store's `WriteAmbiguous`). Repeating an unkeyed mutation can apply it twice: re-read first, or repeat with the same `Idempotency-Key` (`details.retry_with_idempotency_key: true`), which replays instead of executing again |
| `storage_full` | 507 | yes | Write refused below the disk watermarks ([storage](storage.md#disk-admission-quotas-and-reclamation-d06)); retry once the controller has headroom |
| `quota_exceeded` | 403 | no | The tenant reached its storage quota; reclaim space or raise it |

`message` and `details` never echo request payloads, secrets or parser fragments.

Codes are additive, so a client meets codes newer than itself. `sentinel_protocol::ErrorCode` parses any code it does not know as `ErrorCode::Unknown` (`#[serde(other)]`; never sent by a server); for such an answer the HTTP status and the document's `retryable` field are authoritative. The CLI switches on the code string and maps unknown codes to exit 1.

## Idempotency

Mutations accept an `Idempotency-Key`: 1 to 64 printable ASCII bytes without spaces, stored inline (65 bytes, no allocation). The server scopes the key to (tenant, principal, route) and records the 128-bit FNV-1a fingerprint of the request body with the first response. Decision table, evaluated in the same transaction as the mutation:

| Stored record | Decision |
|---|---|
| none, or older than 24 hours | execute and store |
| same fingerprint, completed | replay stored response, do not execute |
| same fingerprint, first execution still in flight | `outcome_unknown`; repeat with the same key (unreachable while the route records and completes the key in the mutation's own transaction, as `POST …/runs` does) |
| different fingerprint | `idempotency_mismatch` |

The fingerprint is not cryptographic: only the caller can collide it, against their own earlier request, and the scope is per authenticated principal.

## Event sequences and cursors

Each event stream (run events, an attempt's log frames, a tenant's audit feed) is numbered by a dense per-stream `Seq` assigned by the writer in commit order, so resuming is one indexed range scan. A `Cursor` is an opaque fixed-size token: 42 bytes (version, tenant, stream kind, stream ID, sequence) encoded as `c1` plus 84 lowercase hex characters. Parsing takes the caller's tenant and rejects a cursor issued for another tenant; that rejection is reported to the client as `invalid_cursor`, indistinguishable from a malformed one. Pages report `next` (absent when exhausted) separately from `complete`, which tells log readers whether upstream truncation or gaps occurred.

**Not yet on the wire.** The `Cursor` type is defined and tested here, but no `/api/v1` route emits or accepts one today: the log routes page by a plain frame sequence (`after=<seq>`) and the run list by the last run's ID (`before=run_…`, answered as `next`). Those parameters are route-level query syntax, not the versioned `c1` contract; a route that adopts `Cursor` will say so in [API](api.md) and [compatibility](compatibility.md).

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
| Artifact data frame payload (`ArtifactData`) | 48 KiB |
| Files in one artifact | 4,096 |
| One artifact's bytes | 4 GiB |
| All artifact bytes of one run | 16 GiB |
| Artifact name | 64 bytes |
| Artifact file path | 1,024 bytes |
| OAuth form body (token, revocation, device authorization, consent) | 8 KiB |
| Worker labels per profile | 16 |
| One cache chunk payload | 48 KiB (must fit a control frame whole) |

Invariants between limits are compile-time assertions. Raise a limit only with a measured need and a note here.

## Worker negotiation

A session opens with `Hello { protocol_min, protocol_max, capabilities, arch, software }`. The controller supports protocol versions in an inclusive range (currently 1 to 7) and answers with the highest version both sides share and the worker's capability bits it recognises. Capabilities are a `u64` bit set so storing, comparing and intersecting is one instruction; bits the controller does not know are masked, never rejected, so newer workers stay compatible.

| Bit | Capability |
|---|---|
| 0 | `OCI_ROOTLESS`: rootless Podman with user namespaces |
| 1–3 | `CGROUP_CPU`, `CGROUP_MEMORY`, `CGROUP_PIDS` |
| 4 | `CGROUP_IO` |
| 5 | `REFLINK` on the cache volume |
| 6 | `TAILCAT` helper available |
| 7 | `NETWORK_NONE` supported |

Bits 0 to 3 are required (the set the F07 probe proved enforceable); a hello without them is rejected. Rejections are typed and final for that hello: `unsupported_version` names the supported range and whether the worker is the side that must upgrade, `missing_capabilities` names the missing bits, `invalid_range` flags `protocol_min > protocol_max`. A worker must not retry an unchanged rejected hello. `software` is a diagnostic string only and never a compatibility input.

## Protocol 7 additions

Protocol 7 is additive: every pre-existing message keeps its shape and enum
index, and a worker and controller that negotiate 6 exchange exactly what
they did before.

| Message | Direction | Purpose |
|---|---|---|
| `Profile` | worker → controller | The scheduling profile (labels ≤ 16, `host_id`, `disk_bytes`, `availability { images, cache_bytes, load_ns }`), sent immediately after `Welcome` when the session negotiated 7 |
| `BulkHello { worker }` | worker → controller | Opens the second (bulk) connection of a session; attached only when a live control session presents the same certificate |
| `Transport` | worker → controller | Q07 telemetry: path, RTT, reconnects, helper version, byte counters; sent after `Profile` and refreshed every 12 beats |
| `CacheNeed(Need)`, `CacheOffer(Upload)`, `CachePush(Push)`, `CachePushEnd(End)` | worker → controller | Q08 remote-cache fetch (with resume offset and prefix digest) and offer/push |
| `CacheGrant(Grant)`, `CacheChunk(Chunk)`, `CacheEnd(End)`, `CacheRefused(Refused)` | controller → worker | Q08 transfer answers; `End` is terminal both ways |

The profile is a message rather than new `Hello` fields because postcard is
not self-describing: a struct decodes exactly the field list its reader
knows, so a trailing `Hello` field would make an older worker's hello
undecodable, and `#[serde(default)]` never fires because the reader hits the
end of the frame instead of an end-of-sequence. Additive *variants* are safe;
additive struct fields are not. The same rule is why `Context2` stayed a new
variant at protocol 6.

Bulk classes (logs, specs, artifacts, cache) travel on the worker's second
connection when it is up and are still accepted on the control connection as
a fallback; control classes (heartbeat, offers, reports) are refused there.
Each connection has its own rustls state behind its own lock, so bulk traffic
cannot delay a beat. See [worker link](worker-link.md#control-and-bulk-protocol-7-q05).

## Versioning policy

The protocol version bumps on any incompatible change to messages, framing or semantics. A new message *variant* is additive; a new or changed *struct field* — optional or not — bumps the protocol, because postcard decodes exactly the field list its reader knows and `#[serde(default)]` never fires (see [Protocol 7 additions](#protocol-7-additions)). Error schema, cursor version byte and protocol version are independent so each can move alone. The JSON shapes of `ApiError`, `Hello` and `Rejected` are pinned by tests.

## Verification

Unit tests: error wire shape and foreign-schema rejection, status and retry mapping, idempotency key bounds and size, fingerprint stability, decision table, cursor round trip with tenant binding and malformed/uppercase/version/kind rejection, sequence saturation, page-size clamping, declared-length checks, version selection with unknown-bit masking, mismatch direction, missing-capability naming, and `Hello`/`Rejected` JSON stability, plus the protocol-7 profile's bounds (`Profile::invalid`) and its postcard round trip (with `serde(default)` on the JSON shape). All pass on Windows and Linux.
