# Tracing, timing and execution boundaries

Implemented for **F04**. The Linux server/worker lifecycle now uses the shared foundations in `crates/sentinel/src/{correlation,diagnostics,timing,work}.rs`. The package's library target exposes these internal APIs for reuse and verification; it is not a stable SDK or a separate service.

## Structured internal diagnostics

```sh
cargo dev-server --data-dir "$PWD/data/controller" --log-format json --log-level debug
cargo dev-worker --data-dir "$PWD/data/worker" --log-format text --log-level info
```

Defaults are `text` and `info`. `log_format` and `log_level` can also be set in the explicit TOML file; command-line values override the file. Levels are `error`, `warn`, `info`, `debug`, `trace`. There is no implicit `RUST_LOG` filter, regex filter, environment capture, or arbitrary per-module filter language.

`tracing` events go through `tracing-subscriber` to a dedicated stderr writer thread. Text is human-readable without ANSI coloring; JSON is one formatted record per line. Help/version/`--check` stay on stdout. CLI and configuration errors occur before diagnostics initialization and remain concise stderr errors, even if JSON was requested. Once diagnostics are initialized, runtime errors use tracing; the caller avoids an additional synchronous stderr write that could hang on a stalled pipe.

### Schema version 1

JSON uses the subscriber's `timestamp`, `level`, `target`, `fields`, and `spans` structure:

- `timestamp`: observer wall time for human chronology, not duration arithmetic.
- `fields.event`: stable internal event name, such as `phase_completed`, `service_initialized`, `work_completed`, `work_rejected`, `runtime_failed`, `shutdown_requested`, `service_stopped`, or `diagnostic_loss`.
- The `correlation` span carries `schema_version = 1`, `process_id`, and any actual request/run/job/attempt IDs.
- The `service` span carries `role` and the Cargo package `version`.
- `phase_completed` adds `phase`, `outcome`, and unsigned integer `duration_ns`.
- `work_completed` is debug-level and adds `work_class`, `queue_wait_ns`, `duration_ns`, and `panicked`. It measures closure execution, not a CI command's exit status.
- `work_rejected` identifies the lane and rejection reason. Admission returns an explicit error to the caller; logging is not the error-handling mechanism.

Context spans remain enabled at all supported log levels so an error-only filter does not discard the error's IDs. These context spans do not themselves emit error events. Subscriber dispatch and the current span are captured explicitly at work admission and restored on the executor thread. Future async tasks need equivalent explicit propagation; thread-local context alone is insufficient.

Only record bounded, selected internal metadata. Never record authorization headers, secret values, full configuration bodies, environments, arbitrary command output, or input documents in tracing fields. IDs are opaque; none grants permission to fetch a resource. Tenant authorization and job-output redaction remain separate implementation contracts.

### Bounded output and loss semantics

| Boundary | F04 policy |
|---|---|
| Diagnostic queue | 256 complete records, nonblocking admission |
| Record admission limit | 16 KiB of formatted bytes, including the newline |
| Queued record allocations | At most 4 MiB, plus the active sink record and per-producer record buffers |
| Queue full | Drop the new record; increment `full` |
| Oversized event | Drop the whole record; increment `oversized`; never intentionally emit a truncated JSON object |
| Closed sink queue | Drop/count `closed` |
| Sink write/flush error | Count `io_errors`; do not recursively log into the failed sink |
| Shutdown flush | Wait at most 500 ms; incomplete drain or sink errors cause service exit code 1 |

`Diagnostics::losses()` exposes atomic snapshots. A best-effort `diagnostic_loss` event reports losses seen before the final drain; it can itself be dropped or filtered and is not proof of complete output. No durable diagnostic retention or remote metric endpoint exists yet. A partial OS write can also leave incomplete output after a sink failure.

The byte limit bounds queued output, **not all formatting or span allocations** inside the subscriber. Call sites must keep metadata and concurrent producers bounded; raw job logs must not flow through this formatter. These internal events are intentionally lossy under pressure. W05/D04 will implement the separate durable, acknowledged job-log spool.

## Correlation IDs

`ProcessId`, `RequestId`, `RunId`, `JobId`, and `AttemptId` are distinct types backed by random UUID v4 values. Their canonical text forms are `prc_<uuid>`, `req_<uuid>`, `run_<uuid>`, `job_<uuid>`, and `att_<uuid>` (40 ASCII bytes each). Parsing rejects the wrong type prefix, non-v4/invalid variant, nil, uppercase or noncanonical UUID encodings. Display is canonical lowercase.

- Each service invocation creates a fresh process correlation ID; it is not the numeric OS PID or a persistent worker identity.
- Request IDs will originate at Sentinel's request boundary. External correlation values require a separate validated field, not unconditional replacement of Sentinel identity.
- A run/job ID will remain stable for that durable entity; each new execution attempt will get a new attempt ID. Retries must not reuse a previous attempt's identity.
- The lifecycle currently emits only its real process ID. Missing request/run/job/attempt fields are absent, not nil IDs or fabricated jobs.

These types are ready for C01's durable model; F04 does not create database records, prove ID ownership, serialize a wire protocol, or implement attempt fencing. Keep correlation identity distinct from authorization, idempotency keys and lease fencing tokens.

## Monotonic timing and end-to-end field contract

Durations use `std::time::Instant` on the observing process. `elapsed_ns` produces a saturating `u64`; phase completion requires an explicit `completed`, `failed`, or `cancelled` outcome. Dropping a timer does not invent successful completion. Emit a final measurement only when its stated boundary has actually been observed.

The implemented lifecycle measures:

| Field / phase | Exact current boundary |
|---|---|
| `configuration` / `duration_ns` | After execution lanes start, through file read, TOML parse, option merge and path validation; emitted after diagnostics become available |
| `startup` / `duration_ns` | Signal registration through data-directory initialization, with explicit success/failure |
| `service_initialized.service_startup_ns` | Entry to the service function through successful initialization; includes lane creation, configuration and diagnostic setup, but not OS process creation or Cargo compilation |
| `shutdown` / `duration_ns` | Begin lane shutdown through both lane stop decisions and loss reporting; excludes the final diagnostic sink drain |
| `work_completed.queue_wait_ns` | Task construction/admission attempt to start on its assigned lane |
| `work_completed.duration_ns` | Execution of the submitted closure, including panic capture; excludes result-consumer delay |

Configuration is measured before the subscriber exists, then emitted with its measured duration. It is not reconstructed by subtracting event wall timestamps.

### Reserved CI measurements — instrument as behavior arrives

The `Phase` enum establishes these phase names now; F04 emits no synthetic job measurements:

| Phase | Future start → finish boundary |
|---|---|
| `intake` | Receipt on controller → durable validated event admission |
| `source_resolution` | Begin resolving pipeline/source inputs → exact pinned source and compiled specification available |
| `dependency_wait` | Job exists but dependencies unresolved → dependency condition determined |
| `capacity_wait` | Dependency-eligible → resources reserved for an attempt |
| `dispatch` | Reservation/offer preparation → offer acknowledgement on controller |
| `checkout` | Begin worker materialization → exact revision ready |
| `image_pull` | Begin image resolution/pull/unpack → usable pinned runtime image |
| `cache_restore` | Begin cache selection/materialization → job-private cache state ready; track first-touch I/O separately |
| `container_setup` | Begin isolated environment creation → first command can start |
| `step` | Step process starts → process termination observed; attach job/attempt and a bounded step identifier |
| `cache_commit` | Begin publication → local generation committed; asynchronous replication measured separately |
| `artifact_upload` | Begin declared output transfer → required durable references acknowledged |
| `log_flush` | Final job output captured → required durable log acknowledgement/completeness recorded |
| `checks_propagation` | Desired check update queued → GitHub acknowledges that update; observer visibility is a distinct external measurement |

User-feedback measurements are overlapping views, not additive phases:

| Field / phase | Contract |
|---|---|
| `ready_to_offer_ns` | On controller, eligible ready work → offer sent; include capacity/locality waiting and label the eligible-idle-capacity benchmark cohort explicitly |
| `ready_to_first_process_ns` | One observer tracks ready notification → worker first-process notification; includes transport observation delay, never subtracts worker `Instant` from controller `Instant` |
| `log_visibility_ns` | Measured by a single instrumented probe from known emission trigger → stream receipt; identify any included trigger/transport delay |
| `failure_query_ns` | On controller, authorized query accepted → bounded indexed response ready |
| `required_checks` | On external harness, push/check trigger → all declared required checks complete under the frozen assertions/freshness contract |
| `first_failure` | Same trigger → first actionable failing diagnostic visible |
| `acceptance` | Same trigger → declared long acceptance/audit lane complete |

Each future benchmark record must identify observer/clock domain, source/tool/image revisions, resource allocation, warm state, sample count and relevant correlation IDs. Unmeasured fields are absent, not zero. Export numeric nanosecond durations with wall-clock provenance separately. Persisted UTC timestamps may support approximate cross-restart chronology but cannot reconstruct a precise monotonic interval after a restart. Do not sum overlapping jobs/phases into wall time, equate cache attachment with first-touch cost, or subtract clocks on different hosts. The [F05 benchmark runner](benchmarking.md) implements machine-readable runs and the no-op baseline; no Sentinel job latency or RSS budget is measured yet.

## Blocking I/O and CPU lanes

F04 runs two separately named, fixed-size executors:

- **Blocking I/O:** one thread, 16 waiting slots. Configuration reads/metadata and directory creation run here.
- **CPU:** one thread, 16 waiting slots. TOML deserialization runs here.
- Each lane has at most one active closure in addition to its waiting slots; one lane cannot consume the other's execution thread.
- `try_submit` immediately accepts or returns `Full`/`Closed`; there is no spawn-per-task fallback or unbounded executor queue.
- Each task has a capacity-one result channel. Callers must also bound captured payload bytes, concurrent producers and retained results. The bootstrap file reader caps input at 64 KiB.
- Admission propagates the current tracing dispatch/span. Panics return `Panicked` and the lane remains usable; the normal Rust panic hook still runs, so panicking with sensitive payloads is forbidden.

`Task::wait` is a **blocking bootstrap/drain interface**, with a five-second wait per bootstrap task in the current service. It must not be called from a future async request/scheduler loop. Such callers will need a nonblocking completion adapter and explicit admission budgets; they must not call blocking filesystem/SQLite/compression/compiler work directly on control threads or rely on an effectively unbounded `spawn_blocking` pool.

A result timeout does not cancel the closure or free its occupied thread. Shutdown closes admission, discards pending work, and waits up to one second per lane for active work. Rust cannot forcibly terminate a running closure. A missed lane deadline is reported as incomplete shutdown, not successful cleanup. Destructors never perform unbounded joins; an unfinished thread may continue until the process exits. No job side effects run on these lanes yet, and this is not the later worker process-group cancellation or lease-recovery contract.

The existing capacity-one signal channel still coalesces repeated shutdown requests independently of bulk work and diagnostic queues. Config validation (`--check`) uses transient work lanes but creates no state, signal handler or diagnostics sink.

## Verification

`cargo test-linux` exercises ID validation, JSON correlation propagation across threads, monotonic nested timings, error-only context retention, whole-record loss, queue saturation, stalled/broken sinks, independent work lanes, panic recovery, timeout capacity accounting and bounded shutdown. Process tests validate text/JSON lifecycle output, configuration precedence, signal shutdown, consistent process IDs and absence of fabricated job IDs. Single-role tests and portable CLI checks remain part of the [development workflow](development.md).
