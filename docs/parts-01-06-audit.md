# Parts 01–06 audit: silent failures, bounds and hot paths

Audited after D07 (`34badb1`), by re-reading every crate the first six parts
built — `sentinel-core`, `sentinel-protocol`, `sentinel-store`,
`sentinel-pipeline`, `sentinel-auth`, `sentinel-github`, `sentinel-git`,
`sentinel-link`, `sentinel-worker`, `sentinel-intake`, `sentinel-checks`,
`sentinel-api`, `sentinel` — with two passes: a correctness pass over every
dropped `Result` (`let _ =`, `.ok()?`, `Err(_) =>`, `unwrap_or*` on
operational paths), and a bounds/hot-path pass over allocations, whole-file
reads, query shapes, thread counts and lock hold times.

The bar: an operational failure is either returned, durably recorded,
retried by a lane, explicitly best-effort cleanup whose residue a sweep
reclaims, or surfaced in diagnostics that do not claim success.

## Fixed in this audit

| # | Finding | Why it mattered | Fix |
|---|---|---|---|
| 1 | **A check parked by a rate limit could be durably refused but reported "throttled".** `checks::retry` answers `Exhausted` when the park spends the last attempt; both the `Retry` and `Throttled` arms counted it but kept the retry/throttle notice. | Diagnostics claimed a parked row would come back; it was durably dead. | Both arms count `Exhausted` under `refused` and emit `refused: retry budget spent (...)`. `tests/lane.rs` drives both arms to exhaustion and asserts the durable state and the notice. |
| 2 | **`Store::read` leaked its pooled connection on panic.** The `idle` push ran only on normal return; `READER_LIMIT` panics permanently drained the pool and every later read shed `Overloaded`. | A recoverable bug became a permanent outage. | `catch_unwind` around the closure, connection returned and the condvar notified, then `resume_unwind`. Tested: `READER_LIMIT + 1` panics leave a working pool. |
| 3 | **A failed provisional index write could tear an entry mid-file.** `checkpoint`'s ignored `write_all` could land a partial entry; later entries then sat behind undecodable bytes and `read_index` stopped early, hiding seal records until reopen. | Degraded tails for the log's whole life, invisibly. | `Open.index_len` tracks the valid tail; `index_write` truncates a failed append back to it and abandons the index (`u64::MAX`) if the repair itself fails — seal failures still propagate. Readers decode less, never more; reopen rebuilds. |
| 4 | **`recovery::mark` failure let an attempt run unrecoverably.** Spawn proceeded without the marker; a crash left a spool with no marker, which recovery discards as already reported. | Silent loss of the attempt's log and outcome. | A failed marker removes the live entry and reports `Failed(Publication)` — the same refusal the `LogPipe::open` failure path already used. |
| 5 | **Worker auth conflated a store fault with an unknown fingerprint.** Any non-`NotFound` read error fell into the enrollment path, refusing a known worker with `NotEnrolled` instead of the retryable `Unavailable`. | A transient store fault told a worker to re-enroll. | `Err(NotFound)` proceeds to enrollment; other errors answer `Unavailable`. |
| 6 | **Failed `rewind` desynced the log send window.** `attached` reset `sent` to `acked` while the spool cursor stayed ahead; `in_flight` under-counted and the session could be handed more than `MAX_UNACKED_LOG_FRAMES`. | The unacked bound could be exceeded. | On `Err`, `sent` is set to `last_seq` — the unread tail counts as in-flight, the skipped range reaches the controller as declared gaps. |
| 7 | **A failed recovery-thread spawn dropped the leftover queue.** `leftovers` was `take()`n and moved into the closure; spawn failure (resource exhaustion) silently deferred delivery to the next process restart. | Work sat invisible for the process's life. | The queue goes through a slot; on spawn failure it is re-queued for the next `attached`. |
| 8 | **Logout reported `ok` over a live session.** The delete's `Result` was dropped; a store fault left the cookie's session valid while the client cleared it. | A user-visible success over a session that still worked. | The store error propagates as an API error. |
| 9 | **Reconcile notices claimed durable settlement they did not perform.** `settle`/`finish` and the inline writes returned `"settled"`, `"target gone"`, `"verified"`, `"installation gone"` whether the write landed or not. | Diagnostics lied about durable state; the rows did self-heal by staying due. | Every settlement write failure reports `"store"` — the same vocabulary as a failed read. |
| 10 | **One writer transaction per placed job.** The dispatch offer loop committed per placement. | N commits per worker pass where one suffices. | Placements batch into a single transaction per worker; a dead session lapses the unsent remainder in one write. |
| 11 | **`status::recent_runs` ran one `run_state` query per row** (up to 501 queries), and `status::run` ran twin correlated attempt subqueries per job. | Hot list view scaled linearly in round trips. | One grouped jobs query with an `IN` subquery materializing the same selection; the twin subqueries became one `LEFT JOIN`. `aggregate([])` keeps a jobless run `Pending`. |
| 12 | **The redactor scanned every registered secret at every byte position.** O(chunk × secrets) on the log hot path. | Seconds of byte loops on a maxed log once secrets are registered. | A 256-bit first-byte bitmap: positions that start no secret emit in O(1). Split-secret, longest-match and per-stream tests unchanged. |

## Verified silent-drop sites are honest

Classified, not changed — each is either a returned error, durable state, a
retried lane pass, or cleanup a sweep reclaims:

- **`controller::record_artifact`** drops its write: a missing artifact row
  is synthesized `failed` by `due_coverage` at `finish`, and a reported
  `Passed` cannot stand over a missing required artifact — the D05
  finalization is the durable backstop, so the dropped write can only
  under-report.
- **`controller` offer-send `lapse` write**: on failure the offer stays
  held until its ack timeout lapses it — delayed, not lost.
- **`storage_pass` stage skips** (`if let Ok`): the pass is periodic; a
  failed stage leaves rows/files for the next pass, and manifest files are
  only unlinked after their rows commit gone.
- **`intake::settle`** propagates store errors (`Conflict` → `Skipped` —
  a concurrent settler won).
- **`logpipe` spool ops**: `acknowledged` failures resend on reopen (the
  store dedups); `append` failures declare gaps (D07); `send_next` read
  failures leave the cursor for the next pump; `remove` failures leave a
  spool the next `recover` deletes.
- **`recovery` cleanups** (`unmark`, askpass dirs, marker-less spools):
  survivors are re-swept at the next `recover`; a stale marker's re-report
  is fenced by the controller.
- **`objects`/`artifacts`/`logs` file removals**: orphan files are
  collected by `sweep_orphans`/`recover`; a `put_chunk` delta is released
  on failure (D06); `seal_upload` recovers via the declared digest (D06).
- **`podman` best-effort stops/removes**: the attempt thread's `destroy`
  (`rm -f`) is the guarantee; `recover()` sweeps owned containers at start.
- **`password::verify` placeholder discard** is deliberate constant-time
  padding on the unknown-user path.
- **API `respond`/`record_use`/join drops**: a hung-up client, best-effort
  last-used telemetry, shutdown joins.

## Bounds re-verified

- **Memory**: request bodies (`take(limit+1)`), GitHub responses
  (header/body caps, no redirects, global timeout), config files,
  manifests, spool scans (64 KiB window + one record), `send_next(limit)`,
  log tails (`Decoder` streaming with the step filter during the scan),
  TLS frames (`MAX_CONTROL_MESSAGE_BYTES` checked before buffering).
- **Concurrency**: writer queue (256) + `WRITE_WAIT`, reader pool (8) +
  `READ_ADMISSION`, API handlers (8) + transfers (4), poll batch (8),
  checks batch (32), reconcile token cache, pending deliveries, offer
  windows.
- **Filesystem**: admission watermarks close discretionary writes before
  the reserve; per-tenant quotas; sweeps are batch-bounded per pass.

## Residual, recorded — since fixed

- **`tiny_http` accepted a connection per thread with no cap and no read
  timeout.** Handler threads were bounded; connection reader threads were
  not. **Fixed:** `sentinel-api` now serves HTTP/1.1 through its own
  bounded layer (`src/http.rs`) — one acceptor, at most 64 connection
  threads (`Tune::connections`), `WORKERS = 8` handler permits, a 16 KiB
  cumulative head cap, 15 s head/idle deadline, 120 s body deadline,
  poll-bounded reads and writes so `Server::shutdown` wakes parked I/O on
  every OS, and `Conns::close` waits out every reader so no thread keeps
  `State` — and the store — alive past shutdown. `tiny_http` is gone from
  the dependency tree.
- **Reconcile settle/finish writes that fail leave the row due** — the
  retry is the recovery, now reported as `"store"`.
- **A reader-thread panic on a step's output** ends that stream silently
  (exit status still governs the verdict). Panic-only path; the spool's
  declared-gap machinery does not cover source-read failures.

## Verification

Windows: `fmt-check`, `lint`, `test-cli`, `release-cli`. WSL2:
`lint-linux`, `test-server`, `test-worker`, `test-linux`, `release-linux`.
New coverage: `tests/bounds.rs` panic-pool recovery,
`sentinel-checks/tests/lane.rs` exhaustion accounting on both arms.
